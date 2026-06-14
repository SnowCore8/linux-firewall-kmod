//! 新行处理模块
//!
//! 负责处理日志文件从上次 offset 起的新增内容。

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use anyhow::{Context, Result};

use crate::line_processor::{process_lines_in_buffer, store_partial_line};
use crate::types::Config;

use super::state::FILE_STATES;

// ============================================================================
// 处理新行
// ============================================================================

/// 处理 `FILE_STATES[idx]` 文件从 `offset` 起的新增内容。
///
/// 流程:打开 (`O_NOFOLLOW`) → 检测轮转 (inode 变化 / size 缩小) → seek 到
/// `offset` → 批量 read → 行分割 + 失败计数 → 更新 `offset`。
///
/// # Arguments
/// - `idx`: `FILE_STATES` 索引
/// - `cfg`: 全局配置
///
/// # Returns
/// `Ok(())` 即便内部错误 (e.g. `O_NOFOLLOW` 撞到 symlink),会标记 `symlink_detected`
/// 但不 bail
///
/// # Errors
/// - `idx` 越界 (即 `FILE_STATES.len() <= idx`)
/// - `jail_idx` 越界
pub fn process_new_lines(idx: usize, cfg: &Config) -> Result<()> {
    // 256KB 批量读: 平衡系统调用次数与内存占用
    const BATCH_READ_MAX: usize = 256 * 1024;

    let file_states = FILE_STATES.read();
    let state = file_states
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("Invalid index {idx}"))?;

    if state.symlink_detected {
        return Ok(());
    }

    let log_path = state.path.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        crate::logger::warn!(
            crate::logger::get(),
            "jail_idx 越界";
            "jail_idx" => jail_idx,
            "jails_count" => cfg.jails.len()
        );
        return Ok(());
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    let mut local_partial_buf = {
        let mut buf = jail.partial_line_buffer.write();
        std::mem::take(&mut *buf)
    };
    // mem::take 后 NLL 立即释放锁, 后续 file.open() 等 IO 操作可与其他 reader 并发

    // O_NOFOLLOW: 启动后文件若被替换为符号链接, 拒绝 follow
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            // ELOOP = O_NOFOLLOW 撞到符号链接, 标记后跳过避免重复报错
            if e.raw_os_error() == Some(libc::ELOOP) {
                let mut file_states = FILE_STATES.write();
                if let Some(state) = file_states.get_mut(idx) {
                    state.symlink_detected = true;
                }
                crate::logger::warn!(
                    crate::logger::get(),
                    "检测到符号链接，跳过文件";
                    "path" => &log_path
                );
            } else {
                crate::logger::debug!(
                    crate::logger::get(),
                    "打开日志文件失败";
                    "path" => &log_path,
                    "error" => %e
                );
            }
            return Ok(());
        }
    };

    // 轮转检测: inode 变化 或 文件大小缩小 (truncate/rotate)
    if let Ok(metadata) = file.metadata() {
        let current_inode = metadata.ino();
        let current_size = metadata.len();

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            if (state.inode != 0 && current_inode != state.inode) || current_size < state.offset {
                // inode 变化或文件缩小，重置状态
                state.inode = current_inode;
                state.offset = 0;
                local_partial_buf.clear();
            }
        }
    }

    let current_offset = {
        let file_states = FILE_STATES.read();
        file_states.get(idx).map_or(0, |s| s.offset)
    };

    if current_offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(current_offset))
            .with_context(|| format!("Failed to seek in {log_path}"))?;
    }

    // 256KB 批量读: 平衡系统调用次数与内存占用
    let mut batch_buf = vec![0u8; BATCH_READ_MAX];
    let mut batch_total = 0;

    loop {
        match file.read(&mut batch_buf[batch_total..]) {
            Ok(0) => break,
            Ok(n) => {
                batch_total += n;
                if batch_total >= BATCH_READ_MAX - 1 {
                    break;
                }
            }
            Err(e) => {
                crate::logger::debug!(
                    crate::logger::get(),
                    "读取日志文件失败";
                    "path" => &log_path,
                    "error" => %e
                );
                return Ok(());
            }
        }
    }

    if batch_total > 0 {
        let mut process_buf = Vec::new();
        if local_partial_buf.is_empty() {
            process_buf.extend_from_slice(&batch_buf[..batch_total]);
        } else {
            process_buf.reserve(local_partial_buf.len() + batch_total);
            process_buf.extend_from_slice(&local_partial_buf);
            process_buf.extend_from_slice(&batch_buf[..batch_total]);
            local_partial_buf.clear();
        }

        let jail = &cfg.jails[jail_idx];
        let mut consumed = 0;
        process_lines_in_buffer(
            jail,
            &process_buf,
            &log_path,
            &mut consumed,
            max_retries,
            findtime,
        );

        if consumed < process_buf.len() {
            store_partial_line(
                jail,
                &process_buf[consumed..],
                &log_path,
                max_retries,
                findtime,
            );
        }

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = current_offset + batch_total as u64;
        }
    }

    Ok(())
}
