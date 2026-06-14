//! 文件读取与行处理模块
//!
//! # 核心职责
//!
//! - 从日志文件读取新内容（从 offset 开始）
//! - 批量读取（256KB）优化系统调用次数
//! - 行分割 + partial 行缓冲管理
//! - 轮转检测（inode/size 变化）
//!
//! # 关键不变量
//!
//! - 256KB 批量读：平衡系统调用次数与内存占用
//! - O_NOFOLLOW：防止符号链接攻击
//! - 轮转后重置 offset 和 partial 缓冲

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};

use crate::file_monitor::FILE_STATES;
use crate::line_processor::{process_lines_in_buffer, store_partial_line};
use crate::types::Config;

// 256KB 批量读：平衡系统调用次数与内存占用
const BATCH_READ_MAX: usize = 256 * 1024;

// ============================================================================
// 文件读取
// ============================================================================

/// 从日志文件读取新内容并处理。
///
/// 流程：打开（O_NOFOLLOW）→ 检测轮转（inode/size）→ seek → 批量 read → 行处理。
///
/// # Arguments
/// - `idx`: FILE_STATES 索引
/// - `cfg`: 全局配置
///
/// # Returns
/// `Ok(())` 即便内部错误（如 ELOOP）也会记录告警但不 bail
pub fn read_and_process_new_lines(idx: usize, cfg: &Config) -> Result<()> {
    let file_states = FILE_STATES.read();
    let state = file_states
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("Invalid index {idx}"))?;

    let log_path = state.path.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        return Ok(());
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    let mut local_partial_buf = {
        let mut buf = jail.partial_line_buffer.write();
        std::mem::take(&mut *buf)
    };

    // 打开文件（O_NOFOLLOW 防符号链接攻击）
    let mut file = match open_log_file(&log_path, idx) {
        Some(f) => f,
        None => return Ok(()),
    };

    // 轮转检测
    detect_and_handle_rotation(&mut file, idx, &mut local_partial_buf);

    let current_offset = {
        let file_states = FILE_STATES.read();
        file_states.get(idx).map_or(0, |s| s.offset)
    };

    if current_offset > 0 {
        file.seek(SeekFrom::Start(current_offset))
            .with_context(|| format!("Failed to seek in {log_path}"))?;
    }

    // 批量读取
    let (batch_buf, batch_total) = read_batch(&mut file);

    if batch_total > 0 {
        process_batch(
            &batch_buf,
            batch_total,
            &mut local_partial_buf,
            idx,
            jail_idx,
            current_offset,
            cfg,
            max_retries,
            findtime,
        );
    }

    Ok(())
}

/// 打开日志文件（O_NOFOLLOW）。
///
/// ELOOP 错误表示文件被替换为符号链接，记录安全告警并返回 None。
/// 不设置永久标志 — 每次读取周期重试,符号链接被移除后自动恢复监控。
fn open_log_file(log_path: &str, idx: usize) -> Option<std::fs::File> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(log_path)
    {
        Ok(f) => Some(f),
        Err(e) => {
            if e.raw_os_error() == Some(libc::ELOOP) {
                // 符号链接攻击检测：可能是攻击者将日志文件替换为指向敏感文件的符号链接
                crate::logger::error!(
                    crate::logger::get(),
                    "安全告警：日志文件被替换为符号链接（可能为攻击行为），本次跳过";
                    "path" => log_path,
                    "file_index" => idx
                );
            }
            None
        }
    }
}

/// 检测轮转（inode/size 变化）并更新状态。
fn detect_and_handle_rotation(
    file: &mut std::fs::File,
    idx: usize,
    local_partial_buf: &mut Vec<u8>,
) {
    if let Ok(metadata) = file.metadata() {
        let current_inode = metadata.ino();
        let current_size = metadata.len();

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            if state.inode != 0 && current_inode != state.inode {
                // inode 变化，认为是轮转
                state.inode = current_inode;
                state.offset = 0;
                local_partial_buf.clear();
            } else if current_size < state.offset {
                // 文件大小缩小，认为是 truncate
                state.inode = current_inode;
                state.offset = 0;
                local_partial_buf.clear();
            }
        }
    }
}

/// 批量读取文件内容（最多 256KB）。
fn read_batch(file: &mut std::fs::File) -> (Vec<u8>, usize) {
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
            Err(_e) => break,
        }
    }

    (batch_buf, batch_total)
}

/// 处理批量读取的数据：行分割 + partial 缓冲管理 + offset 更新。
#[allow(clippy::too_many_arguments)]
fn process_batch(
    batch_buf: &[u8],
    batch_total: usize,
    local_partial_buf: &mut Vec<u8>,
    idx: usize,
    jail_idx: usize,
    current_offset: u64,
    cfg: &Config,
    max_retries: u32,
    findtime: u32,
) {
    let mut process_buf = Vec::new();
    if local_partial_buf.is_empty() {
        process_buf.extend_from_slice(&batch_buf[..batch_total]);
    } else {
        process_buf.reserve(local_partial_buf.len() + batch_total);
        process_buf.extend_from_slice(local_partial_buf);
        process_buf.extend_from_slice(&batch_buf[..batch_total]);
        local_partial_buf.clear();
    }

    let jail = &cfg.jails[jail_idx];
    let Some(log_path) = jail.log_files.first() else {
        // log_files 为空: 无日志文件可关联, 跳过处理 (不应出现在正确配置中)
        return;
    };
    let mut consumed = 0;
    process_lines_in_buffer(
        jail,
        &process_buf,
        log_path,
        &mut consumed,
        max_retries,
        findtime,
    );

    if consumed < process_buf.len() {
        store_partial_line(
            jail,
            &process_buf[consumed..],
            log_path,
            max_retries,
            findtime,
        );
    }

    let mut file_states = FILE_STATES.write();
    if let Some(state) = file_states.get_mut(idx) {
        state.offset = current_offset + batch_total as u64;
    }
}
