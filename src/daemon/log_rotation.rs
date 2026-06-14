//! 日志轮转检测与处理模块
//!
//! # 核心职责
//!
//! - 日志轮转处理:inotify DELETE/MOVED_FROM 事件触发
//! - 新日志文件发现:周期性检查新增的日志文件
//! - inode/offset 更新:轮转后重新注册 inotify watch
//!
//! # 关键不变量
//!
//! - 每个日志文件 inode 在 `setup_inotify` 时记录,变化时认为是轮转
//! - 轮转前先 flush partial 行缓冲,避免丢失数据

use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::Ordering;

use inotify::WatchMask;

use crate::file_monitor::{setup_inotify, FILE_STATES, INOTIFY_STATE};
use crate::line_processor::process_single_line;
use crate::types::{Config, DAEMON_STATS};

// ============================================================================
// 日志轮转处理
// ============================================================================

/// 处理日志轮转：inotify DELETE / `MOVED_FROM` 事件触发，先 flush partial 行，
/// 再更新 inode + offset，最后重新注册 inotify watch。
///
/// # Arguments
/// - `idx`: `FILE_STATES` 索引
/// - `cfg`: 全局配置
pub fn handle_log_rotation(idx: usize, cfg: &Config) {
    let file_states = FILE_STATES.read();
    let Some(state) = file_states.get(idx) else {
        return;
    };

    let path = state.path.clone();
    let wd = state.wd.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        return;
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    // flush partial 行缓冲
    let mut buf = jail.partial_line_buffer.write();
    if buf.is_empty() {
        drop(buf);
    } else {
        let temp = buf.clone();
        buf.clear();
        drop(buf);

        if let Ok(line) = std::str::from_utf8(&temp) {
            process_single_line(jail, line, &path, max_retries, findtime);
        }
    }

    DAEMON_STATS.log_rotations.fetch_add(1, Ordering::Relaxed);

    let path_obj = Path::new(&path);
    if !path_obj.exists() {
        // 文件已删除,重置 offset
        crate::logger::debug!(
            crate::logger::get(),
            "日志轮转后文件不存在";
            "path" => &path
        );
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = 0;
        }
        return;
    }

    // 更新 inode 并重新注册 watch
    if let Ok(metadata) = path_obj.metadata() {
        let current_inode = metadata.ino();
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            if current_inode != state.inode {
                // inode 变化,认为是轮转
                // inode 变化，更新状态
                state.inode = current_inode;
                state.offset = 0;

                if let Some(inotify) = INOTIFY_STATE.fd.write().as_mut() {
                    if let Some(old_wd) = wd {
                        if let Err(e) = inotify.watches().remove(old_wd) {
                            crate::logger::debug!(
                                crate::logger::get(),
                                "移除 inotify watch 失败";
                                "error" => %e
                            );
                        }
                    }

                    let mask = WatchMask::MODIFY
                        | WatchMask::MOVED_FROM
                        | WatchMask::MOVED_TO
                        | WatchMask::DELETE
                        | WatchMask::CREATE;

                    match inotify.watches().add(&path, mask) {
                        Ok(new_wd) => {
                            state.wd = Some(new_wd.clone());
                        }
                        Err(e) => {
                            crate::logger::warn!(
                                crate::logger::get(),
                                "重新注册 inotify watch 失败";
                                "path" => &path,
                                "error" => %e
                            );
                            state.wd = None;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 新日志文件发现
// ============================================================================

/// 周期检查新增日志文件：遍历所有 enabled jail 的 log_files，若发现未 watch 的
/// 已存在文件则重新 `setup_inotify`。
///
/// # Arguments
/// - `cfg`: 全局配置
pub(crate) fn check_for_new_log_files(cfg: &Config) {
    let file_states = FILE_STATES.read();
    let mut needs_resetup = false;

    for jail in &cfg.jails {
        if !jail.enabled {
            continue;
        }
        for log_file in &jail.log_files {
            if Path::new(log_file).exists() {
                let already_watched = file_states
                    .iter()
                    .any(|s| s.wd.is_some() && s.path == *log_file);
                if !already_watched {
                    // 发现新文件,需要重新 setup
                    crate::logger::info!(
                        crate::logger::get(),
                        "发现新的日志文件";
                        "path" => log_file
                    );
                    needs_resetup = true;
                }
            }
        }
    }

    if needs_resetup {
        drop(file_states);
        if let Err(e) = setup_inotify(cfg) {
            crate::logger::warn!(
                crate::logger::get(),
                "重新设置 inotify 失败";
                "error" => %e
            );
        } else {
            crate::logger::info!(crate::logger::get(), "重新设置 inotify 成功");
        }
    }
}
