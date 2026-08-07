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

use crate::file_monitor::{log_file_watch_mask, setup_inotify, FILE_STATES, INOTIFY_STATE};
use crate::line_processor::flush_partial_line;
use crate::types::{Config, DAEMON_STATS};

// ============================================================================
// 日志轮转处理
// ============================================================================

/// 处理日志轮转：`MOVE_SELF` / `DELETE_SELF` 触发，先 flush partial 行，
/// 再更新 inode + offset，最后按路径重新注册 inotify watch（指向新 inode）。
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
    flush_partial_line(jail, &path, max_retries, findtime);

    DAEMON_STATS.log_rotations.fetch_add(1, Ordering::Relaxed);

    let path_obj = Path::new(&path);
    if !path_obj.exists() {
        // 文件已删除/尚未重建：丢掉旧 wd，等 check_for_new_log_files 重建
        crate::logger::debug!(
            crate::logger::get(),
            "日志轮转后文件不存在";
            "path" => &path
        );
        if let Some(inotify) = INOTIFY_STATE.fd.write().as_mut() {
            if let Some(old_wd) = wd {
                let _ = inotify.watches().remove(old_wd);
            }
        }
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = 0;
            state.inode = 0;
            state.wd = None;
        }
        return;
    }

    // 路径上已有新文件：摘掉旧 inode 的 watch，挂到当前路径
    if let Ok(metadata) = path_obj.metadata() {
        let current_inode = metadata.ino();
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
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

                let mask = log_file_watch_mask();

                match inotify.watches().add(&path, mask) {
                    Ok(new_wd) => {
                        state.wd = Some(new_wd);
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
