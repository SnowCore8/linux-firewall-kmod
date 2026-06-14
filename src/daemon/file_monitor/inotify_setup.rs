//! inotify 监控设置模块
//!
//! 负责为所有 enabled jail 的日志文件建立 inotify watch。

use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use inotify::{Inotify, WatchMask};

use crate::types::Config;

use super::state::{FileState, FILE_STATES, INOTIFY_STATE};

// ============================================================================
// inotify 设置
// ============================================================================

/// 为 `Config` 中所有 enabled jail 的日志文件建立 inotify watch。
///
/// 启动时拒绝符号链接(攻击者可借此动态切换目标);运行期改用 `O_NOFOLLOW`
/// 二次防御。
///
/// # Arguments
/// - `cfg`: 全局配置
///
/// # Returns
/// 至少 1 个文件 watch 成功即返回 `Ok`
///
/// # Errors
/// 没有任何文件能被 watch (配置错误 / kmod 未加载 / 权限不足)
pub fn setup_inotify(cfg: &Config) -> Result<()> {
    let inotify = Inotify::init().context("Failed to initialize inotify")?;

    let mut file_states = Vec::new();
    let mut watched_count = 0;

    for (j_idx, jail) in cfg.jails.iter().enumerate() {
        if !jail.enabled {
            continue;
        }

        for log_file in &jail.log_files {
            let mut state = FileState::new();
            state.path.clone_from(log_file);
            state.jail_idx = j_idx;

            // 启动时拒绝符号链接日志文件
            let path = Path::new(log_file);
            if path.is_symlink() {
                crate::logger::warn!(
                    crate::logger::get(),
                    "跳过符号链接日志文件";
                    "path" => log_file
                );
                continue;
            }

            if let Ok(metadata) = path.metadata() {
                state.inode = metadata.ino();
                state.offset = metadata.len();
            }

            let mask = WatchMask::MODIFY
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::DELETE
                | WatchMask::CREATE;

            match inotify.watches().add(log_file, mask) {
                Ok(wd) => {
                    state.wd = Some(wd.clone());
                    watched_count += 1;
                }
                Err(e) => {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "添加 inotify watch 失败";
                        "path" => log_file,
                        "error" => %e
                    );
                }
            }

            file_states.push(state);
        }
    }

    *FILE_STATES.write() = file_states;
    let raw_fd = inotify.as_raw_fd();
    *INOTIFY_STATE.fd.write() = Some(inotify);
    INOTIFY_STATE.raw_fd.store(raw_fd, Ordering::Relaxed);

    // 一个文件都没监控成功: 启动无意义, 直接退出
    if watched_count == 0 {
        return Err(anyhow::anyhow!("No log files could be watched initially"));
    }

    Ok(())
}
