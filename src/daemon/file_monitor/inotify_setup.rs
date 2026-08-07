//! inotify 监控设置模块
//!
//! 负责为所有 enabled jail 的日志文件建立 inotify watch。
//! 同时监控配置文件变化，自动触发热重载。

use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use inotify::Inotify;

use crate::types::Config;

use super::state::{FileState, FILE_STATES, INOTIFY_STATE};
use super::watch_mask::log_file_watch_mask;

// ============================================================================
// inotify 设置
// ============================================================================

/// 为 `Config` 中所有 enabled jail 的日志文件建立 inotify watch。
/// 同时监控配置文件变化，自动触发热重载。
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
    // 关闭旧的 inotify 实例（reload 时避免 fd 泄漏）
    if let Some(old) = INOTIFY_STATE.fd.write().take() {
        drop(old);
    }

    let inotify = Inotify::init().context("Failed to initialize inotify")?;

    let mut file_states = Vec::new();
    let mut watched_count = 0;

    // 监控配置文件变化
    if let Some(ref config_path) = cfg.config_file {
        let mut state = FileState::new();
        state.path.clone_from(config_path);
        state.is_config = true;

        let path = Path::new(config_path);
        if let Ok(metadata) = path.metadata() {
            state.inode = metadata.ino();
        }

        let mask = log_file_watch_mask();

        match inotify.watches().add(config_path, mask) {
            Ok(wd) => {
                state.wd = Some(wd);
                watched_count += 1;
                file_states.push(state);
                crate::logger::info!(
                    crate::logger::get(),
                    "已添加配置文件监控";
                    "path" => %config_path
                );
            }
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "添加配置文件监控失败";
                    "path" => %config_path,
                    "error" => %e
                );
            }
        }
    }

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

            let mask = log_file_watch_mask();

            match inotify.watches().add(log_file, mask) {
                Ok(wd) => {
                    state.wd = Some(wd.clone());
                    watched_count += 1;
                    // 只有 watch 成功时才加入列表
                    file_states.push(state);
                }
                Err(e) => {
                    // 日志文件不存在是正常情况（多配置兼容），只记录 debug
                    if !path.exists() {
                        crate::logger::debug!(
                            crate::logger::get(),
                            "日志文件不存在，跳过";
                            "path" => log_file
                        );
                    } else {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "添加 inotify watch 失败";
                            "path" => log_file,
                            "error" => %e
                        );
                    }
                }
            }
        }
    }

    // 只有至少有一个文件 watch 成功时，才更新全局状态
    if watched_count == 0 {
        // 清理新创建的 inotify 实例
        drop(inotify);
        return Err(anyhow::anyhow!("No log files could be watched"));
    }

    // 更新全局状态
    *FILE_STATES.write() = file_states;
    let raw_fd = inotify.as_raw_fd();
    *INOTIFY_STATE.fd.write() = Some(inotify);
    INOTIFY_STATE.raw_fd.store(raw_fd, Ordering::Relaxed);

    Ok(())
}
