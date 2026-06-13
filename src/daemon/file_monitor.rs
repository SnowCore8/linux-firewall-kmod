//! inotify 监控日志文件 → 行分割 (不完整行缓冲) → 日志轮转检测 (inode/大小) → 主循环 (poll + SIGHUP 重载)
//!
//! # 模块结构
//!
//! 1. **文件状态**:`FileState` 跟踪每个监控文件的 path/offset/inode/watch descriptor
//! 2. **inotify 设置**:`setup_inotify` 给所有 enabled jail 的日志文件加 watch
//! 3. **主循环**:`monitor_loop` 调 `poll` 等待 inotify 事件 / SIGHUP / 周期维护
//!
//! # 关键不变量
//!
//! - 每个日志文件 inode 在 `setup_inotify` 时记录,变化时认为是轮转
//! - 单行硬上限 8KB,异常超长行会跳过 (避免 OOM)
//! - `O_NOFOLLOW` 防止日志文件被替换为符号链接后 readlink 到攻击者文件

use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use inotify::{Inotify, WatchDescriptor, WatchMask};
use parking_lot::RwLock;

use crate::config_reloader::{cleanup_partial_line_buffer, reload_configuration};
use crate::file_reader::read_and_process_new_lines;
use crate::log_rotation::{check_for_new_log_files, handle_log_rotation};
use crate::types::{Config, DAEMON_STATS};

// ============================================================================
// 文件状态
// ============================================================================

/// 单个被监控日志文件的运行时状态。`FILE_STATES` 索引 = `FileState.wd` 在
/// inotify 事件中的对应位置。
#[derive(Debug)]
pub struct FileState {
    /// 日志文件路径
    pub path: String,
    /// 下次 read 的起始字节偏移
    pub offset: u64,
    /// 文件 inode (用于检测轮转)
    pub inode: u64,
    /// inotify watch descriptor
    pub wd: Option<WatchDescriptor>,
    /// 关联的 jail 在 `Config.jails` 中的索引
    pub jail_idx: usize,
    /// 文件被检测为符号链接,标记后跳过
    pub symlink_detected: bool,
}

impl Default for FileState {
    fn default() -> Self {
        Self::new()
    }
}

impl FileState {
    /// 构造空 `FileState`,所有字段为默认值
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: String::new(),
            offset: 0,
            inode: 0,
            wd: None,
            jail_idx: 0,
            symlink_detected: false,
        }
    }
}

/// 全局:所有被监控文件的 `FileState` 列表
pub static FILE_STATES: RwLock<Vec<FileState>> = RwLock::new(Vec::new());
/// 全局:inotify 句柄。`reload_configuration` 期间会替换
pub static INOTIFY_FD: RwLock<Option<Inotify>> = RwLock::new(None);
/// 全局:inotify raw fd,单独存以便 [`monitor_loop`] 的 `poll` 调用避开借出整个 `Inotify` 句柄
pub static INOTIFY_RAW_FD: AtomicI32 = AtomicI32::new(-1);
/// 全局:监控循环运行标志 (备用,实际由 `main()` 持有的 `Arc<AtomicBool>` 控制)
pub static MONITOR_RUNNING: AtomicBool = AtomicBool::new(true);

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
                Err(_e) => {}
            }

            file_states.push(state);
        }
    }

    *FILE_STATES.write() = file_states;
    let raw_fd = inotify.as_raw_fd();
    *INOTIFY_FD.write() = Some(inotify);
    INOTIFY_RAW_FD.store(raw_fd, Ordering::Relaxed);

    if watched_count == 0 {
        return Err(anyhow::anyhow!("No log files could be watched initially"));
    }

    Ok(())
}

// ============================================================================
// 主监控循环
// ============================================================================

/// 主事件循环:`poll` 等待 inotify fd / SIGHUP / 周期维护触发。
///
/// 主循环每次迭代:
/// 1. `poll(timeout=interval*1000ms)` 阻塞等待
/// 2. 唤醒时分类处理:有事件 → 读 inotify 事件分发;超时 → 检查
///    SIGHUP/周期清理/新增文件
/// 3. `running` 标志为 false 时优雅退出
pub fn monitor_loop(
    cfg: &mut Config,
    running: &Arc<AtomicBool>,
    reload_config: &Arc<AtomicBool>,
) -> Result<()> {
    let mut last_partial_cleanup = SystemTime::now();
    let mut last_new_file_check = SystemTime::now();

    let raw_fd = INOTIFY_RAW_FD.load(Ordering::Relaxed);
    if raw_fd < 0 {
        return Ok(());
    }

    while running.load(Ordering::Relaxed) {
        let current_interval = cfg.interval;

        let mut poll_fds = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ms = (current_interval as i32) * 1000;
        // SAFETY: `poll_fds` 是栈上的 `pollfd` 数组,fds 字段是 `setup_inotify` 中
        // 已打开并通过 inotify API 管理的 fd。`nfds=1` 严格匹配数组长度。
        // `timeout_ms` 是 i32 类型且 config_validate 保证 `current_interval ∈ [1, 60]`,
        // 乘 1000 后仍在 i32 正数范围 (`60 * 1000 = 60000 << i32::MAX`)。
        let poll_result = unsafe { libc::poll(&mut poll_fds, 1, timeout_ms) };

        if poll_result > 0 {
            if let Some(inotify) = INOTIFY_FD.write().as_mut() {
                let mut buffer = [0u8; 4096];
                if let Ok(events) = inotify.read_events(&mut buffer) {
                    DAEMON_STATS.inotify_events.fetch_add(1, Ordering::Relaxed);
                    for event in events {
                        let wd = event.wd;
                        let file_states = FILE_STATES.read();
                        for (idx, state) in file_states.iter().enumerate() {
                            if state.wd.as_ref() == Some(&wd) {
                                if event.mask.contains(inotify::EventMask::MODIFY)
                                    || event.mask.contains(inotify::EventMask::MOVED_TO)
                                {
                                    let _ = read_and_process_new_lines(idx, cfg);
                                }
                                if event.mask.contains(inotify::EventMask::DELETE)
                                    || event.mask.contains(inotify::EventMask::MOVED_FROM)
                                {
                                    handle_log_rotation(idx, cfg);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } else if poll_result == 0 {
            if reload_config.load(Ordering::Relaxed) {
                reload_config.store(false, Ordering::Relaxed);

                if let Err(_e) = reload_configuration(cfg) {
                    // 重载失败,继续使用旧配置
                }
                continue;
            }

            let now = SystemTime::now();
            if now
                .duration_since(last_partial_cleanup)
                .unwrap_or_default()
                .as_secs()
                >= 60
            {
                last_partial_cleanup = now;
                cleanup_partial_line_buffer(cfg);
            }

            if now
                .duration_since(last_new_file_check)
                .unwrap_or_default()
                .as_secs()
                >= 60
            {
                last_new_file_check = now;
                check_for_new_log_files(cfg);
            }
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }

    Ok(())
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_state_new() {
        let state = FileState::new();
        assert!(state.path.is_empty());
        assert_eq!(state.offset, 0);
        assert_eq!(state.inode, 0);
        assert!(state.wd.is_none());
        assert!(!state.symlink_detected);
    }
}
