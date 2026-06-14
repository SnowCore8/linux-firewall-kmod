//! 主监控循环模块
//!
//! 实现 `poll` 等待 inotify 事件 / SIGHUP / 周期维护的主事件循环。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use anyhow::Result;
use inotify::WatchDescriptor;

use crate::config_reloader::{cleanup_partial_line_buffer, reload_configuration};
use crate::log_rotation::{check_for_new_log_files, handle_log_rotation};
use crate::types::{Config, DAEMON_STATS};

use super::periodic_tasks::{check_and_handle_ddos, perform_data_cleanup, write_stats_snapshot};
use super::processor::process_new_lines;
use super::state::{FILE_STATES, INOTIFY_FD, INOTIFY_RAW_FD};

// ============================================================================
// 超时状态
// ============================================================================

/// 周期性任务的最后执行时间戳集合。
///
/// 封装主循环中 6 个独立的超时检查点，避免函数参数过多。
struct TimeoutState {
    /// Partial line 缓冲清理
    last_partial_cleanup: SystemTime,
    /// 新日志文件检查
    last_new_file_check: SystemTime,
    /// SQLite dirty 标志同步
    last_sqlite_sync: SystemTime,
    /// 统计快照写入
    last_stats_snapshot: SystemTime,
    /// 数据清理
    last_data_cleanup: SystemTime,
    /// DDoS 检测
    last_ddos_check: SystemTime,
}

impl Default for TimeoutState {
    fn default() -> Self {
        Self::new()
    }
}

impl TimeoutState {
    /// 构造新的超时状态，所有时间戳初始化为当前时间。
    fn new() -> Self {
        let now = SystemTime::now();
        Self {
            last_partial_cleanup: now,
            last_new_file_check: now,
            last_sqlite_sync: now,
            last_stats_snapshot: now,
            last_data_cleanup: now,
            last_ddos_check: now,
        }
    }
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
    running: &AtomicBool,
    reload_config: &AtomicBool,
) -> Result<()> {
    let mut timeout_state = TimeoutState::new();

    let raw_fd = INOTIFY_RAW_FD.load(Ordering::Relaxed);
    if raw_fd < 0 {
        crate::logger::error!(
            crate::logger::get(),
            "inotify raw fd 无效";
            "raw_fd" => raw_fd
        );
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

        // poll_result 分 3 段处理: > 0 = 有事件 / = 0 = 超时 / < 0 = 错误
        if poll_result > 0 {
            handle_inotify_events(cfg);
        } else if poll_result == 0 {
            handle_timeout(cfg, reload_config, &mut timeout_state);
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            crate::logger::error!(
                crate::logger::get(),
                "poll 错误，退出主循环";
                "error" => %err
            );
            break;
        }
    }

    Ok(())
}

/// 处理 inotify 事件：读取事件并分发到相应的处理函数。
fn handle_inotify_events(cfg: &mut Config) {
    // 读取 inotify 事件到 Vec 后立即释放 INOTIFY_FD 写锁
    let collected_events: Vec<(WatchDescriptor, inotify::EventMask)> = {
        if let Some(inotify) = INOTIFY_FD.write().as_mut() {
            let mut buffer = [0u8; 4096];
            if let Ok(events) = inotify.read_events(&mut buffer) {
                DAEMON_STATS.inotify_events.fetch_add(1, Ordering::Relaxed);
                events.map(|e| (e.wd, e.mask)).collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };

    // 事件分发: 不持有任何全局锁调用处理函数
    for (wd, mask) in collected_events {
        let file_idx = {
            let file_states = FILE_STATES.read();
            file_states
                .iter()
                .enumerate()
                .find(|(_, state)| state.wd.as_ref() == Some(&wd))
                .map(|(idx, _)| idx)
        };

        let Some(idx) = file_idx else { continue };

        if mask.contains(inotify::EventMask::MODIFY) || mask.contains(inotify::EventMask::MOVED_TO)
        {
            if let Err(e) = process_new_lines(idx, cfg) {
                crate::logger::debug!(
                    crate::logger::get(),
                    "处理日志行失败";
                    "error" => %e
                );
            }
        }
        if mask.contains(inotify::EventMask::DELETE)
            || mask.contains(inotify::EventMask::MOVED_FROM)
        {
            handle_log_rotation(idx, cfg);
        }
    }
}

/// 处理超时事件：配置重载和周期性维护任务。
fn handle_timeout(cfg: &mut Config, reload_config: &AtomicBool, state: &mut TimeoutState) {
    if reload_config.load(Ordering::Relaxed) {
        reload_config.store(false, Ordering::Relaxed);

        if let Err(e) = reload_configuration(cfg) {
            crate::logger::warn!(
                crate::logger::get(),
                "配置重载失败";
                "error" => %e
            );
        } else {
            crate::logger::info!(crate::logger::get(), "配置重载成功");
        }
        return;
    }

    let now = SystemTime::now();

    // Partial line 清理 (每 60 秒)
    if now
        .duration_since(state.last_partial_cleanup)
        .unwrap_or_default()
        .as_secs()
        >= 60
    {
        state.last_partial_cleanup = now;
        cleanup_partial_line_buffer(cfg);
    }

    // 新文件检查 (每 60 秒)
    if now
        .duration_since(state.last_new_file_check)
        .unwrap_or_default()
        .as_secs()
        >= 60
    {
        state.last_new_file_check = now;
        check_for_new_log_files(cfg);
    }

    // SQLite dirty 标志清理
    if crate::sqlite_writer::is_dirty()
        && now
            .duration_since(state.last_sqlite_sync)
            .unwrap_or_default()
            .as_secs()
            >= cfg.storage.writer.flush_interval_secs as u64
    {
        state.last_sqlite_sync = now;
        crate::sqlite_writer::clear_dirty();
        crate::logger::debug!(crate::logger::get(), "SQLite dirty 标志已清理");
    }

    // 统计快照 (每 60 秒)
    if now
        .duration_since(state.last_stats_snapshot)
        .unwrap_or_default()
        .as_secs()
        >= 60
    {
        state.last_stats_snapshot = now;
        write_stats_snapshot(cfg);
    }

    // 数据清理
    if now
        .duration_since(state.last_data_cleanup)
        .unwrap_or_default()
        .as_secs()
        >= cfg.storage.retention.cleanup_interval_secs as u64
    {
        state.last_data_cleanup = now;
        perform_data_cleanup(cfg);
    }

    // DDoS 检测
    if cfg.ddos.enabled
        && now
            .duration_since(state.last_ddos_check)
            .unwrap_or_default()
            .as_secs()
            >= cfg.ddos.check_interval as u64
    {
        state.last_ddos_check = now;
        check_and_handle_ddos(cfg);
    }
}
