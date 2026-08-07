//! 主监控循环模块
//!
//! 实现 `poll` 等待 inotify 事件 / SIGHUP / 周期维护的主事件循环。

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use anyhow::Result;
use inotify::WatchDescriptor;

use crate::config_reloader::{cleanup_partial_line_buffer, reload_configuration, rollback_config};
use crate::log_rotation::{check_for_new_log_files, handle_log_rotation};
use crate::types::{Config, DAEMON_STATS};

use super::periodic_tasks::{check_and_handle_ddos, record_history_snapshot, write_stats_snapshot};
use super::processor::process_new_lines;
use super::setup_inotify;
use super::state::{FILE_STATES, INOTIFY_STATE};

// ============================================================================
// 超时状态
// ============================================================================

/// 周期性任务的最后执行时间戳集合。
///
/// 封装主循环中 7 个独立的超时检查点，避免函数参数过多。
struct TimeoutState {
    /// Partial line 缓冲清理
    last_partial_cleanup: SystemTime,
    /// 新日志文件检查
    last_new_file_check: SystemTime,
    /// 统计快照写入
    last_stats_snapshot: SystemTime,
    /// DDoS 检测
    last_ddos_check: SystemTime,
    /// 历史数据快照（每 5 分钟）
    last_history_snapshot: SystemTime,
    /// 速率统计查询（每 2 秒）
    last_rates_query: SystemTime,
    /// 数据清理（封禁历史/信誉分/failed_hash，每 5 分钟）
    last_data_cleanup: SystemTime,
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
            last_stats_snapshot: now,
            last_ddos_check: now,
            last_history_snapshot: now,
            last_rates_query: now,
            last_data_cleanup: now,
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

    // 初始 fd 有效性检查
    if INOTIFY_STATE.raw_fd.load(Ordering::Relaxed) < 0 {
        crate::logger::error!(
            crate::logger::get(),
            "inotify raw fd 无效";
            "raw_fd" => INOTIFY_STATE.raw_fd.load(Ordering::Relaxed)
        );
        return Ok(());
    }

    while running.load(Ordering::Relaxed) {
        // 同步 GLOBAL_JAILS → cfg.jails 的 enabled 状态
        // API 修改 jail 启用/禁用时只更新 GLOBAL_JAILS，此处桥接到 cfg.jails
        // 使监控循环在下一个 poll 周期自动感知变更
        let mut jail_enabled_changed = false;
        if let Some(lock) = crate::http_exporter::GLOBAL_JAILS.get() {
            let global_jails = lock.read();
            for gj in global_jails.iter() {
                if let Some(cfg_jail) = cfg.jails.iter_mut().find(|j| j.name == gj.name) {
                    if cfg_jail.enabled != gj.enabled {
                        crate::logger::info!(
                            crate::logger::get(),
                            "Jail 启用状态同步";
                            "jail" => &gj.name,
                            "enabled" => gj.enabled
                        );
                        cfg_jail.enabled = gj.enabled;
                        jail_enabled_changed = true;
                    }
                }
            }
        }
        // jail enabled 变化后重建 inotify watch（启用 → 添加 watch，禁用 → 跳过）
        if jail_enabled_changed {
            if let Err(e) = setup_inotify(cfg) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "Jail 启用状态变更后重建 inotify 失败";
                    "error" => %e
                );
            }
        }

        let current_interval = cfg.interval;

        // 每次迭代重新读取 raw_fd（支持 reload 时更换 inotify 实例）
        let raw_fd = INOTIFY_STATE.raw_fd.load(Ordering::Relaxed);
        if raw_fd < 0 {
            // reload 失败导致 fd 无效，等待后重试
            std::thread::sleep(std::time::Duration::from_secs(current_interval as u64));
            continue;
        }

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
            crate::logger::debug!(
                crate::logger::get(),
                "poll 返回有事件";
                "poll_result" => poll_result
            );
            // 优先检查配置回滚标志（SIGUSR1 触发）
            if crate::signals::GLOBAL_ROLLBACK.load(Ordering::Relaxed) {
                crate::signals::GLOBAL_ROLLBACK.store(false, Ordering::Relaxed);
                if let Err(e) = rollback_config(cfg) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "配置回滚失败";
                        "error" => %e
                    );
                } else {
                    crate::logger::info!(crate::logger::get(), "配置回滚成功");
                }
            } else if reload_config.load(Ordering::Relaxed) {
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
            } else {
                handle_inotify_events(cfg);
            }
        } else if poll_result == 0 {
            // poll 超时：执行周期性维护任务（配置重载、数据清理、DDoS 检测等）
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
    // 读取 inotify 事件到 Vec 后立即释放 INOTIFY_STATE.fd 写锁
    let collected_events: Vec<(WatchDescriptor, inotify::EventMask)> = {
        if let Some(inotify) = INOTIFY_STATE.fd.write().as_mut() {
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
        let file_info = {
            let file_states = FILE_STATES.read();
            file_states
                .iter()
                .enumerate()
                .find(|(_, state)| state.wd.as_ref() == Some(&wd))
                .map(|(idx, state)| (idx, state.is_config))
        };

        let Some((idx, is_config)) = file_info else {
            continue;
        };

        // 配置文件变化：触发热重载
        if is_config {
            if mask.contains(inotify::EventMask::MODIFY)
                || mask.contains(inotify::EventMask::CLOSE_WRITE)
                || mask.contains(inotify::EventMask::ATTRIB)
                || mask.contains(inotify::EventMask::MOVE_SELF)
                || mask.contains(inotify::EventMask::DELETE_SELF)
            {
                crate::logger::info!(
                    crate::logger::get(),
                    "检测到配置文件变化，自动重载";
                    "path" => &FILE_STATES.read()[idx].path
                );
                if let Err(e) = reload_configuration(cfg) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "配置自动重载失败";
                        "error" => %e
                    );
                } else {
                    crate::logger::info!(crate::logger::get(), "配置自动重载成功");
                }
            }
            continue;
        }

        // 日志文件：内容变更
        if mask.contains(inotify::EventMask::MODIFY)
            || mask.contains(inotify::EventMask::CLOSE_WRITE)
            || mask.contains(inotify::EventMask::ATTRIB)
        {
            if let Err(e) = process_new_lines(idx, cfg) {
                crate::logger::debug!(
                    crate::logger::get(),
                    "处理日志行失败";
                    "error" => %e
                );
            }
        }
        // 文件自身被 rename/unlink：重新挂到路径上的新 inode
        if mask.contains(inotify::EventMask::MOVE_SELF)
            || mask.contains(inotify::EventMask::DELETE_SELF)
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
    // duration_since 在时钟回拨时返回 Err, unwrap_or_default() → Duration::ZERO,
    // 0 >= 60 为 false, 定时器不触发, 直到时钟恢复 → 正确行为, 无需 saturating_duration_since
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

    // 历史数据快照（每 5 分钟）
    if now
        .duration_since(state.last_history_snapshot)
        .unwrap_or_default()
        .as_secs()
        >= 300
    {
        state.last_history_snapshot = now;
        record_history_snapshot(cfg);
    }

    // 数据清理：failed_hash 过期条目 + 封禁历史 + 信誉分恢复/清理（每 5 分钟）
    if now
        .duration_since(state.last_data_cleanup)
        .unwrap_or_default()
        .as_secs()
        >= 300
    {
        state.last_data_cleanup = now;
        super::perform_data_cleanup(cfg);
    }

    // 速率统计查询（每 2 秒）- 通过 netlink 从内核获取
    // 改进：从 5 秒缩短到 2 秒，提升 Web UI 数据实时性
    // 开销：~1.3ms / 2s = 0.65ms/s（可忽略）
    if now
        .duration_since(state.last_rates_query)
        .unwrap_or_default()
        .as_secs()
        >= 2
    {
        state.last_rates_query = now;
        query_rates_from_kernel();

        // 下发基线更新到内核（动态阈值）
        // 在速率查询后立即发送，确保内核使用最新基线进行违规检测
        send_baseline_update();
    }
}

/// 通过 netlink 查询内核的速率统计数据
fn query_rates_from_kernel() {
    use crate::netlink::get_global_netlink_ctx;

    if let Some(ctx) = get_global_netlink_ctx() {
        // 使用递增的序列号
        static RATES_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
        let seq = RATES_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = ctx.send_list_rates_query(seq) {
            crate::logger::debug!(
                crate::logger::get(),
                "发送速率查询失败";
                "error" => %e
            );
        }
    }
}

/// 下发基线更新到内核（动态阈值）
///
/// 从全局 EWMA 基线缓存读取当前值，通过 netlink BASELINE_UPDATE 发送到内核。
/// 内核在 check_rate_violation 中使用 max(静态阈值, 基线×倍数) 作为实际阈值。
///
/// 基线保护：业务高峰期（9-18 点 UTC）基线自动上调 50%，
/// 避免正常业务流量增长被误判为攻击。
fn send_baseline_update() {
    use crate::netlink::get_global_netlink_ctx;
    use crate::netlink::{config_flags, ConfigUpdate};

    let baseline_pps = crate::types::get_baseline_pps();
    let baseline_bps = crate::types::get_baseline_bps();

    // 基线为零时不下发（尚未收敛）
    if baseline_pps == 0 && baseline_bps == 0 {
        return;
    }

    // 基线保护：业务高峰期上调 50%
    let now_hour = chrono::Utc::now()
        .format("%H")
        .to_string()
        .parse::<u32>()
        .unwrap_or(0);
    let is_peak_hours = (9..18).contains(&now_hour);
    let (effective_pps, effective_bps) = if is_peak_hours {
        (baseline_pps * 3 / 2, baseline_bps * 3 / 2)
    } else {
        (baseline_pps, baseline_bps)
    };

    // 只在有效基线变化时发送，避免每 2 秒重复发送相同值
    static LAST_SENT_PPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    static LAST_SENT_BPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    let last_pps = LAST_SENT_PPS.load(std::sync::atomic::Ordering::Relaxed);
    let last_bps = LAST_SENT_BPS.load(std::sync::atomic::Ordering::Relaxed);

    if effective_pps == last_pps && effective_bps == last_bps {
        return; // 有效基线未变化，跳过发送
    }

    LAST_SENT_PPS.store(effective_pps, std::sync::atomic::Ordering::Relaxed);
    LAST_SENT_BPS.store(effective_bps, std::sync::atomic::Ordering::Relaxed);

    if let Some(ctx) = get_global_netlink_ctx() {
        let config = ConfigUpdate::new(config_flags::BASELINE_UPDATE)
            .with_baseline(effective_pps, effective_bps);

        if let Err(e) = ctx.send_config_update(&config) {
            crate::logger::debug!(
                crate::logger::get(),
                "发送基线更新失败";
                "error" => %e
            );
        }
    }
}

/// 获取基线保护状态（Web UI 显示用）
pub fn is_baseline_peak_hours() -> bool {
    let now_hour = chrono::Utc::now()
        .format("%H")
        .to_string()
        .parse::<u32>()
        .unwrap_or(0);
    (9..18).contains(&now_hour)
}
