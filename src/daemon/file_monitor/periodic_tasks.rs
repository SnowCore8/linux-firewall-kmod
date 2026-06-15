//! 周期性任务模块
//!
//! 包含主循环中超时触发的周期性维护任务：统计快照、数据清理、DDoS 检测。

use crate::types::Config;
use std::sync::atomic::Ordering;

// ============================================================================
// 统计快照写入
// ============================================================================

/// 上次快照的统计数据（用于计算差值）
static LAST_SNAPSHOT_STATS: once_cell::sync::Lazy<std::sync::Mutex<SnapshotStats>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(SnapshotStats::default()));

/// 快照统计数据
#[derive(Default, Clone)]
struct SnapshotStats {
    ips_banned: u64,
    failed_attempts: u64,
    ddos_events: u64,
}

/// 写入守护进程和 jail 的统计快照（纯内存，无持久化）。
///
/// 每 60 秒调用一次，记录当前系统状态用于监控。
///
/// # Arguments
/// - `cfg`: 全局配置（预留，当前未使用）
pub fn write_stats_snapshot(_cfg: &Config) {
    // 统计信息仅通过 Prometheus 指标暴露
    crate::logger::debug!(crate::logger::get(), "统计快照更新完成（纯内存）");
}

/// 记录历史数据快照（每 5 分钟调用一次）。
///
/// 计算与上次快照的差值，并存储到 SQLite 历史数据库。
///
/// # Arguments
/// - `_cfg`: 全局配置（预留）
pub fn record_history_snapshot(_cfg: &Config) {
    let now = crate::types::now_secs();

    // 获取当前统计数据
    let current_stats = SnapshotStats {
        ips_banned: crate::types::DAEMON_STATS.ips_banned.load(Ordering::Relaxed),
        failed_attempts: crate::types::DAEMON_STATS.failed_attempts.load(Ordering::Relaxed),
        ddos_events: crate::types::DDOS_STATS.events_detected.load(Ordering::Relaxed),
    };

    // 计算差值
    let mut last_stats = LAST_SNAPSHOT_STATS.lock().unwrap();
    let bans_diff = current_stats.ips_banned.saturating_sub(last_stats.ips_banned);
    let failed_diff = current_stats.failed_attempts.saturating_sub(last_stats.failed_attempts);
    let ddos_diff = current_stats.ddos_events.saturating_sub(last_stats.ddos_events);

    // 更新上次快照
    *last_stats = current_stats;

    // 记录到历史数据库
    if let Err(e) = crate::history_snapshot::record_snapshot(now, bans_diff, failed_diff, ddos_diff) {
        crate::logger::warn!(
            crate::logger::get(),
            "记录历史快照失败";
            "error" => %e
        );
    } else {
        crate::logger::debug!(
            crate::logger::get(),
            "历史快照记录成功";
            "bans" => bans_diff,
            "failed" => failed_diff,
            "ddos" => ddos_diff
        );
    }
}

// ============================================================================
// 数据清理
// ============================================================================

/// 执行数据清理任务：过期封禁清理、failed_hash 清理。
///
/// 按 `retention.cleanup_interval_secs` 间隔调用。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn perform_data_cleanup(cfg: &Config) {
    let now_secs = crate::types::now_secs();

    // 清理过期的临时封禁
    if let Some(cache) = crate::types::ACTIVE_BAN_CACHE.get() {
        let expired = cache.purge_expired(now_secs);
        if !expired.is_empty() {
            crate::logger::info!(
                crate::logger::get(),
                "清理过期临时封禁";
                "count" => expired.len()
            );
            for ban_info in &expired {
                // 从内核移除
                if let Err(e) = crate::ban::unban_ip(&ban_info.ip) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "解封过期封禁失败";
                        "ip" => &ban_info.ip,
                        "error" => %e
                    );
                }
            }
        }
    }

    // 清理各 jail 的 failed_hash 中过期条目（防止内存泄漏）
    for jail in cfg.jails.iter() {
        if jail.enabled {
            let removed = crate::failed_tracker::cleanup_expired_entries(
                jail,
                now_secs,
                jail.findtime as i64,
            );
            if removed > 0 {
                crate::logger::debug!(
                    crate::logger::get(),
                    "清理 failed_hash 过期条目";
                    "jail" => &jail.name,
                    "removed" => removed
                );
            }
        }
    }

    crate::logger::debug!(crate::logger::get(), "数据清理完成");
}

// ============================================================================
// DDoS 检测
// ============================================================================

/// 执行 DDoS 检测并处理检测到的事件。
///
/// 按 `ddos.check_interval` 间隔调用。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn check_and_handle_ddos(cfg: &Config) {
    let tracker = crate::ddos_detector::get_conn_rate_tracker();
    let events = tracker.detect(&cfg.ddos);

    if !events.is_empty() {
        crate::logger::info!(
            crate::logger::get(),
            "DDoS 检测到异常事件";
            "events_count" => events.len()
        );

        for event in &events {
            if event.action_taken == "ban" && event.ip != "global" {
                if let Err(e) = crate::ban::ban_ip_with_history(
                    &event.ip,
                    "ddos_detector",
                    0,
                    cfg.ddos.auto_ban_duration as u64,
                ) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "DDoS 自动封禁失败";
                        "ip" => &event.ip,
                        "error" => %e
                    );
                } else {
                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 自动封禁成功";
                        "ip" => &event.ip,
                        "event_type" => &event.event_type,
                        "rate" => event.rate_per_second,
                        "threshold" => event.threshold
                    );
                }
            }
        }
    }

    tracker.cleanup_stale_entries();
}
