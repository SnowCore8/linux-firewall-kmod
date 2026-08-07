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
        ips_banned: crate::types::DAEMON_STATS
            .ips_banned
            .load(Ordering::Relaxed),
        failed_attempts: crate::types::DAEMON_STATS
            .failed_attempts
            .load(Ordering::Relaxed),
        ddos_events: crate::types::DDOS_STATS
            .events_detected
            .load(Ordering::Relaxed),
    };

    // 计算差值
    let mut last_stats = LAST_SNAPSHOT_STATS
        .lock()
        .expect("LAST_SNAPSHOT_STATS 互斥锁中毒");
    let bans_diff = current_stats
        .ips_banned
        .saturating_sub(last_stats.ips_banned);
    let failed_diff = current_stats
        .failed_attempts
        .saturating_sub(last_stats.failed_attempts);
    let ddos_diff = current_stats
        .ddos_events
        .saturating_sub(last_stats.ddos_events);

    // 更新上次快照
    *last_stats = current_stats;

    // 记录到历史数据库
    if let Err(e) = crate::history_snapshot::record_snapshot(now, bans_diff, failed_diff, ddos_diff)
    {
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

/// 执行数据清理任务：failed_hash 清理 + 封禁历史清理 + 信誉分恢复/清理。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn perform_data_cleanup(cfg: &Config) {
    let now_secs = crate::types::now_secs();

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

    // 清理过期封禁历史（7 天无活动的内存条目，防止长期运行内存泄漏）
    if let Some(history) = crate::types::BAN_HISTORY.get() {
        history.cleanup_expired();
    }

    // 恢复信誉分（每小时 +1，补偿两次快照之间的时间流逝）
    crate::ip_reputation::get_store().recover_scores();

    // 清理信誉分已恢复至 100 且 24 小时无活动的条目（防止内存泄漏）
    let rep_cleaned = crate::ip_reputation::get_store().cleanup_stale();
    if rep_cleaned > 0 {
        crate::logger::debug!(
            crate::logger::get(),
            "清理过期信誉分条目";
            "removed" => rep_cleaned
        );
    }

    // 清理 DDoS 决策引擎中过期的 IP 跟踪器（防止 ip_trackers HashMap 无限增长）
    if let Some(engine) = crate::http_exporter::get_global_decision_engine() {
        let before = engine.tracked_ips_count();
        engine.cleanup_stale_trackers();
        let after = engine.tracked_ips_count();
        if before > after {
            crate::logger::debug!(
                crate::logger::get(),
                "清理过期 DDoS IP 跟踪器";
                "removed" => before - after,
                "remaining" => after
            );
        }
    }

    crate::logger::debug!(crate::logger::get(), "数据清理完成");
}

// ============================================================================
// DDoS 检测
// ============================================================================

/// 用户态网络层 DDoS 检测已下沉到 kmod；此入口保留为空操作，避免误启双封禁。
///
/// 应用层检测（SSH 暴力破解等）仍由日志 jail / failed_tracker 负责。
pub fn check_and_handle_ddos(_cfg: &Config) {
    // intentionally empty
}
