//! 周期性任务模块
//!
//! 包含主循环中超时触发的周期性维护任务：统计快照、数据清理、DDoS 检测。

use std::time::SystemTime;

use crate::types::Config;

// ============================================================================
// 统计快照写入
// ============================================================================

/// 写入守护进程和 jail 的统计快照到 SQLite。
///
/// 每 60 秒调用一次，记录当前系统状态用于监控和审计。
///
/// # Arguments
/// - `cfg`: 全局配置（预留，当前未使用）
pub fn write_stats_snapshot(_cfg: &Config) {
    let now = SystemTime::now();
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    if let Some(db) = crate::sqlite::get_global_db() {
        let conn = crate::sqlite::get_conn(&db);

        // 写入全局守护进程统计快照
        let daemon_stats = crate::sqlite_writer::DaemonStatsSnapshot {
            snapshot_time: now_secs,
            uptime_seconds: (now_secs
                - crate::types::DAEMON_STATS
                    .start_time
                    .load(std::sync::atomic::Ordering::Relaxed) as i64)
                .max(0) as u64,
            total_lines_parsed: crate::types::DAEMON_STATS
                .lines_parsed
                .load(std::sync::atomic::Ordering::Relaxed),
            total_ips_banned: crate::types::DAEMON_STATS
                .ips_banned
                .load(std::sync::atomic::Ordering::Relaxed),
            total_failed: crate::types::DAEMON_STATS
                .failed_attempts
                .load(std::sync::atomic::Ordering::Relaxed),
            active_ban_count: crate::types::ACTIVE_BAN_CACHE
                .get()
                .map(|c| c.len())
                .unwrap_or(0) as u64,
            kernel_ban_count: 0,
        };
        if let Err(e) = crate::sqlite_writer::insert_daemon_stats(&conn, &daemon_stats) {
            crate::logger::warn!(
                crate::logger::get(),
                "写入守护进程统计快照失败";
                "error" => %e
            );
        }

        // 写入 per-jail 统计快照
        if let Some(map) = crate::types::JAIL_STATS.get() {
            let read_guard = map.read();
            for (_jail_name, counters) in read_guard.iter() {
                let snapshot = counters.snapshot();
                let jail_stats = crate::sqlite_writer::JailStatsSnapshot {
                    jail_name: snapshot.jail_name.clone(),
                    snapshot_time: now_secs,
                    lines_parsed: snapshot.lines_parsed,
                    ips_extracted: snapshot.ips_extracted,
                    bans_triggered: snapshot.bans_triggered,
                    failed_attempts: snapshot.failed_attempts,
                    active_bans: crate::types::ACTIVE_BAN_CACHE
                        .get()
                        .map(|cache| cache.get_by_jail(&snapshot.jail_name).len())
                        .unwrap_or(0) as u64,
                };
                if let Err(e) = crate::sqlite_writer::insert_jail_stats(&conn, &jail_stats) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "写入 jail 统计快照失败";
                        "jail" => &snapshot.jail_name,
                        "error" => %e
                    );
                }
            }
        }

        crate::logger::debug!(crate::logger::get(), "统计快照写入完成");
    } else {
        // SQLite 不可用时记录警告（降级模式）
        crate::logger::warn!(
            crate::logger::get(),
            "SQLite 全局数据库未初始化，跳过统计快照写入（降级模式）"
        );
    }
}

// ============================================================================
// 数据清理
// ============================================================================

/// 执行数据清理任务：过期封禁清理、failed_hash 清理、SQLite 历史数据清理。
///
/// 按 `retention.cleanup_interval_secs` 间隔调用。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn perform_data_cleanup(cfg: &Config) {
    let now = SystemTime::now();
    let now_secs = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

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
            // 标记 dirty，同步到 SQLite
            crate::sqlite_writer::mark_dirty();
        }
    }

    // 清理各 jail 的 failed_hash 中过期条目（防止内存泄漏）
    let now_secs_for_cleanup = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    for jail in cfg.jails.iter() {
        if jail.enabled {
            let removed = crate::failed_tracker::cleanup_expired_entries(
                jail,
                now_secs_for_cleanup,
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

    if let Some(db) = crate::sqlite::get_global_db() {
        let conn = crate::sqlite::get_conn(&db);

        if let Err(e) = crate::sqlite_writer::cleanup_old_data(
            &conn,
            cfg.storage.retention.ban_history_days,
            cfg.storage.retention.failed_logs_days,
            cfg.storage.retention.jail_stats_days,
            cfg.storage.retention.ddos_events_days,
        ) {
            crate::logger::warn!(
                crate::logger::get(),
                "清理过期数据失败";
                "error" => %e
            );
        } else {
            crate::logger::debug!(
                crate::logger::get(),
                "过期数据清理完成";
                "ban_history_days" => cfg.storage.retention.ban_history_days,
                "failed_logs_days" => cfg.storage.retention.failed_logs_days
            );
        }
    } else {
        // SQLite 不可用时记录警告（降级模式）
        crate::logger::warn!(
            crate::logger::get(),
            "SQLite 全局数据库未初始化，跳过过期数据清理（降级模式）"
        );
    }
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
            "DDoS 检测完成";
            "events_detected" => events.len()
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

            if let Some(db) = crate::sqlite::get_global_db() {
                let conn = crate::sqlite::get_conn(&db);
                if let Err(e) = crate::sqlite_writer::insert_ddos_event(
                    &conn,
                    &event.ip,
                    &event.event_type,
                    event.rate_per_second,
                    event.threshold,
                    event.detected_at,
                    &event.action_taken,
                ) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "记录 DDoS 事件失败";
                        "ip" => &event.ip,
                        "error" => %e
                    );
                }
            }
        }
    }

    tracker.cleanup_stale_entries();
}
