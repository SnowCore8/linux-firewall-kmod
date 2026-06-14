//! 统计快照操作

use anyhow::Result;
use rusqlite::Connection;

use super::{DaemonStatsSnapshot, JailStatsSnapshot, SqliteStats};

/// 插入 Jail 统计快照
pub fn insert_jail_stats(conn: &Connection, stats: &JailStatsSnapshot) -> Result<()> {
    conn.execute(
        "INSERT INTO jail_stats_snapshots (jail_name, snapshot_time, lines_parsed, ips_extracted, bans_triggered, failed_attempts, active_bans)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            stats.jail_name,
            stats.snapshot_time,
            stats.lines_parsed,
            stats.ips_extracted,
            stats.bans_triggered,
            stats.failed_attempts,
            stats.active_bans,
        ],
    )?;
    Ok(())
}

/// 插入 DDoS 事件记录
pub fn insert_ddos_event(
    conn: &Connection,
    ip: &str,
    event_type: &str,
    rate_per_second: f64,
    threshold: f64,
    detected_at: i64,
    action_taken: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO ddos_events (ip, event_type, rate_per_second, threshold, detected_at, action_taken)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![ip, event_type, rate_per_second, threshold, detected_at, action_taken],
    )?;
    Ok(())
}

/// 插入守护进程统计快照
pub fn insert_daemon_stats(conn: &Connection, stats: &DaemonStatsSnapshot) -> Result<()> {
    conn.execute(
        "INSERT INTO daemon_stats_snapshots (snapshot_time, uptime_seconds, total_lines_parsed, total_ips_banned, total_failed, active_ban_count, kernel_ban_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            stats.snapshot_time,
            stats.uptime_seconds,
            stats.total_lines_parsed,
            stats.total_ips_banned,
            stats.total_failed,
            stats.active_ban_count,
            stats.kernel_ban_count,
        ],
    )?;
    Ok(())
}

/// 获取 SQLite 统计信息
pub fn get_stats(conn: &Connection) -> Result<SqliteStats> {
    let ban_history_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM ban_history", [], |row| row.get(0))?;

    let ban_history_active: u64 = conn.query_row(
        "SELECT COUNT(*) FROM ban_history WHERE status = 'active'",
        [],
        |row| row.get(0),
    )?;

    let failed_logs_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM failed_attempt_logs", [], |row| {
            row.get(0)
        })?;

    let jail_stats_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM jail_stats_snapshots", [], |row| {
            row.get(0)
        })?;

    let ddos_events_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM ddos_events", [], |row| row.get(0))?;

    Ok(SqliteStats {
        ban_history_total,
        ban_history_active,
        failed_logs_total,
        jail_stats_total,
        ddos_events_total,
    })
}
