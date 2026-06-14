//! 数据清理与工具函数

use anyhow::Result;
use rusqlite::Connection;

/// 清理过期数据（按保留天数）
pub fn cleanup_old_data(
    conn: &Connection,
    ban_history_days: u32,
    failed_logs_days: u32,
    jail_stats_days: u32,
    ddos_events_days: u32,
) -> Result<()> {
    let now = crate::types::now_secs();

    let tx = conn.unchecked_transaction()?;

    // 清理已过期且超过保留期的封禁历史
    let cutoff = now - (ban_history_days as i64) * 86400;
    tx.execute(
        "DELETE FROM ban_history WHERE banned_at < ?1 AND status != 'active'",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的失败日志
    let cutoff = now - (failed_logs_days as i64) * 86400;
    tx.execute(
        "DELETE FROM failed_attempt_logs WHERE window_end < ?1",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的 Jail 统计
    let cutoff = now - (jail_stats_days as i64) * 86400;
    tx.execute(
        "DELETE FROM jail_stats_snapshots WHERE snapshot_time < ?1",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的 DDoS 事件
    let cutoff = now - (ddos_events_days as i64) * 86400;
    tx.execute(
        "DELETE FROM ddos_events WHERE detected_at < ?1",
        rusqlite::params![cutoff],
    )?;

    tx.commit()?;
    Ok(())
}

/// 获取 WAL 文件大小（字节）
pub fn get_wal_size(db_path: &str) -> u64 {
    let wal_path = format!("{}-wal", db_path);
    std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0)
}
