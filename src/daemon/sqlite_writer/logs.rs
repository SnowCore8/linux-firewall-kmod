//! 失败尝试日志操作

use anyhow::Result;
use rusqlite::Connection;

/// 插入失败尝试聚合记录
pub fn insert_failed_log(
    conn: &Connection,
    ip: &str,
    jail_name: &str,
    fail_count: u32,
    window_start: i64,
    window_end: i64,
    triggered_ban: bool,
) -> Result<()> {
    conn.execute(
        "INSERT INTO failed_attempt_logs (ip, jail_name, fail_count, window_start, window_end, triggered_ban)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![ip, jail_name, fail_count, window_start, window_end, triggered_ban as i32],
    )?;
    Ok(())
}
