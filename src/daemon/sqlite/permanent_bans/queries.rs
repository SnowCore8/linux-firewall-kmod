//! 永久封禁查询操作

use anyhow::Result;

use rusqlite::params;

use crate::sqlite::connection::{PermanentBanEntry, SqliteDb};

// ============================================================================
// 查询操作
// ============================================================================
pub fn sqlite_is_permanent_banned(db: &SqliteDb, ip_num: u32) -> Result<i32> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT 1 FROM permanent_banlist WHERE ip_num = ?1 AND is_active = 1 LIMIT 1",
    )?;

    let exists: Option<i32> = stmt
        .query_row(params![i64::from(ip_num)], |row| row.get(0))
        .ok();
    Ok(exists.unwrap_or(0))
}

/// 检查 IPv6 字符串是否在永久黑名单中 (按 `ip` 文本查)。
pub fn sqlite_is_permanent_banned_ipv6(db: &SqliteDb, ip: &str) -> Result<i32> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare_cached(
        "SELECT 1 FROM permanent_banlist WHERE ip = ?1 AND is_active = 1 LIMIT 1",
    )?;

    let exists: Option<i32> = stmt.query_row(params![ip], |row| row.get(0)).ok();
    Ok(exists.unwrap_or(0))
}

/// 软删除 (`is_active=0`),实际记录保留供审计。
pub fn sqlite_load_all_permanent_bans(
    db: &SqliteDb,
) -> Result<Vec<PermanentBanEntry>> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare(
        "SELECT id, ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active
         FROM permanent_banlist WHERE is_active = 1 ORDER BY created_at",
    )?;

    let entries = stmt
        .query_map([], |row| {
            Ok(PermanentBanEntry {
                id: row.get(0)?,
                ip: row.get(1)?,
                ip_num: row.get::<_, i64>(2)? as u32,
                reason: row.get(3)?,
                created_at: row.get(4)?,
                created_by: row.get(5)?,
                hit_count: row.get(6)?,
                last_hit_at: row.get(7)?,
                is_active: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    Ok(entries)
}
