//! 封禁历史 CRUD 操作

use anyhow::Result;
use rusqlite::Connection;

use crate::types::{BanInfo, BanReason, BanStatus};

/// 插入封禁历史记录（定时器调用）
pub fn insert_ban_history(conn: &Connection, info: &BanInfo) -> Result<i64> {
    conn.execute(
        "INSERT INTO ban_history (ip, ip_num, jail_name, reason, banned_at, expires_at, status, fail_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            info.ip,
            info.ip_num,
            info.jail_name,
            info.reason.as_str(),
            info.banned_at,
            info.expires_at,
            BanStatus::Active.as_str(),
            info.fail_count,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 批量插入封禁历史（定时器调用，事务保证原子性）
///
/// 使用 `INSERT OR IGNORE` 跳过重复记录。返回值为实际插入的行数（不包含被跳过的重复项）。
pub fn insert_ban_history_batch(conn: &Connection, infos: &[BanInfo]) -> Result<usize> {
    let mut inserted = 0;
    let mut skipped = 0;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO ban_history (ip, ip_num, jail_name, reason, banned_at, expires_at, status, fail_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for info in infos {
            let affected = stmt.execute(rusqlite::params![
                info.ip,
                info.ip_num,
                info.jail_name,
                info.reason.as_str(),
                info.banned_at,
                info.expires_at,
                BanStatus::Active.as_str(),
                info.fail_count,
            ])?;
            if affected > 0 {
                inserted += 1;
            } else {
                skipped += 1;
            }
        }
    }
    tx.commit()?;
    if skipped > 0 {
        crate::logger::warn!(
            crate::logger::get(),
            "批量插入 ban_history 跳过重复记录";
            "inserted" => inserted,
            "skipped" => skipped,
            "total" => infos.len()
        );
    }
    Ok(inserted)
}

/// 更新封禁状态（解封/过期时调用）
pub fn update_ban_status(conn: &Connection, ip: &str, status: BanStatus) -> Result<usize> {
    let affected = conn.execute(
        "UPDATE ban_history SET status = ?1 WHERE ip = ?2 AND status = 'active'",
        rusqlite::params![status.as_str(), ip],
    )?;
    Ok(affected)
}

/// 批量更新封禁状态
pub fn update_ban_status_batch(
    conn: &Connection,
    ips: &[String],
    status: BanStatus,
) -> Result<usize> {
    let mut count = 0;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt =
            tx.prepare("UPDATE ban_history SET status = ?1 WHERE ip = ?2 AND status = 'active'")?;
        for ip in ips {
            count += stmt.execute(rusqlite::params![status.as_str(), ip])?;
        }
    }
    tx.commit()?;
    Ok(count)
}

/// 加载所有活跃封禁（启动时恢复）
pub fn load_active_bans(conn: &Connection) -> Result<Vec<BanInfo>> {
    let mut stmt = conn.prepare(
        "SELECT ip, ip_num, jail_name, reason, banned_at, expires_at, fail_count
         FROM ban_history WHERE status = 'active'",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(BanInfo {
            ip: row.get(0)?,
            ip_num: row.get(1)?,
            jail_name: row.get(2)?,
            reason: BanReason::parse(&row.get::<_, String>(3)?),
            banned_at: row.get(4)?,
            expires_at: row.get(5)?,
            is_permanent: row.get::<_, i64>(5)? == 0,
            fail_count: row.get(6)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}
