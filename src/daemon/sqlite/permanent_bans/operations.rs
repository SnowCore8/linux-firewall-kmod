//! 永久封禁增删操作

use anyhow::{bail, Result};
use rusqlite::params;

use crate::sqlite::connection::SqliteDb;

// ============================================================================
// 永久封禁操作
// ============================================================================
pub fn sqlite_add_permanent_ban(
    db: &SqliteDb,
    ip: &str,
    ip_num: u32,
    reason: &str,
    created_by: &str,
) -> Result<i64> {
    let conn = db.conn.lock();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let result = conn.execute(
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 1)",
        params![ip, i64::from(ip_num), reason, now, created_by],
    );

    match result {
        Ok(_) => Ok(0),
        Err(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ErrorCode::ConstraintViolation,
                ..
            },
            _,
        )) => Ok(-2),
        Err(e) => {
            bail!("SQLite insert failed: {e}");
        }
    }
}

/// 批量添加永久封禁:遇 UNIQUE 冲突跳过,遇其他错误立即回滚事务。
pub fn sqlite_add_permanent_bans_batch(
    db: &SqliteDb,
    ips: &[&str],
    ip_nums: &[u32],
    reasons: &[&str],
    created_bys: &[&str],
) -> Result<i32> {
    if ips.is_empty()
        || ips.len() != ip_nums.len()
        || ips.len() != reasons.len()
        || ips.len() != created_bys.len()
    {
        bail!("sqlite_add_permanent_bans_batch: invalid parameter");
    }

    let mut conn = db.conn.lock();
    let mut success_count: i32 = 0;
    let tx = conn.transaction()?;

    for i in 0..ips.len() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let result = tx.execute(
            "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, 1)",
            params![ips[i], i64::from(ip_nums[i]), reasons[i], now, created_bys[i]],
        );

        match result {
            Ok(_) => success_count += 1,
            Err(rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: rusqlite::ErrorCode::ConstraintViolation,
                    ..
                },
                _,
            )) => {}
            Err(e) => {
                let _ = tx.rollback();
                bail!("Batch insert failed at index {i}: {e}");
            }
        }
    }

    tx.commit()?;
    Ok(success_count)
}

// ============================================================================
// 删除操作
// ============================================================================

pub fn sqlite_remove_permanent_ban(db: &SqliteDb, ip: &str) -> Result<i32> {
    let conn = db.conn.lock();
    let changes = conn.execute(
        "UPDATE permanent_banlist SET is_active = 0 WHERE ip = ?1 AND is_active = 1",
        params![ip],
    )?;

    if changes > 0 {
        Ok(0)
    } else {
        Ok(-2)
    }
}
