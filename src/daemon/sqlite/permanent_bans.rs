//! SQLite 永久封禁操作模块
//!
//! # 核心职责
//!
//! - 添加/删除永久封禁
//! - 批量添加永久封禁
//! - 检查 IP 是否在永久黑名单中
//! - 加载所有活跃永久封禁
//! - 表结构初始化和迁移

use anyhow::{bail, Context, Result};
use rusqlite::{params, Connection};

use super::connection::SqliteDb;

// ============================================================================
// 永久封禁操作
// ============================================================================

/// 添加单条永久封禁。
///
/// # Arguments
/// - `db`: db 句柄
/// - `ip`: 已通过 [`crate::ban::validate_ip`] 的字符串
/// - `ip_num`: IPv4 网络字节序;IPv6 传 0
/// - `reason`: 封禁原因
/// - `created_by`: 创建者标识
///
/// # Returns
/// - `Ok(0)`: 新插入成功
/// - `Ok(-2)`: 已存在 (UNIQUE 约束冲突,静默忽略)
/// - `Err`: 其他 `SQLite` 错误
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

/// 检查 IPv4 是否在永久黑名单中 (按 `ip_num` 查索引)。
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

/// 加载所有活跃永久封禁。`main()` 启动时调,把条目逐个 `ban::ban_ip_permanent`
/// 恢复到内核。
pub fn sqlite_load_all_permanent_bans(
    db: &SqliteDb,
) -> Result<Vec<super::connection::PermanentBanEntry>> {
    let conn = db.conn.lock();
    let mut stmt = conn.prepare(
        "SELECT id, ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active
         FROM permanent_banlist WHERE is_active = 1 ORDER BY created_at",
    )?;

    let entries = stmt
        .query_map([], |row| {
            Ok(super::connection::PermanentBanEntry {
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

// ============================================================================
// 表结构初始化 + 迁移
// ============================================================================

pub(crate) fn init_db_schema(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS permanent_banlist_new (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            ip_num INTEGER NOT NULL DEFAULT 0,
            reason TEXT DEFAULT 'auto-ban',
            created_at INTEGER NOT NULL,
            created_by TEXT DEFAULT 'auto',
            hit_count INTEGER DEFAULT 0,
            last_hit_at INTEGER,
            is_active INTEGER DEFAULT 1
        );",
    )
    .context("Failed to create permanent_banlist_new table")?;

    let new_table_empty: bool = conn.query_row(
        "SELECT COUNT(*) = 0 FROM permanent_banlist_new",
        [],
        |row| row.get(0),
    )?;

    let old_table_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='permanent_banlist'",
        [],
        |row| row.get(0),
    )?;

    if new_table_empty && old_table_exists {
        let tx = conn.transaction()?;

        tx.execute(
            "DELETE FROM permanent_banlist WHERE rowid NOT IN (
                SELECT MIN(rowid) FROM permanent_banlist GROUP BY ip
            )",
            [],
        )?;

        tx.execute(
            "INSERT OR IGNORE INTO permanent_banlist_new
             (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active)
             SELECT ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active
             FROM permanent_banlist",
            [],
        )?;

        tx.execute_batch(
            "DROP TABLE IF EXISTS permanent_banlist;
             ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        )?;

        tx.commit()?;
    } else if !new_table_empty {
        let _ = conn.execute_batch("DROP TABLE IF EXISTS permanent_banlist_new;");
    } else {
        let _ = conn.execute_batch(
            "DROP TABLE IF EXISTS permanent_banlist;
             ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        );
    }

    let _ = conn.execute_batch("DROP INDEX IF EXISTS idx_ip_num_unique;");

    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_ip_num ON permanent_banlist(ip_num);
         CREATE INDEX IF NOT EXISTS idx_is_active ON permanent_banlist(is_active);",
    )
    .context("Failed to create indexes")?;

    Ok(())
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::connection::{sqlite_close, sqlite_init};
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1000);

    fn temp_db_path() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir =
            std::env::temp_dir().join(format!("fw_sqlite_perm_test_{}_{}", std::process::id(), n));
        fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test.db").to_string_lossy().to_string();
        let _ = fs::remove_file(&path);
        path
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_file(path);
        if let Some(dir) = std::path::Path::new(path).parent() {
            let _ = fs::remove_dir(dir);
        }
    }

    #[test]
    fn sqlite_add_and_query_ban() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let rc =
            sqlite_add_permanent_ban(&db, "192.168.1.100", 0xC0A80164, "test ban", "auto").unwrap();
        assert_eq!(rc, 0);

        let banned = sqlite_is_permanent_banned(&db, 0xC0A80164).unwrap();
        assert_eq!(banned, 1);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_duplicate_ban_returns_minus2() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let rc1 = sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "test", "auto").unwrap();
        assert_eq!(rc1, 0);

        let rc2 = sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "test2", "auto").unwrap();
        assert_eq!(rc2, -2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_remove_ban() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "10.0.0.2", 0x0A000002, "test", "auto").unwrap();
        let rc = sqlite_remove_permanent_ban(&db, "10.0.0.2").unwrap();
        assert_eq!(rc, 0);

        let banned = sqlite_is_permanent_banned(&db, 0x0A000002).unwrap();
        assert_eq!(banned, 0);

        let rc2 = sqlite_remove_permanent_ban(&db, "10.0.0.2").unwrap();
        assert_eq!(rc2, -2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_load_all_bans() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "1.1.1.1", 0x01010101, "ban1", "auto").unwrap();
        sqlite_add_permanent_ban(&db, "2.2.2.2", 0x02020202, "ban2", "manual").unwrap();

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].ip, "1.1.1.1");
        assert_eq!(entries[1].ip, "2.2.2.2");

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_success() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"];
        let ip_nums = vec![0x0A000001, 0x0A000002, 0x0A000003];
        let reasons = vec!["reason1", "reason2", "reason3"];
        let created_bys = vec!["auto", "auto", "manual"];

        let success_count =
            sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys).unwrap();
        assert_eq!(success_count, 3);

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 3);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_skips_duplicates() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "10.0.0.1", 0x0A000001, "first", "auto").unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2"];
        let ip_nums = vec![0x0A000001, 0x0A000002];
        let reasons = vec!["dup", "new"];
        let created_bys = vec!["auto", "auto"];

        let success_count =
            sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys).unwrap();
        assert_eq!(success_count, 1);

        let entries = sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries.len(), 2);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn sqlite_add_permanent_bans_batch_invalid_length() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        let ips = vec!["10.0.0.1", "10.0.0.2"];
        let ip_nums = vec![0x0A000001];
        let reasons = vec!["r1", "r2"];
        let created_bys = vec!["auto", "auto"];

        let result = sqlite_add_permanent_bans_batch(&db, &ips, &ip_nums, &reasons, &created_bys);
        assert!(result.is_err());

        sqlite_close(&db);
        cleanup(&path);
    }
}
