//! SQLite 统计查询模块
//!
//! # 核心职责
//!
//! - 更新命中统计 (hit_count + last_hit_at)
//! - 获取统计信息 (总条数/活跃条数)
//! - 清理软删除记录
//! 统计查询 + 数据清理

use anyhow::Result;
use rusqlite::params;

use super::connection::SqliteDb;

// ============================================================================
// 统计操作
// ============================================================================

/// 累加 `hit_count` + 更新 `last_hit_at`。每次拦截命中永久黑名单的 IP 时调。
pub fn sqlite_update_hit_stats(db: &SqliteDb, ip_num: u32) -> Result<()> {
    let conn = db.conn.lock();
use super::SqliteDb;

/// 累加 `hit_count` + 更新 `last_hit_at`
pub fn sqlite_update_hit_stats(db: &SqliteDb, ip_num: u32) -> Result<()> {
    let conn = db.lock_conn();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    conn.execute(
        "UPDATE permanent_banlist SET hit_count = hit_count + 1, last_hit_at = ?1 WHERE ip_num = ?2 AND is_active = 1",
        params![now, i64::from(ip_num)],
    )?;

    Ok(())
}

/// 统计 (总条数, 活跃条数)。`/metrics` 或管理命令用。
pub fn sqlite_get_stats(db: &SqliteDb) -> Result<(i32, i32)> {
    let conn = db.conn.lock();
/// 统计 (总条数, 活跃条数)
pub fn sqlite_get_stats(db: &SqliteDb) -> Result<(i32, i32)> {
    let conn = db.lock_conn();
    let total: i32 = conn.query_row("SELECT COUNT(*) FROM permanent_banlist", [], |row| {
        row.get(0)
    })?;
    let active: i32 = conn.query_row(
        "SELECT COUNT(*) FROM permanent_banlist WHERE is_active = 1",
        [],
        |row| row.get(0),
    )?;
    Ok((total, active))
}

/// 清理软删除记录。
pub fn sqlite_purge_deleted(db: &SqliteDb, days: i32) -> Result<i32> {
    let conn = db.conn.lock();
/// 清理软删除记录
pub fn sqlite_purge_deleted(db: &SqliteDb, days: i32) -> Result<i32> {
    let conn = db.lock_conn();
    if days > 0 {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            - (i64::from(days) * 86400);

        let changes = conn.execute(
            "DELETE FROM permanent_banlist WHERE is_active = 0 AND last_hit_at < ?1",
            params![cutoff],
        )?;
        Ok(changes as i32)
    } else {
        let changes = conn.execute("DELETE FROM permanent_banlist WHERE is_active = 0", [])?;
        Ok(changes as i32)
    }
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sqlite::connection::{sqlite_close, sqlite_init};
    use crate::sqlite::permanent_bans::sqlite_add_permanent_ban;
    use crate::sqlite::permanent_bans::sqlite_remove_permanent_ban;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(2000);
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(200);

    fn temp_db_path() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir =
            std::env::temp_dir().join(format!("fw_sqlite_stats_test_{}_{}", std::process::id(), n));
        fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test.db").to_string_lossy().to_string();
        let _ = fs::remove_file(&path);
        path
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_file(path);
        if let Some(dir) = Path::new(path).parent() {
            let _ = fs::remove_dir(dir);
        }
    }

    #[test]
    fn sqlite_stats() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "3.3.3.3", 0x03030303, "test", "auto").unwrap();
        let (total, active) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total, 1);
        assert_eq!(active, 1);

        sqlite_remove_permanent_ban(&db, "3.3.3.3").unwrap();
        let (total2, active2) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total2, 1); // 软删除, 记录仍在
        assert_eq!(total2, 1);
        assert_eq!(active2, 0);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn test_update_hit_stats() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "4.4.4.4", 0x04040404, "test", "auto").unwrap();
        sqlite_update_hit_stats(&db, 0x04040404).unwrap();

        let entries = crate::sqlite::permanent_bans::sqlite_load_all_permanent_bans(&db).unwrap();
        assert_eq!(entries[0].hit_count, 1);

        sqlite_close(&db);
        cleanup(&path);
    }

    #[test]
    fn test_purge_deleted() {
        let path = temp_db_path();
        let db = sqlite_init(&path).unwrap();

        sqlite_add_permanent_ban(&db, "5.5.5.5", 0x05050505, "test", "auto").unwrap();
        sqlite_remove_permanent_ban(&db, "5.5.5.5").unwrap();

        let purged = sqlite_purge_deleted(&db, 0).unwrap();
        assert_eq!(purged, 1);

        let (total, _) = sqlite_get_stats(&db).unwrap();
        assert_eq!(total, 0);

        sqlite_close(&db);
        cleanup(&path);
    }
}
