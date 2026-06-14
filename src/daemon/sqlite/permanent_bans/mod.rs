//! SQLite 永久封禁操作模块
//!
//! # 模块结构
//!
//! - `operations`：永久封禁增删操作
//! - `queries`：永久封禁查询操作
//!
//! # 核心职责
//!
//! - 添加/删除永久封禁
//! - 批量添加永久封禁
//! - 检查 IP 是否在永久黑名单中
//! - 加载所有活跃永久封禁

mod operations;
mod queries;

pub use operations::{
    sqlite_add_permanent_ban, sqlite_add_permanent_bans_batch, sqlite_remove_permanent_ban,
};
pub use queries::{
    sqlite_is_permanent_banned, sqlite_is_permanent_banned_ipv6, sqlite_load_all_permanent_bans,
};

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
