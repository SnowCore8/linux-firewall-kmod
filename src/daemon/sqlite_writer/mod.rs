//! SQLite 定时器批量同步模块
//!
//! # 设计
//!
//! 不用异步 channel，采用定时器驱动的批量同步：
//! - 内存操作（ban/unban）立即生效，标记 dirty
//! - 主循环每 5 秒检查 dirty，批量同步到 SQLite
//! - 简单可靠，无后台线程，无 channel 背压
//!
//! # 同步策略
//!
//! ```text
//! 封禁操作:
//!   1. [同步] ActiveBanCache.insert() + 内核 procfs 写入
//!   2. [标记] dirty = true
//!   3. [定时器] 下次 tick 时批量 INSERT ban_history
//!
//! 解封操作:
//!   1. [同步] ActiveBanCache.remove() + 内核 procfs 写入
//!   2. [标记] dirty = true
//!   3. [定时器] 下次 tick 时批量 UPDATE status
//! ```

pub mod bans;
pub mod cleanup;
pub mod logs;
pub mod stats;
pub mod tables;

use std::sync::atomic::{AtomicBool, Ordering};

// ============================================================================
// 数据类型定义
// ============================================================================

/// Jail 统计数据快照
pub struct JailStatsSnapshot {
    pub jail_name: String,
    pub snapshot_time: i64,
    pub lines_parsed: u64,
    pub ips_extracted: u64,
    pub bans_triggered: u64,
    pub failed_attempts: u64,
    pub active_bans: u64,
}

/// 守护进程统计数据快照
pub struct DaemonStatsSnapshot {
    pub snapshot_time: i64,
    pub uptime_seconds: u64,
    pub total_lines_parsed: u64,
    pub total_ips_banned: u64,
    pub total_failed: u64,
    pub active_ban_count: u64,
    pub kernel_ban_count: u64,
}

/// SQLite 统计信息
pub struct SqliteStats {
    pub ban_history_total: u64,
    pub ban_history_active: u64,
    pub failed_logs_total: u64,
    pub jail_stats_total: u64,
    pub ddos_events_total: u64,
}

// ============================================================================
// Dirty 标志管理
// ============================================================================

/// 脏标记：内存数据有变更尚未同步到 SQLite
static SYNC_DIRTY: AtomicBool = AtomicBool::new(false);

/// 标记需要同步（封禁/解封操作后调用）
pub fn mark_dirty() {
    SYNC_DIRTY.store(true, Ordering::Relaxed);
}

/// 检查是否有待同步的数据
pub fn is_dirty() -> bool {
    SYNC_DIRTY.load(Ordering::Relaxed)
}

/// 清除脏标记
pub fn clear_dirty() {
    SYNC_DIRTY.store(false, Ordering::Relaxed);
}

// 重新导出所有子模块的公共 API
pub use bans::{
    insert_ban_history, insert_ban_history_batch, load_active_bans, update_ban_status,
    update_ban_status_batch,
};
pub use cleanup::{cleanup_old_data, get_wal_size};
pub use logs::insert_failed_log;
pub use stats::{get_stats, insert_daemon_stats, insert_ddos_event, insert_jail_stats};
pub use tables::init_tables;

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BanInfo, BanReason, BanStatus};
    use rusqlite::Connection;

    /// 创建内存数据库并初始化表结构
    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        init_tables(&conn).expect("init tables");
        conn
    }

    /// 构造测试用 BanInfo
    fn make_ban_info(ip: &str, jail: &str, banned_at: i64, expires_at: i64) -> BanInfo {
        BanInfo {
            ip: ip.to_string(),
            ip_num: 0,
            jail_name: jail.to_string(),
            reason: BanReason::FailedAttempts,
            banned_at,
            expires_at,
            is_permanent: false,
            fail_count: 3,
        }
    }

    // ---- Dirty 标志测试 ----

    #[test]
    fn test_dirty_flag_lifecycle() {
        // 初始为 false
        clear_dirty();
        assert!(!is_dirty());

        // 标记脏
        mark_dirty();
        assert!(is_dirty());

        // 清除脏标记
        clear_dirty();
        assert!(!is_dirty());
    }

    // ---- 表初始化测试 ----

    #[test]
    fn test_init_tables_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        // 多次调用不报错 (IF NOT EXISTS)
        init_tables(&conn).unwrap();
        init_tables(&conn).unwrap();
    }

    // ---- bans 模块测试 ----

    #[test]
    fn test_insert_and_load_ban_history() {
        let conn = setup_db();
        let info = make_ban_info("1.2.3.4", "ssh", 1000, 1600);

        let rowid = insert_ban_history(&conn, &info).unwrap();
        assert!(rowid > 0);

        let bans = load_active_bans(&conn).unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].ip, "1.2.3.4");
        assert_eq!(bans[0].jail_name, "ssh");
        assert_eq!(bans[0].banned_at, 1000);
        assert_eq!(bans[0].expires_at, 1600);
    }

    #[test]
    fn test_update_ban_status_and_batch() {
        let conn = setup_db();
        insert_ban_history(&conn, &make_ban_info("1.1.1.1", "ssh", 1000, 1600)).unwrap();
        insert_ban_history(&conn, &make_ban_info("2.2.2.2", "ssh", 1000, 1600)).unwrap();
        insert_ban_history(&conn, &make_ban_info("3.3.3.3", "http", 1000, 1600)).unwrap();

        // 单条更新
        let affected = update_ban_status(&conn, "1.1.1.1", BanStatus::Expired).unwrap();
        assert_eq!(affected, 1);

        // 已更新的 IP 不再出现在 active 列表
        let active = load_active_bans(&conn).unwrap();
        assert_eq!(active.len(), 2);

        // 批量更新剩余
        let ips = vec!["2.2.2.2".to_string(), "3.3.3.3".to_string()];
        let batch_affected =
            update_ban_status_batch(&conn, &ips, BanStatus::UnbannedManual).unwrap();
        assert_eq!(batch_affected, 2);

        let remaining = load_active_bans(&conn).unwrap();
        assert_eq!(remaining.len(), 0);
    }

    #[test]
    fn test_insert_ban_history_batch() {
        let conn = setup_db();
        let infos = vec![
            make_ban_info("10.0.0.1", "ssh", 2000, 2600),
            make_ban_info("10.0.0.2", "ssh", 2000, 2600),
            make_ban_info("10.0.0.3", "http", 2000, 2600),
        ];

        let count = insert_ban_history_batch(&conn, &infos).unwrap();
        assert_eq!(count, 3);

        let active = load_active_bans(&conn).unwrap();
        assert_eq!(active.len(), 3);
    }

    // ---- logs 模块测试 ----

    #[test]
    fn test_insert_failed_log() {
        let conn = setup_db();
        insert_failed_log(&conn, "5.5.5.5", "ssh", 5, 900, 1000, true).unwrap();
        insert_failed_log(&conn, "6.6.6.6", "http", 2, 900, 1000, false).unwrap();

        let stats = get_stats(&conn).unwrap();
        assert_eq!(stats.failed_logs_total, 2);
    }

    // ---- stats 模块测试 ----

    #[test]
    fn test_insert_jail_stats_snapshot() {
        let conn = setup_db();
        let snapshot = JailStatsSnapshot {
            jail_name: "ssh".to_string(),
            snapshot_time: 1000,
            lines_parsed: 5000,
            ips_extracted: 100,
            bans_triggered: 5,
            failed_attempts: 50,
            active_bans: 3,
        };

        insert_jail_stats(&conn, &snapshot).unwrap();

        let stats = get_stats(&conn).unwrap();
        assert_eq!(stats.jail_stats_total, 1);
    }

    #[test]
    fn test_insert_ddos_event() {
        let conn = setup_db();
        insert_ddos_event(
            &conn,
            "10.20.30.40",
            "rate_exceeded",
            150.5,
            100.0,
            5000,
            "banned",
        )
        .unwrap();

        let stats = get_stats(&conn).unwrap();
        assert_eq!(stats.ddos_events_total, 1);
    }

    #[test]
    fn test_insert_daemon_stats_snapshot() {
        let conn = setup_db();
        let snapshot = DaemonStatsSnapshot {
            snapshot_time: 1000,
            uptime_seconds: 3600,
            total_lines_parsed: 100_000,
            total_ips_banned: 42,
            total_failed: 200,
            active_ban_count: 10,
            kernel_ban_count: 10,
        };

        insert_daemon_stats(&conn, &snapshot).unwrap();

        // 直接查询验证
        let count: u64 = conn
            .query_row("SELECT COUNT(*) FROM daemon_stats_snapshots", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    // ---- get_stats 综合测试 ----

    #[test]
    fn test_get_stats_comprehensive() {
        let conn = setup_db();

        // 插入数据到所有表
        insert_ban_history(&conn, &make_ban_info("1.1.1.1", "ssh", 1000, 1600)).unwrap();
        insert_ban_history(&conn, &make_ban_info("2.2.2.2", "ssh", 1000, 1600)).unwrap();
        update_ban_status(&conn, "2.2.2.2", BanStatus::Expired).unwrap();
        insert_failed_log(&conn, "3.3.3.3", "http", 1, 900, 1000, false).unwrap();
        insert_ddos_event(&conn, "4.4.4.4", "flood", 200.0, 100.0, 5000, "banned").unwrap();
        insert_jail_stats(
            &conn,
            &JailStatsSnapshot {
                jail_name: "ssh".to_string(),
                snapshot_time: 1000,
                lines_parsed: 1000,
                ips_extracted: 50,
                bans_triggered: 2,
                failed_attempts: 10,
                active_bans: 1,
            },
        )
        .unwrap();

        let stats = get_stats(&conn).unwrap();
        assert_eq!(stats.ban_history_total, 2);
        assert_eq!(stats.ban_history_active, 1); // 2 total - 1 expired
        assert_eq!(stats.failed_logs_total, 1);
        assert_eq!(stats.jail_stats_total, 1);
        assert_eq!(stats.ddos_events_total, 1);
    }
}
