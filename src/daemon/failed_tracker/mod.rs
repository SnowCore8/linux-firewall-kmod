//! 失败尝试跟踪：滑动窗口计数（R9-7 优化）+ 阈值检查 + 触发封禁
//!
//! 本文件内 `u64 → i64` 是 Unix 时间戳常规做法
//!
//! # 模块结构
//!
//! - `entry_ops`：失败条目管理（查找、创建、移除）
//! - `tracking`：失败跟踪逻辑（计数、时间戳处理、触发封禁）
//!
//! # 数据流
//!
//! 1. [`crate::file_monitor::process_single_line`] 解析日志行得到 IP
//! 2. 调 [`handle_failed_attempt_for_jail`] 累计 `FailedEntry.timestamps`
//! 3. [`count_recent`] 统计窗口内失败次数
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
//! 4. 达到 `max_retries` 时调 [`crate::ban::ban_ip`] 封禁,成功后清理条目
//!
//! # 关键优化 (R9-7)
//!
//! `FailedEntry.recent_head` 是已确认过期的前缀起点,`count_recent` 从该点
//! 开始扫描实现滑动窗口的 O(1) 平均复杂度。满 [`MAX_FAILED_TIMESTAMPS`] 时
//! FIFO 移出最旧时间戳,同时维护索引避免 O(n) 重建。
//!
//! # 锁纪律
//!
//! 调 `ban::ban_ip` 前必须先 `drop(hash)`,否则 ban 内部可能触发的日志写入
//! 会与本 `failed_hash` 写锁死锁 (R9-3 修复)。

mod entry_ops;
mod tracking;

pub use entry_ops::{create_entry_for_jail, find_entry, remove_entry_for_jail};
pub use tracking::{
    cleanup_expired_entries, count_recent, handle_failed_attempt_for_jail,
    process_failed_timestamps,
};

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Jail, MAX_FAILED_TIMESTAMPS};
    use tracking::now_secs;

    fn make_test_jail() -> Jail {
        Jail::new("test_jail".to_string())
    }

    #[test]
    fn create_and_find_entry() {
        let jail = make_test_jail();
        create_entry_for_jail(&jail, "192.168.1.100").unwrap();

        let hash = jail.failed_hash.read();
        assert!(hash.contains_key("192.168.1.100"));
    }

    #[test]
    fn create_duplicate_entry_is_ok() {
        let jail = make_test_jail();
        create_entry_for_jail(&jail, "10.0.0.1").unwrap();
        create_entry_for_jail(&jail, "10.0.0.1").unwrap();
    }

    #[test]
    fn remove_entry() {
        let jail = make_test_jail();
        create_entry_for_jail(&jail, "10.0.0.2").unwrap();
        remove_entry_for_jail(&jail, "10.0.0.2");

        let hash = jail.failed_hash.read();
        assert!(!hash.contains_key("10.0.0.2"));
    }

    #[test]
    fn count_recent_within_window() {
        let jail = make_test_jail();
        create_entry_for_jail(&jail, "10.0.0.3").unwrap();

        let now = now_secs();
        let mut hash = jail.failed_hash.write();
        let entry = hash.get_mut("10.0.0.3").unwrap();

        entry.timestamps.push_back(now - 10);
        entry.timestamps.push_back(now - 5);
        entry.timestamps.push_back(now - 1);

        let count = count_recent(entry, 60, 5);
        assert_eq!(count, 3);
    }

    #[test]
    fn count_recent_expires_old() {
        let jail = make_test_jail();
        create_entry_for_jail(&jail, "10.0.0.4").unwrap();

        let now = now_secs();
        let mut hash = jail.failed_hash.write();
        let entry = hash.get_mut("10.0.0.4").unwrap();

        entry.timestamps.push_back(now - 120);
        entry.timestamps.push_back(now - 100);
        entry.timestamps.push_back(now - 5);

        let count = count_recent(entry, 60, 5);
        assert_eq!(count, 1);
    }

    #[test]
    fn process_failed_timestamps_grow() {
        let mut entry = crate::types::FailedEntry::new("10.0.0.5".to_string());
        let now = now_secs();

        for i in 0..50 {
            process_failed_timestamps(&mut entry, now + i as i64, 3600);
        }

        assert_eq!(entry.timestamps.len(), 50);
    }

    #[test]
    fn process_failed_timestamps_overflow() {
        let mut entry = crate::types::FailedEntry::new("10.0.0.6".to_string());
        let now = now_secs();

        for i in 0..MAX_FAILED_TIMESTAMPS {
            process_failed_timestamps(&mut entry, now + i as i64, 3600);
        }

        assert_eq!(entry.timestamps.len(), MAX_FAILED_TIMESTAMPS);

        process_failed_timestamps(&mut entry, now + MAX_FAILED_TIMESTAMPS as i64, 3600);
        assert_eq!(entry.timestamps.len(), MAX_FAILED_TIMESTAMPS);
    }

    #[test]
    fn handle_failed_attempt_bans_at_threshold() {
        let jail = make_test_jail();
        let max_retries = 3;
        let findtime = 60;

        for _ in 0..3 {
            handle_failed_attempt_for_jail(&jail, "10.0.0.7", max_retries, findtime);
        }

        let _guard = jail.failed_hash.read();
    }

    #[test]
    fn empty_ip_is_rejected() {
        let jail = make_test_jail();
        handle_failed_attempt_for_jail(&jail, "", 3, 60);

        let hash = jail.failed_hash.read();
        assert!(!hash.contains_key(""));
    }

    #[test]
    fn count_recent_zero_window() {
        let entry = crate::types::FailedEntry::new("10.0.0.8".to_string());
        let count = count_recent(&entry, 0, 5);
        assert_eq!(count, 0);
    }
}
