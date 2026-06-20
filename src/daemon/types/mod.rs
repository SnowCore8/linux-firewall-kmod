//! 跨模块共享的数据结构与系统级常量
//!
//! 拆出独立模块以避免 `ban` ↔ `jail` ↔ `failed_tracker` 等模块间出现循环依赖。
//! 本模块只放纯数据结构 + 全局原子统计，不含任何业务逻辑。
//!
//! # 子模块划分
//!
//! - [`jail`]: `Jail` / `FailedEntry` / `RegexInfo`
//! - [`config`]: `Config` / `StorageConfig` / `RetentionConfig` / `WriterConfig`
//! - [`ban`]: `BanInfo` / `BanReason` / `BanStatus` / `ActiveBanCache`
//! - [`stats`]: `DaemonStats` / `JailStatsCounters` / per-jail 统计
//! - [`ddos`]: `DdosConfig` / `ConnRateEntry` / `DdosEvent` / `DdosStats`
//!
//! # 并发模型
//!
//! - `FailedEntry::recent_head` 使用 `AtomicUsize`（lock-free）
//! - `Jail::failed_hash` 与 `Jail::partial_line_buffer` 使用 `parking_lot::RwLock`
//!   （性能优于 `std::sync::RwLock`，无写线程饥饿）
//! - `DaemonStats` 全字段使用 `AtomicU64`（Relaxed 序，统计不要求严格同步）

// 模块声明
mod ban;
mod config;
mod ddos;
mod jail;
mod stats;

// Re-export 所有公共类型，保持向后兼容
pub use ban::{ActiveBanCache, BanInfo, BanReason, BanStatus, ACTIVE_BAN_CACHE};
pub use config::{Config, RetentionConfig, StorageConfig, WebuiConfig, WriterConfig};
pub use ddos::{ConnRateEntry, DdosConfig, DdosEvent, DdosStats, DDOS_STATS};
pub use jail::{
    FailedEntry, Jail, RegexInfo, MAX_FAILED_TIMESTAMPS, MAX_JAILS, MAX_LOG_FILES,
    MAX_REGEX_NAME_LEN, MAX_REGEX_PATTERNS,
};
pub use stats::{
    get_baseline_bps, get_baseline_pps, record_ban_duration, record_rate_history,
    set_baseline_warmup_samples, update_traffic_baseline, with_jail_stats, DaemonStats,
    JailStatsCounters, JailStatsSnapshot, RateEntry, RateHistoryEntry, WhitelistEntry,
    BAN_DURATION_BUCKETS, DAEMON_STATS, JAIL_STATS, RATE_CACHE, RATE_HISTORY, WHITELIST_CACHE,
};

/// inotify 事件缓冲大小：`1024` 个事件 × 单事件 `~16B` + 16KB 安全裕量。
/// 典型负载下保证单次 `read_events` 不丢事件。
pub const EVENT_BUF_LEN: usize =
    1024 * std::mem::size_of::<nix::sys::inotify::InotifyEvent>() + 16 * 1024;

/// 获取当前 Unix 时间戳（秒）。
///
/// 封装 `SystemTime::now().duration_since(UNIX_EPOCH)` 模式，
/// 仅在系统时钟早于 1970 时返回 0（理论上不可能）。
/// 消除跨模块重复的 `.unwrap_or(0)` 调用。
#[must_use]
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // BanReason 测试
    #[test]
    fn test_ban_reason_as_str() {
        assert_eq!(BanReason::FailedAttempts.as_str(), "failed_attempts");
        assert_eq!(BanReason::DDoSRateLimit.as_str(), "ddos_rate");
        assert_eq!(BanReason::ManualBan.as_str(), "manual");
        assert_eq!(BanReason::PermanentAuto.as_str(), "permanent_auto");
    }

    #[test]
    fn test_ban_reason_parse() {
        assert_eq!(
            BanReason::parse("failed_attempts"),
            BanReason::FailedAttempts
        );
        assert_eq!(BanReason::parse("ddos_rate"), BanReason::DDoSRateLimit);
        assert_eq!(BanReason::parse("manual"), BanReason::ManualBan);
        assert_eq!(BanReason::parse("permanent_auto"), BanReason::PermanentAuto);
        // 未知值回退到 FailedAttempts
        assert_eq!(BanReason::parse("unknown"), BanReason::FailedAttempts);
        assert_eq!(BanReason::parse(""), BanReason::FailedAttempts);
    }

    // BanStatus 测试
    #[test]
    fn test_ban_status_as_str() {
        assert_eq!(BanStatus::Active.as_str(), "active");
        assert_eq!(BanStatus::Expired.as_str(), "expired");
        assert_eq!(BanStatus::UnbannedManual.as_str(), "unbanned_manual");
    }

    #[test]
    fn test_ban_status_parse() {
        assert_eq!(BanStatus::parse("active"), BanStatus::Active);
        assert_eq!(BanStatus::parse("expired"), BanStatus::Expired);
        assert_eq!(
            BanStatus::parse("unbanned_manual"),
            BanStatus::UnbannedManual
        );
        // 未知值回退到 Active
        assert_eq!(BanStatus::parse("unknown"), BanStatus::Active);
    }

    // BanInfo 测试
    #[test]
    fn test_ban_info_is_expired() {
        let now = 1000;

        // 永久封禁永不过期
        let permanent = BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0,
            jail_name: "test".to_string(),
            reason: BanReason::ManualBan,
            banned_at: 900,
            expires_at: 0,
            is_permanent: true,
            fail_count: 0,
        };
        assert!(!permanent.is_expired(now));

        // 临时封禁未过期
        let temp_active = BanInfo {
            ip: "1.2.3.5".to_string(),
            ip_num: 0,
            jail_name: "test".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 900,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 3,
        };
        assert!(!temp_active.is_expired(now));

        // 临时封禁已过期
        let temp_expired = BanInfo {
            ip: "1.2.3.6".to_string(),
            ip_num: 0,
            jail_name: "test".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 900,
            expires_at: 950,
            is_permanent: false,
            fail_count: 3,
        };
        assert!(temp_expired.is_expired(now));
    }

    #[test]
    fn test_ban_info_duration_secs() {
        let now = 1000;

        // 永久封禁：duration = now - banned_at
        let permanent = BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0,
            jail_name: "test".to_string(),
            reason: BanReason::ManualBan,
            banned_at: 900,
            expires_at: 0,
            is_permanent: true,
            fail_count: 0,
        };
        assert_eq!(permanent.duration_secs(now), 100);

        // 临时封禁：duration = expires_at - banned_at
        let temp = BanInfo {
            ip: "1.2.3.5".to_string(),
            ip_num: 0,
            jail_name: "test".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 900,
            expires_at: 1000,
            is_permanent: false,
            fail_count: 3,
        };
        assert_eq!(temp.duration_secs(now), 100);
    }

    // ActiveBanCache 测试
    #[test]
    fn test_active_ban_cache_basic_operations() {
        let cache = ActiveBanCache::new();

        // 初始为空
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);

        // 插入封禁
        let ban1 = BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0x01020304,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 3,
        };
        cache.insert(ban1.clone());

        assert_eq!(cache.len(), 1);
        assert!(!cache.is_empty());

        // 查询存在的 IP
        let retrieved = cache.get("1.2.3.4").unwrap();
        assert_eq!(retrieved.ip, "1.2.3.4");
        assert_eq!(retrieved.jail_name, "ssh");

        // 查询不存在的 IP
        assert!(cache.get("5.6.7.8").is_none());

        // 移除封禁
        let removed = cache.remove("1.2.3.4").unwrap();
        assert_eq!(removed.ip, "1.2.3.4");
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        // 移除不存在的 IP
        assert!(cache.remove("5.6.7.8").is_none());
    }

    #[test]
    fn test_active_ban_cache_get_by_jail() {
        let cache = ActiveBanCache::new();

        // 插入多个 jail 的封禁
        cache.insert(BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 3,
        });
        cache.insert(BanInfo {
            ip: "5.6.7.8".to_string(),
            ip_num: 0,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 3,
        });
        cache.insert(BanInfo {
            ip: "9.10.11.12".to_string(),
            ip_num: 0,
            jail_name: "http".to_string(),
            reason: BanReason::DDoSRateLimit,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 0,
        });

        // 查询 ssh jail
        let ssh_bans = cache.get_by_jail("ssh");
        assert_eq!(ssh_bans.len(), 2);
        assert!(ssh_bans.contains(&"1.2.3.4".to_string()));
        assert!(ssh_bans.contains(&"5.6.7.8".to_string()));

        // 查询 http jail
        let http_bans = cache.get_by_jail("http");
        assert_eq!(http_bans.len(), 1);
        assert!(http_bans.contains(&"9.10.11.12".to_string()));

        // 查询不存在的 jail
        let ftp_bans = cache.get_by_jail("ftp");
        assert_eq!(ftp_bans.len(), 0);
    }

    #[test]
    fn test_active_ban_cache_purge_expired() {
        let cache = ActiveBanCache::new();
        let now = 1000;

        // 插入未过期和已过期的封禁
        cache.insert(BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 900,
            expires_at: 1100, // 未过期
            is_permanent: false,
            fail_count: 3,
        });
        cache.insert(BanInfo {
            ip: "5.6.7.8".to_string(),
            ip_num: 0,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 900,
            expires_at: 950, // 已过期
            is_permanent: false,
            fail_count: 3,
        });
        cache.insert(BanInfo {
            ip: "9.10.11.12".to_string(),
            ip_num: 0,
            jail_name: "http".to_string(),
            reason: BanReason::DDoSRateLimit,
            banned_at: 900,
            expires_at: 0, // 永久封禁
            is_permanent: true,
            fail_count: 0,
        });

        assert_eq!(cache.len(), 3);

        // 清理过期封禁
        let expired = cache.purge_expired(now);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].ip, "5.6.7.8");

        // 验证剩余封禁
        assert_eq!(cache.len(), 2);
        assert!(cache.get("1.2.3.4").is_some());
        assert!(cache.get("5.6.7.8").is_none());
        assert!(cache.get("9.10.11.12").is_some());

        // 验证反向索引清理
        let ssh_bans = cache.get_by_jail("ssh");
        assert_eq!(ssh_bans.len(), 1);
        assert!(ssh_bans.contains(&"1.2.3.4".to_string()));
    }

    #[test]
    fn test_active_ban_cache_snapshot() {
        let cache = ActiveBanCache::new();

        cache.insert(BanInfo {
            ip: "1.2.3.4".to_string(),
            ip_num: 0,
            jail_name: "ssh".to_string(),
            reason: BanReason::FailedAttempts,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 3,
        });
        cache.insert(BanInfo {
            ip: "5.6.7.8".to_string(),
            ip_num: 0,
            jail_name: "http".to_string(),
            reason: BanReason::DDoSRateLimit,
            banned_at: 1000,
            expires_at: 1100,
            is_permanent: false,
            fail_count: 0,
        });

        let snapshot = cache.snapshot();
        assert_eq!(snapshot.len(), 2);
    }

    // DaemonStats 测试
    #[test]
    fn test_daemon_stats_atomic_operations() {
        let stats = DaemonStats::new();

        // 初始值为 0
        assert_eq!(
            stats
                .lines_parsed
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            stats.ips_banned.load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        // 原子递增
        stats
            .lines_parsed
            .fetch_add(10, std::sync::atomic::Ordering::Relaxed);
        stats
            .ips_banned
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);

        assert_eq!(
            stats
                .lines_parsed
                .load(std::sync::atomic::Ordering::Relaxed),
            10
        );
        assert_eq!(
            stats.ips_banned.load(std::sync::atomic::Ordering::Relaxed),
            5
        );
    }

    // JailStatsCounters 测试
    #[test]
    fn test_jail_stats_counters() {
        let counters = JailStatsCounters::new("ssh".to_string());

        assert_eq!(counters.jail_name, "ssh");
        assert_eq!(
            counters
                .lines_parsed
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        assert_eq!(
            counters
                .bans_triggered
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        // 递增计数
        counters
            .lines_parsed
            .fetch_add(100, std::sync::atomic::Ordering::Relaxed);
        counters
            .bans_triggered
            .fetch_add(5, std::sync::atomic::Ordering::Relaxed);

        // 快照
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.jail_name, "ssh");
        assert_eq!(snapshot.lines_parsed, 100);
        assert_eq!(snapshot.bans_triggered, 5);
    }
}
