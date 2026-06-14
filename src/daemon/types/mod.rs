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
pub use config::{Config, RetentionConfig, StorageConfig, WriterConfig};
pub use ddos::{ConnRateEntry, DdosConfig, DdosEvent, DdosStats, DDOS_STATS};
pub use jail::{
    FailedEntry, Jail, RegexInfo, MAX_FAILED_TIMESTAMPS, MAX_JAILS, MAX_LOG_FILES,
    MAX_REGEX_NAME_LEN, MAX_REGEX_PATTERNS,
};
pub use stats::{
    record_ban_duration, with_jail_stats, DaemonStats, JailStatsCounters, JailStatsSnapshot,
    BAN_DURATION_BUCKETS, DAEMON_STATS, JAIL_STATS,
};

/// inotify 事件缓冲大小：`1024` 个事件 × 单事件 `~16B` + 16KB 安全裕量。
/// 典型负载下保证单次 `read_events` 不丢事件。
pub const EVENT_BUF_LEN: usize =
    1024 * std::mem::size_of::<nix::sys::inotify::InotifyEvent>() + 16 * 1024;
