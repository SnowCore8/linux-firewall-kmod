//! 跨模块共享的数据结构与系统级常量
//!
//! 拆出独立模块以避免 `ban` ↔ `jail` ↔ `failed_tracker` 等模块间出现循环依赖。
//! 本模块只放纯数据结构 + 全局原子统计,不含任何业务逻辑。
//!
//! # 主要内容
//!
//! - **容量上限常量**:`MAX_FAILED_TIMESTAMPS` / `MAX_LOG_FILES` / `MAX_JAILS` 等
//!   用于限制攻击面与内存占用
//! - **Jail 相关**:`Jail` + `RegexInfo` + `FailedEntry`
//! - **配置**:`Config` 全局配置
//! - **统计**:`DaemonStats` 跨模块共享的原子计数器
//!
//! # 并发模型
//!
//! - `FailedEntry::recent_head` 使用 `AtomicUsize` (lock-free)
//! - `Jail::failed_hash` 与 `Jail::partial_line_buffer` 使用 `parking_lot::RwLock`
//!   (性能优于 `std::sync::RwLock`,无写线程饥饿)
//! - `DaemonStats` 全字段使用 `AtomicU64` (Relaxed 序,统计不要求严格同步)

// 模块声明
mod config;
mod jail;
mod stats;

// 公共导出
pub use config::Config;
pub use jail::{FailedEntry, Jail, RegexInfo};
pub use stats::{DaemonStats, DAEMON_STATS};
//! # 子模块划分
//!
//! - [`jail`]: `Jail` / `FailedEntry` / `RegexInfo`
//! - [`config`]: `Config` / `StorageConfig` / `RetentionConfig` / `WriterConfig`
//! - [`ban`]: `BanInfo` / `BanReason` / `BanStatus` / `ActiveBanCache`
//! - [`stats`]: `DaemonStats` / `JailStatsCounters` / per-jail 统计
//! - [`ddos`]: `DdosConfig` / `ConnRateEntry` / `DdosEvent` / `DdosStats`

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
    with_jail_stats, DaemonStats, JailStatsCounters, JailStatsSnapshot, DAEMON_STATS, JAIL_STATS,
};

// ============================================================================
// 常量
// ============================================================================

/// 单个 IP 在 `FailedEntry.timestamps` 中最多保留的失败时间戳数。
///
/// 满后采用 FIFO 移出最旧时间戳。100 兼顾"高频攻击者最近 100 次"和"内存占用
/// 上界 (100 × `i64` × `MAX_JAILS` × IP 数)"。
pub const MAX_FAILED_TIMESTAMPS: usize = 100;

/// 单个 `Jail` 可配置的日志文件数上限。10 覆盖典型多通道日志场景 (e.g. sshd +
/// 4×web + 邮件) 同时限制单 jail 的 fd 占用。
pub const MAX_LOG_FILES: usize = 10;

/// 单个 `Jail` 可配置的正则表达式数上限。10 留足自定义空间但限制编译开销。
pub const MAX_REGEX_PATTERNS: usize = 10;

/// 正则名称字符串的最大长度 (字节)。`compile_jail_regex` 不强制,但 UI/日志截断时
/// 依赖此上界避免异常长名称。
pub const MAX_REGEX_NAME_LEN: usize = 64;

/// 全局可同时活跃的 `Jail` 数上限。`config` 在解析时检查此上界。
pub const MAX_JAILS: usize = 16;

/// inotify 事件缓冲大小:`1024` 个事件 × 单事件 `~16B` + 16KB 安全裕量。
/// 典型负载下保证单次 `read_events` 不丢事件。
pub const EVENT_BUF_LEN: usize =
    1024 * std::mem::size_of::<nix::sys::inotify::InotifyEvent>() + 16 * 1024;
