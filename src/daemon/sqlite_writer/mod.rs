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
pub use bans::{insert_ban_history, insert_ban_history_batch, load_active_bans, update_ban_status, update_ban_status_batch};
pub use cleanup::{cleanup_old_data, get_wal_size};
pub use logs::insert_failed_log;
pub use stats::{get_stats, insert_daemon_stats, insert_ddos_event, insert_jail_stats};
pub use tables::init_tables;
