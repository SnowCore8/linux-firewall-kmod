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

use anyhow::Result;
use rusqlite::Connection;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::types::{BanInfo, BanReason, BanStatus};

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

// ============================================================================
// 表创建与迁移
// ============================================================================

/// 创建所有新表（如果不存在）
pub fn init_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        -- 封禁历史表（临时 + 永久的完整记录）
        CREATE TABLE IF NOT EXISTS ban_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT    NOT NULL,
            ip_num      INTEGER NOT NULL DEFAULT 0,
            jail_name   TEXT    NOT NULL DEFAULT 'unknown',
            reason      TEXT    NOT NULL DEFAULT 'failed_attempts',
            banned_at   INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL DEFAULT 0,
            status      TEXT    NOT NULL DEFAULT 'active',
            fail_count  INTEGER DEFAULT 0,
            created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_ban_history_ip ON ban_history(ip);
        CREATE INDEX IF NOT EXISTS idx_ban_history_status ON ban_history(status);
        CREATE INDEX IF NOT EXISTS idx_ban_history_jail ON ban_history(jail_name);
        CREATE INDEX IF NOT EXISTS idx_ban_history_banned_at ON ban_history(banned_at);

        -- 失败尝试聚合日志
        CREATE TABLE IF NOT EXISTS failed_attempt_logs (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ip            TEXT    NOT NULL,
            jail_name     TEXT    NOT NULL,
            fail_count    INTEGER NOT NULL,
            window_start  INTEGER NOT NULL,
            window_end    INTEGER NOT NULL,
            triggered_ban INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_failed_logs_ip ON failed_attempt_logs(ip);
        CREATE INDEX IF NOT EXISTS idx_failed_logs_window ON failed_attempt_logs(window_end);

        -- Jail 统计快照（定期写入）
        CREATE TABLE IF NOT EXISTS jail_stats_snapshots (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            jail_name       TEXT    NOT NULL,
            snapshot_time   INTEGER NOT NULL,
            lines_parsed    INTEGER NOT NULL DEFAULT 0,
            ips_extracted   INTEGER NOT NULL DEFAULT 0,
            bans_triggered  INTEGER NOT NULL DEFAULT 0,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            active_bans     INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_jail_stats_time ON jail_stats_snapshots(snapshot_time);
        CREATE INDEX IF NOT EXISTS idx_jail_stats_name ON jail_stats_snapshots(jail_name);

        -- DDoS 事件记录
        CREATE TABLE IF NOT EXISTS ddos_events (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ip              TEXT    NOT NULL,
            event_type      TEXT    NOT NULL,
            rate_per_second REAL    NOT NULL,
            threshold       REAL    NOT NULL,
            detected_at     INTEGER NOT NULL,
            action_taken    TEXT    NOT NULL DEFAULT 'none'
        );
        CREATE INDEX IF NOT EXISTS idx_ddos_time ON ddos_events(detected_at);

        -- 全局守护进程统计快照
        CREATE TABLE IF NOT EXISTS daemon_stats_snapshots (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            snapshot_time       INTEGER NOT NULL,
            uptime_seconds      INTEGER NOT NULL,
            total_lines_parsed  INTEGER NOT NULL,
            total_ips_banned    INTEGER NOT NULL,
            total_failed        INTEGER NOT NULL,
            active_ban_count    INTEGER NOT NULL,
            kernel_ban_count    INTEGER NOT NULL
        );
        ",
    )?;

    Ok(())
}

// ============================================================================
// 封禁历史 CRUD
// ============================================================================

/// 插入封禁历史记录（定时器调用）
pub fn insert_ban_history(conn: &Connection, info: &BanInfo) -> Result<i64> {
    conn.execute(
        "INSERT INTO ban_history (ip, ip_num, jail_name, reason, banned_at, expires_at, status, fail_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        rusqlite::params![
            info.ip,
            info.ip_num,
            info.jail_name,
            info.reason.as_str(),
            info.banned_at,
            info.expires_at,
            BanStatus::Active.as_str(),
            info.fail_count,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

/// 批量插入封禁历史（定时器调用，事务保证原子性）
pub fn insert_ban_history_batch(conn: &Connection, infos: &[BanInfo]) -> Result<usize> {
    let mut count = 0;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO ban_history (ip, ip_num, jail_name, reason, banned_at, expires_at, status, fail_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        )?;
        for info in infos {
            stmt.execute(rusqlite::params![
                info.ip,
                info.ip_num,
                info.jail_name,
                info.reason.as_str(),
                info.banned_at,
                info.expires_at,
                BanStatus::Active.as_str(),
                info.fail_count,
            ])?;
            count += 1;
        }
    }
    tx.commit()?;
    Ok(count)
}

/// 更新封禁状态（解封/过期时调用）
pub fn update_ban_status(conn: &Connection, ip: &str, status: BanStatus) -> Result<usize> {
    let affected = conn.execute(
        "UPDATE ban_history SET status = ?1 WHERE ip = ?2 AND status = 'active'",
        rusqlite::params![status.as_str(), ip],
    )?;
    Ok(affected)
}

/// 批量更新封禁状态
pub fn update_ban_status_batch(
    conn: &Connection,
    ips: &[String],
    status: BanStatus,
) -> Result<usize> {
    let mut count = 0;
    let tx = conn.unchecked_transaction()?;
    {
        let mut stmt =
            tx.prepare("UPDATE ban_history SET status = ?1 WHERE ip = ?2 AND status = 'active'")?;
        for ip in ips {
            count += stmt.execute(rusqlite::params![status.as_str(), ip])?;
        }
    }
    tx.commit()?;
    Ok(count)
}

/// 加载所有活跃封禁（启动时恢复）
pub fn load_active_bans(conn: &Connection) -> Result<Vec<BanInfo>> {
    let mut stmt = conn.prepare(
        "SELECT ip, ip_num, jail_name, reason, banned_at, expires_at, fail_count
         FROM ban_history WHERE status = 'active'",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(BanInfo {
            ip: row.get(0)?,
            ip_num: row.get(1)?,
            jail_name: row.get(2)?,
            reason: BanReason::parse(&row.get::<_, String>(3)?),
            banned_at: row.get(4)?,
            expires_at: row.get(5)?,
            is_permanent: row.get::<_, i64>(5)? == 0,
            fail_count: row.get(6)?,
        })
    })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

// ============================================================================
// 失败尝试日志
// ============================================================================

/// 插入失败尝试聚合记录
pub fn insert_failed_log(
    conn: &Connection,
    ip: &str,
    jail_name: &str,
    fail_count: u32,
    window_start: i64,
    window_end: i64,
    triggered_ban: bool,
) -> Result<()> {
    conn.execute(
        "INSERT INTO failed_attempt_logs (ip, jail_name, fail_count, window_start, window_end, triggered_ban)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![ip, jail_name, fail_count, window_start, window_end, triggered_ban as i32],
    )?;
    Ok(())
}

// ============================================================================
// Jail 统计快照
// ============================================================================

/// 插入 Jail 统计快照
pub fn insert_jail_stats(conn: &Connection, stats: &JailStatsSnapshot) -> Result<()> {
    conn.execute(
        "INSERT INTO jail_stats_snapshots (jail_name, snapshot_time, lines_parsed, ips_extracted, bans_triggered, failed_attempts, active_bans)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            stats.jail_name,
            stats.snapshot_time,
            stats.lines_parsed,
            stats.ips_extracted,
            stats.bans_triggered,
            stats.failed_attempts,
            stats.active_bans,
        ],
    )?;
    Ok(())
}

// ============================================================================
// DDoS 事件
// ============================================================================

/// 插入 DDoS 事件记录
pub fn insert_ddos_event(
    conn: &Connection,
    ip: &str,
    event_type: &str,
    rate_per_second: f64,
    threshold: f64,
    detected_at: i64,
    action_taken: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO ddos_events (ip, event_type, rate_per_second, threshold, detected_at, action_taken)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![ip, event_type, rate_per_second, threshold, detected_at, action_taken],
    )?;
    Ok(())
}

// ============================================================================
// 全局统计快照
// ============================================================================

/// 插入守护进程统计快照
pub fn insert_daemon_stats(conn: &Connection, stats: &DaemonStatsSnapshot) -> Result<()> {
    conn.execute(
        "INSERT INTO daemon_stats_snapshots (snapshot_time, uptime_seconds, total_lines_parsed, total_ips_banned, total_failed, active_ban_count, kernel_ban_count)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            stats.snapshot_time,
            stats.uptime_seconds,
            stats.total_lines_parsed,
            stats.total_ips_banned,
            stats.total_failed,
            stats.active_ban_count,
            stats.kernel_ban_count,
        ],
    )?;
    Ok(())
}

// ============================================================================
// 数据清理
// ============================================================================

/// 清理过期数据（按保留天数）
pub fn cleanup_old_data(
    conn: &Connection,
    ban_history_days: u32,
    failed_logs_days: u32,
    jail_stats_days: u32,
    ddos_events_days: u32,
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let tx = conn.unchecked_transaction()?;

    // 清理已过期且超过保留期的封禁历史
    let cutoff = now - (ban_history_days as i64) * 86400;
    tx.execute(
        "DELETE FROM ban_history WHERE banned_at < ?1 AND status != 'active'",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的失败日志
    let cutoff = now - (failed_logs_days as i64) * 86400;
    tx.execute(
        "DELETE FROM failed_attempt_logs WHERE window_end < ?1",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的 Jail 统计
    let cutoff = now - (jail_stats_days as i64) * 86400;
    tx.execute(
        "DELETE FROM jail_stats_snapshots WHERE snapshot_time < ?1",
        rusqlite::params![cutoff],
    )?;

    // 清理过期的 DDoS 事件
    let cutoff = now - (ddos_events_days as i64) * 86400;
    tx.execute(
        "DELETE FROM ddos_events WHERE detected_at < ?1",
        rusqlite::params![cutoff],
    )?;

    tx.commit()?;
    Ok(())
}

// ============================================================================
// 统计查询（供 metrics 导出）
// ============================================================================

/// SQLite 统计信息
pub struct SqliteStats {
    pub ban_history_total: u64,
    pub ban_history_active: u64,
    pub failed_logs_total: u64,
    pub jail_stats_total: u64,
    pub ddos_events_total: u64,
}

/// 获取 SQLite 统计信息
pub fn get_stats(conn: &Connection) -> Result<SqliteStats> {
    let ban_history_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM ban_history", [], |row| row.get(0))?;

    let ban_history_active: u64 = conn.query_row(
        "SELECT COUNT(*) FROM ban_history WHERE status = 'active'",
        [],
        |row| row.get(0),
    )?;

    let failed_logs_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM failed_attempt_logs", [], |row| {
            row.get(0)
        })?;

    let jail_stats_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM jail_stats_snapshots", [], |row| {
            row.get(0)
        })?;

    let ddos_events_total: u64 =
        conn.query_row("SELECT COUNT(*) FROM ddos_events", [], |row| row.get(0))?;

    Ok(SqliteStats {
        ban_history_total,
        ban_history_active,
        failed_logs_total,
        jail_stats_total,
        ddos_events_total,
    })
}

/// 获取 WAL 文件大小（字节）
pub fn get_wal_size(db_path: &str) -> u64 {
    let wal_path = format!("{}-wal", db_path);
    std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0)
}
