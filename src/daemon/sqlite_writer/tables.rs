//! 表初始化与迁移模块

use anyhow::Result;
use rusqlite::Connection;

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
