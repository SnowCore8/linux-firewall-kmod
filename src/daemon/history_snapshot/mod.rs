//! 历史数据快照模块 - 使用时间序列数据库存储监控历史
//!
//! # 功能
//! - 定期记录统计数据快照（每 5 分钟）
//! - 保留最近 24 小时的历史数据
//! - 为 Web UI 图表提供真实的历史趋势数据
//!
//! # 设计
//! - 使用 SQLite 存储时间序列数据
//! - 表结构：(timestamp, metric_name, metric_value)
//! - 启动时初始化数据库并清理过期数据
//! - 运行时定期写入新快照

use anyhow::Result;
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::Mutex;

/// 历史数据数据库路径
const HISTORY_DB_PATH: &str = "/var/lib/firewall/history.db";

/// 保留时长（秒）：24 小时
const RETENTION_SECS: i64 = 24 * 60 * 60;

/// 全局数据库连接
static HISTORY_DB: once_cell::sync::Lazy<Mutex<Option<Connection>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// 初始化历史数据库
pub fn init_history_db() -> Result<()> {
    let db_path = PathBuf::from(HISTORY_DB_PATH);

    // 确保目录存在
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(&db_path)?;

    // 创建表
    conn.execute(
        "CREATE TABLE IF NOT EXISTS historical_stats (
            timestamp INTEGER NOT NULL,
            metric_name TEXT NOT NULL,
            metric_value INTEGER NOT NULL,
            PRIMARY KEY (timestamp, metric_name)
        )",
        [],
    )?;

    // 创建索引
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON historical_stats(timestamp)",
        [],
    )?;

    // 清理过期数据
    cleanup_expired_data(&conn)?;

    // 保存全局连接
    let mut db = HISTORY_DB.lock().unwrap();
    *db = Some(conn);

    Ok(())
}

/// 记录统计数据快照
pub fn record_snapshot(
    timestamp: i64,
    bans_last_5min: u64,
    failed_attempts_last_5min: u64,
    ddos_events_last_5min: u64,
) -> Result<()> {
    let db = HISTORY_DB.lock().unwrap();
    if let Some(conn) = db.as_ref() {
        // 插入封禁数
        conn.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'bans', ?2)",
            params![timestamp, bans_last_5min],
        )?;

        // 插入失败尝试数
        conn.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'failed_attempts', ?2)",
            params![timestamp, failed_attempts_last_5min],
        )?;

        // 插入 DDoS 事件数
        conn.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'ddos_events', ?2)",
            params![timestamp, ddos_events_last_5min],
        )?;

        // 定期清理过期数据（每次写入时检查）
        cleanup_expired_data(conn)?;
    }
    Ok(())
}

/// 查询最近 24 小时的趋势数据
pub fn get_trend_data(metric_name: &str, hours: i64) -> Result<Vec<(i64, u64)>> {
    let db = HISTORY_DB.lock().unwrap();
    if let Some(conn) = db.as_ref() {
        let now = chrono::Utc::now().timestamp();
        let start_time = now - (hours * 3600);

        let mut stmt = conn.prepare(
            "SELECT timestamp, metric_value FROM historical_stats
             WHERE metric_name = ?1 AND timestamp >= ?2
             ORDER BY timestamp ASC"
        )?;

        let rows = stmt.query_map(params![metric_name, start_time], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;

        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }

        Ok(result)
    } else {
        Ok(Vec::new())
    }
}

/// 查询 Jail 分布数据（最近 24 小时的总和）
pub fn get_jail_distribution() -> Result<Vec<(String, u64)>> {
    // 从 ACTIVE_BAN_CACHE 获取当前分布
    let cache = crate::types::ACTIVE_BAN_CACHE.get();
    if let Some(cache) = cache {
        let snapshot = cache.snapshot();
        let mut jail_counts = std::collections::HashMap::new();

        for ban in snapshot {
            *jail_counts.entry(ban.jail_name.clone()).or_insert(0u64) += 1;
        }

        Ok(jail_counts.into_iter().collect())
    } else {
        Ok(Vec::new())
    }
}

/// 清理过期数据
fn cleanup_expired_data(conn: &Connection) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - RETENTION_SECS;

    conn.execute(
        "DELETE FROM historical_stats WHERE timestamp < ?1",
        params![cutoff],
    )?;

    Ok(())
}

/// 关闭数据库连接
pub fn close_history_db() {
    let mut db = HISTORY_DB.lock().unwrap();
    *db = None;
}
