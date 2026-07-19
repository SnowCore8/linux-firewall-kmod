//! 历史数据快照模块 - 使用时间序列数据库存储监控历史
//!
//! # 功能
//! - 定期记录统计数据快照（每 5 分钟）
//! - 保留最近 24 小时的历史数据
//! - 为 Web UI 图表提供真实的历史趋势数据
//! - 封禁历史持久化与恢复
//! - IP 信誉分持久化
//!
//! # 子模块
//! - [`attack_detection`] — 周期性攻击者检测、协同攻击检测
//! - [`attack_prediction`] — 攻击时间预测、Jail 攻击趋势
//! - [`ban_recommendations`] — 封禁时长推荐
//! - [`threshold_analysis`] — 阈值调优建议
//! - [`network_distribution`] — 攻击源网络分布

// 子模块
mod attack_detection;
mod attack_prediction;
mod ban_recommendations;
mod network_distribution;
mod threshold_analysis;

// 重导出子模块的公共类型和函数，保持外部引用路径不变
pub use attack_detection::{
    detect_collaborative_attacks, detect_periodic_attackers, CollaborativeAttack, PeriodicAttacker,
};
pub use attack_prediction::{
    predict_attacks, AttackPrediction, AttackPredictionSummary, JailAttackTrend,
};
pub use ban_recommendations::{recommend_ban_durations, JailBanRecommendation};
pub use network_distribution::{get_network_distribution, NetworkBlock};
pub use threshold_analysis::{
    analyze_thresholds, ThresholdRecommendation, ThresholdRecommendationResponse,
};

use anyhow::Result;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::Mutex;

/// 历史数据数据库路径
const HISTORY_DB_PATH: &str = "/var/lib/firewall/history.db";

/// 保留时长（秒）：24 小时
const RETENTION_SECS: i64 = 24 * 60 * 60;

/// 全局数据库连接（通过 `history_db()` 访问）
static HISTORY_DB: once_cell::sync::Lazy<Mutex<Option<Connection>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// 获取历史数据库锁（统一错误信息）
///
/// Mutex 中毒仅在所有权线程 panic 时发生，
/// 本模块所有 SQLite 操作均为简单查询/写入，不会 panic。
pub(super) fn history_db() -> std::sync::MutexGuard<'static, Option<Connection>> {
    HISTORY_DB
        .lock()
        .expect("HISTORY_DB 互斥锁中毒，请检查 SQLite 操作是否发生 panic")
}

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

    // 封禁历史表（渐进式封禁持久化）
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ban_history (
            ip TEXT PRIMARY KEY,
            ban_count INTEGER NOT NULL DEFAULT 0,
            last_banned_at INTEGER NOT NULL DEFAULT 0,
            last_unbanned_at INTEGER NOT NULL DEFAULT 0,
            was_permanent INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;

    // 封禁事件表（每次封禁记录一行，用于周期性攻击检测）
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ban_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            jail_name TEXT NOT NULL DEFAULT '',
            banned_at INTEGER NOT NULL,
            ban_count INTEGER NOT NULL DEFAULT 1
        )",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ban_events_ip ON ban_events(ip)",
        [],
    )?;

    // IP 信誉分表（动态阈值联动）
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_reputation (
            ip TEXT PRIMARY KEY,
            score INTEGER NOT NULL DEFAULT 100,
            last_failure_at INTEGER NOT NULL DEFAULT 0,
            total_failures INTEGER NOT NULL DEFAULT 0,
            total_bans INTEGER NOT NULL DEFAULT 0
        )",
        [],
    )?;

    // 清理过期数据
    cleanup_expired_data(&conn)?;

    // 清理过期封禁历史（7 天无活动）
    cleanup_expired_ban_history(&conn)?;

    // 从 SQLite 加载封禁历史到内存
    load_ban_history(&conn)?;

    // 保存全局连接
    let mut db = history_db();
    *db = Some(conn);

    // 从 SQLite 加载信誉分到内存（在连接存入后调用，使用 get_db）
    drop(db);
    load_ip_reputation();

    Ok(())
}

/// 记录统计数据快照
pub fn record_snapshot(
    timestamp: i64,
    bans_last_5min: u64,
    failed_attempts_last_5min: u64,
    ddos_events_last_5min: u64,
) -> Result<()> {
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        // 事务保证三个 INSERT 原子性，避免部分失败导致数据不一致
        let tx = conn.unchecked_transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'bans', ?2)",
            params![timestamp, bans_last_5min],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'failed_attempts', ?2)",
            params![timestamp, failed_attempts_last_5min],
        )?;

        tx.execute(
            "INSERT OR REPLACE INTO historical_stats (timestamp, metric_name, metric_value)
             VALUES (?1, 'ddos_events', ?2)",
            params![timestamp, ddos_events_last_5min],
        )?;

        tx.commit()?;

        // 定期清理过期数据（每次写入时检查）
        cleanup_expired_data(conn)?;

        // 清理过期封禁历史和事件（仅启动时清理不够，运行期间也需定期清理）
        cleanup_expired_ban_history(conn)?;
    }
    Ok(())
}

/// 查询最近 24 小时的趋势数据
pub fn get_trend_data(metric_name: &str, hours: i64) -> Result<Vec<(i64, u64)>> {
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        let now = chrono::Utc::now().timestamp();
        let start_time = now - (hours * 3600);

        let mut stmt = conn.prepare(
            "SELECT timestamp, metric_value FROM historical_stats
             WHERE metric_name = ?1 AND timestamp >= ?2
             ORDER BY timestamp ASC",
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

/// 按小时聚合的攻击热力图数据
///
/// 24 个时段（0-23），每个时段包含三个指标的聚合值
#[derive(Debug, Clone, serde::Serialize)]
pub struct HourlyHeatmap {
    /// 24 个小时时段（索引 0 = 当天 0 点）
    pub hours: [HourlyBucket; 24],
}

/// 单个时段的聚合数据
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct HourlyBucket {
    /// 小时编号（0-23）
    pub hour: u32,
    /// 该小时封禁总数
    pub bans: u64,
    /// 该小时失败尝试总数
    pub failed_attempts: u64,
    /// 该小时 DDoS 事件总数
    pub ddos_events: u64,
}

/// 查询最近 24 小时按小时聚合的热力图数据
///
/// 将 5 分钟粒度的原始数据聚合为 24 个小时桶，用于热力图可视化
pub fn get_hourly_heatmap() -> Result<HourlyHeatmap> {
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        let now = chrono::Utc::now().timestamp();
        let start_time = now - RETENTION_SECS;

        // 查询 24 小时内的所有数据
        let mut stmt = conn.prepare(
            "SELECT timestamp, metric_name, metric_value FROM historical_stats
             WHERE timestamp >= ?1
             ORDER BY timestamp ASC",
        )?;

        let rows = stmt.query_map(params![start_time], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, u64>(2)?,
            ))
        })?;

        let mut buckets = [HourlyBucket::default(); 24];
        for (i, bucket) in buckets.iter_mut().enumerate() {
            bucket.hour = i as u32;
        }

        for row in rows {
            let (timestamp, metric_name, value) = row?;
            // 将 Unix 时间戳转换为小时编号（UTC）
            let hour = ((timestamp % 86400) / 3600) as usize;
            if hour >= 24 {
                continue;
            }
            buckets[hour].hour = hour as u32;
            match metric_name.as_str() {
                "bans" => buckets[hour].bans += value,
                "failed_attempts" => buckets[hour].failed_attempts += value,
                "ddos_events" => buckets[hour].ddos_events += value,
                _ => {}
            }
        }

        Ok(HourlyHeatmap { hours: buckets })
    } else {
        // 无数据库时返回全零
        let mut buckets = [HourlyBucket::default(); 24];
        for (i, bucket) in buckets.iter_mut().enumerate() {
            bucket.hour = i as u32;
        }
        Ok(HourlyHeatmap { hours: buckets })
    }
}

/// 查询 Jail 分布数据
pub fn get_jail_distribution() -> Result<Vec<(String, u64)>> {
    let cache = crate::types::ACTIVE_BAN_CACHE.get();
    if let Some(cache) = cache {
        let snapshot = cache.snapshot();
        let mut jail_counts = std::collections::HashMap::new();

        for ban in snapshot {
            *jail_counts.entry(ban.jail_name.clone()).or_insert(0u64) += 1;
        }

        let mut result: Vec<(String, u64)> = jail_counts.into_iter().collect();
        // 按名称排序保证顺序稳定，防止饼图跳动
        result.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(result)
    } else {
        Ok(Vec::new())
    }
}

/// 清理过期数据
pub(super) fn cleanup_expired_data(conn: &Connection) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - RETENTION_SECS;

    conn.execute(
        "DELETE FROM historical_stats WHERE timestamp < ?1",
        params![cutoff],
    )?;

    Ok(())
}

/// 从 SQLite 加载封禁历史到内存 BAN_HISTORY
fn load_ban_history(conn: &Connection) -> Result<()> {
    let history = crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);

    let mut stmt = conn.prepare(
        "SELECT ip, ban_count, last_banned_at, last_unbanned_at, was_permanent
         FROM ban_history",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, bool>(4)?,
        ))
    })?;

    let mut count = 0u32;
    for row in rows {
        let (ip, ban_count, last_banned_at, last_unbanned_at, was_permanent) = row?;
        history.restore_entry(
            &ip,
            ban_count,
            last_banned_at,
            last_unbanned_at,
            was_permanent,
        );
        count += 1;
    }

    if count > 0 {
        crate::logger::info!(
          crate::logger::get(),
          "从 SQLite 加载封禁历史";
          "count" => count
        );
    }

    Ok(())
}

/// 清理过期封禁历史（7 天无活动）
fn cleanup_expired_ban_history(conn: &Connection) -> Result<()> {
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - 7 * 24 * 3600;

    // 只清理已解封且超过 7 天未活动的条目
    // last_unbanned_at > 0 表示已解封，last_banned_at 表示最后封禁时间
    conn.execute(
        "DELETE FROM ban_history
         WHERE last_unbanned_at > 0 AND last_unbanned_at < ?1",
        params![cutoff],
    )?;

    // 清理超过 7 天的封禁事件
    conn.execute(
        "DELETE FROM ban_events WHERE banned_at < ?1",
        params![cutoff],
    )?;

    Ok(())
}

/// 持久化单个 IP 的封禁历史到 SQLite
///
/// 在 record_ban/record_unban 后调用，使用 INSERT OR REPLACE 保证幂等
pub fn persist_ban_entry(
    ip: &str,
    ban_count: u32,
    last_banned_at: i64,
    last_unbanned_at: i64,
    was_permanent: bool,
) {
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO ban_history
             (ip, ban_count, last_banned_at, last_unbanned_at, was_permanent)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                ip,
                ban_count,
                last_banned_at,
                last_unbanned_at,
                was_permanent as i64
            ],
        ) {
            crate::logger::warn!(
                crate::logger::get(),
                "持久化封禁历史失败";
                "ip" => ip,
                "error" => %e
            );
        }
    }
}

/// 记录单次封禁事件（每次封禁追加一行，用于周期性攻击检测）
pub fn record_ban_event(ip: &str, jail_name: &str, ban_count: u32) {
    let now = crate::types::now_secs();
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        if let Err(e) = conn.execute(
            "INSERT INTO ban_events (ip, jail_name, banned_at, ban_count)
             VALUES (?1, ?2, ?3, ?4)",
            params![ip, jail_name, now, ban_count],
        ) {
            crate::logger::warn!(
                crate::logger::get(),
                "记录封禁事件失败";
                "ip" => ip,
                "jail" => jail_name,
                "error" => %e
            );
        }
    }
}

/// 持久化 IP 信誉分到 SQLite
pub fn persist_ip_reputation(
    ip: &str,
    score: u32,
    last_failure_at: i64,
    total_failures: u32,
    total_bans: u32,
) {
    let db = history_db();
    if let Some(conn) = db.as_ref() {
        if let Err(e) = conn.execute(
            "INSERT OR REPLACE INTO ip_reputation
             (ip, score, last_failure_at, total_failures, total_bans)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ip, score, last_failure_at, total_failures, total_bans],
        ) {
            crate::logger::warn!(
                crate::logger::get(),
                "持久化 IP 信誉分失败";
                "ip" => ip,
                "error" => %e
            );
        }
    }
}

/// 从 SQLite 加载 IP 信誉分到内存
fn load_ip_reputation() {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return,
    };
    let store = crate::ip_reputation::get_store();

    let mut stmt = match conn
        .prepare("SELECT ip, score, last_failure_at, total_failures, total_bans FROM ip_reputation")
    {
        Ok(s) => s,
        Err(_) => return,
    };

    let rows = match stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, u32>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, u32>(3)?,
            row.get::<_, u32>(4)?,
        ))
    }) {
        Ok(rows) => rows,
        Err(_) => return,
    };

    for (ip, score, last_failure_at, total_failures, total_bans) in rows.flatten() {
        store.restore_entry(&ip, score, last_failure_at, total_failures, total_bans);
    }

    // 加载后立即执行一次信誉恢复（补偿守护进程停机期间的恢复量）
    store.recover_scores();
}

/// 关闭数据库连接
pub fn close_history_db() {
    let mut db = history_db();
    *db = None;
}
