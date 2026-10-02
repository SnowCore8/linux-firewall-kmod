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
mod attack_geo;
mod attack_prediction;
mod ban_recommendations;
mod network_distribution;
mod threshold_analysis;
mod today_bans;

// 重导出子模块的公共类型和函数，保持外部引用路径不变
pub use attack_detection::{
    detect_collaborative_attacks, detect_periodic_attackers, CollaborativeAttack, PeriodicAttacker,
};
pub use attack_geo::{get_attack_geo, AttackGeoResponse, GeoPoint};
pub use attack_prediction::{
    predict_attacks, AttackPrediction, AttackPredictionSummary, JailAttackTrend,
};
pub use ban_recommendations::{recommend_ban_durations, JailBanRecommendation};
pub use network_distribution::{get_network_distribution, NetworkBlock};
pub use threshold_analysis::{
    analyze_thresholds, ThresholdRecommendation, ThresholdRecommendationResponse,
};
pub use today_bans::today_ban_count;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::thread::JoinHandle;

use crate::runtime::channel::{self, Backpressure};

/// 历史数据数据库路径
const HISTORY_DB_PATH: &str = "/var/lib/firewall/history.db";

/// 保留时长（秒）：24 小时
const RETENTION_SECS: i64 = 24 * 60 * 60;

/// 异步写库任务（封禁热路径只入队；队列满时阻塞生产者，不丢弃审计数据）
#[derive(Debug)]
enum DbWriteOp {
    PersistBan {
        ip: String,
        ban_count: u32,
        last_banned_at: i64,
        last_unbanned_at: i64,
        was_permanent: bool,
    },
    BanEvent {
        ip: String,
        jail_name: String,
        ban_count: u32,
        banned_at: i64,
    },
    PersistReputation {
        ip: String,
        score: u32,
        last_failure_at: i64,
        total_failures: u32,
        total_bans: u32,
    },
}

/// 全局数据库连接（通过 `history_db()` 访问）
static HISTORY_DB: once_cell::sync::Lazy<Mutex<Option<Connection>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// 写队列容量。与旧 `sync_channel(1024)` 同值：本次改的是**满时行为**
/// （丢弃 → 阻塞），不调队列长度，故滞留上界不变。
const DB_WRITE_QUEUE_CAPACITY: usize = 1024;

/// 队列深度告警水位。达到此深度打一条 warn（升沿触发，不刷屏），让「写库变慢」
/// 在监控面上先可见，而不是等它变成阻塞。
const DB_WRITE_HIGH_WATER: usize = DB_WRITE_QUEUE_CAPACITY * 3 / 4;

/// 写队列发送端（有界，[`Backpressure::Block`]：满时阻塞生产者）。
///
/// 投递方**先克隆发送端再 `send`**：`send` 可能在满队列上阻塞，不能握着这把锁阻塞
/// ——否则关停线程取不到锁，无法摘掉发送端、队列也就永远不会断开。
static DB_WRITE_TX: once_cell::sync::Lazy<Mutex<Option<channel::Sender<DbWriteOp>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// 写线程句柄。关停时必须 `join`：写线程会把已入队的 op 全部落盘后才退出。
static DB_WRITE_JOIN: once_cell::sync::Lazy<Mutex<Option<JoinHandle<()>>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(None));

/// 「队列不可用」是否已经报过。仅在**升沿**打 warn：库初始化失败时
/// `persist_ip_reputation` 处于每条失败日志的路径上，逐条 warn 会淹掉日志。
static DB_WRITE_ABSENT_LOGGED: AtomicBool = AtomicBool::new(false);

/// 队列深度是否已越过 [`DB_WRITE_HIGH_WATER`]（用于升沿触发）。
static DB_WRITE_ALARMED: AtomicBool = AtomicBool::new(false);

/// 获取历史数据库锁（统一错误信息）
///
/// Mutex 中毒仅在所有权线程 panic 时发生，
/// 本模块所有 SQLite 操作均为简单查询/写入，不会 panic。
pub(super) fn history_db() -> std::sync::MutexGuard<'static, Option<Connection>> {
    HISTORY_DB
        .lock()
        .expect("HISTORY_DB 互斥锁中毒，请检查 SQLite 操作是否发生 panic")
}

fn enqueue_db_write(op: DbWriteOp) {
    // 先克隆发送端、释放全局锁，再投递：`Block` 策略下 `send` 可能在满队列上阻塞，
    // 不能握着锁阻塞（见 `DB_WRITE_TX` 的说明）。
    let tx = DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒").clone();
    let Some(tx) = tx else {
        // 库未装配或已关停。旧实现这里是静默 `return`——除「队列满」之外的第二条
        // 静默丢弃路径；按缺陷 G 的口径，凡未入队都必须可见。仅报一次（升沿）。
        if !DB_WRITE_ABSENT_LOGGED.swap(true, Ordering::Relaxed) {
            crate::logger::warn!(
                crate::logger::get(),
                "历史库写队列不可用，持久化未入队（后续同类情况不再重复告警）";
                "reason" => "未装配或已关停"
            );
        }
        return;
    };

    // 投递失败只可能是通道断开（写线程已退出）——同样不能静默。
    if tx.send(op).is_err() {
        crate::logger::warn!(crate::logger::get(), "历史库写线程已退出，一次持久化未入队");
        return;
    }

    note_queue_depth(tx.len());
}

/// 队列深度可见性：首次越过 [`DB_WRITE_HIGH_WATER`] 时打一条 warn（升沿触发），
/// 回落到水位以下后重新武装。
fn note_queue_depth(depth: usize) {
    if depth >= DB_WRITE_HIGH_WATER {
        if !DB_WRITE_ALARMED.swap(true, Ordering::Relaxed) {
            crate::logger::warn!(
                crate::logger::get(),
                "历史库写队列积压，写库已跟不上";
                "depth" => depth,
                "capacity" => DB_WRITE_QUEUE_CAPACITY
            );
        }
    } else if DB_WRITE_ALARMED.load(Ordering::Relaxed) {
        DB_WRITE_ALARMED.store(false, Ordering::Relaxed);
    }
}

fn apply_db_write(conn: &Connection, op: DbWriteOp) {
    match op {
        DbWriteOp::PersistBan {
            ip,
            ban_count,
            last_banned_at,
            last_unbanned_at,
            was_permanent,
        } => {
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
                    "error" => %e
                );
            }
        }
        DbWriteOp::BanEvent {
            ip,
            jail_name,
            ban_count,
            banned_at,
        } => {
            if let Err(e) = conn.execute(
                "INSERT INTO ban_events (ip, jail_name, banned_at, ban_count)
                 VALUES (?1, ?2, ?3, ?4)",
                params![ip, jail_name, banned_at, ban_count],
            ) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "记录封禁事件失败";
                    "error" => %e
                );
            }
        }
        DbWriteOp::PersistReputation {
            ip,
            score,
            last_failure_at,
            total_failures,
            total_bans,
        } => {
            if let Err(e) = conn.execute(
                "INSERT OR REPLACE INTO ip_reputation
                 (ip, score, last_failure_at, total_failures, total_bans)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![ip, score, last_failure_at, total_failures, total_bans],
            ) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "持久化 IP 信誉分失败";
                    "error" => %e
                );
            }
        }
    }
}

/// 建表与索引。
///
/// schema 的**唯一来源**：初始化路径与单测共用，避免两边各写一份 DDL 后漂移
/// （测试用的是内存库 / 临时库，走的是同一个 `init_schema`）。
fn init_schema(conn: &Connection) -> Result<()> {
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

    Ok(())
}

/// 初始化历史数据库
pub fn init_history_db() -> Result<()> {
    let db_path = PathBuf::from(HISTORY_DB_PATH);

    // 确保目录存在
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(&db_path)?;
    init_schema(&conn)?;

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

    // 后台写线程：封禁热路径只入队，避免同步 fsync 拖住主循环 / netlink 处理。
    // 队列满时**阻塞生产者**（`Backpressure::Block`）——历史是审计数据，不允许丢。
    let (tx, rx, _stats) =
        channel::bounded::<DbWriteOp>(DB_WRITE_QUEUE_CAPACITY, Backpressure::Block);
    *DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒") = Some(tx);
    *DB_WRITE_JOIN.lock().expect("DB_WRITE_JOIN 互斥锁中毒") = Some(spawn_db_writer(rx)?);
    // 队列重新可用：解除「不可用」告警闩锁，让下一次不可用能再报一次。
    DB_WRITE_ABSENT_LOGGED.store(false, Ordering::Relaxed);

    Ok(())
}

/// 启动写线程：把已入队的 op 全部落盘，直到所有发送端退出。
///
/// 退出条件是**发送端全部丢弃**（`recv` 返回 `Err`），而不是收到某个「关闭哨兵」：
/// 哨兵排在队列尾部，排在它后面的 op 会被跳过；丢弃发送端则让本循环先把队列排空、
/// 再退出——这正是 [`close_history_db`] 依赖的顺序保证。
fn spawn_db_writer(rx: channel::Receiver<DbWriteOp>) -> Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("history-db-writer".into())
        .spawn(move || {
            while let Ok(op) = rx.recv() {
                let db = history_db();
                match db.as_ref() {
                    Some(conn) => apply_db_write(conn, op),
                    // 连接已关而队列里还有 op：正确顺序下不可达（`close_history_db`
                    // 先 join 本线程再关连接）。这里仍打 warning 而不是静默跳过，
                    // 免得将来把顺序改错时又退回「无声丢弃」。
                    None => {
                        crate::logger::warn!(crate::logger::get(), "历史库已关闭，一次持久化未落盘")
                    }
                }
            }
        })
        .context("启动 history-db-writer 失败")
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

/// 持久化单个 IP 的封禁历史到 SQLite（异步入队，不阻塞调用方）
///
/// 在 record_ban/record_unban 后调用，使用 INSERT OR REPLACE 保证幂等
pub fn persist_ban_entry(
    ip: &str,
    ban_count: u32,
    last_banned_at: i64,
    last_unbanned_at: i64,
    was_permanent: bool,
) {
    enqueue_db_write(DbWriteOp::PersistBan {
        ip: ip.to_string(),
        ban_count,
        last_banned_at,
        last_unbanned_at,
        was_permanent,
    });
}

/// 记录单次封禁事件（每次封禁追加一行，用于周期性攻击检测）
pub fn record_ban_event(ip: &str, jail_name: &str, ban_count: u32) {
    enqueue_db_write(DbWriteOp::BanEvent {
        ip: ip.to_string(),
        jail_name: jail_name.to_string(),
        ban_count,
        banned_at: crate::types::now_secs(),
    });
}

/// 持久化 IP 信誉分到 SQLite（异步入队）
pub fn persist_ip_reputation(
    ip: &str,
    score: u32,
    last_failure_at: i64,
    total_failures: u32,
    total_bans: u32,
) {
    enqueue_db_write(DbWriteOp::PersistReputation {
        ip: ip.to_string(),
        score,
        last_failure_at,
        total_failures,
        total_bans,
    });
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
///
/// 顺序：**断开写队列 → join 写线程（它会把已入队的 op 全部落盘）→ 关连接**。
///
/// 旧实现是「发一个 `Shutdown` 哨兵后立刻把连接置 `None`」：哨兵排在队列尾部，而连接
/// 已变 `None`，写线程拿到 `None` 就静默跳过——队列里尚未落盘的历史数据被无声丢掉，
/// 且没有任何日志。也就是说，「关停时先停 netlink 再 flush」这条承诺此前并不成立。
pub fn close_history_db() {
    // 摘下发送端并丢弃：所有克隆（含正在投递的临时克隆）释放后，写线程的 `recv`
    // 会先把队列里剩余的 op 全部返回、再返回 `Err`，于是它排空后才退出。
    let tx = DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒").take();
    drop(tx);

    if let Some(handle) = DB_WRITE_JOIN
        .lock()
        .expect("DB_WRITE_JOIN 互斥锁中毒")
        .take()
    {
        if handle.join().is_err() {
            crate::logger::warn!(
                crate::logger::get(),
                "历史库写线程异常退出，可能有未落盘的持久化"
            );
        }
    }

    // 到这里队列已排空、写线程已退出，关连接不会再有并发写。
    let mut db = history_db();
    *db = None;

    // 关停窗口内若还有生产者（正常顺序下不该有），让「不可用」再报一次。
    DB_WRITE_ABSENT_LOGGED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::channel::QueueStats;
    use std::sync::Arc;

    /// 每个用例都会改全局（`HISTORY_DB` / `DB_WRITE_TX` / `DB_WRITE_JOIN`），
    /// 而 `cargo test` 默认多线程跑同一进程，故彼此串行。
    static SERIAL: Mutex<()> = Mutex::new(());

    /// 临时库路径。用完即删（`assemble` 开头也先删一次，避免上次残留）。
    fn tmp_db(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("fw-history-test-{}-{tag}.db", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    /// 装配「库 + 有界队列 + 写线程」，并把发送端登记到全局。
    ///
    /// 与 [`init_history_db`] 的区别只在库的来源（临时文件 vs 固定路径）：
    /// schema 走同一个 [`init_schema`]，队列与写线程走同一条装配路径。
    /// 调用方负责结束时调 [`close_history_db`] 拆掉全局。
    fn assemble(capacity: usize, path: &std::path::Path) -> Arc<QueueStats> {
        let conn = Connection::open(path).expect("打开测试库");
        init_schema(&conn).expect("建表");
        *history_db() = Some(conn);

        let (tx, rx, stats) = channel::bounded::<DbWriteOp>(capacity, Backpressure::Block);
        *DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒") = Some(tx);
        *DB_WRITE_JOIN.lock().expect("DB_WRITE_JOIN 互斥锁中毒") =
            Some(spawn_db_writer(rx).expect("启动写线程"));
        DB_WRITE_ABSENT_LOGGED.store(false, Ordering::Relaxed);
        stats
    }

    fn count_rows(path: &std::path::Path, sql: &str) -> i64 {
        let conn = Connection::open(path).expect("重开测试库");
        conn.query_row(sql, [], |r| r.get(0)).expect("计数")
    }

    /// 队列容量远小于投递量：`Block` 策略下生产者必须被阻塞而不是被丢弃——
    /// 全部 op 一条不少地落盘，且拒绝计数为 0。
    ///
    /// 这是缺陷 G 的核心断言：旧实现（`try_send`）在容量 4 的队列上投 200 条，
    /// 绝大多数会被丢弃，本用例会直接失败。
    #[test]
    fn saturated_queue_blocks_the_producer_and_loses_nothing() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        const CAPACITY: usize = 4;
        const OPS: usize = 200;

        let path = tmp_db("saturated");
        let stats = assemble(CAPACITY, &path);

        for i in 0..OPS {
            enqueue_db_write(DbWriteOp::PersistBan {
                ip: format!("10.0.0.{i}"),
                ban_count: 1,
                last_banned_at: 1_700_000_000 + i as i64,
                last_unbanned_at: 0,
                was_permanent: false,
            });
        }

        // `close_history_db` 保证「排空后才关连接」，因此关停点即同步点，无需 sleep。
        close_history_db();

        assert!(
            stats.sent() as usize >= OPS,
            "入队条数少于投递条数: {} < {OPS}",
            stats.sent()
        );
        assert_eq!(stats.rejected(), 0, "Block 策略下不应出现拒绝计数");
        // 只数本用例自己的 IP 段：同进程内其它单测的写入（如决策层测封禁记录的用例）
        // 也会经全局发送端落库，按 IP 段过滤才不会把它们算进来。
        assert_eq!(
            count_rows(
                &path,
                "SELECT COUNT(*) FROM ban_history WHERE ip LIKE '10.0.0.%'"
            ),
            OPS as i64,
            "有持久化未落盘（被静默丢弃）"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 关停时队列里还压着未落盘的 op：必须先全部落盘再关连接。
    ///
    /// 构造方式：先只登记发送端（无消费者），把 op 全部压进队列，**之后**才起写线程
    /// 并立即关停。旧实现（哨兵 + 立刻置 `None`）会把这批 op 整批跳过；本用例在旧
    /// 实现下必然失败，在新实现下必然通过（不依赖时序）。
    #[test]
    fn close_drains_ops_queued_before_the_writer_started() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        const OPS: usize = 50;

        let path = tmp_db("drain");
        let conn = Connection::open(&path).expect("打开测试库");
        init_schema(&conn).expect("建表");
        *history_db() = Some(conn);

        let (tx, rx, _stats) = channel::bounded::<DbWriteOp>(64, Backpressure::Block);
        for i in 0..OPS {
            tx.send(DbWriteOp::BanEvent {
                ip: format!("10.1.0.{i}"),
                jail_name: "sshd".into(),
                ban_count: 1,
                banned_at: 1_700_000_000 + i as i64,
            })
            .expect("队列容量 64，压 50 条不应失败");
        }
        assert_eq!(tx.len(), OPS, "前提：这批 op 尚未被消费");

        // 现在才起写线程，并立刻关停——关停必须把它全部排空。
        *DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒") = Some(tx);
        *DB_WRITE_JOIN.lock().expect("DB_WRITE_JOIN 互斥锁中毒") =
            Some(spawn_db_writer(rx).expect("启动写线程"));
        close_history_db();

        assert_eq!(
            count_rows(
                &path,
                "SELECT COUNT(*) FROM ban_events WHERE ip LIKE '10.1.0.%'"
            ),
            OPS as i64,
            "关停时队列里未落盘的 op 被丢弃"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// 未装配时投递：不得 panic，也不得静默——此刻队列为空、无写线程。
    #[test]
    fn enqueue_without_assembly_is_a_no_op_and_reports_once() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        *DB_WRITE_TX.lock().expect("DB_WRITE_TX 互斥锁中毒") = None;
        DB_WRITE_ABSENT_LOGGED.store(false, Ordering::Relaxed);

        enqueue_db_write(DbWriteOp::BanEvent {
            ip: "10.2.0.1".into(),
            jail_name: "sshd".into(),
            ban_count: 1,
            banned_at: 1,
        });
        enqueue_db_write(DbWriteOp::BanEvent {
            ip: "10.2.0.2".into(),
            jail_name: "sshd".into(),
            ban_count: 1,
            banned_at: 1,
        });

        assert!(
            DB_WRITE_ABSENT_LOGGED.load(Ordering::Relaxed),
            "未装配时的丢弃必须被标记为「已告警」，不能静默"
        );
    }

    /// 队列深度告警水位：越过水位报警（升沿只报一次），回落后重新武装。
    #[test]
    fn depth_alarm_fires_on_the_rising_edge_only() {
        let _guard = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        DB_WRITE_ALARMED.store(false, Ordering::Relaxed);

        note_queue_depth(DB_WRITE_HIGH_WATER - 1);
        assert!(
            !DB_WRITE_ALARMED.load(Ordering::Relaxed),
            "未到水位不应报警"
        );

        note_queue_depth(DB_WRITE_HIGH_WATER);
        assert!(DB_WRITE_ALARMED.load(Ordering::Relaxed), "到达水位应报警");

        note_queue_depth(0);
        assert!(
            !DB_WRITE_ALARMED.load(Ordering::Relaxed),
            "回落后应重新武装"
        );
    }
}
