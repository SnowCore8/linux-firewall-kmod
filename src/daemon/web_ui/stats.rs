//! Dashboard 统计数据 — 威胁等级、图表数据、复发率
//!
//! # 职责
//! - `get_stats()` — Dashboard 统计数据聚合
//! - `calculate_threat_level()` — 威胁等级评估
//! - `generate_*()` — 图表数据生成（趋势、分布）
//! - `get_ban_recidivism()` — 封禁复发率统计

use serde::Serialize;

use crate::types::{ACTIVE_BAN_CACHE, DAEMON_STATS, DDOS_STATS};

/// 趋势数据缓存（避免每秒重复查询 SQLite，数据每 5 分钟才更新一次）
static TREND_CACHE: std::sync::OnceLock<parking_lot::Mutex<TrendCache>> =
    std::sync::OnceLock::new();

struct TrendCache {
    ban_trend: ChartData,
    failed_trend: ChartData,
    last_update: i64,
}

/// 趋势数据缓存间隔（秒）：30 秒内复用上次查询结果
const TREND_CACHE_INTERVAL: i64 = 30;

fn get_trend_cache() -> &'static parking_lot::Mutex<TrendCache> {
    TREND_CACHE.get_or_init(|| {
        parking_lot::Mutex::new(TrendCache {
            ban_trend: ChartData {
                labels: vec![],
                values: vec![],
            },
            failed_trend: ChartData {
                labels: vec![],
                values: vec![],
            },
            last_update: 0,
        })
    })
}

/// 威胁等级评估
#[derive(Serialize)]
pub struct ThreatLevel {
    /// 威胁等级：safe/low/medium/high/critical
    pub level: String,
    /// 数值化等级（0-4）
    pub score: u8,
    /// 评估依据
    pub factors: Vec<String>,
    /// 当前 PPS
    pub current_pps: u64,
    /// PPS 阈值比率（0.0-1.0+）
    pub pps_ratio: f64,
    /// 封禁表使用率（0.0-1.0）
    pub ban_table_usage: f64,
    /// 最近 5 分钟封禁数
    pub recent_bans: u64,
    /// 基线是否冻结（异常流量检测）
    pub baseline_frozen: bool,
    /// 是否处于业务高峰期（基线上调 50%）
    pub peak_hours: bool,
}

/// 统计数据响应
#[derive(Serialize)]
pub struct StatsResponse {
    pub daemon_version: String,
    pub kernel_version: String,
    pub today_bans: u64,
    pub failed_attempts: u64,
    pub ddos_events: u64,
    pub uptime_seconds: u64,
    pub ban_trend: ChartData,
    pub jail_distribution: ChartData,
    pub failure_reasons: ChartData,
    pub failed_attempts_trend: ChartData,
    // 内核统计数据
    pub current_bans: u64,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub whitelist_count: u64,
    pub packets_dropped: u64,
    pub packets_accepted: u64,
    /// 实时威胁等级评估
    pub threat_level: ThreatLevel,
}

/// 图表数据
#[derive(Serialize, Clone)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub values: Vec<u64>,
}

// ============================================================================
// 封禁效果追踪 — 复发率统计
// ============================================================================

/// 封禁效果追踪 — 复发率统计
///
/// 复发：一个 IP 被封禁后解封，再次被封禁（ban_count >= 2）
#[derive(Serialize)]
pub struct RecidivismResponse {
    /// 总封禁 IP 数（历史）
    pub total_ips: u64,
    /// 复发 IP 数（ban_count >= 2）
    pub recidivist_ips: u64,
    /// 复发率（0.0 ~ 100.0）
    pub recidivism_rate: f64,
    /// 当前永久封禁 IP 数
    pub permanent_bans: u64,
    /// 复发 IP TOP 10
    pub top_recidivists: Vec<RecidivistEntry>,
}

/// 单个复发 IP 的信息
#[derive(Serialize)]
pub struct RecidivistEntry {
    pub ip: String,
    pub ban_count: u32,
    pub last_banned_at: i64,
    pub was_permanent: bool,
}

/// 获取统计数据
pub fn get_stats() -> StatsResponse {
    let now = crate::types::now_secs();
    let start_time = DAEMON_STATS
        .start_time
        .load(std::sync::atomic::Ordering::Relaxed) as i64;
    let uptime = if start_time > 0 { now - start_time } else { 0 };

    let today_bans = DAEMON_STATS
        .ips_banned
        .load(std::sync::atomic::Ordering::Relaxed);
    let failed_attempts = DAEMON_STATS
        .failed_attempts
        .load(std::sync::atomic::Ordering::Relaxed);
    let ddos_events = DDOS_STATS
        .events_detected
        .load(std::sync::atomic::Ordering::Relaxed);

    // 封禁数据全部走内存，与 /api/bans 保持一致
    let current_bans = ACTIVE_BAN_CACHE
        .get()
        .map(|cache| cache.len() as u64)
        .unwrap_or(0);
    let total_bans = DAEMON_STATS
        .ips_banned
        .load(std::sync::atomic::Ordering::Relaxed);

    // 从内存计数器读取（近似值）
    let total_unbans = DAEMON_STATS
        .total_unbans
        .load(std::sync::atomic::Ordering::Relaxed);
    let whitelist_count = DAEMON_STATS
        .whitelist_count
        .load(std::sync::atomic::Ordering::Relaxed);
    let packets_dropped = DAEMON_STATS
        .packets_dropped
        .load(std::sync::atomic::Ordering::Relaxed);
    let packets_accepted = DAEMON_STATS
        .packets_accepted
        .load(std::sync::atomic::Ordering::Relaxed);

    // 单次快照计算三个维度：Jail 分布 + 原因分布 + 近 5 分钟封禁数
    let five_min_ago = now - 300;
    let (jail_distribution, failure_reasons, recent_bans) = {
        let mut jail_map = std::collections::HashMap::new();
        let mut reason_map = std::collections::HashMap::new();
        let mut recent = 0u64;

        if let Some(cache) = ACTIVE_BAN_CACHE.get() {
            for ban in cache.snapshot() {
                *jail_map.entry(ban.jail_name.clone()).or_insert(0u64) += 1;
                *reason_map.entry(ban.reason.clone()).or_insert(0) += 1;
                if ban.banned_at > five_min_ago {
                    recent += 1;
                }
            }
        }

        let mut jail_dist: Vec<(String, u64)> = jail_map.into_iter().collect();
        jail_dist.sort_by(|a, b| a.0.cmp(&b.0));

        let mut reason_dist: Vec<(String, u64)> = reason_map.into_iter().collect();
        reason_dist.sort_by_key(|b| std::cmp::Reverse(b.1));

        (
            ChartData {
                labels: jail_dist.iter().map(|(l, _)| l.clone()).collect(),
                values: jail_dist.iter().map(|(_, v)| *v).collect(),
            },
            ChartData {
                labels: reason_dist.iter().map(|(l, _)| l.clone()).collect(),
                values: reason_dist.iter().map(|(_, v)| *v).collect(),
            },
            recent,
        )
    };

    // 趋势数据共享缓存（30 秒刷新，避免每秒两次 SQLite 查询）
    let (ban_trend, failed_attempts_trend) = generate_trends_cached();

    StatsResponse {
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        kernel_version: "2.2".to_string(),
        today_bans,
        failed_attempts,
        ddos_events,
        uptime_seconds: uptime.max(0) as u64,
        ban_trend,
        jail_distribution,
        failure_reasons,
        failed_attempts_trend,
        current_bans,
        total_bans,
        total_unbans,
        whitelist_count,
        packets_dropped,
        packets_accepted,
        threat_level: calculate_threat_level(current_bans, ddos_events, recent_bans),
    }
}

/// 计算实时威胁等级
///
/// 综合多个信号源评估当前威胁状态：
/// - PPS 与阈值的比率
/// - 封禁表使用率
/// - 最近 5 分钟封禁数（由调用方预计算，避免重复遍历缓存）
/// - DDoS 事件计数
fn calculate_threat_level(current_bans: u64, ddos_events: u64, recent_bans: u64) -> ThreatLevel {
    let mut factors: Vec<String> = Vec::new();
    let mut score: u8 = 0;

    // 1. 当前 PPS（短期窗口）
    let current_pps = crate::types::get_rate_windows().pps_short;
    // 从 Web UI 配置读取实际阈值，确保与用户配置一致
    let pps_threshold = crate::http_exporter::get_global_webui_config()
        .map(|c| c.rate_warning_pps)
        .unwrap_or(100_000u64);
    let pps_ratio = if pps_threshold > 0 {
        current_pps as f64 / pps_threshold as f64
    } else {
        0.0
    };

    if pps_ratio > 1.0 {
        score = score.max(4);
        factors.push(format!("PPS 超阈值 ({:.1}x)", pps_ratio));
    } else if pps_ratio > 0.5 {
        score = score.max(3);
        factors.push(format!("PPS 接近阈值 ({:.0}%)", pps_ratio * 100.0));
    } else if pps_ratio > 0.2 {
        score = score.max(1);
    }

    // 2. 封禁表使用率
    // 内核哈希表固定 4096 桶（BAN_HASH_BITS=12），链式哈希可超出但性能下降。
    // 使用率基于内核桶数，非 daemon 配置容量。
    const KERNEL_BAN_BUCKETS: u64 = 4096;
    let ban_table_usage = current_bans as f64 / KERNEL_BAN_BUCKETS as f64;

    if ban_table_usage > 0.9 {
        score = score.max(4);
        factors.push(format!("封禁表即将满载 ({:.0}%)", ban_table_usage * 100.0));
    } else if ban_table_usage > 0.5 {
        score = score.max(2);
        factors.push(format!(
            "封禁表使用率偏高 ({:.0}%)",
            ban_table_usage * 100.0
        ));
    }

    // 3. 最近 5 分钟封禁数（调用方已计算）
    if recent_bans > 50 {
        score = score.max(4);
        factors.push(format!("5 分钟内 {} 次封禁", recent_bans));
    } else if recent_bans > 20 {
        score = score.max(3);
        factors.push(format!("5 分钟内 {} 次封禁", recent_bans));
    } else if recent_bans > 5 {
        score = score.max(2);
    }

    // 4. DDoS 事件（累计）
    if ddos_events > 10 {
        score = score.max(3);
        factors.push(format!("累计 {} 次 DDoS 事件", ddos_events));
    } else if ddos_events > 0 {
        score = score.max(1);
    }

    // 5. 基线冻结状态
    let baseline_frozen = crate::types::is_baseline_frozen();
    if baseline_frozen {
        score = score.max(3);
        factors.push("基线已冻结（异常流量突增）".to_string());
    }

    // 确定等级标签
    let level = match score {
        0 => "safe",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "critical",
    }
    .to_string();

    if factors.is_empty() {
        factors.push("一切正常".to_string());
    }

    ThreatLevel {
        level,
        score,
        factors,
        current_pps,
        pps_ratio,
        ban_table_usage,
        recent_bans,
        baseline_frozen: crate::types::is_baseline_frozen(),
        peak_hours: crate::file_monitor::monitor_loop::is_baseline_peak_hours(),
    }
}

/// 生成封禁趋势 + 失败尝试趋势（共享缓存，30 秒刷新一次）
fn generate_trends_cached() -> (ChartData, ChartData) {
    let now = crate::types::now_secs();
    let mut cache = get_trend_cache().lock();

    if now - cache.last_update < TREND_CACHE_INTERVAL && !cache.ban_trend.labels.is_empty() {
        return (cache.ban_trend.clone(), cache.failed_trend.clone());
    }

    let ban_trend = match crate::history_snapshot::get_trend_data("bans", 24) {
        Ok(data) if !data.is_empty() => {
            let labels = data
                .iter()
                .map(|(ts, _)| {
                    let dt =
                        chrono::DateTime::from_timestamp(*ts, 0).unwrap_or_else(chrono::Utc::now);
                    dt.format("%H:%M").to_string()
                })
                .collect();
            let values = data.iter().map(|(_, v)| *v).collect();
            ChartData { labels, values }
        }
        _ => ChartData {
            labels: vec![],
            values: vec![],
        },
    };

    let failed_trend = match crate::history_snapshot::get_trend_data("failed_attempts", 1) {
        Ok(data) if !data.is_empty() => {
            let labels = data
                .iter()
                .map(|(ts, _)| {
                    let dt =
                        chrono::DateTime::from_timestamp(*ts, 0).unwrap_or_else(chrono::Utc::now);
                    dt.format("%H:%M").to_string()
                })
                .collect();
            let values = data.iter().map(|(_, v)| *v).collect();
            ChartData { labels, values }
        }
        _ => ChartData {
            labels: vec![],
            values: vec![],
        },
    };

    cache.ban_trend = ban_trend.clone();
    cache.failed_trend = failed_trend.clone();
    cache.last_update = now;

    (ban_trend, failed_trend)
}

/// 封禁效果追踪 — 复发率 + TOP 10
pub fn get_ban_recidivism() -> RecidivismResponse {
    let history = match crate::types::BAN_HISTORY.get() {
        Some(h) => h,
        None => {
            return RecidivismResponse {
                total_ips: 0,
                recidivist_ips: 0,
                recidivism_rate: 0.0,
                permanent_bans: 0,
                top_recidivists: Vec::new(),
            };
        }
    };

    let snapshot = history.snapshot();
    let total_ips = snapshot.len() as u64;
    let mut recidivists: Vec<&crate::types::BanHistoryEntry> =
        snapshot.iter().filter(|e| e.ban_count >= 2).collect();
    let recidivist_ips = recidivists.len() as u64;
    let permanent_bans = snapshot.iter().filter(|e| e.was_permanent).count() as u64;
    let recidivism_rate = if total_ips > 0 {
        (recidivist_ips as f64 / total_ips as f64) * 100.0
    } else {
        0.0
    };

    // 按 ban_count 降序排序取 TOP 10
    recidivists.sort_by_key(|b| std::cmp::Reverse(b.ban_count));
    let top_recidivists = recidivists
        .into_iter()
        .take(10)
        .map(|e| RecidivistEntry {
            ip: e.ip.clone(),
            ban_count: e.ban_count,
            last_banned_at: e.last_banned_at,
            was_permanent: e.was_permanent,
        })
        .collect();

    RecidivismResponse {
        total_ips,
        recidivist_ips,
        recidivism_rate,
        permanent_bans,
        top_recidivists,
    }
}
