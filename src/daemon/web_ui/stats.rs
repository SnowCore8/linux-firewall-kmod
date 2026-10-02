//! Dashboard 统计数据 — 威胁等级、图表数据、复发率
//!
//! # 职责
//! - `generate_*()` — 图表数据生成（趋势、分布）
//! - `get_ban_recidivism()` — 封禁复发率统计
//!
//! 统计总览（`StatsResponse`）与威胁等级已迁到 [`crate::api::views`]：那份实现
//! 由 SSE 与 REST 共用，本模块不再持有第二份。

use serde::Serialize;

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

/// 生成封禁趋势 + 失败尝试趋势（共享缓存，30 秒刷新一次）
///
/// 供 `api::adapters` 的临时历史端口使用；2.F 历史库重写后连同 `generate_trends_cached`
/// 一并删除。
pub fn trends_snapshot() -> (ChartData, ChartData) {
    generate_trends_cached()
}

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
