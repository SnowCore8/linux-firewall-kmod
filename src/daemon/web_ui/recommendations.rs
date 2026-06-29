//! 智能推荐
//!
//! 提供封禁时长推荐、IP 信誉分、阈值调优建议等 API 实现。

use serde::Serialize;

/// 单个 Jail 的封禁时长推荐
#[derive(Serialize)]
pub struct BanDurationRecommendation {
    pub jail_name: String,
    pub current_ban_time: i32,
    pub recidivist_count: u32,
    pub median_return_secs: u64,
    pub recommended_ban_time: u64,
    pub reason: String,
    /// 是否需要调整
    pub needs_adjustment: bool,
}

/// 封禁时长推荐响应
#[derive(Serialize)]
pub struct BanDurationRecommendationResponse {
    pub recommendations: Vec<BanDurationRecommendation>,
    pub summary: String,
}

/// IP 信誉分条目响应
#[derive(Serialize)]
pub struct ReputationEntryResponse {
    /// IP 地址
    pub ip: String,
    /// 信誉分（0-100）
    pub score: u32,
    /// 最后一次失败时间（Unix 秒）
    pub last_failure_at: i64,
    /// 累计失败次数
    pub total_failures: u32,
    /// 累计封禁次数
    pub total_bans: u32,
    /// 当前阈值乘数
    pub threshold_multiplier: f64,
}

/// 阈值调优建议响应（复用 history_snapshot 类型）
pub use crate::history_snapshot::ThresholdRecommendationResponse;

/// 获取封禁时长推荐
pub fn get_ban_duration_recommendations() -> BanDurationRecommendationResponse {
    let jails = super::super::http_exporter::get_global_jails();
    let raw = crate::history_snapshot::recommend_ban_durations(&jails);

    if raw.is_empty() {
        return BanDurationRecommendationResponse {
            recommendations: vec![],
            summary: "无足够数据生成推荐（需要至少 7 天封禁历史）".to_string(),
        };
    }

    let needs_adj_count = raw
        .iter()
        .filter(|r| {
            let current = if r.current_ban_time > 0 {
                r.current_ban_time as u64
            } else {
                86400
            };
            r.recommended_ban_time > current
        })
        .count();

    let summary = if needs_adj_count == 0 {
        "所有 Jail 的封禁时长已足够，无需调整".to_string()
    } else {
        format!("{} 个 Jail 建议延长封禁时长以降低复发率", needs_adj_count)
    };

    let recommendations = raw
        .into_iter()
        .map(|r| {
            let current = if r.current_ban_time > 0 {
                r.current_ban_time as u64
            } else {
                86400
            };
            BanDurationRecommendation {
                jail_name: r.jail_name,
                current_ban_time: r.current_ban_time,
                recidivist_count: r.recidivist_count,
                median_return_secs: r.median_return_secs,
                recommended_ban_time: r.recommended_ban_time,
                reason: r.reason,
                needs_adjustment: r.recommended_ban_time > current,
            }
        })
        .collect();

    BanDurationRecommendationResponse {
        recommendations,
        summary,
    }
}
