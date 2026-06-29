//! 阈值调优建议——分析每个 Jail 的阈值是否合理并给出调优建议

use super::history_db;

/// 单个 Jail 的阈值调优建议
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThresholdRecommendation {
    /// Jail 名称
    pub jail_name: String,
    /// 当前阈值（max_retries）
    pub current_threshold: u32,
    /// 推荐阈值（0 = 无需调整）
    pub recommended_threshold: u32,
    /// 建议方向："increase" / "decrease" / "maintain"
    pub direction: String,
    /// 7 天内总封禁次数
    pub total_bans: u32,
    /// 7 天内唯一 IP 数
    pub unique_ips: u32,
    /// 复发 IP 数（被封禁 > 1 次）
    pub recidivist_ips: u32,
    /// 复发率
    pub recidivism_rate: f64,
    /// 平均每个 IP 封禁次数
    pub avg_bans_per_ip: f64,
    /// 建议说明
    pub reason: String,
    /// 建议置信度（0-100）
    pub confidence: u8,
}

/// 阈值调优建议响应
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThresholdRecommendationResponse {
    pub recommendations: Vec<ThresholdRecommendation>,
    pub summary: String,
}

/// 分析每个 Jail 的阈值是否合理，给出调优建议
///
/// 算法逻辑：
/// - 复发率 > 30% → 阈值过松，建议增加（攻击者未被充分阻止）
/// - 复发率 < 10% 且封禁数 > 20 → 阈值可能过严（大量一次性误封）
/// - 复发率 10%-30% → 阈值合适
/// - 数据量 < 10 → 置信度低，建议观察
pub fn analyze_thresholds(
    jails: &[crate::http_exporter::JailInfo],
) -> ThresholdRecommendationResponse {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => {
            return ThresholdRecommendationResponse {
                recommendations: Vec::new(),
                summary: "数据库未初始化".to_string(),
            };
        }
    };

    let cutoff = crate::types::now_secs() - 7 * 86400;

    // 查询近 7 天内所有封禁事件，按 jail 分组统计
    let mut stmt = match conn.prepare(
        "SELECT jail_name, ip, COUNT(*) as cnt
     FROM ban_events
     WHERE banned_at >= ?1 AND jail_name != ''
     GROUP BY jail_name, ip
     ORDER BY jail_name",
    ) {
        Ok(s) => s,
        Err(_) => {
            return ThresholdRecommendationResponse {
                recommendations: Vec::new(),
                summary: "查询失败".to_string(),
            };
        }
    };

    let rows = match stmt.query_map([cutoff], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, u32>(2)?,
        ))
    }) {
        Ok(r) => r,
        Err(_) => {
            return ThresholdRecommendationResponse {
                recommendations: Vec::new(),
                summary: "查询失败".to_string(),
            };
        }
    };

    // 按 Jail 聚合
    struct JailStats {
        total_bans: u32,
        unique_ips: u32,
        recidivist_ips: u32,
    }
    let mut jail_stats_map: std::collections::HashMap<String, JailStats> =
        std::collections::HashMap::new();

    for row in rows.flatten() {
        let (jail_name, _ip, cnt) = row;
        let stats = jail_stats_map.entry(jail_name).or_insert(JailStats {
            total_bans: 0,
            unique_ips: 0,
            recidivist_ips: 0,
        });
        stats.total_bans += cnt;
        stats.unique_ips += 1;
        if cnt > 1 {
            stats.recidivist_ips += 1;
        }
    }

    let mut recommendations = Vec::new();
    let mut needs_adjust = 0usize;

    for jail in jails {
        let jail_name = &jail.name;
        let current = jail.max_retries;

        let stats = match jail_stats_map.get(jail_name) {
            Some(s) => s,
            None => continue, // 无封禁数据
        };

        let total_bans = stats.total_bans;
        let unique_ips = stats.unique_ips;
        let recidivist_ips = stats.recidivist_ips;
        let recidivism_rate = if unique_ips > 0 {
            recidivist_ips as f64 / unique_ips as f64
        } else {
            0.0
        };
        let avg_bans_per_ip = if unique_ips > 0 {
            total_bans as f64 / unique_ips as f64
        } else {
            0.0
        };

        // 置信度基于数据量
        let confidence = if total_bans >= 50 {
            90
        } else if total_bans >= 20 {
            70
        } else if total_bans >= 10 {
            50
        } else {
            30
        };

        let (recommended, direction, reason) = if total_bans < 10 {
            // 数据量不足
            (
                current,
                "maintain".to_string(),
                format!("数据量不足（仅 {} 次封禁），建议继续观察", total_bans),
            )
        } else if recidivism_rate > 0.3 {
            // 复发率过高 → 阈值过松
            let new_threshold = (current as f64 * 0.7).ceil().max(1.0) as u32;
            needs_adjust += 1;
            (
                new_threshold,
                "decrease".to_string(),
                format!(
                    "复发率 {:.0}% 过高（{} 个 IP 重复攻击），建议降低阈值从 {} → {} 以更快封禁",
                    recidivism_rate * 100.0,
                    recidivist_ips,
                    current,
                    new_threshold
                ),
            )
        } else if recidivism_rate < 0.1 && total_bans > 20 {
            // 复发率很低 + 大量封禁 → 可能误封过多
            let new_threshold = (current as f64 * 1.5).ceil() as u32;
            needs_adjust += 1;
            (
                new_threshold,
                "increase".to_string(),
                format!(
                    "复发率仅 {:.0}% 但封禁 {} 个 IP，可能存在误封，建议放宽阈值从 {} → {}",
                    recidivism_rate * 100.0,
                    unique_ips,
                    current,
                    new_threshold
                ),
            )
        } else {
            (
                current,
                "maintain".to_string(),
                format!(
                    "复发率 {:.0}% 在合理区间（10%-30%），当前阈值 {} 合适",
                    recidivism_rate * 100.0,
                    current
                ),
            )
        };

        recommendations.push(ThresholdRecommendation {
            jail_name: jail_name.clone(),
            current_threshold: current,
            recommended_threshold: recommended,
            direction,
            total_bans,
            unique_ips,
            recidivist_ips,
            recidivism_rate,
            avg_bans_per_ip,
            reason,
            confidence,
        });
    }

    let summary = if recommendations.is_empty() {
        "近 7 天无封禁数据，无法分析".to_string()
    } else if needs_adjust == 0 {
        format!("已分析 {} 个 Jail，所有阈值均合理", recommendations.len())
    } else {
        format!(
            "已分析 {} 个 Jail，{} 个建议调整",
            recommendations.len(),
            needs_adjust
        )
    };

    ThresholdRecommendationResponse {
        recommendations,
        summary,
    }
}
