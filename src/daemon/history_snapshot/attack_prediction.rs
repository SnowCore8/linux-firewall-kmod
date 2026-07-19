//! 攻击预测——基于历史封禁模式预测下次攻击时间
//!
//! 算法：对 ban_events 表中封禁次数 ≥ 3 的 IP，
//! 计算相邻封禁间隔的中位数作为预期周期，
//! 预测下次攻击时间 = 最后一次封禁时间 + 中位间隔。
//! 置信度基于周期规律性（CV）和事件数量。

use super::history_db;

/// 攻击预测结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct AttackPrediction {
    /// IP 地址
    pub ip: String,
    /// 历史封禁次数
    pub ban_count: u32,
    /// 最近 Jail
    pub jail_name: String,
    /// 最后一次封禁时间（Unix 时间戳）
    pub last_ban_at: i64,
    /// 预期攻击间隔中位数（秒）
    pub median_interval_secs: f64,
    /// 预测下次攻击时间（Unix 时间戳）
    pub predicted_next_attack: i64,
    /// 距离预测时间的剩余秒数（负数表示已超期）
    pub remaining_secs: i64,
    /// 预测置信度（0-100）
    pub confidence: u8,
    /// 紧急程度：imminent（<1h）/ soon（<6h）/ later（<24h）/ distant
    pub urgency: String,
}

/// Jail 级攻击趋势
#[derive(Debug, Clone, serde::Serialize)]
pub struct JailAttackTrend {
    /// Jail 名称
    pub jail_name: String,
    /// 24 小时内封禁数
    pub bans_24h: u32,
    /// 7 天内封禁数
    pub bans_7d: u32,
    /// 趋势方向：rising / stable / falling
    pub trend: String,
    /// 预测 24 小时内将有攻击的 IP 数
    pub predicted_attackers_24h: u32,
}

/// 攻击预测汇总
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct AttackPredictionSummary {
    /// per-IP 预测列表（按紧急程度排序）
    pub predictions: Vec<AttackPrediction>,
    /// per-Jail 攻击趋势
    pub jail_trends: Vec<JailAttackTrend>,
    /// 全局统计：预测 1 小时内将有攻击的 IP 数
    pub imminent_count: u32,
    /// 全局统计：预测 24 小时内将有攻击的 IP 数
    pub within_24h_count: u32,
}

/// 计算中位数（要求输入已排序）
fn median(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    if len % 2 == 0 {
        (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
    } else {
        sorted[len / 2]
    }
}

/// 预测攻击时间
///
/// 对每个封禁次数 ≥ 3 的 IP，分析封禁间隔规律，
/// 预测下次攻击可能发生的时间。
pub fn predict_attacks() -> AttackPredictionSummary {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return AttackPredictionSummary::default(),
    };

    let now = crate::types::now_secs();
    let cutoff_7d = now - 7 * 86400;
    let cutoff_24h = now - 86400;

    // 查询近 7 天内封禁次数 ≥ 3 的 IP
    let mut stmt = match conn.prepare(
        "SELECT ip, COUNT(*) as cnt, GROUP_CONCAT(banned_at, ',') as ts_list,
            MAX(jail_name) as jail, MAX(banned_at) as last_ban
         FROM ban_events
         WHERE banned_at >= ?1
         GROUP BY ip
         HAVING cnt >= 3
         ORDER BY cnt DESC
         LIMIT 100",
    ) {
        Ok(s) => s,
        Err(_) => return AttackPredictionSummary::default(),
    };

    let rows = match stmt.query_map([cutoff_7d], |row| {
        let ip: String = row.get(0)?;
        let ban_count: u32 = row.get(1)?;
        let ts_list: String = row.get(2)?;
        let jail_name: String = row.get(3)?;
        let last_ban_at: i64 = row.get(4)?;
        Ok((ip, ban_count, ts_list, jail_name, last_ban_at))
    }) {
        Ok(r) => r,
        Err(_) => return AttackPredictionSummary::default(),
    };

    let mut predictions = Vec::new();

    for row in rows.flatten() {
        let (ip, ban_count, ts_list, jail_name, last_ban_at) = row;
        let mut timestamps: Vec<i64> = ts_list
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect();
        timestamps.sort();

        if timestamps.len() < 3 {
            continue;
        }

        // 计算相邻间隔
        let mut intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .filter(|&iv| iv > 0.0)
            .collect();

        if intervals.len() < 2 {
            continue;
        }

        intervals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let median_interval = median(&intervals);

        // 过滤极短间隔（< 30 秒 = 持续攻击而非周期性攻击）
        if median_interval < 30.0 {
            continue;
        }

        // 预测下次攻击时间
        let predicted_next_attack = last_ban_at + median_interval as i64;
        let remaining_secs = predicted_next_attack - now;

        // 计算置信度
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let stddev = variance.sqrt();
        let cv = if mean > 0.0 { stddev / mean } else { 1.0 };

        // 置信度 = 规律性分 × 数据量分
        // 规律性：CV < 0.3 → 100, CV > 1.5 → 0
        let regularity_score = if cv >= 1.5 {
            0.0
        } else {
            ((1.0 - cv / 1.5) * 100.0).max(0.0)
        };
        // 数据量：≥ 5 个间隔 → 100%，3-4 → 60-80%
        let data_score = (intervals.len() as f64 / 5.0).min(1.0) * 100.0;
        let confidence = ((regularity_score * 0.6 + data_score * 0.4) as u8).min(100);

        // 仅保留置信度 ≥ 20 的预测
        if confidence < 20 {
            continue;
        }

        // 紧急程度分类
        let urgency = if remaining_secs < 3600 {
            "imminent".to_string() // < 1 小时（含已超期）
        } else if remaining_secs < 21600 {
            "soon".to_string() // < 6 小时
        } else if remaining_secs < 86400 {
            "later".to_string() // < 24 小时
        } else {
            "distant".to_string()
        };

        predictions.push(AttackPrediction {
            ip,
            ban_count,
            jail_name,
            last_ban_at,
            median_interval_secs: median_interval,
            predicted_next_attack,
            remaining_secs,
            confidence,
            urgency,
        });
    }

    // 按紧急程度排序（remaining_secs 升序，最紧急的排前面）
    predictions.sort_by_key(|p| p.remaining_secs);
    predictions.truncate(50);

    // 统计
    let imminent_count = predictions
        .iter()
        .filter(|p| p.urgency == "imminent")
        .count() as u32;
    let within_24h_count = predictions
        .iter()
        .filter(|p| p.remaining_secs < 86400)
        .count() as u32;

    // Jail 级趋势分析
    let jail_trends = compute_jail_trends(conn, cutoff_24h, cutoff_7d, &predictions);

    AttackPredictionSummary {
        predictions,
        jail_trends,
        imminent_count,
        within_24h_count,
    }
}

/// 计算 per-Jail 攻击趋势
fn compute_jail_trends(
    conn: &rusqlite::Connection,
    cutoff_24h: i64,
    cutoff_7d: i64,
    predictions: &[AttackPrediction],
) -> Vec<JailAttackTrend> {
    // 查询每个 Jail 的 24h 和 7d 封禁数
    let mut stmt = match conn.prepare(
        "SELECT jail_name,
            SUM(CASE WHEN banned_at >= ?1 THEN 1 ELSE 0 END) as bans_24h,
            COUNT(*) as bans_7d
         FROM ban_events
         WHERE banned_at >= ?2
         GROUP BY jail_name
         ORDER BY bans_7d DESC
         LIMIT 20",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([&cutoff_24h, &cutoff_7d], |row| {
        let jail_name: String = row.get(0)?;
        let bans_24h: u32 = row.get(1)?;
        let bans_7d: u32 = row.get(2)?;
        Ok((jail_name, bans_24h, bans_7d))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut trends = Vec::new();

    for row in rows.flatten() {
        let (jail_name, bans_24h, bans_7d) = row;

        // 趋势判定：比较近 24h 日均 vs 7d 日均
        let daily_avg_7d = bans_7d as f64 / 7.0;
        let trend = if daily_avg_7d < 1.0 {
            "stable".to_string()
        } else {
            let ratio = bans_24h as f64 / daily_avg_7d;
            if ratio > 1.5 {
                "rising".to_string()
            } else if ratio < 0.5 {
                "falling".to_string()
            } else {
                "stable".to_string()
            }
        };

        // 统计该 Jail 预测 24h 内将有攻击的 IP 数
        let predicted_attackers_24h = predictions
            .iter()
            .filter(|p| p.jail_name == jail_name && p.remaining_secs < 86400)
            .count() as u32;

        trends.push(JailAttackTrend {
            jail_name,
            bans_24h,
            bans_7d,
            trend,
            predicted_attackers_24h,
        });
    }

    trends
}
