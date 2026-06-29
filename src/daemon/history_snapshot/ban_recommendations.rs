//! 封禁时长推荐——基于复发间隔分析为每个 Jail 推荐最优封禁时长

use super::history_db;

/// 单个 Jail 的封禁时长推荐
pub struct JailBanRecommendation {
    pub jail_name: String,
    /// 当前配置的封禁时长（秒）
    pub current_ban_time: i32,
    /// 观察到的复发 IP 数
    pub recidivist_count: u32,
    /// 复发间隔中位数（秒）— 复发 IP 再次被封禁的平均间隔
    pub median_return_secs: u64,
    /// 推荐的封禁时长（秒）
    pub recommended_ban_time: u64,
    /// 推荐说明
    pub reason: String,
}

/// 基于 ban_events 数据分析，为每个 Jail 推荐最优封禁时长。
///
/// 算法：
/// 1. 对每个 Jail 中封禁次数 ≥ 2 的 IP，计算相邻封禁间隔
/// 2. 取所有间隔的中位数作为"典型复发时间"
/// 3. 推荐封禁时长 = max(当前时长 × 2, 中位数 × 1.5)
/// 4. 如果当前时长已足够（≥ 中位数），则不推荐调整
pub fn recommend_ban_durations(
    jails: &[crate::http_exporter::JailInfo],
) -> Vec<JailBanRecommendation> {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };

    let cutoff = crate::types::now_secs() - 7 * 86400;

    // 查询近 7 天内所有封禁事件，按 jail + ip 分组
    let mut stmt = match conn.prepare(
        "SELECT jail_name, ip, GROUP_CONCAT(banned_at, ',') as ts_list
     FROM ban_events
     WHERE banned_at >= ?1 AND jail_name != ''
     GROUP BY jail_name, ip
     HAVING COUNT(*) >= 2
     ORDER BY jail_name",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([cutoff], |row| {
        let jail_name: String = row.get(0)?;
        let ip: String = row.get(1)?;
        let ts_list: String = row.get(2)?;
        Ok((jail_name, ip, ts_list))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // 按 Jail 收集所有复发间隔
    let mut jail_intervals: std::collections::HashMap<String, Vec<u64>> =
        std::collections::HashMap::new();

    for row in rows {
        let (jail_name, _ip, ts_list) = match row {
            Ok(r) => r,
            Err(_) => continue,
        };

        let mut timestamps: Vec<i64> = ts_list
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect();
        timestamps.sort();

        // 计算相邻封禁间隔
        for i in 1..timestamps.len() {
            let diff = timestamps[i] - timestamps[i - 1];
            // 时钟回拨防御：diff 为负时跳过，避免 as u64 静默溢出为巨大正数
            if diff <= 0 {
                continue;
            }
            let gap = diff as u64;
            if gap > 60 {
                // 忽略 < 1 分钟的间隔（可能是连续触发）
                jail_intervals
                    .entry(jail_name.clone())
                    .or_default()
                    .push(gap);
            }
        }
    }

    // 为每个 Jail 生成推荐
    let mut results = Vec::new();

    for jail in jails {
        let jail_name = &jail.name;
        let current_ban_time = jail.ban_time;

        let intervals = jail_intervals.get(jail_name);
        let (recidivist_count, median_return_secs) = match intervals {
            Some(iv) if !iv.is_empty() => {
                let mut sorted = iv.clone();
                sorted.sort();
                let median = sorted[sorted.len() / 2];
                (sorted.len() as u32, median)
            }
            _ => continue, // 无复发数据，跳过
        };

        // 推荐逻辑
        let current_secs = if current_ban_time > 0 {
            current_ban_time as u64
        } else {
            86400 // 永久封禁视为 24 小时
        };

        let (recommended, reason) = if current_secs >= median_return_secs {
            // 当前时长已足够
            (
                current_secs,
                format!(
                    "当前封禁时长（{}s）已覆盖典型复发间隔（{}s），无需调整",
                    current_secs, median_return_secs
                ),
            )
        } else {
            // 推荐延长
            let recommended = (median_return_secs * 3 / 2).max(current_secs * 2);
            (
                recommended,
                format!(
                    "{} 个 IP 平均在 {}s 后复发，当前封禁时长 {}s 不足，建议延长至 {}s",
                    recidivist_count, median_return_secs, current_secs, recommended
                ),
            )
        };

        results.push(JailBanRecommendation {
            jail_name: jail_name.clone(),
            current_ban_time,
            recidivist_count,
            median_return_secs,
            recommended_ban_time: recommended,
            reason,
        });
    }

    results
}
