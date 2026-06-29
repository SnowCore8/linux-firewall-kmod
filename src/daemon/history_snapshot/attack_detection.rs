//! 攻击模式检测——周期性攻击者与协同攻击

use super::history_db;

/// 周期性攻击检测结果
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeriodicAttacker {
    /// IP 地址
    pub ip: String,
    /// 总封禁次数
    pub ban_count: u32,
    /// 平均间隔（秒）
    pub avg_interval_secs: f64,
    /// 间隔标准差（秒）
    pub interval_stddev: f64,
    /// 周期规律性评分（0-100，越高越规律）
    pub periodicity_score: u8,
    /// 最近 Jail
    pub jail_name: String,
    /// 事件时间戳列表
    pub timestamps: Vec<i64>,
}

/// 协同攻击检测结果
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollaborativeAttack {
    /// 目标 Jail 名称
    pub jail_name: String,
    /// 攻击时间窗口起始（Unix 时间戳）
    pub window_start: i64,
    /// 攻击时间窗口结束（Unix 时间戳）
    pub window_end: i64,
    /// 参与攻击的 IP 数量
    pub ip_count: u32,
    /// 参与攻击的 IP 列表
    pub ips: Vec<String>,
    /// 总封禁次数
    pub total_bans: u32,
    /// 协同攻击评分（0-100，越高越协同）
    pub correlation_score: u8,
}

/// 检测周期性攻击者
///
/// 查询 ban_events 表，对封禁次数 ≥ 3 的 IP 计算相邻封禁间隔的变异系数（CV）。
/// CV < 0.3 表示攻击间隔高度规律（机器人特征），评分 = (1 - CV) × 100。
pub fn detect_periodic_attackers() -> Vec<PeriodicAttacker> {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };

    // 查询近 7 天内封禁次数 ≥ 3 的 IP
    let cutoff = crate::types::now_secs() - 7 * 86400;
    let mut stmt = match conn.prepare(
        "SELECT ip, COUNT(*) as cnt, GROUP_CONCAT(banned_at, ',') as ts_list,
            MAX(jail_name) as jail
     FROM ban_events
     WHERE banned_at >= ?1
     GROUP BY ip
     HAVING cnt >= 3
     ORDER BY cnt DESC
     LIMIT 50",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([cutoff], |row| {
        let ip: String = row.get(0)?;
        let ban_count: u32 = row.get(1)?;
        let ts_list: String = row.get(2)?;
        let jail_name: String = row.get(3)?;
        Ok((ip, ban_count, ts_list, jail_name))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let mut results = Vec::new();

    for row in rows.flatten() {
        let (ip, ban_count, ts_list, jail_name) = row;
        let mut timestamps: Vec<i64> = ts_list
            .split(',')
            .filter_map(|s| s.trim().parse::<i64>().ok())
            .collect();
        timestamps.sort();

        if timestamps.len() < 3 {
            continue;
        }

        // 计算相邻间隔
        let intervals: Vec<f64> = timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64)
            .filter(|&iv| iv > 0.0)
            .collect();

        if intervals.len() < 2 {
            continue;
        }

        // 均值
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if mean < 10.0 {
            // 间隔 < 10 秒不算周期性，更像持续攻击
            continue;
        }

        // 标准差
        let variance =
            intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let stddev = variance.sqrt();

        // 变异系数 CV = stddev / mean
        let cv = stddev / mean;

        // 评分：CV < 0.3 → 高分（规律），CV > 1.0 → 0 分
        let score = if cv >= 1.0 {
            0
        } else {
            ((1.0 - cv) * 100.0) as u8
        };

        // 仅返回评分 ≥ 30 的（有一定规律性）
        if score >= 30 {
            results.push(PeriodicAttacker {
                ip,
                ban_count,
                avg_interval_secs: mean,
                interval_stddev: stddev,
                periodicity_score: score,
                jail_name,
                timestamps,
            });
        }
    }

    // 按评分降序排列
    results.sort_by_key(|b| std::cmp::Reverse(b.periodicity_score));
    results.truncate(20);
    results
}

/// 检测协同攻击
///
/// 查询 ban_events 表，找出 5 分钟时间窗口内对同一 Jail 发起攻击的多个 IP 集群。
/// 算法：
/// 1. 按 jail_name 分组
/// 2. 对每个 jail，按时间排序所有封禁事件
/// 3. 滑动窗口（300 秒）检测密集攻击时段
/// 4. 如果窗口内 IP 数 ≥ 3，判定为协同攻击
/// 5. 评分 = (IP 数 / 10) * 100，上限 100
pub fn detect_collaborative_attacks() -> Vec<CollaborativeAttack> {
    let db = history_db();
    let conn = match db.as_ref() {
        Some(c) => c,
        None => return Vec::new(),
    };

    // 查询近 7 天内所有封禁事件，按 jail 和时间排序
    let cutoff = crate::types::now_secs() - 7 * 86400;
    let mut stmt = match conn.prepare(
        "SELECT jail_name, ip, banned_at
     FROM ban_events
     WHERE banned_at >= ?1 AND jail_name != ''
     ORDER BY jail_name, banned_at",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let rows = match stmt.query_map([cutoff], |row| {
        let jail: String = row.get(0)?;
        let ip: String = row.get(1)?;
        let ts: i64 = row.get(2)?;
        Ok((jail, ip, ts))
    }) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    // 按 jail 分组收集事件
    let mut jail_events: std::collections::HashMap<String, Vec<(i64, String)>> =
        std::collections::HashMap::new();
    for row in rows.flatten() {
        let (jail, ip, ts) = row;
        jail_events.entry(jail).or_default().push((ts, ip));
    }

    let mut results = Vec::new();
    let window_size = 300i64; // 5 分钟窗口

    for (jail, mut events) in jail_events {
        // 按时间排序
        events.sort_by_key(|&(ts, _)| ts);

        // 滑动窗口检测
        let mut i = 0;
        while i < events.len() {
            let window_start = events[i].0;
            let window_end = window_start + window_size;

            // 收集窗口内的所有事件
            let mut j = i;
            let mut window_ips = std::collections::HashSet::new();
            let mut window_events = Vec::new();

            while j < events.len() && events[j].0 <= window_end {
                window_ips.insert(events[j].1.clone());
                window_events.push(events[j].clone());
                j += 1;
            }

            let ip_count = window_ips.len() as u32;

            // 如果窗口内 IP 数 ≥ 3，判定为协同攻击
            if ip_count >= 3 {
                let ips: Vec<String> = window_ips.into_iter().collect();
                let total_bans = window_events.len() as u32;
                let actual_window_end = window_events
                    .last()
                    .map(|&(ts, _)| ts)
                    .unwrap_or(window_end);

                // 评分 = (IP 数 / 10) * 100，上限 100
                let score = (ip_count.min(10) * 10) as u8;

                results.push(CollaborativeAttack {
                    jail_name: jail.clone(),
                    window_start,
                    window_end: actual_window_end,
                    ip_count,
                    ips,
                    total_bans,
                    correlation_score: score,
                });

                // 跳过这个窗口，避免重复检测
                i = j;
            } else {
                i += 1;
            }
        }
    }

    // 按评分降序排列
    results.sort_by_key(|b| std::cmp::Reverse(b.correlation_score));
    results.truncate(20);
    results
}
