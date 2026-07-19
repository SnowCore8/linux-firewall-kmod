//! 封禁效果分析 + 攻击检测
//!
//! 提供封禁效果分析（按级别统计复发率）、周期性攻击检测、
//! 协同攻击检测、智能白名单推荐等 API 实现。

use serde::Serialize;

/// 白名单推荐条目
#[derive(Serialize)]
pub struct WhitelistRecommendation {
    /// 推荐类型：subnet（子网）或 ip（单 IP）
    pub rec_type: String,
    /// 推荐的 CIDR 或 IP
    pub cidr: String,
    /// 推荐理由
    pub reason: String,
    /// 相关 IP 数量（子网类型时为子网内被封禁的 IP 数）
    pub affected_ips: u32,
    /// 总封禁次数（子网内所有 IP 的封禁次数之和）
    pub total_bans: u32,
    /// 置信度（0-100）
    pub confidence: u8,
}

/// 单个封禁级别的效果数据
#[derive(Serialize)]
pub struct BanLevelEffectiveness {
    /// 封禁级别（1=首次, 2=二次, 3=三次, 4=四次+）
    pub level: u8,
    /// 级别描述
    pub label: String,
    /// 达到此级别的 IP 总数
    pub total_ips: u32,
    /// 其中复发（再次被封禁）的 IP 数
    pub recidivist_ips: u32,
    /// 复发率（0.0-1.0）
    pub recidivism_rate: f64,
    /// 永久封禁数
    pub permanent_bans: u32,
    /// 效果评估
    pub verdict: String,
}

/// 封禁效果分析响应
#[derive(Serialize)]
pub struct BanEffectivenessResponse {
    /// 按级别的封禁效果
    pub levels: Vec<BanLevelEffectiveness>,
    /// 总体统计
    pub total_unique_ips: u32,
    pub overall_recidivism_rate: f64,
    /// 综合建议
    pub summary: String,
}

/// 智能白名单推荐
///
/// 分析 BAN_HISTORY 识别误封模式：
/// 1. 同一 /24 子网内多个 IP 被封禁 → 推荐子网白名单
/// 2. 单个 IP 被封禁多次但每次都是临时封禁 → 可能为误封
/// 3. 封禁后很快被手动解封 → 管理员认为是误封
pub fn get_whitelist_recommendations() -> Vec<WhitelistRecommendation> {
    let history = match crate::types::BAN_HISTORY.get() {
        Some(h) => h,
        None => return Vec::new(),
    };

    let snapshot = history.snapshot();
    if snapshot.is_empty() {
        return Vec::new();
    }

    let mut recommendations = Vec::new();

    // 1. 子网聚合分析（IPv4 /24 + IPv6 /48）
    let mut subnet_stats: std::collections::HashMap<String, Vec<&crate::types::BanHistoryEntry>> =
        std::collections::HashMap::new();

    for entry in &snapshot {
        if let Some(subnet) = extract_subnet_key(&entry.ip) {
            subnet_stats.entry(subnet).or_default().push(entry);
        }
    }

    for (subnet, entries) in &subnet_stats {
        // 子网内 >= 3 个不同 IP 被封禁 → 推荐子网白名单
        if entries.len() >= 3 {
            let total_bans: u32 = entries.iter().map(|e| e.ban_count).sum();

            // CIDR 格式：subnet key 已经是 "a.b.c" (IPv4) 或 "x:y:z" (IPv6)
            let cidr = if subnet.contains(':') {
                format!("{subnet}::/48")
            } else {
                format!("{subnet}.0/24")
            };

            // 置信度：基于 IP 数量和封禁次数
            let confidence = (entries.len() * 15).min(60) as u8 + (total_bans.min(20) as u8);

            recommendations.push(WhitelistRecommendation {
                rec_type: "subnet".to_string(),
                cidr,
                reason: format!(
                    "子网内 {} 个 IP 累计被封禁 {} 次，可能为同一合法网络",
                    entries.len(),
                    total_bans
                ),
                affected_ips: entries.len() as u32,
                total_bans,
                confidence: confidence.min(95),
            });
        }
    }

    // 2. 频繁临时封禁的单 IP（多次封禁但从未永久封禁）
    for entry in &snapshot {
        if entry.ban_count >= 3 && !entry.was_permanent && entry.last_unbanned_at > 0 {
            // 封禁 3 次以上 + 从未永久封禁 + 已被解封 → 可能是误封
            recommendations.push(WhitelistRecommendation {
                rec_type: "ip".to_string(),
                cidr: entry.ip.clone(),
                reason: format!(
                    "被封禁 {} 次但均为临时封禁且已解封，可能为误封",
                    entry.ban_count
                ),
                affected_ips: 1,
                total_bans: entry.ban_count,
                confidence: 40 + (entry.ban_count * 5).min(30) as u8,
            });
        }
    }

    // 按置信度降序排序
    recommendations.sort_by_key(|r| std::cmp::Reverse(r.confidence));
    recommendations.truncate(10); // 最多 10 条推荐

    recommendations
}

/// 提取 IP 的子网键（IPv4 /24 或 IPv6 /48）
///
/// - IPv4: "192.168.1.100" → Some("192.168.1")
/// - IPv6: "2001:db8:abcd:..." → Some("2001:db8:abcd")
fn extract_subnet_key(ip: &str) -> Option<String> {
    if ip.contains(':') {
        // IPv6: 取前 3 段（/48）
        let parts: Vec<&str> = ip.split(':').collect();
        if parts.len() >= 3 {
            Some(parts[..3].join(":"))
        } else {
            None
        }
    } else {
        // IPv4: 取前 3 段（/24）
        let parts: Vec<&str> = ip.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let octets: Result<Vec<u32>, _> = parts.iter().map(|p| p.parse::<u32>()).collect();
        match octets {
            Ok(o) if o.len() == 4 && o.iter().all(|&x| x <= 255) => {
                Some(format!("{}.{}.{}", o[0], o[1], o[2]))
            }
            _ => None,
        }
    }
}

/// 封禁效果分析 — 按级别统计复发率，评估渐进式封禁的有效性
pub fn get_ban_effectiveness() -> BanEffectivenessResponse {
    let history = match crate::types::BAN_HISTORY.get() {
        Some(h) => h,
        None => {
            return BanEffectivenessResponse {
                levels: Vec::new(),
                total_unique_ips: 0,
                overall_recidivism_rate: 0.0,
                summary: "无封禁历史数据".to_string(),
            };
        }
    };

    let snapshot = history.snapshot();
    if snapshot.is_empty() {
        return BanEffectivenessResponse {
            levels: Vec::new(),
            total_unique_ips: 0,
            overall_recidivism_rate: 0.0,
            summary: "无封禁历史数据".to_string(),
        };
    }

    let total_unique_ips = snapshot.len() as u32;

    // 按 ban_count 分组统计
    let mut level_stats: std::collections::HashMap<u8, (u32, u32, u32)> =
        std::collections::HashMap::new(); // level -> (total, recidivist, permanent)

    for entry in &snapshot {
        // 根据最终 ban_count 判断此 IP "达到"的最高级别
        let level = entry.ban_count.min(4) as u8;
        let is_recidivist = entry.ban_count >= 2;
        let is_permanent = entry.was_permanent;

        let stats = level_stats.entry(level).or_insert((0, 0, 0));
        stats.0 += 1;
        if is_recidivist {
            stats.1 += 1;
        }
        if is_permanent {
            stats.2 += 1;
        }
    }

    let mut levels = Vec::new();
    let labels = [
        (1u8, "首次封禁"),
        (2, "二次封禁（累犯）"),
        (3, "三次封禁（惯犯）"),
        (4, "四次+封禁（高频）"),
    ];

    for (level_val, label) in &labels {
        let (total, recidivist, permanent) =
            level_stats.get(level_val).copied().unwrap_or((0, 0, 0));
        let rate = if total > 0 {
            recidivist as f64 / total as f64
        } else {
            0.0
        };

        let verdict = if total == 0 {
            "无数据".to_string()
        } else if *level_val == 4 {
            if rate < 0.1 {
                "永久封禁有效，复发率极低".to_string()
            } else {
                "永久封禁后仍有复发，建议检查是否为共享 IP".to_string()
            }
        } else if rate > 0.5 {
            format!("复发率 {:.0}%，建议延长该级别封禁时长", rate * 100.0)
        } else if rate > 0.2 {
            format!("复发率 {:.0}%，封禁效果一般", rate * 100.0)
        } else {
            format!("复发率 {:.0}%，封禁效果良好", rate * 100.0)
        };

        levels.push(BanLevelEffectiveness {
            level: *level_val,
            label: label.to_string(),
            total_ips: total,
            recidivist_ips: recidivist,
            permanent_bans: permanent,
            recidivism_rate: rate,
            verdict,
        });
    }

    // 总体复发率
    let total_recidivists = snapshot.iter().filter(|e| e.ban_count >= 2).count();
    let overall_rate = if total_unique_ips > 0 {
        total_recidivists as f64 / total_unique_ips as f64
    } else {
        0.0
    };

    let summary = if overall_rate > 0.3 {
        format!(
            "总体复发率 {:.0}%，建议全面升级封禁策略：缩短检测窗口或延长基础封禁时长",
            overall_rate * 100.0
        )
    } else if overall_rate > 0.1 {
        format!(
            "总体复发率 {:.0}%，渐进式封禁策略运行正常",
            overall_rate * 100.0
        )
    } else {
        format!("总体复发率 {:.0}%，封禁策略效果优秀", overall_rate * 100.0)
    };

    BanEffectivenessResponse {
        levels,
        total_unique_ips,
        overall_recidivism_rate: overall_rate,
        summary,
    }
}

/// 获取周期性攻击者检测结果
pub fn get_periodic_attackers() -> Vec<crate::history_snapshot::PeriodicAttacker> {
    crate::history_snapshot::detect_periodic_attackers()
}

/// 获取协同攻击检测结果
pub fn get_collaborative_attacks() -> Vec<crate::history_snapshot::CollaborativeAttack> {
    crate::history_snapshot::detect_collaborative_attacks()
}

/// 获取攻击预测结果
pub fn get_attack_predictions() -> crate::history_snapshot::AttackPredictionSummary {
    crate::history_snapshot::predict_attacks()
}
