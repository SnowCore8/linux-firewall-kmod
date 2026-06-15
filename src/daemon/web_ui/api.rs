//! Web UI API - 提供 JSON 数据端点
//!
//! # 端点
//! - `/api/stats` - 统计数据
//! - `/api/bans` - 活跃封禁列表
//! - `/api/jails` - Jail 配置

use serde::Serialize;
use crate::types::{DAEMON_STATS, DDOS_STATS, ACTIVE_BAN_CACHE};

/// 统计数据响应
#[derive(Serialize)]
pub struct StatsResponse {
    pub active_bans: usize,
    pub today_bans: u64,
    pub failed_attempts: u64,
    pub ddos_events: u64,
    pub uptime_seconds: u64,
    pub ban_trend: ChartData,
    pub jail_distribution: ChartData,
    pub failure_reasons: ChartData,
    pub traffic: ChartData,
}

/// 图表数据
#[derive(Serialize)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub values: Vec<u64>,
}

/// 封禁信息响应
#[derive(Serialize)]
pub struct BanResponse {
    pub ip: String,
    pub jail: String,
    pub banned_at: i64,
    pub remaining_seconds: i64,
    pub reason: String,
}

/// Jail 信息响应
#[derive(Serialize)]
pub struct JailResponse {
    pub name: String,
    pub enabled: bool,
    pub ban_count: usize,
}

/// 获取统计数据
pub fn get_stats() -> StatsResponse {
    let now = crate::types::now_secs();
    let start_time = DAEMON_STATS.start_time.load(std::sync::atomic::Ordering::Relaxed) as i64;
    let uptime = if start_time > 0 { now - start_time } else { 0 };

    let active_bans = ACTIVE_BAN_CACHE.get()
        .map(|cache| cache.len())
        .unwrap_or(0);

    let today_bans = DAEMON_STATS.ips_banned.load(std::sync::atomic::Ordering::Relaxed);
    let failed_attempts = DAEMON_STATS.failed_attempts.load(std::sync::atomic::Ordering::Relaxed);
    let ddos_events = DDOS_STATS.events_detected.load(std::sync::atomic::Ordering::Relaxed);

    StatsResponse {
        active_bans,
        today_bans,
        failed_attempts,
        ddos_events,
        uptime_seconds: uptime.max(0) as u64,
        ban_trend: generate_ban_trend(),
        jail_distribution: generate_jail_distribution(),
        failure_reasons: generate_failure_reasons(),
        traffic: generate_traffic_data(),
    }
}

/// 生成封禁趋势数据（从 SQLite 读取真实历史数据）
fn generate_ban_trend() -> ChartData {
    // 从历史数据库读取最近 24 小时的数据
    match crate::history_snapshot::get_trend_data("bans", 24) {
        Ok(data) if !data.is_empty() => {
            let labels: Vec<String> = data.iter()
                .map(|(ts, _)| {
                    let dt = chrono::DateTime::from_timestamp(*ts, 0)
                        .unwrap_or_else(chrono::Utc::now);
                    dt.format("%H:%M").to_string()
                })
                .collect();
            let values: Vec<u64> = data.iter().map(|(_, v)| *v).collect();
            ChartData { labels, values }
        }
        _ => {
            // 如果没有历史数据，返回空的图表
            ChartData {
                labels: vec![],
                values: vec![],
            }
        }
    }
}

/// 生成 Jail 分布数据（从当前活跃封禁统计）
fn generate_jail_distribution() -> ChartData {
    match crate::history_snapshot::get_jail_distribution() {
        Ok(data) if !data.is_empty() => {
            let labels: Vec<String> = data.iter().map(|(name, _)| name.clone()).collect();
            let values: Vec<u64> = data.iter().map(|(_, count)| *count).collect();
            ChartData { labels, values }
        }
        _ => {
            // 如果没有封禁数据，返回空的图表
            ChartData {
                labels: vec![],
                values: vec![],
            }
        }
    }
}

/// 生成失败原因数据（使用累计统计数据）
fn generate_failure_reasons() -> ChartData {
    // 从 DAEMON_STATS 读取累计统计数据
    let failed_attempts = crate::types::DAEMON_STATS.failed_attempts.load(std::sync::atomic::Ordering::Relaxed);
    let ddos_events = crate::types::DDOS_STATS.events_detected.load(std::sync::atomic::Ordering::Relaxed);

    // 简单分类：大部分是失败尝试，部分是 DDoS
    let labels = vec![
        "失败尝试".to_string(),
        "DDoS 检测".to_string(),
    ];

    let values = vec![
        failed_attempts,
        ddos_events,
    ];

    ChartData { labels, values }
}

/// 生成流量数据（使用失败尝试趋势）
fn generate_traffic_data() -> ChartData {
    // 从历史数据库读取最近 1 小时的失败尝试数据
    match crate::history_snapshot::get_trend_data("failed_attempts", 1) {
        Ok(data) if !data.is_empty() => {
            let labels: Vec<String> = data.iter()
                .map(|(ts, _)| {
                    let dt = chrono::DateTime::from_timestamp(*ts, 0)
                        .unwrap_or_else(chrono::Utc::now);
                    dt.format("%H:%M").to_string()
                })
                .collect();
            let values: Vec<u64> = data.iter().map(|(_, v)| *v).collect();
            ChartData { labels, values }
        }
        _ => {
            // 如果没有历史数据，返回空的图表
            ChartData {
                labels: vec![],
                values: vec![],
            }
        }
    }
}

/// 获取活跃封禁列表
pub fn get_active_bans() -> Vec<BanResponse> {
    let now = crate::types::now_secs();

    ACTIVE_BAN_CACHE.get()
        .map(|cache| {
            cache.snapshot()
                .into_iter()
                .map(|ban| {
                    let remaining = if ban.is_permanent {
                        -1
                    } else {
                        ban.expires_at - now
                    };

                    BanResponse {
                        ip: ban.ip.clone(),
                        jail: ban.jail_name.clone(),
                        banned_at: ban.banned_at,
                        remaining_seconds: remaining,
                        reason: match ban.reason {
                            crate::types::BanReason::FailedAttempts => "失败尝试".to_string(),
                            crate::types::BanReason::DDoSRateLimit => "DDoS 检测".to_string(),
                            crate::types::BanReason::ManualBan => "手动封禁".to_string(),
                            crate::types::BanReason::PermanentAuto => "自动永久封禁".to_string(),
                        },
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 获取 Jail 列表
pub fn get_jails(jail_infos: &[crate::http_exporter::JailInfo]) -> Vec<JailResponse> {
    jail_infos.iter()
        .map(|jail_info| {
            let ban_count = ACTIVE_BAN_CACHE.get()
                .map(|cache| cache.get_by_jail(&jail_info.name).len())
                .unwrap_or(0);

            JailResponse {
                name: jail_info.name.clone(),
                enabled: jail_info.enabled,
                ban_count,
            }
        })
        .collect()
}
