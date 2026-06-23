//! Web UI API - 提供 JSON 数据端点
//!
//! # RESTful 端点（v1）
//! - `GET /api/v1/stats` - 统计数据
//! - `GET /api/v1/bans` - 封禁列表
//! - `POST /api/v1/bans` - 封禁 IP
//! - `DELETE /api/v1/bans/:ip` - 解封 IP
//! - `GET /api/v1/jails` - Jail 列表
//! - `PUT /api/v1/jails/:name` - 更新 Jail 状态
//! - `GET /api/v1/config` - 配置
//! - `GET /api/v1/whitelist` - 白名单列表
//! - `POST /api/v1/whitelist` - 添加白名单
//! - `DELETE /api/v1/whitelist/:cidr` - 移除白名单
//! - `GET /api/v1/rates/current` - 当前速率
//! - `GET /api/v1/rates/history` - 速率历史
//! - `GET /api/v1/events` - SSE 实时推送

use crate::types::{ACTIVE_BAN_CACHE, DAEMON_STATS, DDOS_STATS};
use serde::{Deserialize, Serialize};

/// 统一 API 响应信封
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub data: T,
    pub message: String,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 0,
            data,
            message: String::new(),
        }
    }

    pub fn error(code: i32, message: String) -> ApiResponse<()> {
        ApiResponse {
            code,
            data: (),
            message,
        }
    }
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
}

/// 图表数据
#[derive(Serialize)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub values: Vec<u64>,
}

/// 封禁信息响应
#[derive(Clone, Serialize)]
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

/// DDoS 速率信息响应
#[derive(Serialize)]
pub struct RateResponse {
    pub ip: String,
    pub packets_per_sec: u64,
    pub bytes_per_sec: u64,
    pub syn_packets_per_sec: u64,
    pub udp_packets_per_sec: u64,
    pub icmp_packets_per_sec: u64,
    pub ack_packets_per_sec: u64,
    pub rst_packets_per_sec: u64,
    pub fin_packets_per_sec: u64,
}

/// 速率历史趋势响应
#[derive(Serialize)]
pub struct RateHistoryResponse {
    pub timestamp: u64,
    pub total_pps: u64,
    pub total_bps: u64,
    pub tracked_ips: u32,
}

/// Web UI 配置响应
#[derive(Serialize)]
pub struct WebuiConfigResponse {
    pub sse_push_interval: u32,
    pub rate_warning_pps: u64,
    pub rate_critical_pps: u64,
    pub rate_warning_syn: u64,
    pub rate_critical_syn: u64,
}

/// 获取 Web UI 配置
pub fn get_webui_config() -> WebuiConfigResponse {
    let config = crate::http_exporter::get_global_webui_config().unwrap_or_default();

    WebuiConfigResponse {
        sse_push_interval: config.sse_push_interval,
        rate_warning_pps: config.rate_warning_pps,
        rate_critical_pps: config.rate_critical_pps,
        rate_warning_syn: config.rate_warning_syn,
        rate_critical_syn: config.rate_critical_syn,
    }
}

/// 更新 Web UI 配置请求
#[derive(Deserialize)]
pub struct UpdateConfigRequest {
    pub sse_push_interval: Option<u32>,
    pub rate_warning_pps: Option<u64>,
    pub rate_critical_pps: Option<u64>,
    pub rate_warning_syn: Option<u64>,
    pub rate_critical_syn: Option<u64>,
}

#[derive(Deserialize)]
pub struct UpdateJailRequest {
    pub enabled: bool,
}

/// 更新 Jail 启用/禁用状态
pub fn update_jail_enabled(name: &str, enabled: bool) -> Result<JailResponse, String> {
    let lock = crate::http_exporter::GLOBAL_JAILS
        .get()
        .ok_or("Jail 存储未初始化".to_string())?;

    let mut jails = lock.write();
    let jail = jails
        .iter_mut()
        .find(|j| j.name == name)
        .ok_or_else(|| format!("Jail '{}' 不存在", name))?;

    jail.enabled = enabled;
    drop(jails);

    // 返回更新后的 Jail 信息
    let ban_count = ACTIVE_BAN_CACHE
        .get()
        .map(|cache| cache.get_by_jail(name).len())
        .unwrap_or(0);

    Ok(JailResponse {
        name: name.to_string(),
        enabled,
        ban_count,
    })
}

/// 更新 Web UI 配置
pub fn update_webui_config(req: UpdateConfigRequest) -> Result<WebuiConfigResponse, String> {
    let mut config = crate::http_exporter::get_global_webui_config().unwrap_or_default();

    // 验证阈值逻辑：warning < critical
    let new_warning_pps = req.rate_warning_pps.unwrap_or(config.rate_warning_pps);
    let new_critical_pps = req.rate_critical_pps.unwrap_or(config.rate_critical_pps);
    let new_warning_syn = req.rate_warning_syn.unwrap_or(config.rate_warning_syn);
    let new_critical_syn = req.rate_critical_syn.unwrap_or(config.rate_critical_syn);

    if new_warning_pps >= new_critical_pps {
        return Err("速率警告阈值必须小于严重阈值".to_string());
    }
    if new_warning_syn >= new_critical_syn {
        return Err("SYN 警告阈值必须小于严重阈值".to_string());
    }

    // 应用更新
    if let Some(v) = req.sse_push_interval {
        if v == 0 || v > 60 {
            return Err("SSE 推送间隔必须在 1-60 秒之间".to_string());
        }
        config.sse_push_interval = v;
    }
    config.rate_warning_pps = new_warning_pps;
    config.rate_critical_pps = new_critical_pps;
    config.rate_warning_syn = new_warning_syn;
    config.rate_critical_syn = new_critical_syn;

    // 写入全局配置
    crate::http_exporter::set_global_webui_config(config.clone());

    Ok(WebuiConfigResponse {
        sse_push_interval: config.sse_push_interval,
        rate_warning_pps: config.rate_warning_pps,
        rate_critical_pps: config.rate_critical_pps,
        rate_warning_syn: config.rate_warning_syn,
        rate_critical_syn: config.rate_critical_syn,
    })
}

/// 获取 DDoS 速率数据
///
/// 从全局 `RATE_CACHE` 读取，该缓存由 netlink 接收线程定期更新。
/// 程序内部走内存（`/proc/firewall/*` 是用户操作接口）。
pub fn get_ddos_rates() -> Vec<RateResponse> {
    crate::types::RATE_CACHE
        .read()
        .iter()
        .map(|entry| RateResponse {
            ip: entry.ip.clone(),
            packets_per_sec: entry.packets_per_sec,
            bytes_per_sec: entry.bytes_per_sec,
            syn_packets_per_sec: entry.syn_packets_per_sec,
            udp_packets_per_sec: entry.udp_packets_per_sec,
            icmp_packets_per_sec: entry.icmp_packets_per_sec,
            ack_packets_per_sec: entry.ack_packets_per_sec,
            rst_packets_per_sec: entry.rst_packets_per_sec,
            fin_packets_per_sec: entry.fin_packets_per_sec,
        })
        .collect()
}

/// 获取速率历史趋势数据
///
/// 从全局 `RATE_HISTORY` 读取，保留最近 1 小时的速率快照（每 2 秒一条）。
/// Web UI 可读取此数据绘制速率趋势图。
pub fn get_rate_history() -> Vec<RateHistoryResponse> {
    crate::types::RATE_HISTORY
        .read()
        .iter()
        .map(|entry| RateHistoryResponse {
            timestamp: entry.timestamp,
            total_pps: entry.total_pps,
            total_bps: entry.total_bps,
            tracked_ips: entry.tracked_ips,
        })
        .collect()
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

    StatsResponse {
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        kernel_version: "2.2".to_string(),
        today_bans,
        failed_attempts,
        ddos_events,
        uptime_seconds: uptime.max(0) as u64,
        ban_trend: generate_ban_trend(),
        jail_distribution: generate_jail_distribution(),
        failure_reasons: generate_ban_reason_distribution(),
        failed_attempts_trend: generate_failed_attempts_trend(),
        current_bans,
        total_bans,
        total_unbans,
        whitelist_count,
        packets_dropped,
        packets_accepted,
    }
}

/// 生成封禁趋势数据（从 SQLite 读取真实历史数据）
fn generate_ban_trend() -> ChartData {
    // 从历史数据库读取最近 24 小时的数据
    match crate::history_snapshot::get_trend_data("bans", 24) {
        Ok(data) if !data.is_empty() => {
            let labels: Vec<String> = data
                .iter()
                .map(|(ts, _)| {
                    let dt =
                        chrono::DateTime::from_timestamp(*ts, 0).unwrap_or_else(chrono::Utc::now);
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

/// 生成封禁原因分布数据（从活跃封禁缓存聚合，按 reason 分组统计）
fn generate_ban_reason_distribution() -> ChartData {
    let cache = match ACTIVE_BAN_CACHE.get() {
        Some(c) => c,
        None => {
            return ChartData {
                labels: vec![],
                values: vec![],
            }
        }
    };

    let mut reason_map: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for ban in cache.snapshot() {
        *reason_map.entry(ban.reason.clone()).or_insert(0) += 1;
    }

    let mut pairs: Vec<(String, u64)> = reason_map.into_iter().collect();
    pairs.sort_by_key(|b| std::cmp::Reverse(b.1));

    ChartData {
        labels: pairs.iter().map(|(l, _)| l.clone()).collect(),
        values: pairs.iter().map(|(_, v)| *v).collect(),
    }
}

/// 生成失败尝试趋势数据
fn generate_failed_attempts_trend() -> ChartData {
    // 从历史数据库读取最近 1 小时的失败尝试数据
    match crate::history_snapshot::get_trend_data("failed_attempts", 1) {
        Ok(data) if !data.is_empty() => {
            let labels: Vec<String> = data
                .iter()
                .map(|(ts, _)| {
                    let dt =
                        chrono::DateTime::from_timestamp(*ts, 0).unwrap_or_else(chrono::Utc::now);
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

    ACTIVE_BAN_CACHE
        .get()
        .map(|cache| {
            cache
                .snapshot()
                .into_iter()
                .map(|ban| {
                    let remaining = if ban.is_permanent {
                        -1
                    } else {
                        let r = ban.expires_at - now;
                        if r < 0 {
                            0
                        } else {
                            r
                        }
                    };

                    BanResponse {
                        ip: ban.ip.clone(),
                        jail: ban.jail_name.clone(),
                        banned_at: ban.banned_at,
                        remaining_seconds: remaining,
                        reason: ban.reason.clone(),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// 获取 Jail 列表
pub fn get_jails(jail_infos: &[crate::http_exporter::JailInfo]) -> Vec<JailResponse> {
    jail_infos
        .iter()
        .map(|jail_info| {
            let ban_count = ACTIVE_BAN_CACHE
                .get()
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

// ============================================================================
// v1 RESTful API - 封禁/白名单操作
// ============================================================================

/// 封禁请求
#[derive(Deserialize)]
pub struct CreateBanRequest {
    /// 待封禁的 IP 地址
    pub ip: String,
    /// 封禁时长（秒）。0 或 null 表示永久封禁，省略则使用默认时长
    pub duration: Option<u64>,
    /// 封禁原因（可选，审计用）
    pub reason: Option<String>,
}

/// 封禁操作响应
#[derive(Serialize)]
pub struct BanOperationResponse {
    pub ip: String,
    /// "banned" 或 "unbanned"
    pub action: String,
    pub permanent: bool,
    pub duration_seconds: Option<u64>,
}

/// 白名单请求
#[derive(Deserialize)]
pub struct CreateWhitelistRequest {
    /// CIDR 格式，如 "10.0.0.0/8" 或 "192.168.1.1"
    pub cidr: String,
}

/// 白名单操作响应
#[derive(Serialize)]
pub struct WhitelistOperationResponse {
    pub cidr: String,
    /// "added" 或 "removed"
    pub action: String,
}

/// 白名单条目响应
#[derive(Serialize)]
pub struct WhitelistEntryResponse {
    pub cidr: String,
    pub device: String,
}

/// 封禁 IP（POST /api/v1/bans）
///
/// 调用 `ban::ban_ip()` 或 `ban::ban_ip_permanent()`。
/// duration=0 或 None 时永久封禁，与内核 ban_time=-1 语义一致。
pub fn create_ban(req: CreateBanRequest) -> Result<BanOperationResponse, String> {
    let ip = req.ip.trim();
    if ip.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }

    // 验证 IP 地址格式
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("无效的 IP 地址格式: {}", ip));
    }

    // None 和 Some(0) 均视为永久封禁，与内核 ban_time=-1 语义一致
    let permanent = req.duration.is_none() || req.duration == Some(0);
    let duration = req.duration.unwrap_or(0);

    // 先写缓存（正确的 reason 和 jail）
    let now = crate::types::now_secs();
    let user_reason = req.reason.as_deref().unwrap_or("manual");
    let ban_info = crate::types::BanInfo {
        ip: ip.to_string(),
        ip_num: 0,
        jail_name: "api".to_string(),
        reason: user_reason.to_string(),
        banned_at: now,
        expires_at: if permanent { 0 } else { now + duration as i64 },
        is_permanent: permanent,
        fail_count: 0,
    };
    let cache = ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
    cache.insert(ban_info);

    // 再发 netlink 到内核
    let result = if permanent {
        crate::ban::ban_ip_permanent(ip, user_reason)
    } else {
        crate::ban::ban_ip(ip, duration, user_reason)
    };

    match result {
        Ok(()) => Ok(BanOperationResponse {
            ip: ip.to_string(),
            action: "banned".to_string(),
            permanent,
            duration_seconds: if permanent { None } else { Some(duration) },
        }),
        Err(e) => Err(format!("封禁失败: {}", e)),
    }
}

/// 解封 IP（DELETE /api/v1/bans/:ip）
///
/// 同时尝试解封临时封禁和永久封禁。
pub fn delete_ban(ip: &str) -> Result<BanOperationResponse, String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }

    // 尝试解封（临时 + 永久）
    let _ = crate::ban::unban_ip(ip);
    let _ = crate::ban::unban_permanent_ip(ip);

    // 从缓存中移除
    if let Some(cache) = ACTIVE_BAN_CACHE.get() {
        cache.remove(ip);
    }

    Ok(BanOperationResponse {
        ip: ip.to_string(),
        action: "unbanned".to_string(),
        permanent: false,
        duration_seconds: None,
    })
}

/// 添加白名单（POST /api/v1/whitelist）
pub fn create_whitelist(req: CreateWhitelistRequest) -> Result<WhitelistOperationResponse, String> {
    let cidr = req.cidr.trim();
    if cidr.is_empty() {
        return Err("CIDR 不能为空".to_string());
    }

    // 验证 CIDR 格式：支持 "ip/prefix" 或纯 "ip"
    if let Some((ip_part, prefix_str)) = cidr.split_once('/') {
        if ip_part.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("无效的 IP 地址: {}", ip_part));
        }
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|_| format!("无效的前缀长度: {}", prefix_str))?;
        let max_prefix = if ip_part.parse::<std::net::Ipv4Addr>().is_ok() {
            32
        } else {
            128
        };
        if prefix > max_prefix {
            return Err(format!(
                "前缀长度 {} 超出范围（最大 {}）",
                prefix, max_prefix
            ));
        }
    } else if cidr.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("无效的 IP/CIDR 格式: {}", cidr));
    }

    let failed = crate::ban::init_trusted_ips(&[cidr.to_string()]);
    if !failed.is_empty() {
        return Err(format!("添加白名单失败: {}", failed.join(", ")));
    }

    Ok(WhitelistOperationResponse {
        cidr: cidr.to_string(),
        action: "added".to_string(),
    })
}

/// 移除白名单（DELETE /api/v1/whitelist/:cidr）
pub fn delete_whitelist(cidr: &str) -> Result<WhitelistOperationResponse, String> {
    let cidr = cidr.trim();
    if cidr.is_empty() {
        return Err("CIDR 不能为空".to_string());
    }

    let failed = crate::ban::remove_trusted_ips(&[cidr.to_string()]);
    if !failed.is_empty() {
        return Err(format!("移除白名单失败: {}", failed.join(", ")));
    }

    Ok(WhitelistOperationResponse {
        cidr: cidr.to_string(),
        action: "removed".to_string(),
    })
}

/// 获取白名单列表（GET /api/v1/whitelist）
///
/// 从 WHITELIST_CACHE 读取，该缓存由 netlink 接收线程在收到 ListWhitelistResponse 时更新。
pub fn get_whitelist() -> Vec<WhitelistEntryResponse> {
    crate::types::WHITELIST_CACHE
        .read()
        .values()
        .map(|entry| WhitelistEntryResponse {
            cidr: entry.cidr.clone(),
            device: entry.device.clone(),
        })
        .collect()
}

// ============================================================================
// 分页支持
// ============================================================================

/// 分页请求参数
#[derive(Deserialize)]
pub struct PaginationParams {
    /// 页码（从 1 开始，默认 1）
    pub page: Option<u32>,
    /// 每页大小（默认 20，最大 100）
    pub page_size: Option<u32>,
    /// 排序字段（可选）：banned_at_desc（默认）、banned_at_asc、ip_asc、jail_asc
    pub sort_by: Option<String>,
}

/// 分页响应包装
#[derive(Serialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

/// 获取分页后的封禁列表
pub fn get_active_bans_paginated(
    page: u32,
    page_size: u32,
    sort_by: Option<String>,
) -> PaginatedResponse<BanResponse> {
    let mut all_bans = get_active_bans();
    let total = all_bans.len() as u64;

    // 排序（默认按封禁时间降序）
    match sort_by.as_deref() {
        Some("banned_at_asc") => all_bans.sort_by_key(|b| b.banned_at),
        Some("ip_asc") => all_bans.sort_by(|a, b| a.ip.cmp(&b.ip)),
        Some("ip_desc") => all_bans.sort_by(|a, b| b.ip.cmp(&a.ip)),
        Some("jail_asc") => all_bans.sort_by(|a, b| a.jail.cmp(&b.jail)),
        Some("remaining_asc") => {
            // 永久封禁（-1）排在最后，临时封禁按剩余时间升序
            all_bans.sort_by(|a, b| {
                let ka = if a.remaining_seconds < 0 {
                    i64::MAX
                } else {
                    a.remaining_seconds
                };
                let kb = if b.remaining_seconds < 0 {
                    i64::MAX
                } else {
                    b.remaining_seconds
                };
                ka.cmp(&kb)
            });
        }
        Some("remaining_desc") => {
            // 临时封禁按剩余时间降序，永久封禁（-1）排在最前
            all_bans.sort_by(|a, b| {
                let ka = if a.remaining_seconds < 0 {
                    i64::MAX
                } else {
                    a.remaining_seconds
                };
                let kb = if b.remaining_seconds < 0 {
                    i64::MAX
                } else {
                    b.remaining_seconds
                };
                kb.cmp(&ka)
            });
        }
        _ => all_bans.sort_by_key(|b| std::cmp::Reverse(b.banned_at)), // banned_at_desc
    }

    // 限制 page_size 范围
    let page_size = page_size.clamp(1, 100);
    let page = page.max(1);

    // 计算分页
    let start = ((page - 1) * page_size) as usize;
    let end = (start + page_size as usize).min(all_bans.len());

    let items = if start < all_bans.len() {
        all_bans[start..end].to_vec()
    } else {
        Vec::new()
    };

    let total_pages = total.div_ceil(page_size as u64) as u32;

    PaginatedResponse {
        items,
        total,
        page,
        page_size,
        total_pages,
    }
}
