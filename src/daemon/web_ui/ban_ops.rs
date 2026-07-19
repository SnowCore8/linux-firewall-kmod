//! 封禁/白名单 CRUD 操作
//!
//! 提供封禁 IP、解封、白名单管理、分页查询等 RESTful API 实现。

use crate::types::ACTIVE_BAN_CACHE;
use crate::web_ui::api::BanResponse;
use serde::{Deserialize, Serialize};

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

/// 批量操作响应
#[derive(Serialize)]
pub struct BatchOperationResponse {
    pub total: u64,
    pub succeeded: u64,
    pub failed_count: u64,
    pub details: Vec<String>,
}

/// 封禁详情响应（GET /api/v1/bans/:ip/detail）
///
/// 包含封禁基本信息 + 封禁历史 + 渐进式封禁决策信息 + 信誉分
#[derive(Serialize)]
pub struct BanDetailResponse {
    /// IP 地址
    pub ip: String,
    /// 当前是否被封禁
    pub is_banned: bool,
    /// Jail 名称
    pub jail_name: String,
    /// 封禁原因
    pub reason: String,
    /// 封禁时间（Unix 秒）
    pub banned_at: i64,
    /// 过期时间（Unix 秒，0=永久）
    pub expires_at: i64,
    /// 是否永久封禁
    pub is_permanent: bool,
    /// 触发封禁前的失败次数
    pub fail_count: u32,
    /// 累计封禁次数
    pub ban_count: u32,
    /// 上次解封时间（0=当前在封禁中）
    pub last_unbanned_at: i64,
    /// 是否曾被永久封禁
    pub was_permanent: bool,
    /// 渐进式封禁等级说明
    pub progressive_level: String,
    /// 下次封禁时长（秒）
    pub next_ban_duration: String,
    /// IP 信誉分（0-100，100=完全信任）
    pub reputation_score: u32,
    /// 信誉阈值乘数（0.5/0.8/1.0）
    pub reputation_multiplier: f64,
}

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

/// 上次 purge_expired 时间戳（避免每次 SSE 推送都获取写锁）
static LAST_PURGE_TIME: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// purge 最小间隔（秒）：每 5 秒最多清理一次，减少写锁竞争
const PURGE_INTERVAL_SECS: i64 = 5;

/// 获取活跃封禁列表
pub fn get_active_bans() -> Vec<BanResponse> {
    let now = crate::types::now_secs();

    ACTIVE_BAN_CACHE
        .get()
        .map(|cache| {
            // 节流清理：每 5 秒最多 purge 一次，避免每秒获取写锁
            let last_purge = LAST_PURGE_TIME.load(std::sync::atomic::Ordering::Relaxed);
            if now - last_purge >= PURGE_INTERVAL_SECS {
                LAST_PURGE_TIME.store(now, std::sync::atomic::Ordering::Relaxed);
                let expired = cache.purge_expired(now);
                // 同步统计：过期条目从缓存移除时补充更新解封计数和封禁时长直方图
                for ban in &expired {
                    crate::types::DAEMON_STATS
                        .total_unbans
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let duration = if ban.expires_at > 0 {
                        ban.expires_at - ban.banned_at
                    } else {
                        now - ban.banned_at
                    };
                    crate::types::record_ban_duration(duration);
                }
            }
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
                        ban_count: ban.ban_count,
                        is_permanent: ban.is_permanent,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
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
    let ban_history = crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
    // 获取当前 ban_count（不递增），record_ban 在 netlink 成功后调用
    let ban_count = ban_history.get_ban_count(ip);
    let ban_info = crate::types::BanInfo {
        ip: ip.to_string(),
        ip_num: 0,
        jail_name: "api".to_string(),
        reason: user_reason.to_string(),
        banned_at: now,
        expires_at: if permanent { 0 } else { now + duration as i64 },
        is_permanent: permanent,
        fail_count: 0,
        ban_count: ban_count + 1,
    };
    let cache = ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
    cache.insert(ban_info);

    // 发 netlink 到内核
    let result = if permanent {
        crate::ban::ban_ip_permanent(ip, user_reason)
    } else {
        crate::ban::ban_ip(ip, duration, user_reason)
    };

    match result {
        Ok(()) => {
            // netlink 成功后才记录副作用（handle_ban_state_change 检测到 cache.contains → 跳过重复记录）
            let new_ban_count = ban_history.record_ban(ip, permanent);
            crate::history_snapshot::record_ban_event(ip, "api", new_ban_count);
            Ok(BanOperationResponse {
                ip: ip.to_string(),
                action: "banned".to_string(),
                permanent,
                duration_seconds: if permanent { None } else { Some(duration) },
            })
        }
        Err(e) => {
            // 封禁失败，回滚缓存（record_ban 未调用，无需回滚）
            cache.remove(ip);
            Err(format!("封禁失败: {}", e))
        }
    }
}

/// 解封 IP（DELETE /api/v1/bans/:ip）
///
/// 发送一次 netlink unban 即可同时解除临时和永久封禁（内核按 IP 查找）。
/// 内核命令成功后才移除缓存，失败时保留缓存条目避免不一致。
pub fn delete_ban(ip: &str) -> Result<BanOperationResponse, String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("无效的 IP 地址格式: {ip}"));
    }

    // unban_ip 和 unban_permanent_ip 最终都走 send_unban，
    // 只需调用一次，避免 total_unbans 统计双计
    if let Err(e) = crate::ban::unban_ip(ip) {
        // 内核命令失败（netlink 不可用 / socket 发送失败）：
        // 保留缓存条目，避免 daemon 与内核状态不一致。
        // 下次启动时 list_bans 同步会修正缓存。
        crate::logger::warn!(
            crate::logger::get(),
            "内核解封失败，保留缓存条目";
            "ip" => ip,
            "error" => %e
        );
        return Err(format!("内核解封失败: {e}"));
    }

    // 内核命令成功，从缓存中移除，记录封禁时长到 histogram
    if let Some(cache) = ACTIVE_BAN_CACHE.get() {
        if let Some(removed_ban) = cache.remove(ip) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let duration = now - removed_ban.banned_at;
            if duration > 0 {
                crate::types::record_ban_duration(duration);
            }
        }
    }

    Ok(BanOperationResponse {
        ip: ip.to_string(),
        action: "unbanned".to_string(),
        permanent: false,
        duration_seconds: None,
    })
}

/// 获取封禁详情
pub fn get_ban_detail(ip: &str) -> Result<BanDetailResponse, String> {
    let ip = ip.trim();
    if ip.is_empty() {
        return Err("IP 地址不能为空".to_string());
    }
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("无效的 IP 地址格式: {ip}"));
    }

    let now = crate::types::now_secs();

    // 从 ACTIVE_BAN_CACHE 获取当前封禁信息
    let (is_banned, jail_name, reason, banned_at, expires_at, is_permanent, fail_count) =
        if let Some(cache) = ACTIVE_BAN_CACHE.get() {
            if let Some(ban) = cache.get(ip) {
                (
                    !ban.is_expired(now),
                    ban.jail_name.clone(),
                    ban.reason.clone(),
                    ban.banned_at,
                    ban.expires_at,
                    ban.is_permanent,
                    ban.fail_count,
                )
            } else {
                (false, String::new(), String::new(), 0, 0, false, 0)
            }
        } else {
            (false, String::new(), String::new(), 0, 0, false, 0)
        };

    // 从 BAN_HISTORY 获取封禁历史
    let (ban_count, last_unbanned_at, was_permanent) =
        if let Some(history) = crate::types::BAN_HISTORY.get() {
            if let Some(entry) = history.get_entry(ip) {
                (entry.ban_count, entry.last_unbanned_at, entry.was_permanent)
            } else {
                (0, 0, false)
            }
        } else {
            (0, 0, false)
        };

    // 渐进式封禁等级说明
    let progressive_level = match ban_count {
        0 => "首次封禁".to_string(),
        1 => "二次封禁（累犯）".to_string(),
        2 => "三次封禁（惯犯）".to_string(),
        _ => "多次封禁（永久）".to_string(),
    };

    // 下次封禁时长
    let next_ban_duration = if let Some(history) = crate::types::BAN_HISTORY.get() {
        let base = 300; // 默认 5 分钟
        let duration = history.calculate_progressive_duration(ip, base);
        if duration == 0 {
            "永久封禁".to_string()
        } else {
            format!("{} 秒", duration)
        }
    } else {
        "未知".to_string()
    };

    Ok(BanDetailResponse {
        ip: ip.to_string(),
        is_banned,
        jail_name,
        reason,
        banned_at,
        expires_at,
        is_permanent,
        fail_count,
        ban_count,
        last_unbanned_at,
        was_permanent,
        progressive_level,
        next_ban_duration,
        reputation_score: crate::ip_reputation::get_store().get_score(ip),
        reputation_multiplier: crate::ip_reputation::get_store().get_threshold_multiplier(ip),
    })
}

/// 批量解封所有临时封禁（POST /api/v1/bans/unban-temporary）
///
/// 遍历 ACTIVE_BAN_CACHE，解封所有非永久封禁的 IP
pub fn unban_all_temporary() -> Result<BatchOperationResponse, String> {
    let cache = ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
    let snapshot = cache.snapshot();

    let mut unbanned = Vec::new();
    let mut failed = Vec::new();

    for ban in &snapshot {
        if ban.is_permanent {
            continue;
        }
        match crate::ban::unban_ip(&ban.ip) {
            Ok(()) => {
                // 记录封禁时长到 histogram
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let duration = now - ban.banned_at;
                if duration > 0 {
                    crate::types::record_ban_duration(duration);
                }
                cache.remove(&ban.ip);
                unbanned.push(ban.ip.clone());
            }
            Err(e) => {
                failed.push(format!("{}: {}", ban.ip, e));
            }
        }
    }

    Ok(BatchOperationResponse {
        total: unbanned.len() as u64 + failed.len() as u64,
        succeeded: unbanned.len() as u64,
        failed_count: failed.len() as u64,
        details: unbanned,
    })
}

/// 批量封禁多个 IP（POST /api/v1/bans/batch）
pub fn batch_ban(ips: Vec<String>) -> Result<BatchOperationResponse, String> {
    let mut banned = Vec::new();
    let mut failed = Vec::new();

    for ip in &ips {
        let req = CreateBanRequest {
            ip: ip.trim().to_string(),
            duration: Some(3600),
            reason: Some("batch_ban".to_string()),
        };
        match create_ban(req) {
            Ok(_) => banned.push(ip.clone()),
            Err(e) => failed.push(format!("{}: {}", ip, e)),
        }
    }

    Ok(BatchOperationResponse {
        total: ips.len() as u64,
        succeeded: banned.len() as u64,
        failed_count: failed.len() as u64,
        details: banned,
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
    // 校验 CIDR 格式：IP 或 IP/prefix
    if let Some((ip_part, prefix_str)) = cidr.split_once('/') {
        if ip_part.parse::<std::net::IpAddr>().is_err() {
            return Err(format!("无效的 IP 地址: {ip_part}"));
        }
        let prefix: u32 = prefix_str
            .parse()
            .map_err(|_| format!("无效的前缀长度: {prefix_str}"))?;
        let max_prefix = if ip_part.contains(':') { 128 } else { 32 };
        if prefix > max_prefix {
            return Err(format!("前缀 /{prefix} 超出范围 (最大 /{max_prefix})"));
        }
    } else if cidr.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("无效的 IP/CIDR 格式: {cidr}"));
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
