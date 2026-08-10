//! Netlink 消息处理器
//!
//! 所有 `handle_*` 方法均为 `NetlinkContext` 的关联函数（无 self），
//! 由 `handle_message` 分发器调用。

use anyhow::Result;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};

use super::protocol::{
    config_flags, FwNlBanStateChange, FwNlCmdResult, FwNlConfigUpdate, FwNlDdosEvent,
    FwNlWhitelistStateChange,
};
use super::responses::{
    FwNlAnalysisResponse, FwNlConfigAck, FwNlListBansResponse, FwNlListRatesResponse,
    FwNlListWhitelistResponse, FwNlStatsResponse, LIST_BANS_PAGE_MAX,
};
use super::DdosDecisionEngine;

const MAX_BAN_ENTRIES_ACCUM: usize = 65536;

struct PendingListBans {
    total: u32,
    next_offset: u32,
    infos: Vec<crate::types::BanInfo>,
}

fn pending_list_bans() -> &'static Mutex<Option<PendingListBans>> {
    static PENDING: OnceLock<Mutex<Option<PendingListBans>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(None))
}

impl super::NetlinkContext {
    /// 处理 DDoS 事件
    pub(super) fn handle_ddos_event(
        hdr_data: &[u8],
        decision_engine: &Option<Arc<DdosDecisionEngine>>,
    ) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlDdosEvent>() {
            anyhow::bail!("DDoS 事件数据太短");
        }

        let event = FwNlDdosEvent::from_bytes(hdr_data)?;
        let ip_str = event.ip_str();
        let reason = event.reason_str();
        let rate_pps = event.rate_pps();

        crate::logger::debug!(
            crate::logger::get(),
            "收到 DDoS 事件";
            "ip" => &ip_str,
            "reason" => &reason,
            "rate_pps" => rate_pps
        );

        // 调用决策引擎
        if let Some(engine) = decision_engine {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                engine.handle_event(ip, &reason, rate_pps);
            } else {
                crate::logger::warn!(
                    crate::logger::get(),
                    "无法解析 IP 地址";
                    "ip" => &ip_str
                );
            }
        }

        Ok(())
    }

    /// 处理封禁状态变更事件
    pub(super) fn handle_ban_state_change(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlBanStateChange>() {
            anyhow::bail!("BanStateChange 事件数据太短");
        }

        let event = FwNlBanStateChange::from_bytes(hdr_data)?;
        let ip_str = event.ip_str();
        let reason_str = event.reason_str();

        if event.is_ban() {
            crate::logger::debug!(
                crate::logger::get(),
                "收到封禁状态变更：封禁";
                "ip" => &ip_str,
                "duration_secs" => event.duration_secs(),
                "reason" => &reason_str
            );

            let cache =
                crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);

            // 检查缓存是否已有此 IP（daemon 在发 netlink 前已 try_insert/insert）
            // 有 → daemon 发起：缓存已有正确 jail/reason；若仍待 ACK 则此时写 ban_history
            // 无 → procfs/内核路径：在此处记录 ban_history 并插入缓存
            let daemon_initiated = cache.contains(&ip_str);

            if daemon_initiated {
                if crate::types::take_pending_ban_ack(&ip_str) {
                    let is_permanent = event.duration_secs() == 0;
                    let ban_history =
                        crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
                    let ban_count = ban_history.record_ban(&ip_str, is_permanent);
                    let jail_name = cache
                        .get(&ip_str)
                        .map(|b| b.jail_name.clone())
                        .unwrap_or_else(|| "api".to_string());
                    crate::history_snapshot::record_ban_event(&ip_str, &jail_name, ban_count);
                    if jail_name != "api" && jail_name != "ddos" && jail_name != "system" {
                        crate::ip_reputation::get_store().record_ban(&ip_str);
                    }
                    crate::types::notify_ban_ack_ok(&ip_str);
                    crate::logger::debug!(
                        crate::logger::get(),
                        "BanStateChange: 内核确认，已写入 ban_history";
                        "ip" => &ip_str,
                        "ban_count" => ban_count
                    );
                } else {
                    crate::types::notify_ban_ack_ok(&ip_str);
                    crate::logger::debug!(
                        crate::logger::get(),
                        "BanStateChange: daemon 发起且历史已确认，跳过";
                        "ip" => &ip_str
                    );
                }
            } else {
                let (actual_reason, jail_name) = if let Some(jn) = event.jail_name_str() {
                    if reason_str.is_empty() {
                        (jn.clone(), jn)
                    } else {
                        (reason_str, jn)
                    }
                } else if reason_str.starts_with("api:") {
                    let actual = reason_str.strip_prefix("api:").unwrap_or(&reason_str);
                    (actual.to_string(), "api".to_string())
                } else if reason_str.contains("SYN flood")
                    || reason_str.contains("UDP flood")
                    || reason_str.contains("ICMP flood")
                    || reason_str.contains("total rate")
                    || reason_str.contains("ddos")
                {
                    (reason_str, "ddos".to_string())
                } else if reason_str == "procfs" || reason_str == "manual" || reason_str == "api" {
                    (reason_str, "api".to_string())
                } else if reason_str == "expired"
                    || reason_str == "unban"
                    || reason_str == "whitelist"
                {
                    (reason_str, "system".to_string())
                } else {
                    (reason_str, "api".to_string())
                };

                let now = crate::types::now_secs();
                let ban_history =
                    crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
                let is_permanent = event.duration_secs() == 0;
                let ban_count = ban_history.record_ban(&ip_str, is_permanent);
                let jail_name_for_event = jail_name.clone();
                let ban_info = crate::types::BanInfo {
                    ip: ip_str.clone(),
                    ip_num: 0,
                    jail_name,
                    reason: actual_reason,
                    banned_at: now,
                    expires_at: if is_permanent {
                        0
                    } else {
                        now + event.duration_secs() as i64
                    },
                    is_permanent,
                    fail_count: 0,
                    ban_count,
                };
                cache.insert(ban_info);
                crate::history_snapshot::record_ban_event(&ip_str, &jail_name_for_event, ban_count);
                crate::logger::info!(
                    crate::logger::get(),
                    "已更新 ACTIVE_BAN_CACHE (procfs 封禁)";
                    "ip" => &ip_str,
                    "cache_len" => cache.len()
                );
            }
        } else if event.is_unban() {
            crate::logger::debug!(
                crate::logger::get(),
                "收到封禁状态变更：解封";
                "ip" => &ip_str
            );

            // 从 ACTIVE_BAN_CACHE 移除，记录封禁时长到 histogram
            let cache =
                crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
            if let Some(removed_ban) = cache.remove(&ip_str) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let duration = now - removed_ban.banned_at;
                if duration > 0 {
                    crate::types::record_ban_duration(duration);
                }
            }
            // 记录解封到 BAN_HISTORY（修复 record_unban 从未被调用的设计缺陷）
            let ban_history = crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
            ban_history.record_unban(&ip_str);
            // 更新 DAEMON_STATS 计数器
            crate::types::DAEMON_STATS
                .total_unbans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }

        // 实时同步统计数据（事件驱动，消除轮询延迟）
        crate::types::DAEMON_STATS.packets_dropped.store(
            event.packets_dropped(),
            std::sync::atomic::Ordering::Relaxed,
        );
        crate::types::DAEMON_STATS.packets_accepted.store(
            event.packets_accepted(),
            std::sync::atomic::Ordering::Relaxed,
        );
        crate::types::DAEMON_STATS.whitelist_count.store(
            event.whitelist_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        // 封禁/解封后立即唤醒 SSE，避免 UI 等待整轮 push interval
        crate::web_ui::sse::wake_sse_clients();

        Ok(())
    }

    /// 处理封禁列表响应（启动时状态恢复）
    pub(super) fn handle_list_bans_response(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlListBansResponse>() {
            anyhow::bail!("封禁列表响应数据太短");
        }

        let (resp, entries) = FwNlListBansResponse::from_bytes(hdr_data)?;
        let page_count = entries.len() as u32;
        let total = u32::from_be(resp.total);
        let offset = u32::from_be(resp.offset);
        let seq = u32::from_be(resp.hdr.seq);

        crate::logger::debug!(
            crate::logger::get(),
            "收到封禁列表响应";
            "count" => page_count,
            "total" => total,
            "offset" => offset
        );

        let mut page_infos = Vec::with_capacity(entries.len());
        for entry in &entries {
            let ip_str = FwNlListBansResponse::ip_str(entry);
            let duration = u32::from_be(entry.duration_secs);
            let is_permanent = entry.is_permanent != 0;
            let banned_at = u64::from_be(entry.banned_at) as i64;
            let raw_jail = FwNlListBansResponse::jail_name_str(entry);
            let reason = FwNlListBansResponse::reason_str(entry);

            let jail_name = if raw_jail.is_empty() || raw_jail == "kernel" {
                let r = if reason.is_empty() {
                    &raw_jail
                } else {
                    &reason
                };
                if r.contains("flood") || r.contains("ddos") || r.contains("total rate") {
                    "ddos".to_string()
                } else {
                    "api".to_string()
                }
            } else {
                raw_jail.clone()
            };
            let final_reason = if reason.is_empty() {
                if raw_jail.is_empty() || raw_jail == "kernel" {
                    "api".to_string()
                } else {
                    raw_jail
                }
            } else {
                reason
            };

            let ban_history = crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
            let ban_count = ban_history.get_ban_count(&ip_str);
            page_infos.push(crate::types::BanInfo {
                ip: ip_str,
                ip_num: 0,
                jail_name,
                reason: final_reason,
                banned_at,
                expires_at: if is_permanent {
                    0
                } else {
                    banned_at + duration as i64
                },
                is_permanent,
                fail_count: 0,
                ban_count,
            });
        }

        let mut done_infos: Option<Vec<crate::types::BanInfo>> = None;
        {
            let mut guard = pending_list_bans()
                .lock()
                .map_err(|_| anyhow::anyhow!("pending list bans lock poisoned"))?;
            if offset == 0 {
                *guard = Some(PendingListBans {
                    total,
                    next_offset: page_count,
                    infos: page_infos,
                });
            } else {
                match guard.as_mut() {
                    Some(pending) if pending.next_offset == offset => {
                        pending.total = total;
                        pending.infos.extend(page_infos);
                        pending.next_offset = offset.saturating_add(page_count);
                    }
                    _ => {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "封禁列表分页失序，丢弃本页并重置";
                            "offset" => offset
                        );
                        *guard = None;
                        return Ok(());
                    }
                }
            }

            if let Some(pending) = guard.as_ref() {
                if pending.next_offset >= pending.total || page_count == 0 {
                    done_infos = guard.take().map(|p| p.infos);
                }
            }
        }

        if let Some(infos) = done_infos {
            if infos.len() > MAX_BAN_ENTRIES_ACCUM {
                anyhow::bail!("累计封禁条目过多: {}", infos.len());
            }
            let cache =
                crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
            let mut kernel_ips = std::collections::HashSet::with_capacity(infos.len());
            for info in &infos {
                kernel_ips.insert(info.ip.clone());
            }
            let removed = cache.reconcile_with_kernel(&kernel_ips, infos);
            crate::logger::info!(
                crate::logger::get(),
                "已对账封禁状态";
                "kernel_count" => kernel_ips.len(),
                "stale_removed" => removed,
                "cache_len" => cache.len()
            );
            return Ok(());
        }

        let next_offset = offset.saturating_add(page_count);
        if let Some(ctx) = super::get_global_netlink_ctx() {
            if let Err(e) =
                ctx.send_list_bans_query_page(seq.wrapping_add(1), next_offset, LIST_BANS_PAGE_MAX)
            {
                crate::logger::warn!(
                    crate::logger::get(),
                    "继续拉取封禁列表失败";
                    "offset" => next_offset,
                    "error" => %e
                );
                let _ = pending_list_bans().lock().map(|mut g| *g = None);
            }
        }

        Ok(())
    }

    /// 处理统计数据响应
    pub(super) fn handle_stats_response(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlStatsResponse>() {
            anyhow::bail!("统计数据响应太短");
        }

        let stats = FwNlStatsResponse::from_bytes(hdr_data)?;
        crate::logger::debug!(
            crate::logger::get(),
            "收到统计数据响应";
            "current_bans" => stats.current_bans(),
            "total_bans" => stats.total_bans(),
            "total_unbans" => stats.total_unbans(),
            "whitelist_count" => stats.whitelist_count(),
            "packets_dropped" => stats.packets_dropped(),
            "packets_accepted" => stats.packets_accepted()
        );

        // 更新 packets 计数（来自 netlink StatsResponse，由后台线程周期性 send_stats_query 触发）
        crate::types::DAEMON_STATS.packets_dropped.store(
            stats.packets_dropped(),
            std::sync::atomic::Ordering::Relaxed,
        );
        crate::types::DAEMON_STATS.packets_accepted.store(
            stats.packets_accepted(),
            std::sync::atomic::Ordering::Relaxed,
        );

        Ok(())
    }

    /// 处理白名单列表响应
    pub(super) fn handle_list_whitelist_response(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlListWhitelistResponse>() {
            anyhow::bail!("白名单列表响应数据太短");
        }

        let (_resp, entries) = FwNlListWhitelistResponse::from_bytes(hdr_data)?;
        crate::logger::debug!(
            crate::logger::get(),
            "收到白名单列表响应";
            "count" => entries.len()
        );

        // 更新 WHITELIST_CACHE
        let whitelist_entries: std::collections::HashMap<String, crate::types::WhitelistEntry> =
            entries
                .iter()
                .map(|e| {
                    let ip_str = if e.af == 2 {
                        // AF_INET
                        format!("{}.{}.{}.{}", e.addr[0], e.addr[1], e.addr[2], e.addr[3])
                    } else if e.af == 10 {
                        // AF_INET6
                        let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(e.addr);
                        addr.to_string()
                    } else {
                        "unknown".to_string()
                    };

                    // 构建 CIDR 格式
                    let cidr = format!("{}/{}", ip_str, e.prefix_len);

                    // 设备名（null 结尾的字节数组）
                    let device = String::from_utf8_lossy(&e.device)
                        .trim_end_matches('\0')
                        .to_string();

                    (cidr.clone(), crate::types::WhitelistEntry { cidr, device })
                })
                .collect();

        *crate::types::WHITELIST_CACHE.write() = whitelist_entries;

        // 更新 DAEMON_STATS.whitelist_count
        crate::types::DAEMON_STATS
            .whitelist_count
            .store(entries.len() as u64, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    /// 处理速率统计响应
    pub(super) fn handle_list_rates_response(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlListRatesResponse>() {
            anyhow::bail!("速率统计响应数据太短");
        }

        let (resp, entries) = FwNlListRatesResponse::from_bytes(hdr_data)?;

        // 提取全局流量速率（内核 atomic64_xchg 读取并重置）
        let global_pps = resp.global_pps();
        let global_bps = resp.global_bps();

        // 更新速率基线（EWMA α=0.01 平滑，用于动态阈值）
        if global_pps > 0 || global_bps > 0 {
            crate::types::update_traffic_baseline(global_pps, global_bps);
            // 更新多窗口速率 EWMA（短期/中期/长期）
            crate::types::update_rate_windows(global_pps, global_bps);
        }

        // 更新 RATE_CACHE 并计算总速率
        let mut total_pps = 0u64;
        let mut total_bps = 0u64;
        let rate_entries: Vec<crate::types::RateEntry> = entries
            .iter()
            .map(|e| {
                let pps = u64::from_be(e.packets);
                let bps = u64::from_be(e.bytes);
                total_pps += pps;
                total_bps += bps;
                crate::types::RateEntry {
                    ip: FwNlListRatesResponse::ip_str(e),
                    packets_per_sec: pps,
                    bytes_per_sec: bps,
                    syn_packets_per_sec: u64::from_be(e.syn_packets),
                    udp_packets_per_sec: u64::from_be(e.udp_packets),
                    icmp_packets_per_sec: u64::from_be(e.icmp_packets),
                    ack_packets_per_sec: u64::from_be(e.ack_packets),
                    rst_packets_per_sec: u64::from_be(e.rst_packets),
                    fin_packets_per_sec: u64::from_be(e.fin_packets),
                }
            })
            .collect();

        *crate::types::RATE_CACHE.write() = rate_entries;

        // 记录速率历史快照（每 2 秒一次，保留 1 小时）
        crate::types::record_rate_history(total_pps, total_bps, entries.len() as u32);

        crate::logger::debug!(
            crate::logger::get(),
            "收到速率统计响应";
            "count" => entries.len(),
            "total_pps" => total_pps,
            "total_bps" => total_bps,
            "global_pps" => global_pps,
            "global_bps" => global_bps
        );

        Ok(())
    }

    /// 处理配置更新确认
    pub(super) fn handle_config_ack(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlConfigAck>() {
            anyhow::bail!("配置确认数据太短");
        }

        let ack = FwNlConfigAck::from_bytes(hdr_data)?;
        let applied = ack.applied_flags();
        let rejected = ack.rejected_flags();

        if rejected != 0 {
            crate::logger::warn!(
                crate::logger::get(),
                "配置更新部分被拒绝";
                "applied_flags" => format!("0x{:x}", applied),
                "rejected_flags" => format!("0x{:x}", rejected)
            );
        } else {
            crate::logger::debug!(
                crate::logger::get(),
                "配置更新已确认";
                "applied_flags" => format!("0x{:x}", applied)
            );
        }

        Ok(())
    }

    /// 处理白名单状态变更事件
    pub(super) fn handle_whitelist_state_change(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlWhitelistStateChange>() {
            anyhow::bail!("白名单状态变更事件数据太短");
        }

        let event = FwNlWhitelistStateChange::from_bytes(hdr_data)?;
        let ip_str = event.ip_str();
        let device_str = event.device_str();
        let prefix_len = event.prefix_len;

        // 构建 CIDR 格式
        let cidr = if ip_str.contains(':') {
            // IPv6
            if prefix_len == 128 || prefix_len == 0 {
                ip_str.clone()
            } else {
                format!("{}/{}", ip_str, prefix_len)
            }
        } else {
            // IPv4
            if prefix_len == 32 || prefix_len == 0 {
                ip_str.clone()
            } else {
                format!("{}/{}", ip_str, prefix_len)
            }
        };

        if event.is_add() {
            crate::logger::debug!(
                crate::logger::get(),
                "收到白名单状态变更：添加";
                "ip" => &ip_str,
                "prefix_len" => prefix_len,
                "device" => &device_str
            );

            // 更新 WHITELIST_CACHE（HashMap insert 天然幂等，补充 device）
            let mut cache = crate::types::WHITELIST_CACHE.write();
            match cache.get_mut(&cidr) {
                Some(entry) if entry.device.is_empty() && !device_str.is_empty() => {
                    entry.device = device_str;
                }
                None => {
                    cache.insert(
                        cidr.clone(),
                        crate::types::WhitelistEntry {
                            cidr,
                            device: device_str,
                        },
                    );
                }
                _ => {}
            }
        } else if event.is_remove() {
            crate::logger::debug!(
                crate::logger::get(),
                "收到白名单状态变更：移除";
                "ip" => &ip_str,
                "prefix_len" => prefix_len
            );

            // 从 WHITELIST_CACHE 移除
            crate::types::WHITELIST_CACHE.write().remove(&cidr);
        }

        // 实时更新白名单计数
        crate::types::DAEMON_STATS.whitelist_count.store(
            event.whitelist_count() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        crate::web_ui::sse::wake_sse_clients();

        Ok(())
    }

    /// 处理内核命令执行结果
    pub(super) fn handle_cmd_result(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlCmdResult>() {
            anyhow::bail!("CmdResult 数据太短");
        }
        let event = FwNlCmdResult::from_bytes(hdr_data)?;
        let ip_str = event.ip_str();
        let cmd = event.original_cmd();
        crate::logger::warn!(
            crate::logger::get(),
            "内核命令执行失败";
            "cmd" => event.cmd_name(),
            "error_code" => event.error_code(),
            "ip" => &ip_str
        );

        // sendto 成功 ≠ 内核成功：回滚乐观写入的缓存，避免脏状态残留
        let cache = crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
        match cmd {
            // BanIp 失败：撤掉提前 insert 的缓存项与待确认历史
            2 if cache.remove(&ip_str).is_some() => {
                crate::types::clear_pending_ban_ack(&ip_str);
                crate::types::notify_ban_ack_err(&ip_str, event.error_code());
                crate::web_ui::sse::wake_sse_clients();
                crate::logger::info!(
                    crate::logger::get(),
                    "BanIp 失败，已回滚封禁缓存";
                    "ip" => &ip_str
                );
            }
            2 => {
                crate::types::clear_pending_ban_ack(&ip_str);
                crate::types::notify_ban_ack_err(&ip_str, event.error_code());
                crate::web_ui::sse::wake_sse_clients();
            }
            3 => {
                // UnbanIp 失败：缓存可能已被乐观 remove；无法无损恢复元数据，
                // 依赖后续 LIST bans 对账补回。此处仅记录。
                crate::logger::debug!(
                    crate::logger::get(),
                    "UnbanIp 失败，等待 LIST 对账恢复缓存";
                    "ip" => &ip_str
                );
            }
            _ => {}
        }
        Ok(())
    }

    /// 处理 procfs 配置变更通知
    pub(super) fn handle_config_change(hdr_data: &[u8]) -> Result<()> {
        if hdr_data.len() < std::mem::size_of::<FwNlConfigUpdate>() {
            anyhow::bail!("ConfigChange 数据太短");
        }
        let cfg = FwNlConfigUpdate::from_bytes(hdr_data)?;
        let flags = cfg.flags();
        if flags & config_flags::BAN_TIME != 0 {
            let new_ban_time = cfg.ban_time();
            crate::logger::debug!(
                crate::logger::get(),
                "内核 ban_time 已通过 procfs 变更";
                "new_ban_time" => new_ban_time
            );
        }
        Ok(())
    }

    /// 处理分析数据响应（内核 → 守护进程）
    ///
    /// 解析内核返回的包大小分布、TTL 分布、IP 分片、UDP/ICMP 分布、
    /// 端口扫描者、服务探测者，更新 ANALYSIS_CACHE。
    pub(super) fn handle_analysis_response(hdr_data: &[u8]) -> Result<()> {
        use crate::types::{
            AnalysisData, AnalysisIcmpTypeEntry, AnalysisScannerEntry, AnalysisUdpPortEntry,
            ANALYSIS_CACHE,
        };

        let resp = FwNlAnalysisResponse::from_bytes(hdr_data)?;

        // 包大小分布（packed 结构体字段必须按值拷贝，禁止取引用）
        let mut pkt_sizes = [0u64; 5];
        {
            let raw = resp.pkt_sizes;
            for (i, val) in pkt_sizes.iter_mut().enumerate() {
                *val = u64::from_be(raw[i]);
            }
        }

        // TTL 分布
        let mut ttl_dist = [0u64; 6];
        {
            let raw = resp.ttl_dist;
            for (i, val) in ttl_dist.iter_mut().enumerate() {
                *val = u64::from_be(raw[i]);
            }
        }

        let ip_total_count = u64::from_be(resp.ip_frag_total);
        let ip_frag_count = u64::from_be(resp.ip_frag_count);

        // UDP 端口分布
        let udp_count = u32::from_be(resp.udp_port_count) as usize;
        let udp_port_capacity = u32::from_be(resp.udp_port_capacity);
        let mut udp_ports = Vec::with_capacity(udp_count.min(64));
        for i in 0..udp_count.min(64) {
            let item = resp.udp_ports[i];
            udp_ports.push(AnalysisUdpPortEntry {
                port: u16::from_be(item.port),
                packets: u64::from_be(item.packets),
                bytes: u64::from_be(item.bytes),
                last_seen_secs: u64::from_be(item.last_seen_secs),
            });
        }

        // ICMP 类型分布
        let icmp_count = u32::from_be(resp.icmp_type_count) as usize;
        let icmp_type_capacity = u32::from_be(resp.icmp_type_capacity);
        let mut icmp_types = Vec::with_capacity(icmp_count.min(64));
        for i in 0..icmp_count.min(64) {
            let item = resp.icmp_types[i];
            icmp_types.push(AnalysisIcmpTypeEntry {
                r#type: item.r#type,
                code: item.code,
                packets: u64::from_be(item.packets),
                bytes: u64::from_be(item.bytes),
                last_seen_secs: u64::from_be(item.last_seen_secs),
            });
        }

        // 端口扫描者
        let ps_count = u32::from_be(resp.port_scan_count) as usize;
        let ps_threshold = u32::from_be(resp.port_scan_threshold);
        let mut port_scanners = Vec::with_capacity(ps_count.min(20));
        for i in 0..ps_count.min(20) {
            let item = resp.port_scanners[i];
            let ip = scanner_item_ip(&item);
            port_scanners.push(AnalysisScannerEntry {
                ip,
                metric: u32::from_be(item.metric),
                packets: u64::from_be(item.packets),
            });
        }

        // 服务探测者
        let sp_count = u32::from_be(resp.service_probe_count) as usize;
        let sp_threshold = u32::from_be(resp.service_probe_threshold);
        let mut service_probes = Vec::with_capacity(sp_count.min(20));
        for i in 0..sp_count.min(20) {
            let item = resp.service_probes[i];
            let ip = scanner_item_ip(&item);
            service_probes.push(AnalysisScannerEntry {
                ip,
                metric: u32::from_be(item.metric),
                packets: u64::from_be(item.packets),
            });
        }

        // 更新缓存
        let data = AnalysisData {
            pkt_sizes,
            ttl_dist,
            ip_total_count,
            ip_frag_count,
            udp_ports,
            udp_port_capacity,
            icmp_types,
            icmp_type_capacity,
            port_scanners,
            port_scan_threshold: ps_threshold,
            service_probes,
            service_probe_threshold: sp_threshold,
        };
        *ANALYSIS_CACHE.write() = data;

        Ok(())
    }
}

/// 从 scanner item 提取 IP 地址字符串
fn scanner_item_ip(item: &super::responses::FwNlScannerItem) -> String {
    use std::net::{Ipv4Addr, Ipv6Addr};
    match item.af {
        2 => {
            // FW_AF_INET
            let bytes = [item.addr[0], item.addr[1], item.addr[2], item.addr[3]];
            Ipv4Addr::from(bytes).to_string()
        }
        10 => {
            // FW_AF_INET6
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&item.addr);
            Ipv6Addr::from(bytes).to_string()
        }
        _ => "unknown".to_string(),
    }
}
