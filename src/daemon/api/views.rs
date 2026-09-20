//! 视图派生：把不可变快照（与少数端口）翻译成线上载荷。
//!
//! # 为什么单独成文件
//!
//! SSE 与 REST 两条路要用**同一份**视图：否则「SSE 推的 bans」与
//! 「`GET /api/v1/bans` 返回的 bans」迟早会长得不一样（旧实现就是各写一份）。
//! 这里只有纯函数：输入快照与端口，输出载荷，不碰任何锁、不写任何状态。
//!
//! # 读路径零副作用
//!
//! 本文件里没有一处修改入参或全局——缺陷 E 的判据正是「读不得改状态」。

use std::collections::HashMap;
use std::net::IpAddr;

use crate::state::bans::{BanEntry, BanSnapshot};
use crate::state::rates::{RateCounters, RateSnapshot};
use crate::state::stats::{Counter, StatsSnapshot};
use crate::state::whitelist::WhitelistSnapshot;

use super::payloads::{
    BanDetailResponse, BanResponse, RateResponse, StatsResponse, ThreatLevel,
    WhitelistEntryResponse,
};
use super::ports::{BanHistoryView, ChartData, TrendsView};

/// 内核封禁哈希桶数（`BAN_HASH_BITS = 12`）。
///
/// 封禁表使用率以**内核桶数**为分母，而不是 daemon 侧的配置容量——两者语义不同。
pub const KERNEL_BAN_BUCKETS: u64 = 4096;

/// 默认每页条数。
pub const DEFAULT_PAGE_SIZE: u32 = 20;
/// 每页条数上限。
pub const MAX_PAGE_SIZE: u32 = 100;
/// 单次批量封禁的条目上限（契约 `40005` 的判据之一）。
pub const MAX_BATCH_SIZE: usize = 100;

/// 5 分钟内封禁数的统计窗（秒）。
pub const RECENT_BAN_WINDOW_SECS: i64 = 300;

/// 详情页「下次封禁时长」所用的基础时长（秒）。
///
/// 取 300（5 分钟）与旧详情页一致；该字段只是展示预估，不影响真实判定——真实的
/// 时长来自各 jail 的 `ban_time`。
pub const NEXT_BAN_BASE_SECS: u32 = 300;

/// 封禁列表的排序键。
///
/// 七个取值与契约及前端联合类型一致；未知取值退化为默认（按封禁时间倒序），
/// 而不是报错——排序是展示偏好，不是业务判据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanSort {
    /// 封禁时间倒序（默认）。
    BannedAtDesc,
    /// 封禁时间升序。
    BannedAtAsc,
    /// IP 升序。
    IpAsc,
    /// IP 降序。
    IpDesc,
    /// 剩余时间升序。
    RemainingAsc,
    /// 剩余时间降序。
    RemainingDesc,
    /// Jail 名升序。
    JailAsc,
}

impl BanSort {
    /// 解析排序键文本；未知取值退化为 [`BanSort::BannedAtDesc`]。
    #[must_use]
    pub fn parse(text: Option<&str>) -> Self {
        match text {
            Some("banned_at_asc") => Self::BannedAtAsc,
            Some("ip_asc") => Self::IpAsc,
            Some("ip_desc") => Self::IpDesc,
            Some("remaining_asc") => Self::RemainingAsc,
            Some("remaining_desc") => Self::RemainingDesc,
            Some("jail_asc") => Self::JailAsc,
            _ => Self::BannedAtDesc,
        }
    }
}

/// 一条封禁的线上形状。
#[must_use]
pub fn ban_to_response(entry: &BanEntry, now: i64) -> BanResponse {
    BanResponse {
        ip: entry.ip.to_string(),
        jail: entry.jail.clone(),
        banned_at: entry.banned_at,
        remaining_seconds: entry.remaining_secs(now),
        reason: entry.reason.clone(),
        ban_count: entry.ban_count,
        is_permanent: entry.is_permanent,
    }
}

/// 按给定排序键排序后的封禁列表。
///
/// 排序在**派生视图**上做，不动快照本身——读侧不得改变被读对象。
#[must_use]
pub fn bans_sorted(snapshot: &BanSnapshot, sort: BanSort, now: i64) -> Vec<BanResponse> {
    let mut items: Vec<BanResponse> = snapshot
        .entries()
        .iter()
        .map(|e| ban_to_response(e, now))
        .collect();
    match sort {
        BanSort::BannedAtDesc => items.sort_by_key(|b| std::cmp::Reverse(b.banned_at)),
        BanSort::BannedAtAsc => items.sort_by_key(|a| a.banned_at),
        BanSort::IpAsc => items.sort_by_key(|a| a.ip.parse::<IpAddr>().ok()),
        BanSort::IpDesc => items.sort_by_key(|a| std::cmp::Reverse(a.ip.parse::<IpAddr>().ok())),
        BanSort::RemainingAsc => items.sort_by_key(|a| a.remaining_seconds),
        BanSort::RemainingDesc => items.sort_by_key(|b| std::cmp::Reverse(b.remaining_seconds)),
        BanSort::JailAsc => items.sort_by(|a, b| a.jail.cmp(&b.jail)),
    }
    items
}

/// 把请求的分页参数规范化：页码至少 1，每页条数落在 `[1, 100]`。
#[must_use]
pub fn normalize_paging(page: Option<u32>, page_size: Option<u32>) -> (u32, u32) {
    let page = page.unwrap_or(1).max(1);
    let page_size = page_size
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE);
    (page, page_size)
}

/// 取排序后列表的一页（页码从 1 开始），并返回总数。
#[must_use]
pub fn page_slice<T>(items: Vec<T>, page: u32, page_size: u32) -> (Vec<T>, u64) {
    let total = items.len() as u64;
    let offset = usize::try_from(page.saturating_sub(1))
        .unwrap_or(usize::MAX)
        .saturating_mul(page_size as usize);
    let sliced = items
        .into_iter()
        .skip(offset)
        .take(page_size as usize)
        .collect();
    (sliced, total)
}

/// 白名单的线上形状。
#[must_use]
pub fn whitelist_view(snapshot: &WhitelistSnapshot) -> Vec<WhitelistEntryResponse> {
    snapshot
        .entries()
        .iter()
        .map(|e| WhitelistEntryResponse {
            cidr: e.cidr.to_string(),
            device: e.device.clone(),
        })
        .collect()
}

/// 单个 IP 速率的线上形状。
#[must_use]
pub fn rate_to_response(ip: &IpAddr, c: &RateCounters) -> RateResponse {
    RateResponse {
        ip: ip.to_string(),
        packets_per_sec: c.packets,
        bytes_per_sec: c.bytes,
        syn_packets_per_sec: c.syn,
        udp_packets_per_sec: c.udp,
        icmp_packets_per_sec: c.icmp,
        ack_packets_per_sec: c.ack,
        rst_packets_per_sec: c.rst,
        fin_packets_per_sec: c.fin,
    }
}

/// 速率列表（按 IP 升序，与快照一致）。
#[must_use]
pub fn rates_view(snapshot: &RateSnapshot) -> Vec<RateResponse> {
    snapshot
        .sample
        .per_ip
        .iter()
        .map(|(ip, c)| rate_to_response(ip, c))
        .collect()
}

/// 按 jail 的封禁分布（标签升序）。
#[must_use]
pub fn jail_distribution(snapshot: &BanSnapshot) -> ChartData {
    let labels: Vec<String> = snapshot.jails().map(str::to_string).collect();
    let values = labels
        .iter()
        .map(|jail| snapshot.count_for_jail(jail) as u64)
        .collect();
    ChartData { labels, values }
}

/// 按原因的封禁分布（次数降序；同次数按原因升序，保证可复现）。
#[must_use]
pub fn failure_reasons(snapshot: &BanSnapshot) -> ChartData {
    let mut counts: HashMap<&str, u64> = HashMap::new();
    for entry in snapshot.entries() {
        *counts.entry(entry.reason.as_str()).or_insert(0) += 1;
    }
    let mut pairs: Vec<(&str, u64)> = counts.into_iter().collect();
    pairs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    ChartData {
        labels: pairs.iter().map(|(r, _)| (*r).to_string()).collect(),
        values: pairs.iter().map(|(_, c)| *c).collect(),
    }
}

/// 最近 `RECENT_BAN_WINDOW_SECS` 内的封禁数。
#[must_use]
pub fn recent_bans(snapshot: &BanSnapshot, now: i64) -> u64 {
    let cutoff = now - RECENT_BAN_WINDOW_SECS;
    snapshot
        .entries()
        .iter()
        .filter(|e| e.banned_at > cutoff)
        .count() as u64
}

/// 威胁等级。
///
/// 输入全部是已经算好的量（当前 pps、阈值、封禁数、DDoS 事件数），本函数只做
/// 分级与文案——不读全局、不查库。分档沿用旧实现的判据，故等级含义不变。
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn threat_level(
    current_bans: u64,
    ddos_events: u64,
    recent: u64,
    current_pps: u64,
    pps_threshold: u64,
    baseline_frozen: bool,
    peak_hours: bool,
) -> ThreatLevel {
    let mut factors: Vec<String> = Vec::new();
    let mut score: u8 = 0;

    let pps_ratio = if pps_threshold > 0 {
        current_pps as f64 / pps_threshold as f64
    } else {
        0.0
    };
    if pps_ratio > 1.0 {
        score = score.max(4);
        factors.push(format!("PPS 超阈值 ({pps_ratio:.1}x)"));
    } else if pps_ratio > 0.5 {
        score = score.max(3);
        factors.push(format!("PPS 接近阈值 ({:.0}%)", pps_ratio * 100.0));
    } else if pps_ratio > 0.2 {
        score = score.max(1);
    }

    let ban_table_usage = current_bans as f64 / KERNEL_BAN_BUCKETS as f64;
    if ban_table_usage > 0.9 {
        score = score.max(4);
        factors.push(format!("封禁表即将满载 ({:.0}%)", ban_table_usage * 100.0));
    } else if ban_table_usage > 0.5 {
        score = score.max(2);
        factors.push(format!(
            "封禁表使用率偏高 ({:.0}%)",
            ban_table_usage * 100.0
        ));
    }

    if recent > 50 {
        score = score.max(4);
        factors.push(format!("5 分钟内 {recent} 次封禁"));
    } else if recent > 20 {
        score = score.max(3);
        factors.push(format!("5 分钟内 {recent} 次封禁"));
    } else if recent > 5 {
        score = score.max(2);
    }

    if ddos_events > 10 {
        score = score.max(3);
        factors.push(format!("累计 {ddos_events} 次 DDoS 事件"));
    } else if ddos_events > 0 {
        score = score.max(1);
    }

    if baseline_frozen {
        score = score.max(3);
        factors.push("基线已冻结（异常流量突增）".to_string());
    }

    let level = match score {
        0 => "safe",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "critical",
    }
    .to_string();

    if factors.is_empty() {
        factors.push("一切正常".to_string());
    }

    ThreatLevel {
        level,
        score,
        factors,
        current_pps,
        pps_ratio,
        ban_table_usage,
        recent_bans: recent,
        baseline_frozen,
        peak_hours,
    }
}

/// 统计总览。
///
/// 输入全是已算好的量：计数器快照、封禁快照、白名单条目数、趋势与威胁等级。
/// 本函数不读全局、不查库，故 SSE 与 REST 两条路能得到同一份结果。
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn stats_view(
    stats: &StatsSnapshot,
    bans: &BanSnapshot,
    whitelist_count: u64,
    now: u64,
    daemon_version: &str,
    kernel_version: &str,
    ddos_events: u64,
    trends: &TrendsView,
    threat: ThreatLevel,
) -> StatsResponse {
    StatsResponse {
        daemon_version: daemon_version.to_string(),
        kernel_version: kernel_version.to_string(),
        // 「今日」窗口尚未实现：与 total_bans 同源（缺陷
        // HTTP_TODAY_BANS_EQUALS_TOTAL 仍成立，属 2.F）。此处保持同一取值，
        // 不引入「看起来像今日窗口」的假实现。
        today_bans: stats.get(Counter::IpsBanned),
        failed_attempts: stats.get(Counter::FailedAttempts),
        ddos_events,
        uptime_seconds: stats.uptime_secs(now),
        ban_trend: trends.ban_trend.clone(),
        jail_distribution: jail_distribution(bans),
        failure_reasons: failure_reasons(bans),
        failed_attempts_trend: trends.failed_attempts_trend.clone(),
        current_bans: bans.len() as u64,
        total_bans: stats.get(Counter::IpsBanned),
        total_unbans: stats.get(Counter::TotalUnbans),
        whitelist_count,
        packets_dropped: stats.get(Counter::PacketsDropped),
        packets_accepted: stats.get(Counter::PacketsAccepted),
        threat_level: threat,
    }
}

/// 渐进式封禁等级的文案。
#[must_use]
pub fn progressive_level_label(ban_count: u32) -> String {
    match ban_count {
        0 => "首次封禁",
        1 => "二次封禁（累犯）",
        2 => "三次封禁（惯犯）",
        _ => "多次封禁（永久）",
    }
    .to_string()
}

/// 下次封禁时长的文案（`0` 表示永久）。
#[must_use]
pub fn next_ban_duration_label(duration_secs: u32) -> String {
    if duration_secs == 0 {
        "永久封禁".to_string()
    } else {
        format!("{duration_secs} 秒")
    }
}

/// 一条封禁的详情。
///
/// `active` 为 `state` 里的当前条目（可能已过期但条目尚在）；`history` 为历史面
/// （可能没有任何历史，此时用默认值）。
#[must_use]
pub fn ban_detail_view(
    ip: IpAddr,
    active: Option<&BanEntry>,
    history: Option<BanHistoryView>,
    next_duration_secs: u32,
    now: i64,
) -> BanDetailResponse {
    let history = history.unwrap_or_default();
    let (is_banned, jail_name, reason, banned_at, expires_at, is_permanent, fail_count, ban_count) =
        match active {
            Some(entry) => (
                !entry.is_expired(now),
                entry.jail.clone(),
                entry.reason.clone(),
                entry.banned_at,
                entry.expires_at,
                entry.is_permanent,
                entry.fail_count,
                entry.ban_count,
            ),
            None => (
                false,
                String::new(),
                String::new(),
                0,
                0,
                false,
                0,
                history.ban_count,
            ),
        };

    BanDetailResponse {
        ip: ip.to_string(),
        is_banned,
        jail_name,
        reason,
        banned_at,
        expires_at,
        is_permanent,
        fail_count,
        ban_count,
        last_unbanned_at: history.last_unbanned_at,
        was_permanent: history.was_permanent,
        progressive_level: progressive_level_label(ban_count),
        next_ban_duration: next_ban_duration_label(next_duration_secs),
        reputation_score: history.reputation_score,
        reputation_multiplier: history.reputation_multiplier,
    }
}
