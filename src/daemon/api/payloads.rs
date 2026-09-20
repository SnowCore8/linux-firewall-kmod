//! HTTP 载荷类型：与 `contract/http.fwidl` 逐字段对应。
//!
//! # 为什么独立成文件
//!
//! `verify_http.py` 会按名字在 daemon 源码里找同名 struct，再逐字段核对名称与
//! `Serialize` / `Deserialize` 派生。把载荷集中在这里有两个好处：一是「契约类型」
//! 与「路由逻辑」分开，读路由时不必在几十个 struct 定义里穿行；二是契约增删字段
//! 时改动面收敛到单个文件。
//!
//! # 字段名就是线上 JSON 的 key
//!
//! 契约里写的是线上 key（不是 Rust 字段名），例如 `IcmpTypeEntry.type` 在 Rust 侧
//! 是 `r#type`。本文件只放**路由自身**拥有的形状；与外部 owner 共享的（`ChartData`、
//! `RuntimeSnapshot`、`WebuiConfigResponse`）放在 [`super::ports`]，避免两处定义。

use serde::{Deserialize, Serialize};

use super::ports::{ChartData, RuntimeView, WebuiConfigView};

// ============================================================================
// 请求
// ============================================================================

/// `GET /api/v1/bans` 的分页与排序参数。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PaginationParams {
    /// 页码，从 1 开始；缺省为 1。
    pub page: Option<u32>,
    /// 每页条数，最大 100；缺省为 20。
    pub page_size: Option<u32>,
    /// 排序字段，缺省 `banned_at_desc`。
    pub sort_by: Option<String>,
}

/// `POST /api/v1/bans` 的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateBanRequest {
    /// 目标 IP。
    pub ip: String,
    /// 封禁时长（秒）；缺省用 jail 配置。`0` 表示永久。
    pub duration: Option<u64>,
    /// 封禁原因；缺省为手工封禁。
    pub reason: Option<String>,
}

/// `POST /api/v1/whitelist` 的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateWhitelistRequest {
    /// CIDR（文本形式，允许裸地址）。
    pub cidr: String,
}

// ============================================================================
// 运行时
// ============================================================================

/// `/health` 与 `/healthz` 的载荷别名。
///
/// 与 [`RuntimeView`] 是同一个类型：契约里叫 `RuntimeSnapshot`，实现里叫
/// `RuntimeView`。旧实现两处各写一份，字段一旦增删就会漂移。
pub type RuntimeSnapshot = RuntimeView;

// ============================================================================
// 统计
// ============================================================================

/// 威胁等级（契约 `ThreatLevel`）。
#[derive(Debug, Clone, Serialize)]
pub struct ThreatLevel {
    /// 等级标签：`safe` / `low` / `medium` / `high` / `critical`。
    pub level: String,
    /// 0–4 的评分。
    pub score: u8,
    /// 触发该等级的因素（人类可读）。至少一条。
    pub factors: Vec<String>,
    /// 短期窗口内的全局 pps。
    pub current_pps: u64,
    /// pps 与警告阈值的比率。
    pub pps_ratio: f64,
    /// 封禁表使用率（相对内核哈希桶数）。
    pub ban_table_usage: f64,
    /// 最近 5 分钟内的封禁数。
    pub recent_bans: u64,
    /// 基线是否已冻结。
    pub baseline_frozen: bool,
    /// 是否处于业务高峰期。
    pub peak_hours: bool,
}

/// `GET /api/v1/stats` 的载荷。
#[derive(Debug, Clone, Serialize)]
pub struct StatsResponse {
    /// 守护进程版本。
    pub daemon_version: String,
    /// 内核模块版本。
    pub kernel_version: String,
    /// 今日封禁数。
    pub today_bans: u64,
    /// 累计失败尝试数。
    pub failed_attempts: u64,
    /// 累计 DDoS 事件数。
    pub ddos_events: u64,
    /// 运行秒数。
    pub uptime_seconds: u64,
    /// 封禁次数趋势。
    pub ban_trend: ChartData,
    /// 按 jail 的封禁分布。
    pub jail_distribution: ChartData,
    /// 按原因的封禁分布。
    pub failure_reasons: ChartData,
    /// 失败尝试趋势。
    pub failed_attempts_trend: ChartData,
    /// 当前活跃封禁数。
    pub current_bans: u64,
    /// 累计封禁数。
    pub total_bans: u64,
    /// 累计解封数。
    pub total_unbans: u64,
    /// 白名单条目数。
    pub whitelist_count: u64,
    /// 内核丢弃包数（近似值）。
    pub packets_dropped: u64,
    /// 内核接受包数（近似值）。
    pub packets_accepted: u64,
    /// 威胁等级。
    pub threat_level: ThreatLevel,
}

// ============================================================================
// 封禁
// ============================================================================

/// 封禁列表里的一条。
#[derive(Debug, Clone, Serialize)]
pub struct BanResponse {
    /// IP。
    pub ip: String,
    /// 归属 jail。
    pub jail: String,
    /// 封禁时间（Unix 秒）。
    pub banned_at: i64,
    /// 剩余秒数；永久封禁为 `-1`。
    pub remaining_seconds: i64,
    /// 封禁原因。
    pub reason: String,
    /// 累计封禁次数。
    pub ban_count: u32,
    /// 是否永久封禁。
    pub is_permanent: bool,
}

/// 单条封禁的详情。
#[derive(Debug, Clone, Serialize)]
pub struct BanDetailResponse {
    /// IP。
    pub ip: String,
    /// 当前是否被封禁（可能已过期但条目尚在）。
    pub is_banned: bool,
    /// Jail 名称；未封禁时为空串。
    pub jail_name: String,
    /// 封禁原因。
    pub reason: String,
    /// 封禁时间（Unix 秒）。
    pub banned_at: i64,
    /// 过期时间（Unix 秒）；`0` 表示永久。
    pub expires_at: i64,
    /// 是否永久封禁。
    pub is_permanent: bool,
    /// 触发封禁前的失败次数。
    pub fail_count: u32,
    /// 累计封禁次数。
    pub ban_count: u32,
    /// 上次解封时间（Unix 秒）；`0` 表示当前仍在封禁中。
    pub last_unbanned_at: i64,
    /// 是否曾被永久封禁。
    pub was_permanent: bool,
    /// 渐进式封禁等级说明。
    pub progressive_level: String,
    /// 下次封禁时长（人类可读，如 `1800 秒` / `永久封禁`）。
    pub next_ban_duration: String,
    /// IP 信誉分（0–100，100 = 完全信任）。
    pub reputation_score: u32,
    /// 信誉阈值乘数（0.5 / 0.8 / 1.0）。
    pub reputation_multiplier: f64,
}

/// 单条封禁/解封操作的结果。
#[derive(Debug, Clone, Serialize)]
pub struct BanOperationResponse {
    /// IP。
    pub ip: String,
    /// `ban` 或 `unban`。
    pub action: String,
    /// 是否永久。
    pub permanent: bool,
    /// 时长（秒）；永久或解封时为 `None`。
    pub duration_seconds: Option<u64>,
}

/// 批量操作的结果。
#[derive(Debug, Clone, Serialize)]
pub struct BatchOperationResponse {
    /// 本次请求涉及的条目总数。
    pub total: u64,
    /// 成功数。
    pub succeeded: u64,
    /// 失败数。
    pub failed_count: u64,
    /// 逐条失败原因。
    pub details: Vec<String>,
}

// ============================================================================
// Jail 与配置
// ============================================================================

/// 一个 Jail 的线上形状（配置面 + 运行期计数）。
#[derive(Debug, Clone, Serialize)]
pub struct JailResponse {
    /// 名称。
    pub name: String,
    /// 是否启用。
    pub enabled: bool,
    /// 当前该 jail 名下的封禁数（来自 `state`）。
    pub ban_count: usize,
    /// 配置的失败阈值。
    pub max_retries: u32,
    /// 当前有效阈值。
    pub effective_max_retries: u32,
    /// 滑动窗口（秒）。
    pub findtime: u32,
    /// 封禁时长（秒）；负值表示永久。
    pub ban_time: i32,
    /// 是否处于业务高峰期。
    pub is_peak_hours: bool,
    /// 高峰期阈值放宽倍数。
    pub peak_hours_multiplier: f64,
    /// 内网 IP 阈值放宽倍数。
    pub internal_ip_multiplier: f64,
    /// per-Jail 统计：已解析行数。
    pub lines_parsed: u64,
    /// per-Jail 统计：正则匹配次数。
    pub regex_matches: u64,
    /// per-Jail 统计：提取的 IP 数。
    pub ips_extracted: u64,
    /// per-Jail 统计：失败尝试次数。
    pub failed_attempts: u64,
    /// per-Jail 统计：触发的封禁数。
    pub bans_triggered: u64,
}

/// `PUT /api/v1/jails/:name` 的请求体。
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateJailRequest {
    /// 是否启用。
    pub enabled: bool,
}

/// `GET /api/v1/config` 的载荷别名。
pub type WebuiConfigResponse = WebuiConfigView;

/// `PUT /api/v1/config` 的请求体别名。
pub type UpdateConfigRequest = super::ports::WebuiConfigPatch;

// ============================================================================
// 白名单
// ============================================================================

/// 白名单里的一条。
#[derive(Debug, Clone, Serialize)]
pub struct WhitelistEntryResponse {
    /// 规范化后的 CIDR（主机位已清零，且恒带 `/prefix`）。
    pub cidr: String,
    /// 限定设备；空串表示不限定。
    pub device: String,
}

/// 白名单增删的结果。
#[derive(Debug, Clone, Serialize)]
pub struct WhitelistOperationResponse {
    /// 规范化后的 CIDR。
    pub cidr: String,
    /// `add` 或 `remove`。
    pub action: String,
}

/// 一条白名单推荐。
#[derive(Debug, Clone, Serialize)]
pub struct WhitelistRecommendation {
    /// 推荐类型。
    pub rec_type: String,
    /// 建议加入白名单的 CIDR。
    pub cidr: String,
    /// 推荐理由（人类可读）。
    pub reason: String,
    /// 受影响的 IP 数。
    pub affected_ips: u32,
    /// 涉及的历史封禁总数。
    pub total_bans: u32,
    /// 置信度（0–100）。
    pub confidence: u8,
}

// ============================================================================
// 速率
// ============================================================================

/// 单个 IP 的速率。
#[derive(Debug, Clone, Serialize)]
pub struct RateResponse {
    /// IP。
    pub ip: String,
    /// 包/秒。
    pub packets_per_sec: u64,
    /// 字节/秒。
    pub bytes_per_sec: u64,
    /// SYN 包/秒。
    pub syn_packets_per_sec: u64,
    /// UDP 包/秒。
    pub udp_packets_per_sec: u64,
    /// ICMP 包/秒。
    pub icmp_packets_per_sec: u64,
    /// ACK 包/秒。
    pub ack_packets_per_sec: u64,
    /// RST 包/秒。
    pub rst_packets_per_sec: u64,
    /// FIN 包/秒。
    pub fin_packets_per_sec: u64,
}

// ============================================================================
// SSE 诊断
// ============================================================================

/// 一条 SSE 流的连接状态。
///
/// 两条流各自独立计数，`limit_reached` 必须由**所属流**的上限判定——旧实现用
/// 单条流的上限推断另一条，缺陷 `HTTP_SSE_STATUS_INCOMPLETE`。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SseStreamStatus {
    /// 当前连接数。
    pub current_connections: usize,
    /// 该流的上限。
    pub max_connections: usize,
    /// 是否已达上限。
    pub limit_reached: bool,
}

impl SseStreamStatus {
    /// 由当前连接数与上限构造。
    #[must_use]
    pub const fn new(current_connections: usize, max_connections: usize) -> Self {
        Self {
            current_connections,
            max_connections,
            limit_reached: current_connections >= max_connections,
        }
    }
}

/// `/api/v1/stats/sse-status` 的载荷：两条流各自的连接状态。
#[derive(Debug, Clone, Copy, Serialize)]
pub struct SseStatusResponse {
    /// `/api/v1/events` 流。
    pub events: SseStreamStatus,
    /// `/api/v1/logs/stream` 流。
    pub logs: SseStreamStatus,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ban_response_serializes_with_the_contract_keys() {
        let ban = BanResponse {
            ip: "10.0.0.1".to_string(),
            jail: "sshd".to_string(),
            banned_at: 100,
            remaining_seconds: -1,
            reason: "r".to_string(),
            ban_count: 2,
            is_permanent: true,
        };
        let json = serde_json::to_value(&ban).expect("可序列化");
        assert_eq!(json["ip"], "10.0.0.1");
        assert_eq!(json["remaining_seconds"], -1);
        assert_eq!(json["is_permanent"], true);
    }

    #[test]
    fn a_permanent_ban_has_no_duration_in_the_operation_response() {
        let op = BanOperationResponse {
            ip: "10.0.0.1".to_string(),
            action: "ban".to_string(),
            permanent: true,
            duration_seconds: None,
        };
        let json = serde_json::to_value(&op).expect("可序列化");
        assert!(json["duration_seconds"].is_null());
    }

    #[test]
    fn a_pagination_request_tolerates_absent_fields() {
        let params: PaginationParams = serde_json::from_str("{}").expect("可反序列化");
        assert!(params.page.is_none());
        assert!(params.page_size.is_none());
        assert!(params.sort_by.is_none());
    }

    #[test]
    fn a_whitelist_operation_reports_the_normalized_cidr() {
        let op = WhitelistOperationResponse {
            cidr: "10.0.0.0/24".to_string(),
            action: "add".to_string(),
        };
        let json = serde_json::to_value(&op).expect("可序列化");
        assert_eq!(json["cidr"], "10.0.0.0/24");
        assert_eq!(json["action"], "add");
    }

    #[test]
    fn a_rate_response_carries_every_protocol_counter() {
        let rate = RateResponse {
            ip: "10.0.0.1".to_string(),
            packets_per_sec: 1,
            bytes_per_sec: 2,
            syn_packets_per_sec: 3,
            udp_packets_per_sec: 4,
            icmp_packets_per_sec: 5,
            ack_packets_per_sec: 6,
            rst_packets_per_sec: 7,
            fin_packets_per_sec: 8,
        };
        let json = serde_json::to_value(&rate).expect("可序列化");
        for key in [
            "packets_per_sec",
            "bytes_per_sec",
            "syn_packets_per_sec",
            "udp_packets_per_sec",
            "icmp_packets_per_sec",
            "ack_packets_per_sec",
            "rst_packets_per_sec",
            "fin_packets_per_sec",
        ] {
            assert!(json.get(key).is_some(), "{key} 必须存在");
        }
    }

    #[test]
    fn an_sse_stream_status_derives_limit_reached_from_its_own_max() {
        let ok = SseStreamStatus::new(3, 10);
        assert!(!ok.limit_reached);
        let full = SseStreamStatus::new(10, 10);
        assert!(full.limit_reached, "达到上限应置位");
        let over = SseStreamStatus::new(11, 10);
        assert!(over.limit_reached, "超过上限同样视为已达上限");
    }

    #[test]
    fn the_sse_status_reports_both_streams_independently() {
        // 缺陷 HTTP_SSE_STATUS_INCOMPLETE 的修法：两条流各自的上限与当前值。
        let status = SseStatusResponse {
            events: SseStreamStatus::new(3, 10),
            logs: SseStreamStatus::new(5, 5),
        };
        let json = serde_json::to_value(status).expect("可序列化");
        assert_eq!(json["events"]["max_connections"], 10);
        assert_eq!(json["events"]["limit_reached"], false);
        assert_eq!(json["logs"]["max_connections"], 5);
        assert_eq!(
            json["logs"]["limit_reached"], true,
            "日志流满时不得因另一条流未满而误报未满"
        );
    }

    #[test]
    fn a_threat_level_always_carries_at_least_one_factor() {
        let level = ThreatLevel {
            level: "safe".to_string(),
            score: 0,
            factors: vec!["一切正常".to_string()],
            current_pps: 0,
            pps_ratio: 0.0,
            ban_table_usage: 0.0,
            recent_bans: 0,
            baseline_frozen: false,
            peak_hours: false,
        };
        let json = serde_json::to_value(&level).expect("可序列化");
        assert_eq!(json["factors"].as_array().expect("数组").len(), 1);
        assert_eq!(json["level"], "safe");
    }
}
