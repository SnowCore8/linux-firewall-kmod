//! API 客户端 — 类型定义 + fetch 调用

use serde::{Deserialize, Serialize};

/// URL 路径段编码（CIDR `/` → `%2F`，IPv6 `:` → `%3A`，防止破坏路由）
fn encode_path_segment(s: &str) -> String {
    s.replace('/', "%2F").replace(':', "%3A")
}

// ============================================================================
// 响应类型
// ============================================================================

#[derive(Deserialize, Clone)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub data: T,
    pub message: String,
}

#[derive(Deserialize, Clone, Default, Serialize)]
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
    pub current_bans: u64,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub whitelist_count: u64,
    pub packets_dropped: u64,
    pub packets_accepted: u64,
    pub threat_level: Option<ThreatLevel>,
}

/// 威胁等级评估
#[derive(Deserialize, Clone, Default, Serialize)]
pub struct ThreatLevel {
    pub level: String,
    pub score: u8,
    pub factors: Vec<String>,
    pub current_pps: u64,
    pub pps_ratio: f64,
    pub ban_table_usage: f64,
    pub recent_bans: u64,
    pub baseline_frozen: bool,
    pub peak_hours: bool,
}

#[derive(Deserialize, Clone, Default, Serialize)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub values: Vec<u64>,
}

#[derive(Deserialize, Clone, Serialize, PartialEq)]
pub struct BanResponse {
    pub ip: String,
    pub jail: String,
    pub banned_at: i64,
    pub remaining_seconds: i64,
    pub reason: String,
    /// 该 IP 累计被封禁次数（渐进式封禁）
    pub ban_count: u32,
    /// 是否永久封禁
    pub is_permanent: bool,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct JailResponse {
    pub name: String,
    pub enabled: bool,
    pub ban_count: usize,
    /// 配置的失败次数阈值
    pub max_retries: u32,
    /// 当前有效阈值（业务高峰期可能放宽）
    pub effective_max_retries: u32,
    /// 滑动窗口大小（秒）
    pub findtime: u32,
    /// 封禁时长（秒），-1 表示永久
    pub ban_time: i32,
    /// 是否处于业务高峰期（9-18 点 UTC）
    pub is_peak_hours: bool,
    /// 高峰期阈值放宽倍数
    pub peak_hours_multiplier: f64,
    /// 内网 IP 阈值放宽倍数
    pub internal_ip_multiplier: f64,
    /// per-Jail 统计：已解析日志行数
    pub lines_parsed: u64,
    /// per-Jail 统计：正则匹配次数
    pub regex_matches: u64,
    /// per-Jail 统计：提取的 IP 数
    pub ips_extracted: u64,
    /// per-Jail 统计：失败尝试次数
    pub failed_attempts: u64,
    /// per-Jail 统计：触发的封禁数
    pub bans_triggered: u64,
}

#[derive(Deserialize, Clone, Serialize)]
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

#[derive(Deserialize, Clone, Serialize)]
pub struct RateHistoryEntry {
    pub timestamp: u64,
    pub total_pps: u64,
    pub total_bps: u64,
    pub tracked_ips: u32,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct WhitelistEntry {
    pub cidr: String,
    pub device: String,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct WebuiConfig {
    pub sse_push_interval: u32,
    pub rate_warning_pps: u64,
    pub rate_critical_pps: u64,
    pub rate_warning_syn: u64,
    pub rate_critical_syn: u64,
    // 协议专项阈值（同步到内核模块）
    pub max_syn_per_second: u32,
    pub max_udp_per_second: u32,
    pub max_icmp_per_second: u32,
    pub max_ack_per_second: u32,
    pub max_rst_per_second: u32,
    pub max_fin_per_second: u32,
    // DDoS 检测算法开关
    pub static_threshold: bool,
    pub dynamic_threshold: bool,
    pub ddos_detection: bool,
    // 容量配置（用户自定义上限）
    pub max_ban_entries: u32,
    pub max_whitelist_entries: u32,
    pub max_rate_entries: u32,
    pub max_local_ip_cache: u32,
}

#[derive(Serialize)]
pub struct UpdateConfigRequest {
    pub sse_push_interval: Option<u32>,
    pub rate_warning_pps: Option<u64>,
    pub rate_critical_pps: Option<u64>,
    pub rate_warning_syn: Option<u64>,
    pub rate_critical_syn: Option<u64>,
    // 协议专项阈值
    pub max_syn_per_second: Option<u32>,
    pub max_udp_per_second: Option<u32>,
    pub max_icmp_per_second: Option<u32>,
    pub max_ack_per_second: Option<u32>,
    pub max_rst_per_second: Option<u32>,
    pub max_fin_per_second: Option<u32>,
    // DDoS 检测算法开关
    pub static_threshold: Option<bool>,
    pub dynamic_threshold: Option<bool>,
    pub ddos_detection: Option<bool>,
    // 容量配置
    pub max_ban_entries: Option<u32>,
    pub max_whitelist_entries: Option<u32>,
    pub max_rate_entries: Option<u32>,
    pub max_local_ip_cache: Option<u32>,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct PaginatedResponse<T: Serialize> {
    pub items: Vec<T>,
    pub total: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct BanOperationResponse {
    pub ip: String,
    pub action: String,
    pub permanent: bool,
    pub duration_seconds: Option<u64>,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct WhitelistOperationResponse {
    pub cidr: String,
    pub action: String,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct LogEntry {
    pub line_number: u64,
    pub content: String,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct LogPageResponse {
    pub items: Vec<LogEntry>,
    pub total_lines: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

// ============================================================================
// 请求类型
// ============================================================================

#[derive(Serialize)]
pub struct CreateBanRequest {
    pub ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Serialize)]
pub struct CreateWhitelistRequest {
    pub cidr: String,
}

// ============================================================================
// API 调用函数
// ============================================================================

/// 从非 2xx 响应中提取后端错误消息
async fn extract_error_message(resp: gloo_net::http::Response) -> String {
    let status = resp.status();
    if let Ok(text) = resp.text().await {
        if let Ok(api_resp) = serde_json::from_str::<ApiResponse<serde_json::Value>>(&text) {
            if !api_resp.message.is_empty() {
                return api_resp.message;
            }
        }
    }
    format!("HTTP {status}")
}

async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let resp = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(extract_error_message(resp).await);
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let api_resp: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if api_resp.code != 0 {
        return Err(api_resp.message);
    }
    Ok(api_resp.data)
}

async fn post_json<B: Serialize, T: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, String> {
    let resp = gloo_net::http::Request::post(url)
        .json(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(extract_error_message(resp).await);
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let api_resp: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if api_resp.code != 0 {
        return Err(api_resp.message);
    }
    Ok(api_resp.data)
}

async fn delete_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let resp = gloo_net::http::Request::delete(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(extract_error_message(resp).await);
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let api_resp: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if api_resp.code != 0 {
        return Err(api_resp.message);
    }
    Ok(api_resp.data)
}

async fn put_json<B: Serialize, T: serde::de::DeserializeOwned>(
    url: &str,
    body: &B,
) -> Result<T, String> {
    let resp = gloo_net::http::Request::put(url)
        .json(body)
        .map_err(|e| e.to_string())?
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(extract_error_message(resp).await);
    }
    let text = resp.text().await.map_err(|e| e.to_string())?;
    let api_resp: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    if api_resp.code != 0 {
        return Err(api_resp.message);
    }
    Ok(api_resp.data)
}

// ============================================================================
// 公共 API
// ============================================================================

/// 获取统计数据（SSE 推送替代，保留为手动刷新 fallback）
#[allow(dead_code)]
pub async fn get_stats() -> Result<StatsResponse, String> {
    get_json("/api/v1/stats").await
}

/// 分页获取封禁列表（前端使用客户端分页替代，保留为服务端分页 fallback）
#[allow(dead_code)]
pub async fn get_bans(
    page: u32,
    page_size: u32,
    sort_by: Option<&str>,
) -> Result<PaginatedResponse<BanResponse>, String> {
    let mut url = format!("/api/v1/bans?page={page}&page_size={page_size}");
    if let Some(s) = sort_by {
        url.push_str(&format!("&sort_by={s}"));
    }
    get_json(&url).await
}

/// 获取全量封禁列表（SSE 推送替代，保留为手动刷新 fallback）
#[allow(dead_code)]
pub async fn get_all_bans() -> Result<Vec<BanResponse>, String> {
    get_json("/api/v1/bans").await
}

pub async fn create_ban(
    ip: &str,
    duration: Option<u64>,
    reason: Option<&str>,
) -> Result<BanOperationResponse, String> {
    let req = CreateBanRequest {
        ip: ip.to_string(),
        duration,
        reason: reason.map(String::from),
    };
    post_json("/api/v1/bans", &req).await
}

pub async fn delete_ban(ip: &str) -> Result<BanOperationResponse, String> {
    delete_json(&format!("/api/v1/bans/{}", encode_path_segment(ip))).await
}

pub async fn get_jails() -> Result<Vec<JailResponse>, String> {
    get_json("/api/v1/jails").await
}

#[derive(Serialize)]
pub struct UpdateJailRequest {
    pub enabled: bool,
}

pub async fn update_jail(name: &str, enabled: bool) -> Result<JailResponse, String> {
    let req = UpdateJailRequest { enabled };
    put_json(&format!("/api/v1/jails/{name}"), &req).await
}

/// 获取白名单列表（SSE 推送替代，保留为手动刷新 fallback）
#[allow(dead_code)]
pub async fn get_whitelist() -> Result<Vec<WhitelistEntry>, String> {
    get_json("/api/v1/whitelist").await
}

pub async fn create_whitelist(cidr: &str) -> Result<WhitelistOperationResponse, String> {
    let req = CreateWhitelistRequest {
        cidr: cidr.to_string(),
    };
    post_json("/api/v1/whitelist", &req).await
}

pub async fn delete_whitelist(cidr: &str) -> Result<WhitelistOperationResponse, String> {
    delete_json(&format!("/api/v1/whitelist/{}", encode_path_segment(cidr))).await
}

/// 获取当前 DDoS 速率（SSE 推送替代，保留为手动刷新 fallback）
#[allow(dead_code)]
pub async fn get_rates_current() -> Result<Vec<RateResponse>, String> {
    get_json("/api/v1/rates/current").await
}

/// 获取速率历史（SSE 推送替代，保留为手动刷新 fallback）
#[allow(dead_code)]
pub async fn get_rates_history() -> Result<Vec<RateHistoryEntry>, String> {
    get_json("/api/v1/rates/history").await
}

/// 多窗口速率快照（短期/中期/长期 EWMA）
#[derive(Deserialize, Clone, Serialize)]
pub struct RateWindowSnapshot {
    /// 短期窗口 PPS（~5s，突发洪水）
    pub pps_short: u64,
    /// 中期窗口 PPS（~60s，持续攻击）
    pub pps_mid: u64,
    /// 长期窗口 PPS（~300s，慢速攻击）
    pub pps_long: u64,
    /// 短期窗口 BPS
    pub bps_short: u64,
    /// 中期窗口 BPS
    pub bps_mid: u64,
    /// 长期窗口 BPS
    pub bps_long: u64,
}

pub async fn get_rate_windows() -> Result<RateWindowSnapshot, String> {
    get_json("/api/v1/rates/windows").await
}

/// 单个时段的聚合数据（24 小时热力图）
#[derive(Deserialize, Clone, Serialize)]
pub struct HourlyBucket {
    pub hour: u32,
    pub bans: u64,
    pub failed_attempts: u64,
    pub ddos_events: u64,
}

/// 24 小时攻击热力图数据
#[derive(Deserialize, Clone, Serialize)]
pub struct HourlyHeatmap {
    pub hours: Vec<HourlyBucket>,
}

pub async fn get_heatmap() -> Result<HourlyHeatmap, String> {
    get_json("/api/v1/stats/heatmap").await
}

/// 封禁效果追踪 — 复发率统计
#[derive(Deserialize, Clone, Serialize)]
pub struct RecidivismResponse {
    pub total_ips: u64,
    pub recidivist_ips: u64,
    pub recidivism_rate: f64,
    pub permanent_bans: u64,
    pub top_recidivists: Vec<RecidivistEntry>,
}

/// 单个复发 IP 的信息
#[derive(Deserialize, Clone, Serialize)]
pub struct RecidivistEntry {
    pub ip: String,
    pub ban_count: u32,
    pub last_banned_at: i64,
    pub was_permanent: bool,
}

pub async fn get_recidivism() -> Result<RecidivismResponse, String> {
    get_json("/api/v1/stats/recidivism").await
}

/// 封禁详情响应
#[derive(Deserialize, Clone, Serialize)]
pub struct BanDetailResponse {
    pub ip: String,
    pub is_banned: bool,
    pub jail_name: String,
    pub reason: String,
    pub banned_at: i64,
    pub expires_at: i64,
    pub is_permanent: bool,
    pub fail_count: u32,
    pub ban_count: u32,
    pub last_unbanned_at: i64,
    pub was_permanent: bool,
    pub progressive_level: String,
    pub next_ban_duration: String,
    /// IP 信誉分（0-100）
    pub reputation_score: u32,
    /// 信誉阈值乘数（0.5/0.8/1.0）
    pub reputation_multiplier: f64,
}

/// 获取封禁详情
pub async fn get_ban_detail(ip: &str) -> Result<BanDetailResponse, String> {
    get_json(&format!("/api/v1/bans/{}/detail", encode_path_segment(ip))).await
}

/// 批量操作响应
#[derive(Deserialize, Clone, Serialize)]
pub struct BatchOperationResponse {
    pub total: u64,
    pub succeeded: u64,
    pub failed_count: u64,
    pub details: Vec<String>,
}

/// 批量解封所有临时封禁
pub async fn unban_all_temporary() -> Result<BatchOperationResponse, String> {
    post_json("/api/v1/bans/unban-temporary", &()).await
}

/// 批量封禁多个 IP
pub async fn batch_ban(ips: Vec<String>) -> Result<BatchOperationResponse, String> {
    post_json("/api/v1/bans/batch", &ips).await
}

pub async fn get_config() -> Result<WebuiConfig, String> {
    get_json("/api/v1/config").await
}

pub async fn update_config(req: UpdateConfigRequest) -> Result<WebuiConfig, String> {
    put_json("/api/v1/config", &req).await
}

pub async fn get_logs(page: u32, page_size: u32) -> Result<LogPageResponse, String> {
    get_json(&format!("/api/v1/logs?page={page}&page_size={page_size}")).await
}

/// 智能白名单推荐条目
#[derive(Deserialize, Clone, Serialize)]
pub struct WhitelistRecommendation {
    pub rec_type: String,
    pub cidr: String,
    pub reason: String,
    pub affected_ips: u32,
    pub total_bans: u32,
    pub confidence: u8,
}

/// 获取智能白名单推荐
pub async fn get_whitelist_recommendations() -> Result<Vec<WhitelistRecommendation>, String> {
    get_json("/api/v1/whitelist/recommendations").await
}

/// 单个封禁级别的效果数据
#[derive(Deserialize, Clone, Serialize)]
pub struct BanLevelEffectiveness {
    pub level: u8,
    pub label: String,
    pub total_ips: u32,
    pub recidivist_ips: u32,
    pub recidivism_rate: f64,
    pub permanent_bans: u32,
    pub verdict: String,
}

/// 封禁效果分析响应
#[derive(Deserialize, Clone, Serialize)]
pub struct BanEffectivenessResponse {
    pub levels: Vec<BanLevelEffectiveness>,
    pub total_unique_ips: u32,
    pub overall_recidivism_rate: f64,
    pub summary: String,
}

/// 获取封禁效果分析
pub async fn get_ban_effectiveness() -> Result<BanEffectivenessResponse, String> {
    get_json("/api/v1/stats/ban-effectiveness").await
}

/// 周期性攻击者检测结果
#[derive(Deserialize, Clone, Serialize)]
pub struct PeriodicAttacker {
    pub ip: String,
    pub ban_count: u32,
    pub avg_interval_secs: f64,
    pub interval_stddev: f64,
    pub periodicity_score: u8,
    pub jail_name: String,
    pub timestamps: Vec<i64>,
}

/// 协同攻击检测结果
#[derive(Deserialize, Clone, Serialize)]
pub struct CollaborativeAttack {
    pub jail_name: String,
    pub window_start: i64,
    pub window_end: i64,
    pub ip_count: u32,
    pub ips: Vec<String>,
    pub total_bans: u32,
    pub correlation_score: u8,
}

/// 获取协同攻击检测
pub async fn get_collaborative_attacks() -> Result<Vec<CollaborativeAttack>, String> {
    get_json("/api/v1/stats/collaborative-attacks").await
}

/// 获取周期性攻击者检测
pub async fn get_periodic_attackers() -> Result<Vec<PeriodicAttacker>, String> {
    get_json("/api/v1/stats/periodic-attackers").await
}

/// UDP 端口分布条目
#[derive(Deserialize, Clone, Serialize)]
pub struct UdpPortEntry {
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// UDP 端口分布响应
#[derive(Deserialize, Clone, Serialize)]
pub struct UdpPortDistributionResponse {
    pub ports: Vec<UdpPortEntry>,
    pub total_entries: usize,
    pub max_entries: usize,
}

/// 获取 UDP 端口分布统计
pub async fn get_udp_port_distribution() -> Result<UdpPortDistributionResponse, String> {
    get_json("/api/v1/stats/udp-ports").await
}

/// ICMP 类型分布条目
#[derive(Deserialize, Clone, Serialize)]
pub struct IcmpTypeEntry {
    pub r#type: u8,
    pub code: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// ICMP 类型分布响应
#[derive(Deserialize, Clone, Serialize)]
pub struct IcmpTypeDistributionResponse {
    pub types: Vec<IcmpTypeEntry>,
    pub total_entries: usize,
    pub max_entries: usize,
}

/// 获取 ICMP 类型分布统计
pub async fn get_icmp_type_distribution() -> Result<IcmpTypeDistributionResponse, String> {
    get_json("/api/v1/stats/icmp-types").await
}

/// SSE 连接状态信息
#[derive(Deserialize, Clone, Serialize)]
pub struct SseStatusInfo {
    pub current_connections: usize,
    pub max_connections: usize,
    pub limit_reached: bool,
}

/// 获取 SSE 连接状态
pub async fn get_sse_status() -> Result<SseStatusInfo, String> {
    get_json("/api/v1/stats/sse-status").await
}

/// 封禁时长分布直方图
#[derive(Deserialize, Clone, Serialize)]
pub struct BanDurationHistogramResponse {
    pub labels: Vec<String>,
    pub counts: Vec<u64>,
    pub total: u64,
}

/// 获取封禁时长分布直方图
pub async fn get_ban_duration_histogram() -> Result<BanDurationHistogramResponse, String> {
    get_json("/api/v1/stats/ban-duration-histogram").await
}

/// 包大小分布响应
#[derive(Deserialize, Clone, Serialize)]
pub struct PacketSizeDistributionResponse {
    pub labels: Vec<String>,
    pub counts: Vec<u64>,
    pub total: u64,
    pub percentages: Vec<f64>,
}

/// 获取包大小分布直方图
pub async fn get_packet_size_distribution() -> Result<PacketSizeDistributionResponse, String> {
    get_json("/api/v1/stats/packet-sizes").await
}

/// TTL 分布响应
#[derive(Deserialize, Clone, Serialize)]
pub struct TtlDistributionResponse {
    pub labels: Vec<String>,
    pub counts: Vec<u64>,
    pub total: u64,
    pub percentages: Vec<f64>,
}

/// 获取 TTL 分布直方图
pub async fn get_ttl_distribution() -> Result<TtlDistributionResponse, String> {
    get_json("/api/v1/stats/ttl-distribution").await
}

/// IP 分片统计响应
#[derive(Deserialize, Clone, Serialize)]
pub struct IpFragmentStatsResponse {
    pub total_packets: u64,
    pub fragment_packets: u64,
    pub fragment_ratio: f64,
}

/// 获取 IP 分片统计
pub async fn get_ip_fragment_stats() -> Result<IpFragmentStatsResponse, String> {
    get_json("/api/v1/stats/ip-fragments").await
}

/// 端口扫描者条目
#[derive(Deserialize, Clone, Serialize)]
pub struct PortScannerEntry {
    pub ip: String,
    pub unique_ports: u32,
    pub packets: u64,
}

/// 端口扫描检测响应
#[derive(Deserialize, Clone, Serialize)]
pub struct PortScanResponse {
    pub threshold: u32,
    pub total_detected: u32,
    pub scanners: Vec<PortScannerEntry>,
}

/// 获取端口扫描检测结果
pub async fn get_port_scan_detection() -> Result<PortScanResponse, String> {
    get_json("/api/v1/stats/port-scanners").await
}

/// 服务探测者条目
#[derive(Deserialize, Clone, Serialize)]
pub struct ServiceProbeEntry {
    pub ip: String,
    pub protocol_count: u32,
    pub packets: u64,
}

/// 服务探测检测响应
#[derive(Deserialize, Clone, Serialize)]
pub struct ServiceProbeResponse {
    pub threshold: u32,
    pub probes: Vec<ServiceProbeEntry>,
}

/// 获取服务探测检测结果
pub async fn get_service_probe_detection() -> Result<ServiceProbeResponse, String> {
    get_json("/api/v1/stats/service-probes").await
}

/// 封禁时长推荐条目
#[derive(Deserialize, Clone, Serialize)]
pub struct BanDurationRecommendation {
    pub jail_name: String,
    pub current_ban_time: i32,
    pub recidivist_count: u32,
    pub median_return_secs: u64,
    pub recommended_ban_time: u64,
    pub reason: String,
    pub needs_adjustment: bool,
}

/// 封禁时长推荐响应
#[derive(Deserialize, Clone, Serialize)]
pub struct BanDurationRecommendationResponse {
    pub recommendations: Vec<BanDurationRecommendation>,
    pub summary: String,
}

/// 获取封禁时长推荐
pub async fn get_ban_duration_recommendations() -> Result<BanDurationRecommendationResponse, String>
{
    get_json("/api/v1/stats/ban-duration-recommendations").await
}

/// IP 信誉分条目
#[derive(Deserialize, Clone, Serialize)]
pub struct ReputationEntry {
    pub ip: String,
    pub score: u32,
    pub last_failure_at: i64,
    pub total_failures: u32,
    pub total_bans: u32,
    pub threshold_multiplier: f64,
}

/// 获取 IP 信誉分列表
pub async fn get_reputation() -> Result<Vec<ReputationEntry>, String> {
    get_json("/api/v1/stats/reputation").await
}

/// 阈值调优建议条目
#[derive(Deserialize, Clone, Serialize)]
pub struct ThresholdRecommendation {
    pub jail_name: String,
    pub current_threshold: u32,
    pub recommended_threshold: u32,
    pub direction: String,
    pub total_bans: u32,
    pub unique_ips: u32,
    pub recidivist_ips: u32,
    pub recidivism_rate: f64,
    pub avg_bans_per_ip: f64,
    pub reason: String,
    pub confidence: u8,
}

/// 阈值调优建议响应
#[derive(Deserialize, Clone, Serialize)]
pub struct ThresholdRecommendationResponse {
    pub recommendations: Vec<ThresholdRecommendation>,
    pub summary: String,
}

/// 获取阈值调优建议
pub async fn get_threshold_recommendations() -> Result<ThresholdRecommendationResponse, String> {
    get_json("/api/v1/stats/threshold-recommendations").await
}

/// 攻击源网络分布条目
#[derive(Deserialize, Clone, Serialize)]
pub struct NetworkBlock {
    pub subnet: String,
    pub unique_ips: u32,
    pub total_bans: u32,
    pub last_banned_at: i64,
    pub top_ip: String,
}

/// 获取攻击源网络分布
pub async fn get_network_distribution() -> Result<Vec<NetworkBlock>, String> {
    get_json("/api/v1/stats/network-distribution").await
}
