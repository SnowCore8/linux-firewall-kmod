//! API 客户端 — 类型定义 + fetch 调用
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

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
}

#[derive(Deserialize, Clone, Default, Serialize)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub values: Vec<u64>,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct BanResponse {
    pub ip: String,
    pub jail: String,
    pub banned_at: i64,
    pub remaining_seconds: i64,
    pub reason: String,
}

#[derive(Deserialize, Clone, Serialize)]
pub struct JailResponse {
    pub name: String,
    pub enabled: bool,
    pub ban_count: usize,
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

async fn get_json<T: serde::de::DeserializeOwned>(url: &str) -> Result<T, String> {
    let resp = gloo_net::http::Request::get(url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.ok() {
        return Err(format!("HTTP {}", resp.status()));
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

pub async fn get_stats() -> Result<StatsResponse, String> {
    get_json("/api/v1/stats").await
}

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
    delete_json(&format!("/api/v1/bans/{ip}")).await
}

pub async fn get_jails() -> Result<Vec<JailResponse>, String> {
    get_json("/api/v1/jails").await
}

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
    delete_json(&format!("/api/v1/whitelist/{cidr}")).await
}

pub async fn get_rates_current() -> Result<Vec<RateResponse>, String> {
    get_json("/api/v1/rates/current").await
}

pub async fn get_rates_history() -> Result<Vec<RateHistoryEntry>, String> {
    get_json("/api/v1/rates/history").await
}

pub async fn get_config() -> Result<WebuiConfig, String> {
    get_json("/api/v1/config").await
}

pub async fn get_logs(page: u32, page_size: u32) -> Result<LogPageResponse, String> {
    get_json(&format!("/api/v1/logs?page={page}&page_size={page_size}")).await
}
