//! 统计与速率读取路由。
//!
//! 三条都是**纯读**：取快照、派生、返回。没有一处清理或计数改写——缺陷 E 的判据。

use std::sync::Arc;

use axum::extract::State;
use axum::Json;

use super::super::envelope::ApiResponse;
use super::super::payloads::{RateResponse, SseStatusResponse, StatsResponse};
use super::super::views;
use super::ApiState;

/// `GET /api/v1/stats`。
pub async fn handle_api_stats(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<StatsResponse>> {
    let now = api.now_secs();
    let stats = api.state.stats().snapshot();
    let bans = api.state.bans().snapshot();
    let whitelist_count = api.state.whitelist().len() as u64;
    let trends = api.history.trends();
    let inputs = api.history.threat_inputs();
    let threshold = api.config.webui().rate_warning_pps;

    // DDoS 事件累计数取内核计数器的权威来源（`DDOS_STATS.events_detected`），
    // 与 Prometheus 的 `firewall_ddos_events_detected_total` 同源。
    let ddos_events = crate::types::DDOS_STATS
        .events_detected
        .load(std::sync::atomic::Ordering::Relaxed);
    let threat = views::threat_level(
        bans.len() as u64,
        ddos_events,
        views::recent_bans(&bans, now),
        inputs.current_pps,
        threshold,
        inputs.baseline_frozen,
        inputs.peak_hours,
    );

    Json(ApiResponse::ok(views::stats_view(
        &stats,
        &bans,
        whitelist_count,
        now.max(0) as u64,
        env!("CARGO_PKG_VERSION"),
        &api.kernel_version,
        ddos_events,
        &trends,
        threat,
        api.history.today_bans(),
    )))
}

/// `GET /api/v1/rates/current`：当前速率列表。
pub async fn handle_api_rates_current(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<Vec<RateResponse>>> {
    let snapshot = api.state.rates().snapshot();
    Json(ApiResponse::ok(views::rates_view(&snapshot)))
}

/// `GET /api/v1/stats/sse-status`：两条 SSE 流各自的连接状态。
///
/// 修复 `HTTP_SSE_STATUS_INCOMPLETE`：旧实现只报一条流的上限，前端据此判断另一条
/// 流是否达上限会在日志流被拒时误判为未达上限，把 503 当成网络故障无限重连。
pub async fn handle_api_sse_status(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<SseStatusResponse>> {
    Json(ApiResponse::ok(api.sse.snapshot()))
}
