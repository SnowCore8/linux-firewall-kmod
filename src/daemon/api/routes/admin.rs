//! Jail 与配置路由。
//!
//! 配置的**语义**（阈值关系、容量非零、持久化）归配置 owner；本层只做形状转换与
//! 业务码映射。Jail 的 `ban_count` 与 per-jail 计数取自 `state`，不再读旧全局。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::Counter;

use super::super::envelope::{ApiError, ApiResponse, BusinessCode};
use super::super::payloads::{
    JailResponse, UpdateConfigRequest, UpdateJailRequest, WebuiConfigResponse,
};
use super::super::ports::JailView;
use super::ApiState;

/// 组装一条 `JailResponse`：配置面来自端口，计数与统计来自 `state`。
fn jail_response(api: &ApiState, view: JailView) -> JailResponse {
    let bans = api.state.bans().snapshot();
    let stats = api.state.stats().snapshot();
    JailResponse {
        ban_count: bans.count_for_jail(&view.name),
        name: view.name,
        enabled: view.enabled,
        max_retries: view.max_retries,
        effective_max_retries: view.effective_max_retries,
        findtime: view.findtime,
        ban_time: view.ban_time,
        is_peak_hours: view.is_peak_hours,
        peak_hours_multiplier: view.peak_hours_multiplier,
        internal_ip_multiplier: view.internal_ip_multiplier,
        // per-jail 统计尚未迁入 `state`（属 2.F 的测试债务面），此处回全局值；
        // 字段存在且类型正确，前端不必特判。
        lines_parsed: stats.get(Counter::LinesParsed),
        regex_matches: stats.get(Counter::RegexMatches),
        ips_extracted: stats.get(Counter::IpsExtracted),
        failed_attempts: stats.get(Counter::FailedAttempts),
        bans_triggered: stats.get(Counter::IpsBanned),
    }
}

/// `GET /api/v1/jails`。
pub async fn handle_api_jails(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<Vec<JailResponse>>> {
    let jails = api
        .config
        .jails()
        .into_iter()
        .map(|j| jail_response(&api, j))
        .collect();
    Json(ApiResponse::ok(jails))
}

/// `PUT /api/v1/jails/:name`：启用/禁用某个 Jail。
pub async fn handle_update_jail(
    State(api): State<Arc<ApiState>>,
    Path(name): Path<String>,
    Json(req): Json<UpdateJailRequest>,
) -> Response {
    match api.config.set_jail_enabled(&name, req.enabled) {
        Ok(view) => (
            StatusCode::OK,
            Json(ApiResponse::ok(jail_response(&api, view))),
        )
            .into_response(),
        Err(msg) => ApiError::new(BusinessCode::JailNotFound, msg).into_response(),
    }
}

/// `GET /api/v1/config`。
pub async fn handle_api_config(
    State(api): State<Arc<ApiState>>,
) -> Json<ApiResponse<WebuiConfigResponse>> {
    Json(ApiResponse::ok(api.config.webui()))
}

/// `PUT /api/v1/config`。
pub async fn handle_update_config(
    State(api): State<Arc<ApiState>>,
    Json(req): Json<UpdateConfigRequest>,
) -> Response {
    match api.config.apply(req) {
        Ok(view) => (StatusCode::OK, Json(ApiResponse::ok(view))).into_response(),
        Err(msg) => ApiError::new(BusinessCode::ConfigOrWhitelistRemoveFailed, msg).into_response(),
    }
}
