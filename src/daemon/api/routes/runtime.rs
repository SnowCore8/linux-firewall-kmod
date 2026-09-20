//! 运行时与指标路由。
//!
//! `GET /health` 是本项目**唯一**以 HTTP 状态码承载语义的端点：http 契约把它记为
//! 有意例外（探针语义），故不经信封；前端用 `getRawJson` 特判。

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use super::ApiState;

/// `GET /health`、`GET /healthz`。
///
/// 就绪返回 200，未就绪返回 503，载荷始终是 `RuntimeSnapshot` 的裸 JSON。
pub async fn handle_health(State(api): State<Arc<ApiState>>) -> Response {
    let snapshot = api.runtime.snapshot();
    let status = if snapshot.is_ready() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let body = serde_json::to_string(&snapshot)
        .unwrap_or_else(|_| "{\"status\":\"degraded\"}".to_string());
    (
        status,
        [("content-type", "application/json")],
        format!("{body}\n"),
    )
        .into_response()
}

/// `GET /metrics`：Prometheus 文本。
pub async fn handle_metrics(State(api): State<Arc<ApiState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        api.runtime.metrics_text(),
    )
}
