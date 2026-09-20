//! 路由装配：把 `api` 的处理函数挂成两个 Router 组。
//!
//! # 与契约的对应
//!
//! 认证分组是契约的一部分（`route` 的 `auth` 必须与源码所在的组一致）：
//! 无认证组 = `/health`、`/healthz`、SPA 外壳、静态资源、`/sw.js`；
//! 需认证组 = `/metrics`、`/api/v1/**`。分组与路径字面量都要与
//! `contract/generated/http_contract.rs` 的 `path::*` 常量逐字一致。
//!
//! # 与旧实现的差别
//!
//! 旧 `build_router` 把所有 handler 写在同一文件里（760 行）。这里按域拆到
//! [`super::routes`] 的子模块，装配处只列路由表，读起来就是契约。

use std::sync::Arc;

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;

use crate::contract::http_contract::path;

use super::render::StateRenderer;
use super::routes::{
    handle_api_bans, handle_api_config, handle_api_jails, handle_api_rates_current,
    handle_api_sse_status, handle_api_stats, handle_api_whitelist, handle_ban_detail,
    handle_batch_ban, handle_create_ban, handle_create_whitelist, handle_delete_ban,
    handle_delete_whitelist, handle_health, handle_metrics, handle_unban_temporary,
    handle_update_config, handle_update_jail, ApiState,
};
use super::sse::{events_response, SseStatus, LIMIT_REACHED_STATUS};

/// `GET /api/v1/events`：管理事件流。
///
/// 连接位满时返回 503（契约 `alt_status`）；否则交出一条按域推送的流。
pub async fn handle_sse(State(api): State<Arc<ApiState>>) -> Response {
    let Some(guard) = api.sse.acquire_events() else {
        return (LIMIT_REACHED_STATUS, "SSE 连接数已达上限\n").into_response();
    };
    let renderer = Arc::new(StateRenderer::new(Arc::clone(&api)));
    events_response(api.state.hub().subscribe(), renderer, guard).into_response()
}

/// 构建需认证的 API 路由组。
///
/// 调用方负责在其上挂认证中间件——本函数不假设认证实现，避免 `api` 依赖某个
/// 具体凭据来源。
pub fn protected_routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(path::ROUTE_GET_METRICS, get(handle_metrics))
        .route(path::ROUTE_GET_API_V1_EVENTS, get(handle_sse))
        .route(path::ROUTE_GET_API_V1_STATS, get(handle_api_stats))
        .route(path::ROUTE_GET_API_V1_BANS, get(handle_api_bans))
        .route(path::ROUTE_POST_API_V1_BANS, post(handle_create_ban))
        .route(path::ROUTE_DELETE_API_V1_BANS_IP, delete(handle_delete_ban))
        .route(
            path::ROUTE_GET_API_V1_BANS_IP_DETAIL,
            get(handle_ban_detail),
        )
        .route(
            path::ROUTE_POST_API_V1_BANS_UNBAN_TEMPORARY,
            post(handle_unban_temporary),
        )
        .route(path::ROUTE_POST_API_V1_BANS_BATCH, post(handle_batch_ban))
        .route(path::ROUTE_GET_API_V1_JAILS, get(handle_api_jails))
        .route(path::ROUTE_PUT_API_V1_JAILS_NAME, put(handle_update_jail))
        .route(path::ROUTE_GET_API_V1_CONFIG, get(handle_api_config))
        .route(path::ROUTE_PUT_API_V1_CONFIG, put(handle_update_config))
        .route(path::ROUTE_GET_API_V1_WHITELIST, get(handle_api_whitelist))
        .route(
            path::ROUTE_POST_API_V1_WHITELIST,
            post(handle_create_whitelist),
        )
        .route(
            path::ROUTE_DELETE_API_V1_WHITELIST_CIDR,
            delete(handle_delete_whitelist),
        )
        .route(
            path::ROUTE_GET_API_V1_RATES_CURRENT,
            get(handle_api_rates_current),
        )
        .route(
            path::ROUTE_GET_API_V1_STATS_SSE_STATUS,
            get(handle_api_sse_status),
        )
        .with_state(state)
}

/// 构建无认证的探针路由组（`/health`、`/healthz`）。
pub fn health_routes(state: Arc<ApiState>) -> Router {
    Router::new()
        .route(path::ROUTE_GET_HEALTH, get(handle_health))
        .route(path::ROUTE_GET_HEALTHZ, get(handle_health))
        .with_state(state)
}

/// 两条流的连接计数（供 SSE 路由与诊断端点共享）。
///
/// 单独取出来是为了让调用方能在装配 SSE 时拿到同一个实例——诊断端点读到的
/// 必须就是连接计数本身，而不是另一份副本。
#[must_use]
pub fn sse_status() -> Arc<SseStatus> {
    Arc::new(SseStatus::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 路由字面量与契约生成物一致——写错一个字符就是 404。
    #[test]
    fn the_path_constants_match_the_contract() {
        assert_eq!(path::ROUTE_GET_HEALTH, "/health");
        assert_eq!(path::ROUTE_GET_HEALTHZ, "/healthz");
        assert_eq!(path::ROUTE_GET_METRICS, "/metrics");
        assert_eq!(path::ROUTE_GET_API_V1_STATS, "/api/v1/stats");
        assert_eq!(path::ROUTE_GET_API_V1_BANS, "/api/v1/bans");
        assert_eq!(path::ROUTE_DELETE_API_V1_BANS_IP, "/api/v1/bans/:ip");
        assert_eq!(
            path::ROUTE_GET_API_V1_BANS_IP_DETAIL,
            "/api/v1/bans/:ip/detail"
        );
        assert_eq!(
            path::ROUTE_POST_API_V1_BANS_UNBAN_TEMPORARY,
            "/api/v1/bans/unban-temporary"
        );
        assert_eq!(path::ROUTE_POST_API_V1_BANS_BATCH, "/api/v1/bans/batch");
        assert_eq!(path::ROUTE_GET_API_V1_JAILS, "/api/v1/jails");
        assert_eq!(path::ROUTE_PUT_API_V1_JAILS_NAME, "/api/v1/jails/:name");
        assert_eq!(path::ROUTE_GET_API_V1_CONFIG, "/api/v1/config");
        assert_eq!(path::ROUTE_PUT_API_V1_CONFIG, "/api/v1/config");
        assert_eq!(path::ROUTE_GET_API_V1_WHITELIST, "/api/v1/whitelist");
        assert_eq!(path::ROUTE_POST_API_V1_WHITELIST, "/api/v1/whitelist");
        assert_eq!(
            path::ROUTE_DELETE_API_V1_WHITELIST_CIDR,
            "/api/v1/whitelist/:cidr"
        );
        assert_eq!(
            path::ROUTE_GET_API_V1_RATES_CURRENT,
            "/api/v1/rates/current"
        );
        assert_eq!(
            path::ROUTE_GET_API_V1_STATS_SSE_STATUS,
            "/api/v1/stats/sse-status"
        );
    }
}
