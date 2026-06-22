//! HTTP 路由构建 + handler 函数 + 安全头中间件

use axum::{
    extract::{Path, Query},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::{delete, get, post, put},
    Router,
};

use super::auth::{auth_middleware, AuthCredentials};
use super::metrics::generate_metrics;
use crate::web_ui;

// ============================================================================
// 路由构建
// ============================================================================

/// 构建 axum Router。
///
/// 路由分层：
/// - 无认证路由组：`/health`、`/healthz`（K8s livenessProbe 跳过认证）
/// - 需认证路由组：其余所有路由（通过 auth middleware 保护）
/// - 安全头：所有路由共享
pub fn build_router(metrics_user: String, metrics_pass: String) -> Router {
    // 无认证路由组
    let public_routes = Router::new()
        .route("/health", get(handle_health))
        .route("/healthz", get(handle_health))
        // SPA 路由（无认证）- 每个路由使用独立的处理函数
        .route("/bans", get(handle_spa_bans))
        .route("/whitelist", get(handle_spa_whitelist))
        .route("/jails", get(handle_spa_jails))
        .route("/ddos", get(handle_spa_ddos))
        .route("/logs", get(handle_spa_logs))
        .route("/settings", get(handle_spa_settings));

    // 需认证路由组（RESTful v1 API）
    let protected_routes = Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/", get(handle_redirect))
        .route("/dashboard", get(handle_dashboard))
        .route("/static/*path", get(handle_static))
        // v1 RESTful API
        .route("/api/v1/stats", get(handle_api_stats))
        .route("/api/v1/bans", get(handle_api_bans))
        .route("/api/v1/bans", post(handle_create_ban))
        .route("/api/v1/bans/:ip", delete(handle_delete_ban))
        .route("/api/v1/jails", get(handle_api_jails))
        .route("/api/v1/jails/:name", put(handle_update_jail))
        .route("/api/v1/config", get(handle_api_config))
        .route("/api/v1/config", put(handle_update_config))
        .route("/api/v1/whitelist", get(handle_api_whitelist))
        .route("/api/v1/whitelist", post(handle_create_whitelist))
        .route("/api/v1/whitelist/:cidr", delete(handle_delete_whitelist))
        .route("/api/v1/rates/current", get(handle_api_rates_current))
        .route("/api/v1/rates/history", get(handle_api_rates_history))
        .route("/api/v1/events", get(handle_sse))
        .route("/api/v1/logs/stream", get(handle_log_stream))
        .route("/api/v1/logs", get(handle_api_logs))
        .layer(middleware::from_fn(auth_middleware))
        .layer(axum::Extension(AuthCredentials {
            username: metrics_user,
            password: metrics_pass,
        }));

    // 合并 + 安全头中间件（所有路由共享）
    public_routes
        .merge(protected_routes)
        .layer(middleware::from_fn(security_headers_middleware))
}

// ============================================================================
// 安全头中间件
// ============================================================================

/// 安全头中间件：为所有响应添加 CSP / X-Frame-Options / X-Content-Type-Options。
///
/// Web UI 路径（`/dashboard`、`/static/*`）使用宽松 CSP 允许同源资源加载。
/// 其他路径使用 `default-src 'none'` 严格限制。
async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();
    let is_webui = path == "/dashboard"
        || path.starts_with("/static/")
        || path == "/bans"
        || path == "/whitelist"
        || path == "/jails"
        || path == "/ddos"
        || path == "/logs"
        || path == "/settings";

    let mut response = next.run(request).await;

    let csp_value = if is_webui {
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data:; connect-src 'self'; font-src 'self' data: https://fonts.gstatic.com"
    } else {
        "default-src 'none'"
    };

    let headers = response.headers_mut();
    headers.insert(
        "X-Content-Type-Options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert(
        "Content-Security-Policy",
        HeaderValue::from_str(csp_value).expect("CSP 值为合法 ASCII"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    response
}

// ============================================================================
// Handler 函数
// ============================================================================

/// `GET /health` 和 `GET /healthz` — 健康检查（跳过认证）
async fn handle_health() -> (StatusCode, HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    (StatusCode::OK, headers, "{\"status\":\"ok\"}\n")
}

/// `GET /metrics` — Prometheus 指标
async fn handle_metrics() -> (StatusCode, HeaderMap, String) {
    let metrics = generate_metrics();
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    (StatusCode::OK, headers, metrics)
}

/// `GET /` — 重定向到 /dashboard
async fn handle_redirect() -> Redirect {
    Redirect::to("/dashboard")
}

/// `GET /dashboard` — Web UI 主页
async fn handle_dashboard() -> Html<String> {
    Html(web_ui::render_dashboard())
}

/// SPA 路由处理函数 — 所有前端路由返回 index.html
async fn handle_spa_bans() -> Html<String> {
    Html(web_ui::render_dashboard())
}

async fn handle_spa_whitelist() -> Html<String> {
    Html(web_ui::render_dashboard())
}

async fn handle_spa_jails() -> Html<String> {
    Html(web_ui::render_dashboard())
}

async fn handle_spa_ddos() -> Html<String> {
    Html(web_ui::render_dashboard())
}

async fn handle_spa_logs() -> Html<String> {
    Html(web_ui::render_dashboard())
}

async fn handle_spa_settings() -> Html<String> {
    Html(web_ui::render_dashboard())
}

/// `GET /static/{*path}` — 静态资源服务
async fn handle_static(Path(path): Path<String>) -> impl IntoResponse {
    match web_ui::get_static_asset(&path) {
        Some((data, mime_type)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime_type).expect("MIME 类型为合法 ASCII"),
            );
            (StatusCode::OK, headers, data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found\n").into_response(),
    }
}

/// `GET /api/v1/stats` — 统计数据 JSON
async fn handle_api_stats() -> Json<web_ui::api::ApiResponse<web_ui::api::StatsResponse>> {
    let stats = web_ui::api::get_stats();
    Json(web_ui::api::ApiResponse::ok(stats))
}

/// `GET /api/v1/bans` — 活跃封禁列表 JSON（支持分页）
async fn handle_api_bans(Query(params): Query<web_ui::api::PaginationParams>) -> impl IntoResponse {
    let page = params.page.unwrap_or(1);
    let page_size = params.page_size.unwrap_or(20);
    let sort_by = params.sort_by;

    // 如果有分页参数，返回分页格式；否则返回全量（向后兼容）
    if params.page.is_some() || params.page_size.is_some() {
        let paginated = web_ui::api::get_active_bans_paginated(page, page_size, sort_by);
        Json(web_ui::api::ApiResponse::ok(paginated)).into_response()
    } else {
        let bans = web_ui::api::get_active_bans();
        Json(web_ui::api::ApiResponse::ok(bans)).into_response()
    }
}

/// `POST /api/v1/bans` — 封禁 IP
async fn handle_create_ban(Json(req): Json<web_ui::api::CreateBanRequest>) -> impl IntoResponse {
    match web_ui::api::create_ban(req) {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(web_ui::api::ApiResponse::ok(resp)),
        )
            .into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40001, msg)),
        )
            .into_response(),
    }
}

/// `DELETE /api/v1/bans/:ip` — 解封 IP
async fn handle_delete_ban(Path(ip): Path<String>) -> impl IntoResponse {
    match web_ui::api::delete_ban(&ip) {
        Ok(resp) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(resp))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40002, msg)),
        )
            .into_response(),
    }
}

/// `GET /api/v1/jails` — Jail 列表 JSON
async fn handle_api_jails() -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::JailResponse>>> {
    let jail_infos = super::get_global_jails();
    let jails = web_ui::api::get_jails(&jail_infos);
    Json(web_ui::api::ApiResponse::ok(jails))
}

/// `PUT /api/v1/jails/:name` — 更新 Jail 启用/禁用状态
async fn handle_update_jail(
    Path(name): Path<String>,
    Json(req): Json<web_ui::api::UpdateJailRequest>,
) -> impl IntoResponse {
    match web_ui::api::update_jail_enabled(&name, req.enabled) {
        Ok(jail) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(jail))).into_response(),
        Err(msg) => {
            let resp = web_ui::api::ApiResponse::<()>::error(404, msg);
            (StatusCode::NOT_FOUND, Json(resp)).into_response()
        }
    }
}

/// `GET /api/v1/config` — Web UI 配置 JSON
async fn handle_api_config() -> Json<web_ui::api::ApiResponse<web_ui::api::WebuiConfigResponse>> {
    let config = web_ui::api::get_webui_config();
    Json(web_ui::api::ApiResponse::ok(config))
}

/// `PUT /api/v1/config` — 更新 Web UI 配置
async fn handle_update_config(
    Json(req): Json<web_ui::api::UpdateConfigRequest>,
) -> impl IntoResponse {
    match web_ui::api::update_webui_config(req) {
        Ok(config) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(config))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40004, msg)),
        )
            .into_response(),
    }
}

/// `GET /api/v1/whitelist` — 白名单列表 JSON
async fn handle_api_whitelist(
) -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::WhitelistEntryResponse>>> {
    let whitelist = web_ui::api::get_whitelist();
    Json(web_ui::api::ApiResponse::ok(whitelist))
}

/// `POST /api/v1/whitelist` — 添加白名单
async fn handle_create_whitelist(
    Json(req): Json<web_ui::api::CreateWhitelistRequest>,
) -> impl IntoResponse {
    match web_ui::api::create_whitelist(req) {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(web_ui::api::ApiResponse::ok(resp)),
        )
            .into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40003, msg)),
        )
            .into_response(),
    }
}

/// `DELETE /api/v1/whitelist/:cidr` — 移除白名单
async fn handle_delete_whitelist(Path(cidr): Path<String>) -> impl IntoResponse {
    match web_ui::api::delete_whitelist(&cidr) {
        Ok(resp) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(resp))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40004, msg)),
        )
            .into_response(),
    }
}

/// `GET /api/v1/rates/current` — 当前 DDoS 速率 JSON
async fn handle_api_rates_current() -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::RateResponse>>>
{
    let rates = web_ui::api::get_ddos_rates();
    Json(web_ui::api::ApiResponse::ok(rates))
}

/// `GET /api/v1/rates/history` — 速率历史趋势 JSON（最近 1 小时，每 2 秒一条）
async fn handle_api_rates_history(
) -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::RateHistoryResponse>>> {
    let history = web_ui::api::get_rate_history();
    Json(web_ui::api::ApiResponse::ok(history))
}

/// `GET /api/v1/events` — SSE 实时事件推送（长连接）
async fn handle_sse() -> impl IntoResponse {
    web_ui::sse::handle_sse().await
}

/// `GET /api/v1/logs/stream` — SSE 实时日志流（tail -f 语义）
async fn handle_log_stream() -> impl IntoResponse {
    web_ui::log_viewer::handle_log_stream().await
}

/// `GET /api/v1/logs` — 历史日志分页查询
async fn handle_api_logs(
    Query(params): Query<web_ui::log_viewer::LogQueryParams>,
) -> impl IntoResponse {
    match web_ui::log_viewer::get_log_page(&params) {
        Ok(page) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(page))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40005, msg)),
        )
            .into_response(),
    }
}
