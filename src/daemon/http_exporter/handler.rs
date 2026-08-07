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

/// 将同步 SQLite / 重查询移出 tokio worker，避免堵住 2-worker runtime。
async fn db_blocking<T, F>(f: F) -> T
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .unwrap_or_else(|e| panic!("history db blocking task join failed: {e}"))
}

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
    // 未配置 metrics_username/password 时 middleware 跳过（与现有 API 一致）；
    // 已配置时 SSE 与其它 API 同样要求 Basic Auth（修复无认证泄露）。
    let protected_routes = Router::new()
        .route("/metrics", get(handle_metrics))
        .route("/", get(handle_redirect))
        .route("/dashboard", get(handle_dashboard))
        .route("/static/*path", get(handle_static))
        // SSE：与管理 API 同一鉴权策略（连接数上限仍由 handle_sse 强制）
        .route("/api/v1/events", get(handle_sse))
        // v1 RESTful API
        .route("/api/v1/stats", get(handle_api_stats))
        .route("/api/v1/bans", get(handle_api_bans))
        .route("/api/v1/bans", post(handle_create_ban))
        .route("/api/v1/bans/:ip", delete(handle_delete_ban))
        .route("/api/v1/bans/:ip/detail", get(handle_ban_detail))
        .route("/api/v1/bans/unban-temporary", post(handle_unban_temporary))
        .route("/api/v1/bans/batch", post(handle_batch_ban))
        .route("/api/v1/jails", get(handle_api_jails))
        .route("/api/v1/jails/:name", put(handle_update_jail))
        .route("/api/v1/config", get(handle_api_config))
        .route("/api/v1/config", put(handle_update_config))
        .route("/api/v1/whitelist", get(handle_api_whitelist))
        .route("/api/v1/whitelist", post(handle_create_whitelist))
        .route("/api/v1/whitelist/:cidr", delete(handle_delete_whitelist))
        .route(
            "/api/v1/whitelist/recommendations",
            get(handle_whitelist_recommendations),
        )
        .route("/api/v1/rates/current", get(handle_api_rates_current))
        .route("/api/v1/rates/history", get(handle_api_rates_history))
        .route("/api/v1/rates/windows", get(handle_api_rates_windows))
        .route("/api/v1/stats/heatmap", get(handle_api_heatmap))
        .route("/api/v1/stats/recidivism", get(handle_api_recidivism))
        .route(
            "/api/v1/stats/ban-effectiveness",
            get(handle_api_ban_effectiveness),
        )
        .route(
            "/api/v1/stats/periodic-attackers",
            get(handle_api_periodic_attackers),
        )
        .route(
            "/api/v1/stats/collaborative-attacks",
            get(handle_api_collaborative_attacks),
        )
        .route("/api/v1/stats/udp-ports", get(handle_api_udp_ports))
        .route("/api/v1/stats/icmp-types", get(handle_api_icmp_types))
        .route("/api/v1/stats/sse-status", get(handle_api_sse_status))
        .route(
            "/api/v1/stats/ban-duration-histogram",
            get(handle_api_ban_duration_histogram),
        )
        .route("/api/v1/stats/packet-sizes", get(handle_api_packet_sizes))
        .route(
            "/api/v1/stats/ttl-distribution",
            get(handle_api_ttl_distribution),
        )
        .route("/api/v1/stats/ip-fragments", get(handle_api_ip_fragments))
        .route("/api/v1/stats/port-scanners", get(handle_api_port_scanners))
        .route(
            "/api/v1/stats/service-probes",
            get(handle_api_service_probes),
        )
        .route(
            "/api/v1/stats/ban-duration-recommendations",
            get(handle_api_ban_duration_recommendations),
        )
        .route("/api/v1/stats/reputation", get(handle_api_reputation))
        .route(
            "/api/v1/stats/threshold-recommendations",
            get(handle_api_threshold_recommendations),
        )
        .route(
            "/api/v1/stats/network-distribution",
            get(handle_api_network_distribution),
        )
        .route(
            "/api/v1/stats/attack-predictions",
            get(handle_api_attack_predictions),
        )
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
///
/// 关联 Netlink 上下文与 `/proc/firewall`：两者就绪返回 200/`ok`，否则 503/`degraded`。
async fn handle_health() -> (StatusCode, HeaderMap, String) {
    let snap = crate::runtime_status::runtime_snapshot();
    let body = serde_json::to_string(&snap).unwrap_or_else(|_| {
        "{\"status\":\"degraded\",\"error\":\"serialize\"}".to_string()
    });
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    let code = if snap.status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, headers, format!("{body}\n"))
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

/// `GET /api/v1/bans/:ip/detail` — 封禁详情（决策链 + 历史）
async fn handle_ban_detail(Path(ip): Path<String>) -> impl IntoResponse {
    match web_ui::api::get_ban_detail(&ip) {
        Ok(resp) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(resp))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40006, msg)),
        )
            .into_response(),
    }
}

/// `POST /api/v1/bans/unban-temporary` — 批量解封所有临时封禁
async fn handle_unban_temporary() -> impl IntoResponse {
    match web_ui::api::unban_all_temporary() {
        Ok(resp) => (StatusCode::OK, Json(web_ui::api::ApiResponse::ok(resp))).into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40003, msg)),
        )
            .into_response(),
    }
}

/// `POST /api/v1/bans/batch` — 批量封禁多个 IP
async fn handle_batch_ban(Json(ips): Json<Vec<String>>) -> impl IntoResponse {
    if ips.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(
                40004,
                "IP 列表不能为空".to_string(),
            )),
        )
            .into_response();
    }
    if ips.len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(
                40005,
                format!("单次最多封禁 100 个 IP，当前 {} 个", ips.len()),
            )),
        )
            .into_response();
    }
    match web_ui::api::batch_ban(ips) {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(web_ui::api::ApiResponse::ok(resp)),
        )
            .into_response(),
        Err(msg) => (
            StatusCode::BAD_REQUEST,
            Json(web_ui::api::ApiResponse::<()>::error(40005, msg)),
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

/// `GET /api/v1/whitelist/recommendations` — 智能白名单推荐
async fn handle_whitelist_recommendations(
) -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::WhitelistRecommendation>>> {
    let recs = web_ui::api::get_whitelist_recommendations();
    Json(web_ui::api::ApiResponse::ok(recs))
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

/// `GET /api/v1/rates/windows` — 多窗口速率 EWMA（短期/中期/长期）
async fn handle_api_rates_windows(
) -> Json<web_ui::api::ApiResponse<crate::types::RateWindowSnapshot>> {
    let windows = web_ui::api::get_rate_windows();
    Json(web_ui::api::ApiResponse::ok(windows))
}

/// `GET /api/v1/stats/heatmap` — 24 小时攻击热力图（按小时聚合）
async fn handle_api_heatmap(
) -> Json<web_ui::api::ApiResponse<crate::history_snapshot::HourlyHeatmap>> {
    let heatmap = db_blocking(web_ui::api::get_heatmap).await;
    Json(web_ui::api::ApiResponse::ok(heatmap))
}

/// `GET /api/v1/stats/recidivism` — 封禁效果追踪（复发率 + TOP 10）
async fn handle_api_recidivism() -> Json<web_ui::api::ApiResponse<web_ui::api::RecidivismResponse>>
{
    let recidivism = db_blocking(web_ui::api::get_ban_recidivism).await;
    Json(web_ui::api::ApiResponse::ok(recidivism))
}

/// `GET /api/v1/stats/ban-effectiveness` — 封禁效果分析（按级别统计复发率）
async fn handle_api_ban_effectiveness(
) -> Json<web_ui::api::ApiResponse<web_ui::api::BanEffectivenessResponse>> {
    let effectiveness = db_blocking(web_ui::api::get_ban_effectiveness).await;
    Json(web_ui::api::ApiResponse::ok(effectiveness))
}

/// `GET /api/v1/stats/periodic-attackers` — 周期性攻击者检测
async fn handle_api_periodic_attackers(
) -> Json<web_ui::api::ApiResponse<Vec<crate::history_snapshot::PeriodicAttacker>>> {
    let attackers = db_blocking(web_ui::api::get_periodic_attackers).await;
    Json(web_ui::api::ApiResponse::ok(attackers))
}

/// `GET /api/v1/stats/collaborative-attacks` — 协同攻击检测
async fn handle_api_collaborative_attacks(
) -> Json<web_ui::api::ApiResponse<Vec<crate::history_snapshot::CollaborativeAttack>>> {
    let attacks = db_blocking(web_ui::api::get_collaborative_attacks).await;
    Json(web_ui::api::ApiResponse::ok(attacks))
}

/// `GET /api/v1/stats/udp-ports` — UDP 端口分布统计
async fn handle_api_udp_ports(
) -> Json<web_ui::api::ApiResponse<web_ui::api::UdpPortDistributionResponse>> {
    let distribution = web_ui::api::get_udp_port_distribution();
    Json(web_ui::api::ApiResponse::ok(distribution))
}

/// `GET /api/v1/stats/icmp-types` — ICMP 类型分布统计
async fn handle_api_icmp_types(
) -> Json<web_ui::api::ApiResponse<web_ui::api::IcmpTypeDistributionResponse>> {
    let distribution = web_ui::api::get_icmp_type_distribution();
    Json(web_ui::api::ApiResponse::ok(distribution))
}

/// `GET /api/v1/stats/sse-status` — SSE 连接状态诊断
async fn handle_api_sse_status() -> Json<web_ui::api::ApiResponse<serde_json::Value>> {
    let (current, max) = web_ui::sse::get_sse_connection_info();
    Json(web_ui::api::ApiResponse::ok(serde_json::json!({
        "current_connections": current,
        "max_connections": max,
        "limit_reached": current >= max
    })))
}

/// `GET /api/v1/stats/ban-duration-histogram` — 封禁时长分布直方图
async fn handle_api_ban_duration_histogram(
) -> Json<web_ui::api::ApiResponse<web_ui::api::BanDurationHistogramResponse>> {
    let histogram = web_ui::api::get_ban_duration_histogram();
    Json(web_ui::api::ApiResponse::ok(histogram))
}

/// `GET /api/v1/stats/packet-sizes` — 包大小分布直方图
async fn handle_api_packet_sizes(
) -> Json<web_ui::api::ApiResponse<web_ui::api::PacketSizeDistributionResponse>> {
    let distribution = web_ui::api::get_packet_size_distribution();
    Json(web_ui::api::ApiResponse::ok(distribution))
}

/// `GET /api/v1/stats/ttl-distribution` — TTL 分布直方图
async fn handle_api_ttl_distribution(
) -> Json<web_ui::api::ApiResponse<web_ui::api::TtlDistributionResponse>> {
    let distribution = web_ui::api::get_ttl_distribution();
    Json(web_ui::api::ApiResponse::ok(distribution))
}

/// `GET /api/v1/stats/ip-fragments` — IP 分片统计
async fn handle_api_ip_fragments(
) -> Json<web_ui::api::ApiResponse<web_ui::api::IpFragmentStatsResponse>> {
    let stats = web_ui::api::get_ip_fragment_stats();
    Json(web_ui::api::ApiResponse::ok(stats))
}

/// `GET /api/v1/stats/port-scanners` — 端口扫描检测
async fn handle_api_port_scanners() -> Json<web_ui::api::ApiResponse<web_ui::api::PortScanResponse>>
{
    let detection = web_ui::api::get_port_scan_detection();
    Json(web_ui::api::ApiResponse::ok(detection))
}

/// `GET /api/v1/stats/service-probes` — 服务探测检测
async fn handle_api_service_probes(
) -> Json<web_ui::api::ApiResponse<web_ui::api::ServiceProbeResponse>> {
    let detection = web_ui::api::get_service_probe_detection();
    Json(web_ui::api::ApiResponse::ok(detection))
}

/// `GET /api/v1/stats/ban-duration-recommendations` — 封禁时长推荐
async fn handle_api_ban_duration_recommendations(
) -> Json<web_ui::api::ApiResponse<web_ui::api::BanDurationRecommendationResponse>> {
    let recs = db_blocking(web_ui::api::get_ban_duration_recommendations).await;
    Json(web_ui::api::ApiResponse::ok(recs))
}

/// `GET /api/v1/stats/reputation` — IP 信誉分列表
async fn handle_api_reputation(
) -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::ReputationEntryResponse>>> {
    let store = crate::ip_reputation::get_store();
    let entries: Vec<web_ui::api::ReputationEntryResponse> = store
        .snapshot()
        .into_iter()
        .map(|e| web_ui::api::ReputationEntryResponse {
            ip: e.ip,
            score: e.score,
            last_failure_at: e.last_failure_at,
            total_failures: e.total_failures,
            total_bans: e.total_bans,
            threshold_multiplier: if e.score >= 80 {
                1.0
            } else if e.score >= 50 {
                0.8
            } else {
                0.5
            },
        })
        .collect();
    Json(web_ui::api::ApiResponse::ok(entries))
}

/// `GET /api/v1/stats/threshold-recommendations` — 阈值调优建议
async fn handle_api_threshold_recommendations(
) -> Json<web_ui::api::ApiResponse<web_ui::api::ThresholdRecommendationResponse>> {
    let recs = db_blocking(|| {
        let jails = crate::http_exporter::get_global_jails();
        crate::history_snapshot::analyze_thresholds(&jails)
    })
    .await;
    Json(web_ui::api::ApiResponse::ok(recs))
}

/// `GET /api/v1/stats/network-distribution` — 攻击源网络分布
async fn handle_api_network_distribution(
) -> Json<web_ui::api::ApiResponse<Vec<crate::history_snapshot::NetworkBlock>>> {
    let blocks = db_blocking(crate::history_snapshot::get_network_distribution).await;
    Json(web_ui::api::ApiResponse::ok(blocks))
}

/// `GET /api/v1/stats/attack-predictions` — 攻击时间预测 + Jail 攻击趋势
async fn handle_api_attack_predictions(
) -> Json<web_ui::api::ApiResponse<crate::history_snapshot::AttackPredictionSummary>> {
    let summary = db_blocking(web_ui::api::get_attack_predictions).await;
    Json(web_ui::api::ApiResponse::ok(summary))
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
