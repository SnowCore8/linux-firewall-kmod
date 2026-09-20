//! HTTP 路由构建 + handler 函数 + 安全头中间件

use axum::{
    extract::{Path, Query},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware,
    response::{Html, IntoResponse, Json, Redirect, Response},
    routing::get,
    Router,
};

use super::auth::auth_middleware;
use crate::web_ui;

/// 将同步 SQLite / 重查询移出 tokio worker，避免堵住 2-worker runtime。
///
/// 返回 `Err` 而不是 panic：release 配置为 `panic = "abort"`（Cargo.toml），
/// 一次查询任务的 join 失败会终止整个守护进程，连带中断封禁能力。
async fn db_blocking<T, F>(f: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| format!("历史库查询任务 join 失败: {e}"))
}

/// 历史库查询失败时的 500 响应：记日志后返回错误信封，不 panic。
fn db_error_response(msg: String) -> Response {
    crate::logger::error!(crate::logger::get(), "历史库查询失败"; "error" => %msg);
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(web_ui::api::ApiResponse::<()>::error(50002, msg)),
    )
        .into_response()
}

// ============================================================================
// 路由构建
// ============================================================================

/// 构建 axum Router。
///
/// 路由分层：
/// - 无认证路由组：SPA 外壳与静态资源、`/sw.js`（`/health`、`/healthz` 已迁到
///   [`crate::api::router::health_routes`]，由它提供）
/// - 需认证路由组：由 [`crate::api::router::protected_routes`]（已迁入的 18 条）
///   与 [`legacy_protected_routes`]（尚未迁入的 35 条）合并而成；本函数把认证
///   中间件统一挂在合并结果上
/// - 安全头：所有路由共享
///
/// 认证凭据不在本函数传入，而是由中间件每请求读取运行期凭据
/// （见 [`crate::http_exporter::set_auth_credentials`]），以支持 SIGHUP 热重载。
///
/// # 关于 `api_state`
///
/// 已迁入的 18 条路由其 handler 的 state 是 [`crate::api::routes::ApiState`]，
/// 未迁入的 handler 不取 state；两者类型不同，只能各自 `.with_state(...)` 之后再
/// `merge`。`api_state` 为 `None`（仅可能发生在极早期启动路径）时只挂未迁入组，
/// 已迁入路由暂缺——但组合根在 `main.rs` 启动期就已注入状态，正常启动不会走到。
pub fn build_router(api_state: Option<std::sync::Arc<crate::api::routes::ApiState>>) -> Router {
    // 无认证路由组（SPA 外壳 + 静态资源 + Service Worker）
    let public_routes = Router::new()
        // SPA 外壳（无认证）：返回的都是不含数据的静态壳，数据一律经受保护的 /api/v1/*
        // 取用，故外壳公开不泄露状态；同时保证浏览器直接打开页面能加载、E2E 无需凭据。
        // 与 /metrics、/api/v1/** 的受保护策略区分开。
        .route("/", get(handle_redirect))
        .route("/dashboard", get(handle_dashboard))
        // SPA 路由（无认证）- 每个路由使用独立的处理函数
        .route("/bans", get(handle_spa_bans))
        .route("/whitelist", get(handle_spa_whitelist))
        .route("/jails", get(handle_spa_jails))
        .route("/ddos", get(handle_spa_ddos))
        .route("/logs", get(handle_spa_logs))
        .route("/settings", get(handle_spa_settings))
        // 前端静态资源（无认证）：同样是构建产物、不含任何运行时数据。
        // 若放进认证组，浏览器加载子资源时会因 401 失败，导致配了凭据后页面反而打不开。
        .route("/static/*path", get(handle_static))
        // PWA Service Worker（无认证）：浏览器注册 SW 时不会带交互式凭据提示，
        // 若放在认证组内会因 401 导致注册失败
        .route("/sw.js", get(handle_sw));

    // 需认证：未迁入组 + 已迁入组。两组的 state 不同，故分别 with_state 后 merge。
    let mut protected_routes = legacy_protected_routes();
    let mut health_routes = Router::new();
    if let Some(api_state) = api_state {
        protected_routes = protected_routes.merge(crate::api::router::protected_routes(
            std::sync::Arc::clone(&api_state),
        ));
        health_routes = crate::api::router::health_routes(api_state);
        // 认证中间件只作用于「未迁入 + 已迁入」的 API 组；探针组保持无认证。
        protected_routes = protected_routes.layer(middleware::from_fn(auth_middleware));
    }

    // 合并 + 安全头中间件（所有路由共享）
    // 注意：凭据不再在构造期按值捕获，改由中间件每请求读取运行期凭据
    // （见 http_exporter::set_auth_credentials），以支持 SIGHUP 热重载
    public_routes
        .merge(health_routes)
        .merge(protected_routes)
        .layer(middleware::from_fn(security_headers_middleware))
}

/// 尚未迁入 `api` 层的需认证路由（35 条）。
///
/// 这些 handler 仍在本文件；每次迁入一批，就把对应的 `.route(...)` 从这里删掉、
/// 加到 [`crate::api::router::protected_routes`]。两条清单加起来必须恰好是契约里
/// 需认证的路由全集，`verify_http.py` 的 `check_routes` 会同时读两个文件核对。
fn legacy_protected_routes() -> Router {
    // 未配置 metrics_username/password 时 middleware 跳过（与现有 API 一致）；
    // 已配置时 SSE 与其它 API 同样要求 Basic Auth（修复无认证泄露）。
    Router::new()
        .route(
            "/api/v1/whitelist/recommendations",
            get(handle_whitelist_recommendations),
        )
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
}

// ============================================================================
// 安全头中间件
// ============================================================================

/// 安全头中间件：为所有响应添加 CSP / X-Frame-Options / X-Content-Type-Options。
///
/// Web UI 路径（`/dashboard`、`/static/*`、`/sw.js`）使用宽松 CSP 允许同源资源加载。
/// 其他路径使用 `default-src 'none'` 严格限制。
///
/// `/sw.js` 必须列入 Web UI：`default-src 'none'` 若被当作 Service Worker 自身的
/// 策略，会禁掉 SW 内部的所有 fetch，导致离线缓存与外壳回退全部失效。
async fn security_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Response {
    let path = request.uri().path().to_string();
    let is_webui = path == "/dashboard"
        || path.starts_with("/static/")
        || path == "/sw.js"
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
    // 默认禁止缓存；已自行声明 Cache-Control 的响应（如 /sw.js 的 no-cache）
    // 尊重其声明 —— Service Worker 的更新检查依赖该头，不能被覆盖成 no-store
    if !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }

    response
}

// ============================================================================
// Handler 函数
// ============================================================================

/// `GET /` — 重定向到 /dashboard
///
/// **必须原样保留 query string**：前端支持用 `/?access_token=<base64(user:pass)>`
/// 直达（令牌会被写入 sessionStorage 后从地址栏清除）。若这里丢弃 query，
/// 令牌在进入应用前就丢了，用户会看到一个「明明是带令牌打开的却要求登录」的页面。
async fn handle_redirect(uri: axum::http::Uri) -> Redirect {
    match uri.query() {
        Some(query) if !query.is_empty() => Redirect::to(&format!("/dashboard?{query}")),
        _ => Redirect::to("/dashboard"),
    }
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

/// `GET /sw.js` — PWA Service Worker
///
/// 走根路径而非 `/static/sw.js`：Service Worker 的作用域上限由其脚本路径决定，
/// `/static/sw.js` 只能接管 `/static/` 下的请求，无法处理页面导航。
///
/// 必须携带的两个响应头：
/// - `Service-Worker-Allowed: /` — 显式声明根作用域（脚本不在根目录时的唯一方式）
/// - `Cache-Control: no-cache` — 浏览器每次注册/更新检查都必须回源，
///   避免旧 SW 被长期缓存导致无法升级
async fn handle_sw() -> impl IntoResponse {
    match web_ui::get_static_asset("sw.js") {
        Some((data, mime_type)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime_type).expect("MIME 类型为合法 ASCII"),
            );
            headers.insert("Service-Worker-Allowed", HeaderValue::from_static("/"));
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            (StatusCode::OK, headers, data).into_response()
        }
        None => (StatusCode::NOT_FOUND, "404 Not Found\n").into_response(),
    }
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

/// `GET /api/v1/whitelist/recommendations` — 智能白名单推荐
async fn handle_whitelist_recommendations(
) -> Json<web_ui::api::ApiResponse<Vec<web_ui::api::WhitelistRecommendation>>> {
    let recs = web_ui::api::get_whitelist_recommendations();
    Json(web_ui::api::ApiResponse::ok(recs))
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
async fn handle_api_heatmap() -> Response {
    match db_blocking(web_ui::api::get_heatmap).await {
        Ok(heatmap) => Json(web_ui::api::ApiResponse::ok(heatmap)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/recidivism` — 封禁效果追踪（复发率 + TOP 10）
async fn handle_api_recidivism() -> Response {
    match db_blocking(web_ui::api::get_ban_recidivism).await {
        Ok(recidivism) => Json(web_ui::api::ApiResponse::ok(recidivism)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/ban-effectiveness` — 封禁效果分析（按级别统计复发率）
async fn handle_api_ban_effectiveness() -> Response {
    match db_blocking(web_ui::api::get_ban_effectiveness).await {
        Ok(effectiveness) => Json(web_ui::api::ApiResponse::ok(effectiveness)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/periodic-attackers` — 周期性攻击者检测
async fn handle_api_periodic_attackers() -> Response {
    match db_blocking(web_ui::api::get_periodic_attackers).await {
        Ok(attackers) => Json(web_ui::api::ApiResponse::ok(attackers)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/collaborative-attacks` — 协同攻击检测
async fn handle_api_collaborative_attacks() -> Response {
    match db_blocking(web_ui::api::get_collaborative_attacks).await {
        Ok(attacks) => Json(web_ui::api::ApiResponse::ok(attacks)).into_response(),
        Err(msg) => db_error_response(msg),
    }
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
async fn handle_api_ban_duration_recommendations() -> Response {
    match db_blocking(web_ui::api::get_ban_duration_recommendations).await {
        Ok(recs) => Json(web_ui::api::ApiResponse::ok(recs)).into_response(),
        Err(msg) => db_error_response(msg),
    }
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
async fn handle_api_threshold_recommendations() -> Response {
    let recs = db_blocking(|| {
        let jails = crate::http_exporter::get_global_jails();
        crate::history_snapshot::analyze_thresholds(&jails)
    })
    .await;
    match recs {
        Ok(recs) => Json(web_ui::api::ApiResponse::ok(recs)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/network-distribution` — 攻击源网络分布
async fn handle_api_network_distribution() -> Response {
    match db_blocking(crate::history_snapshot::get_network_distribution).await {
        Ok(blocks) => Json(web_ui::api::ApiResponse::ok(blocks)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/stats/attack-predictions` — 攻击时间预测 + Jail 攻击趋势
async fn handle_api_attack_predictions() -> Response {
    match db_blocking(web_ui::api::get_attack_predictions).await {
        Ok(summary) => Json(web_ui::api::ApiResponse::ok(summary)).into_response(),
        Err(msg) => db_error_response(msg),
    }
}

/// `GET /api/v1/logs/stream` — SSE 实时日志流（tail -f 语义）
///
/// 连接位取自进程级共享的 [`crate::api::shared_sse_status`]：与 `/api/v1/events`
/// 同一实例，但日志流有自己的上限（5）。
async fn handle_log_stream() -> axum::response::Response {
    web_ui::log_viewer::handle_log_stream(crate::api::shared_sse_status()).await
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
