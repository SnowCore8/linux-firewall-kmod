//! HTTP 请求处理 + 安全头 + 路由分发

use std::io::Cursor;

use tiny_http::{Header, Method, Request, Response, StatusCode};

use super::auth::check_basic_auth;
use super::metrics::generate_metrics;
use crate::web_ui;

// ============================================================================
// 安全头
// ============================================================================

/// 给响应添加 4 个安全头:`X-Content-Type-Options` / `X-Frame-Options` /
/// `X-Content-Security-Policy` / `Cache-Control: no-store`。
///
/// # Arguments
/// - `response`: 原始 `tiny_http` 响应
///
/// # Panics
/// `Header::from_bytes` 仅在 header 名/值含非 ASCII 或 CRLF 时 panic。
/// 4 个 header 名 + 值都是静态 ASCII 字符串,实际不可能 panic
fn add_security_headers(response: Response<Cursor<Vec<u8>>>) -> Response<Cursor<Vec<u8>>> {
    response
        .with_header(
            Header::from_bytes("X-Content-Type-Options", "nosniff").expect("静态 ASCII 头"),
        )
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").expect("静态 ASCII 头"))
        .with_header(
            Header::from_bytes("X-Content-Security-Policy", "default-src 'none'")
                .expect("静态 ASCII 头"),
        )
        .with_header(Header::from_bytes("Cache-Control", "no-store").expect("静态 ASCII 头"))
}

// ============================================================================
// 请求处理
// ============================================================================

/// 单个 HTTP 请求的分发器:路由到 `/health` / `/metrics` / 404。
///
/// `/health` 走完全跳过 auth 路径,其他路径先 auth 再分发。
///
/// # Arguments
/// - `request`: 来自 `tiny_http` 的请求
/// - `cfg_user` / `cfg_pass`: Basic Auth 凭据 (空 = 跳过 auth)
fn handle_request(request: Request, cfg_user: &str, cfg_pass: &str) {
    let url = request.url().to_string();

    // /health 和 /healthz 完全跳过 Basic Auth, 即使配置了认证
    // 供 K8s livenessProbe 等场景使用, 不应被 auth 拖累
    if url == "/health" || url == "/healthz" {
        let body = "{\"status\":\"ok\"}\n";
        let response = Response::from_string(body).with_header(
            Header::from_bytes("Content-Type", "application/json").expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /health 响应失败";
                "error" => %e
            );
        }
        return;
    }

    let auth_header = request
        .headers()
        .iter()
        .find(|h| h.field.as_str() == "Authorization")
        .map(|h| h.value.as_str());

    let auth_result = check_basic_auth(auth_header, cfg_user, cfg_pass);
    if auth_result == 0 {
        let body = "401 Unauthorized\r\n";
        let response = Response::from_string(body)
            .with_status_code(StatusCode(401))
            .with_header(
                Header::from_bytes("WWW-Authenticate", "Basic realm=\"firewall-metrics\"")
                    .expect("静态 ASCII 头"),
            );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 401 响应失败";
                "error" => %e
            );
        }
        return;
    }

    if let (&Method::Get, "/metrics") = (request.method(), url.as_str()) {
        let metrics = generate_metrics();
        let response = Response::from_string(metrics).with_header(
            Header::from_bytes("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                .expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /metrics 响应失败";
                "error" => %e
            );
        }
    } else if let (&Method::Get, "/") = (request.method(), url.as_str()) {
        // 根路径重定向到 /dashboard
        let response = Response::from_string("")
            .with_status_code(StatusCode(302))
            .with_header(Header::from_bytes("Location", "/dashboard").expect("静态 ASCII 头"));
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送重定向响应失败";
                "error" => %e
            );
        }
    } else if let (&Method::Get, "/dashboard") = (request.method(), url.as_str()) {
        // Dashboard 页面
        let html = web_ui::render_dashboard();
        let response = Response::from_string(html).with_header(
            Header::from_bytes("Content-Type", "text/html; charset=utf-8").expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /dashboard 响应失败";
                "error" => %e
            );
        }
    } else if url.starts_with("/static/") {
        // 静态资源
        let path = url.trim_start_matches("/static/");
        if let Some((data, mime_type)) = web_ui::get_static_asset(path) {
            let response = Response::from_data(data)
                .with_header(Header::from_bytes("Content-Type", mime_type).expect("静态 ASCII 头"));
            if let Err(e) = request.respond(add_security_headers(response)) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "发送静态资源失败";
                    "path" => path,
                    "error" => %e
                );
            }
        } else {
            let body = "404 Not Found\r\n";
            let response = Response::from_string(body).with_status_code(StatusCode(404));
            if let Err(e) = request.respond(add_security_headers(response)) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "发送 404 响应失败";
                    "error" => %e
                );
            }
        }
    } else if let (&Method::Get, "/api/stats") = (request.method(), url.as_str()) {
        // API: 统计数据
        let stats = web_ui::api::get_stats();
        let json = serde_json::to_string(&stats).unwrap_or_else(|_| "{}".to_string());
        let response = Response::from_string(json).with_header(
            Header::from_bytes("Content-Type", "application/json").expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /api/stats 响应失败";
                "error" => %e
            );
        }
    } else if let (&Method::Get, "/api/bans") = (request.method(), url.as_str()) {
        // API: 活跃封禁列表
        let bans = web_ui::api::get_active_bans();
        let json = serde_json::to_string(&bans).unwrap_or_else(|_| "[]".to_string());
        let response = Response::from_string(json).with_header(
            Header::from_bytes("Content-Type", "application/json").expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /api/bans 响应失败";
                "error" => %e
            );
        }
    } else if let (&Method::Get, "/api/jails") = (request.method(), url.as_str()) {
        // API: Jail 列表（从全局 Jail 信息读取）
        let jails = if let Some(jail_infos) = super::get_global_jails() {
            web_ui::api::get_jails(jail_infos)
        } else {
            Vec::new()
        };
        let json = serde_json::to_string(&jails).unwrap_or_else(|_| "[]".to_string());
        let response = Response::from_string(json).with_header(
            Header::from_bytes("Content-Type", "application/json").expect("静态 ASCII 头"),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /api/jails 响应失败";
                "error" => %e
            );
        }
    } else if let (&Method::Get, "/api/events") = (request.method(), url.as_str()) {
        // SSE: 实时事件推送（Server-Sent Events）
        web_ui::sse::handle_sse_connection(request);
    } else {
        let body = "404 Not Found\r\n";
        let response = Response::from_string(body).with_status_code(StatusCode(404));
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 404 响应失败";
                "error" => %e
            );
        }
    }
}

/// `handle_request` 的可选认证版本。把 `Option<String>` 展开为 `&str` 后透传。
///
/// # Arguments
/// - `request`: HTTP 请求
/// - `metrics_user` / `metrics_pass`: `Option<String>` 形式的凭据 (`None` 视为空)
pub(super) fn handle_request_with_auth(
    request: Request,
    metrics_user: Option<&String>,
    metrics_pass: Option<&String>,
) {
    let user = metrics_user.map(String::as_str).unwrap_or_default();
    let pass = metrics_pass.map(String::as_str).unwrap_or_default();
    handle_request(request, user, pass);
}
