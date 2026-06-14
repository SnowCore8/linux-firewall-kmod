//! HTTP 请求处理 + 安全头 + 路由分发

use std::io::Cursor;

use tiny_http::{Header, Method, Request, Response, StatusCode};

use super::auth::check_basic_auth;
use super::metrics::generate_metrics;

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
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap())
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").unwrap())
        .with_header(Header::from_bytes("X-Content-Security-Policy", "default-src 'none'").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
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
        let response = Response::from_string(body)
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
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
                Header::from_bytes("WWW-Authenticate", "Basic realm=\"firewall-metrics\"").unwrap(),
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
            Header::from_bytes("Content-Type", "text/plain; version=0.0.4; charset=utf-8").unwrap(),
        );
        if let Err(e) = request.respond(add_security_headers(response)) {
            crate::logger::warn!(
                crate::logger::get(),
                "发送 /metrics 响应失败";
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
