//! Basic Auth 验证 + 暴力破解防护 + axum middleware 适配

use std::sync::atomic::Ordering;

use axum::{
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};

use super::{AUTH_FAILURE_THRESHOLD, AUTH_LOCKOUT_DURATION, AUTH_STATE};
use crate::types::now_secs;

// ============================================================================
// Basic Auth 核心逻辑
// ============================================================================

/// 恒定时间字符串比较:零填充到等长后做完整 XOR,防止时序攻击泄露密码长度 / 内容。
///
/// 标准 `==` 在不同长度 / 不同前缀时会以不同时间返回,攻击者可通过响应时延
/// 推断密码前缀。本函数对全部字节做 XOR 累加,无论是否匹配耗时相同。
///
/// # Arguments
/// - `a` / `b`: 待比较字节切片
///
/// # Returns
/// 完全相等时 `true`(包括两个都为空)
pub(super) fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    if max_len == 0 {
        return true;
    }

    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    let mut result: u8 = 0;
    for (x, y) in a_padded.iter().zip(b_padded.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// 验证 Basic Auth 凭据。
///
/// 返回:1=通过,0=失败 / 锁定,-1=未配置认证 (跳过)。
///
/// # Arguments
/// - `auth_header`: HTTP `Authorization` 头值 (raw)
/// - `cfg_user` / `cfg_pass`: 配置的用户名 / 密码
pub(super) fn check_basic_auth(auth_header: Option<&str>, cfg_user: &str, cfg_pass: &str) -> i32 {
    if cfg_user.is_empty() || cfg_pass.is_empty() {
        return -1;
    }

    // 暴力破解防护: 10 次失败后 60s 内拒绝所有请求
    let now = now_secs();
    let last = AUTH_STATE.last_failure_time.load(Ordering::Relaxed) as i64;
    if AUTH_STATE.failures.load(Ordering::Relaxed) >= AUTH_FAILURE_THRESHOLD
        && (now - last) < AUTH_LOCKOUT_DURATION
    {
        return 0;
    }

    let Some(auth_header) = auth_header else {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        return 0;
    };

    if !auth_header.starts_with("Basic ") {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        return 0;
    }

    let Ok(decoded) = STANDARD.decode(&auth_header[6..]) else {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        return 0;
    };

    let Ok(decoded_str) = String::from_utf8(decoded) else {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        return 0;
    };

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        return 0;
    }

    let auth_user = parts[0].as_bytes();
    let auth_pass = parts[1].as_bytes();

    let user_ok = constant_time_compare(auth_user, cfg_user.as_bytes());
    let pass_ok = constant_time_compare(auth_pass, cfg_pass.as_bytes());

    if user_ok && pass_ok {
        AUTH_STATE.failures.store(0, Ordering::Relaxed);
        1
    } else {
        AUTH_STATE.failures.fetch_add(1, Ordering::Relaxed);
        AUTH_STATE
            .last_failure_time
            .store(now_secs() as u64, Ordering::Relaxed);
        0
    }
}

// ============================================================================
// axum middleware 适配
// ============================================================================

/// Basic Auth 中间件状态（通过 axum Extension 传递）
#[derive(Clone)]
pub struct AuthCredentials {
    pub username: String,
    pub password: String,
}

/// axum Basic Auth middleware。
///
/// 从请求头提取 `Authorization`，调用 `check_basic_auth` 验证。
/// 若无 header，则尝试 query `access_token`（Base64(`user:pass`)），供 EventSource 使用。
/// 通过则放行，失败则返回 401 + `WWW-Authenticate` 头。
pub async fn auth_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // 从 Extension 获取凭据（在 Router 中通过 layer 注入）
    let creds = request
        .extensions()
        .get::<AuthCredentials>()
        .cloned()
        .unwrap_or(AuthCredentials {
            username: String::new(),
            password: String::new(),
        });

    let mut auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // EventSource 无法自定义 Authorization：允许 ?access_token=<base64(user:pass)>
    if auth_header.is_none() {
        if let Some(query) = request.uri().query() {
            for pair in query.split('&') {
                if let Some(token) = pair.strip_prefix("access_token=") {
                    if !token.is_empty() {
                        auth_header = Some(format!("Basic {token}"));
                    }
                    break;
                }
            }
        }
    }

    let result = check_basic_auth(auth_header.as_deref(), &creds.username, &creds.password);

    match result {
        1 | -1 => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            [(
                axum::http::header::WWW_AUTHENTICATE,
                "Basic realm=\"firewall-metrics\"",
            )],
            "401 Unauthorized\n",
        )
            .into_response(),
    }
}
