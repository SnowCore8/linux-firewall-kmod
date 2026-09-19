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
/// **未配置**的判定是「用户名与密码**都**为空」。半配置（只给了其中一项）
/// 一律按失败处理而**不放行**——否则一个配置笔误就会让 `/api/v1/**` 完全开放。
///
/// # Arguments
/// - `auth_header`: HTTP `Authorization` 头值 (raw)
/// - `cfg_user` / `cfg_pass`: 配置的用户名 / 密码
pub(super) fn check_basic_auth(auth_header: Option<&str>, cfg_user: &str, cfg_pass: &str) -> i32 {
    // 显式未配置：两项都为空 → 由调用方决定是否放行（启动守卫已拒绝非回环下的这种情况）
    if cfg_user.is_empty() && cfg_pass.is_empty() {
        return -1;
    }
    // 半配置：任一项为空即视为无效配置，拒绝而非跳过
    if cfg_user.is_empty() || cfg_pass.is_empty() {
        return 0;
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

/// 运行期 HTTP Basic Auth 凭据。
///
/// 启动时设置一次，SIGHUP 热重载时更新。`None` 表示完全未配置认证
/// （中间件将放行；非回环绑定下的这种情况已在启动守卫阶段被拒绝）。
pub(super) static AUTH_CREDENTIALS: std::sync::OnceLock<
    parking_lot::RwLock<Option<(String, String)>>,
> = std::sync::OnceLock::new();

/// 设置 / 更新运行期凭据。
///
/// 用户名与密码都为空时归一化为 `None`（= 关闭认证）；半配置（只给一项）时
/// 保留原值，由 `check_basic_auth` 判为失败，避免误放行。
pub(crate) fn set_auth_credentials(user: &str, pass: &str) {
    let creds = if user.is_empty() && pass.is_empty() {
        None
    } else {
        Some((user.to_string(), pass.to_string()))
    };
    *AUTH_CREDENTIALS
        .get_or_init(|| parking_lot::RwLock::new(None))
        .write() = creds;
}

/// 读取运行期凭据的快照（微秒级读锁，不持有到请求处理结束）。
fn current_credentials() -> Option<(String, String)> {
    AUTH_CREDENTIALS
        .get_or_init(|| parking_lot::RwLock::new(None))
        .read()
        .clone()
}

/// axum Basic Auth middleware。
///
/// 从请求头提取 `Authorization`，调用 `check_basic_auth` 验证。
/// 若无 header，则尝试 query `access_token`（Base64(`user:pass`)），供 EventSource 使用。
/// 通过则放行，失败则返回 401。
///
/// 凭据每请求读取运行期存储，因此 SIGHUP 修改配置后立即生效，无需重启。
///
/// **不发送 `WWW-Authenticate` 头（有意为之）**：该头会让浏览器对 401 弹出原生
/// 凭据对话框，并且对话框弹出期间 `fetch` 会一直挂起、拿不到响应——表现为
/// 「登录时输错密码，按钮永久转圈」。本项目的登录页是应用内表单，凭据由前端显式
/// 携带，无需浏览器代劳，因此对 `/api/v1/**` 与 `/metrics` 一律不广告 Basic 认证。
/// （严格 HTTP 语义下 401 应带该头；此处为可用性刻意偏离，错误码仍保留 401
/// 以便前端识别为「凭据问题」而非「无权限」。）
pub async fn auth_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    // 每请求读取运行期凭据（支持热重载）；未配置时放行
    let Some((cfg_user, cfg_pass)) = current_credentials() else {
        return next.run(request).await;
    };

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

    let result = check_basic_auth(auth_header.as_deref(), &cfg_user, &cfg_pass);

    match result {
        1 => next.run(request).await,
        _ => (StatusCode::UNAUTHORIZED, "401 Unauthorized\n").into_response(),
    }
}
