//! Prometheus HTTP 导出器: `/metrics` 端点 + `/health` (跳过 auth) + Basic Auth + 暴力破解防护
//!
//! 本文件内 `u64 → i64` 是 Unix 时间戳常规做法;`isize → usize`
//! 来自 `now - last` 表达式(已确认 `now >= last`)
#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss, clippy::cast_possible_truncation)]
//!
//! # 端点清单
//!
//! | 路径 | 方法 | auth | 说明 |
//! |------|------|------|------|
//! | `/health` / `/healthz` | GET | ❌ 跳过 | K8s livenessProbe 用,返回 `{"status":"ok"}` |
//! | `/metrics` | GET | ✅ Basic Auth | Prometheus 抓取入口 |
//! | 其他 | * | * | 404 Not Found |
//!
//! # 安全设计
//!
//! - **Basic Auth 恒定时间比较**:`constant_time_compare` 零填充到等长后做完整
//!   XOR,防止时序攻击泄露密码长度 / 内容
//! - **暴力破解防护**:10 次失败后 60s 内拒绝所有 `/metrics` 请求
//! - **CSP / nosniff / DENY**:防止 XSS / 点击劫持
//! - **/health 豁免 auth**:不拖累 K8s liveness 探针
//!
//! # 指标列表
//!
//! 内核态 (`/proc/firewall/stats` 读取):
//! - `firewall_kernel_banned_ips_current` (gauge)
//! - `firewall_kernel_bans_total` (counter)
//! - `firewall_kernel_unbans_total` (counter)
//! - `firewall_kernel_whitelist_count` (gauge)
//!
//! 用户态 (`DAEMON_STATS`):
//! - `firewall_daemon_lines_parsed_total` / `ips_extracted_total` /
//!   `ips_banned_total` / `failed_attempts_total`
//! - `firewall_daemon_config_reloads_total` / `inotify_events_total` /
//!   `log_rotations_total` / `lines_skipped_total` / `regex_matches_total`
//! - `firewall_daemon_uptime_seconds` (gauge)

use std::io::Cursor;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use tiny_http::{Header, Method, Request, Response, Server, StatusCode};

use crate::types::{Config, DAEMON_STATS};
use crate::{log_err, log_info, log_warn};

// ============================================================================
// 配置参数
// ============================================================================

/// Basic Auth 连续失败次数阈值,达到后触发 [`AUTH_LOCKOUT_DURATION`] 锁定
const AUTH_FAILURE_THRESHOLD: u64 = 10;
/// 锁定持续时间 (秒)。窗口期内所有认证请求一律 401
const AUTH_LOCKOUT_DURATION: i64 = 60;

// ============================================================================
// 运行状态
// ============================================================================

/// 导出器运行标志。`stop_http_exporter` 置 false 后,`incoming_requests` 阻塞
/// 会被 dummy 连接唤醒,然后循环检测到 false 退出
static EXPORTER_RUNNING: AtomicBool = AtomicBool::new(false);
/// 累计认证失败次数。`>= AUTH_FAILURE_THRESHOLD` 触发锁定
static AUTH_FAILURES: AtomicU64 = AtomicU64::new(0);
/// 上次失败时间 (Unix 秒)。用于计算锁定窗口剩余时间
static LAST_FAILURE_TIME: AtomicU64 = AtomicU64::new(0);
/// 导出器实际监听端口 (供 `stop_http_exporter` 发 dummy 唤醒连接)
static EXPORTER_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

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
// 内核统计信息读取
// ============================================================================

/// 从 `/proc/firewall/stats` 解析 4 个内核态指标:当前封禁数 / 总封禁 /
/// 总解封 / 当前白名单数。文件不存在时全部为 0。
///
/// 提前退出:4 个 key 都找到后立即 break,避免读完整文件。
///
/// # Returns
/// `(banned, total_bans, total_unbans, whitelist_count)` 元组
fn read_kernel_stats() -> (u64, u64, u64, u64) {
    let mut banned: u64 = 0;
    let mut total_bans: u64 = 0;
    let mut total_unbans: u64 = 0;
    let mut whitelist_count: u64 = 0;
    let mut has_banned = false;
    let mut has_total_bans = false;
    let mut has_total_unbans = false;
    let mut has_whitelist_count = false;

    if let Ok(content) = std::fs::read_to_string("/proc/firewall/stats") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if let Ok(val) = parts[1].parse::<u64>() {
                    match parts[0] {
                        "current_bans" => {
                            banned = val;
                            has_banned = true;
                        }
                        "total_bans" => {
                            total_bans = val;
                            has_total_bans = true;
                        }
                        "total_unbans" => {
                            total_unbans = val;
                            has_total_unbans = true;
                        }
                        "current_whitelist" => {
                            whitelist_count = val;
                            has_whitelist_count = true;
                        }
                        _ => {}
                    }
                    // 4 个 key 都找到后提前退出
                    if has_banned
                        && has_total_bans
                        && has_total_unbans
                        && has_whitelist_count
                    {
                        break;
                    }
                }
            }
        }
    }

    (banned, total_bans, total_unbans, whitelist_count)
}

// ============================================================================
// 指标生成
// ============================================================================

/// 生成 Prometheus 文本格式 (`text/plain; version=0.0.4`) 的全部指标。
///
/// 包含 4 个内核态 + 10 个用户态 + 1 个 `uptime` gauge。
///
/// # Returns
/// Prometheus exposition 格式字符串
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
fn generate_metrics() -> String {
    let (banned, total_bans, total_unbans, whitelist_count) = read_kernel_stats();

    let lines_parsed = DAEMON_STATS.lines_parsed.load(Ordering::Relaxed);
    let ips_extracted = DAEMON_STATS.ips_extracted.load(Ordering::Relaxed);
    let ips_banned = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
    let failed_attempts = DAEMON_STATS.failed_attempts.load(Ordering::Relaxed);
    let config_reloads = DAEMON_STATS.config_reloads.load(Ordering::Relaxed);
    let inotify_events = DAEMON_STATS.inotify_events.load(Ordering::Relaxed);
    let log_rotations = DAEMON_STATS.log_rotations.load(Ordering::Relaxed);
    let lines_skipped = DAEMON_STATS.lines_skipped.load(Ordering::Relaxed);
    let regex_matches = DAEMON_STATS.regex_matches.load(Ordering::Relaxed);

    let start_time = DAEMON_STATS.start_time.load(Ordering::Relaxed);
    let uptime = if start_time > 0 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - start_time
    } else {
        0
    };

    format!(
        "# HELP firewall_kernel_banned_ips_current Current number of banned IPs in kernel\n\
         # TYPE firewall_kernel_banned_ips_current gauge\n\
         firewall_kernel_banned_ips_current {banned}\n\
         \n\
         # HELP firewall_kernel_bans_total Total number of ban operations in kernel\n\
         # TYPE firewall_kernel_bans_total counter\n\
         firewall_kernel_bans_total {total_bans}\n\
         \n\
         # HELP firewall_kernel_unbans_total Total number of unban operations in kernel\n\
         # TYPE firewall_kernel_unbans_total counter\n\
         firewall_kernel_unbans_total {total_unbans}\n\
         \n\
         # HELP firewall_kernel_whitelist_count Current number of whitelisted IPs\n\
         # TYPE firewall_kernel_whitelist_count gauge\n\
         firewall_kernel_whitelist_count {whitelist_count}\n\
         \n\
         # HELP firewall_daemon_lines_parsed_total Total log lines parsed by daemon\n\
         # TYPE firewall_daemon_lines_parsed_total counter\n\
         firewall_daemon_lines_parsed_total {lines_parsed}\n\
         \n\
         # HELP firewall_daemon_ips_extracted_total Total IP addresses extracted from logs\n\
         # TYPE firewall_daemon_ips_extracted_total counter\n\
         firewall_daemon_ips_extracted_total {ips_extracted}\n\
         \n\
         # HELP firewall_daemon_ips_banned_total Total IP addresses banned by daemon\n\
         # TYPE firewall_daemon_ips_banned_total counter\n\
         firewall_daemon_ips_banned_total {ips_banned}\n\
         \n\
         # HELP firewall_daemon_failed_attempts_total Total failed login attempts detected\n\
         # TYPE firewall_daemon_failed_attempts_total counter\n\
         firewall_daemon_failed_attempts_total {failed_attempts}\n\
         \n\
         # HELP firewall_daemon_config_reloads_total Total configuration reloads\n\
         # TYPE firewall_daemon_config_reloads_total counter\n\
         firewall_daemon_config_reloads_total {config_reloads}\n\
         \n\
         # HELP firewall_daemon_inotify_events_total Total inotify events received\n\
         # TYPE firewall_daemon_inotify_events_total counter\n\
         firewall_daemon_inotify_events_total {inotify_events}\n\
         \n\
         # HELP firewall_daemon_log_rotations_total Total log rotation events detected\n\
         # TYPE firewall_daemon_log_rotations_total counter\n\
         firewall_daemon_log_rotations_total {log_rotations}\n\
         \n\
         # HELP firewall_daemon_lines_skipped_total Total log lines skipped (too long or invalid)\n\
         # TYPE firewall_daemon_lines_skipped_total counter\n\
         firewall_daemon_lines_skipped_total {lines_skipped}\n\
         \n\
         # HELP firewall_daemon_regex_matches_total Total regex pattern matches across all jails\n\
         # TYPE firewall_daemon_regex_matches_total counter\n\
         firewall_daemon_regex_matches_total {regex_matches}\n\
         \n\
         # HELP firewall_daemon_uptime_seconds Daemon uptime in seconds\n\
         # TYPE firewall_daemon_uptime_seconds gauge\n\
         firewall_daemon_uptime_seconds {uptime}\n\
         "
    )
}

// ============================================================================
// Basic Auth
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
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
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
fn check_basic_auth(auth_header: Option<&str>, cfg_user: &str, cfg_pass: &str) -> i32 {
    if cfg_user.is_empty() || cfg_pass.is_empty() {
        return -1;
    }

    // 暴力破解防护: 10 次失败后 60s 内拒绝所有请求
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let last = LAST_FAILURE_TIME.load(Ordering::Relaxed) as i64;
    if AUTH_FAILURES.load(Ordering::Relaxed) >= AUTH_FAILURE_THRESHOLD
        && (now - last) < AUTH_LOCKOUT_DURATION
    {
        log_warn!(
            "Auth temporarily locked due to too many failures ({} failures in {} seconds)",
            AUTH_FAILURES.load(Ordering::Relaxed),
            now - last
        );
        return 0;
    }

    let Some(auth_header) = auth_header else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        return 0;
    };

    if !auth_header.starts_with("Basic ") {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        return 0;
    }

    let Ok(decoded) = STANDARD.decode(&auth_header[6..]) else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        return 0;
    };

    let Ok(decoded_str) = String::from_utf8(decoded) else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        return 0;
    };

    let parts: Vec<&str> = decoded_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        return 0;
    }

    let auth_user = parts[0].as_bytes();
    let auth_pass = parts[1].as_bytes();

    let user_ok = constant_time_compare(auth_user, cfg_user.as_bytes());
    let pass_ok = constant_time_compare(auth_pass, cfg_pass.as_bytes());

    if user_ok && pass_ok {
        AUTH_FAILURES.store(0, Ordering::Relaxed);
        1
    } else {
        AUTH_FAILURES.fetch_add(1, Ordering::Relaxed);
        LAST_FAILURE_TIME.store(
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            Ordering::Relaxed,
        );
        0
    }
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
        let _ = request.respond(add_security_headers(response));
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
            .with_header(Header::from_bytes("WWW-Authenticate", "Basic realm=\"firewall-metrics\"").unwrap());
        let _ = request.respond(add_security_headers(response));
        return;
    }

    if let (&Method::Get, "/metrics") = (request.method(), url.as_str()) {
        let metrics = generate_metrics();
        let response = Response::from_string(metrics)
            .with_header(Header::from_bytes("Content-Type", "text/plain; version=0.0.4; charset=utf-8").unwrap());
        let _ = request.respond(add_security_headers(response));
    } else {
        let body = "404 Not Found\r\n";
        let response = Response::from_string(body).with_status_code(StatusCode(404));
        let _ = request.respond(add_security_headers(response));
    }
}

/// `handle_request` 的可选认证版本。把 `Option<String>` 展开为 `&str` 后透传。
///
/// # Arguments
/// - `request`: HTTP 请求
/// - `metrics_user` / `metrics_pass`: `Option<String>` 形式的凭据 (`None` 视为空)
fn handle_request_with_auth(request: Request, metrics_user: Option<&String>, metrics_pass: Option<&String>) {
    let user = metrics_user.map(String::as_str).unwrap_or_default();
    let pass = metrics_pass.map(String::as_str).unwrap_or_default();
    handle_request(request, user, pass);
}

// ============================================================================
// 启动/停止
// ============================================================================

/// 启动 Prometheus 导出器线程 (后台)。
///
/// 在新线程里 `bind` + 循环处理 `incoming_requests`,直到 `EXPORTER_RUNNING`
/// 被 `stop_http_exporter` 置 false。线程 `JoinHandle` 返回给 `main()` 用于
/// 优雅 join。
///
/// # Arguments
/// - `port`: 监听端口 (`cfg.metrics_port`)
/// - `cfg`: 全局配置 (取 `metrics_*` 字段)
///
/// # Returns
/// 子线程 `JoinHandle<()>`,`main()` 在 cleanup 后 join
#[must_use] 
pub fn start_http_exporter(port: u16, cfg: &Config) -> thread::JoinHandle<()> {
    let metrics_user = cfg.metrics_username.clone();
    let metrics_pass = cfg.metrics_password.clone();
    let bind_address = if cfg.metrics_bind_address.is_empty() {
        "127.0.0.1".to_string()
    } else {
        cfg.metrics_bind_address.clone()
    };

    thread::spawn(move || {
        let addr = format!("{bind_address}:{port}");
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                log_err!("Failed to bind to {}: {}", addr, e);
                return;
            }
        };

        let server = match Server::from_listener(listener, None) {
            Ok(s) => s,
            Err(e) => {
                log_err!("Failed to create HTTP server: {}", e);
                return;
            }
        };

        EXPORTER_RUNNING.store(true, Ordering::Relaxed);
        EXPORTER_PORT.store(port, Ordering::Relaxed);
        log_info!("Prometheus exporter started on port {}", port);

        loop {
            if !EXPORTER_RUNNING.load(Ordering::Relaxed) {
                break;
            }
            if let Some(request) = server.incoming_requests().next() {
                handle_request_with_auth(request, metrics_user.as_ref(), metrics_pass.as_ref());
            } else {
                break;
            }
        }

        EXPORTER_RUNNING.store(false, Ordering::Relaxed);
        log_info!("Prometheus exporter stopped");
    })
}

/// 优雅停止导出器:置 `EXPORTER_RUNNING=false` + 发 dummy TCP 连接唤醒
/// `incoming_requests` 阻塞。
///
/// # Panics
/// `addr.parse().unwrap()` 仅在 `addr` 不是合法 IP:port 时 panic。
/// `addr` 是 `"{}:{}"` 形式字符串(刚由 `format!` 拼接),实际不可能
pub fn stop_http_exporter() {
    EXPORTER_RUNNING.store(false, Ordering::Relaxed);
    // 发个 dummy 连接唤醒阻塞的 incoming_requests()
    let port = EXPORTER_PORT.load(Ordering::Relaxed);
    if port > 0 {
        use std::net::TcpStream;
        use std::time::Duration;
        let addr = format!("127.0.0.1:{port}");
        let _ = TcpStream::connect_timeout(
            &addr.parse().unwrap(),
            Duration::from_millis(10),
        );
    }
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_compare_equal() {
        assert!(constant_time_compare(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_compare_different_length() {
        assert!(!constant_time_compare(b"hello", b"hell"));
    }

    #[test]
    fn constant_time_compare_different_content() {
        assert!(!constant_time_compare(b"hello", "world".as_bytes()));
    }

    #[test]
    fn check_basic_auth_no_config() {
        let result = check_basic_auth(Some("Basic dXNlcjpwYXNz"), "", "");
        assert_eq!(result, -1);
    }

    #[test]
    fn check_basic_auth_valid() {
        // admin:secret → YWRtaW46c2VjcmV0
        let result = check_basic_auth(Some("Basic YWRtaW46c2VjcmV0"), "admin", "secret");
        assert_eq!(result, 1);
    }

    #[test]
    fn check_basic_auth_invalid() {
        // wrong:password → d3Jvbmc6cGFzc3dvcmQ
        let result = check_basic_auth(Some("Basic d3Jvbmc6cGFzc3dvcmQ"), "admin", "secret");
        assert_eq!(result, 0);
    }

    #[test]
    fn generate_metrics_contains_expected() {
        let metrics = generate_metrics();
        assert!(metrics.contains("firewall_kernel_banned_ips_current"));
        assert!(metrics.contains("firewall_daemon_lines_parsed_total"));
        assert!(metrics.contains("firewall_daemon_uptime_seconds"));
    }
}
