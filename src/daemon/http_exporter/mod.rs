//! Prometheus HTTP 导出器: `/metrics` 端点 + `/health` (跳过 auth) + Basic Auth + 暴力破解防护
//!
//! # 模块结构
//!
//! - `metrics`: 内核统计读取 + Prometheus 指标生成
//! - `auth`: Basic Auth 验证 + 暴力破解防护
//! - `handler`: HTTP 请求处理 + 安全头 + 路由分发
//! - `lifecycle`: 导出器启动/停止 + 运行状态管理

mod auth;
mod handler;
mod lifecycle;
mod metrics;

pub use lifecycle::{start_http_exporter, stop_http_exporter};

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
static EXPORTER_RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// 导出器实际监听端口 (供 `stop_http_exporter` 发 dummy 唤醒连接)
static EXPORTER_PORT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

/// Basic Auth 暴力破解防护状态 — 连续失败计数 + 最后失败时间
///
/// 两个原子量总是一起读写（`check_basic_auth` 失败时同时更新），
/// 聚合为一个 struct 减少全局 static 数量并明确逻辑关联。
pub(super) struct AuthFailureState {
    /// 累计认证失败次数。`>= AUTH_FAILURE_THRESHOLD` 触发锁定
    pub failures: std::sync::atomic::AtomicU64,
    /// 上次失败时间 (Unix 秒)。用于计算锁定窗口剩余时间
    pub last_failure_time: std::sync::atomic::AtomicU64,
}

impl AuthFailureState {
    pub const fn new() -> Self {
        Self {
            failures: std::sync::atomic::AtomicU64::new(0),
            last_failure_time: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

impl Default for AuthFailureState {
    fn default() -> Self {
        Self::new()
    }
}

static AUTH_STATE: AuthFailureState = AuthFailureState::new();

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::auth::check_basic_auth;
    use super::auth::constant_time_compare;
    use super::metrics::generate_metrics;

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
