//! Prometheus HTTP 导出器: `/metrics` 端点 + `/health` (跳过 auth) + Basic Auth + 暴力破解防护
//!
//! # 模块结构
//!
//! - `metrics`: 内核统计读取 + Prometheus 指标生成
//! - `auth`: Basic Auth 验证 + 暴力破解防护 + axum middleware
//! - `handler`: HTTP 路由构建 + handler 函数 + 安全头中间件
//! - `lifecycle`: HTTP 服务启动/停止 + tokio runtime 管理

pub(crate) mod auth;
mod handler;
mod lifecycle;
mod metrics;

pub use lifecycle::{start_http_exporter, stop_http_exporter};

/// 渲染 Prometheus 指标文本。
///
/// 供 `api::adapters` 的临时运行时端口使用；`metrics` 重写后此转发删除。
pub fn render_prometheus_metrics() -> String {
    metrics::generate_metrics()
}

/// 更新运行期 HTTP Basic Auth 凭据（SIGHUP 热重载时调用）。
///
/// 空/半配置语义见 `auth::set_auth_credentials`。
pub fn set_http_auth_credentials(user: &str, pass: &str) {
    auth::set_auth_credentials(user, pass);
}

/// 检查 HTTP 导出器是否正在运行
pub fn is_exporter_running() -> bool {
    EXPORTER_RUNNING.load(std::sync::atomic::Ordering::Relaxed)
}

// ============================================================================
// 全局 Jail 信息存储（支持热更新）
// ============================================================================

/// 简化的 Jail 信息（用于 /api/jails 端点，避免存储包含 RwLock 的完整 Config）
#[derive(Clone)]
pub struct JailInfo {
    pub name: String,
    pub enabled: bool,
    /// 触发封禁的失败次数阈值
    pub max_retries: u32,
    /// 滑动窗口大小（秒）
    pub findtime: u32,
    /// 封禁时长（秒），-1 表示永久
    pub ban_time: i32,
}

/// 全局 Jail 信息存储（使用 OnceLock<RwLock> 支持热更新，兼容 Rust 1.75 MSRV）
pub static GLOBAL_JAILS: std::sync::OnceLock<parking_lot::RwLock<Vec<JailInfo>>> =
    std::sync::OnceLock::new();

/// 设置全局 Jail 信息（启动时和热重载时调用）
pub fn set_global_jails(jails: Vec<JailInfo>) {
    let lock = GLOBAL_JAILS.get_or_init(|| parking_lot::RwLock::new(Vec::new()));
    *lock.write() = jails;
}

/// 获取全局 Jail 信息（在 handler 中调用）
pub fn get_global_jails() -> Vec<JailInfo> {
    GLOBAL_JAILS
        .get()
        .map(|lock| lock.read().clone())
        .unwrap_or_default()
}

// ============================================================================
// 全局 Web UI 配置存储（支持热更新）
// ============================================================================

/// 全局 Web UI 配置存储（使用 OnceLock<RwLock> 支持热更新，兼容 Rust 1.75 MSRV）
static GLOBAL_WEBUI_CONFIG: std::sync::OnceLock<
    parking_lot::RwLock<Option<crate::types::WebuiConfig>>,
> = std::sync::OnceLock::new();

/// 设置全局 Web UI 配置（启动时和热重载时调用）
pub fn set_global_webui_config(config: crate::types::WebuiConfig) {
    let lock = GLOBAL_WEBUI_CONFIG.get_or_init(|| parking_lot::RwLock::new(None));
    *lock.write() = Some(config);
}

/// 获取全局 Web UI 配置（在 handler 中调用）
pub fn get_global_webui_config() -> Option<crate::types::WebuiConfig> {
    GLOBAL_WEBUI_CONFIG
        .get()
        .and_then(|lock| lock.read().clone())
}

// ============================================================================
// 全局 DDoS 决策引擎引用（供配置热重载使用）
// ============================================================================

use crate::decision::DdosDecisionEngine;
use std::sync::Arc;

/// 全局决策引擎引用（供配置热重载时同步到内核）
static GLOBAL_DECISION_ENGINE: std::sync::OnceLock<Arc<DdosDecisionEngine>> =
    std::sync::OnceLock::new();

/// 设置全局决策引擎引用（启动时调用）
pub fn set_global_decision_engine(engine: Arc<DdosDecisionEngine>) {
    let _ = GLOBAL_DECISION_ENGINE.set(engine);
}

/// 获取全局决策引擎引用
pub fn get_global_decision_engine() -> Option<&'static Arc<DdosDecisionEngine>> {
    GLOBAL_DECISION_ENGINE.get()
}

// ============================================================================
// 配置参数
// ============================================================================

/// Basic Auth 连续失败次数阈值,达到后触发 [`AUTH_LOCKOUT_DURATION`] 锁定
pub(crate) const AUTH_FAILURE_THRESHOLD: u64 = 10;
/// 锁定持续时间 (秒)。窗口期内所有认证请求一律 401
pub(crate) const AUTH_LOCKOUT_DURATION: i64 = 60;

// ============================================================================
// 运行状态
// ============================================================================

/// 导出器运行标志。`stop_http_exporter` 置 false 后,
/// tokio runtime 内的 shutdown 循环检测到后触发 axum graceful_shutdown
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
    use super::auth::access_token_from_query;
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
    fn check_basic_auth_half_config_is_rejected() {
        // 只配置了其中一项时不得跳过认证（历史缺陷：任一为空即返回 -1 放行）
        // 该分支不触碰 AUTH_STATE，故与其它测试无相互影响
        assert_eq!(
            check_basic_auth(None, "admin", ""),
            0,
            "密码为空时必须拒绝，不得跳过认证"
        );
        assert_eq!(
            check_basic_auth(None, "", "secret"),
            0,
            "用户名为空时必须拒绝，不得跳过认证"
        );
        // 即便请求头看似合法，半配置也不放行
        assert_eq!(check_basic_auth(Some("Basic YWRtaW46"), "admin", ""), 0);
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
    fn access_token_is_percent_decoded() {
        // 前端用 encodeURIComponent 编码 base64 令牌：`=` 变 `%3D`，`+` 变 `%2B`。
        // 不还原就会把 `%3D%3D` 当令牌内容，base64 解出乱码 → SSE 永久 401。
        assert_eq!(
            access_token_from_query(Some("access_token=ZTJlOmUyZS1wYXNzd29yZA%3D%3D")).as_deref(),
            Some("ZTJlOmUyZS1wYXNzd29yZA==")
        );
    }

    #[test]
    fn access_token_keeps_plus_as_a_base64_character() {
        // `+` 是 base64 字母表成员：这里必须是百分号解码（`%2B`→`+`），
        // 不能按表单规则把裸 `+` 当空格，否则同一串会解出另一个令牌。
        assert_eq!(
            access_token_from_query(Some("access_token=a%2Bb")).as_deref(),
            Some("a+b")
        );
        assert_eq!(
            access_token_from_query(Some("access_token=a+b")).as_deref(),
            Some("a+b")
        );
    }

    #[test]
    fn access_token_ignores_other_query_keys() {
        assert_eq!(
            access_token_from_query(Some("page=1&access_token=abc&sort=ip")).as_deref(),
            Some("abc")
        );
        // 无令牌 / 空值 / 无 query 一律返回 None（调用方据此不发 Authorization 头）
        assert_eq!(access_token_from_query(Some("page=1")), None);
        assert_eq!(access_token_from_query(Some("access_token=")), None);
        assert_eq!(access_token_from_query(None), None);
    }

    #[test]
    fn generate_metrics_contains_expected() {
        let metrics = generate_metrics();
        assert!(metrics.contains("firewall_kernel_banned_ips_current"));
        assert!(metrics.contains("firewall_daemon_lines_parsed_total"));
        assert!(metrics.contains("firewall_daemon_uptime_seconds"));
        assert!(metrics.contains("firewall_netlink_messages_sent_total"));
        assert!(metrics.contains("firewall_netlink_messages_received_total"));
        assert!(metrics.contains("firewall_netlink_send_errors_total"));
        assert!(metrics.contains("firewall_netlink_recv_errors_total"));
        assert!(metrics.contains("firewall_reputation_tracked_ips"));
        assert!(metrics.contains("firewall_reputation_low_count"));
        assert!(metrics.contains("firewall_reputation_critical_count"));
        assert!(metrics.contains("firewall_anomaly_global_score"));
        assert!(metrics.contains("firewall_anomaly_anomalous_ips"));
    }
}
