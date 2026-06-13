//! 配置结构
//!
//! # 核心结构
//!
//! - **`Config`**:全局配置 (CLI / YAML / 默认值三路合并的最终结果)
//!
//! # 字段分组
//!
//! - **Jail 缺省参数**:`default_*` 在 `apply_smart_defaults_to_all` 阶段对未
//!   显式设置的 Jail 生效
//! - **行为开关**:`daemon` (是否后台化) / `permanent_ban_enabled` (`SQLite` 同步)
//! - **Metrics 端点**:`metrics_port` / `metrics_bind_address` / `metrics_username`
//!   / `metrics_password`
//! - **日志系统**:`log_file` / `log_level` / `log_destination` / `log_format`
//! - **配置来源追踪**:`config_file` / `config_dir` (SIGHUP 重载时复用)

use super::{Jail, MAX_JAILS};

// ============================================================================
// 配置结构
// ============================================================================

/// 全局配置 (CLI / YAML / 默认值三路合并的最终结果)。
///
/// 字段分组:
/// - **Jail 缺省参数**:`default_*` 在 `apply_smart_defaults_to_all` 阶段对未
///   显式设置的 Jail 生效
/// - **行为开关**:`daemon` (是否后台化) / `permanent_ban_enabled` (`SQLite` 同步)
/// - **Metrics 端点**:`metrics_port` / `metrics_bind_address` / `metrics_username`
///   / `metrics_password`
/// - **日志系统**:`log_file` / `log_level` / `log_destination` / `log_format`
/// - **配置来源追踪**:`config_file` / `config_dir` (SIGHUP 重载时复用)
#[derive(Debug)]
pub struct Config {
    /// Jail 未显式配置 `max_retries` 时使用的全局默认
    pub default_max_retries: u32,
    pub default_findtime: u32,
    pub default_ban_time: u32,
    /// 是否以守护进程模式运行 (`-d` / `--daemon`)
    pub daemon: bool,
    /// 主循环 poll 超时 (秒)。`config_validate` 要求 1..=60
    pub interval: u32,
    /// Prometheus 导出器监听端口。`0` = 禁用
    pub metrics_port: u16,
    /// 监听地址 (默认 `127.0.0.1`)
    pub metrics_bind_address: String,
    /// `/metrics` 端点 Basic Auth 用户名。None 或空 = 跳过认证
    pub metrics_username: Option<String>,
    pub metrics_password: Option<String>,
    /// 已加载的配置文件路径。SIGHUP 重载时复用
    pub config_file: Option<String>,
    /// 已加载的配置目录路径。SIGHUP 重载时复用
    pub config_dir: Option<String>,
    /// 永久黑名单 `SQLite` 数据库路径
    pub permanent_db_path: Option<String>,
    /// 是否启用永久黑名单持久化
    pub permanent_ban_enabled: bool,
    /// 独立日志文件路径 (覆盖默认 syslog)
    pub log_file: Option<String>,
    /// 日志级别 (0..=4, 见 `log::LOG_LEVEL_*`)
    pub log_level: u8,
    /// 日志目的地 (0..=3, 见 `log::LogDestination`)
    pub log_destination: u8,
    /// 日志格式 (0..=1, 见 `log::LogFormat`)
    pub log_format: u8,
    /// YAML 严格模式开关。开启时未知 key 直接报错退出
    pub strict_mode: bool,
    /// 已加载的 Jail 列表
    pub jails: Vec<Jail>,
}

impl Default for Config {
    /// 与 C 版 `config_defaults` 严格一致的默认值。
    ///
    /// 任何字段的修改都必须验证 111 项集成测试仍能通过,以保证
    /// C ↔ Rust 行为等价。
    fn default() -> Self {
        Self {
            default_max_retries: 3,
            default_findtime: 600,
            default_ban_time: 600,
            daemon: false,
            interval: 1,
            metrics_port: 9119,
            metrics_bind_address: "127.0.0.1".to_string(),
            metrics_username: None,
            metrics_password: None,
            config_file: None,
            config_dir: None,
            permanent_db_path: None,
            permanent_ban_enabled: false,
            log_file: None,
            log_level: 3,       // INFO
            log_destination: 2, // BOTH
            log_format: 0,      // PLAIN
            strict_mode: true,
            jails: Vec::with_capacity(MAX_JAILS),
        }
    }
}
