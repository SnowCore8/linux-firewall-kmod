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
//! - **行为开关**:`daemon` (是否后台化)
//! - **Metrics 端点**:`metrics_port` / `metrics_bind_address` / `metrics_username`
//!   / `metrics_password`
//! - **日志系统**:`log_file` / `log_level` / `log_destination` / `log_format`
//! - **配置来源追踪**:`config_file` / `config_dir` (SIGHUP 重载时复用)

use super::jail::{Jail, MAX_JAILS};

// ============================================================================
// Web UI 配置
// ============================================================================

/// Web UI 配置（SSE 推送和速率告警阈值）
#[derive(Debug, Clone)]
pub struct WebuiConfig {
    /// SSE 推送间隔（秒）
    pub sse_push_interval: u32,
    /// 速率警告阈值（包/秒）
    pub rate_warning_pps: u64,
    /// 速率严重告警阈值（包/秒）
    pub rate_critical_pps: u64,
    /// SYN 速率警告阈值（包/秒）
    pub rate_warning_syn: u64,
    /// SYN 速率严重告警阈值（包/秒）
    pub rate_critical_syn: u64,
}

impl Default for WebuiConfig {
    fn default() -> Self {
        Self {
            sse_push_interval: 1,
            rate_warning_pps: 1000,
            rate_critical_pps: 10000,
            rate_warning_syn: 100,
            rate_critical_syn: 1000,
        }
    }
}

// ============================================================================
// 配置结构
// ============================================================================

/// 全局配置 (CLI / YAML / 默认值三路合并的最终结果)。
///
/// 字段分组:
/// - **Jail 缺省参数**:`default_*` 在 `apply_smart_defaults_to_all` 阶段对未
///   显式设置的 Jail 生效
/// - **行为开关**:`daemon` (是否后台化)
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
    /// 混合存储配置 (Phase 1 新增)
    pub storage: StorageConfig,
    /// DDoS 防护配置 (Phase 3 新增)
    pub ddos: super::DdosConfig,
    /// Web UI 配置（SSE 推送和速率告警阈值）
    pub webui: WebuiConfig,
}

impl Default for Config {
    /// 与 C 版 `config_defaults` 严格一致的默认值。
    ///
    /// 任何字段的修改都必须验证 111 项集成测试仍能通过，以保证
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
            log_file: None,
            log_level: 3,       // INFO
            log_destination: 2, // BOTH
            log_format: 0,      // PLAIN
            strict_mode: true,
            jails: Vec::with_capacity(MAX_JAILS),
            storage: StorageConfig::default(),
            ddos: super::DdosConfig::default(),
            webui: WebuiConfig::default(),
        }
    }
}

// ============================================================================
// 存储配置
// ============================================================================

/// 数据保留策略配置
#[derive(Debug, Clone)]
pub struct RetentionConfig {
    /// 封禁历史保留天数 (默认 90)
    pub ban_history_days: u32,
    /// 失败日志保留天数 (默认 30)
    pub failed_logs_days: u32,
    /// Jail 统计保留天数 (默认 365)
    pub jail_stats_days: u32,
    /// DDoS 事件保留天数 (默认 30)
    pub ddos_events_days: u32,
    /// 清理间隔 (秒,默认 86400 = 每天)
    pub cleanup_interval_secs: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            ban_history_days: 90,
            failed_logs_days: 30,
            jail_stats_days: 365,
            ddos_events_days: 30,
            cleanup_interval_secs: 86400,
        }
    }
}

/// 异步写入器配置
#[derive(Debug, Clone)]
pub struct WriterConfig {
    /// bounded channel 容量 (默认 1000)
    pub channel_size: usize,
    /// 批量写入大小 (默认 50)
    pub batch_size: usize,
    /// 最大 flush 间隔 (秒,默认 5)
    pub flush_interval_secs: u32,
}

impl Default for WriterConfig {
    fn default() -> Self {
        Self {
            channel_size: 1000,
            batch_size: 50,
            flush_interval_secs: 5,
        }
    }
}

/// 混合存储配置
#[derive(Debug, Clone, Default)]
pub struct StorageConfig {
    /// 数据保留策略
    pub retention: RetentionConfig,
    /// 异步写入器配置
    pub writer: WriterConfig,
}
