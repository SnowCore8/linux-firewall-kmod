//! 跨模块共享的数据结构与系统级常量
//!
//! 拆出独立模块以避免 `ban` ↔ `jail` ↔ `failed_tracker` 等模块间出现循环依赖。
//! 本模块只放纯数据结构 + 全局原子统计,不含任何业务逻辑。
//!
//! # 主要内容
//!
//! - **容量上限常量**:`MAX_FAILED_TIMESTAMPS` / `MAX_LOG_FILES` / `MAX_JAILS` 等
//!   用于限制攻击面与内存占用
//! - **`FailedEntry`**:单个 IP 的失败时间戳环形缓冲 + 滑动窗口 head 索引
//! - **`RegexInfo`**:命名正则表达式 (含编译结果,避免每次匹配重复编译)
//! - **`Jail`**:单个服务监狱的所有配置 + 运行时状态 (`failed_hash` / `partial_line_buffer`)
//! - **`Config`**:全局配置,含默认值、metrics、永久黑名单、日志等所有设置
//! - **`DaemonStats`**:跨模块共享的原子计数器,供 Prometheus 导出器读取
//!
//! # 并发模型
//!
//! - `FailedEntry::recent_head` 使用 `AtomicUsize` (lock-free)
//! - `Jail::failed_hash` 与 `Jail::partial_line_buffer` 使用 `parking_lot::RwLock`
//!   (性能优于 `std::sync::RwLock`,无写线程饥饿)
//! - `DaemonStats` 全字段使用 `AtomicU64` (Relaxed 序,统计不要求严格同步)

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize};

use parking_lot::RwLock;

// ============================================================================
// 常量
// ============================================================================

/// 单个 IP 在 `FailedEntry.timestamps` 中最多保留的失败时间戳数。
///
/// 满后采用 FIFO 移出最旧时间戳。100 兼顾"高频攻击者最近 100 次"和"内存占用
/// 上界 (100 × `i64` × `MAX_JAILS` × IP 数)"。
pub const MAX_FAILED_TIMESTAMPS: usize = 100;

/// 单个 `Jail` 可配置的日志文件数上限。10 覆盖典型多通道日志场景 (e.g. sshd +
/// 4×web + 邮件) 同时限制单 jail 的 fd 占用。
pub const MAX_LOG_FILES: usize = 10;

/// 单个 `Jail` 可配置的正则表达式数上限。10 留足自定义空间但限制编译开销。
pub const MAX_REGEX_PATTERNS: usize = 10;

/// 正则名称字符串的最大长度 (字节)。`compile_jail_regex` 不强制,但 UI/日志截断时
/// 依赖此上界避免异常长名称。
pub const MAX_REGEX_NAME_LEN: usize = 64;

/// 全局可同时活跃的 `Jail` 数上限。`config_parser` 在解析时检查此上界。
pub const MAX_JAILS: usize = 16;

/// inotify 事件缓冲大小:`1024` 个事件 × 单事件 `~16B` + 16KB 安全裕量。
/// 典型负载下保证单次 `read_events` 不丢事件。
pub const EVENT_BUF_LEN: usize =
    1024 * std::mem::size_of::<nix::sys::inotify::InotifyEvent>() + 16 * 1024;

// ============================================================================
// 失败条目
// ============================================================================

/// 单个 IP 在某个 Jail 中的失败尝试状态。
///
/// 设计要点:
/// - `timestamps` 是单调追加的失败时间戳 (Unix 秒)
/// - `recent_head` 标记已确认过期的前缀起点,`count_recent` 从该点开始扫描
///   实现滑动窗口的 O(1) 平均复杂度 (R9-7 优化)
///
/// 典型使用流程见 [`crate::failed_tracker::handle_failed_attempt_for_jail`].
#[derive(Debug)]
pub struct FailedEntry {
    /// 失败 IP 的字符串形式 (原样保留,未归一化)
    pub ip: String,
    /// 失败时间戳 (Unix 秒) 的有序追加数组
    pub timestamps: Vec<i64>,
    /// 滑动窗口起始索引 (R9-7 优化: 避免每次 `count_recent` 从头线性扫描过期时间戳)
    pub recent_head: AtomicUsize,
}

impl FailedEntry {
    /// 创建新条目,预分配 [`MAX_FAILED_TIMESTAMPS`] 容量。
    ///
    /// # Arguments
    /// - `ip`: 原始 IP 字符串 (由调用方保证已通过 [`crate::ban::validate_ip`])
    #[must_use]
    pub fn new(ip: String) -> Self {
        Self {
            ip,
            timestamps: Vec::with_capacity(MAX_FAILED_TIMESTAMPS),
            recent_head: AtomicUsize::new(0),
        }
    }
}

// ============================================================================
// 命名正则表达式
// ============================================================================

/// 命名正则表达式条目:同时持有原始模式串与编译结果。
///
/// 编译结果在 `Jail` 初始化 (`jail::init_log_patterns`) 阶段填充,匹配热路径
/// 避免重复编译开销。未编译 (`compiled == None`) 时,`log_parser::match_regex`
/// 会自动跳过该条。
#[derive(Debug)]
pub struct RegexInfo {
    /// 人类可读的命名 (e.g. `"default"`, `"invalid_user"`, `"root_login"`)
    pub name: String,
    /// 原始 PCRE 兼容模式串
    pub pattern: String,
    /// 已编译的 regex 对象,None 表示尚未编译或编译失败
    pub compiled: Option<regex::Regex>,
}

// ============================================================================
// Jail 结构
// ============================================================================

/// 单个服务监狱:一组被监控的日志文件 + 失败阈值 + 运行时状态。
///
/// 一个 Jail 对应一个逻辑服务 (e.g. `sshd`、`nginx`),所有 IP 的失败计数和未
/// 完整行缓冲都独立于其他 Jail。
///
/// 字段分组:
/// - **静态配置**:`name` / `enabled` / `log_files` / `regexes` / `max_retries` /
///   `findtime` / `ban_time` 及其对应的 `*_set` 标志
/// - **运行时状态**:`failed_hash` (失败计数器) / `partial_line_buffer` (跨
///   `read` 调用保留的不完整行字节)
#[derive(Debug)]
pub struct Jail {
    /// 唯一名称 (与 YAML 中的 key 对应)
    pub name: String,
    /// 是否启用。`false` 时主循环跳过此 jail 的所有文件
    pub enabled: bool,
    /// 监控的日志文件路径 (绝对路径,已通过 `validate_and_normalize_path`)
    pub log_files: Vec<String>,
    /// 命名正则表达式列表。空时 `log_parser` 走字符串回退
    pub regexes: Vec<RegexInfo>,
    /// 触发封禁的失败次数阈值
    pub max_retries: u32,
    /// 滑动窗口大小 (秒)
    pub findtime: u32,
    /// 封禁时长 (秒)。`0` 表示永久封禁
    pub ban_time: u32,
    /// `*_set` 标志区分"用户显式配置"与"智能默认推断",避免被默认值覆盖
    pub max_retries_set: bool,
    pub findtime_set: bool,
    pub ban_time_set: bool,
    /// IP → 失败条目。读写并发由 `parking_lot::RwLock` 保护
    pub failed_hash: RwLock<HashMap<String, FailedEntry>>,
    /// 不完整行的字节缓冲,避免单行跨多次 read 时被切碎
    pub partial_line_buffer: RwLock<Vec<u8>>,
}

impl Jail {
    /// 创建新 Jail,所有数值字段初始化为 0/默认值,运行时容器预分配容量。
    ///
    /// # Arguments
    /// - `name`: 唯一名称,需在 `Config.jails` 中保持唯一
    #[must_use]
    pub fn new(name: String) -> Self {
        Self {
            name,
            enabled: true,
            log_files: Vec::with_capacity(MAX_LOG_FILES),
            regexes: Vec::with_capacity(MAX_REGEX_PATTERNS),
            max_retries: 0,
            findtime: 0,
            ban_time: 0,
            max_retries_set: false,
            findtime_set: false,
            ban_time_set: false,
            failed_hash: RwLock::new(HashMap::new()),
            partial_line_buffer: RwLock::new(Vec::with_capacity(8192)),
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

// ============================================================================
// 守护进程统计
// ============================================================================

/// 守护进程运行期原子计数器集合,供 Prometheus 导出器读取。
///
/// 所有字段使用 `AtomicU64` + `Relaxed` 序,牺牲严格可见性换取性能。
/// 统计读数的一致性不要求因果序,Prometheus 抓取间隔天然容忍轻微偏差。
pub struct DaemonStats {
    /// 已解析的日志行数 (`process_single_line` 调用成功)
    pub lines_parsed: AtomicU64,
    /// 从日志中成功提取的 IP 数 (`extract_and_validate_ip` 通过)
    pub ips_extracted: AtomicU64,
    /// 已成功发起的封禁数 (Temp + Permanent)
    pub ips_banned: AtomicU64,
    /// 失败尝试总数 (含未触发封禁的早期失败)
    pub failed_attempts: AtomicU64,
    /// SIGHUP 配置重载成功次数
    pub config_reloads: AtomicU64,
    /// inotify `read_events` 唤醒次数 (与事件数无关)
    pub inotify_events: AtomicU64,
    /// 日志轮转 (truncate/rename/inode 变化) 检测次数
    pub log_rotations: AtomicU64,
    /// 因超长/格式异常跳过的行数
    pub lines_skipped: AtomicU64,
    /// 正则匹配命中总数 (与 jail 数、捕获组数无关)
    pub regex_matches: AtomicU64,
    /// 守护进程启动时间 (Unix 秒)。`uptime = now - start_time`
    pub start_time: AtomicU64,
}

impl Default for DaemonStats {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonStats {
    /// `const fn` 构造,允许 `pub static DAEMON_STATS` 在静态上下文求值
    /// (普通 `new()` 涉及 `AtomicU64::new` 的非 const 包装函数时无法静态初始化)。
    #[must_use]
    pub const fn new() -> Self {
        Self {
            lines_parsed: AtomicU64::new(0),
            ips_extracted: AtomicU64::new(0),
            ips_banned: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            config_reloads: AtomicU64::new(0),
            inotify_events: AtomicU64::new(0),
            log_rotations: AtomicU64::new(0),
            lines_skipped: AtomicU64::new(0),
            regex_matches: AtomicU64::new(0),
            start_time: AtomicU64::new(0),
        }
    }
}

/// 全局单例统计对象。跨模块共享,任何位置可直接 `DAEMON_STATS.ips_banned.fetch_add(1, ...)`。
pub static DAEMON_STATS: DaemonStats = DaemonStats::new();
