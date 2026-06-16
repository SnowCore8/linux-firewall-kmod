//! Jail 相关类型
//!
//! # 核心结构
//!
//! - **`FailedEntry`**：单个 IP 的失败时间戳环形缓冲 + 滑动窗口 head 索引
//! - **`RegexInfo`**：命名正则表达式（含编译结果，避免每次匹配重复编译）
//! - **`Jail`**：单个服务监狱的所有配置 + 运行时状态

use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;

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
use std::collections::VecDeque;

/// 失败尝试条目: 记录单个 IP 的失败历史
#[derive(Debug)]
pub struct FailedEntry {
    /// 失败 IP 的字符串形式 (原样保留,未归一化)
    pub ip: String,
    /// 失败时间戳 (Unix 秒) 的有序追加队列
    ///
    /// # 性能优化
    ///
    /// 使用 `VecDeque` 而非 `Vec`，FIFO 移出操作从 O(n) 降低到 O(1)。
    /// 在 10Gbps 场景下，大量失败事件涌入时，`Vec::remove(0)` 会在持有
    /// 写锁期间执行 O(100) 元素移动，阻塞同一 jail 的所有其他 IP 处理。
    pub timestamps: VecDeque<i64>,
    /// 滑动窗口起始索引 (R9-7 优化: 避免每次 `count_recent` 从头线性扫描过期时间戳)
    pub recent_head: std::sync::atomic::AtomicUsize,
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
            timestamps: VecDeque::with_capacity(MAX_FAILED_TIMESTAMPS),
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

impl RegexInfo {
    /// 创建新的正则条目,`compiled` 初始化为 `None`。
    ///
    /// # Arguments
    /// - `name`: 正则名称
    /// - `pattern`: 原始模式串
    #[must_use]
    pub fn new(name: String, pattern: String) -> Self {
        Self {
            name,
            pattern,
            compiled: None,
        }
    }
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
