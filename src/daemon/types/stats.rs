//! 守护进程统计
//!
//! # 核心结构
//!
//! - **`DaemonStats`**：跨模块共享的原子计数器，供 Prometheus 导出器读取
//!
//! # 并发模型
//!
//! 所有字段使用 `AtomicU64` + `Relaxed` 序，牺牲严格可见性换取性能。
//! 统计读数的一致性不要求因果序，Prometheus 抓取间隔天然容忍轻微偏差。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;

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
    /// 累计解封数 (程序内部维护，近似值)
    pub total_unbans: AtomicU64,
    /// 当前白名单数 (程序内部维护)
    pub whitelist_count: AtomicU64,
    /// 丢弃数据包数 (近似值，每次 ban 时 +1)
    pub packets_dropped: AtomicU64,
    /// 接受数据包数 (近似值，无法准确统计)
    pub packets_accepted: AtomicU64,
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
            total_unbans: AtomicU64::new(0),
            whitelist_count: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            packets_accepted: AtomicU64::new(0),
        }
    }
}

/// 全局单例统计对象。跨模块共享,任何位置可直接 `DAEMON_STATS.ips_banned.fetch_add(1, ...)`。
pub static DAEMON_STATS: DaemonStats = DaemonStats::new();

// ============================================================================
// Jail 统计计数器
// ============================================================================

/// 单个 Jail 的运行期原子计数器 — per-jail 维度的 Prometheus 指标源
///
/// 与全局 `DaemonStats` 互补:全局指标是聚合值,`JailStatsCounters` 按 jail
/// 拆分,支持 Grafana 按服务下钻分析。
#[derive(Debug)]
pub struct JailStatsCounters {
    /// Jail 名称 (标识用)
    pub jail_name: String,
    /// 已解析日志行数
    pub lines_parsed: AtomicU64,
    /// 成功提取的 IP 数
    pub ips_extracted: AtomicU64,
    /// 触发的封禁数
    pub bans_triggered: AtomicU64,
    /// 失败尝试总数
    pub failed_attempts: AtomicU64,
    /// 正则匹配命中数
    pub regex_matches: AtomicU64,
}

impl JailStatsCounters {
    #[must_use]
    pub fn new(jail_name: String) -> Self {
        Self {
            jail_name,
            lines_parsed: AtomicU64::new(0),
            ips_extracted: AtomicU64::new(0),
            bans_triggered: AtomicU64::new(0),
            failed_attempts: AtomicU64::new(0),
            regex_matches: AtomicU64::new(0),
        }
    }

    /// 快照当前计数值 (用于 metrics 导出)
    #[must_use]
    pub fn snapshot(&self) -> JailStatsSnapshot {
        JailStatsSnapshot {
            jail_name: self.jail_name.clone(),
            lines_parsed: self.lines_parsed.load(Ordering::Relaxed),
            ips_extracted: self.ips_extracted.load(Ordering::Relaxed),
            bans_triggered: self.bans_triggered.load(Ordering::Relaxed),
            failed_attempts: self.failed_attempts.load(Ordering::Relaxed),
            regex_matches: self.regex_matches.load(Ordering::Relaxed),
        }
    }
}

/// Jail 统计快照 — 从 `JailStatsCounters` 读取的瞬时值,用于指标导出
#[derive(Debug, Clone)]
pub struct JailStatsSnapshot {
    pub jail_name: String,
    pub lines_parsed: u64,
    pub ips_extracted: u64,
    pub bans_triggered: u64,
    pub failed_attempts: u64,
    pub regex_matches: u64,
}

// ============================================================================
// 全局实例和辅助函数
// ============================================================================

/// 全局 per-jail 统计计数器映射
///
/// `jail_name` → `JailStatsCounters`,使用 `RwLock` 保护并发读写。
/// 每个 jail 首次访问时自动创建计数器 (lazy initialization)。
pub static JAIL_STATS: std::sync::OnceLock<RwLock<HashMap<String, JailStatsCounters>>> =
    std::sync::OnceLock::new();

// ============================================================================
// 封禁时长 Histogram
// ============================================================================

/// 封禁时长分布桶边界（秒）
///
/// Prometheus histogram 标准格式：`le="60"` 表示 ≤60 秒的累计计数。
/// 桶边界选择依据：
/// - 60s: 短期暴力破解封禁（典型 findtime=600 的 1/10）
/// - 300s (5min): 中等时长封禁
/// - 3600s (1h): 标准封禁时长（bantime 默认值）
/// - +Inf: 超长封禁（含永久封禁的实际持续时间）
const BUCKET_BOUNDARIES: [i64; 3] = [60, 300, 3600];

/// 封禁时长 histogram 桶计数器
///
/// 索引 0-2 对应 `BUCKET_BOUNDARIES`，索引 3 为 +Inf（所有封禁均计入）。
/// 使用 `AtomicU64` + `Relaxed` 序，与 `DaemonStats` 一致。
pub static BAN_DURATION_BUCKETS: [AtomicU64; 4] = [
    AtomicU64::new(0), // ≤60s
    AtomicU64::new(0), // ≤300s
    AtomicU64::new(0), // ≤3600s
    AtomicU64::new(0), // +Inf
];

/// 记录一次封禁的持续时长到 histogram
///
/// 在解封（`unban_ip_with_history`）时调用。永久封禁按实际持续时间计入对应桶。
///
/// # Arguments
/// * `duration_secs` — 封禁持续秒数（`expires_at - banned_at` 或 `now - banned_at`）
pub fn record_ban_duration(duration_secs: i64) {
    // +Inf 桶始终累加
    BAN_DURATION_BUCKETS[3].fetch_add(1, Ordering::Relaxed);

    // 按桶边界累加（histogram 语义：每个桶包含所有 ≤ 该边界的样本）
    if duration_secs <= BUCKET_BOUNDARIES[0] {
        BAN_DURATION_BUCKETS[0].fetch_add(1, Ordering::Relaxed);
    }
    if duration_secs <= BUCKET_BOUNDARIES[1] {
        BAN_DURATION_BUCKETS[1].fetch_add(1, Ordering::Relaxed);
    }
    if duration_secs <= BUCKET_BOUNDARIES[2] {
        BAN_DURATION_BUCKETS[2].fetch_add(1, Ordering::Relaxed);
    }
}

/// 直接获取 jail 统计计数器的引用 (用于累加操作)
///
/// 如果 jail 不存在，自动创建。返回的是映射中的实际引用，可直接调用 fetch_add 等方法。
pub fn with_jail_stats<F, R>(jail_name: &str, f: F) -> R
where
    F: FnOnce(&JailStatsCounters) -> R,
{
    let map = JAIL_STATS.get_or_init(|| RwLock::new(HashMap::new()));

    // 先尝试读锁
    {
        let read_guard = map.read();
        if let Some(counters) = read_guard.get(jail_name) {
            return f(counters);
        }
    }

    // 读锁未命中，升级为写锁创建新计数器
    let mut write_guard = map.write();
    let counters = write_guard
        .entry(jail_name.to_string())
        .or_insert_with(|| JailStatsCounters::new(jail_name.to_string()));
    f(counters)
}
