//! 守护进程统计
//!
//! # 核心结构
//!
//! - **`DaemonStats`**:跨模块共享的原子计数器,供 Prometheus 导出器读取
//!
//! # 并发模型
//!
//! 所有字段使用 `AtomicU64` + `Relaxed` 序,牺牲严格可见性换取性能。
//! 统计读数的一致性不要求因果序,Prometheus 抓取间隔天然容忍轻微偏差。

use std::sync::atomic::AtomicU64;
//! 统计相关数据结构：DaemonStats、JailStatsCounters

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

    /// 快照当前计数值 (用于定期写入 SQLite 和 metrics 导出)
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

/// Jail 统计快照 — 从 `JailStatsCounters` 读取的瞬时值,用于 SQLite 写入
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
