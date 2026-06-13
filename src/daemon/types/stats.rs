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
