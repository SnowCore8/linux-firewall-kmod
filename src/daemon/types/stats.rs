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
    /// netlink 消息发送总数
    pub netlink_messages_sent: AtomicU64,
    /// netlink 消息接收总数
    pub netlink_messages_received: AtomicU64,
    /// netlink 发送失败数
    pub netlink_send_errors: AtomicU64,
    /// netlink 接收/解析失败数
    pub netlink_recv_errors: AtomicU64,
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
            netlink_messages_sent: AtomicU64::new(0),
            netlink_messages_received: AtomicU64::new(0),
            netlink_send_errors: AtomicU64::new(0),
            netlink_recv_errors: AtomicU64::new(0),
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
/// 在解封时调用。永久封禁按实际持续时间计入对应桶。
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

// ============================================================================
// 速率统计缓存（从内核 netlink 获取）
// ============================================================================

/// 单个 IP 的速率统计条目
#[derive(Debug, Clone)]
pub struct RateEntry {
    /// IP 地址字符串
    pub ip: String,
    /// 数据包数/秒
    pub packets_per_sec: u64,
    /// 字节数/秒
    pub bytes_per_sec: u64,
    /// SYN 包数/秒
    pub syn_packets_per_sec: u64,
    /// UDP 包数/秒
    pub udp_packets_per_sec: u64,
    /// ICMP 包数/秒
    pub icmp_packets_per_sec: u64,
    /// ACK 包数/秒
    pub ack_packets_per_sec: u64,
    /// RST 包数/秒
    pub rst_packets_per_sec: u64,
    /// FIN 包数/秒
    pub fin_packets_per_sec: u64,
}

/// 全局速率统计缓存
///
/// 由 netlink 接收线程定期更新，HTTP API 读取。
/// 使用 `RwLock<Vec<RateEntry>>` 保护，读多写少场景。
pub static RATE_CACHE: once_cell::sync::Lazy<parking_lot::RwLock<Vec<RateEntry>>> =
    once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(Vec::new()));

// ============================================================================
// 白名单缓存
// ============================================================================

/// 白名单条目（从内核 netlink 同步）
#[derive(Debug, Clone)]
pub struct WhitelistEntry {
    /// IP 地址或 CIDR（如 "10.0.0.0/8"）
    pub cidr: String,
    /// 网络设备名（如 "eth0"）
    pub device: String,
}

/// 全局白名单缓存（HashMap 天然去重，写入即幂等）
///
/// 由 netlink 接收线程在收到 ListWhitelistResponse 时更新，HTTP API 读取。
pub static WHITELIST_CACHE: once_cell::sync::Lazy<
    parking_lot::RwLock<std::collections::HashMap<String, WhitelistEntry>>,
> = once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(std::collections::HashMap::new()));

// ============================================================================
// 速率历史趋势（环形缓冲区）
// ============================================================================

/// 速率历史快照（每 2 秒记录一次）
#[derive(Debug, Clone)]
pub struct RateHistoryEntry {
    /// Unix 时间戳（秒）
    pub timestamp: u64,
    /// 所有 IP 的总 PPS
    pub total_pps: u64,
    /// 所有 IP 的总 BPS
    pub total_bps: u64,
    /// 当前跟踪的 IP 数量
    pub tracked_ips: u32,
}

/// 速率历史环形缓冲区容量（1800 条 × 2 秒 = 1 小时）
const RATE_HISTORY_CAPACITY: usize = 1800;

/// 全局速率历史环形缓冲区
///
/// 每次 netlink 速率查询时记录一个快照，保留最近 1 小时的历史。
/// Web UI 可读取此数据绘制速率趋势图。
pub static RATE_HISTORY: once_cell::sync::Lazy<parking_lot::RwLock<Vec<RateHistoryEntry>>> =
    once_cell::sync::Lazy::new(|| {
        parking_lot::RwLock::new(Vec::with_capacity(RATE_HISTORY_CAPACITY))
    });

/// 记录一次速率快照到历史环形缓冲区
///
/// 在 netlink 速率查询响应处理时调用。缓冲区满时移除最旧的条目。
pub fn record_rate_history(total_pps: u64, total_bps: u64, tracked_ips: u32) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut history = RATE_HISTORY.write();
    if history.len() >= RATE_HISTORY_CAPACITY {
        history.remove(0);
    }
    history.push(RateHistoryEntry {
        timestamp,
        total_pps,
        total_bps,
        tracked_ips,
    });
}

// ============================================================================
// 动态阈值基线（EWMA 平滑全局流量）
// ============================================================================

/// 基线 EWMA 平滑因子
/// 公式：baseline = (α_num * current + (α_den - α_num) * baseline) / α_den
///
/// 自适应策略：
/// - 启动期（前 50 次更新，约 100 秒）：α=0.1，快速收敛到实际流量水平
///   收敛速度：50 次后初始权重 0.9^50 ≈ 0.005，即 99.5% 已收敛
/// - 稳定期：α=0.01，极慢衰减，跟踪长期趋势
///   半衰期：约 69 次更新（~138 秒），对突发流量不敏感
const BASELINE_ALPHA_FAST_NUM: u64 = 10; // α=0.1（启动期）
const BASELINE_ALPHA_SLOW_NUM: u64 = 1; // α=0.01（稳定期）
const BASELINE_ALPHA_DEN: u64 = 100;

/// 启动期→稳定期的切换阈值（默认 50 次更新 ≈ 100 秒）
/// 可通过 `set_baseline_warmup_samples` 配置，适配不同启动场景
static BASELINE_WARMUP_SAMPLES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(50);

/// 全局流量基线（PPS）— EWMA 平滑值
///
/// 由 netlink 接收线程在每次速率查询响应时更新。
/// 守护进程定期将此值下发到内核，用于动态阈值计算。
static BASELINE_PPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 全局流量基线（BPS）— EWMA 平滑值
static BASELINE_BPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 基线更新次数（用于自适应 α 切换）
static BASELINE_SAMPLE_COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// 基线冻结状态
///
/// 当检测到流量突增（当前 PPS > 基线 × 3）时冻结基线更新，
/// 防止攻击流量污染基线导致阈值跟随上升。
/// 冻结持续 BASELINE_FREEZE_SAMPLES 个样本后自动恢复。
static BASELINE_FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static BASELINE_FREEZE_REMAINING: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// 基线冻结阈值：当前流量 > 基线 × 此倍数时触发冻结
const BASELINE_FREEZE_RATIO: u64 = 3;
/// 冻结持续样本数（每 2 秒一个样本，150 = 5 分钟）
const BASELINE_FREEZE_SAMPLES: u64 = 150;

/// 获取基线冻结状态（Web UI 显示用）
pub fn is_baseline_frozen() -> bool {
    BASELINE_FROZEN.load(std::sync::atomic::Ordering::Relaxed)
}

/// 更新全局流量基线（自适应 EWMA + 异常冻结）
///
/// 在 netlink 速率查询响应处理时调用，传入内核返回的全局 PPS/BPS。
/// 启动期使用 α=0.1 快速收敛（约 100 秒达到 99.5%），
/// 稳定期切换到 α=0.01 长期跟踪。
///
/// 异常冻结：当 global_pps > baseline × 3 时，判定为攻击流量，
/// 冻结基线更新 5 分钟，防止攻击流量污染基线。
pub fn update_traffic_baseline(global_pps: u64, global_bps: u64) {
    use std::sync::atomic::Ordering;

    let old_pps = BASELINE_PPS.load(Ordering::Relaxed);
    let old_bps = BASELINE_BPS.load(Ordering::Relaxed);

    // 异常基线检测：流量突增 > 3 倍基线时冻结
    if old_pps > 0 && global_pps > old_pps.saturating_mul(BASELINE_FREEZE_RATIO) {
        if !BASELINE_FROZEN.load(Ordering::Relaxed) {
            crate::logger::warn!(
                crate::logger::get(),
                "基线冻结：检测到异常流量突增";
                "current_pps" => global_pps,
                "baseline_pps" => old_pps,
                "ratio" => global_pps / old_pps.max(1)
            );
        }
        BASELINE_FROZEN.store(true, Ordering::Relaxed);
        BASELINE_FREEZE_REMAINING.store(BASELINE_FREEZE_SAMPLES, Ordering::Relaxed);
        // 冻结期间不更新基线
        return;
    }

    // 冻结倒计时
    if BASELINE_FROZEN.load(Ordering::Relaxed) {
        let remaining = BASELINE_FREEZE_REMAINING.load(Ordering::Relaxed);
        if remaining > 1 {
            BASELINE_FREEZE_REMAINING.store(remaining - 1, Ordering::Relaxed);
            return; // 仍在冻结期
        }
        // 冻结结束
        BASELINE_FROZEN.store(false, Ordering::Relaxed);
        BASELINE_FREEZE_REMAINING.store(0, Ordering::Relaxed);
        crate::logger::info!(
            crate::logger::get(),
            "基线冻结结束，恢复 EWMA 更新";
            "baseline_pps" => old_pps
        );
    }

    let sample = BASELINE_SAMPLE_COUNT.fetch_add(1, Ordering::Relaxed);
    let warmup = BASELINE_WARMUP_SAMPLES.load(Ordering::Relaxed);
    let alpha_num = if sample < warmup {
        BASELINE_ALPHA_FAST_NUM
    } else {
        BASELINE_ALPHA_SLOW_NUM
    };

    // saturating 运算防止极端流量场景下的整数溢出
    let new_pps = alpha_num
        .saturating_mul(global_pps)
        .saturating_add((BASELINE_ALPHA_DEN - alpha_num).saturating_mul(old_pps))
        / BASELINE_ALPHA_DEN;
    let new_bps = alpha_num
        .saturating_mul(global_bps)
        .saturating_add((BASELINE_ALPHA_DEN - alpha_num).saturating_mul(old_bps))
        / BASELINE_ALPHA_DEN;

    BASELINE_PPS.store(new_pps, Ordering::Relaxed);
    BASELINE_BPS.store(new_bps, Ordering::Relaxed);
}

/// 获取当前基线 PPS
pub fn get_baseline_pps() -> u64 {
    BASELINE_PPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// 获取当前基线 BPS
pub fn get_baseline_bps() -> u64 {
    BASELINE_BPS.load(std::sync::atomic::Ordering::Relaxed)
}

/// 设置基线收敛样本数（配置加载时调用）
///
/// 控制启动期→稳定期的切换时机：
/// - 值越小（如 20）：更快进入稳定期，适合流量稳定的环境
/// - 值越大（如 100）：启动期更长，适合流量波动大的环境
///
/// 默认 50（约 100 秒，2 秒/次查询）
pub fn set_baseline_warmup_samples(samples: u32) {
    BASELINE_WARMUP_SAMPLES.store(samples as u64, std::sync::atomic::Ordering::Relaxed);
}

// ============================================================================
// 多窗口速率检测（短期/中期/长期 EWMA）
// ============================================================================

/// 多窗口 EWMA 平滑系数（α_den=1000）
///
/// - 短期（~5s）：α=0.200，快速响应突发洪水
/// - 中期（~60s）：α=0.020，检测持续攻击
/// - 长期（~300s）：α=0.004，识别慢速攻击
const WINDOW_ALPHA_SHORT: u64 = 200;
const WINDOW_ALPHA_MID: u64 = 20;
const WINDOW_ALPHA_LONG: u64 = 4;
const WINDOW_ALPHA_DEN: u64 = 1000;

/// 短期窗口 PPS（~5s）— 突发洪水检测
static WINDOW_PPS_SHORT: AtomicU64 = AtomicU64::new(0);
/// 中期窗口 PPS（~60s）— 持续攻击检测
static WINDOW_PPS_MID: AtomicU64 = AtomicU64::new(0);
/// 长期窗口 PPS（~300s）— 慢速攻击检测
static WINDOW_PPS_LONG: AtomicU64 = AtomicU64::new(0);

/// 短期窗口 BPS
static WINDOW_BPS_SHORT: AtomicU64 = AtomicU64::new(0);
/// 中期窗口 BPS
static WINDOW_BPS_MID: AtomicU64 = AtomicU64::new(0);
/// 长期窗口 BPS
static WINDOW_BPS_LONG: AtomicU64 = AtomicU64::new(0);

/// 更新多窗口速率 EWMA
///
/// 每 2 秒由 netlink 速率查询响应触发。
/// 三个窗口独立维护，分别对应不同时间尺度的流量特征：
/// - 短期窗口（~5s）：捕捉突发洪水（SYN Flood 等）
/// - 中期窗口（~60s）：识别持续攻击（持续 1 分钟以上的高速）
/// - 长期窗口（~300s）：检测慢速攻击（低频但持续 5 分钟以上的异常）
pub fn update_rate_windows(global_pps: u64, global_bps: u64) {
    use std::sync::atomic::Ordering;

    // 短期窗口（α=0.200）
    // saturating 运算防止极端流量场景下的整数溢出（与 update_traffic_baseline 一致）
    let old = WINDOW_PPS_SHORT.load(Ordering::Relaxed);
    WINDOW_PPS_SHORT.store(
        (WINDOW_ALPHA_SHORT.saturating_mul(global_pps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_SHORT).saturating_mul(old))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );
    let old_bps = WINDOW_BPS_SHORT.load(Ordering::Relaxed);
    WINDOW_BPS_SHORT.store(
        (WINDOW_ALPHA_SHORT.saturating_mul(global_bps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_SHORT).saturating_mul(old_bps))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );

    // 中期窗口（α=0.020）
    let old = WINDOW_PPS_MID.load(Ordering::Relaxed);
    WINDOW_PPS_MID.store(
        (WINDOW_ALPHA_MID.saturating_mul(global_pps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_MID).saturating_mul(old))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );
    let old_bps = WINDOW_BPS_MID.load(Ordering::Relaxed);
    WINDOW_BPS_MID.store(
        (WINDOW_ALPHA_MID.saturating_mul(global_bps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_MID).saturating_mul(old_bps))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );

    // 长期窗口（α=0.004）
    let old = WINDOW_PPS_LONG.load(Ordering::Relaxed);
    WINDOW_PPS_LONG.store(
        (WINDOW_ALPHA_LONG.saturating_mul(global_pps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_LONG).saturating_mul(old))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );
    let old_bps = WINDOW_BPS_LONG.load(Ordering::Relaxed);
    WINDOW_BPS_LONG.store(
        (WINDOW_ALPHA_LONG.saturating_mul(global_bps)
            + (WINDOW_ALPHA_DEN - WINDOW_ALPHA_LONG).saturating_mul(old_bps))
            / WINDOW_ALPHA_DEN,
        Ordering::Relaxed,
    );
}

/// 多窗口速率快照（用于 API 响应）
#[derive(Debug, Clone, serde::Serialize)]
pub struct RateWindowSnapshot {
    /// 短期窗口 PPS（~5s，突发洪水）
    pub pps_short: u64,
    /// 中期窗口 PPS（~60s，持续攻击）
    pub pps_mid: u64,
    /// 长期窗口 PPS（~300s，慢速攻击）
    pub pps_long: u64,
    /// 短期窗口 BPS
    pub bps_short: u64,
    /// 中期窗口 BPS
    pub bps_mid: u64,
    /// 长期窗口 BPS
    pub bps_long: u64,
}

/// 获取多窗口速率快照
pub fn get_rate_windows() -> RateWindowSnapshot {
    use std::sync::atomic::Ordering;
    RateWindowSnapshot {
        pps_short: WINDOW_PPS_SHORT.load(Ordering::Relaxed),
        pps_mid: WINDOW_PPS_MID.load(Ordering::Relaxed),
        pps_long: WINDOW_PPS_LONG.load(Ordering::Relaxed),
        bps_short: WINDOW_BPS_SHORT.load(Ordering::Relaxed),
        bps_mid: WINDOW_BPS_MID.load(Ordering::Relaxed),
        bps_long: WINDOW_BPS_LONG.load(Ordering::Relaxed),
    }
}

// ============================================================================
// 分析数据缓存（替代 procfs 读取）
// ============================================================================

/// UDP 端口分布条目（从内核 netlink 同步）
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisUdpPortEntry {
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// ICMP 类型分布条目（从内核 netlink 同步）
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisIcmpTypeEntry {
    pub r#type: u8,
    pub code: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// 端口扫描/服务探测条目（从内核 netlink 同步）
#[derive(Debug, Clone, serde::Serialize)]
pub struct AnalysisScannerEntry {
    pub ip: String,
    pub metric: u32,
    pub packets: u64,
}

/// 内核分析数据快照（由 netlink AnalysisResponse 更新，Web UI API 读取）
#[derive(Debug, Clone, Default)]
pub struct AnalysisData {
    /// 包大小分布（5 桶：<64B, 64-256B, 256B-1KB, 1-1.5KB, >1.5KB）
    pub pkt_sizes: [u64; 5],
    /// TTL 分布（6 桶：=1, 2-32, 33-64, 65-128, 129-192, 193-255）
    pub ttl_dist: [u64; 6],
    /// IP 总包数
    pub ip_total_count: u64,
    /// IP 分片包数
    pub ip_frag_count: u64,
    /// UDP 端口分布
    pub udp_ports: Vec<AnalysisUdpPortEntry>,
    /// UDP 端口最大容量
    pub udp_port_capacity: u32,
    /// ICMP 类型分布
    pub icmp_types: Vec<AnalysisIcmpTypeEntry>,
    /// ICMP 类型最大容量
    pub icmp_type_capacity: u32,
    /// 端口扫描者
    pub port_scanners: Vec<AnalysisScannerEntry>,
    /// 端口扫描阈值
    pub port_scan_threshold: u32,
    /// 服务探测者
    pub service_probes: Vec<AnalysisScannerEntry>,
    /// 服务探测阈值
    pub service_probe_threshold: u32,
}

/// 全局分析数据缓存
///
/// 由 netlink 接收线程在收到 AnalysisResponse 时更新，Web UI API 读取。
/// 替代原来直接读取 /proc/firewall/ 的 7 个接口。
pub static ANALYSIS_CACHE: once_cell::sync::Lazy<parking_lot::RwLock<AnalysisData>> =
    once_cell::sync::Lazy::new(|| parking_lot::RwLock::new(AnalysisData::default()));
