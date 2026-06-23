//! DDoS 防护相关数据结构：DdosConfig、ConnRateEntry、DdosEvent、DdosStats
//!
//! # 10Gbps 优化
//!
//! - `ConnRateEntry.ip`: 使用 `Arc<str>` 共享字符串，避免重复分配
//! - `ConnRateEntry.ip_num`: IPv4 数值化（u32），用于快速哈希查找

use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;

// ============================================================================
// DDoS 配置
// ============================================================================

/// DDoS 防护配置
#[derive(Debug, Clone)]
pub struct DdosConfig {
    /// 是否启用 DDoS 检测
    pub enabled: bool,
    /// 单 IP 每秒最大连接数 (默认 50)
    pub per_ip_conn_rate: u32,
    /// 单 IP 每分钟最大失败次数 (默认 30)
    pub per_ip_fail_rate: u32,
    /// 全局每秒最大连接数 (默认 10000)
    pub global_conn_rate: u32,
    /// 自动封禁时长 (秒, 默认 3600)
    pub auto_ban_duration: u32,
    /// 超阈值几次后封禁 (默认 3)
    pub auto_ban_threshold: u32,
    /// 检测间隔 (秒, 默认 5)
    pub check_interval: u32,
    /// 动态阈值基线收敛样本数（默认 50，约 100 秒）
    /// 启动期使用 α=0.1 快速收敛，达到此样本数后切换到 α=0.01 长期跟踪
    pub baseline_warmup_samples: u32,
    /// 协议专项阈值（同步到内核模块）
    pub max_syn_per_second: u32, // SYN flood 阈值（默认 200）
    pub max_udp_per_second: u32,  // UDP flood 阈值（默认 1000）
    pub max_icmp_per_second: u32, // ICMP flood 阈值（默认 50）
    pub max_ack_per_second: u32,  // ACK flood 阈值（默认 2000）
    pub max_rst_per_second: u32,  // RST flood 阈值（默认 200）
    pub max_fin_per_second: u32,  // FIN flood 阈值（默认 200）
    // DDoS 检测算法开关
    pub static_threshold: bool,  // 静态阈值检测（默认 true）
    pub dynamic_threshold: bool, // 动态阈值检测（默认 false）
    pub ddos_detection: bool,    // DDoS 检测总开关（默认 true）
    // 内核模块参数
    pub max_bans_per_second: u32, // 每秒最大封禁数（默认 200）
    pub max_rate_entries: u32,    // 速率表容量（默认 65536）
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            enabled: true, // 默认启用 DDoS 检测
            per_ip_conn_rate: 50,
            per_ip_fail_rate: 30,
            global_conn_rate: 10000,
            auto_ban_duration: 3600,
            auto_ban_threshold: 3,
            check_interval: 5,
            baseline_warmup_samples: 50,
            // 协议专项阈值（与内核模块 DEFAULT_MAX_*_PER_SECOND 保持一致）
            max_syn_per_second: 200,
            max_udp_per_second: 1000,
            max_icmp_per_second: 50,
            max_ack_per_second: 2000,
            max_rst_per_second: 200,
            max_fin_per_second: 200,
            // DDoS 检测算法开关（与内核模块参数默认值一致）
            static_threshold: true,
            dynamic_threshold: false,
            ddos_detection: true,
            // 内核模块参数
            max_bans_per_second: 200,
            max_rate_entries: 65536,
        }
    }
}

// ============================================================================
// 连接速率跟踪
// ============================================================================

/// 连接速率跟踪条目（10Gbps 优化：使用 Arc<str> 共享 IP 字符串）
#[derive(Debug)]
pub struct ConnRateEntry {
    /// IP 地址（Arc 共享，避免重复分配）
    pub ip: Arc<str>,
    /// IPv4 数值（u32，用于快速哈希；IPv6 为 0）
    pub ip_num: u32,
    /// IPv6 数值（[u8; 16]，用于快速哈希；IPv4 为 [0; 16]）
    pub ipv6_num: [u8; 16],
    /// 时间窗口内的连接计数
    pub conn_count: u64,
    /// 时间窗口内的失败计数
    pub fail_count: u64,
    /// 窗口起始时间 (Unix 秒)
    pub window_start: i64,
    /// 最后活动时间 (Unix 秒)
    pub last_activity: i64,
    /// 超阈值次数 (用于触发封禁) - 使用原子类型确保并发安全
    pub violation_count: AtomicU32,
}

impl ConnRateEntry {
    /// 创建新的连接速率条目
    ///
    /// # Arguments
    /// * `ip` - IP 地址字符串
    /// * `ip_num` - IPv4 数值（u32），IPv6 传 0
    /// * `ipv6_num` - IPv6 数值（[u8; 16]），IPv4 传 [0; 16]
    /// * `now` - 当前时间戳
    pub fn new(ip: impl Into<Arc<str>>, ip_num: u32, ipv6_num: [u8; 16], now: i64) -> Self {
        Self {
            ip: ip.into(),
            ip_num,
            ipv6_num,
            conn_count: 0,
            fail_count: 0,
            window_start: now,
            last_activity: now,
            violation_count: AtomicU32::new(0),
        }
    }

    /// 重置计数器 (新窗口)
    pub fn reset(&mut self, now: i64) {
        self.conn_count = 0;
        self.fail_count = 0;
        self.window_start = now;
        // violation_count 不重置，需要跨检测周期累积以判断是否触发自动封禁
    }
}

// ============================================================================
// DDoS 事件记录
// ============================================================================

/// DDoS 事件记录
#[derive(Debug, Clone)]
pub struct DdosEvent {
    /// 触发事件的 IP 地址
    pub ip: String,
    /// 事件类型 ("conn_rate" / "fail_rate" / "global_rate")
    pub event_type: String,
    /// 检测到的速率 (每秒)
    pub rate_per_second: f64,
    /// 配置的阈值
    pub threshold: f64,
    /// 检测时间 (Unix 秒)
    pub detected_at: i64,
    /// 采取的措施 ("ban" / "log" / "none")
    pub action_taken: String,
}

// ============================================================================
// DDoS 统计
// ============================================================================

/// 全局 DDoS 统计计数器
#[derive(Debug, Default)]
pub struct DdosStats {
    /// 检测到的 DDoS 事件总数
    pub events_detected: AtomicU64,
    /// 因 DDoS 自动封禁的 IP 数
    pub auto_bans_triggered: AtomicU64,
    /// 当前被跟踪的 IP 数
    pub tracked_ips: AtomicU64,
}

impl DdosStats {
    /// 创建新的 DDoS 统计计数器
    pub const fn new() -> Self {
        Self {
            events_detected: AtomicU64::new(0),
            auto_bans_triggered: AtomicU64::new(0),
            tracked_ips: AtomicU64::new(0),
        }
    }
}

/// 全局 DDoS 统计实例
pub static DDOS_STATS: DdosStats = DdosStats::new();
