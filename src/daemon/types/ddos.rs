//! DDoS 防护相关数据结构：DdosConfig、DdosEvent、DdosStats
//!
//! 网络层 DDoS 检测与连接速率跟踪已下沉到内核模块，用户态不再保存连接速率条目。

use std::sync::atomic::AtomicU64;

// ============================================================================
// DDoS 配置
// ============================================================================

/// DDoS 防护配置
#[derive(Debug, Clone)]
pub struct DdosConfig {
    /// 是否启用 DDoS 检测
    pub enabled: bool,
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
    pub max_syn_per_second: u32, // SYN flood 阈值（默认 2000）
    pub max_udp_per_second: u32,  // UDP flood 阈值（默认 10000）
    pub max_icmp_per_second: u32, // ICMP flood 阈值（默认 500）
    pub max_ack_per_second: u32,  // ACK flood 阈值（默认 20000）
    pub max_rst_per_second: u32,  // RST flood 阈值（默认 2000）
    pub max_fin_per_second: u32,  // FIN flood 阈值（默认 2000）
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
            global_conn_rate: 100000,
            auto_ban_duration: 3600,
            auto_ban_threshold: 3,
            check_interval: 5,
            baseline_warmup_samples: 50,
            // 协议专项阈值（与内核模块 DEFAULT_MAX_*_PER_SECOND 保持一致）
            max_syn_per_second: 2000,
            max_udp_per_second: 10000,
            max_icmp_per_second: 500,
            max_ack_per_second: 20000,
            max_rst_per_second: 2000,
            max_fin_per_second: 2000,
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
