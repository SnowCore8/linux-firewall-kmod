//! DDoS/内核统计数据可视化
//!
//! 提供 UDP 端口分布、ICMP 类型分布、封禁时长直方图等 API。
//! UDP/ICMP 数据源为 ANALYSIS_CACHE（由 netlink AnalysisResponse 更新），不再读取 procfs。

use serde::Serialize;

/// UDP 端口分布条目
#[derive(Serialize)]
pub struct UdpPortEntry {
    /// 端口号
    pub port: u16,
    /// 数据包数
    pub packets: u64,
    /// 字节数
    pub bytes: u64,
    /// 最后出现时间（秒前）
    pub last_seen_secs: u64,
}

/// UDP 端口分布响应
#[derive(Serialize)]
pub struct UdpPortDistributionResponse {
    /// 端口列表（按数据包数降序）
    pub ports: Vec<UdpPortEntry>,
    /// 总条目数
    pub total_entries: usize,
    /// 最大容量
    pub max_entries: usize,
}

/// ICMP 类型分布条目
#[derive(Serialize)]
pub struct IcmpTypeEntry {
    /// ICMP 类型
    pub r#type: u8,
    /// ICMP 代码
    pub code: u8,
    /// 数据包数
    pub packets: u64,
    /// 字节数
    pub bytes: u64,
    /// 最后出现时间（秒前）
    pub last_seen_secs: u64,
}

/// ICMP 类型分布响应
#[derive(Serialize)]
pub struct IcmpTypeDistributionResponse {
    /// 类型列表（按数据包数降序）
    pub types: Vec<IcmpTypeEntry>,
    /// 总条目数
    pub total_entries: usize,
    /// 最大容量
    pub max_entries: usize,
}

/// 封禁时长 Histogram 响应
#[derive(Serialize)]
pub struct BanDurationHistogramResponse {
    /// 桶边界标签（"≤60s", "≤5min", "≤1h", ">1h"）
    pub labels: Vec<String>,
    /// 每个桶的封禁次数（非累积，用于展示）
    pub counts: Vec<u64>,
    /// 总封禁数
    pub total: u64,
}

/// 获取 UDP 端口分布统计
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_udp_port_distribution() -> UdpPortDistributionResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();

    let mut ports: Vec<UdpPortEntry> = cache
        .udp_ports
        .iter()
        .map(|e| UdpPortEntry {
            port: e.port,
            packets: e.packets,
            bytes: e.bytes,
            last_seen_secs: e.last_seen_secs,
        })
        .collect();

    // 按数据包数降序排序
    ports.sort_by_key(|b| std::cmp::Reverse(b.packets));

    UdpPortDistributionResponse {
        ports,
        total_entries: cache.udp_ports.len(),
        max_entries: cache.udp_port_capacity as usize,
    }
}

/// 获取 ICMP 类型分布统计
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_icmp_type_distribution() -> IcmpTypeDistributionResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();

    let mut types: Vec<IcmpTypeEntry> = cache
        .icmp_types
        .iter()
        .map(|e| IcmpTypeEntry {
            r#type: e.r#type,
            code: e.code,
            packets: e.packets,
            bytes: e.bytes,
            last_seen_secs: e.last_seen_secs,
        })
        .collect();

    // 按数据包数降序排序
    types.sort_by_key(|b| std::cmp::Reverse(b.packets));

    IcmpTypeDistributionResponse {
        types,
        total_entries: cache.icmp_types.len(),
        max_entries: cache.icmp_type_capacity as usize,
    }
}

/// 获取封禁时长分布直方图
///
/// 从全局 BAN_DURATION_BUCKETS 计数器读取，转换为非累积计数
pub fn get_ban_duration_histogram() -> BanDurationHistogramResponse {
    use crate::types::BAN_DURATION_BUCKETS;
    use std::sync::atomic::Ordering;

    // 读取累积桶计数
    let bucket_le_60s = BAN_DURATION_BUCKETS[0].load(Ordering::Relaxed);
    let bucket_le_5min = BAN_DURATION_BUCKETS[1].load(Ordering::Relaxed);
    let bucket_le_1h = BAN_DURATION_BUCKETS[2].load(Ordering::Relaxed);
    let bucket_total = BAN_DURATION_BUCKETS[3].load(Ordering::Relaxed);

    // 转换为非累积计数
    let count_le_60s = bucket_le_60s;
    let count_le_5min = bucket_le_5min.saturating_sub(bucket_le_60s);
    let count_le_1h = bucket_le_1h.saturating_sub(bucket_le_5min);
    let count_gt_1h = bucket_total.saturating_sub(bucket_le_1h);

    BanDurationHistogramResponse {
        labels: vec!["≤60s".into(), "≤5min".into(), "≤1h".into(), ">1h".into()],
        counts: vec![count_le_60s, count_le_5min, count_le_1h, count_gt_1h],
        total: bucket_total,
    }
}
