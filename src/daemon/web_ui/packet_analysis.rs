//! 数据包特征分析
//!
//! 提供包大小分布、TTL 分布、IP 分片统计、端口扫描检测、服务探测检测等 API。
//! 数据源为 ANALYSIS_CACHE（由 netlink AnalysisResponse 更新），不再读取 procfs。

use serde::{Deserialize, Serialize};

/// 包大小分布响应
#[derive(Serialize)]
pub struct PacketSizeDistributionResponse {
    /// 桶标签（"<64B", "64-256B", "256B-1KB", "1-1.5KB", ">1.5KB"）
    pub labels: Vec<String>,
    /// 每个桶的数据包数
    pub counts: Vec<u64>,
    /// 总数据包数
    pub total: u64,
    /// 每个桶的百分比
    pub percentages: Vec<f64>,
}

/// TTL 分布响应
#[derive(Deserialize, Clone, Serialize)]
pub struct TtlDistributionResponse {
    /// 每个 TTL 范围区间的标签
    pub labels: Vec<String>,
    /// 每个区间的包数量
    pub counts: Vec<u64>,
    /// 总包数量
    pub total: u64,
    /// 每个桶的百分比
    pub percentages: Vec<f64>,
}

/// IP 分片统计响应
#[derive(Deserialize, Clone, Serialize)]
pub struct IpFragmentStatsResponse {
    /// 总 IP 数据包数
    pub total_packets: u64,
    /// 分片包数
    pub fragment_packets: u64,
    /// 分片比例（百分比）
    pub fragment_ratio: f64,
}

/// 端口扫描者条目
#[derive(Deserialize, Clone, Serialize)]
pub struct PortScannerEntry {
    pub ip: String,
    pub unique_ports: u32,
    pub packets: u64,
}

/// 端口扫描检测响应
#[derive(Deserialize, Clone, Serialize)]
pub struct PortScanResponse {
    pub threshold: u32,
    pub total_detected: u32,
    pub scanners: Vec<PortScannerEntry>,
}

/// 服务探测者条目
#[derive(Deserialize, Clone, Serialize)]
pub struct ServiceProbeEntry {
    pub ip: String,
    pub protocol_count: u32,
    pub packets: u64,
}

/// 服务探测检测响应
#[derive(Deserialize, Clone, Serialize)]
pub struct ServiceProbeResponse {
    pub threshold: u32,
    pub probes: Vec<ServiceProbeEntry>,
}

/// 获取包大小分布直方图
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_packet_size_distribution() -> PacketSizeDistributionResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();
    let counts = cache.pkt_sizes.to_vec();
    let total: u64 = counts.iter().sum();

    let labels = vec![
        "<64B".into(),
        "64-256B".into(),
        "256B-1KB".into(),
        "1-1.5KB".into(),
        ">1.5KB".into(),
    ];

    let percentages: Vec<f64> = counts
        .iter()
        .map(|&c| {
            if total > 0 {
                (c as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        })
        .collect();

    PacketSizeDistributionResponse {
        labels,
        counts,
        total,
        percentages,
    }
}

/// 获取 TTL 分布直方图
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_ttl_distribution() -> TtlDistributionResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();
    let counts = cache.ttl_dist.to_vec();
    let total: u64 = counts.iter().sum();

    let labels = vec![
        "=1".into(),
        "2-32".into(),
        "33-64".into(),
        "65-128".into(),
        "129-192".into(),
        "193-255".into(),
    ];

    let percentages: Vec<f64> = counts
        .iter()
        .map(|&c| {
            if total > 0 {
                (c as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        })
        .collect();

    TtlDistributionResponse {
        labels,
        counts,
        total,
        percentages,
    }
}

/// 获取 IP 分片统计
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_ip_fragment_stats() -> IpFragmentStatsResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();
    let total_packets = cache.ip_total_count;
    let fragment_packets = cache.ip_frag_count;

    let fragment_ratio = if total_packets > 0 {
        (fragment_packets as f64 / total_packets as f64) * 100.0
    } else {
        0.0
    };

    IpFragmentStatsResponse {
        total_packets,
        fragment_packets,
        fragment_ratio,
    }
}

/// 获取端口扫描检测结果
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_port_scan_detection() -> PortScanResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();

    let scanners = cache
        .port_scanners
        .iter()
        .map(|e| PortScannerEntry {
            ip: e.ip.clone(),
            unique_ports: e.metric,
            packets: e.packets,
        })
        .collect();

    PortScanResponse {
        threshold: cache.port_scan_threshold,
        total_detected: cache.port_scanners.len() as u32,
        scanners,
    }
}

/// 获取服务探测检测结果
///
/// 从 ANALYSIS_CACHE 读取内核统计数据（由 netlink AnalysisResponse 更新）
pub fn get_service_probe_detection() -> ServiceProbeResponse {
    let cache = crate::types::ANALYSIS_CACHE.read();

    let probes = cache
        .service_probes
        .iter()
        .map(|e| ServiceProbeEntry {
            ip: e.ip.clone(),
            protocol_count: e.metric,
            packets: e.packets,
        })
        .collect();

    ServiceProbeResponse {
        threshold: cache.service_probe_threshold,
        probes,
    }
}
