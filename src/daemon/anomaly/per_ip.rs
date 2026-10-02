//! Per-IP 行为异常检测。
//!
//! 每 5 分钟对活跃 IP 计算 6 维行为向量，用**中位数绝对偏差（MAD）**在群体内
//! 识别离群者。不依赖历史——只要当轮有足够 IP，就能判定谁的行为在当前流量池里
//! 是异类。
//!
//! # 特征维度
//!
//! | 索引 | 名称 | 含义 |
//! |------|------|------|
//! | 0 | `syn_ratio` | 该 IP 的 SYN 包占比 |
//! | 1 | `udp_ratio` | 该 IP 的 UDP 包占比 |
//! | 2 | `icmp_ratio` | 该 IP 的 ICMP 包占比 |
//! | 3 | `volume_pps` | 该 IP 的包速率 |
//! | 4 | `avg_pkt_size` | 平均包大小（bytes/packets，若 packets=0 则为 0） |
//! | 5 | `port_diversity` | 该 IP 访问过的去重目标端口数（内核累计并集，下界近似） |
//!
//! # 评分方法
//!
//! 对每个维度计算 `|x_i - median| / MAD`，超过阈值（默认 3.0）的维度计为一个
//! "异常维度"。异常维度数占总维度的比例即为该 IP 的异常评分（0-100）。

use std::net::IpAddr;

use super::IpFeatureVector;

/// 维度数量。
const DIM_COUNT: usize = 6;

/// 维度名称。
pub const DIM_NAMES: [&str; DIM_COUNT] = [
    "syn_ratio",
    "udp_ratio",
    "icmp_ratio",
    "volume_pps",
    "avg_pkt_size",
    "port_diversity",
];

/// MAD 异常阈值：偏差超过 3 倍 MAD 视为该维度异常。
const MAD_THRESHOLD: f64 = 3.0;

/// 最少活跃 IP 数：低于此值时无法做群体比较，输出空结果。
const MIN_ACTIVE_IPS: usize = 5;

/// 输出的异常 IP 数量上限。
pub const TOP_ANOMALOUS_LIMIT: usize = 20;

/// Per-IP 异常检测结果。
#[derive(Clone, Debug)]
pub struct IpAnomaly {
    pub ip: IpAddr,
    /// 异常评分（0-100）。
    pub score: f64,
    /// 各维度的 MAD 偏差分。
    pub dimension_scores: [f64; DIM_COUNT],
    /// 特征向量。
    pub features: IpFeatureVector,
}

/// 从速率计数器提取 per-IP 特征向量。
///
/// `unique_ports` 来自内核的累计去重端口并集（`RateCounters::unique_ports`），
/// 直接作为 `port_diversity` 维度：MAD 比较的是群体内的相对位置，绝对计数即可，
/// 不需要再归一化成比例。
pub fn extract_ip_features(
    packets: u64,
    bytes: u64,
    syn: u64,
    udp: u64,
    icmp: u64,
    unique_ports: u32,
) -> IpFeatureVector {
    let total = syn + udp + icmp + packets.saturating_sub(syn + udp + icmp);
    // 上面 total 可能大于 packets（如果 syn/udp/icmp 有重复计数），用 packets 兜底。
    let total = total.max(packets);

    let syn_ratio = if total > 0 {
        syn as f64 / total as f64
    } else {
        0.0
    };
    let udp_ratio = if total > 0 {
        udp as f64 / total as f64
    } else {
        0.0
    };
    let icmp_ratio = if total > 0 {
        icmp as f64 / total as f64
    } else {
        0.0
    };
    let volume_pps = packets as f64;
    let avg_pkt_size = if packets > 0 {
        bytes as f64 / packets as f64
    } else {
        0.0
    };
    // port_diversity: 内核上报的累计去重端口数（下界近似，内核侧封顶 32）。
    let port_diversity = unique_ports as f64;

    IpFeatureVector([
        syn_ratio,
        udp_ratio,
        icmp_ratio,
        volume_pps,
        avg_pkt_size,
        port_diversity,
    ])
}

/// 对一批 (IP, 特征向量) 计算 MAD 异常评分，返回 TOP 异常 IP（降序）。
pub fn score_ip_anomalies(entries: &[(IpAddr, IpFeatureVector)]) -> Vec<IpAnomaly> {
    if entries.len() < MIN_ACTIVE_IPS {
        return Vec::new();
    }

    // 对每个维度计算中位数与 MAD。
    let mut medians = [0.0; DIM_COUNT];
    let mut mads = [0.0; DIM_COUNT];

    for d in 0..DIM_COUNT {
        let mut vals: Vec<f64> = entries.iter().map(|(_, f)| f.0[d]).collect();
        vals.sort_by(|a, b| a.total_cmp(b));
        medians[d] = median(&vals);

        // MAD = median(|x_i - median|)。
        let mut abs_devs: Vec<f64> = vals.iter().map(|&v| (v - medians[d]).abs()).collect();
        abs_devs.sort_by(|a, b| a.total_cmp(b));
        mads[d] = median(&abs_devs);
    }

    let mut results: Vec<IpAnomaly> = entries
        .iter()
        .map(|(ip, features)| {
            let mut dim_scores = [0.0; DIM_COUNT];
            let mut anomaly_count = 0;

            for d in 0..DIM_COUNT {
                let mad = mads[d].max(1e-9);
                let deviation = (features.0[d] - medians[d]).abs() / mad;
                let normalized = (deviation / MAD_THRESHOLD).min(1.0);
                dim_scores[d] = normalized;
                if deviation > MAD_THRESHOLD {
                    anomaly_count += 1;
                }
            }

            let score = (anomaly_count as f64 / DIM_COUNT as f64) * 100.0;

            IpAnomaly {
                ip: *ip,
                score,
                dimension_scores: dim_scores,
                features: *features,
            }
        })
        .collect();

    // 按评分降序排列，取 TOP N。
    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(TOP_ANOMALOUS_LIMIT);
    results
}

/// 中位数。`sorted` 必须已排序。
fn median(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fv(vals: [f64; DIM_COUNT]) -> IpFeatureVector {
        IpFeatureVector(vals)
    }

    #[test]
    fn too_few_ips_returns_empty() {
        let entries = vec![
            (IpAddr::from([1, 1, 1, 1]), fv([0.5; DIM_COUNT])),
            (IpAddr::from([2, 2, 2, 2]), fv([0.5; DIM_COUNT])),
        ];
        assert!(score_ip_anomalies(&entries).is_empty());
    }

    #[test]
    fn uniform_ips_no_anomaly() {
        let entries: Vec<_> = (0..10)
            .map(|i| {
                (
                    IpAddr::from([10, 0, 0, i as u8]),
                    fv([0.3, 0.2, 0.05, 100.0, 500.0, 0.0]),
                )
            })
            .collect();
        let results = score_ip_anomalies(&entries);
        // 所有 IP 特征相同 → 所有评分应为 0。
        for r in &results {
            assert!(r.score < 1.0, "均匀特征 IP 评分应接近 0，实际 {}", r.score);
        }
    }

    #[test]
    fn outlier_detected() {
        let mut entries: Vec<_> = (0..10)
            .map(|i| {
                (
                    IpAddr::from([10, 0, 0, i as u8]),
                    fv([0.3, 0.2, 0.05, 100.0, 500.0, 0.0]),
                )
            })
            .collect();
        // 添加一个极端异常 IP：SYN 比例 0.99（其他都是 0.3）。
        entries.push((
            IpAddr::from([192, 168, 1, 1]),
            fv([0.99, 0.0, 0.0, 100.0, 500.0, 0.0]),
        ));
        let results = score_ip_anomalies(&entries);
        // 异常 IP 应排在第一位。
        assert_eq!(results[0].ip, IpAddr::from([192, 168, 1, 1]));
        assert!(results[0].score > 0.0, "异常 IP 评分应大于 0");
    }

    #[test]
    fn port_scanner_detected_by_port_diversity() {
        // 端口扫描者的形态：协议比例与包量都正常，只有端口数异常高。
        // 这一维曾是恒 0 的占位（内核未上报），本用例锁定它真的参与评分。
        let mut entries: Vec<_> = (0..10)
            .map(|i| {
                (
                    IpAddr::from([10, 0, 0, i as u8]),
                    fv([0.3, 0.2, 0.05, 100.0, 500.0, 2.0]),
                )
            })
            .collect();
        entries.push((
            IpAddr::from([203, 0, 113, 9]),
            fv([0.3, 0.2, 0.05, 100.0, 500.0, 30.0]),
        ));
        let results = score_ip_anomalies(&entries);
        assert_eq!(
            results[0].ip,
            IpAddr::from([203, 0, 113, 9]),
            "端口数离群的 IP 应排在第一位"
        );
        assert!(
            results[0].dimension_scores[5] > 0.9,
            "port_diversity 维度应判定为异常，实际 {}",
            results[0].dimension_scores[5]
        );
    }

    #[test]
    fn extract_features_zero_packets() {
        let f = extract_ip_features(0, 0, 0, 0, 0, 0);
        assert_eq!(f.0[3], 0.0, "零包时 volume_pps 应为 0");
        assert_eq!(f.0[4], 0.0, "零包时 avg_pkt_size 应为 0");
        assert_eq!(f.0[5], 0.0, "零端口时 port_diversity 应为 0");
    }

    #[test]
    fn extract_features_normal() {
        let f = extract_ip_features(100, 50000, 50, 20, 5, 12);
        assert!((f.0[3] - 100.0).abs() < 1e-9, "volume_pps = packets");
        assert!(
            (f.0[4] - 500.0).abs() < 1e-9,
            "avg_pkt_size = bytes/packets"
        );
        // syn_ratio = 50/100 = 0.5
        assert!((f.0[0] - 0.5).abs() < 1e-9);
        assert!(
            (f.0[5] - 12.0).abs() < 1e-9,
            "port_diversity = unique_ports"
        );
    }

    #[test]
    fn median_odd() {
        assert!((median(&[1.0, 2.0, 3.0]) - 2.0).abs() < 1e-9);
    }

    #[test]
    fn median_even() {
        assert!((median(&[1.0, 2.0, 3.0, 4.0]) - 2.5).abs() < 1e-9);
    }
}
