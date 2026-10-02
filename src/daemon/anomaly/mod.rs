//! 异常检测：全局流量基线偏离 + per-IP 行为离群。
//!
//! 两层检测共享同一数据源（`state::rates::RateSnapshot`），每 5 分钟由调度器驱动更新：
//!
//! | 层 | 方法 | 作用 |
//! |---|---|---|
//! | 全局（[`global`]） | 滚动 p50/p95 分位，加权偏差评分 | 发现整体流量模式偏移（新型攻击向量、零日扫描） |
//! | per-IP（[`per_ip`]） | MAD 群体离群检测 | 发现行为异常个体（慢速扫描、隐蔽隧道） |
//!
//! 检测结果仅观测展示（API + 前端面板），不触发自动封禁。

pub mod global;
pub mod per_ip;

use std::net::IpAddr;

use parking_lot::RwLock;

use crate::state::rates::RateSnapshot;

// ---------------------------------------------------------------------------
// 特征向量类型
// ---------------------------------------------------------------------------

/// 全局流量特征向量（8 维）。
///
/// 维度含义见 [`global::DIM_NAMES`]。
#[derive(Clone, Copy, Debug)]
pub struct FeatureVector(pub [f64; global::DIM_COUNT]);

impl std::ops::Index<usize> for FeatureVector {
    type Output = f64;
    fn index(&self, idx: usize) -> &f64 {
        &self.0[idx]
    }
}

/// per-IP 行为特征向量（6 维）。
///
/// 维度含义见 [`per_ip::DIM_NAMES`]。
#[derive(Clone, Copy, Debug)]
pub struct IpFeatureVector(pub [f64; 6]);

impl std::ops::Index<usize> for IpFeatureVector {
    type Output = f64;
    fn index(&self, idx: usize) -> &f64 {
        &self.0[idx]
    }
}

// ---------------------------------------------------------------------------
// 检测器聚合
// ---------------------------------------------------------------------------

/// 异常检测结果的完整快照。
#[derive(Clone, Debug)]
pub struct AnomalySnapshot {
    /// 全局异常评分（0-100）。
    pub global_score: f64,
    /// 全局各维度偏差分（8 维，0-1 归一化）。
    pub global_dimension_scores: [f64; global::DIM_COUNT],
    /// 全局各维度名称。
    pub global_dimension_names: [&'static str; global::DIM_COUNT],
    /// 全局当前特征向量。
    pub global_features: Option<FeatureVector>,
    /// 全局 p50 基线。
    pub global_baseline_p50: [f64; global::DIM_COUNT],
    /// 全局 p95 基线。
    pub global_baseline_p95: [f64; global::DIM_COUNT],
    /// 全局滚动窗口样本数。
    pub global_sample_count: usize,
    /// per-IP 异常 IP 列表（按评分降序，最多 [`per_ip::TOP_ANOMALOUS_LIMIT`] 个）。
    pub ip_anomalies: Vec<per_ip::IpAnomaly>,
    /// 最近更新时间戳（Unix 秒）。
    pub timestamp: i64,
}

/// 异常检测器。
///
/// 全局单例 [`ANOMALY_DETECTOR`] 持有，由调度器每 5 分钟驱动 [`update`]。
pub struct AnomalyDetector {
    global_det: global::GlobalAnomalyDetector,
    last_ip_anomalies: Vec<per_ip::IpAnomaly>,
    last_timestamp: i64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            global_det: global::GlobalAnomalyDetector::new(),
            last_ip_anomalies: Vec::new(),
            last_timestamp: 0,
        }
    }

    /// 喂入一轮速率快照，更新全局与 per-IP 评分。
    pub fn update(&mut self, snapshot: &RateSnapshot, timestamp: i64) {
        self.last_timestamp = timestamp;

        // 全局特征提取。
        let global_features = extract_global_features(snapshot);
        self.global_det.update(global_features, timestamp);

        // per-IP 特征提取与评分。
        let ip_entries: Vec<(IpAddr, IpFeatureVector)> = snapshot
            .sample
            .per_ip
            .iter()
            .map(|(ip, c)| {
                let fv = per_ip::extract_ip_features(
                    c.packets,
                    c.bytes,
                    c.syn,
                    c.udp,
                    c.icmp,
                    c.unique_ports,
                );
                (*ip, fv)
            })
            .collect();
        self.last_ip_anomalies = per_ip::score_ip_anomalies(&ip_entries);
    }

    /// 生成当前快照（供 API 读取）。
    pub fn snapshot(&self) -> AnomalySnapshot {
        let (p50, p95) = self.global_det.baseline();
        AnomalySnapshot {
            global_score: self.global_det.score(),
            global_dimension_scores: self.global_det.dimension_scores(),
            global_dimension_names: global::DIM_NAMES,
            global_features: self.global_det.features().copied(),
            global_baseline_p50: p50,
            global_baseline_p95: p95,
            global_sample_count: self.global_det.sample_count(),
            ip_anomalies: self.last_ip_anomalies.clone(),
            timestamp: self.last_timestamp,
        }
    }
}

/// 从速率快照提取全局特征向量。
fn extract_global_features(snapshot: &RateSnapshot) -> FeatureVector {
    let mut total_packets: u64 = 0;
    let mut total_syn: u64 = 0;
    let mut total_udp: u64 = 0;
    let mut total_icmp: u64 = 0;
    let mut total_ack: u64 = 0;
    let mut total_rst: u64 = 0;
    let mut total_fin: u64 = 0;

    for c in snapshot.sample.per_ip.values() {
        total_packets = total_packets.saturating_add(c.packets);
        total_syn = total_syn.saturating_add(c.syn);
        total_udp = total_udp.saturating_add(c.udp);
        total_icmp = total_icmp.saturating_add(c.icmp);
        total_ack = total_ack.saturating_add(c.ack);
        total_rst = total_rst.saturating_add(c.rst);
        total_fin = total_fin.saturating_add(c.fin);
    }

    let total = total_packets.max(1);
    let syn_ratio = total_syn as f64 / total as f64;
    let udp_ratio = total_udp as f64 / total as f64;
    let icmp_ratio = total_icmp as f64 / total as f64;
    let ack_ratio = total_ack as f64 / total as f64;
    let rst_ratio = total_rst as f64 / total as f64;
    let fin_ratio = total_fin as f64 / total as f64;

    // volume_ratio: 当前 pps / 基线 pps。基线为 0 时（预热期）用 1.0 兜底。
    let baseline = snapshot.baseline_pps.max(1);
    let volume_ratio = snapshot.sample.global_pps as f64 / baseline as f64;

    let active_ips = snapshot.sample.tracked_ips() as f64;

    FeatureVector([
        syn_ratio,
        udp_ratio,
        icmp_ratio,
        ack_ratio,
        rst_ratio,
        fin_ratio,
        volume_ratio,
        active_ips,
    ])
}

// ---------------------------------------------------------------------------
// 全局单例
// ---------------------------------------------------------------------------

/// 全局异常检测器实例。
///
/// 由 `runtime::scheduler` 每 5 分钟调用 [`update`]，API 通过 [`query`] 读取快照。
pub static ANOMALY_DETECTOR: once_cell::sync::Lazy<RwLock<AnomalyDetector>> =
    once_cell::sync::Lazy::new(|| RwLock::new(AnomalyDetector::new()));

/// 喂入一轮速率快照（由调度器调用）。
pub fn update(snapshot: &RateSnapshot, timestamp: i64) {
    ANOMALY_DETECTOR.write().update(snapshot, timestamp);
}

/// 读取当前异常快照（由 API handler 调用）。
pub fn query() -> AnomalySnapshot {
    ANOMALY_DETECTOR.read().snapshot()
}

/// 调度器入口：从全局状态取速率快照并驱动异常检测更新。
///
/// 由 `runtime::scheduler` 每 5 分钟调用一次。`GLOBAL_STATE` 未注入时（启动初期）
/// 静默跳过，不报错。
pub fn update_anomaly_tick(timestamp: i64) {
    let Some(state) = crate::state::global_state() else {
        return;
    };
    let snapshot = state.rates().snapshot();
    ANOMALY_DETECTOR.write().update(&snapshot, timestamp);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn make_rate_snapshot(
        pps: u64,
        bps: u64,
        ips: &[(IpAddr, u64, u64, u64, u64, u64)],
    ) -> RateSnapshot {
        make_rate_snapshot_with_ports(pps, bps, ips, 0)
    }

    /// 与 [`make_rate_snapshot`] 同形，但给所有 IP 指定同一个端口数。
    fn make_rate_snapshot_with_ports(
        pps: u64,
        bps: u64,
        ips: &[(IpAddr, u64, u64, u64, u64, u64)],
        unique_ports: u32,
    ) -> RateSnapshot {
        let mut per_ip = BTreeMap::new();
        for (ip, pkts, bytes, syn, udp, icmp) in ips {
            per_ip.insert(
                *ip,
                crate::state::rates::RateCounters {
                    packets: *pkts,
                    bytes: *bytes,
                    syn: *syn,
                    udp: *udp,
                    icmp: *icmp,
                    ack: 0,
                    rst: 0,
                    fin: 0,
                    unique_ports,
                },
            );
        }
        RateSnapshot {
            sample: Arc::new(crate::state::rates::RateSample {
                global_pps: pps,
                global_bps: bps,
                per_ip,
            }),
            baseline_pps: pps,
            baseline_bps: bps,
            baseline_frozen: false,
            baseline_samples: 100,
        }
    }

    #[test]
    fn empty_snapshot_no_crash() {
        let snap = make_rate_snapshot(0, 0, &[]);
        let mut det = AnomalyDetector::new();
        det.update(&snap, 1000);
        let result = det.snapshot();
        assert_eq!(result.global_score, 0.0);
        assert!(result.ip_anomalies.is_empty());
    }

    #[test]
    fn global_feature_extraction_ratios() {
        let ips = vec![
            (IpAddr::from([1, 1, 1, 1]), 100, 50000, 50, 20, 5),
            (IpAddr::from([2, 2, 2, 2]), 200, 100000, 100, 40, 10),
        ];
        let snap = make_rate_snapshot(300, 150000, &ips);
        let features = extract_global_features(&snap);
        // total = 300 packets, syn = 150 → ratio = 0.5
        assert!((features[0] - 0.5).abs() < 1e-9, "syn_ratio 应为 0.5");
        // udp = 60/300 = 0.2
        assert!((features[1] - 0.2).abs() < 1e-9, "udp_ratio 应为 0.2");
        // icmp = 15/300 = 0.05
        assert!((features[2] - 0.05).abs() < 1e-9, "icmp_ratio 应为 0.05");
        // active_ips = 2
        assert!((features[7] - 2.0).abs() < 1e-9, "active_ips 应为 2");
    }

    #[test]
    fn detector_warmup_and_scoring() {
        let mut det = AnomalyDetector::new();
        let normal_ips: Vec<_> = (0..10)
            .map(|i| {
                (
                    IpAddr::from([10, 0, 0, i as u8]),
                    100u64,
                    50000u64,
                    30u64,
                    20u64,
                    5u64,
                )
            })
            .collect();
        let snap = make_rate_snapshot(1000, 500000, &normal_ips);

        // 喂入 15 轮稳定数据（超过 MIN_WARMUP_SAMPLES=12）。
        for i in 0..15 {
            det.update(&snap, i64::from(i) * 300);
        }
        let result = det.snapshot();
        // 稳定数据 → 全局评分应很低。
        assert!(
            result.global_score < 10.0,
            "稳定流量全局评分应 < 10，实际 {}",
            result.global_score
        );
        assert_eq!(result.global_sample_count, 15);
    }

    #[test]
    fn unique_ports_reaches_the_ip_features() {
        // 端到端锁定「内核上报的端口数 → per-IP 特征」这一段不再断链：
        // 快照里给的端口数必须原样出现在特征的 port_diversity 维度上。
        let ips: Vec<_> = (0..6)
            .map(|i| {
                (
                    IpAddr::from([10, 0, 0, i as u8]),
                    100u64,
                    50000u64,
                    30u64,
                    20u64,
                    5u64,
                )
            })
            .collect();
        let snap = make_rate_snapshot_with_ports(600, 300000, &ips, 17);

        let mut det = AnomalyDetector::new();
        det.update(&snap, 0);

        let result = det.snapshot();
        let entry = result
            .ip_anomalies
            .first()
            .expect("6 个活跃 IP 超过 MIN_ACTIVE_IPS，应产出异常列表");
        assert!(
            (entry.features.0[5] - 17.0).abs() < 1e-9,
            "port_diversity 应取自快照的 unique_ports，实际 {}",
            entry.features.0[5]
        );
    }
}
