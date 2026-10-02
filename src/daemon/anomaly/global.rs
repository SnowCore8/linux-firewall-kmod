//! 全局流量异常检测。
//!
//! 每 5 分钟从速率快照提取一个 8 维特征向量，维护最近 24 小时的滚动窗口
//! （288 个样本），用滚动 p50/p95 分位判定当前流量是否偏离正常模式。
//!
//! # 特征维度
//!
//! | 索引 | 名称 | 含义 |
//! |------|------|------|
//! | 0 | `syn_ratio` | SYN 包占总包比例 |
//! | 1 | `udp_ratio` | UDP 包占总包比例 |
//! | 2 | `icmp_ratio` | ICMP 包占总包比例 |
//! | 3 | `ack_ratio` | ACK 包占总包比例 |
//! | 4 | `rst_ratio` | RST 包占总包比例 |
//! | 5 | `fin_ratio` | FIN 包占总包比例 |
//! | 6 | `volume_ratio` | 当前 pps / EWMA 基线 pps |
//! | 7 | `active_ips` | 活跃 IP 数（速率表条目数） |

use std::collections::VecDeque;

use super::FeatureVector;

/// 维度数量。
pub const DIM_COUNT: usize = 8;

/// 维度名称（与 [`FeatureVector`] 索引对应）。
pub const DIM_NAMES: [&str; DIM_COUNT] = [
    "syn_ratio",
    "udp_ratio",
    "icmp_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "volume_ratio",
    "active_ips",
];

/// 滚动窗口容量：24h / 5min = 288。
const WINDOW_CAPACITY: usize = 288;

/// 异常判定阈值：分维度偏差分超过此值视为该维度异常。
const ANOMALY_THRESHOLD: f64 = 2.0;

/// 全局异常评分的维度权重。
///
/// 协议比例维度（0-5）等权，体量（6）和活跃 IP 数（7）各占 2 倍权重——
/// 体量的剧烈偏离（如突然翻倍或归零）与 IP 数骤变通常比单一协议比例偏移更显著。
const DIM_WEIGHTS: [f64; DIM_COUNT] = [1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 2.0, 2.0];

/// 最少需要的样本数才输出有意义的评分。
///
/// 低于此值时评分固定为 0（无法判定什么是"正常"）。
const MIN_WARMUP_SAMPLES: usize = 12; // 1 小时

/// 全局流量异常检测器。
#[derive(Debug)]
pub struct GlobalAnomalyDetector {
    /// 滚动窗口（FIFO，最多 WINDOW_CAPACITY 个样本）。
    history: VecDeque<FeatureVector>,
    /// 最近一次评分（0-100）。
    last_score: f64,
    /// 最近一次各维度的偏差分。
    last_dimension_scores: [f64; DIM_COUNT],
    /// 最近一次的特征向量。
    last_features: Option<FeatureVector>,
    /// 最近一次的时间戳（Unix 秒）。
    last_timestamp: i64,
}

impl Default for GlobalAnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl GlobalAnomalyDetector {
    pub fn new() -> Self {
        Self {
            history: VecDeque::with_capacity(WINDOW_CAPACITY),
            last_score: 0.0,
            last_dimension_scores: [0.0; DIM_COUNT],
            last_features: None,
            last_timestamp: 0,
        }
    }

    /// 喂入一个新的特征向量，更新评分。
    pub fn update(&mut self, features: FeatureVector, timestamp: i64) {
        if self.history.len() >= WINDOW_CAPACITY {
            self.history.pop_front();
        }
        self.history.push_back(features);
        self.last_features = Some(features);
        self.last_timestamp = timestamp;
        self.recompute();
    }

    /// 当前评分（0-100）。样本不足时返回 0。
    pub fn score(&self) -> f64 {
        self.last_score
    }

    /// 各维度的偏差分。
    pub fn dimension_scores(&self) -> [f64; DIM_COUNT] {
        self.last_dimension_scores
    }

    /// 最近一次的特征向量。
    pub fn features(&self) -> Option<&FeatureVector> {
        self.last_features.as_ref()
    }

    /// 滚动窗口中的样本数。
    pub fn sample_count(&self) -> usize {
        self.history.len()
    }

    /// 最近一次评分的时间戳。
    pub fn timestamp(&self) -> i64 {
        self.last_timestamp
    }

    /// 各维度的 p50 与 p95 基线。
    pub fn baseline(&self) -> ([f64; DIM_COUNT], [f64; DIM_COUNT]) {
        let mut p50 = [0.0; DIM_COUNT];
        let mut p95 = [0.0; DIM_COUNT];
        if self.history.len() < MIN_WARMUP_SAMPLES {
            return (p50, p95);
        }
        for d in 0..DIM_COUNT {
            let mut vals: Vec<f64> = self.history.iter().map(|f| f[d]).collect();
            vals.sort_by(|a, b| a.total_cmp(b));
            p50[d] = percentile(&vals, 50.0);
            p95[d] = percentile(&vals, 95.0);
        }
        (p50, p95)
    }

    /// 重新计算评分。
    fn recompute(&mut self) {
        let n = self.history.len();
        if n < MIN_WARMUP_SAMPLES {
            self.last_score = 0.0;
            self.last_dimension_scores = [0.0; DIM_COUNT];
            return;
        }

        let current = match &self.last_features {
            Some(f) => f.0,
            None => return,
        };

        let mut dim_scores = [0.0; DIM_COUNT];
        let mut weighted_sum = 0.0;
        let mut weight_total = 0.0;

        for d in 0..DIM_COUNT {
            let mut vals: Vec<f64> = self.history.iter().map(|f| f[d]).collect();
            vals.sort_by(|a, b| a.total_cmp(b));
            let p50 = percentile(&vals, 50.0);
            let p95 = percentile(&vals, 95.0);

            // 偏差分 = (当前值 - p50) / max(p95 - p50, epsilon)
            // p95 == p50 意味着该维度完全稳定，任何偏离都值得注意（用 epsilon 兜底）。
            let iqr = (p95 - p50).max(1e-9);
            let deviation = (current[d] - p50) / iqr;
            // 只关注正向偏离（高于正常范围）——对协议比例和体量来说，
            // "低于 p50" 通常是流量下降，不算异常（除非降到 0，但那由 volume_ratio 捕获）。
            let clamped = deviation.max(0.0);
            // 归一到 0-1：deviation > ANOMALY_THRESHOLD 时饱和为 1。
            let normalized = (clamped / ANOMALY_THRESHOLD).min(1.0);
            dim_scores[d] = normalized;
            weighted_sum += normalized * DIM_WEIGHTS[d];
            weight_total += DIM_WEIGHTS[d];
        }

        self.last_dimension_scores = dim_scores;
        // 加权平均 → 0-1 → 0-100。
        self.last_score = if weight_total > 0.0 {
            (weighted_sum / weight_total) * 100.0
        } else {
            0.0
        };
    }
}

/// 线性插值百分位。`sorted` 必须已排序。
fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = (p / 100.0) * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    let frac = rank - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi.min(sorted.len() - 1)] * frac
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_features(vals: [f64; DIM_COUNT]) -> FeatureVector {
        FeatureVector(vals)
    }

    #[test]
    fn warmup_period_returns_zero_score() {
        let mut det = GlobalAnomalyDetector::new();
        for i in 0..MIN_WARMUP_SAMPLES - 1 {
            det.update(make_features([0.1; DIM_COUNT]), i as i64);
        }
        assert_eq!(det.score(), 0.0, "样本不足时评分应为 0");
    }

    #[test]
    fn stable_traffic_scores_low() {
        let mut det = GlobalAnomalyDetector::new();
        // 喂入 50 个稳定样本（相同特征）。
        for i in 0..50i64 {
            det.update(
                make_features([0.3, 0.2, 0.05, 0.25, 0.1, 0.1, 1.0, 100.0]),
                i,
            );
        }
        // 当前值 = p50 = p95，偏差为 0 → 评分接近 0。
        assert!(
            det.score() < 5.0,
            "稳定流量评分应接近 0，实际 {}",
            det.score()
        );
    }

    #[test]
    fn sudden_spike_scores_high() {
        let mut det = GlobalAnomalyDetector::new();
        let normal = [0.3, 0.2, 0.05, 0.25, 0.1, 0.1, 1.0, 100.0];
        for i in 0..50i64 {
            det.update(make_features(normal), i);
        }
        // 突然 SYN 比例飙升到 0.9（正常 p50=0.3, p95≈0.3）。
        let spike = [0.9, 0.02, 0.01, 0.02, 0.02, 0.02, 1.0, 100.0];
        det.update(make_features(spike), 50);
        assert!(
            det.score() >= 5.0,
            "SYN 比例飙升后评分应升高，实际 {}",
            det.score()
        );
        // syn_ratio 维度得分应最高。
        let scores = det.dimension_scores();
        assert!(scores[0] > scores[1], "syn_ratio 维度偏差应最大");
    }

    #[test]
    fn percentile_basic() {
        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        assert!((percentile(&data, 50.0) - 3.0).abs() < 1e-9);
        assert!((percentile(&data, 0.0) - 1.0).abs() < 1e-9);
        assert!((percentile(&data, 100.0) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn percentile_single_element() {
        let data = vec![42.0];
        assert!((percentile(&data, 50.0) - 42.0).abs() < 1e-9);
        assert!((percentile(&data, 95.0) - 42.0).abs() < 1e-9);
    }

    #[test]
    fn ring_buffer_eviction() {
        let mut det = GlobalAnomalyDetector::new();
        for i in 0..(WINDOW_CAPACITY + 10) as i64 {
            det.update(make_features([0.1; DIM_COUNT]), i);
        }
        assert_eq!(det.sample_count(), WINDOW_CAPACITY, "滚动窗口不超过容量");
    }
}
