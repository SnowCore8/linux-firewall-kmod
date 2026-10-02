//! 异常检测 API 响应类型。
//!
//! 数据源为 `crate::anomaly::ANOMALY_DETECTOR`（由调度器每 5 分钟驱动更新）。

use serde::Serialize;

/// `GET /api/v1/stats/anomalies` 响应。
#[derive(Serialize)]
pub struct AnomalyResponse {
    /// 全局异常评分（0-100）。
    pub global_score: f64,
    /// 全局各维度偏差分（0-1 归一化）。
    pub global_dimensions: Vec<DimensionScore>,
    /// 全局当前特征值。
    pub global_features: Option<Vec<FeatureValue>>,
    /// 全局 p50 基线。
    pub global_baseline_p50: Vec<FeatureValue>,
    /// 全局 p95 基线。
    pub global_baseline_p95: Vec<FeatureValue>,
    /// 滚动窗口样本数。
    pub global_sample_count: usize,
    /// per-IP 异常 IP 列表（按评分降序）。
    pub ip_anomalies: Vec<IpAnomalyEntry>,
    /// 最近更新时间戳（Unix 秒）。
    pub timestamp: i64,
}

/// 单维度偏差分。
#[derive(Serialize)]
pub struct DimensionScore {
    /// 维度名称。
    pub name: String,
    /// 偏差分（0-1）。
    pub score: f64,
}

/// 单个特征维度的当前值与基线。
#[derive(Serialize)]
pub struct FeatureValue {
    /// 维度名称。
    pub name: String,
    /// 当前值。
    pub value: f64,
}

/// per-IP 异常条目。
#[derive(Serialize)]
pub struct IpAnomalyEntry {
    /// IP 地址。
    pub ip: String,
    /// 异常评分（0-100）。
    pub score: f64,
    /// 各维度偏差分。
    pub dimensions: Vec<DimensionScore>,
}

/// 查询异常检测快照并转换为 API 响应。
pub fn get_anomaly_response() -> AnomalyResponse {
    let snap = crate::anomaly::query();

    let global_dimensions: Vec<DimensionScore> = snap
        .global_dimension_names
        .iter()
        .zip(snap.global_dimension_scores.iter())
        .map(|(name, score)| DimensionScore {
            name: (*name).to_string(),
            score: *score,
        })
        .collect();

    let global_features = snap.global_features.map(|fv| {
        snap.global_dimension_names
            .iter()
            .zip(fv.0.iter())
            .map(|(name, value)| FeatureValue {
                name: (*name).to_string(),
                value: *value,
            })
            .collect()
    });

    let baseline_p50: Vec<FeatureValue> = snap
        .global_dimension_names
        .iter()
        .zip(snap.global_baseline_p50.iter())
        .map(|(name, value)| FeatureValue {
            name: (*name).to_string(),
            value: *value,
        })
        .collect();

    let baseline_p95: Vec<FeatureValue> = snap
        .global_dimension_names
        .iter()
        .zip(snap.global_baseline_p95.iter())
        .map(|(name, value)| FeatureValue {
            name: (*name).to_string(),
            value: *value,
        })
        .collect();

    let ip_anomalies: Vec<IpAnomalyEntry> = snap
        .ip_anomalies
        .iter()
        .map(|a| IpAnomalyEntry {
            ip: a.ip.to_string(),
            score: a.score,
            dimensions: crate::anomaly::per_ip::DIM_NAMES
                .iter()
                .zip(a.dimension_scores.iter())
                .map(|(name, score)| DimensionScore {
                    name: (*name).to_string(),
                    score: *score,
                })
                .collect(),
        })
        .collect();

    AnomalyResponse {
        global_score: snap.global_score,
        global_dimensions,
        global_features,
        global_baseline_p50: baseline_p50,
        global_baseline_p95: baseline_p95,
        global_sample_count: snap.global_sample_count,
        ip_anomalies,
        timestamp: snap.timestamp,
    }
}
