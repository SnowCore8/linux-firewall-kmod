//! 速率与 EWMA 基线的**单所有者**。
//!
//! # 数据形态
//!
//! 每轮查询（内核 `ListRatesResponse` 全量分页）产出一份 [`RateSample`]：全局
//! `pps`/`bps` 加上按 IP 的条目。本模块持有最新样本与一根 EWMA 基线。
//!
//! # 背压取向
//!
//! 「内核速率响应 → 状态」是**覆盖式**的：新样本整个替换旧样本，中间样本可以丢，
//! 最新样本必须到。这与 [`super::hub`] 的 `watch` 语义一致，故这里不做排队——
//! 排队只会让读侧看到一份过期的速率。
//!
//! # EWMA 与预热
//!
//! 收敛速度按样本数分两段（与旧实现一致）：预热期用较大的 α 快速收敛，样本数达到
//! `warmup_samples` 后切到小 α 长期跟踪。基线一旦「冻结」就不再更新——冻结意味着
//! 已积累足够样本，可作为动态阈值的稳定参照。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use super::hub::{Domain, SharedHub};

/// 单个 IP 的速率。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RateCounters {
    /// 包/秒。
    pub packets: u64,
    /// 字节/秒。
    pub bytes: u64,
    /// SYN 包/秒。
    pub syn: u64,
    /// UDP 包/秒。
    pub udp: u64,
    /// ICMP 包/秒。
    pub icmp: u64,
    /// ACK 包/秒。
    pub ack: u64,
    /// RST 包/秒。
    pub rst: u64,
    /// FIN 包/秒。
    pub fin: u64,
}

/// 一轮速率查询的完整样本。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RateSample {
    /// 全局包/秒（`ListRatesResponse.global_pps`，取最后一页）。
    pub global_pps: u64,
    /// 全局字节/秒（`ListRatesResponse.global_bps`，取最后一页）。
    pub global_bps: u64,
    /// 按 IP 的速率（按 IP 升序）。
    pub per_ip: BTreeMap<IpAddr, RateCounters>,
}

impl RateSample {
    /// 被跟踪的 IP 数。
    #[must_use]
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.len()
    }

    /// 按 IP 取速率。
    #[must_use]
    pub fn get(&self, ip: &IpAddr) -> Option<&RateCounters> {
        self.per_ip.get(ip)
    }
}

/// 速率快照：最新样本 + EWMA 基线 + 冻结标志。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RateSnapshot {
    /// 最新一轮样本。
    pub sample: Arc<RateSample>,
    /// EWMA 基线（包/秒）。
    pub baseline_pps: u64,
    /// EWMA 基线（字节/秒）。
    pub baseline_bps: u64,
    /// 基线是否已冻结（样本足够，不再更新）。
    pub baseline_frozen: bool,
    /// 已累积的基线样本数。
    pub baseline_samples: u32,
}

/// 速率与基线的单所有者。
pub struct Rates {
    sample: RwLock<Arc<RateSample>>,
    baseline: RwLock<Baseline>,
    hub: SharedHub,
}

/// EWMA 基线的内部状态。
#[derive(Clone, Copy, Debug)]
struct Baseline {
    pps: f64,
    bps: f64,
    samples: u32,
    warmup_samples: u32,
    frozen: bool,
}

/// 预热期学习率（快速收敛）。
const WARMUP_ALPHA: f64 = 0.1;
/// 长期学习率（稳定跟踪）。
const STEADY_ALPHA: f64 = 0.01;
/// 默认预热样本数。
const DEFAULT_WARMUP_SAMPLES: u32 = 50;

impl Default for Baseline {
    fn default() -> Self {
        Self {
            pps: 0.0,
            bps: 0.0,
            samples: 0,
            warmup_samples: DEFAULT_WARMUP_SAMPLES,
            frozen: false,
        }
    }
}

impl Baseline {
    /// 用一份新样本推进基线；返回是否发生了变化。
    fn observe(&mut self, pps: u64, bps: u64) -> bool {
        if self.frozen {
            return false;
        }
        #[allow(clippy::cast_precision_loss)]
        let (p, b) = (pps as f64, bps as f64);
        if self.samples == 0 {
            // 首个样本直接作为起点，避免从 0 缓慢爬升。
            self.pps = p;
            self.bps = b;
        } else {
            let alpha = if self.samples < self.warmup_samples {
                WARMUP_ALPHA
            } else {
                STEADY_ALPHA
            };
            self.pps += alpha * (p - self.pps);
            self.bps += alpha * (b - self.bps);
        }
        self.samples = self.samples.saturating_add(1);
        true
    }

    fn snapshot(&self) -> (u64, u64, bool, u32) {
        // 基线是速率参照，负值无意义；取整并截断到 0。
        let pps = self.pps.max(0.0).round();
        let bps = self.bps.max(0.0).round();
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        (pps as u64, bps as u64, self.frozen, self.samples)
    }

    /// 冻结基线（此后不再更新）。
    fn freeze(&mut self) {
        self.frozen = true;
    }
}

impl Rates {
    /// 构造空所有者；变更会发布到 `hub` 的 [`Domain::Rates`]。
    #[must_use]
    pub fn new(hub: SharedHub) -> Self {
        Self {
            sample: RwLock::new(Arc::new(RateSample::default())),
            baseline: RwLock::new(Baseline::default()),
            hub,
        }
    }

    /// 用一轮新样本覆盖式更新速率，并推进 EWMA 基线。
    ///
    /// 返回 `true` 表示速率或基线确有变化。完全相同的新样本不推进版本号
    /// （内核每 1 s 推一次，空闲时数值不变）。
    pub fn apply(&self, sample: RateSample) -> bool {
        let sample = Arc::new(sample);
        let sample_changed = {
            let mut current = self.sample.write();
            if **current == *sample {
                false
            } else {
                *current = Arc::clone(&sample);
                true
            }
        };
        let baseline_changed = {
            let mut baseline = self.baseline.write();
            baseline.observe(sample.global_pps, sample.global_bps)
        };
        if sample_changed || baseline_changed {
            self.hub.publish(Domain::Rates);
            true
        } else {
            false
        }
    }

    /// 冻结基线（样本足够后停止更新）。
    pub fn freeze_baseline(&self) {
        let changed = {
            let mut baseline = self.baseline.write();
            if baseline.frozen {
                false
            } else {
                baseline.freeze();
                true
            }
        };
        if changed {
            self.hub.publish(Domain::Rates);
        }
    }

    /// 设置预热样本数（配置热重载时调用）。
    pub fn set_warmup_samples(&self, samples: u32) {
        self.baseline.write().warmup_samples = samples;
    }

    /// 取一份速率快照。
    #[must_use]
    pub fn snapshot(&self) -> RateSnapshot {
        let sample = Arc::clone(&self.sample.read());
        let (baseline_pps, baseline_bps, baseline_frozen, baseline_samples) =
            self.baseline.read().snapshot();
        RateSnapshot {
            sample,
            baseline_pps,
            baseline_bps,
            baseline_frozen,
            baseline_samples,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::hub::Hub;

    fn hub() -> SharedHub {
        Arc::new(Hub::new())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试输入应为合法 IP")
    }

    fn sample(pps: u64, bps: u64) -> RateSample {
        RateSample {
            global_pps: pps,
            global_bps: bps,
            per_ip: BTreeMap::new(),
        }
    }

    #[test]
    fn a_fresh_owner_starts_from_an_empty_sample() {
        let rates = Rates::new(hub());
        let snap = rates.snapshot();
        assert_eq!(snap.sample.global_pps, 0);
        assert_eq!(snap.sample.tracked_ips(), 0);
        assert_eq!(snap.baseline_samples, 0);
        assert!(!snap.baseline_frozen);
    }

    #[test]
    fn applying_a_new_sample_replaces_the_previous_one() {
        let rates = Rates::new(hub());
        assert!(rates.apply(sample(100, 1_000)));
        let snap = rates.snapshot();
        assert_eq!(snap.sample.global_pps, 100);
        assert_eq!(snap.sample.global_bps, 1_000);
    }

    #[test]
    fn the_first_sample_seeds_the_baseline_rather_than_ramping_from_zero() {
        let rates = Rates::new(hub());
        rates.apply(sample(500, 5_000));
        let snap = rates.snapshot();
        assert_eq!(snap.baseline_pps, 500);
        assert_eq!(snap.baseline_bps, 5_000);
        assert_eq!(snap.baseline_samples, 1);
    }

    #[test]
    fn the_baseline_converges_toward_a_steady_input() {
        let rates = Rates::new(hub());
        for _ in 0..200 {
            rates.apply(sample(1_000, 10_000));
        }
        let snap = rates.snapshot();
        // 输入恒定，基线应收敛到该值附近。
        assert!(
            snap.baseline_pps.abs_diff(1_000) <= 1,
            "基线应收敛到 1000，实得 {}",
            snap.baseline_pps
        );
    }

    #[test]
    fn the_baseline_tracks_an_upward_shift() {
        let rates = Rates::new(hub());
        for _ in 0..100 {
            rates.apply(sample(100, 1_000));
        }
        for _ in 0..400 {
            rates.apply(sample(900, 9_000));
        }
        let snap = rates.snapshot();
        assert!(
            snap.baseline_pps > 700,
            "基线应随输入上移，实得 {}",
            snap.baseline_pps
        );
    }

    #[test]
    fn a_frozen_baseline_stops_following_the_input() {
        let rates = Rates::new(hub());
        rates.apply(sample(100, 1_000));
        rates.apply(sample(100, 1_000));
        rates.freeze_baseline();
        let frozen = rates.snapshot().baseline_pps;
        for _ in 0..100 {
            rates.apply(sample(9_999, 99_999));
        }
        let snap = rates.snapshot();
        assert!(snap.baseline_frozen);
        assert_eq!(snap.baseline_pps, frozen, "冻结后基线不应再变");
    }

    #[test]
    fn identical_samples_do_not_bump_the_version() {
        // 内核每 1 s 推一次速率；空闲时数值不变，不该惊动 SSE。
        let h = hub();
        let rates = Rates::new(Arc::clone(&h));
        rates.apply(sample(50, 500));
        let v = h.versions().get(Domain::Rates);
        // 第二份完全相同的样本：样本未变，但基线仍会推进（samples +1）。
        rates.apply(sample(50, 500));
        assert_eq!(h.versions().get(Domain::Rates), v + 1);
        // 冻结后完全相同的样本不再推进任何东西。
        rates.freeze_baseline();
        let v2 = h.versions().get(Domain::Rates);
        assert!(!rates.apply(sample(50, 500)), "冻结且样本相同应报告无变化");
        assert_eq!(h.versions().get(Domain::Rates), v2);
    }

    #[test]
    fn a_mutation_bumps_only_the_rates_domain() {
        let h = hub();
        let rates = Rates::new(Arc::clone(&h));
        rates.apply(sample(1, 1));
        assert_eq!(h.versions().get(Domain::Rates), 1);
        assert_eq!(h.versions().get(Domain::Stats), 0);
    }

    #[test]
    fn per_ip_counters_are_kept_verbatim() {
        let rates = Rates::new(hub());
        let mut s = sample(200, 2_000);
        s.per_ip.insert(
            ip("10.0.0.1"),
            RateCounters {
                packets: 120,
                bytes: 1_200,
                syn: 5,
                udp: 0,
                icmp: 1,
                ack: 100,
                rst: 2,
                fin: 3,
            },
        );
        rates.apply(s);
        let snap = rates.snapshot();
        assert_eq!(snap.sample.tracked_ips(), 1);
        let c = snap.sample.get(&ip("10.0.0.1")).expect("应能查到");
        assert_eq!(c.packets, 120);
        assert_eq!(c.syn, 5);
        assert_eq!(c.fin, 3);
    }

    #[test]
    fn reading_a_snapshot_does_not_mutate_the_baseline() {
        let rates = Rates::new(hub());
        rates.apply(sample(100, 1_000));
        let before = rates.snapshot();
        for _ in 0..5 {
            let _ = rates.snapshot();
        }
        assert_eq!(rates.snapshot().baseline_samples, before.baseline_samples);
    }

    #[test]
    fn a_zeroed_sample_does_not_produce_a_negative_baseline() {
        let rates = Rates::new(hub());
        rates.apply(sample(0, 0));
        let snap = rates.snapshot();
        assert_eq!(snap.baseline_pps, 0);
        assert_eq!(snap.baseline_bps, 0);
    }
}
