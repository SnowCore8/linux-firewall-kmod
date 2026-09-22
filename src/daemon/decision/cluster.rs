//! 集群扫描检测：**一个网段内出现多个不同源 IP** 的判定。
//!
//! # 为什么需要它
//!
//! 单 IP 计数（[`FailureWindow`]）的形状是「同一 IP 在 `findtime` 内失败 ≥ N 次即封」。
//! 这恰好与扫描/暴破的形态相反：扫描器**每个源 IP 只用一两次**，永远碰不到单 IP
//! 阈值；而频繁访问的正常访客（浏览器加载页面、单出口多用户）反而会被封。已停用的
//! `frp` jail 正是这个方向性错误：它封住了访客、漏掉了扫描器。
//!
//! 真实数据上的可分性（2026-09-22 实测，frps 全量 6337 条连接）：
//!
//! | 流量 | 网段内不同 IP 数 | 每 IP 失败数 |
//! |------|------------------|--------------|
//! | 正常访客（单用户/单出口） | 1 | 多 |
//! | CGNAT（多用户共用出口） | 多 | 多 |
//! | 分布式扫描 / 暴破 | 多 | **少** |
//!
//! 判据因此是「网段内不同源 IP 数 ≥ `min_ips`，**且**这些 IP 各自的失败数
//! ≤ `max_per_ip`」——第二条把 CGNAT 与正常高频访客排除在外，是判据不误伤的关键。
//!
//! # 边界
//!
//! 本模块只做**纯计算**：不碰封禁表、不下发报文、不写全局态；是否处置由调用方决定
//! （与 [`crate::decision::policy`] 同一约定）。IPv6 默认按 `/48` 聚合，因为 `/24`
//! 在 IPv6 上不构成一个有意义的边界。

use std::collections::BTreeMap;
use std::net::IpAddr;

use crate::decision::window::FailureWindow;
use crate::state::cidr::CidrKey;

/// IPv4 默认聚合前缀（一个 C 类网段）。
pub const DEFAULT_PREFIX_V4: u8 = 24;
/// IPv6 默认聚合前缀（`/24` 在 IPv6 上无意义，取覆盖单站点常用的一段）。
pub const DEFAULT_PREFIX_V6: u8 = 48;

/// 集群检测参数（每 jail 一份，来自 jail 配置的 `cluster` 段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClusterConfig {
    /// 是否启用集群检测。
    pub enabled: bool,
    /// 只记录不封禁（上线初期观察用）。
    pub audit_only: bool,
    /// IPv4 聚合前缀长度。
    pub prefix_v4: u8,
    /// IPv6 聚合前缀长度。
    pub prefix_v6: u8,
    /// 观测窗口（秒）。
    pub window: u32,
    /// 命中所需的最小不同源 IP 数。
    pub min_ips: u32,
    /// 单个源 IP 允许的失败数上限（超过则视为「高频」而排除）。
    pub max_per_ip: u32,
    /// 命中后该网段的封禁时长（秒）。
    pub ban_time: u32,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            audit_only: true,
            prefix_v4: DEFAULT_PREFIX_V4,
            prefix_v6: DEFAULT_PREFIX_V6,
            window: 60,
            min_ips: 5,
            max_per_ip: 3,
            ban_time: 3600,
        }
    }
}

impl ClusterConfig {
    /// 该地址族使用的聚合前缀长度。
    #[must_use]
    pub fn prefix_for(&self, ip: IpAddr) -> u8 {
        match ip {
            IpAddr::V4(_) => self.prefix_v4,
            IpAddr::V6(_) => self.prefix_v6,
        }
    }
}

/// 一次集群命中。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterHit {
    /// 命中的网段（已按前缀归一化，主机位为零）。
    pub cidr: CidrKey,
    /// 网段内被计为「低频」的源 IP（升序，即参与判定的那些）。
    pub ips: Vec<IpAddr>,
    /// 该网段内观测到的最大单 IP 失败数（用于日志与诊断）。
    pub peak: u32,
}

impl ClusterHit {
    /// 供日志与封禁原因使用的一行摘要。
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "集群扫描: {} 命中 {} 个源 IP（峰值 {} 次）",
            self.cidr,
            self.ips.len(),
            self.peak
        )
    }
}

/// 取某 IP 所属的聚合网段键。
#[must_use]
pub fn subnet_key(ip: IpAddr, cfg: &ClusterConfig) -> CidrKey {
    CidrKey::new(ip, cfg.prefix_for(ip))
}

/// 在失败窗口中检出集群扫描，返回命中的网段（按网段升序，结果可复现）。
///
/// 判定：网段内「失败数 ≤ `cfg.max_per_ip`」的不同源 IP 数 ≥ `cfg.min_ips`。
///
/// # Arguments
/// - `window`: 该 jail 的失败窗口（只读，不改动）
/// - `now`: 当前 Unix 秒（由调用方注入，本函数纯粹于时钟）
/// - `cfg`: 集群检测参数
#[must_use]
pub fn detect(window: &FailureWindow, now: i64, cfg: &ClusterConfig) -> Vec<ClusterHit> {
    if !cfg.enabled || cfg.window == 0 || cfg.min_ips == 0 {
        return Vec::new();
    }

    // `peek` 把计数截断在 `cap`；取 `max_per_ip + 1` 即可判定「是否超过上限」，
    // 无需拿到精确计数（与 `FailureWindow::observe` 的 cap 语义一致）。
    let cap = cfg.max_per_ip.saturating_add(1);
    let groups = group_by_subnet(window, now, cfg, cap);

    let mut hits = Vec::new();
    for (cidr, members) in groups {
        let quiet = count_quiet(&members, cfg.max_per_ip);
        if quiet < u64::from(cfg.min_ips) {
            continue;
        }
        let mut ips: Vec<IpAddr> = members
            .iter()
            .filter(|(_, count)| *count <= cfg.max_per_ip)
            .map(|(ip, _)| *ip)
            .collect();
        ips.sort_unstable();
        let peak = members.iter().map(|(_, count)| *count).max().unwrap_or(0);
        hits.push(ClusterHit { cidr, ips, peak });
    }
    hits
}

/// 把窗口中「窗口内有失败」的 IP 按网段分组。
fn group_by_subnet(
    window: &FailureWindow,
    now: i64,
    cfg: &ClusterConfig,
    cap: u32,
) -> BTreeMap<CidrKey, Vec<(IpAddr, u32)>> {
    let mut groups: BTreeMap<CidrKey, Vec<(IpAddr, u32)>> = BTreeMap::new();
    for (ip, _last_seen) in window.iter() {
        let count = window.peek(ip, now, cfg.window, cap);
        if count == 0 {
            continue;
        }
        groups
            .entry(subnet_key(ip, cfg))
            .or_default()
            .push((ip, count));
    }
    groups
}

/// 统计组内「失败数 ≤ 上限」的 IP 个数。
fn count_quiet(members: &[(IpAddr, u32)], max_per_ip: u32) -> u64 {
    members
        .iter()
        .filter(|(_, count)| *count <= max_per_ip)
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试用 IP 必须合法")
    }

    fn cfg() -> ClusterConfig {
        ClusterConfig {
            enabled: true,
            audit_only: false,
            min_ips: 3,
            max_per_ip: 2,
            window: 60,
            ..ClusterConfig::default()
        }
    }

    /// 往窗口里给 `ip` 记 `times` 次失败（同一时刻）。
    fn seed(window: &mut FailureWindow, ip: IpAddr, times: u32, now: i64, cfg: &ClusterConfig) {
        for _ in 0..times {
            let _ = window.observe(ip, now, cfg.window, u32::MAX);
        }
    }

    #[test]
    fn hits_when_enough_low_frequency_ips_share_a_subnet() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 10_000_i64;
        for host in [1, 2, 3] {
            seed(&mut w, ip(&format!("203.0.113.{host}")), 2, now, &c);
        }
        let hits = detect(&w, now, &c);
        assert_eq!(hits.len(), 1, "三个 /24 内低频 IP 应命中一个网段");
        assert_eq!(hits[0].cidr.as_str(), "203.0.113.0/24");
        assert_eq!(hits[0].ips.len(), 3);
        assert_eq!(hits[0].peak, 2);
    }

    #[test]
    fn needs_exactly_min_ips() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 20_000_i64;
        seed(&mut w, ip("198.51.100.1"), 1, now, &c);
        seed(&mut w, ip("198.51.100.2"), 1, now, &c);
        assert!(
            detect(&w, now, &c).is_empty(),
            "只有 2 个 IP（min_ips=3）不应命中"
        );
        seed(&mut w, ip("198.51.100.3"), 1, now, &c);
        assert_eq!(detect(&w, now, &c).len(), 1, "第 3 个 IP 应使其命中");
    }

    #[test]
    fn high_frequency_ip_is_excluded_from_the_quiet_set() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 30_000_i64;
        // 三个低频 IP 命中；再加一个高频 IP 不应改变结论。
        for host in [1, 2, 3] {
            seed(&mut w, ip(&format!("192.0.2.{host}")), 1, now, &c);
        }
        seed(&mut w, ip("192.0.2.99"), 50, now, &c);
        let hits = detect(&w, now, &c);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ips.len(), 3, "高频 IP 不应进入参与判定的集合");
        assert_eq!(hits[0].peak, 3, "峰值应反映被截断到 max_per_ip + 1 的计数");
    }

    #[test]
    fn cgnat_shaped_traffic_does_not_hit() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 40_000_i64;
        // 多 IP、每个都超过 max_per_ip：形如 CGNAT 出口，不应判为集群扫描。
        for host in [10, 20, 30, 40] {
            seed(&mut w, ip(&format!("198.18.0.{host}")), 5, now, &c);
        }
        assert!(
            detect(&w, now, &c).is_empty(),
            "每个 IP 都高频时不判集群（否则会误封 CGNAT）"
        );
    }

    #[test]
    fn subnet_boundary_ips_are_separate_groups() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 50_000_i64;
        // .255 属于 10.0.0.0/24 而不是 10.0.1.0/24；后者自己凑够 min_ips。
        seed(&mut w, ip("10.0.0.255"), 1, now, &c);
        seed(&mut w, ip("10.0.1.1"), 1, now, &c);
        seed(&mut w, ip("10.0.1.2"), 1, now, &c);
        seed(&mut w, ip("10.0.1.3"), 1, now, &c);
        let hits = detect(&w, now, &c);
        assert_eq!(hits.len(), 1, "只有 10.0.1.0/24 达到 min_ips");
        assert_eq!(hits[0].cidr.as_str(), "10.0.1.0/24");
        assert_eq!(hits[0].ips.len(), 3, ".255 不应被并进 10.0.1.0/24");
    }

    #[test]
    fn failures_outside_the_window_are_not_counted() {
        let c = cfg();
        let mut w = FailureWindow::new();
        seed(&mut w, ip("203.0.113.1"), 1, 1_000, &c);
        seed(&mut w, ip("203.0.113.2"), 1, 1_000, &c);
        seed(&mut w, ip("203.0.113.3"), 1, 1_000, &c);
        assert!(
            detect(&w, 1_000 + i64::from(c.window) + 1, &c).is_empty(),
            "窗口外的时间戳不应参与判定"
        );
    }

    #[test]
    fn ipv6_uses_the_v6_prefix() {
        let c = cfg();
        let mut w = FailureWindow::new();
        let now = 60_000_i64;
        for host in 1..=3 {
            seed(&mut w, ip(&format!("2001:db8:0:{host}::1")), 1, now, &c);
        }
        let hits = detect(&w, now, &c);
        assert_eq!(hits.len(), 1, "IPv6 应按 /48 聚合同一网段");
        assert_eq!(hits[0].cidr.as_str(), "2001:db8::/48");
    }

    #[test]
    fn disabled_or_degenerate_config_returns_empty() {
        let mut w = FailureWindow::new();
        let now = 70_000_i64;
        let base = cfg();
        seed(&mut w, ip("203.0.113.1"), 1, now, &base);
        seed(&mut w, ip("203.0.113.2"), 1, now, &base);
        seed(&mut w, ip("203.0.113.3"), 1, now, &base);

        let off = ClusterConfig {
            enabled: false,
            ..base
        };
        assert!(detect(&w, now, &off).is_empty(), "未启用时应返回空");

        let zero_window = ClusterConfig { window: 0, ..base };
        assert!(
            detect(&w, now, &zero_window).is_empty(),
            "窗口为 0 时应返回空"
        );

        let zero_min = ClusterConfig { min_ips: 0, ..base };
        assert!(
            detect(&w, now, &zero_min).is_empty(),
            "min_ips 为 0 时应返回空（否则任意流量都被判集群）"
        );
    }

    #[test]
    fn summary_mentions_cidr_and_counts() {
        let hit = ClusterHit {
            cidr: CidrKey::new(ip("203.0.113.7"), 24),
            ips: vec![ip("203.0.113.1"), ip("203.0.113.2")],
            peak: 2,
        };
        let text = hit.summary();
        assert!(
            text.contains("203.0.113.0/24"),
            "摘要应含归一化网段: {text}"
        );
        assert!(text.contains('2'), "摘要应含计数: {text}");
    }
}
