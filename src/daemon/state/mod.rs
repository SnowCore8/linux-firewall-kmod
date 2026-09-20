//! 状态层：每个数据域**单所有者**，读侧拿不可变快照。
//!
//! # 分层
//!
//! - [`cidr`]：白名单 CIDR 的唯一规范化实现。键是 [`cidr::CidrKey`] 而不是
//!   `String`，使「插入了未规范化的键」不可表达（修缺陷 M）。
//! - [`hub`]：版本化发布点。每个域一个单调版本号，SSE 据此只序列化变化的域；
//!   唤醒走 `watch`（只保留最新值，与快照语义吻合）。
//! - [`bans`] / [`whitelist`] / [`rates`] / [`stats`]：四个数据所有者。写侧独占
//!   自己的状态，读侧只经快照方法取 `Arc<不可变快照>` 或只读计数器——
//!   **读路径不改状态、不推进版本、不动统计**（修缺陷 E）。
//! - [`State`]：把四个所有者与 hub 装在一起的聚合，由组合根构造一次并注入。
//!
//! # 为什么不用服务定位器
//!
//! 旧实现把状态放在 `OnceLock` / `LazyLock` 全局里（`ACTIVE_BAN_CACHE`、
//! `WHITELIST_CACHE`、`RATE_CACHE`、`DAEMON_STATS`…），跨模块读写共享可变全局，
//! 并为此维护一套「6 步锁获取顺序」的文档约定。本层的模块一律由组合根
//! 构造并注入：跨模块传递的是**消息**或 `Arc<不可变快照>`，锁顺序协议不再
//! 需要，读路径也不再能顺手改统计（缺陷 E 的根因）。
//!
//! # 变更 → 版本 的对应关系
//!
//! 每当某个所有者真正发生变更（值不同），它就推进对应域的版本号并唤醒订阅者。
//! **无变化的写入不推进版本**：内核会重复广播同一条 `BanStateChange`，每 60 s
//! 全量对账一次白名单，每 1 s 推一次速率——数值没变时惊动 SSE 只是浪费。

pub mod bans;
pub mod cidr;
pub mod hub;
pub mod rates;
pub mod stats;
pub mod whitelist;

use std::sync::Arc;

pub use bans::{BanEntry, BanSnapshot, Bans};
pub use cidr::{CidrError, CidrKey};
pub use hub::{Domain, Hub, SharedHub, Versions};
pub use rates::{RateCounters, RateSample, RateSnapshot, Rates};
pub use stats::{Counter, Stats, StatsSnapshot};
pub use whitelist::{Whitelist, WhitelistEntry, WhitelistSnapshot};

/// 状态聚合：四个所有者 + 一个版本化发布点。
///
/// 组合根构造**一次**（通常经 [`State::new`] 拿到 `Arc<Self>`），然后把 `Arc` 交给
/// 需要它的模块。没有全局单例，也没有 `get_global_*()` 家族。
pub struct State {
    hub: SharedHub,
    bans: Bans,
    whitelist: Whitelist,
    rates: Rates,
    stats: Stats,
}

impl Default for State {
    fn default() -> Self {
        Self::new_inner()
    }
}

impl State {
    /// 构造一套共享同一 hub 的状态。
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::new_inner())
    }

    /// 构造状态，复用外部已有的 hub（供测试注入自定义版本起点）。
    #[must_use]
    pub fn with_hub(hub: SharedHub) -> Arc<Self> {
        Arc::new(Self {
            bans: Bans::new(Arc::clone(&hub)),
            whitelist: Whitelist::new(Arc::clone(&hub)),
            rates: Rates::new(Arc::clone(&hub)),
            stats: Stats::new(),
            hub,
        })
    }

    fn new_inner() -> Self {
        let hub: SharedHub = Arc::new(Hub::new());
        Self {
            bans: Bans::new(Arc::clone(&hub)),
            whitelist: Whitelist::new(Arc::clone(&hub)),
            rates: Rates::new(Arc::clone(&hub)),
            stats: Stats::new(),
            hub,
        }
    }

    /// 版本化发布点（SSE 订阅它）。
    #[must_use]
    pub fn hub(&self) -> &SharedHub {
        &self.hub
    }

    /// 活跃封禁所有者。
    #[must_use]
    pub fn bans(&self) -> &Bans {
        &self.bans
    }

    /// 白名单所有者。
    #[must_use]
    pub fn whitelist(&self) -> &Whitelist {
        &self.whitelist
    }

    /// 速率与基线所有者。
    #[must_use]
    pub fn rates(&self) -> &Rates {
        &self.rates
    }

    /// 计数器。
    #[must_use]
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试输入应为合法 IP")
    }

    #[test]
    fn a_fresh_state_has_every_domain_at_version_zero() {
        let state = State::new();
        let versions = state.hub().versions();
        for domain in Domain::ALL {
            assert_eq!(versions.get(domain), 0, "{domain:?} 初值应为 0");
        }
    }

    #[test]
    fn all_four_owners_share_one_hub() {
        // 四个所有者必须发布到同一个版本源，否则 SSE 会漏掉某些域。
        let state = State::new();

        state.bans().insert(BanEntry::new(
            ip("10.0.0.1"),
            "sshd",
            "r",
            100,
            200,
            false,
            1,
            1,
        ));
        state
            .whitelist()
            .insert(CidrKey::parse("192.168.0.0/24").expect("可解析"), "");
        state.rates().apply(RateSample {
            global_pps: 10,
            global_bps: 100,
            per_ip: std::collections::BTreeMap::new(),
        });
        state.stats().inc(Counter::LinesParsed);

        let versions = state.hub().versions();
        assert_eq!(versions.get(Domain::Bans), 1);
        assert_eq!(versions.get(Domain::Whitelist), 1);
        assert_eq!(versions.get(Domain::Rates), 1);
        // 计数器不经 hub 发布（只增原子量，读侧直接 load）；统计域版本保持 0。
        assert_eq!(versions.get(Domain::Stats), 0);
    }

    #[test]
    fn reading_every_snapshot_leaves_the_versions_untouched() {
        // 缺陷 E：读路径不得改状态，也不得推进版本。
        let state = State::new();
        state.bans().insert(BanEntry::new(
            ip("10.0.0.1"),
            "sshd",
            "r",
            100,
            200,
            false,
            1,
            1,
        ));
        let before = state.hub().versions();

        let _ = state.bans().snapshot();
        let _ = state.whitelist().snapshot();
        let _ = state.rates().snapshot();
        let _ = state.stats().snapshot();

        assert_eq!(state.hub().versions(), before);
    }

    #[test]
    fn injecting_a_hub_lets_the_caller_observe_versions_directly() {
        let hub: SharedHub = Arc::new(Hub::new());
        let state = State::with_hub(Arc::clone(&hub));
        state
            .whitelist()
            .insert(CidrKey::parse("10.0.0.0/24").expect("可解析"), "");
        assert_eq!(hub.versions().get(Domain::Whitelist), 1);
    }

    #[test]
    fn the_aggregate_is_shareable_across_threads() {
        // 组合根把 Arc<State> 交给多个执行体，必须满足 Send + Sync。
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<State>();
        assert_send_sync::<Arc<State>>();
        let state = State::new();
        let clone = Arc::clone(&state);
        let handle = std::thread::spawn(move || {
            clone.stats().inc(Counter::InotifyEvents);
        });
        handle.join().expect("线程应正常结束");
        assert_eq!(state.stats().get(Counter::InotifyEvents), 1);
    }
}
