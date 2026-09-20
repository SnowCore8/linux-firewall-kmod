//! 版本化快照发布点：SSE 只订「变化」，不订「时间」。
//!
//! # 为什么需要它
//!
//! 旧 SSE（`web_ui/sse.rs`）每个 tick 无条件重新取 `stats` / `bans` / `jails` /
//! `whitelist` / `rates` 五份载荷并各自 `serde_json::to_string`，与数据是否变化
//! 无关；每条连接都重复做这件事。封禁较多时 `bans` 是主要成本。
//!
//! 本模块提供两件事：
//!
//! 1. **每个域一个单调版本号**。写侧更新某域后调用 [`Hub::publish`] 就地把该域的
//!    版本 +1；读侧据此判断「这个域变了没有」，从而只序列化变化的部分。
//! 2. **一个 `watch` 通道**用于唤醒。`watch` 的语义是「只保留最新值」——与快照
//!    发布完全吻合：中间版本可以丢，最新版本必须到。这也是背压的取向之一
//!    （事件 → 状态 hub 用覆盖式发布，不排队）。
//!
//! # 它不持有数据
//!
//! 快照本身归各 `state::*` 所有者持有（`Arc<Snapshot>` 原子替换）。`Hub` 只管
//! 版本与通知，因此没有「同一份数据存在两处」的问题：读侧先看版本，再向所有者
//! 取 `Arc`，二者之间即使又发生一次发布，拿到的也仍是**某一个完整版本**的快照。

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::watch;

/// 可独立版本化的状态域。
///
/// 取值集合与 SSE 的按域序列化一一对应：一个域一个 `event:`。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Domain {
    /// 计数器快照。
    Stats,
    /// 活跃封禁。
    Bans,
    /// Jail 列表与状态。
    Jails,
    /// 白名单。
    Whitelist,
    /// 速率与基线。
    Rates,
}

impl Domain {
    /// 全部域，顺序固定。
    ///
    /// [`Versions::changed`] 按此顺序返回，使 SSE 的事件顺序在多次运行间稳定
    /// （测试与前端都能依赖它）。
    pub const ALL: [Self; 5] = [
        Self::Stats,
        Self::Bans,
        Self::Jails,
        Self::Whitelist,
        Self::Rates,
    ];

    /// 域名称（日志与诊断用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stats => "stats",
            Self::Bans => "bans",
            Self::Jails => "jails",
            Self::Whitelist => "whitelist",
            Self::Rates => "rates",
        }
    }
}

/// 每个域各一个单调递增版本号。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Versions {
    stats: u64,
    bans: u64,
    jails: u64,
    whitelist: u64,
    rates: u64,
}

impl Versions {
    /// 全零（尚未发布任何域）。
    #[must_use]
    pub const fn initial() -> Self {
        Self {
            stats: 0,
            bans: 0,
            jails: 0,
            whitelist: 0,
            rates: 0,
        }
    }

    /// 读取某域的当前版本号。
    #[must_use]
    pub const fn get(&self, domain: Domain) -> u64 {
        match domain {
            Domain::Stats => self.stats,
            Domain::Bans => self.bans,
            Domain::Jails => self.jails,
            Domain::Whitelist => self.whitelist,
            Domain::Rates => self.rates,
        }
    }

    /// 把某域的版本 +1，返回新值。
    ///
    /// 单独暴露（而非只在 [`Hub`] 内部用）是为了让「发布」可被纯函数式地测试。
    #[must_use]
    pub const fn bump(mut self, domain: Domain) -> Self {
        let slot = match domain {
            Domain::Stats => &mut self.stats,
            Domain::Bans => &mut self.bans,
            Domain::Jails => &mut self.jails,
            Domain::Whitelist => &mut self.whitelist,
            Domain::Rates => &mut self.rates,
        };
        *slot = slot.wrapping_add(1);
        self
    }

    /// 相比 `before`，哪些域发生了变化（按 [`Domain::ALL`] 顺序）。
    #[must_use]
    pub fn changed(&self, before: Self) -> Vec<Domain> {
        Domain::ALL
            .into_iter()
            .filter(|d| self.get(*d) != before.get(*d))
            .collect()
    }

    /// 是否存在任一域与 `before` 不同。
    #[must_use]
    pub fn is_newer_than(&self, before: Self) -> bool {
        *self != before
    }
}

/// 版本化发布点。写侧 `publish`，读侧 `subscribe` + 向所有者取快照。
#[derive(Debug)]
pub struct Hub {
    versions: RwLock<Versions>,
    tx: watch::Sender<Versions>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    /// 构造初始版本全零的发布点。
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(Versions::initial());
        Self {
            versions: RwLock::new(Versions::initial()),
            tx,
        }
    }

    /// 标记某域已更新：版本 +1 并唤醒订阅者，返回新版本集合。
    pub fn publish(&self, domain: Domain) -> Versions {
        let next = {
            let mut guard = self.versions.write();
            *guard = guard.bump(domain);
            *guard
        };
        // 先更新版本再唤醒：订阅者醒来后读到的版本必定 >= 通知里的版本。
        // `send_replace` 在没有订阅者时也不失败——版本推进与「有没有人看」无关。
        self.tx.send_replace(next);
        next
    }

    /// 读取当前版本集合。
    #[must_use]
    pub fn versions(&self) -> Versions {
        *self.versions.read()
    }

    /// 订阅版本变化。新订阅者立即看到当前版本（`watch` 语义），不需要先等一轮。
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Versions> {
        self.tx.subscribe()
    }
}

/// 与 [`Hub`] 共享的句柄类型。
pub type SharedHub = Arc<Hub>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_hub_reports_every_domain_at_version_zero() {
        let hub = Hub::new();
        let versions = hub.versions();
        for domain in Domain::ALL {
            assert_eq!(versions.get(domain), 0, "{domain:?} 初值应为 0");
        }
    }

    #[test]
    fn publishing_one_domain_leaves_the_others_untouched() {
        let hub = Hub::new();
        hub.publish(Domain::Bans);
        let versions = hub.versions();
        assert_eq!(versions.get(Domain::Bans), 1);
        assert_eq!(versions.get(Domain::Stats), 0);
        assert_eq!(versions.get(Domain::Whitelist), 0);
    }

    #[test]
    fn versions_are_monotonic_per_domain() {
        let hub = Hub::new();
        let mut last = hub.versions();
        for _ in 0..8 {
            let now = hub.publish(Domain::Rates);
            assert!(now.get(Domain::Rates) > last.get(Domain::Rates));
            last = now;
        }
        assert_eq!(hub.versions().get(Domain::Rates), 8);
    }

    #[test]
    fn changed_reports_exactly_the_moved_domains_in_a_stable_order() {
        let before = Versions::initial();
        let after = before
            .bump(Domain::Rates)
            .bump(Domain::Stats)
            .bump(Domain::Rates);
        // 顺序必须与 Domain::ALL 一致，而不是 bump 的先后顺序。
        assert_eq!(after.changed(before), vec![Domain::Stats, Domain::Rates]);
    }

    #[test]
    fn changed_is_empty_when_nothing_moved() {
        let v = Versions::initial();
        assert!(v.changed(v).is_empty());
        assert!(!v.is_newer_than(v));
    }

    #[test]
    fn a_subscriber_created_before_a_publish_is_notified_and_sees_the_new_versions() {
        let hub = Hub::new();
        let rx = hub.subscribe();
        assert!(!rx.has_changed().expect("发送端仍存活"));

        hub.publish(Domain::Whitelist);

        assert!(rx.has_changed().expect("发送端仍存活"));
        assert_eq!(rx.borrow().get(Domain::Whitelist), 1);
    }

    #[test]
    fn a_subscriber_created_after_a_publish_sees_the_current_versions_at_once() {
        // watch 语义：不需要先等一轮变更就能拿到当前值（SSE 首帧依赖这一点）。
        let hub = Hub::new();
        hub.publish(Domain::Bans);
        let rx = hub.subscribe();
        assert_eq!(rx.borrow().get(Domain::Bans), 1);
        assert!(!rx.has_changed().expect("发送端仍存活"));
    }

    #[test]
    fn every_subscriber_observes_the_same_publish() {
        let hub = Hub::new();
        let a = hub.subscribe();
        let b = hub.subscribe();
        hub.publish(Domain::Stats);
        assert!(a.has_changed().expect("发送端仍存活"));
        assert!(b.has_changed().expect("发送端仍存活"));
        assert_eq!(a.borrow().get(Domain::Stats), 1);
        assert_eq!(b.borrow().get(Domain::Stats), 1);
    }

    #[test]
    fn publishing_without_any_subscriber_still_advances_the_versions() {
        // 版本推进与「有没有人看」无关，否则首个 SSE 连接会拿到错的基线。
        let hub = Hub::new();
        hub.publish(Domain::Jails);
        hub.publish(Domain::Jails);
        assert_eq!(hub.versions().get(Domain::Jails), 2);
        let rx = hub.subscribe();
        assert_eq!(rx.borrow().get(Domain::Jails), 2);
    }

    #[test]
    fn a_dropped_hub_is_visible_to_subscribers_as_a_closed_channel() {
        let hub = Hub::new();
        let rx = hub.subscribe();
        drop(hub);
        assert!(rx.has_changed().is_err(), "Hub 消失后应报告通道已关闭");
    }

    #[test]
    fn the_domain_names_are_stable_and_distinct() {
        let names: Vec<&str> = Domain::ALL.iter().map(|d| d.name()).collect();
        assert_eq!(names, vec!["stats", "bans", "jails", "whitelist", "rates"]);
    }
}
