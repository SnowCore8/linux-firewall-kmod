//! 活跃封禁的**单所有者**。
//!
//! # 读写分离
//!
//! 写侧（本模块的 `insert` / `remove` / `purge_expired`）独占数据；读侧只
//! `snapshot()` 拿一份 `Arc<BanSnapshot>`，看不到半个更新，也**改不动任何东西**。
//!
//! 这直接消除结构问题 E：旧 `get_active_bans()`（`web_ui/ban_ops.rs`）在**读**路径
//! 里做限流 `purge_expired`，并顺手改 `DAEMON_STATS.total_unbans` 与喂
//! `record_ban_duration`。于是「读一次封禁列表」会改变统计数字，SSE 每秒读一次，
//! 统计就每秒被读路径改写。现在 purge 是 [`Bans::purge_expired`]，只由 scheduler
//! 的独立任务调用，且**返回**被清掉的条目，让调用方自己决定要不要记统计。
//!
//! # 快照是派生值，不是第二份状态
//!
//! `snapshot()` 把内部表映射成不可变 `Vec`+索引并缓存。缓存是**派生值的记忆化**：
//! 它不改动条目、不动计数器、对外不可观测；有变更时缓存失效，下一次 `snapshot()`
//! 重建。这样读侧仍是纯的（缺陷 E 的判据是「读改状态」，不是「读不能有缓存」），
//! 同时避免每秒为每条 SSE 连接重建一次全表。

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::RwLock;

use super::hub::{Domain, SharedHub};

/// 快照里的一条封禁（不可变）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanEntry {
    /// 被封禁的 IP。
    pub ip: IpAddr,
    /// 触发封禁的 jail。
    pub jail: String,
    /// 封禁原因。
    pub reason: String,
    /// 封禁时间（Unix 秒）。
    pub banned_at: i64,
    /// 过期时间（Unix 秒）；0 或永久封禁时为 0。
    pub expires_at: i64,
    /// 是否永久封禁。
    pub is_permanent: bool,
    /// 该 IP 累计被封禁次数（渐进式封禁：第 1/2/3/4+ 次）。
    pub ban_count: u32,
    /// 触发封禁前的失败次数。
    pub fail_count: u32,
}

impl BanEntry {
    /// 构造一条封禁。
    ///
    /// 八个字段一一对应，不设 `builder`：这是纯数据条目，字段之间没有可推导的
    /// 关系，构造器参数多寡与语义复杂度一致。
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ip: IpAddr,
        jail: impl Into<String>,
        reason: impl Into<String>,
        banned_at: i64,
        expires_at: i64,
        is_permanent: bool,
        ban_count: u32,
        fail_count: u32,
    ) -> Self {
        Self {
            ip,
            jail: jail.into(),
            reason: reason.into(),
            banned_at,
            expires_at,
            is_permanent,
            ban_count,
            fail_count,
        }
    }

    /// 该封禁是否已过期（永久封禁永不过期）。
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        !self.is_permanent && self.expires_at > 0 && now >= self.expires_at
    }

    /// 剩余秒数；永久封禁返回 `-1`（与 HTTP 契约的 `remaining_seconds` 一致），
    /// 已过期返回 `0`，不返回负数。
    #[must_use]
    pub fn remaining_secs(&self, now: i64) -> i64 {
        if self.is_permanent {
            return -1;
        }
        (self.expires_at - now).max(0)
    }

    /// 本次封禁的持续时长（秒）。
    #[must_use]
    pub fn duration_secs(&self, now: i64) -> i64 {
        if self.is_permanent || self.expires_at == 0 {
            (now - self.banned_at).max(0)
        } else {
            (self.expires_at - self.banned_at).max(0)
        }
    }
}

/// 活跃封禁的不可变快照。
///
/// 由 [`Bans::snapshot`] 构造，条目按 IP 升序排列——顺序稳定，读侧与测试都能依赖。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BanSnapshot {
    entries: Vec<BanEntry>,
    per_jail: BTreeMap<String, usize>,
}

impl BanSnapshot {
    /// 条目（按 IP 升序）。
    #[must_use]
    pub fn entries(&self) -> &[BanEntry] {
        &self.entries
    }

    /// 条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 按 IP 查条目。
    #[must_use]
    pub fn get(&self, ip: &IpAddr) -> Option<&BanEntry> {
        self.entries
            .binary_search_by(|e| e.ip.cmp(ip))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// 某个 jail 名下的封禁数。
    #[must_use]
    pub fn count_for_jail(&self, jail: &str) -> usize {
        self.per_jail.get(jail).copied().unwrap_or(0)
    }

    /// 出现过的 jail 名（升序）。
    pub fn jails(&self) -> impl Iterator<Item = &str> {
        self.per_jail.keys().map(String::as_str)
    }

    /// 由已排序的条目列表构造（内部用）。
    fn from_sorted(entries: Vec<BanEntry>) -> Self {
        let mut per_jail: BTreeMap<String, usize> = BTreeMap::new();
        for e in &entries {
            *per_jail.entry(e.jail.clone()).or_insert(0) += 1;
        }
        Self { entries, per_jail }
    }
}

/// 活跃封禁的单所有者。
pub struct Bans {
    entries: RwLock<BTreeMap<IpAddr, BanEntry>>,
    cache: RwLock<Option<Arc<BanSnapshot>>>,
    hub: SharedHub,
}

impl Bans {
    /// 构造空所有者；变更会发布到 `hub` 的 [`Domain::Bans`]。
    #[must_use]
    pub fn new(hub: SharedHub) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            cache: RwLock::new(None),
            hub,
        }
    }

    /// 插入或替换一条封禁。
    ///
    /// 若新条目与已有条目完全相同，视为**无变化**：不失效缓存、不推进版本号，
    /// 返回 `false`。内核会重复广播同一条 `BanStateChange`，无变化就不该惊动 SSE。
    pub fn insert(&self, entry: BanEntry) -> bool {
        let key = entry.ip;
        let changed = {
            let mut table = self.entries.write();
            // 先比对再决定是否改动：完全相同的条目视为无变化。
            let changed = match table.get(&key) {
                Some(existing) => *existing != entry,
                None => true,
            };
            if changed {
                table.insert(key, entry);
            }
            changed
        };
        if changed {
            self.invalidate_and_publish();
        }
        changed
    }

    /// 移除一条封禁，返回被移除的条目。
    pub fn remove(&self, ip: &IpAddr) -> Option<BanEntry> {
        let removed = self.entries.write().remove(ip);
        if removed.is_some() {
            self.invalidate_and_publish();
        }
        removed
    }

    /// 移除全部**非永久**封禁，返回被移除的条目（供批量解封使用）。
    pub fn remove_all_temporary(&self) -> Vec<BanEntry> {
        let removed = {
            let mut table = self.entries.write();
            let victims: Vec<IpAddr> = table
                .values()
                .filter(|e| !e.is_permanent)
                .map(|e| e.ip)
                .collect();
            victims
                .into_iter()
                .filter_map(|ip| table.remove(&ip))
                .collect::<Vec<_>>()
        };
        if !removed.is_empty() {
            self.invalidate_and_publish();
        }
        removed
    }

    /// 清掉已过期的封禁，返回被清掉的条目。
    ///
    /// **只应由 scheduler 的独立周期任务调用**，不挂在任何读路径上（结构问题 E）。
    /// 返回值让调用方决定统计动作——统计不再由读路径顺手改写。
    pub fn purge_expired(&self, now: i64) -> Vec<BanEntry> {
        let removed = {
            let mut table = self.entries.write();
            let victims: Vec<IpAddr> = table
                .values()
                .filter(|e| e.is_expired(now))
                .map(|e| e.ip)
                .collect();
            victims
                .into_iter()
                .filter_map(|ip| table.remove(&ip))
                .collect::<Vec<_>>()
        };
        if !removed.is_empty() {
            self.invalidate_and_publish();
        }
        removed
    }

    /// 当前条目数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// 是否为空。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    /// 取一份不可变快照。
    ///
    /// 首次调用（或变更后首次调用）重建并缓存，其后共享同一个 `Arc`。纯读：
    /// 不改条目、不动统计。
    #[must_use]
    pub fn snapshot(&self) -> Arc<BanSnapshot> {
        if let Some(cached) = self.cache.read().as_ref() {
            return Arc::clone(cached);
        }
        let built = Arc::new(BanSnapshot::from_sorted(
            self.entries.read().values().cloned().collect(),
        ));
        *self.cache.write() = Some(Arc::clone(&built));
        built
    }

    /// 失效缓存后发布版本。
    ///
    /// 顺序有意为之：**先释放数据锁再发布**。读侧是「先读版本、再取快照」，
    /// 若这里在持数据锁时去拿 hub 的锁，就与读侧形成锁序反转。
    fn invalidate_and_publish(&self) {
        *self.cache.write() = None;
        self.hub.publish(Domain::Bans);
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

    fn entry(ip_str: &str, jail: &str, banned_at: i64, expires_at: i64) -> BanEntry {
        BanEntry::new(ip(ip_str), jail, "test", banned_at, expires_at, false, 1, 5)
    }

    #[test]
    fn a_fresh_owner_holds_nothing() {
        let bans = Bans::new(hub());
        assert!(bans.is_empty());
        assert!(bans.snapshot().is_empty());
    }

    #[test]
    fn inserting_an_entry_makes_it_visible_in_the_snapshot() {
        let bans = Bans::new(hub());
        assert!(bans.insert(entry("10.0.0.1", "sshd", 100, 200)));

        let snap = bans.snapshot();
        assert_eq!(snap.len(), 1);
        let found = snap.get(&ip("10.0.0.1")).expect("应能查到");
        assert_eq!(found.jail, "sshd");
    }

    #[test]
    fn an_identical_reinsert_is_reported_as_no_change() {
        // 内核会重复广播同一条 BanStateChange；无变化就不该推进版本号。
        let bans = Bans::new(hub());
        let e = entry("10.0.0.1", "sshd", 100, 200);
        assert!(bans.insert(e.clone()));
        let v1 = bans.snapshot();
        assert!(!bans.insert(e), "完全相同的条目应视为无变化");
        assert!(Arc::ptr_eq(&v1, &bans.snapshot()), "无变化时不应重建快照");
    }

    #[test]
    fn replacing_an_entry_with_different_fields_is_a_change() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 200));
        let changed = bans.insert(entry("10.0.0.1", "sshd", 100, 300));
        assert!(changed);
        assert_eq!(bans.snapshot().len(), 1, "同 IP 应被替换而不是新增");
        assert_eq!(
            bans.snapshot().get(&ip("10.0.0.1")).unwrap().expires_at,
            300
        );
    }

    #[test]
    fn a_mutation_bumps_the_bans_domain_version() {
        let h = hub();
        let bans = Bans::new(Arc::clone(&h));
        assert_eq!(h.versions().get(Domain::Bans), 0);
        bans.insert(entry("10.0.0.1", "sshd", 100, 200));
        assert_eq!(h.versions().get(Domain::Bans), 1);
        bans.remove(&ip("10.0.0.1"));
        assert_eq!(h.versions().get(Domain::Bans), 2);
        // 其他域不受影响。
        assert_eq!(h.versions().get(Domain::Whitelist), 0);
    }

    #[test]
    fn a_no_op_mutation_does_not_bump_the_version() {
        let h = hub();
        let bans = Bans::new(Arc::clone(&h));
        assert!(bans.remove(&ip("10.0.0.9")).is_none());
        assert_eq!(h.versions().get(Domain::Bans), 0, "空操作不应推进版本");
    }

    #[test]
    fn removing_returns_the_entry_that_was_there() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 200));
        let gone = bans.remove(&ip("10.0.0.1")).expect("应返回被移除的条目");
        assert_eq!(gone.jail, "sshd");
        assert!(bans.is_empty());
    }

    #[test]
    fn purge_removes_only_expired_entries() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 150)); // 已过期
        bans.insert(entry("10.0.0.2", "sshd", 100, 500)); // 仍有效
        bans.insert(BanEntry::new(
            ip("10.0.0.3"),
            "sshd",
            "permanent",
            100,
            0,
            true,
            1,
            5,
        ));

        let removed = bans.purge_expired(200);
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].ip, ip("10.0.0.1"));
        let snap = bans.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.get(&ip("10.0.0.3")).is_some(), "永久封禁不应被清");
    }

    #[test]
    fn purge_never_removes_a_permanent_entry_however_late_the_clock() {
        let bans = Bans::new(hub());
        bans.insert(BanEntry::new(
            ip("10.0.0.3"),
            "sshd",
            "permanent",
            100,
            0,
            true,
            1,
            5,
        ));
        assert!(bans.purge_expired(i64::MAX).is_empty());
    }

    #[test]
    fn reading_a_snapshot_does_not_purge_or_otherwise_mutate() {
        // 结构问题 E 的核心断言：读路径不得改状态。
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 150)); // 早已过期
        for _ in 0..5 {
            let _ = bans.snapshot();
        }
        assert_eq!(bans.len(), 1, "读快照不应清掉过期条目");
        assert_eq!(bans.snapshot().len(), 1);
    }

    #[test]
    fn removing_all_temporary_leaves_permanent_entries_alone() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 500));
        bans.insert(entry("10.0.0.2", "nginx", 100, 500));
        bans.insert(BanEntry::new(
            ip("10.0.0.3"),
            "sshd",
            "permanent",
            100,
            0,
            true,
            1,
            5,
        ));

        let removed = bans.remove_all_temporary();
        assert_eq!(removed.len(), 2);
        let snap = bans.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap.entries()[0].ip, ip("10.0.0.3"));
    }

    #[test]
    fn the_snapshot_is_ordered_by_ip_so_reads_are_reproducible() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.3", "sshd", 100, 500));
        bans.insert(entry("10.0.0.1", "sshd", 100, 500));
        bans.insert(entry("10.0.0.2", "sshd", 100, 500));
        let ips: Vec<IpAddr> = bans.snapshot().entries().iter().map(|e| e.ip).collect();
        assert_eq!(ips, vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")]);
    }

    #[test]
    fn the_snapshot_counts_entries_per_jail() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 500));
        bans.insert(entry("10.0.0.2", "sshd", 100, 500));
        bans.insert(entry("10.0.0.3", "nginx", 100, 500));
        let snap = bans.snapshot();
        assert_eq!(snap.count_for_jail("sshd"), 2);
        assert_eq!(snap.count_for_jail("nginx"), 1);
        assert_eq!(snap.count_for_jail("absent"), 0);
        assert_eq!(snap.jails().collect::<Vec<_>>(), vec!["nginx", "sshd"]);
    }

    #[test]
    fn repeated_snapshots_are_cached_until_a_mutation() {
        let bans = Bans::new(hub());
        bans.insert(entry("10.0.0.1", "sshd", 100, 500));
        let a = bans.snapshot();
        let b = bans.snapshot();
        assert!(Arc::ptr_eq(&a, &b), "无变更时读侧应共享同一份快照");
        bans.insert(entry("10.0.0.2", "sshd", 100, 500));
        let c = bans.snapshot();
        assert!(!Arc::ptr_eq(&b, &c), "变更后应重建快照");
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn remaining_seconds_follows_the_http_contract_shape() {
        let permanent = BanEntry::new(ip("10.0.0.1"), "j", "r", 100, 0, true, 1, 1);
        assert_eq!(permanent.remaining_secs(1_000), -1, "永久封禁为 -1");
        let timed = entry("10.0.0.2", "j", 100, 200);
        assert_eq!(timed.remaining_secs(150), 50);
        assert_eq!(timed.remaining_secs(999), 0, "过期后为 0，不返回负数");
    }

    #[test]
    fn duration_is_measured_from_the_ban_time() {
        let timed = entry("10.0.0.2", "j", 100, 200);
        assert_eq!(timed.duration_secs(999), 100, "定时封禁用过期时间算");
        let permanent = BanEntry::new(ip("10.0.0.1"), "j", "r", 100, 0, true, 1, 1);
        assert_eq!(permanent.duration_secs(150), 50, "永久封禁用当前时间算");
    }
}
