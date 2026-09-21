//! 白名单的**单所有者**，键是规范化的 [`CidrKey`]。
//!
//! # 缺陷 M 的修法
//!
//! 旧实现有三处各自构造 CIDR 缓存键（LIST 响应、状态变更事件、`ban/mod.rs` 的
//! `build_cidr_key`），规则互不相同；同一子网因此可能拿到两个键，LIST 覆盖与事件
//! 移除互不抵消。这三处**已全部删除**（随旧 `netlink/` 层与 `build_cidr_key` 退役）。
//! 现在本模块把键类型定为 [`CidrKey`]——它只能经规范化构造器产生
//! （见 [`super::cidr`]）——于是每条写入路径**必然**落在同一个键空间，
//! 「插了一个未规范化的键」在本模块里不可表达。
//!
//! # 与 HTTP 形状的关系
//!
//! `CidrKey` 的文本形式就是契约里 `cidr` 字段的取值，也是
//! `DELETE /api/v1/whitelist/:cidr` 的路径参数。故前端用 `GET` 拿到的字符串可以
//! 原样回传给 `DELETE`，不需要前端再做一次规范化——规范化只有 daemon 侧一处。

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;

use super::cidr::CidrKey;
use super::hub::{Domain, SharedHub};

/// 快照里的一条白名单（不可变）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhitelistEntry {
    /// 规范化后的 CIDR。
    pub cidr: CidrKey,
    /// 限定设备；空串表示不限定。
    pub device: String,
}

/// 白名单的不可变快照（按规范化 CIDR 升序）。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct WhitelistSnapshot {
    entries: Vec<WhitelistEntry>,
}

impl WhitelistSnapshot {
    /// 条目（按规范化 CIDR 升序）。
    #[must_use]
    pub fn entries(&self) -> &[WhitelistEntry] {
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

    /// 按规范化 CIDR 查条目。
    #[must_use]
    pub fn get(&self, cidr: &CidrKey) -> Option<&WhitelistEntry> {
        self.entries
            .binary_search_by(|e| e.cidr.cmp(cidr))
            .ok()
            .map(|i| &self.entries[i])
    }

    /// 是否含该 CIDR。
    #[must_use]
    pub fn contains(&self, cidr: &CidrKey) -> bool {
        self.get(cidr).is_some()
    }
}

/// 白名单的单所有者。
pub struct Whitelist {
    /// 键为规范化 CIDR，值为设备限定（空串表示不限定）。
    entries: RwLock<BTreeMap<CidrKey, String>>,
    cache: RwLock<Option<Arc<WhitelistSnapshot>>>,
    hub: SharedHub,
}

impl Whitelist {
    /// 构造空所有者；变更会发布到 `hub` 的 [`Domain::Whitelist`]。
    #[must_use]
    pub fn new(hub: SharedHub) -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            cache: RwLock::new(None),
            hub,
        }
    }

    /// 插入或更新一条白名单。
    ///
    /// 设备名沿用旧事件路径的语义：新值为空时**保留**已有设备，避免内核事件不带
    /// 设备名时把已记录的限定抹掉。
    ///
    /// 返回 `true` 表示确有变化。
    pub fn insert(&self, cidr: CidrKey, device: impl Into<String>) -> bool {
        let device = device.into();
        let changed = {
            let mut table = self.entries.write();
            match table.get_mut(&cidr) {
                Some(existing) => {
                    if device.is_empty() || *existing == device {
                        false
                    } else {
                        *existing = device;
                        true
                    }
                }
                None => {
                    table.insert(cidr, device);
                    true
                }
            }
        };
        if changed {
            self.invalidate_and_publish();
        }
        changed
    }

    /// 移除一条白名单，返回其设备限定（若有）。
    pub fn remove(&self, cidr: &CidrKey) -> Option<String> {
        let removed = self.entries.write().remove(cidr);
        if removed.is_some() {
            self.invalidate_and_publish();
        }
        removed
    }

    /// 用一整套条目**替换**白名单（对应内核 LIST 响应的全量覆盖）。
    ///
    /// 返回 `true` 表示内容确有变化。空输入同样是一次合法覆盖（内核表为空）。
    pub fn replace_all(&self, incoming: impl IntoIterator<Item = (CidrKey, String)>) -> bool {
        let next: BTreeMap<CidrKey, String> = incoming.into_iter().collect();
        let changed = {
            let mut table = self.entries.write();
            if *table == next {
                false
            } else {
                *table = next;
                true
            }
        };
        if changed {
            self.invalidate_and_publish();
        }
        changed
    }

    /// 是否含该 CIDR。
    #[must_use]
    pub fn contains(&self, cidr: &CidrKey) -> bool {
        self.entries.read().contains_key(cidr)
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

    /// 取一份不可变快照（缓存语义同 [`super::bans::Bans::snapshot`]）。
    #[must_use]
    pub fn snapshot(&self) -> Arc<WhitelistSnapshot> {
        if let Some(cached) = self.cache.read().as_ref() {
            return Arc::clone(cached);
        }
        let entries: Vec<WhitelistEntry> = self
            .entries
            .read()
            .iter()
            .map(|(cidr, device)| WhitelistEntry {
                cidr: cidr.clone(),
                device: device.clone(),
            })
            .collect();
        let built = Arc::new(WhitelistSnapshot { entries });
        *self.cache.write() = Some(Arc::clone(&built));
        built
    }

    /// 失效缓存后发布版本（先释放数据锁再发布，避免与读侧形成锁序反转）。
    fn invalidate_and_publish(&self) {
        *self.cache.write() = None;
        self.hub.publish(Domain::Whitelist);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::hub::Hub;
    use std::net::IpAddr;

    fn hub() -> SharedHub {
        Arc::new(Hub::new())
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试输入应为合法 IP")
    }

    fn key(s: &str) -> CidrKey {
        CidrKey::parse(s).expect("测试输入应为合法 CIDR")
    }

    #[test]
    fn a_fresh_owner_holds_nothing() {
        let wl = Whitelist::new(hub());
        assert!(wl.is_empty());
        assert!(wl.snapshot().is_empty());
    }

    #[test]
    fn the_two_old_write_paths_now_cancel_each_other() {
        // 缺陷 M 的核心断言：LIST 路径写入的键与事件路径移除的键必须相等。
        // 旧实现里 LIST 恒拼 "/24"，而事件路径在 /32・/128・/0 时省略前缀；
        // 两者对同一子网的写法不同，故移除落空。现在两条路径都过 CidrKey 规范化。
        let wl = Whitelist::new(hub());
        // LIST 路径：内核回传 10.0.0.5 与 prefix 24（未归一化地址）。
        wl.replace_all([(CidrKey::new(ip("10.0.0.5"), 24), String::new())]);
        assert!(wl.contains(&key("10.0.0.0/24")));

        // 事件路径：内核广播同一子网的移除，地址写成网络地址形式。
        let removed = wl.remove(&CidrKey::new(ip("10.0.0.0"), 24));
        assert!(removed.is_some(), "两种写法必须落在同一个键上");
        assert!(wl.is_empty());
    }

    #[test]
    fn a_host_entry_written_two_ways_is_one_entry() {
        let wl = Whitelist::new(hub());
        wl.insert(CidrKey::new(ip("192.168.1.7"), 32), "");
        assert_eq!(wl.len(), 1);
        // 同一主机条目再写一次（裸地址形式），不应新增。
        assert!(!wl.insert(key("192.168.1.7"), ""));
        assert_eq!(wl.len(), 1);
    }

    #[test]
    fn entries_are_ordered_by_normalized_cidr() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "");
        wl.insert(key("10.0.0.0/16"), "");
        wl.insert(key("192.168.0.0/24"), "");
        let order: Vec<String> = wl
            .snapshot()
            .entries()
            .iter()
            .map(|e| e.cidr.to_string())
            .collect();
        assert_eq!(order, vec!["10.0.0.0/16", "10.0.0.0/24", "192.168.0.0/24"]);
    }

    #[test]
    fn replace_all_overwrites_the_previous_contents_completely() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "");
        wl.insert(key("192.168.0.0/24"), "");
        let changed = wl.replace_all([(key("172.16.0.0/12"), "eth0".to_string())]);
        assert!(changed);
        assert_eq!(wl.len(), 1);
        assert!(wl.contains(&key("172.16.0.0/12")));
        assert!(!wl.contains(&key("10.0.0.0/24")));
    }

    #[test]
    fn replace_all_with_identical_contents_reports_no_change() {
        // 内核每 60 s 全量对账一次；内容没变时不该惊动 SSE。
        let wl = Whitelist::new(hub());
        wl.replace_all([(key("10.0.0.0/24"), String::new())]);
        let changed = wl.replace_all([(key("10.0.0.0/24"), String::new())]);
        assert!(!changed);
    }

    #[test]
    fn replace_all_with_an_empty_set_is_a_valid_overwrite() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "");
        assert!(wl.replace_all(Vec::new()));
        assert!(wl.is_empty());
    }

    #[test]
    fn the_device_name_is_kept_when_the_new_value_is_empty() {
        // 内核状态变更事件可能不带设备名，不能因此把已记录的限定抹掉。
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "eth0");
        assert!(!wl.insert(key("10.0.0.0/24"), ""), "空设备名视为无变化");
        assert_eq!(wl.snapshot().entries()[0].device, "eth0");
    }

    #[test]
    fn a_non_empty_device_name_replaces_the_old_one() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "eth0");
        assert!(wl.insert(key("10.0.0.0/24"), "eth1"));
        assert_eq!(wl.snapshot().entries()[0].device, "eth1");
    }

    #[test]
    fn a_mutation_bumps_the_whitelist_domain_version() {
        let h = hub();
        let wl = Whitelist::new(Arc::clone(&h));
        wl.insert(key("10.0.0.0/24"), "");
        assert_eq!(h.versions().get(Domain::Whitelist), 1);
        assert_eq!(h.versions().get(Domain::Bans), 0, "别的域不受影响");
        wl.remove(&key("10.0.0.0/24"));
        assert_eq!(h.versions().get(Domain::Whitelist), 2);
    }

    #[test]
    fn a_no_op_mutation_does_not_bump_the_version() {
        let h = hub();
        let wl = Whitelist::new(Arc::clone(&h));
        assert!(wl.remove(&key("10.0.0.0/24")).is_none());
        assert_eq!(h.versions().get(Domain::Whitelist), 0);
    }

    #[test]
    fn reading_a_snapshot_does_not_mutate_anything() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "eth0");
        let before = wl.len();
        for _ in 0..3 {
            let _ = wl.snapshot();
        }
        assert_eq!(wl.len(), before);
        assert!(wl.contains(&key("10.0.0.0/24")));
    }

    #[test]
    fn snapshots_are_shared_until_a_change() {
        let wl = Whitelist::new(hub());
        wl.insert(key("10.0.0.0/24"), "");
        let a = wl.snapshot();
        let b = wl.snapshot();
        assert!(Arc::ptr_eq(&a, &b));
        wl.insert(key("192.168.0.0/24"), "");
        assert!(!Arc::ptr_eq(&b, &wl.snapshot()));
    }
}
