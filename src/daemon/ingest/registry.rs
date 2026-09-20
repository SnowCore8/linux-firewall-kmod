//! 日志源的稳定身份与 `wd` 映射。
//!
//! 旧实现用 `Vec<FileState>` 的**下标**表示文件身份（`FILE_STATES` 索引 = `wd`），
//! 而 jail 启用状态变化会重建整个 `Vec`，重建后下标与实际 watch 的对应关系依赖
//! 重建顺序——那是隐式契约，编译期毫无保障（结构问题 C）。
//!
//! 这里把身份变成显式类型：[`SourceId`] 在登记时分配，此后**永不变化**。轮转会更换
//! inotify `wd`、更换 inode，配置重载会增删源，但同一路径的 `SourceId` 稳定，因此
//! 各源的读取偏移、partial 行缓冲、失败计数窗口都能安全地以 `SourceId` 为键。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use inotify::WatchDescriptor;

/// 稳定的日志源标识。分配后不再变化，与 inotify `wd` 解耦。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(u32);

impl SourceId {
    /// 数值形式（日志与诊断用）。
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// 仅测试用：直接构造一个身份编号，供不依赖 inotify 的纯逻辑测试使用。
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn from_raw(id: u32) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// 注册项的用途：区分日志源与被监视的配置文件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceOwner {
    /// 某个 jail 的日志源。jail 名以 `Arc<str>` 共享，避免每批日志克隆字符串。
    Log {
        /// 归属的 jail 名。
        jail: Arc<str>,
    },
    /// 守护进程自身的配置文件（变化时由组合根触发重载）。
    Config,
}

impl SourceOwner {
    /// 日志源时返回其 jail 名。
    #[must_use]
    pub fn jail(&self) -> Option<&Arc<str>> {
        match self {
            Self::Log { jail } => Some(jail),
            Self::Config => None,
        }
    }

    /// 是否为配置文件监视项。
    #[must_use]
    pub fn is_config(&self) -> bool {
        matches!(self, Self::Config)
    }
}

/// 一个注册项的当前状态。
#[derive(Debug, Clone)]
pub struct SourceEntry {
    /// 用途（日志源 / 配置文件）。
    pub owner: SourceOwner,
    /// 被监视的路径。
    pub path: PathBuf,
    /// 当前生效的 inotify watch 描述符（轮转后会更新）。
    pub wd: WatchDescriptor,
    /// 登记（或最近一次重挂）时记录的 inode，仅用于诊断日志。
    pub inode: u64,
}

/// `SourceId` ↔ `wd` ↔ `path` 三向映射，由采集线程独占（无需锁）。
#[derive(Debug, Default)]
pub struct SourceRegistry {
    /// 身份 → 状态。
    by_id: HashMap<SourceId, SourceEntry>,
    /// 当前 `wd` → 身份，供事件路由。
    by_wd: HashMap<WatchDescriptor, SourceId>,
    /// 路径 → 身份，保证同一路径身份稳定（轮转重挂、重载都不改身份）。
    by_path: HashMap<PathBuf, SourceId>,
    /// 下一个待分配的身份号，单调递增，不复用已删除的身份。
    next: u32,
}

impl SourceRegistry {
    /// 新建空注册表。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 登记一个被监视的路径，返回其稳定身份。
    ///
    /// 同一路径重复登记（轮转重挂、重载后重扫）返回**同一个** [`SourceId`]，只更新
    /// `wd` 与 inode；这样各源以身份为键的偏移与缓冲不会被重挂动作清空。
    pub fn register(
        &mut self,
        owner: SourceOwner,
        path: &Path,
        wd: WatchDescriptor,
        inode: u64,
    ) -> SourceId {
        if let Some(&id) = self.by_path.get(path) {
            self.rebind(id, wd, inode);
            // 重载可能改变归属（同一路径改挂到别的 jail），故归属一并更新。
            if let Some(entry) = self.by_id.get_mut(&id) {
                entry.owner = owner;
            }
            return id;
        }

        let id = SourceId(self.next);
        self.next += 1;
        // 该路径之前可能登记过别的 wd（理论上不会：by_path 已去重），
        // 但防御性摘除可避免 by_wd 里留下指向旧身份的悬挂映射。
        self.by_wd.retain(|_, mapped| *mapped != id);
        self.by_wd.insert(wd.clone(), id);
        self.by_path.insert(path.to_path_buf(), id);
        self.by_id.insert(
            id,
            SourceEntry {
                owner,
                path: path.to_path_buf(),
                wd,
                inode,
            },
        );
        id
    }

    /// 更新某个身份当前的 `wd` 与 inode（轮转后重挂 watch 时调用）。
    pub fn rebind(&mut self, id: SourceId, wd: WatchDescriptor, inode: u64) {
        let Some(entry) = self.by_id.get_mut(&id) else {
            return;
        };
        let old_wd = std::mem::replace(&mut entry.wd, wd.clone());
        entry.inode = inode;
        // 旧 wd 可能因轮转已失效：按值比较，不相等才需要改映射。
        if old_wd != wd {
            self.by_wd.remove(&old_wd);
            self.by_wd.insert(wd, id);
        }
    }

    /// 事件路由：由 `wd` 找到稳定身份。未知 `wd`（已被摘除的旧 watch）返回 `None`。
    #[must_use]
    pub fn resolve(&self, wd: &WatchDescriptor) -> Option<SourceId> {
        self.by_wd.get(wd).copied()
    }

    /// 按身份取状态。
    #[must_use]
    pub fn get(&self, id: SourceId) -> Option<&SourceEntry> {
        self.by_id.get(&id)
    }

    /// 摘除一个身份，返回其状态（调用方据此摘 watch）。
    pub fn remove(&mut self, id: SourceId) -> Option<SourceEntry> {
        let entry = self.by_id.remove(&id)?;
        self.by_path.remove(&entry.path);
        // 只有当 `by_wd` 里的映射确实指向本身份时才删除：轮转后可能已由
        // `rebind` 指向新 wd，用 `remove(旧 wd)` 会误删当前映射。
        if self.by_wd.get(&entry.wd) == Some(&id) {
            self.by_wd.remove(&entry.wd);
        }
        Some(entry)
    }

    /// 遍历全部登记项（顺序不保证）。
    pub fn iter(&self) -> impl Iterator<Item = (SourceId, &SourceEntry)> {
        self.by_id.iter().map(|(&id, entry)| (id, entry))
    }

    /// 是否已登记该路径。
    #[must_use]
    pub fn contains_path(&self, path: &Path) -> bool {
        self.by_path.contains_key(path)
    }

    /// 当前登记项数量。
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否没有任何登记项。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Weak;

    /// 构造一个仅用于映射测试的 `WatchDescriptor`。
    ///
    /// `WatchDescriptor` 的字段是 crate 私有，测试里无法直接构造，故借真实
    /// inotify 实例取得：`Watches::add` 返回的描述符带 crate 私有的 fd 弱引用。
    fn tempdir() -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-registry-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }

    /// 需要真实 inotify 实例才能拿到 `WatchDescriptor`，故测试统一走这里。
    struct Fixture {
        watcher: crate::ingest::watcher::Watcher,
        dir: PathBuf,
        seq: u32,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                watcher: crate::ingest::watcher::Watcher::new().expect("inotify 初始化失败"),
                dir: tempdir(),
                seq: 0,
            }
        }

        fn watch(&mut self, name: &str) -> (PathBuf, WatchDescriptor) {
            self.seq += 1;
            let path = self.dir.join(name);
            if !path.exists() {
                std::fs::write(&path, b"").expect("建测试文件失败");
            }
            let wd = self
                .watcher
                .add(&path, crate::ingest::watcher::log_file_watch_mask())
                .expect("添加 watch 失败");
            (path, wd)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn owner(jail: &str) -> SourceOwner {
        SourceOwner::Log {
            jail: Arc::from(jail),
        }
    }

    #[test]
    fn register_assigns_stable_ids_and_resolves_wd() {
        let mut fx = Fixture::new();
        let mut reg = SourceRegistry::new();

        let (p1, wd1) = fx.watch("a.log");
        let (p2, wd2) = fx.watch("b.log");

        let id1 = reg.register(owner("sshd"), &p1, wd1.clone(), 11);
        let id2 = reg.register(owner("nginx"), &p2, wd2.clone(), 22);

        assert_ne!(id1, id2, "不同路径必须得到不同身份");
        assert_eq!(id1.get(), 0);
        assert_eq!(id2.get(), 1);
        assert_eq!(reg.resolve(&wd1), Some(id1), "wd 必须路由回原身份");
        assert_eq!(reg.resolve(&wd2), Some(id2));
        assert_eq!(reg.len(), 2);

        let e1 = reg.get(id1).expect("身份应存在");
        assert_eq!(e1.owner.jail().map(|j| j.as_ref()), Some("sshd"));
        assert_eq!(e1.inode, 11);
        assert!(!e1.owner.is_config());
    }

    #[test]
    fn re_registering_same_path_keeps_identity_and_rebinds_wd() {
        let mut fx = Fixture::new();
        let mut reg = SourceRegistry::new();

        let (p, old_wd) = fx.watch("a.log");
        let id = reg.register(owner("sshd"), &p, old_wd.clone(), 11);

        // 模拟轮转后重挂。内核的 wd 是**可复用的 id**：同一路径重挂很可能拿回同一个
        // wd（`rebind` 里的 `old_wd != wd` 判断正为此而设）。要覆盖「映射确实换到新
        // wd」这一分支，必须取另一个**同时存在**的真实 watch，保证与旧 wd 不同值。
        let (_, new_wd) = fx.watch("b.log");
        assert_ne!(new_wd, old_wd, "同时存在的两个 watch 描述符必不相同");

        let again = reg.register(owner("sshd"), &p, new_wd.clone(), 33);
        assert_eq!(again, id, "同一路径必须保持同一身份（结构问题 C）");
        assert_eq!(reg.len(), 1, "不应产生第二个登记项");
        assert_eq!(reg.resolve(&new_wd), Some(id), "新 wd 应指向同一身份");
        assert_eq!(reg.resolve(&old_wd), None, "旧 wd 不应再路由");
        assert_eq!(reg.get(id).expect("身份应存在").inode, 33);
    }

    #[test]
    fn rebinding_to_the_same_wd_keeps_routing() {
        let mut fx = Fixture::new();
        let mut reg = SourceRegistry::new();

        let (p, wd) = fx.watch("a.log");
        let id = reg.register(owner("sshd"), &p, wd.clone(), 11);
        // 内核复用同一 wd 的重挂：不能因「先删旧映射」而把当前映射也删掉。
        let again = reg.register(owner("sshd"), &p, wd.clone(), 11);

        assert_eq!(again, id);
        assert_eq!(
            reg.resolve(&wd),
            Some(id),
            "同 wd 重挂后仍须路由（防御性 retain 不得误删）"
        );
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn re_registering_can_change_owner_without_changing_identity() {
        let mut fx = Fixture::new();
        let mut reg = SourceRegistry::new();

        let (p, wd) = fx.watch("shared.log");
        let id = reg.register(owner("sshd"), &p, wd.clone(), 11);
        let same = reg.register(owner("nginx"), &p, wd, 11);

        assert_eq!(same, id);
        assert_eq!(
            reg.get(id)
                .expect("身份应存在")
                .owner
                .jail()
                .map(|j| j.as_ref()),
            Some("nginx"),
            "重载后同一路径改挂到别的 jail 应更新归属"
        );
    }

    #[test]
    fn remove_drops_all_three_mappings() {
        let mut fx = Fixture::new();
        let mut reg = SourceRegistry::new();

        let (p, wd) = fx.watch("a.log");
        let id = reg.register(owner("sshd"), &p, wd.clone(), 11);
        assert!(reg.contains_path(&p));

        let removed = reg.remove(id).expect("应有登记项");
        assert_eq!(removed.path, p);
        assert!(reg.get(id).is_none());
        assert_eq!(reg.resolve(&wd), None);
        assert!(!reg.contains_path(&p));
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_is_send_without_shared_locks() {
        // 身份必须是 `Copy + Send + Sync`：采集线程独占注册表，跨线程只传身份与
        // 不可变消息，不再需要为「下标即身份」额外加锁。
        fn assert_send_sync<T: Send + Sync + Copy>() {}
        assert_send_sync::<SourceId>();

        // 弱引用字段不影响 `WatchDescriptor` 作为键的可比较性。
        fn assert_hash_key<T: std::hash::Hash + Eq>() {}
        assert_hash_key::<WatchDescriptor>();

        // 显式提及 `Weak`，避免未使用导入（同时声明本测试依赖 wd 的弱引用语义）。
        let _: Option<Weak<()>> = None;
    }
}
