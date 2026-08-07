//! 封禁相关数据结构：BanInfo、BanReason、BanStatus、ActiveBanCache、BanHistory

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

// ============================================================================
// 封禁原因枚举
// ============================================================================

/// 封禁原因枚举 — 区分触发封禁的来源,便于审计和 Grafana 分类展示
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanReason {
    /// 登录失败超阈值 (传统 fail2ban 模式)
    FailedAttempts,
    /// DDoS 速率限制触发 (Phase 3)
    DDoSRateLimit,
    /// 管理员手动封禁
    ManualBan,
    /// 自动永久封禁 (多次临时封禁后升级)
    PermanentAuto,
}

impl BanReason {
    /// 转为文本标识
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FailedAttempts => "failed_attempts",
            Self::DDoSRateLimit => "ddos_rate",
            Self::ManualBan => "manual",
            Self::PermanentAuto => "permanent_auto",
        }
    }

    /// 从文本标识还原枚举,未知值回退到 `FailedAttempts`
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "ddos_rate" => Self::DDoSRateLimit,
            "manual" => Self::ManualBan,
            "permanent_auto" => Self::PermanentAuto,
            _ => Self::FailedAttempts,
        }
    }
}

// ============================================================================
// 封禁状态枚举
// ============================================================================

/// 封禁状态枚举 — 对应 `ban_history.status` 列
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanStatus {
    /// 当前活跃 (内核 + 内存均有记录)
    Active,
    /// 自然过期 (临时封禁到期)
    Expired,
    /// 手动解封 (管理员操作)
    UnbannedManual,
}

impl BanStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::UnbannedManual => "unbanned_manual",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "expired" => Self::Expired,
            "unbanned_manual" => Self::UnbannedManual,
            _ => Self::Active,
        }
    }
}

// ============================================================================
// 封禁信息
// ============================================================================

/// 单条封禁的完整信息 — 用于内存缓存 (`ActiveBanCache`)
#[derive(Debug, Clone)]
pub struct BanInfo {
    /// IP 文本表示 (IPv4 或 IPv6)
    pub ip: String,
    /// IPv4 网络字节序整数 (用于索引查询),IPv6 为 0
    pub ip_num: u32,
    /// 触发封禁的 jail 名称
    pub jail_name: String,
    /// 封禁原因（原始字符串）
    pub reason: String,
    /// 封禁时间 (Unix 秒)
    pub banned_at: i64,
    /// 过期时间 (Unix 秒),0 = 永久
    pub expires_at: i64,
    /// 是否永久封禁
    pub is_permanent: bool,
    /// 触发封禁前的失败次数
    pub fail_count: u32,
    /// 该 IP 累计被封禁次数（渐进式封禁：第1次/第2次/第3次/第4次+）
    pub ban_count: u32,
}

impl BanInfo {
    /// 判断封禁是否已过期 (永久封禁永不过期)
    #[must_use]
    pub fn is_expired(&self, now: i64) -> bool {
        !self.is_permanent && self.expires_at > 0 && now >= self.expires_at
    }

    /// 计算封禁持续时长 (秒)
    #[must_use]
    pub fn duration_secs(&self, now: i64) -> i64 {
        if self.is_permanent || self.expires_at == 0 {
            now - self.banned_at
        } else {
            self.expires_at - self.banned_at
        }
    }
}

// ============================================================================
// 活跃封禁缓存
// ============================================================================

/// 活跃封禁内存缓存 — 内存权威存储
///
/// 设计要点:
/// - `bans`: IP → Arc<BanInfo>,`parking_lot::RwLock` 保护读写并发
/// - `by_jail`: jail_name → IP 集合,支持按 jail 维度快速查询
/// - 使用 Arc 共享 BanInfo，避免频繁克隆（metrics/snapshot 场景）
#[derive(Debug)]
pub struct ActiveBanCache {
    /// IP → 封禁信息（Arc 共享，减少克隆开销）
    bans: RwLock<HashMap<String, Arc<BanInfo>>>,
    /// jail 名称 → 该 jail 封禁的 IP 集合 (反向索引)
    by_jail: RwLock<HashMap<String, HashSet<String>>>,
}

impl Default for ActiveBanCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ActiveBanCache {
    /// 构造新的空缓存（10Gbps 优化：预分配容量）
    #[must_use]
    pub fn new() -> Self {
        Self {
            // 预分配 1 万封禁容量（10Gbps 场景下可能的活跃封禁数）
            bans: RwLock::new(HashMap::with_capacity(10_000)),
            // 预分配 100 个 jail 容量
            by_jail: RwLock::new(HashMap::with_capacity(100)),
        }
    }

    /// 插入或更新封禁条目,同时维护反向索引
    ///
    /// 同时持有 bans + by_jail 两把锁，消除锁间竞态窗口。
    /// 锁顺序: bans → by_jail (与 remove/try_insert/purge_expired 保持一致,避免 ABBA 死锁)
    pub fn insert(&self, info: BanInfo) {
        let ip = info.ip.clone();
        let jail = info.jail_name.clone();
        let info_arc = Arc::new(info);

        // 同时持有两把锁，消除 drop(bans) → acquire(by_jail) 之间的竞态窗口
        let mut bans = self.bans.write();
        let mut by_jail = self.by_jail.write();

        // 更新主表，捕获旧条目以清理 stale by_jail 映射
        let old_jail = bans
            .insert(ip.clone(), info_arc)
            .map(|old| old.jail_name.clone());

        // 清理旧 jail 的反向映射（IP 被不同 jail 重新封禁时）
        if let Some(ref old) = old_jail {
            if *old != jail {
                if let Some(ips) = by_jail.get_mut(old) {
                    ips.remove(&ip);
                    if ips.is_empty() {
                        by_jail.remove(old);
                    }
                }
            }
        }
        by_jail.entry(jail).or_default().insert(ip);
    }

    /// 原子性检查并插入：仅当 IP 不在缓存中（或已过期）时插入。
    ///
    /// 消除 check-then-act 竞态：多线程同时调用时，只有一个线程成功插入。
    /// 同时持有 bans + by_jail 两把锁，消除锁间竞态窗口。
    ///
    /// # Returns
    /// - `true`: IP 新插入（调用方可安全执行内核封禁）
    /// - `false`: IP 已存在且未过期（调用方应跳过封禁）
    pub fn try_insert(&self, info: BanInfo) -> bool {
        let ip = info.ip.clone();
        let jail = info.jail_name.clone();
        let now = crate::types::now_secs();
        let info_arc = Arc::new(info);

        // 同时持有两把锁，消除 drop(bans) → acquire(by_jail) 之间的竞态窗口
        let mut bans = self.bans.write();
        let mut by_jail = self.by_jail.write();

        // 检查是否已存在且未过期
        if let Some(existing) = bans.get(&ip) {
            if !existing.is_expired(now) {
                return false; // 已存在且活跃，跳过
            }
        }

        // 不存在或已过期 → 插入，捕获旧条目以清理 stale by_jail 映射
        let old_jail = bans
            .insert(ip.clone(), info_arc)
            .map(|old| old.jail_name.clone());

        // 清理旧 jail 的反向映射（IP 被不同 jail 重新封禁时）
        if let Some(ref old) = old_jail {
            if *old != jail {
                if let Some(ips) = by_jail.get_mut(old) {
                    ips.remove(&ip);
                    if ips.is_empty() {
                        by_jail.remove(old);
                    }
                }
            }
        }
        by_jail.entry(jail).or_default().insert(ip);
        true
    }

    /// 移除封禁条目,同时清理反向索引（返回 Arc，零克隆开销）
    ///
    /// 同时持有 bans + by_jail 两把锁，消除锁间竞态窗口。
    pub fn remove(&self, ip: &str) -> Option<Arc<BanInfo>> {
        // 同时持有两把锁，消除 drop(bans) → acquire(by_jail) 之间的竞态窗口
        let mut bans = self.bans.write();
        let mut by_jail = self.by_jail.write();

        let info = bans.remove(ip)?;

        // 清理反向索引
        if let Some(ips) = by_jail.get_mut(&info.jail_name) {
            ips.remove(ip);
            if ips.is_empty() {
                by_jail.remove(&info.jail_name);
            }
        }

        Some(info)
    }

    /// 查询单个 IP 是否被封禁（返回 Arc，零克隆开销）
    #[must_use]
    pub fn get(&self, ip: &str) -> Option<Arc<BanInfo>> {
        self.bans.read().get(ip).cloned()
    }

    /// 检查 IP 是否被封禁（不返回数据，最快路径）
    #[must_use]
    pub fn contains(&self, ip: &str) -> bool {
        self.bans.read().contains_key(ip)
    }

    /// 获取当前活跃封禁总数
    #[must_use]
    pub fn len(&self) -> usize {
        self.bans.read().len()
    }

    /// 缓存是否为空
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bans.read().is_empty()
    }

    /// 获取指定 jail 的封禁 IP 列表
    #[must_use]
    pub fn get_by_jail(&self, jail_name: &str) -> Vec<String> {
        let by_jail = self.by_jail.read();
        by_jail
            .get(jail_name)
            .map(|ips| ips.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// 获取所有活跃封禁的快照 (用于 metrics 导出和 API，返回 Arc 避免克隆)
    #[must_use]
    pub fn snapshot(&self) -> Vec<Arc<BanInfo>> {
        self.bans.read().values().cloned().collect()
    }

    /// 清理过期封禁,返回被清理的条目列表
    pub fn purge_expired(&self, now: i64) -> Vec<Arc<BanInfo>> {
        let mut expired = Vec::new();
        let mut bans = self.bans.write();
        let mut by_jail = self.by_jail.write();

        bans.retain(|ip, info| {
            if info.is_expired(now) {
                // 清理反向索引
                if let Some(ips) = by_jail.get_mut(&info.jail_name) {
                    ips.remove(ip);
                    if ips.is_empty() {
                        by_jail.remove(&info.jail_name);
                    }
                }
                expired.push(Arc::clone(info));
                false
            } else {
                true
            }
        });

        expired
    }

    /// 与内核 LIST bans 全量对账：删除「缓存有、内核无」的陈旧项，补齐缺失项。
    ///
    /// `kernel_ips` 为内核当前活跃封禁 IP 集合。已在集合内的缓存项保留
    /// （不覆盖 BanStateChange 写入的 reason/jail）；缺失则插入 `to_insert`。
    pub fn reconcile_with_kernel(
        &self,
        kernel_ips: &std::collections::HashSet<String>,
        to_insert: Vec<BanInfo>,
    ) -> usize {
        let mut removed = 0usize;
        {
            let mut bans = self.bans.write();
            let mut by_jail = self.by_jail.write();
            let stale: Vec<String> = bans
                .keys()
                .filter(|ip| !kernel_ips.contains(*ip))
                .cloned()
                .collect();
            for ip in stale {
                if let Some(info) = bans.remove(&ip) {
                    if let Some(ips) = by_jail.get_mut(&info.jail_name) {
                        ips.remove(&ip);
                        if ips.is_empty() {
                            by_jail.remove(&info.jail_name);
                        }
                    }
                    removed += 1;
                }
            }
        }
        for info in to_insert {
            let _ = self.try_insert(info);
        }
        removed
    }
}

// ============================================================================
// 全局实例
// ============================================================================

/// 全局活跃封禁缓存实例
///
/// 与 `ActiveBanCache::new()` 等价,但作为全局单例供所有模块访问。
/// 运行时由 `ban` 模块更新。
/// 使用 `OnceLock` 延迟初始化,避免 const 构造限制。
pub static ACTIVE_BAN_CACHE: std::sync::OnceLock<ActiveBanCache> = std::sync::OnceLock::new();

/// 等待内核 BanStateChange 确认后再写 ban_history 的 IP 集合
///
/// sendto 成功 ≠ 内核成功：乐观写缓存后登记于此，ACK 到达才 `record_ban`；
/// CmdResult 失败则摘除，避免污染渐进式封禁计数。
static PENDING_BAN_ACK: std::sync::OnceLock<RwLock<HashSet<String>>> = std::sync::OnceLock::new();

fn pending_ban_ack() -> &'static RwLock<HashSet<String>> {
    PENDING_BAN_ACK.get_or_init(|| RwLock::new(HashSet::new()))
}

/// 登记待确认封禁（乐观缓存写入后调用）
pub fn mark_pending_ban_ack(ip: &str) {
    pending_ban_ack().write().insert(ip.to_string());
}

/// 取出并清除待确认标记；返回是否曾登记
pub fn take_pending_ban_ack(ip: &str) -> bool {
    pending_ban_ack().write().remove(ip)
}

/// 丢弃待确认标记（CmdResult 失败路径）
pub fn clear_pending_ban_ack(ip: &str) {
    let _ = take_pending_ban_ack(ip);
}

// ============================================================================
// 封禁历史（渐进式封禁）
// ============================================================================

/// 单个 IP 的封禁历史记录
#[derive(Debug, Clone)]
pub struct BanHistoryEntry {
    /// IP 文本表示
    pub ip: String,
    /// 累计被封禁次数
    pub ban_count: u32,
    /// 最近一次封禁时间 (Unix 秒)
    pub last_banned_at: i64,
    /// 最近一次解封时间 (Unix 秒)，0 表示当前仍在封禁中
    pub last_unbanned_at: i64,
    /// 是否曾被永久封禁
    pub was_permanent: bool,
}

/// 封禁历史缓存 — 记录每个 IP 的累计封禁次数
///
/// 用于渐进式封禁：根据历史封禁次数递增封禁时长
/// - 第 1 次：基础时长（jail.ban_time）
/// - 第 2 次：30 分钟（1800 秒）
/// - 第 3 次：24 小时（86400 秒）
/// - 第 4 次+：永久封禁
#[derive(Debug)]
pub struct BanHistory {
    /// IP → 封禁历史
    entries: RwLock<HashMap<String, BanHistoryEntry>>,
}

impl Default for BanHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl BanHistory {
    /// 构造新的封禁历史缓存
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(10_000)),
        }
    }

    /// 获取 IP 的当前封禁次数（用于决定本次封禁时长）
    #[must_use]
    pub fn get_ban_count(&self, ip: &str) -> u32 {
        self.entries
            .read()
            .get(ip)
            .map(|e| e.ban_count)
            .unwrap_or(0)
    }

    /// 记录一次封禁（封禁成功后调用）
    ///
    /// # Returns
    /// 递增后的新 ban_count（例如首次封禁返回 1）
    pub fn record_ban(&self, ip: &str, is_permanent: bool) -> u32 {
        let now = crate::types::now_secs();
        let (ban_count, last_banned_at, last_unbanned_at, was_permanent);
        {
            let mut entries = self.entries.write();
            let entry = entries
                .entry(ip.to_string())
                .or_insert_with(|| BanHistoryEntry {
                    ip: ip.to_string(),
                    ban_count: 0,
                    last_banned_at: 0,
                    last_unbanned_at: 0,
                    was_permanent: false,
                });

            entry.ban_count += 1;
            entry.last_banned_at = now;
            entry.last_unbanned_at = 0; // 当前在封禁中
            if is_permanent {
                entry.was_permanent = true;
            }

            ban_count = entry.ban_count;
            last_banned_at = entry.last_banned_at;
            last_unbanned_at = entry.last_unbanned_at;
            was_permanent = entry.was_permanent;
        }

        // 持久化到 SQLite（在写锁外调用，避免潜在死锁）
        crate::history_snapshot::persist_ban_entry(
            ip,
            ban_count,
            last_banned_at,
            last_unbanned_at,
            was_permanent,
        );

        ban_count
    }

    /// 记录一次解封（解封成功后调用）
    pub fn record_unban(&self, ip: &str) {
        let now = crate::types::now_secs();
        let (ban_count, last_banned_at, last_unbanned_at, was_permanent);
        {
            let mut entries = self.entries.write();
            if let Some(entry) = entries.get_mut(ip) {
                entry.last_unbanned_at = now;
                ban_count = entry.ban_count;
                last_banned_at = entry.last_banned_at;
                last_unbanned_at = entry.last_unbanned_at;
                was_permanent = entry.was_permanent;
            } else {
                return;
            }
        }

        // 持久化到 SQLite
        crate::history_snapshot::persist_ban_entry(
            ip,
            ban_count,
            last_banned_at,
            last_unbanned_at,
            was_permanent,
        );
    }

    /// 从 SQLite 恢复封禁历史条目（启动时调用）
    pub fn restore_entry(
        &self,
        ip: &str,
        ban_count: u32,
        last_banned_at: i64,
        last_unbanned_at: i64,
        was_permanent: bool,
    ) {
        let mut entries = self.entries.write();
        entries.insert(
            ip.to_string(),
            BanHistoryEntry {
                ip: ip.to_string(),
                ban_count,
                last_banned_at,
                last_unbanned_at,
                was_permanent,
            },
        );
    }

    /// 计算渐进式封禁时长
    ///
    /// # Arguments
    /// - `ip`: 目标 IP
    /// - `base_duration`: 基础封禁时长（jail.ban_time）
    ///
    /// # Returns
    /// - 本次应该封禁的时长（秒），0 表示永久
    #[must_use]
    pub fn calculate_progressive_duration(&self, ip: &str, base_duration: u32) -> u32 {
        let ban_count = self.get_ban_count(ip);

        match ban_count {
            0 => base_duration, // 第 1 次：基础时长
            1 => 1800,          // 第 2 次：30 分钟
            2 => 86400,         // 第 3 次：24 小时
            _ => 0,             // 第 4 次+：永久封禁
        }
    }

    /// 获取 IP 的完整封禁历史
    #[must_use]
    pub fn get_entry(&self, ip: &str) -> Option<BanHistoryEntry> {
        self.entries.read().get(ip).cloned()
    }

    /// 获取所有封禁历史快照
    #[must_use]
    pub fn snapshot(&self) -> Vec<BanHistoryEntry> {
        self.entries.read().values().cloned().collect()
    }

    /// 清理过期历史（7 天无活动）
    pub fn cleanup_expired(&self) {
        let now = crate::types::now_secs();
        let expire_threshold = now - 7 * 24 * 3600; // 7 天前
        let mut entries = self.entries.write();

        entries.retain(|_, entry| {
            // 保留：当前在封禁中（last_unbanned_at == 0）或最近 7 天有活动
            entry.last_unbanned_at == 0 || entry.last_unbanned_at > expire_threshold
        });
    }
}

/// 全局封禁历史实例
///
/// 用于渐进式封禁：根据 IP 的历史封禁次数递增封禁时长
pub static BAN_HISTORY: std::sync::OnceLock<BanHistory> = std::sync::OnceLock::new();
