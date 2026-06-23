//! 封禁相关数据结构：BanInfo、BanReason、BanStatus、ActiveBanCache

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
    /// 锁顺序: bans → by_jail (与 remove/purge_expired 保持一致,避免 ABBA 死锁)
    pub fn insert(&self, info: BanInfo) {
        let ip = info.ip.clone();
        let jail = info.jail_name.clone();
        let info_arc = Arc::new(info);

        // 先更新主表
        {
            let mut bans = self.bans.write();
            bans.insert(ip.clone(), info_arc);
        }

        // 再更新反向索引
        {
            let mut by_jail = self.by_jail.write();
            by_jail.entry(jail).or_default().insert(ip);
        }
    }

    /// 原子性检查并插入：仅当 IP 不在缓存中（或已过期）时插入。
    ///
    /// 消除 check-then-act 竞态：多线程同时调用时，只有一个线程成功插入。
    ///
    /// # Returns
    /// - `true`: IP 新插入（调用方可安全执行内核封禁）
    /// - `false`: IP 已存在且未过期（调用方应跳过封禁）
    pub fn try_insert(&self, info: BanInfo) -> bool {
        let ip = info.ip.clone();
        let jail = info.jail_name.clone();
        let now = crate::types::now_secs();
        let info_arc = Arc::new(info);

        let mut bans = self.bans.write();

        // 检查是否已存在且未过期
        if let Some(existing) = bans.get(&ip) {
            if !existing.is_expired(now) {
                return false; // 已存在且活跃，跳过
            }
        }

        // 不存在或已过期 → 插入
        bans.insert(ip.clone(), info_arc);
        drop(bans); // 释放 bans 锁后再获取 by_jail 锁，保持锁序一致

        let mut by_jail = self.by_jail.write();
        by_jail.entry(jail).or_default().insert(ip);
        true
    }

    /// 移除封禁条目,同时清理反向索引（返回 Arc，零克隆开销）
    pub fn remove(&self, ip: &str) -> Option<Arc<BanInfo>> {
        let info = {
            let mut bans = self.bans.write();
            bans.remove(ip)?
        };

        // 清理反向索引
        {
            let mut by_jail = self.by_jail.write();
            if let Some(ips) = by_jail.get_mut(&info.jail_name) {
                ips.remove(ip);
                if ips.is_empty() {
                    by_jail.remove(&info.jail_name);
                }
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
