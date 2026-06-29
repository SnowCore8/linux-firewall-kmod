//! IP 信誉分系统 — 基于行为历史动态评估 IP 可信度
//!
//! # 评分规则
//!
//! - 初始分数：100
//! - 每次失败：-10 分
//! - 每次封禁：额外 -10 分（与失败同时发生）
//! - 恢复：每小时无失败 +1 分，上限 100
//! - 范围：0-100
//!
//! # 阈值联动
//!
//! | 信誉分 | 阈值乘数 | 效果 |
//! |--------|----------|------|
//! | ≥ 80   | × 1.0    | 正常 |
//! | 50-79  | × 0.8    | 略严 |
//! | < 50   | × 0.5    | 严格 |
//!
//! # 持久化
//!
//! SQLite `ip_reputation` 表保存信誉分，守护进程重启时自动加载。

#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::OnceLock;

/// 单个 IP 的信誉条目
#[derive(Debug, Clone)]
pub struct ReputationEntry {
    /// IP 文本表示
    pub ip: String,
    /// 信誉分（0-100）
    pub score: u32,
    /// 最后一次失败时间（Unix 秒）
    pub last_failure_at: i64,
    /// 累计失败次数
    pub total_failures: u32,
    /// 累计封禁次数
    pub total_bans: u32,
}

/// IP 信誉分存储
///
/// 内存中维护所有已知 IP 的信誉分，通过 SQLite 持久化。
/// 使用 `RwLock<HashMap>` 保护并发访问。
#[derive(Debug)]
pub struct IpReputationStore {
    entries: RwLock<HashMap<String, ReputationEntry>>,
}

impl Default for IpReputationStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IpReputationStore {
    /// 构造空的信誉存储
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(HashMap::with_capacity(5_000)),
        }
    }

    /// 记录一次失败，扣减 10 分并持久化
    pub fn record_failure(&self, ip: &str) {
        let now = crate::types::now_secs();
        let entry = {
            let mut entries = self.entries.write();
            let entry = entries
                .entry(ip.to_string())
                .or_insert_with(|| ReputationEntry {
                    ip: ip.to_string(),
                    score: 100,
                    last_failure_at: 0,
                    total_failures: 0,
                    total_bans: 0,
                });
            entry.score = entry.score.saturating_sub(10);
            entry.last_failure_at = now;
            entry.total_failures += 1;
            entry.clone()
        };
        persist_entry(&entry);
    }

    /// 记录一次封禁，额外扣减 10 分并持久化
    pub fn record_ban(&self, ip: &str) {
        let now = crate::types::now_secs();
        let entry = {
            let mut entries = self.entries.write();
            let entry = entries
                .entry(ip.to_string())
                .or_insert_with(|| ReputationEntry {
                    ip: ip.to_string(),
                    score: 100,
                    last_failure_at: 0,
                    total_failures: 0,
                    total_bans: 0,
                });
            entry.score = entry.score.saturating_sub(10);
            entry.last_failure_at = now;
            entry.total_bans += 1;
            entry.clone()
        };
        persist_entry(&entry);
    }

    /// 根据最后一次失败时间恢复信誉分
    ///
    /// 每小时 +1 分，上限 100。遍历所有条目，仅处理有失败记录的 IP。
    pub fn recover_scores(&self) {
        let now = crate::types::now_secs();
        let mut entries = self.entries.write();

        for entry in entries.values_mut() {
            if entry.last_failure_at == 0 || entry.score >= 100 {
                continue;
            }
            // saturating_sub 防御时钟回拨（NTP 调整导致 now < last_failure_at）
            let elapsed = now.saturating_sub(entry.last_failure_at);
            let hours_since_failure = elapsed / 3600;
            if hours_since_failure > 0 {
                entry.score = (entry.score + hours_since_failure as u32).min(100);
            }
        }
    }

    /// 获取 IP 的信誉分（未知 IP 返回 100）
    #[must_use]
    pub fn get_score(&self, ip: &str) -> u32 {
        self.entries.read().get(ip).map(|e| e.score).unwrap_or(100)
    }

    /// 根据信誉分计算阈值乘数
    ///
    /// - ≥ 80：× 1.0（正常）
    /// - 50-79：× 0.8（略严）
    /// - < 50：× 0.5（严格）
    #[must_use]
    pub fn get_threshold_multiplier(&self, ip: &str) -> f64 {
        let score = self.get_score(ip);
        if score >= 80 {
            1.0
        } else if score >= 50 {
            0.8
        } else {
            0.5
        }
    }

    /// 获取 IP 的完整信誉条目（不存在返回 None）
    #[must_use]
    pub fn get_entry(&self, ip: &str) -> Option<ReputationEntry> {
        self.entries.read().get(ip).cloned()
    }

    /// 获取所有信誉条目快照（按分数升序排列）
    #[must_use]
    pub fn snapshot(&self) -> Vec<ReputationEntry> {
        let mut entries: Vec<ReputationEntry> = self.entries.read().values().cloned().collect();
        entries.sort_by_key(|e| e.score);
        entries
    }

    /// 设置指定 IP 的信誉分（API 手动调整用）
    pub fn set_score(&self, ip: &str, score: u32) {
        let now = crate::types::now_secs();
        let entry_to_persist;
        {
            let mut entries = self.entries.write();
            let entry = entries
                .entry(ip.to_string())
                .or_insert_with(|| ReputationEntry {
                    ip: ip.to_string(),
                    score: 100,
                    last_failure_at: 0,
                    total_failures: 0,
                    total_bans: 0,
                });
            entry.score = score.min(100);
            entry.last_failure_at = now;
            entry_to_persist = entry.clone();
        }
        persist_entry(&entry_to_persist);
    }

    /// 从 SQLite 恢复信誉分（启动时调用）
    pub fn restore_entry(
        &self,
        ip: &str,
        score: u32,
        last_failure_at: i64,
        total_failures: u32,
        total_bans: u32,
    ) {
        let mut entries = self.entries.write();
        entries.insert(
            ip.to_string(),
            ReputationEntry {
                ip: ip.to_string(),
                score: score.min(100),
                last_failure_at,
                total_failures,
                total_bans,
            },
        );
    }

    /// 清理信誉分已恢复至 100 且长期无活动的条目
    ///
    /// 清理条件：score >= 100 且 last_failure_at 在 24 小时前
    pub fn cleanup_stale(&self) -> usize {
        let now = crate::types::now_secs();
        let threshold = now - 24 * 3600;
        let mut entries = self.entries.write();
        let before = entries.len();
        entries.retain(|_, e| e.score < 100 || e.last_failure_at > threshold);
        before - entries.len()
    }

    /// 返回已知 IP 数量
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().len()
    }

    /// 是否为空
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }
}

/// 全局 IP 信誉存储实例
pub static IP_REPUTATION: OnceLock<IpReputationStore> = OnceLock::new();

/// 获取或初始化全局信誉存储
#[must_use]
pub fn get_store() -> &'static IpReputationStore {
    IP_REPUTATION.get_or_init(IpReputationStore::new)
}

// ============================================================================
// SQLite 持久化（委托 history_snapshot 模块）
// ============================================================================

/// 持久化信誉分到 SQLite（在 record_failure/record_ban 后调用）
fn persist_entry(entry: &ReputationEntry) {
    crate::history_snapshot::persist_ip_reputation(
        &entry.ip,
        entry.score,
        entry.last_failure_at,
        entry.total_failures,
        entry.total_bans,
    );
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> IpReputationStore {
        IpReputationStore::new()
    }

    #[test]
    fn initial_score_is_100() {
        let store = make_store();
        assert_eq!(store.get_score("1.2.3.4"), 100);
    }

    #[test]
    fn failure_decreases_score() {
        let store = make_store();
        store.record_failure("1.2.3.4");
        assert_eq!(store.get_score("1.2.3.4"), 90);
        store.record_failure("1.2.3.4");
        assert_eq!(store.get_score("1.2.3.4"), 80);
    }

    #[test]
    fn ban_decreases_score() {
        let store = make_store();
        store.record_ban("1.2.3.4");
        assert_eq!(store.get_score("1.2.3.4"), 90);
    }

    #[test]
    fn failure_and_ban_combined() {
        let store = make_store();
        // 一次失败触发封禁：failure -10 + ban -10 = -20
        store.record_failure("1.2.3.4");
        store.record_ban("1.2.3.4");
        assert_eq!(store.get_score("1.2.3.4"), 80);
    }

    #[test]
    fn score_does_not_go_below_zero() {
        let store = make_store();
        for _ in 0..20 {
            store.record_failure("1.2.3.4");
        }
        assert_eq!(store.get_score("1.2.3.4"), 0);
    }

    #[test]
    fn threshold_multiplier_high_score() {
        let store = make_store();
        // 默认 100 → × 1.0
        assert!((store.get_threshold_multiplier("1.2.3.4") - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_multiplier_medium_score() {
        let store = make_store();
        // 扣 3 次 → 70 → × 0.8
        for _ in 0..3 {
            store.record_failure("1.2.3.4");
        }
        assert!((store.get_threshold_multiplier("1.2.3.4") - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn threshold_multiplier_low_score() {
        let store = make_store();
        // 扣 6 次 → 40 → × 0.5
        for _ in 0..6 {
            store.record_failure("1.2.3.4");
        }
        assert!((store.get_threshold_multiplier("1.2.3.4") - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn set_score_clamped() {
        let store = make_store();
        store.set_score("1.2.3.4", 150);
        assert_eq!(store.get_score("1.2.3.4"), 100);
    }

    #[test]
    fn snapshot_sorted_by_score() {
        let store = make_store();
        store.record_failure("1.1.1.1"); // 90
        for _ in 0..5 {
            store.record_failure("2.2.2.2"); // 50
        }
        store.record_failure("3.3.3.3"); // 90

        let snap = store.snapshot();
        assert_eq!(snap.len(), 3);
        assert!(snap[0].score <= snap[1].score);
        assert!(snap[1].score <= snap[2].score);
    }

    #[test]
    fn unknown_ip_returns_none_entry() {
        let store = make_store();
        assert!(store.get_entry("9.9.9.9").is_none());
    }

    #[test]
    fn entry_tracks_counts() {
        let store = make_store();
        store.record_failure("1.2.3.4");
        store.record_failure("1.2.3.4");
        store.record_ban("1.2.3.4");

        let entry = store.get_entry("1.2.3.4").unwrap();
        assert_eq!(entry.total_failures, 2);
        assert_eq!(entry.total_bans, 1);
    }
}
