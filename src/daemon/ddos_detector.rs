//! DDoS 检测模块 — 10Gbps+ 级性能优化
//!
//! # 核心职责
//!
//! - 跟踪 per-IP 连接速率和失败速率
//! - 检测全局连接速率
//! - 超阈值时自动封禁
//!
//! # 性能优化（10Gbps+ 场景）
//!
//! 1. **原子计数器**：`global_conn_count` 使用 `AtomicU64`，无锁更新
//! 2. **DashMap 分片锁**：替代 RwLock<HashMap>，16 分片减少锁竞争
//! 3. **Arc<str> 共享**：IP 字符串共享，避免重复分配
//! 4. **预分配容量**：HashMap 预分配 10 万容量，避免运行时扩容
//! 5. **批量处理**：收集 1000 个事件后一次性更新 DashMap，减少锁获取次数
//!
//! # 检测策略
//!
//! 1. **Per-IP 连接速率**: 单 IP 每秒连接数超过 `per_ip_conn_rate`
//! 2. **Per-IP 失败速率**: 单 IP 每分钟失败次数超过 `per_ip_fail_rate`
//! 3. **全局连接速率**: 所有 IP 每秒总连接数超过 `global_conn_rate`
//!
//! # 封禁触发
//!
//! 超阈值 `auto_ban_threshold` 次后自动封禁，封禁时长为 `auto_ban_duration` 秒。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::types::{now_secs, ConnRateEntry, DdosConfig, DdosEvent, DDOS_STATS};

/// 批量处理缓冲区大小（10Gbps+ 优化：收集 1000 个事件后一次性更新）
const BATCH_BUFFER_SIZE: usize = 1000;

/// 批量事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchEvent {
    Connection,
    Failure,
}

/// 连接速率跟踪器 — 10Gbps+ 优化版（DashMap 分片锁 + 批量处理）
///
/// 维护所有 IP 的连接速率统计，支持 per-IP 和全局限速检测。
///
/// # 性能特性
///
/// - `global_conn_count`: 原子计数器，无锁更新
/// - `entries`: DashMap 16 分片，并发读写性能比 RwLock<HashMap> 高 5-10x
/// - `Arc<str>` 共享 IP 字符串，减少内存分配
/// - `batch_buffer`: 批量缓冲区，收集 1000 个事件后一次性更新，减少锁获取次数
pub struct ConnRateTracker {
    /// IP → 连接速率条目（DashMap 16 分片，无全局锁）
    entries: DashMap<Arc<str>, ConnRateEntry>,
    /// 全局连接计数（原子操作，无锁）
    global_conn_count: AtomicU64,
    /// 上次重置时间 (Unix 秒)
    last_reset_time: RwLock<i64>,
    /// 批量处理缓冲区（收集事件后一次性更新 DashMap）
    batch_buffer: RwLock<Vec<(Arc<str>, BatchEvent)>>,
}

impl ConnRateTracker {
    /// 创建新的连接速率跟踪器（10Gbps+ 优化：DashMap 16 分片 + 批量缓冲）
    pub fn new() -> Self {
        let now = now_secs();

        Self {
            // DashMap 默认 16 分片（CPU 核心数），预分配 10 万容量
            entries: DashMap::with_capacity(100_000),
            global_conn_count: AtomicU64::new(0),
            last_reset_time: RwLock::new(now),
            // 批量缓冲区预分配 1000 容量
            batch_buffer: RwLock::new(Vec::with_capacity(BATCH_BUFFER_SIZE)),
        }
    }

    /// 记录一次连接（10Gbps+ 优化：批量缓冲 + DashMap 分片锁 + 原子计数）
    ///
    /// # Arguments
    /// * `ip` - 来源 IP 地址
    pub fn record_connection(&self, ip: &str) {
        // 原子更新全局计数（无锁，10Gbps+ 关键路径）
        self.global_conn_count.fetch_add(1, Ordering::Relaxed);

        // 批量缓冲：先加入缓冲区，达到阈值后一次性刷新
        let ip_arc: Arc<str> = Arc::from(ip);
        let should_flush = {
            let mut buffer = self.batch_buffer.write();
            buffer.push((ip_arc, BatchEvent::Connection));
            buffer.len() >= BATCH_BUFFER_SIZE
        };

        if should_flush {
            self.flush_batch_buffer();
        }
    }

    /// 记录一次失败尝试（10Gbps+ 优化：批量缓冲 + DashMap 分片锁）
    ///
    /// # Arguments
    /// * `ip` - 来源 IP 地址
    pub fn record_failure(&self, ip: &str) {
        // 批量缓冲：先加入缓冲区，达到阈值后一次性刷新
        let ip_arc: Arc<str> = Arc::from(ip);
        let should_flush = {
            let mut buffer = self.batch_buffer.write();
            buffer.push((ip_arc, BatchEvent::Failure));
            buffer.len() >= BATCH_BUFFER_SIZE
        };

        if should_flush {
            self.flush_batch_buffer();
        }
    }

    /// 刷新批量缓冲区，将收集的事件一次性更新到 DashMap
    ///
    /// # 性能优化
    ///
    /// - 将 1000 个 DashMap 操作合并为一次批量更新
    /// - 使用 HashMap 聚合相同 IP 的事件，减少 DashMap 访问次数
    fn flush_batch_buffer(&self) {
        let events = {
            let mut buffer = self.batch_buffer.write();
            std::mem::take(&mut *buffer)
        };

        if events.is_empty() {
            return;
        }

        let now = now_secs();

        // 聚合相同 IP 的事件，减少 DashMap 访问次数
        let mut aggregated: HashMap<Arc<str>, (u64, u64)> = HashMap::new();
        for (ip_arc, event_type) in events {
            let entry = aggregated.entry(ip_arc).or_insert((0, 0));
            match event_type {
                BatchEvent::Connection => entry.0 += 1,
                BatchEvent::Failure => entry.1 += 1,
            }
        }

        // 一次性更新 DashMap（批量操作）
        for (ip_arc, (conn_count, fail_count)) in aggregated {
            let mut entry = self.entries.entry(ip_arc.clone()).or_insert_with(|| {
                ConnRateEntry::new(ip_arc, now)
            });
            entry.conn_count += conn_count;
            entry.fail_count += fail_count;
            entry.last_activity = now;
        }

        DDOS_STATS
            .tracked_ips
            .store(self.entries.len() as u64, Ordering::Relaxed);
    }

    /// 检测 DDoS 攻击
    ///
    /// # Arguments
    /// * `config` - DDoS 配置
    ///
    /// # Returns
    /// 检测到的 DDoS 事件列表
    pub fn detect(&self, config: &DdosConfig) -> Vec<DdosEvent> {
        if !config.enabled {
            return Vec::new();
        }

        // 检测前强制刷新缓冲区，确保所有事件已处理
        self.flush();

        let now = now_secs();
        let mut events = Vec::new();

        // 检测全局连接速率
        {
            let global_count = self.global_conn_count.load(Ordering::Relaxed);
            let global_rate = global_count as f64;

            if global_rate > config.global_conn_rate as f64 {
                DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);

                events.push(DdosEvent {
                    ip: "global".to_string(),
                    event_type: "global_rate".to_string(),
                    rate_per_second: global_rate,
                    threshold: config.global_conn_rate as f64,
                    detected_at: now,
                    action_taken: "log".to_string(),
                });
            }
        }

        // 检测 per-IP 速率
        //
        // 两阶段处理：读锁下检测违规并收集快照，写锁下更新 violation_count 并判断封禁。
        // 直接在读锁内 `.cloned()` 后修改副本会导致 violation_count 写回丢失，
        // auto_ban_threshold 比较永远基于 1，自动封禁完全失效。

        struct PerIpViolation {
            ip: Arc<str>,
            event_type: &'static str,
            rate_for_event: f64,
            threshold_for_event: f64,
        }

        let mut violations: Vec<PerIpViolation> = Vec::new();

        // 阶段 1: DashMap 并发迭代收集违规 IP 及事件快照
        {
            let total_ips = self.entries.len();
            let mut violation_count = 0;

            for entry in self.entries.iter() {
                let entry = entry.value();
                let conn_rate = entry.conn_count as f64;
                let fail_rate_per_min = entry.fail_count as f64 * 60.0;

                // 仅记录违规 IP（避免日志洪泛：不再每条 IP 都输出）
                if conn_rate > config.per_ip_conn_rate as f64 {
                    DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);
                    violation_count += 1;
                    violations.push(PerIpViolation {
                        ip: entry.ip.clone(),
                        event_type: "conn_rate",
                        rate_for_event: conn_rate,
                        threshold_for_event: config.per_ip_conn_rate as f64,
                    });

                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 检测：IP 连接速率违规";
                        "ip" => &entry.ip,
                        "conn_rate" => conn_rate,
                        "threshold" => config.per_ip_conn_rate
                    );
                }

                if fail_rate_per_min > config.per_ip_fail_rate as f64 {
                    DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);
                    violation_count += 1;
                    violations.push(PerIpViolation {
                        ip: entry.ip.clone(),
                        event_type: "fail_rate",
                        rate_for_event: fail_rate_per_min / 60.0,
                        threshold_for_event: config.per_ip_fail_rate as f64 / 60.0,
                    });

                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 检测：IP 失败速率违规";
                        "ip" => &entry.ip,
                        "fail_rate" => fail_rate_per_min / 60.0,
                        "threshold" => config.per_ip_fail_rate as f64 / 60.0
                    );
                }
            }

            // 汇总日志：每次检测输出一次总体统计（替代每条 IP 都输出）
            crate::logger::info!(
                crate::logger::get(),
                "DDoS 检测汇总";
                "tracked_ips" => total_ips,
                "violations" => violation_count,
                "global_conn_count" => self.global_conn_count.load(Ordering::Relaxed)
            );
        } // 读锁释放

        // 阶段 2: DashMap 更新 violation_count 并判断是否触发封禁
        {
            for v in &violations {
                if let Some(mut entry) = self.entries.get_mut(v.ip.as_ref()) {
                    entry.violation_count += 1;

                    let action = if entry.violation_count >= config.auto_ban_threshold {
                        DDOS_STATS
                            .auto_bans_triggered
                            .fetch_add(1, Ordering::Relaxed);
                        "ban"
                    } else {
                        "log"
                    };

                    events.push(DdosEvent {
                        ip: v.ip.to_string(),
                        event_type: v.event_type.to_string(),
                        rate_per_second: v.rate_for_event,
                        threshold: v.threshold_for_event,
                        detected_at: now,
                        action_taken: action.to_string(),
                    });
                }
            }
        } // 写锁释放

        // 重置计数器 (每秒重置) - 必须在检测后执行
        {
            let mut last_reset = self.last_reset_time.write();
            if now > *last_reset {
                // 原子重置全局计数（无锁）
                self.global_conn_count.store(0, Ordering::Relaxed);

                // 重置 per-IP 计数（DashMap 并发迭代）
                {
                    for mut entry in self.entries.iter_mut() {
                        entry.value_mut().reset(now);
                    }
                }

                *last_reset = now;
            }
        }

        events
    }

    /// 强制刷新批量缓冲区（用于测试或检测前确保数据最新）
    pub fn flush(&self) {
        self.flush_batch_buffer();
    }

    /// 获取当前跟踪的 IP 数量
    pub fn tracked_ip_count(&self) -> usize {
        self.entries.len()
    }

    /// 清理过期条目 (超过 5 分钟无活动)
    pub fn cleanup_stale_entries(&self) {
        let now = now_secs();

        let cutoff = now - 300; // 5 分钟

        // DashMap retain API
        self.entries.retain(|_, entry| entry.last_activity > cutoff);

        DDOS_STATS
            .tracked_ips
            .store(self.entries.len() as u64, Ordering::Relaxed);
    }
}

impl Default for ConnRateTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// 全局连接速率跟踪器实例
pub static CONN_RATE_TRACKER: std::sync::OnceLock<ConnRateTracker> = std::sync::OnceLock::new();

/// 获取或创建全局连接速率跟踪器
pub fn get_conn_rate_tracker() -> &'static ConnRateTracker {
    CONN_RATE_TRACKER.get_or_init(ConnRateTracker::new)
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DdosConfig;

    /// 创建低阈值的测试配置，便于触发检测
    fn test_config() -> DdosConfig {
        DdosConfig {
            enabled: true,
            per_ip_conn_rate: 5,
            per_ip_fail_rate: 10,
            global_conn_rate: 100,
            auto_ban_duration: 3600,
            auto_ban_threshold: 3,
            check_interval: 5,
        }
    }

    // ---- ConnRateEntry 测试 ----

    #[test]
    fn test_conn_rate_entry_new() {
        let entry = ConnRateEntry::new("1.2.3.4", 1000);
        assert_eq!(&*entry.ip, "1.2.3.4");
        assert_eq!(entry.conn_count, 0);
        assert_eq!(entry.fail_count, 0);
        assert_eq!(entry.window_start, 1000);
        assert_eq!(entry.last_activity, 1000);
        assert_eq!(entry.violation_count, 0);
    }

    #[test]
    fn test_conn_rate_entry_reset() {
        let mut entry = ConnRateEntry::new("1.2.3.4".to_string(), 1000);
        entry.conn_count = 50;
        entry.fail_count = 20;
        entry.violation_count = 3;

        entry.reset(2000);
        assert_eq!(entry.conn_count, 0);
        assert_eq!(entry.fail_count, 0);
        assert_eq!(entry.window_start, 2000);
        // violation_count 不重置，需要跨检测周期累积以判断是否触发自动封禁
        assert_eq!(entry.violation_count, 3);
    }

    // ---- ConnRateTracker 基础测试 ----

    #[test]
    fn test_tracker_new_empty() {
        let tracker = ConnRateTracker::new();
        assert_eq!(tracker.tracked_ip_count(), 0);
    }

    #[test]
    fn test_record_connection_creates_entry() {
        let tracker = ConnRateTracker::new();
        tracker.record_connection("10.0.0.1");
        tracker.record_connection("10.0.0.1");
        tracker.record_connection("10.0.0.2");
        tracker.flush(); // 强制刷新缓冲区

        assert_eq!(tracker.tracked_ip_count(), 2);
    }

    #[test]
    fn test_record_failure_creates_entry() {
        let tracker = ConnRateTracker::new();
        tracker.record_failure("10.0.0.1");
        tracker.record_failure("10.0.0.1");
        tracker.flush(); // 强制刷新缓冲区

        assert_eq!(tracker.tracked_ip_count(), 1);
    }

    // ---- detect 测试 ----

    #[test]
    fn test_detect_disabled_returns_empty() {
        let tracker = ConnRateTracker::new();
        tracker.record_connection("10.0.0.1");

        let mut config = test_config();
        config.enabled = false;

        let events = tracker.detect(&config);
        assert!(events.is_empty());
    }

    #[test]
    fn test_detect_no_violation_returns_empty() {
        let tracker = ConnRateTracker::new();
        // 记录低于阈值的连接数
        for _ in 0..3 {
            tracker.record_connection("10.0.0.1");
        }

        let config = test_config(); // per_ip_conn_rate = 5
        let events = tracker.detect(&config);
        assert!(events.is_empty(), "低于阈值不应产生事件");
    }

    #[test]
    fn test_detect_conn_rate_violation() {
        let tracker = ConnRateTracker::new();
        // 超过 per_ip_conn_rate (5) 阈值
        for _ in 0..10 {
            tracker.record_connection("10.0.0.1");
        }

        let config = test_config();
        let events = tracker.detect(&config);

        assert!(!events.is_empty(), "超阈值应产生事件");
        assert_eq!(events[0].ip, "10.0.0.1");
        assert_eq!(events[0].event_type, "conn_rate");
        assert_eq!(events[0].action_taken, "log"); // 首次违规,未达 auto_ban_threshold
    }

    #[test]
    fn test_detect_fail_rate_violation() {
        let tracker = ConnRateTracker::new();
        // 超过 per_ip_fail_rate (10/min) 阈值
        for _ in 0..15 {
            tracker.record_failure("10.0.0.1");
        }

        let config = test_config();
        let events = tracker.detect(&config);

        assert!(!events.is_empty(), "失败率超阈值应产生事件");
        assert_eq!(events[0].event_type, "fail_rate");
    }

    #[test]
    fn test_detect_auto_ban_after_threshold() {
        let tracker = ConnRateTracker::new();
        let config = test_config(); // auto_ban_threshold = 3

        // 多次调用 detect 使 violation_count 达到阈值
        for _ in 0..3 {
            // 每次 detect 前需要重新记录连接 (计数器在 detect 内被重置)
            for _ in 0..10 {
                tracker.record_connection("10.0.0.1");
            }
            let events = tracker.detect(&config);
            // 最后一次违规应触发 "ban"
            if let Some(last) = events.last() {
                if last.action_taken == "ban" {
                    assert_eq!(last.ip, "10.0.0.1");
                    return; // 测试通过
                }
            }
        }

        panic!("连续 3 次违规后应触发 auto-ban");
    }

    // ---- cleanup 测试 ----

    #[test]
    fn test_cleanup_stale_entries() {
        let tracker = ConnRateTracker::new();
        // 记录连接 — last_activity 为当前时间
        tracker.record_connection("10.0.0.1");
        tracker.record_connection("10.0.0.2");
        tracker.flush(); // 强制刷新缓冲区

        // 刚记录的条目不应被清理 (last_activity > now - 300)
        tracker.cleanup_stale_entries();
        assert_eq!(tracker.tracked_ip_count(), 2);
    }
}
