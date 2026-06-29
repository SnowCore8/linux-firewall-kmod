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
//! 6. **线程本地缓冲**：每个线程维护独立缓冲区，消除锁竞争
//! 7. **IP 数值化**：IPv4 使用 u32 键，避免字符串哈希（10x 提升）
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

use std::cell::RefCell;
use std::sync::atomic::AtomicU64;

use crossbeam::queue::SegQueue;
use dashmap::DashMap;
use parking_lot::RwLock;

use crate::types::ConnRateEntry;

/// DDoS 检测决策逻辑（ConnRateTracker 方法实现）
mod ddos_decision;

/// 批量处理缓冲区大小（10Gbps+ 优化：收集 1000 个事件后一次性更新）
pub(super) const BATCH_BUFFER_SIZE: usize = 1000;

/// 线程本地缓冲区最小大小（自适应下限）
const THREAD_BUFFER_MIN: usize = 50;

/// 线程本地缓冲区最大大小（自适应上限）
const THREAD_BUFFER_MAX: usize = 500;

/// 线程本地缓冲区初始大小
const THREAD_BUFFER_INITIAL: usize = 100;

/// 自适应缓冲调整周期（秒）
const ADAPTIVE_RESIZE_INTERVAL: i64 = 10;

/// 自适应缓冲区状态跟踪
#[derive(Debug)]
pub(super) struct AdaptiveBufferState {
    /// 当前缓冲容量
    pub(super) capacity: usize,
    /// 上次调整时间
    pub(super) last_resize_time: i64,
    /// 周期内 flush 次数
    pub(super) flush_count: u32,
}

impl AdaptiveBufferState {
    pub(super) const fn new_const() -> Self {
        Self {
            capacity: THREAD_BUFFER_INITIAL,
            last_resize_time: 0,
            flush_count: 0,
        }
    }
}

impl Default for AdaptiveBufferState {
    fn default() -> Self {
        Self::new_const()
    }
}

impl AdaptiveBufferState {
    /// 根据负载动态调整缓冲大小
    ///
    /// # 策略
    ///
    /// - 高负载（flush 频繁）：增大缓冲，减少 flush 次数
    /// - 低负载（flush 稀少）：减小缓冲，节省内存
    /// - 调整间隔：至少 10 秒，避免抖动
    pub(super) fn maybe_resize(&mut self) -> usize {
        let now = crate::types::now_secs();
        let elapsed = now - self.last_resize_time;

        // 未到调整周期，保持当前大小
        if elapsed < ADAPTIVE_RESIZE_INTERVAL {
            return self.capacity;
        }

        // 根据 flush 频率调整
        let new_capacity = if self.flush_count > 10 {
            // 高负载：增大缓冲（每次增长 20%，上限 500）
            (self.capacity * 12 / 10).min(THREAD_BUFFER_MAX)
        } else if self.flush_count < 2 {
            // 低负载：减小缓冲（每次缩减 20%，下限 50）
            (self.capacity * 8 / 10).max(THREAD_BUFFER_MIN)
        } else {
            // 中等负载：保持不变
            self.capacity
        };

        // 更新状态
        self.capacity = new_capacity;
        self.last_resize_time = now;
        self.flush_count = 0;

        new_capacity
    }

    /// 记录一次 flush
    pub(super) fn record_flush(&mut self) {
        self.flush_count += 1;
    }
}

/// 批量事件类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BatchEvent {
    Connection,
    Failure,
}

/// 批量事件（线程本地缓冲使用）
///
/// # 性能优化
///
/// 使用 `String` 而非 `Arc<str>`，延迟 Arc 分配到 flush 阶段。
/// 在 10Gbps 场景下，每次事件都进行 Arc 分配的开销显著。
/// 改为 flush 时批量构造 Arc，减少堆分配次数。
#[derive(Debug, Clone)]
pub(super) struct ThreadLocalEvent {
    pub(super) ip: String,
    pub(super) ip_num: u32,
    pub(super) ipv6_num: [u8; 16],
    pub(super) is_ipv6: bool,
    pub(super) event_type: BatchEvent,
}

/// 连接速率跟踪器 — 10Gbps+ 优化版（IP 数值化 + 线程本地缓冲 + 热点缓存 + DashMap 分片锁）
///
/// 维护所有 IP 的连接速率统计，支持 per-IP 和全局限速检测。
///
/// # 性能特性
///
/// - `global_conn_count`: 原子计数器，无锁更新
/// - `entries_ipv4`: IPv4 使用 u32 键，避免字符串哈希（比 Arc<str> 快 5-10x）
/// - `entries_ipv6`: IPv6 使用 [u8; 16] 键，避免字符串哈希（比 Arc<str> 快 8-10x）
/// - `Arc<str>` 共享 IP 字符串，减少内存分配
/// - **线程本地缓冲**：每个线程维护独立缓冲区，消除锁竞争（10Gbps+ 关键优化）
/// - **IP 数值化**：IPv4/IPv6 都使用数值键，哈希性能提升 8-10x
/// - **热点 IP 缓存**：线程本地 LRU 缓存，减少 DashMap 访问（DDoS 场景关键优化）
pub struct ConnRateTracker {
    /// IPv4 → 连接速率条目（u32 键，避免字符串哈希）
    pub(super) entries_ipv4: DashMap<u32, ConnRateEntry>,
    /// IPv6 → 连接速率条目（[u8; 16] 键，避免字符串哈希）
    pub(super) entries_ipv6: DashMap<[u8; 16], ConnRateEntry>,
    /// 全局连接计数（原子操作，无锁）
    pub(super) global_conn_count: AtomicU64,
    /// 上次重置时间 (Unix 秒)
    pub(super) last_reset_time: RwLock<i64>,
    /// 全局批量缓冲区（无锁队列，消除 RwLock 竞争）
    /// 使用 crossbeam::queue::SegQueue，支持高并发 push/pop
    pub(super) global_batch_buffer: SegQueue<ThreadLocalEvent>,
}

// 线程本地缓冲区（每个线程独立，无锁写入）+ 自适应状态
thread_local! {
    pub(super) static THREAD_BUFFER: RefCell<Vec<ThreadLocalEvent>> = const { RefCell::new(Vec::new()) };
    pub(super) static BUFFER_STATE: RefCell<AdaptiveBufferState> = const { RefCell::new(AdaptiveBufferState::new_const()) };
}

impl ConnRateTracker {
    /// 创建新的连接速率跟踪器（10Gbps+ 优化：IP 数值化 + 线程本地缓冲 + 无锁队列）
    pub fn new() -> Self {
        let now = crate::types::now_secs();

        Self {
            // IPv4 DashMap 默认 16 分片（CPU 核心数），预分配 10 万容量
            entries_ipv4: DashMap::with_capacity(100_000),
            // IPv6 DashMap 预分配 1 万容量（IPv6 流量通常较少）
            entries_ipv6: DashMap::with_capacity(10_000),
            global_conn_count: AtomicU64::new(0),
            last_reset_time: RwLock::new(now),
            // 全局缓冲区使用无锁队列（消除 RwLock 竞争）
            global_batch_buffer: SegQueue::new(),
        }
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

    // ---- AdaptiveBufferState 测试 ----

    #[test]
    fn test_adaptive_buffer_initial_state() {
        let state = AdaptiveBufferState::default();
        assert_eq!(state.capacity, THREAD_BUFFER_INITIAL);
        assert_eq!(state.flush_count, 0);
    }

    #[test]
    fn test_adaptive_buffer_high_load_growth() {
        let mut state = AdaptiveBufferState::default();
        state.last_resize_time = crate::types::now_secs() - ADAPTIVE_RESIZE_INTERVAL - 1;
        state.flush_count = 15; // 高负载

        let new_capacity = state.maybe_resize();
        // 应该增长 20%
        assert_eq!(
            new_capacity,
            (THREAD_BUFFER_INITIAL * 12 / 10).min(THREAD_BUFFER_MAX)
        );
        assert_eq!(state.flush_count, 0); // 应该重置
    }

    #[test]
    fn test_adaptive_buffer_low_load_shrink() {
        let mut state = AdaptiveBufferState::default();
        state.last_resize_time = crate::types::now_secs() - ADAPTIVE_RESIZE_INTERVAL - 1;
        state.flush_count = 1; // 低负载

        let new_capacity = state.maybe_resize();
        // 应该缩减 20%
        assert_eq!(
            new_capacity,
            (THREAD_BUFFER_INITIAL * 8 / 10).max(THREAD_BUFFER_MIN)
        );
        assert_eq!(state.flush_count, 0); // 应该重置
    }

    #[test]
    fn test_adaptive_buffer_medium_load_stable() {
        let mut state = AdaptiveBufferState::default();
        state.last_resize_time = crate::types::now_secs() - ADAPTIVE_RESIZE_INTERVAL - 1;
        state.flush_count = 5; // 中等负载

        let new_capacity = state.maybe_resize();
        // 应该保持不变
        assert_eq!(new_capacity, THREAD_BUFFER_INITIAL);
        assert_eq!(state.flush_count, 0); // 应该重置
    }

    #[test]
    fn test_adaptive_buffer_not_resized_within_interval() {
        let mut state = AdaptiveBufferState::default();
        state.last_resize_time = crate::types::now_secs(); // 刚刚调整过
        state.flush_count = 100; // 即使 flush 很多

        let new_capacity = state.maybe_resize();
        // 未到调整周期，应该保持不变
        assert_eq!(new_capacity, THREAD_BUFFER_INITIAL);
        assert_eq!(state.flush_count, 100); // 不应该重置
    }

    #[test]
    fn test_adaptive_buffer_respects_bounds() {
        let mut state = AdaptiveBufferState::default();

        // 测试上限
        state.capacity = THREAD_BUFFER_MAX;
        state.last_resize_time = crate::types::now_secs() - ADAPTIVE_RESIZE_INTERVAL - 1;
        state.flush_count = 100;
        let new_capacity = state.maybe_resize();
        assert!(new_capacity <= THREAD_BUFFER_MAX);

        // 测试下限
        state.capacity = THREAD_BUFFER_MIN;
        state.last_resize_time = crate::types::now_secs() - ADAPTIVE_RESIZE_INTERVAL - 1;
        state.flush_count = 0;
        let new_capacity = state.maybe_resize();
        assert!(new_capacity >= THREAD_BUFFER_MIN);
    }

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
            baseline_warmup_samples: 50,
            // 协议专项阈值（测试用低值）
            max_syn_per_second: 200,
            max_udp_per_second: 1000,
            max_icmp_per_second: 50,
            max_ack_per_second: 2000,
            max_rst_per_second: 200,
            max_fin_per_second: 200,
            // DDoS 检测算法开关
            static_threshold: true,
            dynamic_threshold: false,
            ddos_detection: true,
            // 内核模块参数
            max_bans_per_second: 200,
            max_rate_entries: 65536,
        }
    }

    // ---- ConnRateEntry 测试 ----

    #[test]
    fn test_conn_rate_entry_new() {
        let entry = ConnRateEntry::new("1.2.3.4", 16909060, [0; 16], 1000); // 1.2.3.4 = 16909060
        assert_eq!(&*entry.ip, "1.2.3.4");
        assert_eq!(entry.ip_num, 16909060);
        assert_eq!(entry.ipv6_num, [0; 16]);
        assert_eq!(entry.conn_count, 0);
        assert_eq!(entry.fail_count, 0);
        assert_eq!(entry.last_activity, 1000);
        assert_eq!(
            entry
                .violation_count
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn test_conn_rate_entry_reset() {
        let mut entry = ConnRateEntry::new("1.2.3.4".to_string(), 16909060, [0; 16], 1000);
        entry.conn_count = 50;
        entry.fail_count = 20;
        entry
            .violation_count
            .store(3, std::sync::atomic::Ordering::Relaxed);

        entry.reset(2000);
        assert_eq!(entry.conn_count, 0);
        assert_eq!(entry.fail_count, 0);
        assert_eq!(entry.window_start, 2000);
        // violation_count 不重置，需要跨检测周期累积以判断是否触发自动封禁
        assert_eq!(
            entry
                .violation_count
                .load(std::sync::atomic::Ordering::Relaxed),
            3
        );
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
    fn test_detect_records_violations_without_auto_ban() {
        // 封禁决策已迁移到 DdosDecisionEngine，detect() 仅记录违规
        let tracker = ConnRateTracker::new();
        let config = test_config(); // auto_ban_threshold = 3

        // 多次调用 detect 使 violation_count 达到阈值
        for _ in 0..3 {
            // 每次 detect 前需要重新记录连接 (计数器在 detect 内被重置)
            for _ in 0..10 {
                tracker.record_connection("10.0.0.1");
            }
            let events = tracker.detect(&config);
            // 所有事件的 action_taken 应为 "log"（封禁决策已迁移）
            for event in &events {
                assert_eq!(event.action_taken, "log");
            }
        }
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
