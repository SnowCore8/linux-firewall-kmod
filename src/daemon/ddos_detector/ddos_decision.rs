//! DDoS 检测决策逻辑 — ConnRateTracker 方法实现
//!
//! 从 `ddos_detector` 模块拆分出的 `ConnRateTracker` 核心方法：
//! - 连接/失败记录（线程本地缓冲 + 批量刷新）
//! - DDoS 检测算法（per-IP 速率 + 全局速率）
//! - 过期条目清理

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::*;
use crate::types::{now_secs, DdosConfig, DdosEvent, DDOS_STATS};

impl ConnRateTracker {
    /// 记录一次连接（10Gbps+ 优化：IP 数值化 + 线程本地缓冲 + 无锁写入）
    ///
    /// # 性能优化
    ///
    /// - **线程本地缓冲**：写入线程本地缓冲区，完全无锁（消除 RwLock 竞争）
    /// - **IP 数值化**：IPv4 → u32，避免字符串哈希
    /// - **原子计数**：全局计数使用 AtomicU64，无锁更新
    ///
    /// # Arguments
    /// * `ip` - 来源 IP 地址
    pub fn record_connection(&self, ip: &str) {
        // 原子更新全局计数（无锁，10Gbps+ 关键路径）
        self.global_conn_count.fetch_add(1, Ordering::Relaxed);

        // IP 数值化：IPv4 → u32，IPv6 保持字符串
        let parsed = match crate::ip_utils::parse_ip(ip) {
            Some(p) => p,
            None => return, // 无效 IP，跳过
        };
        // 性能优化：使用 String 而非 Arc<str>，延迟 Arc 构造到 flush 阶段
        let ip_string = String::from(ip);

        // 线程本地缓冲：无锁写入（消除 RwLock 竞争）+ 自适应大小
        let should_flush = THREAD_BUFFER.with(|buffer| {
            let mut buf = buffer.borrow_mut();
            buf.push(ThreadLocalEvent {
                ip: ip_string,
                ip_num: parsed.ip_num,
                ipv6_num: parsed.ipv6_num,
                is_ipv6: parsed.is_ipv6,
                event_type: BatchEvent::Connection,
            });
            // 使用自适应缓冲容量
            let capacity = BUFFER_STATE.with(|state| state.borrow().capacity);
            buf.len() >= capacity
        });

        // 本地缓冲区满时，刷新到全局缓冲区
        if should_flush {
            self.flush_thread_buffer();
        }
    }

    /// 记录一次失败尝试（10Gbps+ 优化：IP 数值化 + 线程本地缓冲 + 无锁写入）
    ///
    /// # 性能优化
    ///
    /// - **线程本地缓冲**：写入线程本地缓冲区，完全无锁
    /// - **IP 数值化**：IPv4 → u32，避免字符串哈希
    ///
    /// # Arguments
    /// * `ip` - 来源 IP 地址
    pub fn record_failure(&self, ip: &str) {
        // IP 数值化：IPv4 → u32，IPv6 保持字符串
        let parsed = match crate::ip_utils::parse_ip(ip) {
            Some(p) => p,
            None => return, // 无效 IP，跳过
        };
        // 性能优化：使用 String 而非 Arc<str>，延迟 Arc 构造到 flush 阶段
        let ip_string = String::from(ip);

        // 线程本地缓冲：无锁写入 + 自适应大小
        let should_flush = THREAD_BUFFER.with(|buffer| {
            let mut buf = buffer.borrow_mut();
            buf.push(ThreadLocalEvent {
                ip: ip_string,
                ip_num: parsed.ip_num,
                ipv6_num: parsed.ipv6_num,
                is_ipv6: parsed.is_ipv6,
                event_type: BatchEvent::Failure,
            });
            // 使用自适应缓冲容量
            let capacity = BUFFER_STATE.with(|state| state.borrow().capacity);
            buf.len() >= capacity
        });

        // 本地缓冲区满时，刷新到全局缓冲区
        if should_flush {
            self.flush_thread_buffer();
        }
    }

    /// 刷新线程本地缓冲区到全局缓冲区
    ///
    /// # 性能优化
    ///
    /// - 线程本地缓冲区满时调用，将事件转移到全局缓冲区
    /// - 使用 `std::mem::take` 零拷贝转移数据
    /// - 全局缓冲区仅在 flush 时统一处理，减少锁竞争
    /// - **自适应调整**：根据 flush 频率动态调整缓冲大小
    fn flush_thread_buffer(&self) {
        let events = THREAD_BUFFER.with(|buffer| {
            let mut buf = buffer.borrow_mut();
            std::mem::take(&mut *buf)
        });

        if events.is_empty() {
            return;
        }

        // 记录 flush 并可能调整缓冲大小
        BUFFER_STATE.with(|state| {
            let mut state = state.borrow_mut();
            state.record_flush();
            let new_capacity = state.maybe_resize();
            // 预分配新的缓冲容量
            THREAD_BUFFER.with(|buffer| {
                let mut buf = buffer.borrow_mut();
                let current_capacity = buf.capacity();
                if new_capacity > current_capacity {
                    buf.reserve(new_capacity - current_capacity);
                }
            });
        });

        // 将线程本地缓冲的事件转移到全局无锁队列
        for event in events {
            self.global_batch_buffer.push(event);
        }

        // 全局队列达到阈值时，刷新到 DashMap
        if self.global_batch_buffer.len() >= BATCH_BUFFER_SIZE {
            self.flush_batch_buffer();
        }
    }

    /// 刷新批量缓冲区，将收集的事件一次性更新到 DashMap
    ///
    /// # 性能优化
    ///
    /// - 将 1000 个 DashMap 操作合并为一次批量更新
    /// - 使用 HashMap 聚合相同 IP 的事件，减少 DashMap 访问次数
    /// - IPv4 使用 u32 键（避免字符串哈希），IPv6 使用 [u8; 16] 键
    /// - **无锁队列**：使用 SegQueue::pop 逐个取出事件，无锁竞争
    fn flush_batch_buffer(&self) {
        // 从无锁队列中取出所有事件
        let mut events = Vec::with_capacity(BATCH_BUFFER_SIZE);
        while let Some(event) = self.global_batch_buffer.pop() {
            events.push(event);
        }

        if events.is_empty() {
            return;
        }

        let now = now_secs();

        // 分离 IPv4 和 IPv6 事件，分别聚合
        let mut aggregated_ipv4: HashMap<u32, (Arc<str>, u64, u64)> = HashMap::new();
        let mut aggregated_ipv6: HashMap<[u8; 16], (Arc<str>, u64, u64)> = HashMap::new();

        for event in events {
            // 性能优化：在 flush 阶段批量构造 Arc<str>，而非每次事件都构造
            let ip_arc: Arc<str> = Arc::from(event.ip.as_str());

            if event.is_ipv6 {
                // IPv6: 使用 [u8; 16] 键（快速哈希）
                let entry = aggregated_ipv6
                    .entry(event.ipv6_num)
                    .or_insert((ip_arc, 0, 0));
                match event.event_type {
                    BatchEvent::Connection => entry.1 += 1,
                    BatchEvent::Failure => entry.2 += 1,
                }
            } else {
                // IPv4: 使用 u32 键（快速哈希）
                let entry = aggregated_ipv4
                    .entry(event.ip_num)
                    .or_insert((ip_arc, 0, 0));
                match event.event_type {
                    BatchEvent::Connection => entry.1 += 1,
                    BatchEvent::Failure => entry.2 += 1,
                }
            }
        }

        // 一次性更新 IPv4 DashMap（u32 键，快速哈希）
        for (ip_num, (ip_arc, conn_count, fail_count)) in aggregated_ipv4 {
            let mut entry = self
                .entries_ipv4
                .entry(ip_num)
                .or_insert_with(|| ConnRateEntry::new(ip_arc, ip_num, [0; 16], now));
            entry.conn_count += conn_count;
            entry.fail_count += fail_count;
            entry.last_activity = now;
        }

        // 一次性更新 IPv6 DashMap（[u8; 16] 键，快速哈希）
        for (ipv6_num, (ip_arc, conn_count, fail_count)) in aggregated_ipv6 {
            let mut entry = self
                .entries_ipv6
                .entry(ipv6_num)
                .or_insert_with(|| ConnRateEntry::new(ip_arc, 0, ipv6_num, now));
            entry.conn_count += conn_count;
            entry.fail_count += fail_count;
            entry.last_activity = now;
        }

        // 更新统计
        let total_ips = self.entries_ipv4.len() + self.entries_ipv6.len();
        DDOS_STATS
            .tracked_ips
            .store(total_ips as u64, Ordering::Relaxed);
    }

    /// 检测 DDoS 攻击
    ///
    /// # Arguments
    /// * `config` - DDoS 配置
    ///
    /// # Returns
    /// 检测到的 DDoS 事件列表
    pub fn detect(&self, config: &DdosConfig) -> Vec<DdosEvent> {
        // 网络层检测已下沉到 kmod；非测试构建禁用用户态 detect，防止误启双封禁
        if !cfg!(test) {
            let _ = (self, config);
            return Vec::new();
        }

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
            ip_num: u32,
            ipv6_num: [u8; 16],
            is_ipv6: bool,
            event_type: &'static str,
            rate_for_event: f64,
            threshold_for_event: f64,
        }

        let mut violations: Vec<PerIpViolation> = Vec::new();

        // 辅助闭包：检查单个条目的违规情况
        let mut check_violations =
            |ip: &Arc<str>,
             ip_num: u32,
             ipv6_num: [u8; 16],
             is_ipv6: bool,
             conn_count: u64,
             fail_count: u64,
             violation_count: &mut usize| {
                let conn_rate = conn_count as f64;
                let fail_rate_per_min = fail_count as f64 * 60.0;

                if conn_rate > config.per_ip_conn_rate as f64 {
                    DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);
                    *violation_count += 1;
                    violations.push(PerIpViolation {
                        ip: ip.clone(),
                        ip_num,
                        ipv6_num,
                        is_ipv6,
                        event_type: "conn_rate",
                        rate_for_event: conn_rate,
                        threshold_for_event: config.per_ip_conn_rate as f64,
                    });

                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 检测：IP 连接速率违规";
                        "ip" => ip.as_ref(),
                        "conn_rate" => conn_rate,
                        "threshold" => config.per_ip_conn_rate
                    );
                }

                if fail_rate_per_min > config.per_ip_fail_rate as f64 {
                    DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);
                    *violation_count += 1;
                    violations.push(PerIpViolation {
                        ip: ip.clone(),
                        ip_num,
                        ipv6_num,
                        is_ipv6,
                        event_type: "fail_rate",
                        rate_for_event: fail_rate_per_min / 60.0,
                        threshold_for_event: config.per_ip_fail_rate as f64 / 60.0,
                    });

                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 检测：IP 失败速率违规";
                        "ip" => ip.as_ref(),
                        "fail_rate" => fail_rate_per_min / 60.0,
                        "threshold" => config.per_ip_fail_rate as f64 / 60.0
                    );
                }
            };

        // 阶段 1: 并发迭代 IPv4 + IPv6 DashMap 收集违规 IP 及事件快照
        {
            let total_ips = self.entries_ipv4.len() + self.entries_ipv6.len();
            let mut violation_count = 0;

            // 检测 IPv4 违规
            for entry in self.entries_ipv4.iter() {
                let entry_ref = entry.value();
                check_violations(
                    &entry_ref.ip,
                    entry_ref.ip_num,
                    [0; 16],
                    false,
                    entry_ref.conn_count,
                    entry_ref.fail_count,
                    &mut violation_count,
                );
            }

            // 检测 IPv6 违规
            for entry in self.entries_ipv6.iter() {
                let entry_ref = entry.value();
                check_violations(
                    &entry_ref.ip,
                    0,
                    entry_ref.ipv6_num,
                    true,
                    entry_ref.conn_count,
                    entry_ref.fail_count,
                    &mut violation_count,
                );
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

        // 阶段 2: DashMap 更新 violation_count（封禁决策已迁移到 netlink 决策引擎）
        // 注意：此处仅记录违规次数，不再触发封禁。封禁由 DdosDecisionEngine 通过 netlink 处理。
        {
            for v in &violations {
                if v.is_ipv6 {
                    // IPv6: 使用 [u8; 16] 键查找
                    if let Some(entry) = self.entries_ipv6.get_mut(&v.ipv6_num) {
                        let _prev_count = entry.violation_count.fetch_add(1, Ordering::Relaxed);

                        events.push(DdosEvent {
                            ip: v.ip.to_string(),
                            event_type: v.event_type.to_string(),
                            rate_per_second: v.rate_for_event,
                            threshold: v.threshold_for_event,
                            detected_at: now,
                            action_taken: "log".to_string(), // 封禁决策已迁移到 netlink 决策引擎
                        });
                    }
                } else {
                    // IPv4: 使用 u32 键查找
                    if let Some(entry) = self.entries_ipv4.get_mut(&v.ip_num) {
                        let _prev_count = entry.violation_count.fetch_add(1, Ordering::Relaxed);

                        events.push(DdosEvent {
                            ip: v.ip.to_string(),
                            event_type: v.event_type.to_string(),
                            rate_per_second: v.rate_for_event,
                            threshold: v.threshold_for_event,
                            detected_at: now,
                            action_taken: "log".to_string(), // 封禁决策已迁移到 netlink 决策引擎
                        });
                    }
                }
            }
        } // 写锁释放

        // 重置计数器 (每秒重置) - 必须在检测后执行
        {
            let mut last_reset = self.last_reset_time.write();
            if now > *last_reset {
                // 原子重置全局计数（无锁）
                self.global_conn_count.store(0, Ordering::Relaxed);

                // 重置 IPv4 per-IP 计数（DashMap 并发迭代）
                {
                    for mut entry in self.entries_ipv4.iter_mut() {
                        entry.value_mut().reset(now);
                    }
                }

                // 重置 IPv6 per-IP 计数（DashMap 并发迭代）
                {
                    for mut entry in self.entries_ipv6.iter_mut() {
                        entry.value_mut().reset(now);
                    }
                }

                *last_reset = now;
            }
        }

        events
    }

    /// 强制刷新批量缓冲区（用于测试或检测前确保数据最新）
    ///
    /// # 刷新顺序
    ///
    /// 1. 刷新线程本地缓冲 → 全局缓冲
    /// 2. 刷新全局缓冲 → DashMap
    pub fn flush(&self) {
        // 先刷新线程本地缓冲到全局缓冲
        self.flush_thread_buffer();
        // 再刷新全局缓冲到 DashMap
        self.flush_batch_buffer();
    }

    /// 获取当前跟踪的 IP 数量（IPv4 + IPv6）
    pub fn tracked_ip_count(&self) -> usize {
        self.entries_ipv4.len() + self.entries_ipv6.len()
    }

    /// 清理过期条目 (超过 5 分钟无活动)
    pub fn cleanup_stale_entries(&self) {
        let now = now_secs();

        let cutoff = now - 300; // 5 分钟

        // DashMap retain API: 清理 IPv4
        self.entries_ipv4
            .retain(|_, entry| entry.last_activity > cutoff);

        // DashMap retain API: 清理 IPv6
        self.entries_ipv6
            .retain(|_, entry| entry.last_activity > cutoff);

        // 更新统计
        let total_ips = self.entries_ipv4.len() + self.entries_ipv6.len();
        DDOS_STATS
            .tracked_ips
            .store(total_ips as u64, Ordering::Relaxed);
    }
}

impl Default for ConnRateTracker {
    fn default() -> Self {
        Self::new()
    }
}
