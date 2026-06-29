//! DDoS 决策引擎
//!
//! 接收内核推送的 DDoS 事件，记录日志和统计。
//! 内核已封禁 IP，守护进程不重复封禁。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::types::{now_secs, DdosConfig, DDOS_STATS};

/// 每 IP 违规跟踪条目
///
/// IP 地址作为 HashMap key 已存储，此处仅记录运行时状态。
/// 移除冗余 `ip` 字段和未被读取的 `first_violation` 字段。
#[derive(Debug)]
struct IpViolationTracker {
    /// 违规次数
    violation_count: AtomicU32,
    /// 最后违规时间（原子类型，支持并发访问）
    last_violation: AtomicI64,
}

impl IpViolationTracker {
    fn new(now: i64) -> Self {
        Self {
            violation_count: AtomicU32::new(1),
            last_violation: AtomicI64::new(now),
        }
    }

    fn increment(&self, now: i64) -> u32 {
        self.last_violation.store(now, Ordering::Relaxed);
        self.violation_count.fetch_add(1, Ordering::Relaxed) + 1
    }
}

/// DDoS 决策引擎
pub struct DdosDecisionEngine {
    /// DDoS 配置（使用 RwLock 支持运行时更新）
    config: RwLock<DdosConfig>,
    /// 每 IP 违规跟踪
    ip_trackers: RwLock<HashMap<IpAddr, Arc<IpViolationTracker>>>,
}

impl DdosDecisionEngine {
    /// 创建决策引擎
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config: RwLock::new(config),
            ip_trackers: RwLock::new(HashMap::new()),
        }
    }

    /// 更新配置
    pub fn update_config(&self, new_config: DdosConfig) {
        let mut config = self.config.write();
        crate::logger::info!(
            crate::logger::get(),
            "DDoS 决策引擎配置更新";
            "auto_ban_threshold" => new_config.auto_ban_threshold,
            "auto_ban_duration" => new_config.auto_ban_duration
        );
        *config = new_config;
    }

    /// 获取当前配置快照（用于 API 层同步 webui → ddos 字段）
    pub fn current_config(&self) -> DdosConfig {
        self.config.read().clone()
    }

    /// 处理 DDoS 事件
    ///
    /// 内核已封禁 IP，守护进程只记录日志和统计（不重复封禁）。
    pub fn handle_event(&self, ip: IpAddr, reason: &str, rate_pps: u32) {
        let now = now_secs();

        // 更新统计
        DDOS_STATS.events_detected.fetch_add(1, Ordering::Relaxed);

        // 获取或创建 IP 跟踪器
        let tracker = {
            let mut trackers = self.ip_trackers.write();
            if let Some(existing) = trackers.get(&ip) {
                existing.clone()
            } else {
                let new_tracker = Arc::new(IpViolationTracker::new(now));
                trackers.insert(ip, new_tracker.clone());
                new_tracker
            }
        };

        // 递增违规次数
        let count = tracker.increment(now);

        // 读取配置（加锁）
        let threshold = {
            let config = self.config.read();
            config.auto_ban_threshold
        };

        // 内核已封禁，守护进程只记录日志
        crate::logger::info!(
            crate::logger::get(),
            "DDoS 事件：内核已封禁";
            "ip" => %ip,
            "reason" => reason,
            "rate_pps" => rate_pps,
            "violation_count" => count,
            "threshold" => threshold
        );
    }

    /// 清理过期的 IP 跟踪器
    ///
    /// 定期调用，清理长时间未活动的 IP 跟踪器，避免内存泄漏。
    pub fn cleanup_stale_trackers(&self) {
        let now = now_secs();
        let stale_threshold = 300; // 5 分钟未活动视为过期

        let mut trackers = self.ip_trackers.write();
        trackers.retain(|_, tracker| {
            let last = tracker.last_violation.load(Ordering::Relaxed);
            now - last < stale_threshold
        });
    }

    /// 获取当前跟踪的 IP 数量
    pub fn tracked_ips_count(&self) -> usize {
        self.ip_trackers.read().len()
    }
}
