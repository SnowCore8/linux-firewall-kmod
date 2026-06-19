//! DDoS 决策引擎
//!
//! 接收内核推送的 DDoS 事件，根据策略决定是否封禁。
//! 通过 netlink 发送封禁指令给内核。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::netlink::NetlinkContext;
use crate::types::{now_secs, DdosConfig, DDOS_STATS};

/// 每 IP 违规跟踪条目
#[derive(Debug)]
#[allow(dead_code)] // ip/first_violation 通过 Debug trait 间接使用
struct IpViolationTracker {
    /// IP 地址
    ip: IpAddr,
    /// 违规次数
    violation_count: AtomicU32,
    /// 首次违规时间
    first_violation: i64,
    /// 最后违规时间（原子类型，支持并发访问）
    last_violation: AtomicI64,
}

impl IpViolationTracker {
    fn new(ip: IpAddr, now: i64) -> Self {
        Self {
            ip,
            violation_count: AtomicU32::new(1),
            first_violation: now,
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
    /// Netlink 上下文（用于发送封禁指令）
    netlink: Arc<NetlinkContext>,
    /// 每 IP 违规跟踪（使用 DashMap 或 RwLock<HashMap>）
    ip_trackers: RwLock<HashMap<IpAddr, Arc<IpViolationTracker>>>,
}

impl DdosDecisionEngine {
    /// 创建决策引擎
    pub fn new(config: DdosConfig, netlink: Arc<NetlinkContext>) -> Self {
        Self {
            config: RwLock::new(config),
            netlink,
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

    /// 处理 DDoS 事件
    ///
    /// 根据违规次数决定是否封禁：
    /// - 违规次数 < auto_ban_threshold: 仅记录日志
    /// - 违规次数 >= auto_ban_threshold: 发送封禁指令
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
                let new_tracker = Arc::new(IpViolationTracker::new(ip, now));
                trackers.insert(ip, new_tracker.clone());
                new_tracker
            }
        };

        // 递增违规次数
        let count = tracker.increment(now);

        // 读取配置（加锁）
        let (threshold, duration) = {
            let config = self.config.read();
            (config.auto_ban_threshold, config.auto_ban_duration)
        };

        // 决策：是否封禁
        if count >= threshold {
            // 触发封禁
            DDOS_STATS
                .auto_bans_triggered
                .fetch_add(1, Ordering::Relaxed);

            crate::logger::info!(
                crate::logger::get(),
                "DDoS 决策：触发封禁";
                "ip" => %ip,
                "reason" => reason,
                "rate_pps" => rate_pps,
                "violation_count" => count,
                "duration_secs" => duration
            );

            // 通过 netlink 发送封禁指令
            if let Err(e) = self.netlink.send_ban(ip, duration) {
                crate::logger::error!(
                    crate::logger::get(),
                    "发送封禁指令失败";
                    "ip" => %ip,
                    "error" => %e
                );
            } else {
                // 封禁指令发送成功，同步到 ACTIVE_BAN_CACHE（Web UI 需要）
                use crate::types::{BanInfo, BanReason, ACTIVE_BAN_CACHE};
                let ban_info = BanInfo {
                    ip: ip.to_string(),
                    ip_num: match ip {
                        std::net::IpAddr::V4(v4) => u32::from(v4),
                        std::net::IpAddr::V6(_) => 0,
                    },
                    jail_name: "ddos".to_string(),
                    reason: BanReason::DDoSRateLimit,
                    banned_at: now,
                    expires_at: if duration > 0 {
                        now + duration as i64
                    } else {
                        0
                    },
                    is_permanent: duration == 0,
                    fail_count: count,
                };
                if let Some(cache) = ACTIVE_BAN_CACHE.get() {
                    cache.insert(ban_info);
                }
            }

            // 重置违规计数（避免重复封禁）
            tracker.violation_count.store(0, Ordering::Relaxed);
        } else {
            // 仅记录日志
            crate::logger::info!(
                crate::logger::get(),
                "DDoS 决策：记录违规";
                "ip" => %ip,
                "reason" => reason,
                "rate_pps" => rate_pps,
                "violation_count" => count,
                "threshold" => threshold
            );
        }
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
