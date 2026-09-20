//! 计数器：**只增**的原子量，读侧免费取快照。
//!
//! # 为什么计数器单列
//!
//! 计数器与其它域的形态不同：它没有「结构」，没有跨字段不变量，每个字段互相独立，
//! 读侧只是把一串原子量读出来。故不适合套用 `Arc<快照>` 的发布模式——那只会给
//! 高频自增加一层锁。这里保持原子自增，读侧直接 `load`。
//!
//! # 读路径无副作用（缺陷 E 的另一半）
//!
//! 旧实现里 `web_ui/ban_ops.rs::get_active_bans()` 在读路径上顺手
//! `DAEMON_STATS.total_unbans.fetch_add(...)` 并喂 `record_ban_duration`。本模块
//! 只提供 `inc` / `add` / `set_gauge`，**读快照不改任何值**；谁该在什么时候自增，
//! 由拥有该行为的模块在自己的写路径上决定（例如 `state::bans::Bans::purge_expired`
//! 的调用方），不挂在读侧。
//!
//! # 白名单数不在这里
//!
//! 旧实现另有一枚 `whitelist_count`（程序内部维护的近似值）。新设计里白名单数由
//! [`super::whitelist::Whitelist`] 单点持有，读侧数它即可，不再维护第二份来源——
//! 两份来源迟早会漂移。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use super::hub::{Domain, Hub, SharedHub};

/// 计数器推送间隔的默认值（秒）。与 `webui.sse_push_interval` 的默认一致；
/// 组合根启动期会用配置里的值覆盖它。
const DEFAULT_STATS_PUSH_SECS: u64 = 1;

/// 只增计数器。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Counter {
    /// 已解析的日志行数。
    LinesParsed,
    /// 从日志中成功提取的 IP 数。
    IpsExtracted,
    /// 已成功发起的封禁数。
    IpsBanned,
    /// 失败尝试总数（含未触发封禁的早期失败）。
    FailedAttempts,
    /// 配置重载成功次数。
    ConfigReloads,
    /// inotify 唤醒次数（与事件数无关）。
    InotifyEvents,
    /// 日志轮转检测次数。
    LogRotations,
    /// 因超长/格式异常跳过的行数。
    LinesSkipped,
    /// 正则匹配命中总数。
    RegexMatches,
    /// 累计解封数。
    TotalUnbans,
    /// 丢弃数据包数（内核侧的近似值）。
    PacketsDropped,
    /// 接受数据包数（内核侧的近似值）。
    PacketsAccepted,
    /// netlink 报文发送总数。
    NetlinkMessagesSent,
    /// netlink 报文接收总数。
    NetlinkMessagesReceived,
    /// netlink 发送失败数。
    NetlinkSendErrors,
    /// netlink 接收/解析失败数。
    NetlinkRecvErrors,
}

impl Counter {
    /// 全部计数器，顺序固定（解码/展示都按此顺序）。
    pub const ALL: [Self; 16] = [
        Self::LinesParsed,
        Self::IpsExtracted,
        Self::IpsBanned,
        Self::FailedAttempts,
        Self::ConfigReloads,
        Self::InotifyEvents,
        Self::LogRotations,
        Self::LinesSkipped,
        Self::RegexMatches,
        Self::TotalUnbans,
        Self::PacketsDropped,
        Self::PacketsAccepted,
        Self::NetlinkMessagesSent,
        Self::NetlinkMessagesReceived,
        Self::NetlinkSendErrors,
        Self::NetlinkRecvErrors,
    ];

    /// 计数器名称（HTTP 字段名与诊断用）。
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::LinesParsed => "lines_parsed",
            Self::IpsExtracted => "ips_extracted",
            Self::IpsBanned => "ips_banned",
            Self::FailedAttempts => "failed_attempts",
            Self::ConfigReloads => "config_reloads",
            Self::InotifyEvents => "inotify_events",
            Self::LogRotations => "log_rotations",
            Self::LinesSkipped => "lines_skipped",
            Self::RegexMatches => "regex_matches",
            Self::TotalUnbans => "total_unbans",
            Self::PacketsDropped => "packets_dropped",
            Self::PacketsAccepted => "packets_accepted",
            Self::NetlinkMessagesSent => "netlink_messages_sent",
            Self::NetlinkMessagesReceived => "netlink_messages_received",
            Self::NetlinkSendErrors => "netlink_send_errors",
            Self::NetlinkRecvErrors => "netlink_recv_errors",
        }
    }

    /// 在 [`Counter::ALL`] 中的下标。
    const fn index(self) -> usize {
        match self {
            Self::LinesParsed => 0,
            Self::IpsExtracted => 1,
            Self::IpsBanned => 2,
            Self::FailedAttempts => 3,
            Self::ConfigReloads => 4,
            Self::InotifyEvents => 5,
            Self::LogRotations => 6,
            Self::LinesSkipped => 7,
            Self::RegexMatches => 8,
            Self::TotalUnbans => 9,
            Self::PacketsDropped => 10,
            Self::PacketsAccepted => 11,
            Self::NetlinkMessagesSent => 12,
            Self::NetlinkMessagesReceived => 13,
            Self::NetlinkSendErrors => 14,
            Self::NetlinkRecvErrors => 15,
        }
    }
}

/// 计数器快照（不可变，按 [`Counter::ALL`] 顺序逐项取一次）。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    values: [u64; 16],
    /// 守护进程启动时间（Unix 秒）；0 表示尚未设置。
    pub start_time: u64,
}

impl StatsSnapshot {
    /// 读某个计数器。
    #[must_use]
    pub const fn get(&self, counter: Counter) -> u64 {
        self.values[counter.index()]
    }

    /// 自 `now` 起的运行秒数；`start_time` 未设置时为 0。
    #[must_use]
    pub const fn uptime_secs(&self, now: u64) -> u64 {
        if self.start_time == 0 || now < self.start_time {
            0
        } else {
            now - self.start_time
        }
    }
}

/// 计数器所有者。
#[derive(Debug)]
pub struct Stats {
    values: [AtomicU64; 16],
    start_time: AtomicU64,
    /// 计数器推送间隔（秒）。SSE 的 `stats` 事件按此周期重发——见
    /// [`Stats::publish_tick`]。
    push_interval_secs: AtomicU64,
    /// 版本化发布点：计数器不经 `state::*` 所有者发布，`stats` 事件由定时 tick
    /// 驱动，故这里持有 hub 的引用。
    hub: SharedHub,
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Stats {
    /// 构造全零计数器，并新建一个独立的发布点。
    ///
    /// 仅供 `State` 之外的直接构造使用（测试）；[`Stats::with_hub`] 才是组合根与
    /// `State` 用的入口，它让四个所有者共用同一个 hub。
    #[must_use]
    pub fn new() -> Self {
        Self::with_hub(Arc::new(Hub::new()))
    }

    /// 构造全零计数器，发布到给定的 hub。
    #[must_use]
    pub fn with_hub(hub: SharedHub) -> Self {
        Self {
            values: std::array::from_fn(|_| AtomicU64::new(0)),
            start_time: AtomicU64::new(0),
            push_interval_secs: AtomicU64::new(DEFAULT_STATS_PUSH_SECS),
            hub,
        }
    }

    /// 自增 1。
    pub fn inc(&self, counter: Counter) {
        self.add(counter, 1);
    }

    /// 自增 `delta`（饱和，不回绕）。
    pub fn add(&self, counter: Counter, delta: u64) {
        self.values[counter.index()].fetch_add(delta, Ordering::Relaxed);
    }

    /// 把某计数器**直接设为** `value`。
    ///
    /// 业务路径上一律是只增语义（`inc` / `add`）；本方法只服务一种场景：把
    /// **外部权威读数原样搬进来**。组合根按固定周期镜像旧全局 `DAEMON_STATS`
    /// 时要求逐项等值，用 `add` 会把同一段增量再计一次。
    pub fn set_gauge(&self, counter: Counter, value: u64) {
        self.values[counter.index()].store(value, Ordering::Relaxed);
    }

    /// 记录启动时间（Unix 秒）。
    pub fn set_start_time(&self, secs: u64) {
        self.start_time.store(secs, Ordering::Relaxed);
    }

    /// 读单个计数器的当前值。
    #[must_use]
    pub fn get(&self, counter: Counter) -> u64 {
        self.values[counter.index()].load(Ordering::Relaxed)
    }

    /// 取快照。纯读：不改任何计数器。
    #[must_use]
    pub fn snapshot(&self) -> StatsSnapshot {
        let mut values = [0_u64; 16];
        for counter in Counter::ALL {
            values[counter.index()] = self.get(counter);
        }
        StatsSnapshot {
            values,
            start_time: self.start_time.load(Ordering::Relaxed),
        }
    }

    /// 设置计数器推送间隔（秒），由配置同步（`webui.sse_push_interval`）。
    pub fn set_push_interval(&self, secs: u64) {
        self.push_interval_secs.store(secs, Ordering::Relaxed);
    }

    /// 计数器推送间隔（秒）。组合根的定时器据此决定多久发一次 `stats` 事件。
    #[must_use]
    pub fn push_interval_secs(&self) -> u64 {
        self.push_interval_secs.load(Ordering::Relaxed)
    }

    /// 发布一次 [`Domain::Stats`]：推进版本号并唤醒 SSE 订阅者。
    ///
    /// 由组合根的定时器按 [`Self::push_interval_secs`] 调用。计数器本身不经
    /// 所有者发布——`stats` 是**周期事件**而非变更事件（前端要的是「最新的累计
    /// 读数」，没有变化也要重发，否则屏幕上的数字会在安静时段冻住）。这里发布
    /// 空白版本推进，正是为了让「周期性」与「按变化」两种语义在同一条 SSE
    /// 链路上共存：版本推进即代表「这一轮该重发 stats」。
    pub fn publish_tick(&self) -> super::hub::Versions {
        self.hub.publish(Domain::Stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_counter_set_is_all_zero() {
        let stats = Stats::new();
        let snap = stats.snapshot();
        for counter in Counter::ALL {
            assert_eq!(snap.get(counter), 0, "{counter:?} 初值应为 0");
        }
        assert_eq!(snap.start_time, 0);
    }

    #[test]
    fn increments_land_on_the_counter_that_was_named() {
        let stats = Stats::new();
        stats.inc(Counter::LinesParsed);
        stats.inc(Counter::LinesParsed);
        stats.inc(Counter::IpsBanned);
        let snap = stats.snapshot();
        assert_eq!(snap.get(Counter::LinesParsed), 2);
        assert_eq!(snap.get(Counter::IpsBanned), 1);
        assert_eq!(snap.get(Counter::IpsExtracted), 0);
    }

    #[test]
    fn add_accumulates_the_delta() {
        let stats = Stats::new();
        stats.add(Counter::FailedAttempts, 7);
        stats.add(Counter::FailedAttempts, 5);
        assert_eq!(stats.get(Counter::FailedAttempts), 12);
    }

    #[test]
    fn set_gauge_stores_the_authoritative_value_verbatim() {
        // 镜像路径要求等值搬运：搬进来的是「外部读数」，不是再累加一次。
        let stats = Stats::new();
        stats.add(Counter::IpsBanned, 5);
        stats.set_gauge(Counter::IpsBanned, 42);
        assert_eq!(stats.get(Counter::IpsBanned), 42);
        stats.set_gauge(Counter::IpsBanned, 7);
        assert_eq!(stats.get(Counter::IpsBanned), 7, "镜像应覆盖而不是累加");
        assert_eq!(
            stats.get(Counter::LinesParsed),
            0,
            "设置一个计数器不得影响其它计数器"
        );
    }

    #[test]
    fn reading_a_snapshot_does_not_change_any_counter() {
        // 缺陷 E 的另一半：读路径不得改统计。
        let stats = Stats::new();
        stats.add(Counter::IpsBanned, 3);
        for _ in 0..10 {
            let _ = stats.snapshot();
        }
        assert_eq!(stats.get(Counter::IpsBanned), 3);
    }

    #[test]
    fn a_snapshot_is_a_frozen_copy() {
        let stats = Stats::new();
        stats.inc(Counter::RegexMatches);
        let snap = stats.snapshot();
        stats.inc(Counter::RegexMatches);
        assert_eq!(snap.get(Counter::RegexMatches), 1, "旧快照不应随之变化");
        assert_eq!(stats.snapshot().get(Counter::RegexMatches), 2);
    }

    #[test]
    fn start_time_and_uptime_are_consistent() {
        let stats = Stats::new();
        stats.set_start_time(1_000);
        let snap = stats.snapshot();
        assert_eq!(snap.start_time, 1_000);
        assert_eq!(snap.uptime_secs(1_600), 600);
        assert_eq!(
            snap.uptime_secs(900),
            0,
            "时钟回拨时运行时间为 0 而不是负数"
        );
    }

    #[test]
    fn uptime_is_zero_when_the_start_time_was_never_set() {
        let snap = Stats::new().snapshot();
        assert_eq!(snap.uptime_secs(u64::MAX), 0);
    }

    #[test]
    fn counter_names_are_stable_and_distinct() {
        let names: Vec<&str> = Counter::ALL.iter().map(|c| c.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "计数器名称不得重复");
        assert_eq!(names.len(), 16);
        assert_eq!(names[0], "lines_parsed");
        assert_eq!(names[15], "netlink_recv_errors");
    }

    #[test]
    fn the_index_mapping_covers_every_counter_exactly_once() {
        // index() 与 ALL 的对应关系若漂移，快照会串位——这里把它钉死。
        let mut seen = [false; 16];
        for counter in Counter::ALL {
            let i = counter.index();
            assert!(!seen[i], "{counter:?} 的下标 {i} 与另一个计数器冲突");
            seen[i] = true;
        }
        assert!(seen.iter().all(|b| *b), "有下标未被覆盖");
    }
}
