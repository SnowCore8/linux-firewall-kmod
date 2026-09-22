//! 组合根的桥接：把旧全局状态**镜像**进 [`State`]，并在个别路径上把新状态**写回**旧全局。
//!
//! # 这是过渡物，不是新架构的一部分
//!
//! 用户裁定「保留编译，分批迁入」：主链路（netlink 事件 / 速率 / 白名单 / 对账）
//! 先迁入新 `state`，其余读者（SPA 分析端点、Prometheus 导出器）仍读旧全局。
//! 迁入期两侧并存，故需要一座桥——就是本模块。
//!
//! 桥只有两个方向，且方向不对称：
//!
//! - **旧 → 新（镜像）**：netlink 已是主链路的写入权威，它的读数在写入点顺手搬进
//!   `State`，因此新 SSE 与 REST 立刻就有真数据。此方向覆盖封禁/白名单/速率/计数器。
//! - **新 → 旧（回写）**：只有一处——封禁对账。对账要**删除**内核已没有的条目，
//!   而旧 `ActiveBanCache::reconcile_with_kernel` 只做「删旧 + 补新」，新
//!   [`State`] 才是这次对账的权威结果，故把权威结果回写旧缓存。少了这一步，旧
//!   SPA 的封禁列表会与内核长期不一致。
//! - **外部 → 新（配置）**：`sse_push_interval` 属配置 owner，SSE 的 `stats` 事件
//!   周期由它决定，故由配置同步路径直接 `set_push_interval`。
//!
//! 各类镜像的时机见 [`mirror_stats_tick`] 的文档：计数器走固定周期（组合根的
//! scheduler），封禁/白名单/速率走各自的写入点。等旧读者全部迁走后，本模块连同
//! 这些调用点一起删除——届时新状态由主链路直接写入，不再「镜像」任何东西。

use std::net::IpAddr;
use std::sync::Arc;

use crate::types::{BanInfo, RateEntry, WhitelistEntry, DAEMON_STATS};

use super::stats::Counter;
use super::State;

/// 组合根装配好的状态聚合。由 [`set_global_state`] 在启动时注入一次。
///
/// 与旧全局（`ACTIVE_BAN_CACHE` / `WHITELIST_CACHE` / `RATE_CACHE` / `DAEMON_STATS`）
/// 的名字区分开：带 `STATE` 的是**新**所有者，读它拿到的是快照与版本。
static GLOBAL_STATE: std::sync::OnceLock<Arc<State>> = std::sync::OnceLock::new();

/// 注入组合根构造的 [`State`]（仅在启动时调用一次）。
///
/// # Errors
///
/// 重复调用返回错误——与 `set_global_netlink_ctx` 同一约定，让「谁先装配」这类
/// 顺序错误在启动期就暴露，而不是静默覆盖。
pub fn set_global_state(state: Arc<State>) -> anyhow::Result<()> {
    GLOBAL_STATE
        .set(state)
        .map_err(|_| anyhow::anyhow!("Global State already set"))
}

/// 取全局状态聚合；组合根尚未装配时返回 `None`。
///
/// 所有镜像函数都容忍 `None`：单元测试（不经 `main` 装配）里这些调用是空操作，
/// 不需要每处都先判 `Option`。
#[must_use]
pub fn global_state() -> Option<Arc<State>> {
    GLOBAL_STATE.get().cloned()
}

/// 让 SSE 推送间隔跟随配置（启动期与每次配置重载调用）。
///
/// `0` 在配置校验里已被拒绝，但此处的 `max(1)` 是不依赖校验的兜底：间隔为 0 会让
/// 定时器变成忙轮询。
pub fn set_push_interval(secs: u32) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.stats().set_push_interval(u64::from(secs.max(1)));
    }
}

/// 记录守护进程启动时间（Unix 秒）到新状态。
///
/// `stats` 的 `uptime_secs` 由它推导；组合根注入状态后立即调用一次。
pub fn set_start_time(secs: u64) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.stats().set_start_time(secs);
    }
}

/// 当前生效的 `stats` 事件推送间隔（秒）。
///
/// 组合根尚未装配时返回 `DEFAULT_STATS_PUSH_SECS`（1）：调度器在启动早期就可能
/// 跑第一轮 tick，此时给它一个合理值即可，不必特判。
#[must_use]
pub fn stats_push_interval_secs() -> u64 {
    GLOBAL_STATE
        .get()
        .map_or(1, |state| state.stats().push_interval_secs())
}

// ============================================================================
// 旧 → 新：镜像
// ============================================================================

/// 把旧 [`BanInfo`] 翻译成新 [`BanEntry`]；IP 文本无法解析时返回 `None`。
///
/// `None` 而不是回退到 `0.0.0.0`：新状态的键是 [`IpAddr`]，塞一个假的键进去会
/// 污染封禁列表，且与「地址必须可解析」这一不变量相悖。解析失败说明内核/旧路径
/// 给了坏数据，丢掉这一条比污染整表好。
fn to_ban_entry(info: &BanInfo) -> Option<super::BanEntry> {
    let ip: IpAddr = info.ip.parse().ok()?;
    Some(super::BanEntry::new(
        ip,
        info.jail_name.clone(),
        info.reason.clone(),
        info.banned_at,
        info.expires_at,
        info.is_permanent,
        info.ban_count,
        info.fail_count,
    ))
}

/// 镜像一次「封禁写入」：把该条目写进新状态。
///
/// 在 netlink 事件路径的 `cache.insert` / `cache.try_insert` 旁调用。新
/// [`super::bans::Bans::insert`] 自带「内容相同即无变化」，重复广播不会推进版本。
pub fn mirror_ban_insert(info: &BanInfo) {
    if let Some(state) = GLOBAL_STATE.get() {
        if let Some(entry) = to_ban_entry(info) {
            state.bans().insert(entry);
        }
    }
}

/// 镜像一次「解封」：从新状态移除该 IP。
pub fn mirror_ban_remove(ip: &str) {
    if let Some(state) = GLOBAL_STATE.get() {
        if let Ok(addr) = ip.parse::<IpAddr>() {
            state.bans().remove(&addr);
        }
    }
}

/// 把旧缓存的**权威对账结果**镜像进新状态，并把新状态回写旧缓存。
///
/// 回写这一步是必须的：旧 `reconcile_with_kernel` 只删「缓存有、内核无」，不处理
/// 事件路径新插入、内核尚不知晓的条目；新状态在这次对账后才是权威，把它的快照
/// 回写旧缓存，旧 SPA 列表才与内核一致。
pub fn mirror_bans_reconcile() {
    let Some(state) = GLOBAL_STATE.get() else {
        return;
    };
    let Some(cache) = crate::types::ACTIVE_BAN_CACHE.get() else {
        return;
    };

    // 旧缓存（权威对账结果）→ 新状态
    let entries: Vec<super::BanEntry> = cache
        .snapshot()
        .iter()
        .filter_map(|info| to_ban_entry(info))
        .collect();
    state.bans().replace_all(entries);

    // 新状态（权威结果）→ 旧缓存，保持旧读者与内核一致
    let snapshot = state.bans().snapshot();
    let round_trip: Vec<BanInfo> = snapshot
        .entries()
        .iter()
        .map(|e| BanInfo {
            ip: e.ip.to_string(),
            ip_num: 0,
            jail_name: e.jail.clone(),
            reason: e.reason.clone(),
            banned_at: e.banned_at,
            expires_at: e.expires_at,
            is_permanent: e.is_permanent,
            fail_count: e.fail_count,
            ban_count: e.ban_count,
        })
        .collect();
    let ips: std::collections::HashSet<String> = round_trip.iter().map(|i| i.ip.clone()).collect();
    cache.reconcile_with_kernel(&ips, round_trip);
}

/// 镜像一次白名单「全量覆盖」（内核 LIST 响应，条目已规范化）。
pub fn mirror_whitelist_replace_all(
    entries: impl IntoIterator<Item = (super::cidr::CidrKey, String)>,
) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.whitelist().replace_all(entries);
    }
}

/// 镜像一次白名单「单条新增」（状态变更事件 / daemon 自己添加）。
pub fn mirror_whitelist_insert(cidr: super::cidr::CidrKey, device: impl Into<String>) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.whitelist().insert(cidr, device);
    }
}

/// 镜像一次白名单「单条移除」。
pub fn mirror_whitelist_remove(cidr: &super::cidr::CidrKey) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.whitelist().remove(cidr);
    }
}

/// 镜像一轮速率样本（内核 `ListRatesResponse`，覆盖式）。
pub fn mirror_rates(sample: super::RateSample) {
    if let Some(state) = GLOBAL_STATE.get() {
        state.rates().apply(sample);
    }
}

/// 从旧 [`RateEntry`] 列表构造一轮新速率样本，并镜像进新状态。
///
/// IP 无法解析的条目跳过——同 [`to_ban_entry`]，不污染新状态的键空间。
pub fn mirror_rates_from_cache(entries: &[RateEntry], global_pps: u64, global_bps: u64) {
    let mut sample = super::RateSample {
        global_pps,
        global_bps,
        per_ip: std::collections::BTreeMap::new(),
    };
    for e in entries {
        let Ok(ip) = e.ip.parse::<IpAddr>() else {
            continue;
        };
        sample.per_ip.insert(
            ip,
            super::RateCounters {
                packets: e.packets_per_sec,
                bytes: e.bytes_per_sec,
                syn: e.syn_packets_per_sec,
                udp: e.udp_packets_per_sec,
                icmp: e.icmp_packets_per_sec,
                ack: e.ack_packets_per_sec,
                rst: e.rst_packets_per_sec,
                fin: e.fin_packets_per_sec,
            },
        );
    }
    mirror_rates(sample);
}

/// 从旧 [`WhitelistEntry`] 映射构造新状态的 `(CidrKey, device)` 迭代器。
///
/// 旧缓存的键是 `String`（三处写入路径规则不一，缺陷 M 的根因）；新状态要求
/// [`super::cidr::CidrKey`]。此函数是**读**方向的规范化：解析失败的键跳过，
/// 不进新状态。
#[must_use]
pub fn whitelist_pairs(
    entries: &std::collections::HashMap<String, WhitelistEntry>,
) -> Vec<(super::cidr::CidrKey, String)> {
    entries
        .values()
        .filter_map(|e| {
            super::cidr::CidrKey::parse(&e.cidr)
                .ok()
                .map(|key| (key, e.device.clone()))
        })
        .collect()
}

// ============================================================================
// 新 → 读侧：显式发布
// ============================================================================

/// 显式推进 `bans` 版本（不搬数据）。
///
/// netlink 事件路径改了旧 `ACTIVE_BAN_CACHE` 的**元数据**（`ban_count` / 渐进时长等），
/// 而新状态的封禁所有者只按 `BanEntry` 内容比对决定是否推进版本——元数据变化对它
/// 不可见。故这些写入点直接推进版本，让读侧重取快照。
///
/// 与 [`mirror_ban_insert`] / [`mirror_ban_remove`] 的关系：那两者搬**内容**并按内容
/// 决定是否变更；本函数只表达「读数已变，重发一次」。多推一次的代价只是前端多一帧
/// 相同载荷。
pub fn publish_bans_changed() {
    if let Some(state) = GLOBAL_STATE.get() {
        state.hub().publish(super::hub::Domain::Bans);
    }
}

/// 显式推进 `stats` 版本（不搬数据）。
///
/// 计数器的常规镜像走 [`mirror_stats_tick`] 的固定周期；但在封禁/解封、白名单增删
/// 这类**用户可见的状态突变**上，等一个周期才更新计数会让界面滞后。故这些写入点
/// 直接推进版本——发布是「有变化」的信号，与「计数器的值是谁搬的」无关。
pub fn publish_stats_changed() {
    if let Some(state) = GLOBAL_STATE.get() {
        state.hub().publish(super::hub::Domain::Stats);
    }
}

/// 显式推进 `jails` 版本（不搬数据）。
///
/// `jails` 是**派生域**：没有 `state/jails.rs` 所有者，载荷在渲染时现读
/// `http_exporter::GLOBAL_JAILS` 与封禁表的 `ban_count`。因此它没有「内容比对」
/// 可用——必须由知道「派生输入变了」的写入点显式推进。三个来源：
///
/// 1. 封禁集合变更 —— [`super::bans::Bans::invalidate_and_publish`]（`ban_count` 变）；
/// 2. jail 启用/禁用 —— `web_ui::api::update_jail_enabled`（`enabled` 变）；
/// 3. 峰值时段翻转 —— `runtime::scheduler`（`is_peak_hours` / `effective_max_retries` 变）。
///
/// 本函数是 2、3 的公共入口（1 与 `bans` 版本同点发布，故写在那里，避免一次封禁
/// 变更拆成两次跨模块调用）。
pub fn publish_jails_changed() {
    if let Some(state) = GLOBAL_STATE.get() {
        state.hub().publish(super::hub::Domain::Jails);
    }
}

// ============================================================================
// 过期封禁清理（固定周期）
// ============================================================================

/// 清掉两侧已过期的封禁，并按旧口径补齐解封记账。
///
/// **只应由组合根的 scheduler 周期调用**——这是结构问题 E 的修法：旧实现把限流
/// `purge_expired` 挂在 `web_ui/ban_ops.rs::get_active_bans()` 的**读**路径上，SSE
/// 每秒读一次就顺手写一次状态（清表 + 改计数器）。迁移后读路径零副作用，清理改由
/// 调度器按固定周期驱动。
///
/// 两侧都要清：
///
/// - 旧 `ACTIVE_BAN_CACHE` 仍被 Prometheus 的 `active_bans` gauge、`/health` 的计数
///   与 `web_ui/stats.rs` 读。读了旧全局的清理入口后若不再清它，过期条目会永久滞留在
///   那张表里，活跃封禁数只增不减。
/// - 新 [`super::bans::Bans`] 是 SSE 与 REST 的数据源；内核侧封禁过期**本就会**发
///   `FW_BAN_ACTION_UNBAN` 自愈，但事件可能丢，故这里仍按显式周期清理。
///
/// 记账（`total_unbans` / 封禁时长直方图）与旧实现**逐字一致**，属搬家而非新增。
/// 与解封事件路径的记账重叠是既有现象（该路径的 `total_unbans` 累加是无条件的），
/// 不由本次改动引入：谁先把条目从表里删掉，另一条路就删不到、也就不再记一次时长。
pub fn purge_expired_bans(now: i64) {
    if let Some(cache) = crate::types::ACTIVE_BAN_CACHE.get() {
        for ban in cache.purge_expired(now) {
            crate::types::DAEMON_STATS
                .total_unbans
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let duration = if ban.expires_at > 0 {
                ban.expires_at - ban.banned_at
            } else {
                now - ban.banned_at
            };
            crate::types::record_ban_duration(duration);
        }
    }

    if let Some(state) = GLOBAL_STATE.get() {
        state.bans().purge_expired(now);
    }
}

// ============================================================================
// 计数器镜像（固定周期）
// ============================================================================

/// 计数器镜像：把旧全局读数**等值**搬进新状态。
///
/// # 为什么在固定周期而不是每个写入点
///
/// 这 9 枚计数器（`LinesParsed`/`IpsExtracted`/`RegexMatches`/`FailedAttempts`/
/// `IpsBanned`/`TotalUnbans`/`PacketsDropped`/`PacketsAccepted`/
/// `NetlinkMessagesReceived`）的旧写入点分散在行处理热路径、正则匹配热路径与
/// 内核接收执行体上。逐个改写入点会把热路径与「过渡期镜像」耦合起来，且每行
/// 日志、每个数据包都要多付一次原子写。周期镜像把这些写入点全部保持原样：
///
/// - 代价固定为「每周期 9 次原子 load + 9 次原子 store」，与流量无关；
/// - 周期对齐 SSE 推送间隔，因此前端看到的最坏陈旧度就是推送间隔本身——再多
///   次镜像也不会让屏幕更早更新。
///
/// # 判据
///
/// 逐项 `set_gauge` 必须与旧全局**等值**（`mirror_stats_matches_legacy` 钉死
/// 这条）。故这里用直接赋值而不是累加：累加会把同一段增量再计一次。
pub fn mirror_stats_tick() {
    let Some(state) = GLOBAL_STATE.get() else {
        return;
    };
    let stats = state.stats();
    for counter in Counter::ALL {
        stats.set_gauge(counter, legacy_counter_value(counter));
    }
    stats.publish_tick();
}

/// 读旧全局 `DAEMON_STATS` 里与 `counter` 对应的当前值。
///
/// 两张表都按 [`Counter::ALL`] 的固定顺序排列，故按位置一一对应。这个「位置对应」
/// 由 `mirror_stats_matches_legacy` 测试逐项比对钉死——任一侧增删计数器而忘记
/// 同步，测试立刻变红。
fn legacy_counter_value(counter: Counter) -> u64 {
    use std::sync::atomic::Ordering;
    let fields: [&std::sync::atomic::AtomicU64; 16] = [
        &DAEMON_STATS.lines_parsed,
        &DAEMON_STATS.ips_extracted,
        &DAEMON_STATS.ips_banned,
        &DAEMON_STATS.failed_attempts,
        &DAEMON_STATS.config_reloads,
        &DAEMON_STATS.inotify_events,
        &DAEMON_STATS.log_rotations,
        &DAEMON_STATS.lines_skipped,
        &DAEMON_STATS.regex_matches,
        &DAEMON_STATS.total_unbans,
        &DAEMON_STATS.packets_dropped,
        &DAEMON_STATS.packets_accepted,
        &DAEMON_STATS.netlink_messages_sent,
        &DAEMON_STATS.netlink_messages_received,
        &DAEMON_STATS.netlink_send_errors,
        &DAEMON_STATS.netlink_recv_errors,
    ];
    fields[counter_index(counter)].load(Ordering::Relaxed)
}

/// [`Counter`] 在 `Counter::ALL` 中的下标（与 `state::stats::Counter::index` 同序）。
const fn counter_index(counter: Counter) -> usize {
    match counter {
        Counter::LinesParsed => 0,
        Counter::IpsExtracted => 1,
        Counter::IpsBanned => 2,
        Counter::FailedAttempts => 3,
        Counter::ConfigReloads => 4,
        Counter::InotifyEvents => 5,
        Counter::LogRotations => 6,
        Counter::LinesSkipped => 7,
        Counter::RegexMatches => 8,
        Counter::TotalUnbans => 9,
        Counter::PacketsDropped => 10,
        Counter::PacketsAccepted => 11,
        Counter::NetlinkMessagesSent => 12,
        Counter::NetlinkMessagesReceived => 13,
        Counter::NetlinkSendErrors => 14,
        Counter::NetlinkRecvErrors => 15,
    }
}

/// 统计域的名称（SSE 事件名与诊断用）。
#[cfg(test)]
const STATS_DOMAIN: super::hub::Domain = super::hub::Domain::Stats;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::hub::{Domain, Hub};

    /// 镜像测试共用一个进程级 `GLOBAL_STATE`（`OnceLock` 只能设置一次），故只写
    /// 一个装着全部镜像断言的测试函数：多个 `#[test]` 并发设置会互相干扰。
    #[test]
    fn mirroring_translates_legacy_shapes_into_the_new_state() {
        let hub: crate::state::SharedHub = Arc::new(Hub::new());
        let state = State::with_hub(Arc::clone(&hub));
        // 若已被别的测试设置过（同进程只允许一次），退化为只校验翻译函数本身。
        let _ = set_global_state(Arc::clone(&state));

        // 封禁：BanInfo → BanEntry，含永久与定时两种。
        let info = BanInfo {
            ip: "10.0.0.1".to_string(),
            ip_num: 0,
            jail_name: "sshd".to_string(),
            reason: "暴力破解".to_string(),
            banned_at: 100,
            expires_at: 200,
            is_permanent: false,
            fail_count: 7,
            ban_count: 2,
        };
        mirror_ban_insert(&info);
        let snapshot = state.bans().snapshot();
        assert_eq!(snapshot.len(), 1);
        let entry = snapshot
            .get(&"10.0.0.1".parse().unwrap())
            .expect("应能查到");
        assert_eq!(entry.jail, "sshd");
        assert_eq!(entry.fail_count, 7);
        assert_eq!(entry.ban_count, 2);

        // 不可解析的 IP 不得污染新状态。
        let bad = BanInfo {
            ip: "not-an-ip".to_string(),
            ..info.clone()
        };
        mirror_ban_insert(&bad);
        assert_eq!(state.bans().snapshot().len(), 1, "坏 IP 应被跳过");

        mirror_ban_remove("10.0.0.1");
        assert!(state.bans().snapshot().is_empty());

        // 白名单：旧 String 键 → 新 CidrKey（经规范化）。
        let mut legacy = std::collections::HashMap::new();
        legacy.insert(
            "192.168.0.0/24".to_string(),
            WhitelistEntry {
                cidr: "192.168.0.0/24".to_string(),
                device: "eth0".to_string(),
            },
        );
        // 未归一化的写法（内核可能回传）也必须落到同一个键上。
        legacy.insert(
            "10.0.0.7/32".to_string(),
            WhitelistEntry {
                cidr: "10.0.0.7/32".to_string(),
                device: String::new(),
            },
        );
        let pairs = whitelist_pairs(&legacy);
        assert_eq!(pairs.len(), 2);
        mirror_whitelist_replace_all(pairs);
        let wl = state.whitelist().snapshot();
        assert_eq!(wl.len(), 2);
        assert!(wl.contains(&super::super::cidr::CidrKey::parse("192.168.0.0/24").unwrap()));

        mirror_whitelist_insert(
            super::super::cidr::CidrKey::parse("172.16.0.0/12").unwrap(),
            "eth1",
        );
        assert_eq!(state.whitelist().snapshot().len(), 3);
        mirror_whitelist_remove(&super::super::cidr::CidrKey::parse("172.16.0.0/12").unwrap());
        assert_eq!(state.whitelist().snapshot().len(), 2);

        // 速率：RateEntry → RateCounters，逐字段搬运。
        let rates = vec![RateEntry {
            ip: "203.0.113.5".to_string(),
            packets_per_sec: 120,
            bytes_per_sec: 1_200,
            syn_packets_per_sec: 5,
            udp_packets_per_sec: 0,
            icmp_packets_per_sec: 1,
            ack_packets_per_sec: 100,
            rst_packets_per_sec: 2,
            fin_packets_per_sec: 3,
        }];
        mirror_rates_from_cache(&rates, 200, 2_000);
        let rate_snapshot = state.rates().snapshot();
        assert_eq!(rate_snapshot.sample.global_pps, 200);
        assert_eq!(rate_snapshot.sample.global_bps, 2_000);
        let counters = rate_snapshot
            .sample
            .get(&"203.0.113.5".parse().unwrap())
            .expect("应能查到");
        assert_eq!(counters.packets, 120);
        assert_eq!(counters.syn, 5);
        assert_eq!(counters.fin, 3);

        // 发布版本：封禁/白名单/速率都动过。
        assert!(hub.versions().get(Domain::Bans) >= 2);
        assert!(hub.versions().get(Domain::Whitelist) >= 3);
        assert!(hub.versions().get(Domain::Rates) >= 1);
    }

    #[test]
    fn mirror_stats_matches_legacy() {
        use std::sync::atomic::Ordering;

        let state = State::new();

        // 给旧全局写入一组互不相同的值，逐项不同才能暴露「位置错位」。
        let legacy_values: [u64; 16] = [
            11, 22, 33, 44, 55, 66, 77, 88, 99, 1010, 1111, 1212, 1313, 1414, 1515, 1616,
        ];
        let fields: [&std::sync::atomic::AtomicU64; 16] = [
            &DAEMON_STATS.lines_parsed,
            &DAEMON_STATS.ips_extracted,
            &DAEMON_STATS.ips_banned,
            &DAEMON_STATS.failed_attempts,
            &DAEMON_STATS.config_reloads,
            &DAEMON_STATS.inotify_events,
            &DAEMON_STATS.log_rotations,
            &DAEMON_STATS.lines_skipped,
            &DAEMON_STATS.regex_matches,
            &DAEMON_STATS.total_unbans,
            &DAEMON_STATS.packets_dropped,
            &DAEMON_STATS.packets_accepted,
            &DAEMON_STATS.netlink_messages_sent,
            &DAEMON_STATS.netlink_messages_received,
            &DAEMON_STATS.netlink_send_errors,
            &DAEMON_STATS.netlink_recv_errors,
        ];
        for (field, value) in fields.iter().zip(legacy_values) {
            field.store(value, Ordering::Relaxed);
        }

        // 直接比对映射函数：新状态里的每一项必须等于旧全局对应项。
        for (i, counter) in Counter::ALL.iter().enumerate() {
            assert_eq!(
                legacy_counter_value(*counter),
                legacy_values[i],
                "{counter:?} 的旧全局映射错位"
            );
        }
        // 且 counter_index 与 Counter::ALL 顺序一致。
        for (i, counter) in Counter::ALL.iter().enumerate() {
            assert_eq!(counter_index(*counter), i);
        }

        // 等值搬运的语义：set_gauge 后新状态读数与旧全局逐项相等。
        let stats = state.stats();
        for counter in Counter::ALL {
            stats.set_gauge(counter, legacy_counter_value(counter));
        }
        let snapshot = stats.snapshot();
        for (i, counter) in Counter::ALL.iter().enumerate() {
            assert_eq!(snapshot.get(*counter), legacy_values[i]);
        }

        // 再跑一次镜像：值未变，读数仍相等（幂等，不累加）。
        for counter in Counter::ALL {
            stats.set_gauge(counter, legacy_counter_value(counter));
        }
        assert_eq!(stats.get(Counter::LinesParsed), 11);
    }

    #[test]
    fn the_stats_tick_publishes_the_stats_domain() {
        // 计数器不经所有者发布；publish_tick 是 stats 事件的唯一来源。
        let state = State::new();
        let before = state.hub().versions().get(STATS_DOMAIN);
        state.stats().publish_tick();
        assert_eq!(state.hub().versions().get(STATS_DOMAIN), before + 1);
    }
}
