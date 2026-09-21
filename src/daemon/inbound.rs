//! 内核事件入站消费层：把 [`crate::kernel::codec::Incoming`] 映射到旧全局缓存与新状态镜像。
//!
//! # 本模块的定位
//!
//! [`crate::kernel`] 只做「字节 ↔ 语义类型」与请求/响应配对，是纯传输层；把解码后的
//! 事件搬进 `ACTIVE_BAN_CACHE` / `WHITELIST_CACHE` / `RATE_CACHE` / `ANALYSIS_CACHE`
//! 并镜像进 `state::compose`，属于业务动作，故独立于 `kernel/` 之外。
//!
//! 本模块取代旧 `crate::netlink::handlers` 的 13 个 `handle_*`。逐项对应关系：
//!
//! | 旧 `handle_*` | 本模块落点 |
//! |---------------|------------|
//! | `handle_ddos_event` | [`Consumer::process`] 的 `DdosEvent` 分支 |
//! | `handle_ban_state_change` | `BanStateChange` 分支 |
//! | `handle_cmd_result` | `CmdResult` 分支 |
//! | `handle_stats_response` | `StatsResponse` 分支 |
//! | `handle_whitelist_state_change` | `WhitelistStateChange` 分支 |
//! | `handle_config_ack` | `ConfigAck` 分支 |
//! | `handle_config_change` | `ConfigChange` 分支 |
//! | `handle_analysis_response` | `AnalysisResponse` 分支 |
//! | `handle_list_bans_response` | [`reconcile_bans`]（周期任务调用） |
//! | `handle_list_whitelist_response` | [`apply_whitelist_all`] |
//! | `handle_list_rates_response` | [`apply_rates`] |
//!
//! # 三张表的 LIST 回复为什么不在事件路径上
//!
//! 旧实现的封禁列表分页是**手工**的：`handle_list_bans_response` 自己维护
//! `PendingListBans`，凑满后再从全局 netlink 上下文补发下一页查询。新层的分页由
//! [`crate::kernel::client::Client::list_bans_all`] 内的 `drain` 负责：分页回复回显
//! `seq`，被 `PendingTable` 认领并直接投给等待的调用方，**不进入事件队列**。因此
//! 事件路径只需处理 12 种变体，封禁/白名单/速率三张表的「全量快照」由周期任务拉取后
//! 喂给 [`reconcile_bans`] / [`apply_whitelist_all`] / [`apply_rates`]。
//!
//! # 与旧实现的两处有意收紧（已获用户裁定）
//!
//! 1. **地址族未定义即跳过**：契约把「地址族未定义」暴露为 `None`（旧层拿到的是原始
//!    整数）。旧实现把它折成一个字面量 `"unknown"` 键写进 `WHITELIST_CACHE` /
//!    `RATE_CACHE`，那是一个永远匹配不上内核的幽灵条目；本模块跳过并计数告警。
//! 2. **白名单键经 [`CidrKey`] 规范化**：旧实现有三套互不相同的 CIDR 键规则（缺陷 M），
//!    本模块统一走 [`CidrKey::new`]，「网络地址 + 恒带 `/prefix`」是唯一形态。

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::contract;
use crate::kernel::codec::{self, Incoming};
use crate::netlink::DdosDecisionEngine;
use crate::runtime::{Receiver, RecvTimeoutError, Shutdown};
use crate::state::compose;
use crate::state::CidrKey;
use crate::types::{
    now_secs, ActiveBanCache, AnalysisData, AnalysisIcmpTypeEntry, AnalysisScannerEntry,
    AnalysisUdpPortEntry, BanHistory, BanInfo, RateEntry, WhitelistEntry, ACTIVE_BAN_CACHE,
    ANALYSIS_CACHE, BAN_HISTORY, DAEMON_STATS, RATE_CACHE, WHITELIST_CACHE,
};

/// 事件队列的等待切片。
///
/// 消费循环用它轮询关停令牌：`Receiver` 本身没有「同时等消息与等关停」的原语，故
/// 以固定超时轮询。取值与旧接收线程的 `poll(100ms)` 同量级，关停延迟不因此变差。
const RECV_TICK: Duration = Duration::from_millis(200);

/// 因地址族未定义而跳过的条目数（白名单 / 速率两条路径合计）。
///
/// 旧实现把这类条目折成 `"unknown"` 键静默写进缓存；本层改为跳过 + 计数，使
/// 「内核送来了认不出的地址族」成为可观察的事实。只增不减，供诊断与门禁读取。
static DROPPED_UNKNOWN_FAMILY: AtomicU64 = AtomicU64::new(0);

/// 入站事件消费体。
///
/// 无状态（决策引擎是 2.H-2 才接线的运行期依赖），故 `process` 取 `&self`，调用方
/// 无需为每条事件加锁。真正的独占点在 [`Consumer::run`]：它独占 `Receiver`。
#[derive(Default)]
pub struct Consumer {
    /// DDoS 决策引擎；`None` 表示尚未接线（2.H-2 之前），此时只记 debug 日志。
    ///
    /// `parking_lot::Mutex` 而非 `OnceLock`：接线发生在组合根启动期，晚于 `Consumer`
    /// 构造（与旧 `http_exporter::set_global_decision_engine` 的时序一致）。
    engine: parking_lot::Mutex<Option<std::sync::Arc<DdosDecisionEngine>>>,
}

impl Consumer {
    /// 新建消费体（决策引擎未接线）。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 接线 DDoS 决策引擎。
    ///
    /// 2.H-2 由组合根在构造之后调用；重复调用以最后一次为准（与 `parking_lot::RwLock`
    /// 的 `update_config` 同语义，不做「只允许一次」的限制）。
    pub fn set_decision_engine(&self, engine: std::sync::Arc<DdosDecisionEngine>) {
        *self.engine.lock() = Some(engine);
    }

    /// 消费一条内核事件，返回它是否改动了对外可见的状态。
    ///
    /// 这里是旧 8 个 `handle_*` 的合并落点：封禁/解封、命令失败、统计、白名单增删、
    /// 配置确认/广播、分析数据、DDoS 事件各自的语义与副作用逐条保留。返回值供诊断与
    /// 单测断言使用——发布动作在各分支内自行完成，不由返回值驱动。
    pub fn process(&self, msg: &Incoming) -> bool {
        match msg {
            Incoming::DdosEvent(e) => {
                self.on_ddos_event(e);
                false
            }
            Incoming::BanStateChange(e) => {
                self.on_ban_state_change(e);
                true
            }
            Incoming::CmdResult(e) => {
                Self::on_cmd_result(e);
                true
            }
            Incoming::StatsResponse(e) => {
                Self::on_stats_response(e);
                false
            }
            Incoming::WhitelistStateChange(e) => {
                Self::on_whitelist_state_change(e);
                true
            }
            Incoming::ConfigAck(e) => {
                Self::on_config_ack(e);
                false
            }
            Incoming::ConfigChange(e) => {
                Self::on_config_change(&e.0);
                false
            }
            Incoming::AnalysisResponse(e) => {
                Self::on_analysis_response(e);
                false
            }
            // 三张表的 LIST 回复走 `Client` 的请求/响应配对，被 `PendingTable` 认领后
            // 直接投给调用方，不经事件队列。若真出现在这里，说明有别的发送方用了
            // 无 seq 的路径——记录一次告警，不静默丢弃。
            Incoming::ListBansResponse(_)
            | Incoming::ListWhitelistResponse(_)
            | Incoming::ListRatesResponse(_) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "事件队列收到分页回复（应由 Client 配对认领）";
                    "type" => msg.msg_type_name()
                );
                false
            }
            // 注册确认由 `kernel::lease` 等待，不落到消费层。同样只在异常出现时告警。
            Incoming::DaemonRegisterAck(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "事件队列收到注册确认（应由租约等待）";
                    "accepted" => e.accepted
                );
                false
            }
        }
    }

    /// 独占事件队列消费循环，直到关停令牌置位或队列断开。
    ///
    /// `Receiver` 不是 `Clone`，故消费循环必须是队列的唯一持有者——这也是「单执行体」
    /// 模型的落点。关停后先把队列里剩余的事件消化完再退出：内核已经发生的事实不该
    /// 因为关机被丢掉。
    pub fn run(self, rx: Receiver<Incoming>, shutdown: Shutdown) {
        while !shutdown.is_shutdown() {
            match rx.recv_timeout(RECV_TICK) {
                Ok(msg) => {
                    self.process(&msg);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        // 关停后清空残留：`try_recv` 在 Empty / Disconnected 上返回 `Err`，循环自然结束。
        while let Ok(msg) = rx.try_recv() {
            self.process(&msg);
        }
    }

    /// 处理 DDoS 违规事件：交给决策引擎记日志与统计（内核已封禁，daemon 不重复封禁）。
    fn on_ddos_event(&self, e: &codec::DdosEvent) {
        crate::logger::debug!(
            crate::logger::get(),
            "收到 DDoS 事件";
            "ip" => e.addr.map(|a| a.to_string()).unwrap_or_else(|| "unknown".to_string()),
            "reason" => &e.reason,
            "rate_pps" => e.rate_pps
        );

        let Some(engine) = self.engine.lock().clone() else {
            return;
        };
        match e.addr {
            Some(ip) => engine.handle_event(ip, &e.reason, e.rate_pps),
            // 旧实现是「解析失败」；新层里原因只有一个——地址族未定义。跳过并告警，
            // 不把认不出的地址塞进引擎的跟踪表。
            None => crate::logger::warn!(
                crate::logger::get(),
                "DDoS 事件地址族未定义，已跳过";
                "reason" => &e.reason
            ),
        }
    }

    /// 处理封禁/解封状态变更，并在结尾同步统计与发布。
    fn on_ban_state_change(&self, e: &codec::BanStateChange) {
        match e.action {
            Some(contract::BanAction::Ban) => Self::on_ban(e),
            Some(contract::BanAction::Unban) => Self::on_unban(e),
            // 动作取值未定义：旧的 `is_ban()` / `is_unban()` 都是 false，即只为尾部
            // 统计服务。这里显式记一行，行为不变。
            None => {
                crate::logger::debug!(crate::logger::get(), "封禁状态变更动作未定义，仅同步统计")
            }
        }

        // 尾部：无论封禁、解封还是动作认不出，都同步统计并发布。
        // 这三项来自内核推送，比周期 StatsQuery 更实时（事件驱动，消除轮询延迟）。
        DAEMON_STATS
            .packets_dropped
            .store(e.packets_dropped, Ordering::Relaxed);
        DAEMON_STATS
            .packets_accepted
            .store(e.packets_accepted, Ordering::Relaxed);
        DAEMON_STATS
            .whitelist_count
            .store(u64::from(e.whitelist_count), Ordering::Relaxed);

        // 封禁/解封后立即发布版本，避免 UI 等待整轮 push interval。计数器的值刚在上面
        // 逐项更新，故 `stats` 一并推进：SSE 只订「变化的域」，不发布就不会发这一帧。
        compose::publish_bans_changed();
        compose::publish_stats_changed();
    }

    /// 封禁分支：区分「daemon 自己发起」「内核/procfs 发起」两条路。
    ///
    /// `e.addr` 为 `None`（地址族未定义）时无 IP 可用，缓存与历史都无键可落，跳过。
    fn on_ban(e: &codec::BanStateChange) {
        let Some(ip) = e.addr else {
            note_dropped_unknown_family("ban_state_change");
            return;
        };
        let ip_str = ip.to_string();

        crate::logger::debug!(
            crate::logger::get(),
            "收到封禁状态变更：封禁";
            "ip" => &ip_str,
            "duration_secs" => e.duration_secs,
            "reason" => &e.reason
        );

        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);

        // 缓存是否已有该 IP 决定两条路：有 → daemon 在发 netlink 前已 insert，此时
        // 只等 ACK 落历史；无 → procfs/内核路径，需在此处补历史并插入缓存。
        if cache.contains(&ip_str) {
            if crate::types::take_pending_ban_ack(&ip_str) {
                let is_permanent = e.is_permanent();
                let ban_count = BAN_HISTORY
                    .get_or_init(BanHistory::new)
                    .record_ban(&ip_str, is_permanent);
                let jail_name = cache
                    .get(&ip_str)
                    .map(|b| b.jail_name.clone())
                    .unwrap_or_else(|| "api".to_string());
                crate::history_snapshot::record_ban_event(&ip_str, &jail_name, ban_count);
                // 只有真实业务的 jail 计入信誉分；内置来源不污染信誉画像。
                if jail_name != "api" && jail_name != "ddos" && jail_name != "system" {
                    crate::ip_reputation::get_store().record_ban(&ip_str);
                }
                crate::types::notify_ban_ack_ok(&ip_str);
                crate::logger::debug!(
                    crate::logger::get(),
                    "BanStateChange: 内核确认，已写入 ban_history";
                    "ip" => &ip_str,
                    "ban_count" => ban_count
                );
            } else {
                crate::types::notify_ban_ack_ok(&ip_str);
                crate::logger::debug!(
                    crate::logger::get(),
                    "BanStateChange: daemon 发起且历史已确认，跳过";
                    "ip" => &ip_str
                );
            }
            return;
        }

        // 非 daemon 发起：从事件自带的 reason / jail_name 反推实际来源。
        let (actual_reason, jail_name) = infer_ban_origin(&e.reason, &e.jail_name);
        let now = now_secs();
        let is_permanent = e.is_permanent();
        let ban_count = BAN_HISTORY
            .get_or_init(BanHistory::new)
            .record_ban(&ip_str, is_permanent);
        let ban_info = BanInfo {
            ip: ip_str.clone(),
            ip_num: 0,
            jail_name,
            reason: actual_reason,
            banned_at: now,
            expires_at: if is_permanent {
                0
            } else {
                now + i64::from(e.duration_secs)
            },
            is_permanent,
            fail_count: 0,
            ban_count,
        };
        let jail_for_event = ban_info.jail_name.clone();
        cache.insert(ban_info.clone());
        compose::mirror_ban_insert(&ban_info);
        crate::history_snapshot::record_ban_event(&ip_str, &jail_for_event, ban_count);
        crate::logger::info!(
            crate::logger::get(),
            "已更新 ACTIVE_BAN_CACHE (procfs 封禁)";
            "ip" => &ip_str,
            "cache_len" => cache.len()
        );
    }

    /// 解封分支：移除缓存、记封禁时长、镜像移除、写历史、累加解封计数。
    fn on_unban(e: &codec::BanStateChange) {
        let Some(ip) = e.addr else {
            note_dropped_unknown_family("ban_state_change");
            return;
        };
        let ip_str = ip.to_string();

        crate::logger::debug!(
            crate::logger::get(),
            "收到封禁状态变更：解封";
            "ip" => &ip_str
        );

        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
        if let Some(removed) = cache.remove(&ip_str) {
            let duration = now_secs() - removed.banned_at;
            if duration > 0 {
                crate::types::record_ban_duration(duration);
            }
        }
        // 镜像：新状态同步移除（幂等，缓存里没有该 IP 时为空操作）。
        compose::mirror_ban_remove(&ip_str);
        // 记录解封到 BAN_HISTORY（旧实现曾漏调，本层保留已修复的行为）。
        BAN_HISTORY
            .get_or_init(BanHistory::new)
            .record_unban(&ip_str);
        DAEMON_STATS.total_unbans.fetch_add(1, Ordering::Relaxed);
    }

    /// 处理内核命令执行失败：`sendto` 成功不等于内核成功，需回滚乐观写入的缓存。
    fn on_cmd_result(e: &codec::CmdResult) {
        let ip_str = e
            .addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        crate::logger::warn!(
            crate::logger::get(),
            "内核命令执行失败";
            "cmd" => cmd_name(e.original_cmd_raw),
            "error_code" => e.error_code,
            "ip" => &ip_str
        );

        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
        match e.original_cmd_raw {
            // BanIp 失败：撤掉提前 insert 的缓存项与待确认历史。`addr` 未定义时无键
            // 可回滚，但仍要回调等待者——否则等待方要空等到超时。
            2 if e.addr.is_some() && cache.remove(&ip_str).is_some() => {
                // 镜像：回滚同样要落到新状态，否则新 SSE 会长期显示一条内核并未接受的封禁。
                compose::mirror_ban_remove(&ip_str);
                crate::types::clear_pending_ban_ack(&ip_str);
                crate::types::notify_ban_ack_err(&ip_str, e.error_code);
                compose::publish_bans_changed();
                crate::logger::info!(
                    crate::logger::get(),
                    "BanIp 失败，已回滚封禁缓存";
                    "ip" => &ip_str
                );
            }
            2 => {
                crate::types::clear_pending_ban_ack(&ip_str);
                crate::types::notify_ban_ack_err(&ip_str, e.error_code);
                compose::publish_bans_changed();
            }
            3 => {
                // UnbanIp 失败：缓存可能已被乐观 remove；无法无损恢复元数据，依赖后续
                // 封禁列表对账补回。此处仅记录。
                crate::logger::debug!(
                    crate::logger::get(),
                    "UnbanIp 失败，等待列表对账恢复缓存";
                    "ip" => &ip_str
                );
            }
            _ => {}
        }
    }

    /// 处理统计响应：只采纳包计数两项。
    ///
    /// `current_bans` / `total_bans` / `total_unbans` / `whitelist_count` 被丢弃，
    /// 与旧 `handle_stats_response` 逐字一致——这是既有行为，不是本次改动引入的缺口。
    ///
    /// 生产路径上这条回复被 [`crate::kernel::client::Client::query_stats`] 按 `seq`
    /// 认领并投给调用方，故周期任务直接调 [`apply_stats`]；本分支只在「回复带 `seq`
    /// 却无人等待」这种异常情形下才会走到。
    fn on_stats_response(e: &codec::StatsResponse) {
        apply_stats(e);
    }

    /// 处理白名单状态变更事件（单条增删，非全量）。
    fn on_whitelist_state_change(e: &codec::WhitelistStateChange) {
        let Some(ip) = e.addr else {
            note_dropped_unknown_family("whitelist_state_change");
            // 计数仍要同步：内核的白名单总数已经变了。
            DAEMON_STATS
                .whitelist_count
                .store(u64::from(e.whitelist_count), Ordering::Relaxed);
            compose::publish_stats_changed();
            return;
        };

        // 键的唯一形态：网络地址 + 恒带前缀。旧的「/32、/128、/0 不拼前缀」三套规则
        // 在此收拢为一条——同一子网的两种写法落到同一个键。
        let key = CidrKey::new(ip, e.prefix_len);

        match e.action {
            Some(contract::WhitelistAction::Add) => {
                crate::logger::debug!(
                    crate::logger::get(),
                    "收到白名单状态变更：添加";
                    "ip" => %ip,
                    "prefix_len" => e.prefix_len,
                    "device" => &e.device
                );

                // 补 device：已存在且原 device 为空、新 device 非空时填入；其余情况不覆盖。
                let mut cache = WHITELIST_CACHE.write();
                match cache.get_mut(key.as_str()) {
                    Some(entry) if entry.device.is_empty() && !e.device.is_empty() => {
                        entry.device = e.device.clone();
                    }
                    None => {
                        cache.insert(
                            key.as_str().to_string(),
                            WhitelistEntry {
                                cidr: key.as_str().to_string(),
                                device: e.device.clone(),
                            },
                        );
                    }
                    _ => {}
                }
                drop(cache);
                compose::mirror_whitelist_insert(key, e.device.clone());
            }
            Some(contract::WhitelistAction::Remove) => {
                crate::logger::debug!(
                    crate::logger::get(),
                    "收到白名单状态变更：移除";
                    "ip" => %ip,
                    "prefix_len" => e.prefix_len
                );

                WHITELIST_CACHE.write().remove(key.as_str());
                compose::mirror_whitelist_remove(&key);
            }
            None => {
                crate::logger::debug!(crate::logger::get(), "白名单状态变更动作未定义，仅同步计数")
            }
        }

        // 白名单的增删已在上面各自镜像（各自发布 `Whitelist` 版本）；此处只补推 `stats`
        // ——白名单计数刚变，前端要立刻看到。
        DAEMON_STATS
            .whitelist_count
            .store(u64::from(e.whitelist_count), Ordering::Relaxed);
        compose::publish_stats_changed();
    }

    /// 处理配置更新确认：部分被拒时告警，全数采纳时只记 debug。
    ///
    /// 同 [`Consumer::on_stats_response`]：生产路径上这条回复由
    /// [`crate::kernel::client::Client::set_config`] 认领，故配置下发方直接调
    /// [`apply_config_ack`]。
    fn on_config_ack(e: &codec::ConfigAck) {
        apply_config_ack(e);
    }

    /// 处理 procfs 配置变更广播：只对 `ban_time` 变动记一行 debug。
    fn on_config_change(cfg: &codec::SetConfig) {
        if cfg.flags & contract::config_flags::BAN_TIME != 0 {
            crate::logger::debug!(
                crate::logger::get(),
                "内核 ban_time 已通过 procfs 变更";
                "new_ban_time" => cfg.ban_time
            );
        }
    }

    /// 处理分析数据响应：整体快照覆盖 `ANALYSIS_CACHE`。
    ///
    /// 同 [`Consumer::on_stats_response`]：生产路径上这条回复由
    /// [`crate::kernel::client::Client::query_analysis`] 认领，故周期任务直接调
    /// [`apply_analysis`]。
    fn on_analysis_response(e: &codec::AnalysisResponse) {
        apply_analysis(e);
    }
}

// ============================================================================
// 请求/响应路径的落地入口
//
// 下面三个响应类型都被 `Client` 按 `seq` 认领并**直接投给调用方**，不进入事件队列，
// 因此周期任务/配置下发方必须在拿到返回值后自己调这里落地。它们是 `Consumer` 同名
// 私有分支的公开版本——两边共用同一份实现，避免「事件路径」与「请求路径」各写一遍
// 而慢慢漂移。
// ============================================================================

/// 把统计响应搬进全局计数器。
///
/// 只采纳 `packets_dropped` / `packets_accepted` 两项，其余字段丢弃——与旧
/// `handle_stats_response` 逐字一致（封禁数、白名单数由事件自带的实时字段维护，
/// 不靠这条周期回复）。
pub fn apply_stats(e: &codec::StatsResponse) {
    crate::logger::debug!(
        crate::logger::get(),
        "收到统计数据响应";
        "current_bans" => e.current_bans,
        "total_bans" => e.total_bans,
        "total_unbans" => e.total_unbans,
        "whitelist_count" => e.whitelist_count,
        "packets_dropped" => e.packets_dropped,
        "packets_accepted" => e.packets_accepted
    );

    DAEMON_STATS
        .packets_dropped
        .store(e.packets_dropped, Ordering::Relaxed);
    DAEMON_STATS
        .packets_accepted
        .store(e.packets_accepted, Ordering::Relaxed);
}

/// 把分析响应整体覆盖进 `ANALYSIS_CACHE`。
pub fn apply_analysis(e: &codec::AnalysisResponse) {
    // 条目数由内核声明，数组长度是编译期容量；取有效交集而不是相信声明值。
    let udp_ports = e.udp_ports[..e.udp_ports_in_use()]
        .iter()
        .map(|p| AnalysisUdpPortEntry {
            port: p.port,
            packets: p.packets,
            bytes: p.bytes,
            last_seen_secs: p.last_seen_secs,
        })
        .collect();
    let icmp_types = e.icmp_types[..e.icmp_types_in_use()]
        .iter()
        .map(|t| AnalysisIcmpTypeEntry {
            r#type: t.icmp_type,
            code: t.code,
            packets: t.packets,
            bytes: t.bytes,
            last_seen_secs: t.last_seen_secs,
        })
        .collect();
    let port_scanners = e.port_scanners[..e.port_scanners_in_use()]
        .iter()
        .filter_map(|s| scanner_entry(s.addr, s.metric, s.packets))
        .collect();
    let service_probes = e.service_probes[..e.service_probes_in_use()]
        .iter()
        .filter_map(|s| scanner_entry(s.addr, s.metric, s.packets))
        .collect();

    *ANALYSIS_CACHE.write() = AnalysisData {
        pkt_sizes: e.pkt_sizes,
        ttl_dist: e.ttl_dist,
        ip_total_count: e.ip_frag_total,
        ip_frag_count: e.ip_frag_count,
        udp_ports,
        udp_port_capacity: e.udp_port_capacity,
        icmp_types,
        icmp_type_capacity: e.icmp_type_capacity,
        port_scanners,
        port_scan_threshold: e.port_scan_threshold,
        service_probes,
        service_probe_threshold: e.service_probe_threshold,
    };
}

/// 记录配置更新的采纳/拒绝位图：有被拒项时告警，全数采纳时只记 debug。
pub fn apply_config_ack(e: &codec::ConfigAck) {
    if e.rejected_flags != 0 {
        crate::logger::warn!(
            crate::logger::get(),
            "配置更新部分被拒绝";
            "applied_flags" => format!("0x{:x}", e.applied_flags),
            "rejected_flags" => format!("0x{:x}", e.rejected_flags)
        );
    } else {
        crate::logger::debug!(
            crate::logger::get(),
            "配置更新已确认";
            "applied_flags" => format!("0x{:x}", e.applied_flags)
        );
    }
}

/// 扫描者条目 → 展示条目；地址族未定义（无 IP 可展示）时返回 `None`。
fn scanner_entry(addr: Option<IpAddr>, metric: u32, packets: u64) -> Option<AnalysisScannerEntry> {
    // 不填 "unknown"：认不出的地址族不该变成一条看起来像真 IP 的记录。
    Some(AnalysisScannerEntry {
        ip: addr?.to_string(),
        metric,
        packets,
    })
}

/// 从事件自带的 `reason` / `jail_name` 反推「实际原因 + jail 名」。
///
/// 逐字复刻旧 `handle_ban_state_change` 的推断链：显式 jail 名优先，其次是 `api:`
/// 前缀，再次是 DDoS 类关键词，最后是三条固定来源串。
fn infer_ban_origin(reason: &str, jail_name: &str) -> (String, String) {
    // 事件直接给了 jail 名（非空）→ 以它为准；reason 为空时用 jail 名兜底。
    if !jail_name.is_empty() {
        let jn = jail_name.to_string();
        return if reason.is_empty() {
            (jn.clone(), jn)
        } else {
            (reason.to_string(), jn)
        };
    }
    if let Some(rest) = reason.strip_prefix("api:") {
        return (rest.to_string(), "api".to_string());
    }
    if reason.contains("SYN flood")
        || reason.contains("UDP flood")
        || reason.contains("ICMP flood")
        || reason.contains("total rate")
        || reason.contains("ddos")
    {
        return (reason.to_string(), "ddos".to_string());
    }
    if reason == "procfs" || reason == "manual" || reason == "api" {
        return (reason.to_string(), "api".to_string());
    }
    if reason == "expired" || reason == "unban" || reason == "whitelist" {
        return (reason.to_string(), "system".to_string());
    }
    (reason.to_string(), "api".to_string())
}

/// 命令类型原始取值 → 名字（与旧 `FwNlCmdResult::cmd_name` 同表）。
///
/// `codec` 侧没有这个助手（它只暴露 `Option<MsgType>` 与原始整数），而日志里留一个
/// 稳定的名字比留一个数字可读，故在此处保留旧表。
fn cmd_name(raw: u16) -> &'static str {
    match raw {
        2 => "BanIp",
        3 => "UnbanIp",
        12 => "AddWhitelist",
        13 => "RemoveWhitelist",
        _ => "Unknown",
    }
}

/// 记录一次「地址族未定义 → 跳过」，并累加丢弃计数。
fn note_dropped_unknown_family(what: &'static str) {
    let total = DROPPED_UNKNOWN_FAMILY.fetch_add(1, Ordering::Relaxed) + 1;
    crate::logger::warn!(
        crate::logger::get(),
        "入站条目地址族未定义，已跳过";
        "source" => what,
        "dropped_total" => total
    );
}

/// 因地址族未定义而跳过的条目总数（诊断 / 门禁用）。
#[must_use]
pub fn dropped_unknown_family_entries() -> u64 {
    DROPPED_UNKNOWN_FAMILY.load(Ordering::Relaxed)
}

// ============================================================================
// 全量快照的三个入口（周期任务调用，取代旧的分页回复处理）
// ============================================================================

/// 用内核的**完整**封禁列表对账本地缓存，返回被清理的过期条目数。
///
/// 取代旧 `handle_list_bans_response`：分页拼接由
/// [`crate::kernel::client::Client::list_bans_all`] 完成，本函数只处理「翻完所有页之后
/// 的整张表」这一语义。对账只删「缓存有、内核无」，不覆盖已有条目的 reason / jail。
///
/// `entry.addr()` 为 `None`（地址族未定义）的条目跳过并计入丢弃计数。
pub fn reconcile_bans(entries: &[codec::BanEntry]) -> usize {
    let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);

    // 内核里的 IP 集合 + 需要补进缓存的失联条目（比如 daemon 重启后的恢复路径）。
    let mut kernel_ips = std::collections::HashSet::with_capacity(entries.len());
    let mut missing: Vec<BanInfo> = Vec::new();
    for entry in entries {
        let Some(ip) = entry.addr() else {
            note_dropped_unknown_family("list_bans");
            continue;
        };
        let ip_str = ip.to_string();
        kernel_ips.insert(ip_str.clone());

        // 已经在缓存里：保留本地已有的 jail / reason 元数据，只由对账删除多余项。
        if cache.contains(&ip_str) {
            continue;
        }

        let (reason, jail_name) = infer_kernel_jail(&entry.reason, &entry.jail_name);
        let ban_count = BAN_HISTORY
            .get_or_init(BanHistory::new)
            .get_ban_count(&ip_str);
        missing.push(BanInfo {
            ip: ip_str,
            ip_num: 0,
            jail_name,
            reason,
            banned_at: entry.banned_at as i64,
            expires_at: if entry.is_permanent {
                0
            } else {
                entry.banned_at as i64 + i64::from(entry.duration_secs)
            },
            is_permanent: entry.is_permanent,
            fail_count: 0,
            ban_count,
        });
    }

    let removed = cache.reconcile_with_kernel(&kernel_ips, missing);
    // 镜像：把对账结果搬进新状态，并把新状态回写旧缓存，使 UI 与内核一致。
    compose::mirror_bans_reconcile();
    crate::logger::info!(
        crate::logger::get(),
        "已对账封禁状态";
        "kernel_count" => kernel_ips.len(),
        "stale_removed" => removed,
        "cache_len" => cache.len()
    );
    removed
}

/// 用内核的**完整**白名单覆盖本地缓存（内核是权威全表）。
///
/// 取代旧 `handle_list_whitelist_response`。键经 [`CidrKey`] 规范化后再进缓存与镜像，
/// 故 `10.0.0.5/24` 与 `10.0.0.0/24` 不会再各占一条。
pub fn apply_whitelist_all(entries: &[codec::WhitelistEntry]) {
    crate::logger::debug!(
        crate::logger::get(),
        "收到白名单列表响应";
        "count" => entries.len()
    );

    let mut map: std::collections::HashMap<String, WhitelistEntry> =
        std::collections::HashMap::with_capacity(entries.len());
    for entry in entries {
        let Some(ip) = entry.addr() else {
            note_dropped_unknown_family("list_whitelist");
            continue;
        };
        let key = CidrKey::new(ip, entry.prefix_len);
        map.insert(
            key.as_str().to_string(),
            WhitelistEntry {
                cidr: key.as_str().to_string(),
                device: entry.device.clone(),
            },
        );
    }

    let count = map.len();
    let pairs = compose::whitelist_pairs(&map);
    *WHITELIST_CACHE.write() = map;
    // 镜像：内核 LIST 是白名单权威全表，覆盖式搬进新状态。
    compose::mirror_whitelist_replace_all(pairs);

    // 计数取实际写入的条目数（与旧实现一致：旧实现用的是内核声明的条目数，此处用
    // 规范化后去重的结果——两种写法在无重复内核表上同值）。
    DAEMON_STATS
        .whitelist_count
        .store(count as u64, Ordering::Relaxed);
}

/// 用内核的**完整**速率快照覆盖本地缓存，并推进速率基线与历史。
///
/// 取代旧 `handle_list_rates_response`。`global_pps` / `global_bps` 取整张表的最后
/// 一页（同一窗口的量，逐页累加会失真——见 [`codec::RateSnapshot`]）。
pub fn apply_rates(snapshot: &codec::RateSnapshot) {
    let global_pps = snapshot.global_pps;
    let global_bps = snapshot.global_bps;

    // 基线与多窗口 EWMA 只在窗口内确有流量时推进：全 0 的窗口会把 EWMA 拉向 0。
    if global_pps > 0 || global_bps > 0 {
        crate::types::update_traffic_baseline(global_pps, global_bps);
        crate::types::update_rate_windows(global_pps, global_bps);
    }

    let mut total_pps = 0u64;
    let mut total_bps = 0u64;
    let mut rate_entries: Vec<RateEntry> = Vec::with_capacity(snapshot.entries.len());
    for e in &snapshot.entries {
        let Some(ip) = e.addr() else {
            note_dropped_unknown_family("list_rates");
            continue;
        };
        total_pps += e.packets;
        total_bps += e.bytes;
        rate_entries.push(RateEntry {
            ip: ip.to_string(),
            packets_per_sec: e.packets,
            bytes_per_sec: e.bytes,
            syn_packets_per_sec: e.syn_packets,
            udp_packets_per_sec: e.udp_packets,
            icmp_packets_per_sec: e.icmp_packets,
            ack_packets_per_sec: e.ack_packets,
            rst_packets_per_sec: e.rst_packets,
            fin_packets_per_sec: e.fin_packets,
        });
    }

    let tracked = rate_entries.len();
    *RATE_CACHE.write() = rate_entries.clone();
    // 镜像：速率样本覆盖式搬进新状态（新状态的 EWMA 基线与旧模块独立演化）。
    compose::mirror_rates_from_cache(&rate_entries, global_pps, global_bps);
    // 记录速率历史快照（环形缓冲，保留 1 小时）。
    crate::types::record_rate_history(total_pps, total_bps, tracked as u32);

    crate::logger::debug!(
        crate::logger::get(),
        "收到速率统计响应";
        "count" => tracked,
        "total_pps" => total_pps,
        "total_bps" => total_bps,
        "global_pps" => global_pps,
        "global_bps" => global_bps
    );
}

/// 封禁列表条目的 jail / reason 推断（与白名单无关，专用于对账路径）。
///
/// 与旧 `handle_list_bans_response` 的推断链逐字一致：`jail_name` 为空或为 `"kernel"`
/// 时按 reason 关键词判 DDoS，否则沿用内核给的 jail 名；reason 为空时用 jail 名兜底。
fn infer_kernel_jail(reason: &str, jail_name: &str) -> (String, String) {
    let jail = if jail_name.is_empty() || jail_name == "kernel" {
        let probe = if reason.is_empty() { jail_name } else { reason };
        if probe.contains("flood") || probe.contains("ddos") || probe.contains("total rate") {
            "ddos".to_string()
        } else {
            "api".to_string()
        }
    } else {
        jail_name.to_string()
    };
    let final_reason = if reason.is_empty() {
        if jail_name.is_empty() || jail_name == "kernel" {
            "api".to_string()
        } else {
            jail_name.to_string()
        }
    } else {
        reason.to_string()
    };
    (final_reason, jail)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::codec::frame_for_test;
    use std::sync::{Arc, Mutex, OnceLock};

    /// 缓存与历史是进程级全局，多个 `#[test]` 并行跑会互相干扰（每个测试都会往里
    /// 塞条目、改计数器）。整段测试串行化：拿不到锁的测试排队而不是失败。
    /// 单测里 `unwrap` 到锁中毒即视为该测试自己的失败。
    fn serial() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 造一条合法线格式报文（走真实头编码器，测试与生产同一条编码路径）。
    fn frame(msg_type: contract::MsgType, seq: u32, body: &[u8]) -> Vec<u8> {
        frame_for_test(msg_type, seq, body)
    }

    /// 解码回 `Incoming`——顺带证明构造的字节确实符合契约。
    fn decode_one(bytes: &[u8]) -> Incoming {
        let (hdr, body) = codec::decode_header(bytes).expect("报文头应合法");
        codec::decode_incoming(hdr.msg_type().expect("类型应在契约内"), body).expect("载荷应能解码")
    }

    /// 把 `IpAddr` 铺进契约的 16 字节地址缓冲。
    fn ip_bytes(ip: IpAddr) -> [u8; 16] {
        let mut out = [0u8; 16];
        match ip {
            IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
            IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
        }
        out
    }

    /// 字段在**载荷体**中的偏移（契约给的偏移含 12 字节公共头）。
    fn body_off(offsets: &[(&str, usize)], name: &str) -> usize {
        raw_off(offsets, name) - codec::HDR_LEN
    }

    /// 字段在**尾部条目**中的偏移（条目无公共头）。
    fn elem_off(offsets: &[(&str, usize)], name: &str) -> usize {
        raw_off(offsets, name)
    }

    fn raw_off(offsets: &[(&str, usize)], name: &str) -> usize {
        offsets
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, o)| *o)
            .unwrap_or_else(|| panic!("契约里没有字段 {name}"))
    }

    /// 往缓冲的指定偏移写一段字节。
    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// 契约里 `reason` / `jail_name` 定长字段的字节宽度（各结构体一致）。
    const TEXT32: usize = 32;
    /// 契约里 `device` 定长字段的字节宽度。
    const TEXT16: usize = 16;

    /// 把文本铺进定长字段：NUL 结尾，超出宽度即截断。
    ///
    /// 宽度必须由调用方显式给出（取自契约），避免「声明 64 字节却写进 32 字节字段」
    /// 这类越界——那会静默覆盖相邻字段，把测试变成假绿。
    fn fixed_field(text: &str, width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        let src = text.as_bytes();
        let n = src.len().min(width - 1);
        out[..n].copy_from_slice(&src[..n]);
        out
    }

    /// 造一条白名单分页响应（定长头 + 尾部条目）。
    fn whitelist_page(entries: &[(IpAddr, u8, &str)]) -> Incoming {
        let head = contract::ListWhitelistResponse::FIELD_OFFSETS;
        let ent = contract::WhitelistEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListWhitelistResponse::FIXED_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(head, "count"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(
            &mut body,
            body_off(head, "total"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(&mut body, body_off(head, "offset"), &0u32.to_be_bytes());
        for (ip, prefix, device) in entries {
            let mut e = vec![0u8; contract::WhitelistEntry::WIRE_SIZE];
            e[elem_off(ent, "af")] = match ip {
                IpAddr::V4(_) => contract::AddrFamily::Inet.to_raw(),
                IpAddr::V6(_) => contract::AddrFamily::Inet6.to_raw(),
            };
            e[elem_off(ent, "prefix_len")] = *prefix;
            put(&mut e, elem_off(ent, "addr"), &ip_bytes(*ip));
            put(
                &mut e,
                elem_off(ent, "device"),
                &fixed_field(device, TEXT16),
            );
            body.extend_from_slice(&e);
        }
        decode_one(&frame(contract::MsgType::ListWhitelistResponse, 1, &body))
    }

    /// 造一条速率分页响应（含全局 pps/bps）。
    fn rates_page(global_pps: u64, global_bps: u64, entries: &[(IpAddr, u64, u64)]) -> Incoming {
        let head = contract::ListRatesResponse::FIELD_OFFSETS;
        let ent = contract::RateEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListRatesResponse::FIXED_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(head, "count"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(
            &mut body,
            body_off(head, "total"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(&mut body, body_off(head, "offset"), &0u32.to_be_bytes());
        put(
            &mut body,
            body_off(head, "global_pps"),
            &global_pps.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(head, "global_bps"),
            &global_bps.to_be_bytes(),
        );
        for (ip, packets, bytes) in entries {
            let mut e = vec![0u8; contract::RateEntry::WIRE_SIZE];
            e[elem_off(ent, "af")] = match ip {
                IpAddr::V4(_) => contract::AddrFamily::Inet.to_raw(),
                IpAddr::V6(_) => contract::AddrFamily::Inet6.to_raw(),
            };
            put(&mut e, elem_off(ent, "packets"), &packets.to_be_bytes());
            put(&mut e, elem_off(ent, "bytes"), &bytes.to_be_bytes());
            put(&mut e, elem_off(ent, "addr"), &ip_bytes(*ip));
            body.extend_from_slice(&e);
        }
        decode_one(&frame(contract::MsgType::ListRatesResponse, 2, &body))
    }

    /// 造一条封禁分页响应（用于对账路径）。
    fn bans_page(entries: &[(IpAddr, bool, u32, u64, &str, &str)]) -> Incoming {
        let head = contract::ListBansResponse::FIELD_OFFSETS;
        let ent = contract::BanEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListBansResponse::FIXED_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(head, "count"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(
            &mut body,
            body_off(head, "total"),
            &u32::try_from(entries.len()).expect("条目数").to_be_bytes(),
        );
        put(&mut body, body_off(head, "offset"), &0u32.to_be_bytes());
        for (ip, permanent, duration, banned_at, jail, reason) in entries {
            let mut e = vec![0u8; contract::BanEntry::WIRE_SIZE];
            e[elem_off(ent, "af")] = match ip {
                IpAddr::V4(_) => contract::AddrFamily::Inet.to_raw(),
                IpAddr::V6(_) => contract::AddrFamily::Inet6.to_raw(),
            };
            e[elem_off(ent, "is_permanent")] = u8::from(*permanent);
            put(
                &mut e,
                elem_off(ent, "duration_secs"),
                &duration.to_be_bytes(),
            );
            put(&mut e, elem_off(ent, "banned_at"), &banned_at.to_be_bytes());
            put(&mut e, elem_off(ent, "addr"), &ip_bytes(*ip));
            put(
                &mut e,
                elem_off(ent, "jail_name"),
                &fixed_field(jail, TEXT32),
            );
            put(
                &mut e,
                elem_off(ent, "reason"),
                &fixed_field(reason, TEXT32),
            );
            body.extend_from_slice(&e);
        }
        decode_one(&frame(contract::MsgType::ListBansResponse, 3, &body))
    }

    /// 拆出分页响应的条目切片（`Incoming` 是分发用的包装）。
    fn unpack_whitelist(msg: &Incoming) -> Vec<codec::WhitelistEntry> {
        match msg {
            Incoming::ListWhitelistResponse(p) => p.entries.clone(),
            other => panic!("类型不符：{}", other.msg_type_name()),
        }
    }

    fn unpack_rates(msg: &Incoming) -> codec::RateSnapshot {
        match msg {
            Incoming::ListRatesResponse(p) => codec::RateSnapshot {
                global_pps: p.global_pps,
                global_bps: p.global_bps,
                entries: p.entries.clone(),
            },
            other => panic!("类型不符：{}", other.msg_type_name()),
        }
    }

    fn unpack_bans(msg: &Incoming) -> Vec<codec::BanEntry> {
        match msg {
            Incoming::ListBansResponse(p) => p.entries.clone(),
            other => panic!("类型不符：{}", other.msg_type_name()),
        }
    }

    /// 测试用的白名单键（避免每个测试各自拼字符串）。
    fn key(ip: &str, prefix: u8) -> String {
        CidrKey::new(ip.parse().expect("测试地址"), prefix)
            .as_str()
            .to_string()
    }

    #[test]
    fn a_procfs_ban_populates_the_cache_and_the_history() {
        let _guard = serial();
        let c = Consumer::new();
        let msg = decode_one(&frame(
            contract::MsgType::BanStateChange,
            0,
            &ban_state_change_body(contract::BanAction::Ban, "198.51.100.10", "manual", "", 600),
        ));

        assert!(c.process(&msg), "封禁事件应报告状态变化");

        let cache = ACTIVE_BAN_CACHE.get().expect("封禁分支应初始化缓存");
        let info = cache.get("198.51.100.10").expect("应写入缓存");
        assert_eq!(info.jail_name, "api", "reason=manual 归入 api");
        assert!(!info.is_permanent);
        assert_eq!(info.expires_at - info.banned_at, 600);
        assert_eq!(
            BAN_HISTORY
                .get()
                .expect("应初始化历史")
                .get_ban_count("198.51.100.10"),
            1
        );
    }

    #[test]
    fn a_ban_event_without_a_family_is_skipped_not_faked() {
        let _guard = serial();
        let c = Consumer::new();
        let before = dropped_unknown_family_entries();

        // 地址族字段留 0（契约里不属于 Inet/Inet6）→ addr 为 None。
        let mut body = vec![0u8; contract::BanStateChange::WIRE_SIZE - codec::HDR_LEN];
        let off = contract::BanStateChange::FIELD_OFFSETS;
        body[body_off(off, "action")] = contract::BanAction::Ban.to_raw();
        c.process(&decode_one(&frame(
            contract::MsgType::BanStateChange,
            0,
            &body,
        )));

        assert_eq!(
            dropped_unknown_family_entries(),
            before + 1,
            "未定义地址族应计入丢弃计数"
        );
        if let Some(cache) = ACTIVE_BAN_CACHE.get() {
            assert!(
                cache.get("unknown").is_none(),
                "不得把字面量 unknown 写进缓存"
            );
        }
    }

    #[test]
    fn an_unban_clears_the_cache_and_counts_toward_stats() {
        let _guard = serial();
        let c = Consumer::new();
        let ip = "198.51.100.11";
        c.process(&decode_one(&frame(
            contract::MsgType::BanStateChange,
            0,
            &ban_state_change_body(contract::BanAction::Ban, ip, "manual", "", 600),
        )));

        let before = DAEMON_STATS.total_unbans.load(Ordering::Relaxed);
        c.process(&decode_one(&frame(
            contract::MsgType::BanStateChange,
            0,
            &ban_state_change_body(contract::BanAction::Unban, ip, "", "", 0),
        )));

        assert!(
            ACTIVE_BAN_CACHE
                .get()
                .expect("缓存已初始化")
                .get(ip)
                .is_none(),
            "解封后缓存不应再有该 IP"
        );
        assert_eq!(
            DAEMON_STATS.total_unbans.load(Ordering::Relaxed),
            before + 1,
            "解封计数应自增一"
        );
    }

    #[test]
    fn the_unban_branch_still_syncs_the_trailing_stats() {
        let _guard = serial();
        let c = Consumer::new();
        let ip = "198.51.100.12";
        // 用解封事件（action=Unban），并把尾部统计置成可识别的值。
        let mut body = ban_state_change_body(contract::BanAction::Unban, ip, "", "", 0);
        let off = contract::BanStateChange::FIELD_OFFSETS;
        put(
            &mut body,
            body_off(off, "packets_dropped"),
            &111u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "packets_accepted"),
            &222u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "whitelist_count"),
            &333u32.to_be_bytes(),
        );
        c.process(&decode_one(&frame(
            contract::MsgType::BanStateChange,
            0,
            &body,
        )));

        assert_eq!(DAEMON_STATS.packets_dropped.load(Ordering::Relaxed), 111);
        assert_eq!(DAEMON_STATS.packets_accepted.load(Ordering::Relaxed), 222);
        assert_eq!(DAEMON_STATS.whitelist_count.load(Ordering::Relaxed), 333);
    }

    #[test]
    fn a_ban_failure_rolls_back_and_wakes_the_waiter() {
        let _guard = serial();
        let ip: IpAddr = "198.51.100.13".parse().expect("测试地址");
        let ip_str = ip.to_string();

        // daemon 发起路径：先乐观 insert + 登记待确认 ACK，再由 CmdResult 回滚。
        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
        cache.insert(BanInfo {
            ip: ip_str.clone(),
            ip_num: 0,
            jail_name: "sshd".to_string(),
            reason: "test".to_string(),
            banned_at: now_secs(),
            expires_at: 0,
            is_permanent: false,
            fail_count: 0,
            ban_count: 1,
        });
        crate::types::mark_pending_ban_ack(&ip_str);
        let rx = crate::types::register_ban_ack_waiter(&ip_str);

        let c = Consumer::new();
        c.process(&decode_one(&frame(
            contract::MsgType::CmdResult,
            0,
            &cmd_result_body(contract::MsgType::BanIp, -22, ip),
        )));

        assert!(
            cache.get(&ip_str).is_none(),
            "BanIp 失败后应撤掉乐观写入的缓存项"
        );
        assert!(!crate::types::is_pending_ban_ack(&ip_str));
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(1)),
            Ok(Err(-22)),
            "等待者应收到带错误码的失败通知"
        );
    }

    #[test]
    fn an_unban_failure_leaves_the_cache_alone() {
        let _guard = serial();
        let ip: IpAddr = "198.51.100.14".parse().expect("测试地址");
        let ip_str = ip.to_string();
        // action = UnbanIp 失败时旧实现只记一行 debug，不动缓存（等 LIST 对账补回）。
        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
        cache.insert(BanInfo {
            ip: ip_str.clone(),
            ip_num: 0,
            jail_name: "sshd".to_string(),
            reason: "test".to_string(),
            banned_at: now_secs(),
            expires_at: 0,
            is_permanent: false,
            fail_count: 0,
            ban_count: 1,
        });

        let c = Consumer::new();
        c.process(&decode_one(&frame(
            contract::MsgType::CmdResult,
            0,
            &cmd_result_body(contract::MsgType::UnbanIp, -5, ip),
        )));

        assert!(cache.get(&ip_str).is_some(), "解封失败不应动用缓存");
    }

    #[test]
    fn a_ddos_event_reaches_the_decision_engine() {
        let _guard = serial();
        let c = Consumer::new();
        let engine = Arc::new(DdosDecisionEngine::new(crate::types::DdosConfig::default()));
        c.set_decision_engine(Arc::clone(&engine));

        c.process(&decode_one(&frame(
            contract::MsgType::DdosEvent,
            0,
            &ddos_event_body("203.0.113.9", "SYN flood", 12345),
        )));

        assert_eq!(engine.tracked_ips_count(), 1, "已接线的引擎应记下这次违规");
    }

    #[test]
    fn a_ddos_event_without_an_engine_is_silently_dropped() {
        let _guard = serial();
        let c = Consumer::new();
        // 未接线（2.H-2 之前）：只记日志，不应 panic。
        assert!(!c.process(&decode_one(&frame(
            contract::MsgType::DdosEvent,
            0,
            &ddos_event_body("203.0.113.10", "SYN flood", 1),
        ))));
    }

    #[test]
    fn a_whitelist_event_normalizes_the_key_and_syncs_the_count() {
        let _guard = serial();
        let c = Consumer::new();
        // 主机位非零：键必须归一化成 10.0.0.0/24。
        c.process(&decode_one(&frame(
            contract::MsgType::WhitelistStateChange,
            0,
            &whitelist_event_body("10.0.0.5", 24, "eth0", 7, true),
        )));

        let cache = WHITELIST_CACHE.read();
        let expected = key("10.0.0.0", 24);
        assert!(
            cache.contains_key(&expected),
            "应写入归一化后的键，实得 {:?}",
            cache.keys().collect::<Vec<_>>()
        );
        assert!(!cache.contains_key("10.0.0.5/24"), "不得写入未归一化的键");
        assert_eq!(cache.get(&expected).expect("应存在").device, "eth0");
        drop(cache);
        assert_eq!(DAEMON_STATS.whitelist_count.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn a_whitelist_removal_drops_the_normalized_key() {
        let _guard = serial();
        let c = Consumer::new();
        c.process(&decode_one(&frame(
            contract::MsgType::WhitelistStateChange,
            0,
            &whitelist_event_body("10.0.0.5", 24, "eth0", 1, true),
        )));
        c.process(&decode_one(&frame(
            contract::MsgType::WhitelistStateChange,
            0,
            &whitelist_event_body("10.0.0.9", 24, "", 0, false),
        )));

        assert!(
            !WHITELIST_CACHE.read().contains_key(&key("10.0.0.0", 24)),
            "移除应清掉同一个归一化键（10.0.0.9/24 与 10.0.0.5/24 同键）"
        );
    }

    #[test]
    fn a_full_whitelist_snapshot_collapses_two_writings_of_one_subnet() {
        let _guard = serial();
        let page = whitelist_page(&[
            ("192.0.2.7".parse().expect("测试地址"), 24, "eth0"),
            ("192.0.2.0".parse().expect("测试地址"), 24, "eth0"),
        ]);
        apply_whitelist_all(&unpack_whitelist(&page));

        let cache = WHITELIST_CACHE.read();
        assert_eq!(
            cache.len(),
            1,
            "同一子网的两种写法应去重成一条，实得 {:?}",
            cache.keys().collect::<Vec<_>>()
        );
        assert!(cache.contains_key(&key("192.0.2.0", 24)));
        drop(cache);
        assert_eq!(DAEMON_STATS.whitelist_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_rate_snapshot_fills_the_cache_and_totals_the_entries() {
        let _guard = serial();
        let page = rates_page(
            100,
            200,
            &[
                ("203.0.113.1".parse().expect("测试地址"), 100, 1_000),
                ("203.0.113.2".parse().expect("测试地址"), 300, 2_000),
            ],
        );
        let snapshot = unpack_rates(&page);
        apply_rates(&snapshot);

        let cache = RATE_CACHE.read();
        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.iter().map(|e| e.packets_per_sec).sum::<u64>(),
            400,
            "两条条目的包速率应各自保留"
        );
    }

    #[test]
    fn a_rate_snapshot_skips_undefined_families() {
        let _guard = serial();
        let before = dropped_unknown_family_entries();
        let mut body = vec![0u8; contract::ListRatesResponse::FIXED_SIZE - codec::HDR_LEN];
        let head = contract::ListRatesResponse::FIELD_OFFSETS;
        let ent = contract::RateEntry::FIELD_OFFSETS;
        put(&mut body, body_off(head, "count"), &1u32.to_be_bytes());
        put(&mut body, body_off(head, "total"), &1u32.to_be_bytes());
        // af 保持 0：不属于 Inet/Inet6。
        let mut e = vec![0u8; contract::RateEntry::WIRE_SIZE];
        put(&mut e, elem_off(ent, "packets"), &77u64.to_be_bytes());
        body.extend_from_slice(&e);
        let page = decode_one(&frame(contract::MsgType::ListRatesResponse, 0, &body));

        apply_rates(&unpack_rates(&page));

        assert_eq!(
            dropped_unknown_family_entries(),
            before + 1,
            "未定义地址族应计入丢弃计数"
        );
        assert!(
            !RATE_CACHE.read().iter().any(|e| e.ip == "unknown"),
            "不得把 unknown 写进速率缓存"
        );
    }

    #[test]
    fn reconciling_bans_adopts_kernel_entries_and_reports_removals() {
        let _guard = serial();
        let kept: IpAddr = "198.51.100.20".parse().expect("测试地址");
        let stale: IpAddr = "198.51.100.21".parse().expect("测试地址");

        // 本地缓存里有一条内核已不知晓的旧条目。
        let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
        cache.insert(BanInfo {
            ip: stale.to_string(),
            ip_num: 0,
            jail_name: "sshd".to_string(),
            reason: "old".to_string(),
            banned_at: 1,
            expires_at: 0,
            is_permanent: false,
            fail_count: 0,
            ban_count: 1,
        });

        // 内核只报告 kept（UDP flood → ddos）。
        let page = bans_page(&[(kept, false, 300, 1_000, "", "UDP flood")]);
        let removed = reconcile_bans(&unpack_bans(&page));

        assert!(removed >= 1, "内核没有的旧条目应被清掉，实得 {removed}");
        let info = cache.get(&kept.to_string()).expect("内核条目应被采纳");
        assert_eq!(info.jail_name, "ddos", "UDP flood 应归入 ddos");
        assert_eq!(info.expires_at - info.banned_at, 300);
        assert!(cache.get(&stale.to_string()).is_none(), "失联条目应被清理");
    }

    #[test]
    fn a_stats_response_adopts_only_the_packet_counters() {
        let _guard = serial();
        let c = Consumer::new();
        // 先置成互不相同的哨兵值，便于断言只有两个包计数器被覆盖。
        DAEMON_STATS
            .packets_dropped
            .store(1_000_000, Ordering::Relaxed);
        DAEMON_STATS
            .packets_accepted
            .store(2_000_000, Ordering::Relaxed);
        // 这三个计数由别的路径推进（解封事件 / 对账），进程内会被其它测试改过，
        // 故只断言「本次调用没有把它们改成报文里的 999」，先取当前值做基线。
        let unbans_before = DAEMON_STATS.total_unbans.load(Ordering::Relaxed);

        let mut body = vec![0u8; contract::StatsResponse::WIRE_SIZE - codec::HDR_LEN];
        let off = contract::StatsResponse::FIELD_OFFSETS;
        put(
            &mut body,
            body_off(off, "current_bans"),
            &999u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "total_bans"),
            &999u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "total_unbans"),
            &999u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "whitelist_count"),
            &999u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "packets_dropped"),
            &55u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "packets_accepted"),
            &66u64.to_be_bytes(),
        );
        c.process(&decode_one(&frame(
            contract::MsgType::StatsResponse,
            0,
            &body,
        )));

        assert_eq!(DAEMON_STATS.packets_dropped.load(Ordering::Relaxed), 55);
        assert_eq!(DAEMON_STATS.packets_accepted.load(Ordering::Relaxed), 66);
        // 其余字段按旧行为丢弃（`handle_stats_response` 只取两个包计数器）：不能因为
        // 换到新代码就顺手采纳 `total_unbans` —— 它由解封事件路径推进，值必须不变。
        assert_eq!(
            DAEMON_STATS.total_unbans.load(Ordering::Relaxed),
            unbans_before,
            "StatsResponse 不应改写 total_unbans"
        );
    }

    #[test]
    fn an_analysis_response_is_mirrored_with_bounded_entry_counts() {
        let _guard = serial();
        let c = Consumer::new();
        let off = contract::AnalysisResponse::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::AnalysisResponse::WIRE_SIZE - codec::HDR_LEN];
        // 声明 70 条 UDP 条目，数组容量 64：有效数必须夹到 64。
        put(
            &mut body,
            body_off(off, "udp_port_count"),
            &70u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "ip_frag_total"),
            &100u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "port_scan_count"),
            &1u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "icmp_type_count"),
            &0u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "service_probe_count"),
            &0u32.to_be_bytes(),
        );
        // port_scanners 数组首元素写一条**有效**记录：地址族未定义会被跳过，
        // 那时 port_scanners 只会是 0 条，断言就退化成恒真。
        let sc_off = contract::ScannerItem::FIELD_OFFSETS;
        let sc_base = body_off(off, "port_scanners");
        let mid = "203.0.113.50".parse::<IpAddr>().expect("测试地址");
        put(
            &mut body,
            sc_base + elem_off(sc_off, "af"),
            &[contract::AddrFamily::Inet.to_raw()],
        );
        put(
            &mut body,
            sc_base + elem_off(sc_off, "addr"),
            &ip_bytes(mid),
        );
        put(
            &mut body,
            sc_base + elem_off(sc_off, "metric"),
            &9u32.to_be_bytes(),
        );
        put(
            &mut body,
            sc_base + elem_off(sc_off, "packets"),
            &42u64.to_be_bytes(),
        );
        c.process(&decode_one(&frame(
            contract::MsgType::AnalysisResponse,
            0,
            &body,
        )));

        let data = ANALYSIS_CACHE.read();
        assert_eq!(data.udp_ports.len(), 64, "声明值超出容量应夹到容量");
        assert_eq!(data.icmp_types.len(), 0);
        assert_eq!(data.port_scanners.len(), 1);
        assert_eq!(data.port_scanners[0].ip, mid.to_string());
        assert_eq!(data.port_scanners[0].metric, 9);
        assert_eq!(data.port_scanners[0].packets, 42);
        assert_eq!(data.service_probes.len(), 0);
        assert_eq!(data.ip_total_count, 100);
    }

    #[test]
    fn a_paged_reply_that_reaches_the_event_path_is_flagged() {
        let _guard = serial();
        let c = Consumer::new();
        // 分页回复本应由 Client 的配对表认领；落到事件路径属异常，只记日志不处理。
        let msg = whitelist_page(&[("192.0.2.1".parse().expect("测试地址"), 32, "")]);
        assert!(!c.process(&msg), "分页回复不应报告状态变化");
    }

    // ---- 事件体构造：按契约偏移拼装，保证与解码器同源 ----

    /// 封禁状态变更事件体（`action` 决定封禁还是解封；`duration` 为 0 表示永久）。
    fn ban_state_change_body(
        action: contract::BanAction,
        ip: &str,
        reason: &str,
        jail: &str,
        duration: u32,
    ) -> Vec<u8> {
        let off = contract::BanStateChange::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::BanStateChange::WIRE_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(off, "af"),
            &[contract::AddrFamily::Inet.to_raw()],
        );
        body[body_off(off, "action")] = action.to_raw();
        put(
            &mut body,
            body_off(off, "duration_secs"),
            &duration.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "addr"),
            &ip_bytes(ip.parse().expect("测试地址")),
        );
        put(
            &mut body,
            body_off(off, "reason"),
            &fixed_field(reason, TEXT32),
        );
        put(
            &mut body,
            body_off(off, "jail_name"),
            &fixed_field(jail, TEXT32),
        );
        body
    }

    /// DDoS 事件体。
    fn ddos_event_body(ip: &str, reason: &str, rate_pps: u32) -> Vec<u8> {
        let off = contract::DdosEvent::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::DdosEvent::WIRE_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(off, "af"),
            &[contract::AddrFamily::Inet.to_raw()],
        );
        put(
            &mut body,
            body_off(off, "reason"),
            &fixed_field(reason, TEXT32),
        );
        put(
            &mut body,
            body_off(off, "rate_pps"),
            &rate_pps.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "addr"),
            &ip_bytes(ip.parse().expect("测试地址")),
        );
        body
    }

    /// 白名单状态变更事件体（动作由 `is_add` 决定，`prefix_len` 为主机位未清零的前缀）。
    fn whitelist_event_body(
        ip: &str,
        prefix_len: u8,
        device: &str,
        whitelist_count: u32,
        is_add: bool,
    ) -> Vec<u8> {
        let off = contract::WhitelistStateChange::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::WhitelistStateChange::WIRE_SIZE - codec::HDR_LEN];
        let action = if is_add {
            contract::WhitelistAction::Add
        } else {
            contract::WhitelistAction::Remove
        };
        body[body_off(off, "action")] = action.to_raw();
        put(
            &mut body,
            body_off(off, "af"),
            &[contract::AddrFamily::Inet.to_raw()],
        );
        body[body_off(off, "prefix_len")] = prefix_len;
        put(
            &mut body,
            body_off(off, "addr"),
            &ip_bytes(ip.parse().expect("测试地址")),
        );
        put(
            &mut body,
            body_off(off, "device"),
            &fixed_field(device, TEXT16),
        );
        put(
            &mut body,
            body_off(off, "whitelist_count"),
            &whitelist_count.to_be_bytes(),
        );
        body
    }

    /// 命令失败通知体。
    fn cmd_result_body(original: contract::MsgType, error_code: i32, ip: IpAddr) -> Vec<u8> {
        let off = contract::CmdResult::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::CmdResult::WIRE_SIZE - codec::HDR_LEN];
        put(
            &mut body,
            body_off(off, "original_cmd"),
            &original.to_raw().to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "error_code"),
            &error_code.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "af"),
            &[match ip {
                IpAddr::V4(_) => contract::AddrFamily::Inet.to_raw(),
                IpAddr::V6(_) => contract::AddrFamily::Inet6.to_raw(),
            }],
        );
        put(&mut body, body_off(off, "addr"), &ip_bytes(ip));
        body
    }

    // ---- 纯函数：推断链与命名表 ----

    #[test]
    fn ban_origin_inference_matches_the_legacy_chain() {
        // 显式 jail 名优先于关键词。
        assert_eq!(
            infer_ban_origin("SYN flood detected", "sshd"),
            ("SYN flood detected".to_string(), "sshd".to_string())
        );
        // 无 jail 名 + DDoS 关键词 → ddos。
        assert_eq!(
            infer_ban_origin("SYN flood detected", ""),
            ("SYN flood detected".to_string(), "ddos".to_string())
        );
        // jail 名存在但 reason 为空 → 两者都用 jail 名。
        assert_eq!(
            infer_ban_origin("", "sshd"),
            ("sshd".to_string(), "sshd".to_string())
        );
        // api: 前缀被剥掉，jail 归 api。
        assert_eq!(
            infer_ban_origin("api:repeated failures", ""),
            ("repeated failures".to_string(), "api".to_string())
        );
        // 三条固定来源串的最后一档。
        assert_eq!(
            infer_ban_origin("whitelist", ""),
            ("whitelist".to_string(), "system".to_string())
        );
        // 认不出的 reason 兜底归 api。
        assert_eq!(
            infer_ban_origin("something else", ""),
            ("something else".to_string(), "api".to_string())
        );
    }

    #[test]
    fn kernel_side_jail_inference_matches_the_legacy_rules() {
        // jail 为空且 reason 含关键词 → ddos。
        assert_eq!(
            infer_kernel_jail("UDP flood", ""),
            ("UDP flood".to_string(), "ddos".to_string())
        );
        // "kernel" 是内核的占位名，同样走推断；reason 为空时回落到 api。
        assert_eq!(
            infer_kernel_jail("", "kernel"),
            ("api".to_string(), "api".to_string())
        );
        // 显式 jail 名不在关键词表里 → 沿用，reason 原样。
        assert_eq!(
            infer_kernel_jail("failed", "sshd"),
            ("failed".to_string(), "sshd".to_string())
        );
    }

    #[test]
    fn the_command_name_table_covers_the_four_known_types() {
        assert_eq!(cmd_name(2), "BanIp");
        assert_eq!(cmd_name(3), "UnbanIp");
        assert_eq!(cmd_name(12), "AddWhitelist");
        assert_eq!(cmd_name(13), "RemoveWhitelist");
        assert_eq!(cmd_name(7), "Unknown");
    }
}
