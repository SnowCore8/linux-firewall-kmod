//! 内核轮询执行体：租约持有 + 周期拉取。
//!
//! # 为什么独立于 `kernel/`
//!
//! [`crate::kernel`] 是纯传输层（「字节 ↔ 语义类型」+ 请求/响应配对）；把拉回来的数据
//! 落地进缓存与状态镜像属于业务动作，故与 [`crate::inbound`] 同级放在 `kernel/` 之外。
//! 本模块是旧 `main.rs` 那条 `netlink-stats-poll` 线程与 `file_monitor::monitor_loop`
//! 那条 2 秒速率/基线段落的合并落点。
//!
//! # 为什么周期任务不能挂在事件循环上
//!
//! 旧实现两条路径都以「`poll` 超时」或「固定 sleep」为节拍：事件洪泛时 `poll` 超时被
//! 不断推后，速率查询与基线下发被饿死（结构问题 A）。本模块以单调时钟为节拍源——
//! 睡眠显式睡到下一个到期时刻（[`Shutdown::wait_until`]），到期判据是「经过时间」，
//! 与事件吞吐无关。
//!
//! # 为什么是「1 秒基础节拍 + 各自门控」
//!
//! 若把每个子周期做成独立定时器，其周期在登记时就被钉死，将来想让间隔跟随配置就得
//! 重启进程。基础节拍 + 门控让每个子任务的间隔都能在下一轮改掉。
//!
//! # 租约归属
//!
//! 内核只承认**一个** daemon portid，且静默超过 30 秒（[`crate::kernel::lease::KERNEL_LEASE_TTL`]）
//! 即允许别的 portid 接管。续约必须「足够频繁、且与拉取共用同一条序列」——若续约挂在
//! 另一条线程上，两条线程各自向同一 socket `sendto`，「谁在续约」就不可复现。故
//! [`Poller`] **持有租约**：组合根同步调一次 [`Poller::startup`] 完成注册与启动快照，
//! 随后把同一个 `Poller` 交给执行体做周期续约与拉取。拉取本身也是向内核发报文，按内核
//! `fw_nl_daemon_activity = jiffies` 的语义同样算活跃信号。

use std::time::{Duration, Instant};

use crate::kernel::client::{Client, RequestError};
use crate::kernel::lease::{Lease, LeaseState};
use crate::kernel::{PAGE_TIMEOUT, REQUEST_TIMEOUT};
use crate::runtime::{Shutdown, Supervisor};

/// 基础节拍。其余子周期都按它是整数倍门控。
const TICK: Duration = Duration::from_secs(1);

/// 续约间隔。必须显著短于内核租约上限（30 秒）。
///
/// 1 秒 = 租约上限的 1/30：允许连续 29 次续约失败而不失联，对调度抖动与内核瞬时繁忙
/// 都有充足余量，同时让「失联」在 30 秒内必然暴露。
const RENEW_INTERVAL: Duration = Duration::from_secs(1);

/// 速率/基线刷新周期（旧 `monitor_loop` 取 2 秒，间隔值不变）。
const RATES_INTERVAL: Duration = Duration::from_secs(2);

/// 封禁表全量对账周期（旧实现「每 60 个 tick」，即 60 秒）。
///
/// 对账要遍历整张封禁表，比读几个计数器的代价高一个量级，故只作为「事件丢失后的兜底」
/// 低频执行。间隔值不变。
const BANS_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// 分析数据刷新周期。
///
/// 旧实现每个 tick 都查一次；分析表（包大小/TTL 分布/端口与扫描者 Top-N）变化远慢于
/// 统计计数器，5 秒足够让界面「看起来是实时的」，同时把那部分内核侧遍历开销降为 1/5。
const ANALYSIS_INTERVAL: Duration = Duration::from_secs(5);

/// 租约状态的进程内快照。
///
/// `state`（枚举）与 `losses`（计数）必须成对更新，故合成一个结构、用一把锁保护；
/// 拆成两个独立原子量会让读者看到「已失联但计数未加」的中间态。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct LeaseStatus {
    /// 对应 [`LeaseState`]；`None` 表示本进程还没有内核链路执行体。
    state: Option<LeaseState>,
    /// 累计失联次数。
    losses: u64,
}

/// 由组合根持有、供 `/health` 读取的租约状态单元。
///
/// [`LeaseCell::state`] 返回 `Option`：「本进程没有内核链路执行体」与「有执行体但尚未
/// 注册」是两件事，调用方需自行区分。
#[derive(Debug, Default)]
pub struct LeaseCell {
    inner: parking_lot::Mutex<LeaseStatus>,
}

impl LeaseCell {
    /// 新建未注入的状态单元。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前租约状态。
    #[must_use]
    pub fn state(&self) -> Option<LeaseState> {
        self.inner.lock().state
    }

    /// 累计失联次数。
    #[must_use]
    pub fn losses(&self) -> u64 {
        self.inner.lock().losses
    }

    /// 一次写入状态与计数。
    fn publish(&self, status: LeaseStatus) {
        *self.inner.lock() = status;
    }
}

/// 周期拉取与租约续期的执行体。
///
/// 组合根先同步调 [`Poller::startup`]（注册 + 启动快照），再把同一个对象交给
/// [`spawn`] 托管。`Poller` 一旦交给执行体就只被那一条线程访问，故各门控字段用
/// `&mut self` 而非原子量。
pub struct Poller {
    client: Client,
    lease: Lease,
    cell: std::sync::Arc<LeaseCell>,
    /// 各子任务上次执行的时刻；`None` 表示尚未跑过（下一轮立即到期）。
    last_analysis: Option<Instant>,
    last_rates: Option<Instant>,
    last_reconcile: Option<Instant>,
    /// 上次下发的**有效**基线（已含高峰期上调）。
    last_baseline: (u64, u64),
}

impl Poller {
    /// 组装轮询器（租约尚未争夺）。
    #[must_use]
    pub fn new(client: Client, cell: std::sync::Arc<LeaseCell>) -> Self {
        Self {
            client,
            lease: Lease::new(),
            cell,
            last_analysis: None,
            last_rates: None,
            last_reconcile: None,
            last_baseline: (0, 0),
        }
    }

    /// 启动期同步动作：争夺租约，成功后拉一遍全量快照。
    ///
    /// # 为什么必须同步、且必须在组合根
    ///
    /// 启动快照要在**可信 IP 写入之前**完成：`ban::init_trusted_ips` 会往本地
    /// `WHITELIST_CACHE` 追加条目，若快照后到，它会用内核侧旧表整体覆盖，把刚写入的
    /// 可信 IP 从本地缓存里抹掉。旧实现靠「`sleep(500ms)`」赌内核回得快——这里改为
    /// 同步等真正的回复（超时由 [`REQUEST_TIMEOUT`] / [`PAGE_TIMEOUT`] 界定）。
    ///
    /// # Errors
    ///
    /// 内核**明确拒绝**注册（已有活跃守护进程持有租约）时返回错误，组合根据此记录
    /// ERROR 并以非零码退出，交给服务管理器的重启策略重试。
    ///
    /// 确认**未到达**（超时 / 瞬时链路问题）只告警并继续：那类失败有自愈余地，直接
    /// 让一个本可恢复的部署陷入重启循环并不划算；执行体会在后续节拍持续重试。
    pub fn startup(&mut self) -> anyhow::Result<()> {
        match self.lease.acquire(&self.client, REQUEST_TIMEOUT) {
            Ok(LeaseState::Held) => {
                self.publish_lease();
                crate::logger::info!(crate::logger::get(), "已向内核注册为唯一守护进程");
            }
            Ok(state) => {
                self.publish_lease();
                anyhow::bail!(
                    "内核拒绝注册（已有活跃守护进程持有租约，状态 {state:?}）；退出交给服务管理器重试"
                );
            }
            Err(e) => {
                self.publish_lease();
                crate::logger::error!(
                    crate::logger::get(),
                    "内核注册未获确认，将在后续节拍重试";
                    "error" => %e
                );
            }
        }

        // 启动快照：四张表各拉一次。**白名单只在启动时全量拉取**——之后靠内核推送的
        // `WhitelistStateChange` 增量维护（旧实现同样如此，此处保持行为不变）。
        match self.client.query_stats(REQUEST_TIMEOUT) {
            Ok(stats) => crate::inbound::apply_stats(&stats),
            Err(e) => Self::note("startup_stats", &e),
        }
        match self.client.query_analysis(REQUEST_TIMEOUT) {
            Ok(analysis) => crate::inbound::apply_analysis(&analysis),
            Err(e) => Self::note("startup_analysis", &e),
        }
        match self.client.list_rates_all(PAGE_TIMEOUT) {
            Ok(snapshot) => crate::inbound::apply_rates(&snapshot),
            Err(e) => Self::note("startup_rates", &e),
        }
        match self.client.list_bans_all(PAGE_TIMEOUT) {
            Ok(entries) => {
                crate::inbound::reconcile_bans(&entries);
            }
            Err(e) => Self::note("startup_bans", &e),
        }
        match self.client.list_whitelist_all(PAGE_TIMEOUT) {
            Ok(entries) => crate::inbound::apply_whitelist_all(&entries),
            Err(e) => Self::note("startup_whitelist", &e),
        }

        // 启动快照已就位，把门控起点记下：执行体的首轮不再重复拉一遍同样的数据。
        let now = Instant::now();
        self.last_analysis = Some(now);
        self.last_rates = Some(now);
        self.last_reconcile = Some(now);
        Ok(())
    }

    /// 执行体主循环：按 1 秒节拍续约与拉取，直到关停被请求。
    fn run(&mut self, watch: Shutdown) {
        let mut next = Instant::now() + TICK;
        while !watch.is_shutdown() {
            next += TICK;
            let now = Instant::now();
            if next <= now {
                // 落后一个周期以上：跳到当前时刻之后，**不补发**欠账，避免醒来后突发
                // 一串回调（与 `runtime::timers` 的重排语义一致）。
                next = now + TICK;
            }
            if watch.wait_until(next) {
                break;
            }
            self.tick(Instant::now());
        }
    }

    /// 每个节拍执行一次：先续约，再按各自门控拉取。
    fn tick(&mut self, now: Instant) {
        self.renew_lease(now);
        self.poll_stats();
        if Self::due(&mut self.last_analysis, now, ANALYSIS_INTERVAL) {
            self.poll_analysis();
        }
        if Self::due(&mut self.last_rates, now, RATES_INTERVAL) {
            self.poll_rates_and_baseline();
        }
        if Self::due(&mut self.last_reconcile, now, BANS_RECONCILE_INTERVAL) {
            self.poll_bans_reconcile();
        }
    }

    /// 把租约状态与失联计数发布给 `/health`。
    fn publish_lease(&self) {
        self.cell.publish(LeaseStatus {
            state: Some(self.lease.state()),
            losses: self.lease.losses(),
        });
    }

    /// 续约或（首次/失联后）重新争夺租约。
    ///
    /// `Lease::renew` 在未持有租约时是空操作，故这里先问状态：非 `Held` 才走 `acquire`，
    /// 避免每轮都去和一个健康持有者抢。
    fn renew_lease(&mut self, now: Instant) {
        if self.lease.state() == LeaseState::Held && !self.lease.needs_renewal(now, RENEW_INTERVAL)
        {
            return;
        }
        let before = self.lease.state();
        let outcome = if before == LeaseState::Held {
            self.lease.renew(&self.client, REQUEST_TIMEOUT)
        } else {
            self.lease.acquire(&self.client, REQUEST_TIMEOUT)
        };
        match outcome {
            Ok(state) => {
                // 只在状态真的变了时记日志：1 秒一次的成功续约不该刷屏。
                if state != before {
                    crate::logger::info!(
                        crate::logger::get(),
                        "内核租约状态变更";
                        "from" => format!("{before:?}"),
                        "to" => format!("{state:?}")
                    );
                }
            }
            Err(e) => {
                // `Lease` 已把状态置为 `Lost`；这里补上有诊断价值的上下文。
                crate::logger::error!(
                    crate::logger::get(),
                    "内核租约确认失败";
                    "error" => %e,
                    "losses" => self.lease.losses()
                );
            }
        }
        self.publish_lease();
    }

    /// 任一「已确认」请求的失败都只记日志：单次失败不该停掉整条轮询链，
    /// 下一节的节拍会自然重试。
    fn note(what: &'static str, err: &RequestError) {
        crate::logger::warn!(
            crate::logger::get(),
            "内核查询失败";
            "what" => what,
            "error" => %err
        );
    }

    /// 查询统计计数器并落地。
    fn poll_stats(&self) {
        match self.client.query_stats(REQUEST_TIMEOUT) {
            Ok(stats) => crate::inbound::apply_stats(&stats),
            Err(e) => Self::note("stats", &e),
        }
    }

    /// 查询分析数据并落地。
    fn poll_analysis(&self) {
        match self.client.query_analysis(REQUEST_TIMEOUT) {
            Ok(analysis) => crate::inbound::apply_analysis(&analysis),
            Err(e) => Self::note("analysis", &e),
        }
    }

    /// 拉取整张速率表并落地，随后下发基线。
    ///
    /// 顺序不能颠倒：基线来自速率样本推出来的 EWMA，先落地再下发，内核用到的是本轮的
    /// 观察值。基线下发是本模块唯一会**写**内核的周期动作，与速率落在同一轮次里，
    /// 复刻旧 `monitor_loop` 的次序。
    fn poll_rates_and_baseline(&mut self) {
        match self.client.list_rates_all(PAGE_TIMEOUT) {
            Ok(snapshot) => crate::inbound::apply_rates(&snapshot),
            Err(e) => Self::note("rates", &e),
        }
        self.push_baseline();
    }

    /// 拉取整张封禁表并对账本地缓存。
    fn poll_bans_reconcile(&self) {
        match self.client.list_bans_all(PAGE_TIMEOUT) {
            Ok(entries) => {
                crate::inbound::reconcile_bans(&entries);
            }
            Err(e) => Self::note("bans_reconcile", &e),
        }
    }

    /// 把当前基线下发到内核（动态阈值）。
    ///
    /// **这是缺陷 L 的修复落点**：旧实现 `file_monitor/monitor_loop.rs::send_baseline_update`
    /// 自建 `ConfigUpdate`，绕过了「配置 → 内核」的唯一实现。现在基线走同一条
    /// [`Client::set_config`]：字段集合、字节序转换、采纳/拒绝位图的处理只有一处。
    ///
    /// 基线为零时不下发（尚未收敛）；高峰期（UTC 9-18 点）上调 50%；有效值未变化时跳过，
    /// 避免每 2 秒重复写同一份。
    fn push_baseline(&mut self) {
        let pps = crate::types::get_baseline_pps();
        let bps = crate::types::get_baseline_bps();
        if pps == 0 && bps == 0 {
            return;
        }

        let (pps, bps) = if crate::decision::is_baseline_peak_hours() {
            (pps * 3 / 2, bps * 3 / 2)
        } else {
            (pps, bps)
        };

        if self.last_baseline == (pps, bps) {
            return;
        }
        self.last_baseline = (pps, bps);

        let change = crate::kernel::codec::SetConfig {
            flags: crate::contract::config_flags::BASELINE_UPDATE,
            baseline_pps: pps,
            baseline_bps: bps,
            ..Default::default()
        };
        match self.client.set_config(&change, REQUEST_TIMEOUT) {
            Ok(ack) => crate::inbound::apply_config_ack(&ack),
            Err(e) => Self::note("baseline", &e),
        }
    }

    /// 门控：`None` 表示尚未跑过（立即执行），否则按间隔比较。
    ///
    /// 显式 `match` 而非 `Option::is_none_or`：后者需 Rust 1.82，本仓库 MSRV 是 1.75。
    fn due(slot: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
        match slot {
            None => {
                *slot = Some(now);
                true
            }
            Some(last) if now.duration_since(*last) >= interval => {
                *last = now;
                true
            }
            Some(_) => false,
        }
    }
}

/// 把已经完成启动同步的轮询器交给执行体托管。
///
/// # Errors
///
/// 线程创建失败时返回 [`std::io::Error`]。
pub fn spawn(sup: &mut Supervisor, token: Shutdown, mut poller: Poller) -> std::io::Result<()> {
    let watch = token.clone();
    sup.spawn("kernel-poll", token, move || poller.run(watch))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn a_gate_fires_immediately_then_waits_for_the_interval() {
        let mut slot: Option<Instant> = None;
        let t0 = Instant::now();
        assert!(
            Poller::due(&mut slot, t0, RATES_INTERVAL),
            "未跑过的门控必须立即到期"
        );
        assert!(
            !Poller::due(&mut slot, t0 + Duration::from_millis(1500), RATES_INTERVAL),
            "未到间隔不应到期"
        );
        assert!(
            Poller::due(&mut slot, t0 + RATES_INTERVAL, RATES_INTERVAL),
            "到间隔即到期"
        );
    }

    #[test]
    fn lease_state_and_losses_are_published_as_a_pair() {
        // state 与 losses 一次写入、一次读出：读者不应看到「已失联但计数未加」。
        let cell = LeaseCell::new();
        assert_eq!(cell.state(), None, "未注入时状态为空");
        assert_eq!(cell.losses(), 0);

        cell.publish(LeaseStatus {
            state: Some(LeaseState::Lost),
            losses: 3,
        });
        assert_eq!(cell.state(), Some(LeaseState::Lost));
        assert_eq!(cell.losses(), 3);
    }

    #[test]
    fn each_sub_task_gates_on_its_own_interval() {
        // 1 秒基础节拍下：统计无门控（每轮都跑）；分析 5s、速率 2s、对账 60s。
        let now = Instant::now();
        let mut analysis = Some(now);
        let mut rates = Some(now);
        let mut reconcile = Some(now);

        // 下一轮（1 秒后）三个子任务都还没到期。
        let t1 = now + TICK;
        assert!(!Poller::due(&mut analysis, t1, ANALYSIS_INTERVAL));
        assert!(!Poller::due(&mut rates, t1, RATES_INTERVAL));
        assert!(!Poller::due(&mut reconcile, t1, BANS_RECONCILE_INTERVAL));

        // 第 3 轮（3 秒后）：速率（2s）已到期，分析（5s）与对账（60s）还没有。
        let t3 = now + TICK * 3;
        assert!(!Poller::due(&mut analysis, t3, ANALYSIS_INTERVAL));
        assert!(Poller::due(&mut rates, t3, RATES_INTERVAL));
        assert!(!Poller::due(&mut reconcile, t3, BANS_RECONCILE_INTERVAL));

        // 第 61 轮（61 秒后）：三者全部到期。
        let t61 = now + TICK * 61;
        assert!(Poller::due(&mut analysis, t61, ANALYSIS_INTERVAL));
        assert!(Poller::due(&mut rates, t61, RATES_INTERVAL));
        assert!(Poller::due(&mut reconcile, t61, BANS_RECONCILE_INTERVAL));
    }

    /// 组装一个「有 socket、但内核模块未加载」的轮询器。
    ///
    /// 本机没加载内核模块时向内核 portid 发报文会拿到错误，故注册必然走
    /// 「确认未到达」分支——正好用来钉住「可自愈类失败必须放行」这条策略。
    fn an_unbacked_poller() -> (Poller, Arc<LeaseCell>) {
        let transport = Arc::new(crate::kernel::transport::Transport::open().expect("建 socket"));
        let (router, _rx, _stats, _live) =
            crate::kernel::reactor::event_channel(crate::kernel::reactor::default_event_queue());
        let client = Client::new(transport, router);
        let cell = Arc::new(LeaseCell::new());
        (Poller::new(client, Arc::clone(&cell)), cell)
    }

    #[test]
    fn an_unconfirmed_registration_is_tolerated_at_startup() {
        // 「内核明确拒绝」那一分支无法在本机造出来（要么模块未加载、要么已有进程持租），
        // 其状态机一侧由 `kernel::lease` 的用例覆盖。这里守住本模块的策略：
        // 确认**未到达**属于可自愈，必须放行。
        let (mut poller, cell) = an_unbacked_poller();
        let outcome = poller.startup();
        assert!(
            outcome.is_ok(),
            "确认未到达应放行（可自愈类失败），实得 {outcome:?}"
        );
        assert!(cell.state().is_some(), "启动期就应把租约状态发布给 /health");
        // 启动快照无论成败都要把门控起点记下，否则执行体首轮会立刻重复拉一遍。
        assert!(poller.last_analysis.is_some());
        assert!(poller.last_rates.is_some());
        assert!(poller.last_reconcile.is_some());
    }

    #[test]
    fn the_executor_stops_promptly_while_idle_between_ticks() {
        // 关停延迟不应被 1 秒节拍拖长：`wait_until` 必须被关停令牌立刻唤醒。
        let (mut poller, _cell) = an_unbacked_poller();
        poller.startup().expect("启动同步应放行");
        let mut sup = Supervisor::new();
        let token = Shutdown::new();
        spawn(&mut sup, token.clone(), poller).expect("登记执行体");
        assert_eq!(sup.len(), 1);

        let start = Instant::now();
        token.request();
        let results = sup.shutdown(Duration::from_secs(5));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, crate::runtime::StopOutcome::Joined);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "关停应即时，实耗 {:?}",
            start.elapsed()
        );
    }
}
