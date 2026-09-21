//! 入站主链路执行体：inotify 监视 → 按源增量读 → 行切分/规则匹配 → 阈值判定 → 封禁下发。
//!
//! 这是设计文档「运行时模型」里 `ingest` + `parse` + `decision` + `pipeline` 四段在
//! **生产路径**上的唯一装配点，由单个线程顺序驱动（旧 `file_monitor::monitor_loop`
//! 的位置）。四段共用同一份「按源读取偏移 + 按源半行缓冲 + 按 jail 失败窗口」状态，
//! 顺序执行即天然串行：段与段之间不需要有界 channel，也就不存在「队列满时丢字节」。
//! 设计文档把 ingest / parse 分成两个线程（各自的有界队列与背压策略）是**多线程**
//! 形态；本批只切主链路，线程拆分留待后续——它会引入「谁独占 splitter」的新问题，
//! 不能顺手做。
//!
//! # 一轮迭代的顺序
//!
//! 1. 跑到期维护（单调时钟定时器，与事件流量解耦）；
//! 2. 把 Web UI 改的 `GLOBAL_JAILS[].enabled` 桥接进本地配置，有变化则重建监视集合；
//! 3. 补挂「轮转后路径暂时不可见」的源（见 [`InboundExecutor::retry_pending_readd`]）；
//! 4. `poll` 同时等 **inotify fd** 与 **signalfd**，超时上限取「`interval` 秒」与
//!    「下一个定时器到期点」的较小者；
//! 5. 分派：信号（终止 / 重载 / 回滚）与 inotify 事件（读新增字节 → 判定 → 下发）。
//!
//! # 与旧主循环的关键差异（都是有意为之）
//!
//! - **文件身份是 [`SourceId`] 而非 `Vec` 下标**：重载与轮转不再让身份漂移；
//! - **长驻 fd + 长驻读缓冲**：不再是每个事件「打开 + 分配 256 KiB + seek」；
//! - **信号是 fd 不是 `EINTR` 协议**：不再依赖「打断 `poll` 交回控制权」；
//! - **周期维护走 [`TimerTable`]**：不再挂在 `poll` 超时上，事件洪泛不会饿死维护；
//! - **轮转后从文件头读并补一次立即读**：挂 watch 之前写入的内容不会丢（旧实现
//!   在这条路径上依赖「新文件已存在」这一时序假设）。
//!
//! # 副作用归属
//!
//! 判定层只产出 [`BanIntent`]（纯内存结论）；**下发与本地镜像在本执行体内完成**
//! （旧 `handle_failed_attempt_for_jail` 的位置）。顺序逐条对齐旧实现：抢缓存锁插入 →
//! 镜像新状态 → 置待确认标记 → `ban::ban_ip` → 失败时回滚这三处。`ban/operations.rs`
//! 明确「下发失败后回滚本地缓存是调用方的事」，故这个责任必须由调用方承担。

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use inotify::WatchDescriptor;

use crate::ban;
use crate::config_reloader;
use crate::decision::is_baseline_peak_hours;
use crate::http_exporter;
use crate::ingest::{
    log_file_watch_mask, SourceId, SourceOwner, SourceReader, SourceRegistry, WatchEvent, Watcher,
};
use crate::parse::{Rule, RuleSet};
use crate::pipeline::{BanIntent, Counters, DecisionFacts, JailPolicy, Pipeline, Tick};
use crate::runtime::{Fired, Shutdown, TimerId, TimerTable};
use crate::signal::{Signal, SignalFd};
use crate::types::{
    clear_pending_ban_ack, mark_pending_ban_ack, now_secs, with_jail_stats, ActiveBanCache,
    BanHistory, BanInfo, Config, Jail, ACTIVE_BAN_CACHE, BAN_HISTORY, DAEMON_STATS,
};

/// 失败窗口清理周期（与旧 `monitor_loop` 的 60 秒一致）。
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
/// 监视集合重扫周期（对应旧 `check_for_new_log_files` 的 60 秒）。
///
/// 覆盖「启动时不存在、之后才创建的日志文件」；轮转待重挂的源不受这个周期约束，
/// 走每轮的 [`InboundExecutor::retry_pending_readd`]。
const RESCAN_INTERVAL: Duration = Duration::from_secs(60);
/// 历史快照周期（与旧实现的 5 分钟一致）。
const HISTORY_INTERVAL: Duration = Duration::from_secs(300);
/// 数据清理周期（与旧实现的 5 分钟一致）。
const DATA_CLEANUP_INTERVAL: Duration = Duration::from_secs(300);
/// 待重挂源的轮询上限：轮转后新文件出现即挂上，不必等 [`RESCAN_INTERVAL`]。
const PENDING_READD_RETRY: Duration = Duration::from_secs(1);

/// 判定所需外部事实的生产实现：信誉分 + 封禁历史。
///
/// 判定层通过 [`DecisionFacts`] 拿这两项，因此本层是唯一接触这两个全局态的地方。
/// `record_failure` 只记信誉分：`DAEMON_STATS.failed_attempts` 与 per-jail 计数在
/// [`mirror_counters`] 里按差值统一镜像，避免同一次失败在两处各加一遍。
#[derive(Debug, Default, Clone, Copy)]
struct LiveFacts;

impl DecisionFacts for LiveFacts {
    fn record_failure(&self, ip: IpAddr) {
        crate::ip_reputation::get_store().record_failure(&ip.to_string());
    }

    fn reputation_score(&self, ip: IpAddr) -> u32 {
        crate::ip_reputation::get_store().get_score(&ip.to_string())
    }

    fn prior_ban_count(&self, ip: IpAddr) -> u32 {
        BAN_HISTORY
            .get_or_init(BanHistory::new)
            .get_ban_count(&ip.to_string())
    }
}

/// 周期任务定时器集合。
struct Timers {
    table: TimerTable,
    cleanup: TimerId,
    rescan: TimerId,
    history: TimerId,
    data_cleanup: TimerId,
}

impl Timers {
    fn new() -> Self {
        let mut table = TimerTable::new(4);
        let first = Instant::now();
        let fail = "容量 4 的定时器表登记四个周期任务不应失败";
        // 首个到期点都是「当前 + 一个周期」：与旧实现「启动时把 last_* 置为 now」同义，
        // 即启动后不在第 0 秒抢跑一轮维护。
        let cleanup = table
            .every(CLEANUP_INTERVAL, first + CLEANUP_INTERVAL)
            .expect(fail);
        let rescan = table
            .every(RESCAN_INTERVAL, first + RESCAN_INTERVAL)
            .expect(fail);
        let history = table
            .every(HISTORY_INTERVAL, first + HISTORY_INTERVAL)
            .expect(fail);
        let data_cleanup = table
            .every(DATA_CLEANUP_INTERVAL, first + DATA_CLEANUP_INTERVAL)
            .expect(fail);
        Self {
            table,
            cleanup,
            rescan,
            history,
            data_cleanup,
        }
    }
}

/// `poll` 的唤醒来源。
#[derive(Debug, Default, Clone, Copy)]
struct Ready {
    /// signalfd 可读。
    signals: bool,
    /// inotify fd 可读。
    inotify: bool,
}

/// 入站主链路执行体。**由单个线程独占**，内部状态一律不加锁。
pub struct InboundExecutor {
    /// 当前生效的配置。本执行体是唯一的改写者（自动重载 / 回滚 / 启用状态同步）。
    cfg: Config,
    /// inotify fd 的唯一所有者。
    watcher: Watcher,
    /// 稳定身份 ↔ wd ↔ 路径。
    registry: SourceRegistry,
    /// 每个源的读取状态（长驻 fd + 长驻读缓冲）。
    readers: HashMap<SourceId, SourceReader>,
    /// 判定装配体（规则集 / 失败窗口 / 半行缓冲 / 计数）。
    pipeline: Pipeline,
    /// 信号 fd（与 inotify fd 并入同一个 `poll`）。
    signals: SignalFd,
    /// 判定事实源。
    facts: LiveFacts,
    /// 封禁意图复用缓冲，避免每批分配。
    intents: Vec<BanIntent>,
    /// 周期任务。
    timers: Timers,
    /// 轮转后路径暂时不可见、等待重挂的源。
    pending_readd: HashSet<PathBuf>,
}

impl InboundExecutor {
    /// 装配执行体：编译 jail 规则集、挂上初始 watch。
    ///
    /// # Errors
    /// inotify 初始化失败，或**一个源都挂不上**（配置错误 / 权限不足 / kmod 未加载）。
    /// 后者与旧 `file_monitor::setup_inotify` 的 `watched_count == 0` 语义一致：装配
    /// 即失败，由组合根以启动失败处理。
    pub fn new(cfg: Config, signals: SignalFd) -> Result<Self> {
        let watcher = Watcher::new().context("初始化 inotify 失败")?;
        let mut executor = Self {
            cfg,
            watcher,
            registry: SourceRegistry::new(),
            readers: HashMap::new(),
            pipeline: Pipeline::new(),
            signals,
            facts: LiveFacts,
            intents: Vec::new(),
            timers: Timers::new(),
            pending_readd: HashSet::new(),
        };
        executor.refresh_jails();
        executor.reconcile_watches();
        if executor.registry.is_empty() {
            bail!("No log files could be watched（没有任何可监视的日志源）");
        }
        crate::logger::info!(
            crate::logger::get(),
            "入站主链路已就绪";
            "sources" => executor.registry.len(),
            "jails" => executor.pipeline.jail_count()
        );
        Ok(executor)
    }

    /// 组合根读配置用（HTTP 端口、Web UI、jail 列表等装配参数）。
    ///
    /// 配置所有权在这里，是因为**只有本执行体改配置**（自动重载 / 回滚 / 启用状态
    /// 同步）；组合根若留一份副本，重载后就会与本执行体分叉。
    #[must_use]
    pub fn cfg(&self) -> &Config {
        &self.cfg
    }

    /// 主循环：阻塞直到关停令牌置位或链路异常。
    ///
    /// `stop` 是本执行体自己的关停令牌（`Supervisor` 逆序关停时置位）；`terminate`
    /// 是组合根等待的终止令牌——收到 SIGTERM/SIGINT 时置位它，让主线程从
    /// `Shutdown::wait` 醒来走清理流程。
    pub fn run(mut self, stop: Shutdown, terminate: Shutdown) {
        while !stop.is_shutdown() {
            let timeout = self.next_poll_timeout(Instant::now());
            if let Err(e) = self.step(timeout, &stop, &terminate) {
                crate::logger::error!(
                    crate::logger::get(),
                    "入站主链路异常退出";
                    "error" => %e
                );
                // 必须置位终止令牌：否则组合根会永远阻塞在 `wait` 上，而本线程已死。
                terminate.request();
                stop.request();
                break;
            }
        }
        crate::logger::info!(crate::logger::get(), "入站主链路已停止");
    }

    /// 一轮迭代（生产与测试共用，便于逐轮驱动断言）。
    fn step(&mut self, timeout: Duration, stop: &Shutdown, terminate: &Shutdown) -> io::Result<()> {
        self.run_due_maintenance();
        if stop.is_shutdown() {
            return Ok(());
        }
        self.sync_jail_enabled();
        self.retry_pending_readd();
        let ready = self.poll(timeout)?;
        if ready.signals {
            self.handle_signals(stop, terminate);
        }
        if ready.inotify {
            self.handle_inotify();
        }
        Ok(())
    }

    // ========================================================================
    // 等待与分派
    // ========================================================================

    /// 同时等 inotify fd 与 signalfd。
    fn poll(&self, timeout: Duration) -> io::Result<Ready> {
        let mut fds = [
            libc::pollfd {
                fd: self.watcher.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.signals.raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // 毫秒上限：`poll` 的 timeout 是 i32 毫秒，钳到上界避免溢出成负数（负数 =
        // 无限等待）。`interval` 由配置校验保证在 [1, 60] 秒内，正常路径远达不到上界。
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `fds` 是栈上长度 2 的 `pollfd` 数组，`nfds = 2` 与之严格一致；
        // 两个 fd 分别由 `Watcher` 与 `SignalFd` 独占持有，调用期间保持有效。
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
        if rc < 0 {
            let err = io::Error::last_os_error();
            // 被信号打断：不是错误，只是该重新等（本实现不依赖 `EINTR` 推进状态）。
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(Ready::default());
            }
            return Err(err);
        }
        Ok(Ready {
            inotify: fds[0].revents != 0,
            signals: fds[1].revents != 0,
        })
    }

    /// 下一轮 `poll` 的超时上限。
    fn next_poll_timeout(&self, now: Instant) -> Duration {
        let mut cap = Duration::from_secs(u64::from(self.cfg.interval.max(1)));
        if !self.pending_readd.is_empty() {
            // 有轮转待重挂的源：以 1 秒为上限轮询，直到路径重新出现。
            cap = cap.min(PENDING_READD_RETRY);
        }
        match self.timers.table.next_deadline() {
            Some(deadline) if deadline < now + cap => deadline.saturating_duration_since(now),
            _ => cap,
        }
    }

    /// 取走本轮全部待处理信号并分派。
    fn handle_signals(&mut self, stop: &Shutdown, terminate: &Shutdown) {
        loop {
            match self.signals.poll_read() {
                Ok(Some(Signal::Terminate)) => {
                    crate::logger::info!(crate::logger::get(), "收到终止信号，停止入站主链路");
                    terminate.request();
                    stop.request();
                    return;
                }
                Ok(Some(Signal::Reload)) => self.reload_config(),
                Ok(Some(Signal::Rollback)) => self.rollback_config(),
                Ok(None) => return,
                Err(e) => {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "读取 signalfd 失败";
                        "error" => %e
                    );
                    return;
                }
            }
        }
    }

    /// 读走本轮全部 inotify 事件并逐条处理。
    fn handle_inotify(&mut self) {
        let events = match self.watcher.read_events() {
            Ok(events) => events,
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "读取 inotify 事件失败";
                    "error" => %e
                );
                return;
            }
        };
        if events.is_empty() {
            return;
        }
        // 与旧实现同口径：**一次唤醒计一次**（不是事件条数），供
        // `firewall_daemon_inotify_events_total` 反映唤醒频率。
        DAEMON_STATS.inotify_events.fetch_add(1, Ordering::Relaxed);
        for event in &events {
            self.handle_event(event);
        }
    }

    /// 单条 inotify 事件的路由。
    fn handle_event(&mut self, event: &WatchEvent) {
        let Some(id) = self.registry.resolve(&event.wd) else {
            // 已被摘除的旧 watch（轮转后残留事件）：无主，丢弃。
            return;
        };
        let Some((owner, path)) = self
            .registry
            .get(id)
            .map(|entry| (entry.owner.clone(), entry.path.clone()))
        else {
            return;
        };

        if owner.is_config() {
            // 掩码判据与旧 `monitor_loop::handle_inotify_events` 的配置文件分支一致：
            // 内容变更或自身被移走都触发自动重载。
            if event.is_content_change() || event.is_self_gone() {
                crate::logger::info!(
                    crate::logger::get(),
                    "检测到配置文件变化，自动重载";
                    "path" => path.display().to_string()
                );
                self.reload_config();
            }
            return;
        }

        if event.is_content_change() {
            self.drain_source(id);
        }
        if event.is_self_gone() {
            self.handle_rotation(id, &path);
        }
    }

    // ========================================================================
    // 源的读取与判定
    // ========================================================================

    /// 读出某个源的新增字节并送进判定。
    fn drain_source(&mut self, id: SourceId) {
        let Some((jail, path)) = self.registry.get(id).and_then(|entry| {
            entry
                .owner
                .jail()
                .map(|j| (Arc::clone(j), entry.path.clone()))
        }) else {
            return;
        };
        // 读取器先从表中取出：`Chunk` 借用它自己的读缓冲（零拷贝），取成局部变量后，
        // `feed` 里再借 `self.pipeline` / `self.facts` 就不会与之冲突。
        let Some(mut reader) = self.readers.remove(&id) else {
            return;
        };
        let result = match reader.read_new(&path) {
            Ok(chunk) => {
                let rotated = chunk.rotated;
                self.feed(&jail, id, chunk.bytes, rotated);
                Ok(())
            }
            Err(e) => Err(e),
        };
        if let Err(e) = result {
            // 持有 fd 意外失效（seek 出错）：重置该源，下一轮重开。
            crate::logger::warn!(
                crate::logger::get(),
                "读取日志失败，重置该源";
                "path" => path.display().to_string(),
                "error" => %e
            );
            reader.reset();
        }
        self.readers.insert(id, reader);
    }

    /// 把一批新增字节喂给判定层，并镜像计数、下发意图。
    fn feed(&mut self, jail: &Arc<str>, id: SourceId, bytes: &[u8], rotated: bool) {
        if rotated {
            // 轮转 / 截断：旧文件的半行不得与新文件的开头拼接。
            self.pipeline.on_source_rotated(id);
        }
        if bytes.is_empty() {
            return;
        }
        let tick = self.tick();
        let before = self.pipeline.counters();
        self.intents.clear();
        let accepted =
            self.pipeline
                .on_chunk(jail, id, bytes, tick, &self.facts, &mut self.intents);
        let after = self.pipeline.counters();
        if !accepted {
            crate::logger::warn!(
                crate::logger::get(),
                "日志源归属的 jail 未注册，本批丢弃";
                "jail" => &**jail
            );
            return;
        }
        mirror_counters(jail, before, after);
        for intent in &self.intents {
            dispatch_intent(intent);
        }
        self.intents.clear();
    }

    /// 把某源挂起的半行当作完整行处理（源关闭 / 轮转前调用，与旧 `flush_partial_line`
    /// 时机一致），同样走计数镜像与意图下发。
    fn flush_pending_line(&mut self, jail: &Arc<str>, id: SourceId) {
        let tick = self.tick();
        let before = self.pipeline.counters();
        self.intents.clear();
        let accepted = self
            .pipeline
            .flush_source(jail, id, tick, &self.facts, &mut self.intents);
        let after = self.pipeline.counters();
        if !accepted {
            return;
        }
        mirror_counters(jail, before, after);
        for intent in &self.intents {
            dispatch_intent(intent);
        }
        self.intents.clear();
    }

    /// 判定用时间上下文：真实时钟 + 真实高峰判定。
    fn tick(&self) -> Tick {
        Tick::new(now_secs(), is_baseline_peak_hours())
    }

    // ========================================================================
    // 轮转与监视集合
    // ========================================================================

    /// 处理轮转（`MOVE_SELF` / `DELETE_SELF`）：flush 半行 → 摘旧 watch → 按当前路径
    /// 重挂（新 inode）并从文件头读起。
    ///
    /// 与旧 `log_rotation::handle_log_rotation` 同序，但补了两处旧实现会漏的地方：
    /// 路径暂时不可见时登记为待重挂（而不是等 60 秒的整表重建），以及挂 watch 后
    /// **立即读一次**（新文件在挂 watch 之前写入的内容不产生任何事件）。
    fn handle_rotation(&mut self, id: SourceId, path: &Path) {
        let Some(jail) = self
            .registry
            .get(id)
            .and_then(|entry| entry.owner.jail().cloned())
        else {
            return;
        };
        // 计数口径与旧实现一致：只有 `MOVE_SELF` / `DELETE_SELF` 记一次轮转，
        // 读取器自行发现的截断（copytruncate）不计——那条路径旧实现也不计。
        DAEMON_STATS.log_rotations.fetch_add(1, Ordering::Relaxed);

        // 旧文件最后那半行仍是证据：先 flush 再摘。
        self.flush_pending_line(&jail, id);
        self.drop_source(id);

        if path.exists() {
            if self.add_log_source(Arc::clone(&jail), path, true).is_none() {
                self.pending_readd.insert(path.to_path_buf());
            }
        } else {
            crate::logger::debug!(
                crate::logger::get(),
                "日志轮转后文件暂不可见，待重挂";
                "path" => path.display().to_string()
            );
            self.pending_readd.insert(path.to_path_buf());
        }
    }

    /// 重试「轮转后待重挂」的源。每轮都跑：路径一出现就挂上（上限 1 秒），
    /// 不必等 [`RESCAN_INTERVAL`]；失败保持静默（只有轮转那一次记 debug），避免
    /// 路径长期不出现时按秒刷日志。
    fn retry_pending_readd(&mut self) {
        if self.pending_readd.is_empty() {
            return;
        }
        let candidates: Vec<PathBuf> = self.pending_readd.iter().cloned().collect();
        for path in candidates {
            if self.registry.contains_path(&path) {
                self.pending_readd.remove(&path);
                continue;
            }
            if !path.exists() {
                continue;
            }
            let Some(jail) = self.jail_for_path(&path) else {
                // 配置里已不再监视该文件（或该 jail 被禁用）：交给重扫摘除。
                self.pending_readd.remove(&path);
                continue;
            };
            if self.add_log_source(jail, &path, true).is_some() {
                self.pending_readd.remove(&path);
                crate::logger::info!(
                    crate::logger::get(),
                    "轮转后的日志文件已重新挂载";
                    "path" => path.display().to_string()
                );
            }
        }
    }

    /// 按当前配置对齐监视集合：摘掉不再需要的，补挂/更新其余的。
    ///
    /// 这是启动、配置重载、jail 启用状态变化与周期重扫（[`RESCAN_INTERVAL`]）共用的
    /// **唯一**路径——旧实现把这四件事分别写成「重建整表」（`setup_inotify`）与
    /// 「发现新文件就重建整表」（`check_for_new_log_files`），重建会连带清空读取偏移，
    /// 且让身份随 `Vec` 下标漂移（结构问题 C）。这里只做增量增删，`SourceId` 保持稳定，
    /// 各源的读取偏移与半行缓冲不受影响。
    fn reconcile_watches(&mut self) {
        let mut keep: Vec<PathBuf> = Vec::new();
        if let Some(path) = &self.cfg.config_file {
            keep.push(PathBuf::from(path));
        }
        let logs = self.enabled_log_sources();
        for (_, path) in &logs {
            keep.push(path.clone());
        }

        let stale: Vec<SourceId> = self
            .registry
            .iter()
            .filter(|(_, entry)| !keep.contains(&entry.path))
            .map(|(id, _)| id)
            .collect();
        for id in stale {
            self.drop_source(id);
        }

        if let Some(path) = self.cfg.config_file.clone() {
            if !self.registry.contains_path(Path::new(&path)) {
                self.add_config_watch(&path);
            }
        }

        for (jail, path) in logs {
            if let Some((_, wd, inode)) = self.entry_for_path(&path) {
                // 已在监视：只更新归属（同一路径可能被改挂到别的 jail）。
                self.registry
                    .register(SourceOwner::Log { jail }, &path, wd, inode);
                continue;
            }
            // 待重挂的源从文件头读（新文件的内容从头算）；其余（新出现的文件）
            // 定位到末尾，不回放历史——与旧 `setup_inotify` 一致。
            let from_start = self.pending_readd.remove(&path);
            self.add_log_source(jail, &path, from_start);
        }

        // 已不再配置的路径不必再等。
        let configured: HashSet<&PathBuf> = keep.iter().collect();
        self.pending_readd.retain(|path| configured.contains(path));
    }

    /// 给一个日志文件挂 watch、登记身份、建读取器，并立即读一次。
    ///
    /// `from_start = false` 时定位到文件末尾（不回放历史）。
    fn add_log_source(
        &mut self,
        jail: Arc<str>,
        path: &Path,
        from_start: bool,
    ) -> Option<SourceId> {
        if path.is_symlink() {
            // 启动后文件被换成符号链接：拒绝（与旧 `setup_inotify` 的启动期拒绝同口径）。
            crate::logger::warn!(
                crate::logger::get(),
                "跳过符号链接日志文件";
                "path" => path.display().to_string()
            );
            return None;
        }
        if !path.exists() {
            crate::logger::debug!(
                crate::logger::get(),
                "日志文件不存在，跳过";
                "path" => path.display().to_string()
            );
            return None;
        }
        let wd = match self.watcher.add(path, log_file_watch_mask()) {
            Ok(wd) => wd,
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "添加 inotify watch 失败";
                    "path" => path.display().to_string(),
                    "error" => %e
                );
                return None;
            }
        };
        let inode = std::fs::metadata(path).map_or(0, |meta| meta.ino());
        let id = self
            .registry
            .register(SourceOwner::Log { jail }, path, wd, inode);
        let mut reader = SourceReader::new();
        if !from_start {
            reader.open_at_end(path);
        }
        self.readers.insert(id, reader);
        // 立即读一次：覆盖「内容先于 watch 到达」的窗口——最典型的是轮转后新文件在
        // 挂 watch 之前就被写入，此时不会有任何 inotify 事件来触发读取。
        self.drain_source(id);
        Some(id)
    }

    /// 给配置文件挂 watch。
    fn add_config_watch(&mut self, path: &str) -> bool {
        match self.watcher.add(Path::new(path), log_file_watch_mask()) {
            Ok(wd) => {
                let inode = std::fs::metadata(path).map_or(0, |meta| meta.ino());
                self.registry
                    .register(SourceOwner::Config, Path::new(path), wd, inode);
                crate::logger::info!(
                    crate::logger::get(),
                    "已添加配置文件监控";
                    "path" => path
                );
                true
            }
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "添加配置文件监控失败";
                    "path" => path,
                    "error" => %e
                );
                false
            }
        }
    }

    /// 摘除一个源：watch、读取器、半行缓冲全部回收。
    fn drop_source(&mut self, id: SourceId) {
        if let Some(entry) = self.registry.remove(id) {
            // 旧 wd 可能已随轮转失效：摘除失败只记 debug。
            if let Err(e) = self.watcher.remove(entry.wd) {
                crate::logger::debug!(
                    crate::logger::get(),
                    "摘除 inotify watch 失败";
                    "path" => entry.path.display().to_string(),
                    "error" => %e
                );
            }
        }
        if let Some(mut reader) = self.readers.remove(&id) {
            reader.reset();
        }
        self.pipeline.forget_source(id);
    }

    /// 按路径找登记项（路径数量是个位到百位量级，线性查找即可）。
    fn entry_for_path(&self, path: &Path) -> Option<(SourceId, WatchDescriptor, u64)> {
        self.registry
            .iter()
            .find(|(_, entry)| entry.path == path)
            .map(|(id, entry)| (id, entry.wd.clone(), entry.inode))
    }

    /// 当前配置里启用的日志源。
    fn enabled_log_sources(&self) -> Vec<(Arc<str>, PathBuf)> {
        let mut out = Vec::new();
        for jail in &self.cfg.jails {
            if !jail.enabled {
                continue;
            }
            let name: Arc<str> = Arc::from(jail.name.as_str());
            for file in &jail.log_files {
                out.push((Arc::clone(&name), PathBuf::from(file)));
            }
        }
        out
    }

    /// 找出监视该路径的 jail（按当前配置，取启用的）。
    fn jail_for_path(&self, path: &Path) -> Option<Arc<str>> {
        let text = path.to_string_lossy();
        self.cfg
            .jails
            .iter()
            .find(|jail| jail.enabled && jail.log_files.iter().any(|f| f.as_str() == text))
            .map(|jail| Arc::from(jail.name.as_str()))
    }

    // ========================================================================
    // 配置：重载 / 回滚 / 启用状态同步
    // ========================================================================

    /// SIGHUP（或配置文件自身变化）触发的热重载。
    fn reload_config(&mut self) {
        match config_reloader::reload_configuration(&mut self.cfg) {
            Ok(()) => crate::logger::info!(crate::logger::get(), "配置重载成功"),
            Err(e) => crate::logger::warn!(
                crate::logger::get(),
                "配置重载失败";
                "error" => %e
            ),
        }
        // 无论成功与否都按**当前** cfg 重建：失败时 `reload_configuration` 已把 cfg
        // 回滚成旧配置，重建即回到旧集合（重建是幂等的，重复调用无副作用）。
        self.refresh_jails();
        self.reconcile_watches();
    }

    /// SIGUSR1 触发的配置回滚。
    fn rollback_config(&mut self) {
        match config_reloader::rollback_config(&mut self.cfg) {
            Ok(()) => {
                crate::logger::info!(crate::logger::get(), "配置回滚成功");
                // 回滚会改 `max_retries` / `findtime` / `ban_time` 与启用状态，判定参数
                // 必须跟着走；监视集合与旧实现一致不重建（启用状态由下一步的
                // `sync_jail_enabled` 桥接覆盖）。
                self.refresh_jails();
            }
            Err(e) => crate::logger::warn!(
                crate::logger::get(),
                "配置回滚失败";
                "error" => %e
            ),
        }
    }

    /// 把 Web UI 改的 `GLOBAL_JAILS[].enabled` 桥接进本地配置。
    ///
    /// `GLOBAL_JAILS` 是启用状态的运行时权威源（`web_ui::api::update_jail_enabled`
    /// 只改它，再持久化到 YAML），旧 `monitor_loop` 也是每个 poll 周期做这同一件事，
    /// 然后靠重建 inotify 让禁用生效。
    fn sync_jail_enabled(&mut self) {
        let Some(lock) = http_exporter::GLOBAL_JAILS.get() else {
            return;
        };
        let mut changed = false;
        {
            let global_jails = lock.read();
            for global in global_jails.iter() {
                if let Some(local) = self.cfg.jails.iter_mut().find(|j| j.name == global.name) {
                    if local.enabled != global.enabled {
                        crate::logger::info!(
                            crate::logger::get(),
                            "Jail 启用状态同步";
                            "jail" => &global.name,
                            "enabled" => global.enabled
                        );
                        local.enabled = global.enabled;
                        changed = true;
                    }
                }
            }
        }
        if changed {
            self.reconcile_watches();
        }
    }

    /// 按当前配置重建各 jail 的规则集与判定参数（失败窗口由 `register_jail` 保留）。
    fn refresh_jails(&mut self) {
        let mut keep: Vec<Arc<str>> = Vec::with_capacity(self.cfg.jails.len());
        for jail in &self.cfg.jails {
            let name: Arc<str> = Arc::from(jail.name.as_str());
            let rules = rule_set_for(jail);
            let policy = JailPolicy::new(jail.max_retries, jail.findtime, jail.ban_time);
            self.pipeline.register_jail(rules, policy);
            keep.push(name);
        }
        // 配置里已消失的 jail 连同其失败窗口一并摘除：旧实现靠整体替换 `cfg.jails`
        // 达到同样效果，本层状态与配置分离，必须显式回收。
        let removed = self.pipeline.retain_jails(&keep);
        if removed > 0 {
            crate::logger::debug!(
                crate::logger::get(),
                "已摘除配置中不再存在的 jail";
                "removed" => removed
            );
        }
    }

    // ========================================================================
    // 周期维护
    // ========================================================================

    /// 跑到期维护任务。
    ///
    /// 四个任务的周期都按旧实现的节拍保留，但驱动源从「`poll` 超时」换成单调时钟
    /// 定时器（结构问题 A）：事件洪泛不再推迟维护。
    fn run_due_maintenance(&mut self) {
        let fired = self.timers.table.fire_due(Instant::now());
        let (cleanup, rescan, history, data_cleanup) = (
            self.timers.cleanup,
            self.timers.rescan,
            self.timers.history,
            self.timers.data_cleanup,
        );
        for event in fired {
            let id = match event {
                Fired::Repeat(id) => id,
                // 本执行体只登记周期定时器，一次性不会出现。
                Fired::OneShot(_) => continue,
            };
            if id == cleanup {
                // 失败窗口的持有点是 `Pipeline`（配置里的 `Jail.failed_hash` 已不再
                // 参与判定），故过期条目清理落在 pipeline 自己身上。
                let removed = self.pipeline.cleanup(now_secs());
                if removed > 0 {
                    crate::logger::debug!(
                        crate::logger::get(),
                        "清理过期失败条目";
                        "removed" => removed
                    );
                }
            } else if id == rescan {
                self.reconcile_watches();
            } else if id == history {
                record_history_snapshot();
            } else if id == data_cleanup {
                perform_data_cleanup();
            }
        }
    }
}

// ============================================================================
// 封禁下发与计数镜像
// ============================================================================

/// 把一个封禁意图下发内核，并镜像到本地缓存与新状态。
///
/// 逐步对齐旧 `handle_failed_attempt_for_jail` 的尾部：
/// `try_insert` 单赢家 → `mirror_ban_insert` → `mark_pending_ban_ack` →
/// `ban::ban_ip` → 失败则回滚三者。`try_insert` 的返回值判定「本次是否抢到」，
/// 抢不到说明别处已封该 IP，直接返回（否则同一条封禁在事件路径上会被算两遍）。
fn dispatch_intent(intent: &BanIntent) {
    let ip = intent.ip.to_string();
    let jail = intent.jail.to_string();
    let Some(info) = ban_info_for(intent) else {
        // IP 文本非法（判定层的 IP 来自 `RuleSet::parse`，理论上不可能到这里）。
        crate::logger::error!(
            crate::logger::get(),
            "IP 验证失败，跳过封禁";
            "ip" => &ip,
            "jail" => &jail
        );
        return;
    };
    let plan = intent.plan;

    crate::logger::info!(
        crate::logger::get(),
        "触发封禁";
        "reason" => %intent.reason,
        "ip" => &ip,
        "jail" => &jail,
        "duration" => plan.duration,
        "is_permanent" => plan.is_permanent,
        "ban_count" => plan.ban_count
    );

    let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
    if !cache.try_insert(info.clone()) {
        return;
    }
    crate::state::compose::mirror_ban_insert(&info);
    mark_pending_ban_ack(&ip);

    if let Err(e) = ban::ban_ip(&ip, plan.duration, &jail) {
        // 下发失败：回滚缓存标记，允许下次重试。`record_ban` / 信誉分 / 历史条目都在
        // 内核 `BAN_STATE_CHANGE` 回来之后才写（见 `inbound::Consumer`），故无需回滚。
        cache.remove(&ip);
        crate::state::compose::mirror_ban_remove(&ip);
        clear_pending_ban_ack(&ip);
        crate::logger::warn!(
            crate::logger::get(),
            "内核封禁失败，已回滚缓存标记";
            "ip" => &ip,
            "jail" => &jail,
            "error" => %e
        );
        return;
    }

    // per-jail 统计：封禁触发（与旧实现同为「下发成功之后」）。
    with_jail_stats(&jail, |stats| {
        stats.bans_triggered.fetch_add(1, Ordering::Relaxed);
    });
}

/// 由封禁意图构造本地缓存条目（[`BanInfo`]）；IP 非法时返回 `None`。
///
/// 字段映射是「判定层 → 缓存层」的唯一接口，单独成函数以便逐字段对照：
/// `BanPlan.duration/expires_at/is_permanent/fail_count/ban_count` 原样搬过来，
/// 而 `reason` 填 **jail 名**——与旧实现逐字一致（前端「原因」列显示的就是它），
/// 判定层给出的明细原因只进日志，避免改变对外可见的文本。
fn ban_info_for(intent: &BanIntent) -> Option<BanInfo> {
    let ip = intent.ip.to_string();
    let ip_num = ban::validate_ip(&ip).ok()?.ip_num;
    let jail = intent.jail.to_string();
    Some(BanInfo {
        ip,
        ip_num,
        jail_name: jail.clone(),
        reason: jail,
        banned_at: now_secs(),
        expires_at: intent.plan.expires_at,
        is_permanent: intent.plan.is_permanent,
        fail_count: intent.plan.fail_count,
        ban_count: intent.plan.ban_count,
    })
}

/// 把一批处理产生的计数差值镜像到全局与 per-jail 计数器。
///
/// `Pipeline` 的计数是**累加**的，且一次 `on_chunk` 只服务一个 jail，故用前后差值即可
/// 精确归属到该 jail——不必让判定层回报每一行的归属信息。
///
/// 口径与旧链路一致：
/// - `lines_parsed` / `lines_skipped` / `regex_matches` / `ips_extracted` 直接搬差值；
/// - `failed_attempts` 等于「识别出的 IP 数」——旧 `handle_failed_attempt_for_jail`
///   每处理一个提取成功的 IP 就 +1（含未达阈值的早期失败），故与 `ips_extracted` 同值。
fn mirror_counters(jail: &str, before: Counters, after: Counters) {
    let parsed = after.lines_parsed.saturating_sub(before.lines_parsed);
    let skipped = after.lines_skipped.saturating_sub(before.lines_skipped);
    let regexes = after.regex_matches.saturating_sub(before.regex_matches);
    let ips = after.ips_extracted.saturating_sub(before.ips_extracted);
    if parsed + skipped + regexes + ips == 0 {
        return;
    }
    DAEMON_STATS
        .lines_parsed
        .fetch_add(parsed, Ordering::Relaxed);
    DAEMON_STATS
        .lines_skipped
        .fetch_add(skipped, Ordering::Relaxed);
    DAEMON_STATS
        .regex_matches
        .fetch_add(regexes, Ordering::Relaxed);
    DAEMON_STATS.ips_extracted.fetch_add(ips, Ordering::Relaxed);
    DAEMON_STATS
        .failed_attempts
        .fetch_add(ips, Ordering::Relaxed);
    with_jail_stats(jail, |stats| {
        stats.lines_parsed.fetch_add(parsed, Ordering::Relaxed);
        stats.regex_matches.fetch_add(regexes, Ordering::Relaxed);
        stats.ips_extracted.fetch_add(ips, Ordering::Relaxed);
        stats.failed_attempts.fetch_add(ips, Ordering::Relaxed);
    });
}

/// 把配置里的 jail 规则编译结果转成判定层要的 [`RuleSet`]。
///
/// **只搬 `compiled: Some(_)` 的条目**：正则的安全校验（ReDoS 启发式）发生在
/// [`crate::jail::init_log_patterns`]，未通过的条目 `compiled == None`，若在这里按
/// 模式串重新编译就会被「救活」，等于绕过安全闸门。已编译的条目再走一次
/// [`Rule::new`]（重载是低频操作），换来的是「规则集不可变、热路径零加锁」。
fn rule_set_for(jail: &Jail) -> RuleSet {
    let mut rules = Vec::new();
    for info in &jail.regexes {
        if info.compiled.is_none() {
            continue;
        }
        match Rule::new(info.name.clone(), &info.pattern) {
            Ok(rule) => rules.push(rule),
            Err(e) => crate::logger::warn!(
                crate::logger::get(),
                "跳过无法编译的规则";
                "jail" => &jail.name,
                "rule" => &info.name,
                "error" => %e
            ),
        }
    }
    RuleSet::new(Arc::from(jail.name.as_str()), rules)
}

// ============================================================================
// 周期任务（随入站执行体一同搬移）
// ============================================================================

/// 上次快照的统计数据（用于计算差值）。
static LAST_SNAPSHOT_STATS: once_cell::sync::Lazy<std::sync::Mutex<SnapshotStats>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(SnapshotStats::default()));

/// 快照统计数据。
#[derive(Default, Clone, Copy)]
struct SnapshotStats {
    ips_banned: u64,
    failed_attempts: u64,
    ddos_events: u64,
}

/// 记录历史数据快照（每 5 分钟）：算与上次的差值并写入 SQLite。
///
/// 从旧 `file_monitor::periodic_tasks` 逐字搬来——它此前挂在旧主循环的 `poll` 超时
/// 分支上，现在挂在入站执行体的单调时钟定时器上；**持有者仍然唯一**（入站执行体），
/// 所以差值的起点不会被两个执行体各推一次。
fn record_history_snapshot() {
    let now = now_secs();
    let current = SnapshotStats {
        ips_banned: DAEMON_STATS.ips_banned.load(Ordering::Relaxed),
        failed_attempts: DAEMON_STATS.failed_attempts.load(Ordering::Relaxed),
        ddos_events: crate::types::DDOS_STATS
            .events_detected
            .load(Ordering::Relaxed),
    };

    let mut last = LAST_SNAPSHOT_STATS
        .lock()
        .expect("LAST_SNAPSHOT_STATS 互斥锁中毒");
    let bans_diff = current.ips_banned.saturating_sub(last.ips_banned);
    let failed_diff = current.failed_attempts.saturating_sub(last.failed_attempts);
    let ddos_diff = current.ddos_events.saturating_sub(last.ddos_events);
    *last = current;
    drop(last);

    if let Err(e) = crate::history_snapshot::record_snapshot(now, bans_diff, failed_diff, ddos_diff)
    {
        crate::logger::warn!(
            crate::logger::get(),
            "记录历史快照失败";
            "error" => %e
        );
    } else {
        crate::logger::debug!(
            crate::logger::get(),
            "历史快照记录成功";
            "bans" => bans_diff,
            "failed" => failed_diff,
            "ddos" => ddos_diff
        );
    }
}

/// 数据清理（每 5 分钟）：封禁历史、信誉分、DDoS 跟踪器。
///
/// 与旧 `file_monitor::perform_data_cleanup` 的差别只有一处：**去掉了 `failed_hash`
/// 的逐 jail 清理**——判定用的失败窗口已迁进 `Pipeline`，由入站执行体的 60 秒
/// [`CLEANUP_INTERVAL`] 定时器通过 `Pipeline::cleanup` 清理（单一持有者）。
fn perform_data_cleanup() {
    // 清理过期封禁历史（7 天无活动的内存条目，防止长期运行内存泄漏）
    if let Some(history) = BAN_HISTORY.get() {
        history.cleanup_expired();
    }

    // 恢复信誉分（每小时 +1，补偿两次快照之间的时间流逝）
    crate::ip_reputation::get_store().recover_scores();

    // 清理信誉分已恢复至 100 且 24 小时无活动的条目（防止内存泄漏）
    let reputation_cleaned = crate::ip_reputation::get_store().cleanup_stale();
    if reputation_cleaned > 0 {
        crate::logger::debug!(
            crate::logger::get(),
            "清理过期信誉分条目";
            "removed" => reputation_cleaned
        );
    }

    // 清理 DDoS 决策引擎中过期的 IP 跟踪器（防止 ip_trackers 无限增长）
    if let Some(engine) = http_exporter::get_global_decision_engine() {
        let before = engine.tracked_ips_count();
        engine.cleanup_stale_trackers();
        let after = engine.tracked_ips_count();
        if before > after {
            crate::logger::debug!(
                crate::logger::get(),
                "清理过期 DDoS IP 跟踪器";
                "removed" => before - after,
                "remaining" => after
            );
        }
    }

    crate::logger::debug!(crate::logger::get(), "数据清理完成");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::plan_ban;
    use crate::types::{Jail, RegexInfo};
    use regex::Regex;
    use std::io::Write;

    const SSH_PATTERN: &str = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";

    /// 系统临时目录下的唯一子目录，避免污染仓库。
    fn tempdir() -> PathBuf {
        use std::sync::atomic::AtomicU32;
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-inbound-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }

    fn failed_line(ip: &str) -> String {
        format!("Feb  7 12:00:00 host sshd[1]: Failed password for root from {ip} port 22 ssh2")
    }

    fn append(path: &Path, data: &[u8]) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .expect("追加打开失败");
        file.write_all(data).expect("追加失败");
        file.sync_all().expect("sync 失败");
    }

    /// 一份「单 jail、单日志文件」的最小配置。
    ///
    /// `jail_name` 由调用方给定：`sync_jail_enabled` 会读进程级 `GLOBAL_JAILS`，用
    /// 互不相同的 jail 名可保证并行的单元测试之间不会互相改到对方的启用状态。
    fn config_with_log(path: &Path, jail_name: &str) -> Config {
        let mut cfg = Config::default();
        let mut jail = Jail::new(jail_name.to_string());
        jail.max_retries = 1;
        jail.findtime = 600;
        jail.ban_time = 60;
        jail.log_files.push(path.display().to_string());
        jail.regexes.push(RegexInfo {
            name: "default".to_string(),
            pattern: SSH_PATTERN.to_string(),
            compiled: Some(Regex::new(SSH_PATTERN).expect("正则应可编译")),
        });
        cfg.jails.push(jail);
        cfg
    }

    fn fixture(path: &Path, jail_name: &str) -> InboundExecutor {
        let cfg = config_with_log(path, jail_name);
        InboundExecutor::new(cfg, SignalFd::new().expect("signalfd 创建失败"))
            .expect("入站执行体应能装配")
    }

    /// 事件驱动推进：反复 `step` 直到条件成立，**不用固定 sleep 猜时间**。
    fn drive_until(ex: &mut InboundExecutor, mut done: impl FnMut(&InboundExecutor) -> bool) {
        let stop = Shutdown::new();
        let terminate = Shutdown::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            ex.step(Duration::from_millis(20), &stop, &terminate)
                .expect("step 不应失败");
            if done(ex) {
                return;
            }
        }
        panic!("等待条件超时");
    }

    #[test]
    fn startup_does_not_replay_history_and_appended_lines_are_judged() {
        let dir = tempdir();
        let log = dir.join("auth.log");
        std::fs::write(&log, format!("{}\n", failed_line("203.0.113.1")).as_bytes())
            .expect("写日志失败");

        let mut ex = fixture(&log, "inbound-replay-test");
        assert_eq!(
            ex.pipeline.counters().lines_parsed,
            0,
            "启动期必须定位到文件末尾，不回放历史内容"
        );
        assert_eq!(ex.registry.len(), 1, "应挂上唯一那个日志文件");

        // 阈值 1 非高峰时段是 1、高峰时段 ×1.5 后是 2，故喂三行保证必达阈值
        // （避免依赖跑测试时的真实时段）。
        let batch = format!("{}\n", failed_line("203.0.113.77")).repeat(3);
        append(&log, batch.as_bytes());

        drive_until(&mut ex, |ex| ex.pipeline.counters().ips_extracted >= 3);
        let counters = ex.pipeline.counters();
        assert_eq!(counters.ips_extracted, 3, "三行都应提取出 IP");
        assert_eq!(counters.regex_matches, 3, "三条都应走正则命中");
        assert!(counters.bans_intent >= 1, "达到阈值必须产出封禁意图");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotation_is_detected_and_the_new_file_is_read_from_the_start() {
        let dir = tempdir();
        let log = dir.join("auth.log");
        std::fs::write(&log, b"").expect("写日志失败");

        let mut ex = fixture(&log, "inbound-rotation-test");
        let rotations_before = DAEMON_STATS.log_rotations.load(Ordering::Relaxed);

        // logrotate 风格：先改名（MOVE_SELF），再新建同名文件（新 inode）。
        std::fs::rename(&log, dir.join("auth.log.1")).expect("改名失败");
        std::fs::write(
            &log,
            format!("{}\n", failed_line("203.0.113.88")).as_bytes(),
        )
        .expect("建新文件失败");

        drive_until(&mut ex, |ex| ex.pipeline.counters().ips_extracted >= 1);
        assert!(
            DAEMON_STATS.log_rotations.load(Ordering::Relaxed) > rotations_before,
            "MOVE_SELF 必须记一次轮转"
        );
        assert!(
            ex.registry.contains_path(&log),
            "轮转后必须按路径重新挂上新的 inode"
        );
        assert!(
            ex.pending_readd.is_empty(),
            "路径已存在的轮转不该留下待重挂项"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disabled_jail_loses_its_watches_and_regains_them() {
        let dir = tempdir();
        let log = dir.join("auth.log");
        std::fs::write(&log, b"").expect("写日志失败");

        // 用独一无二的 jail 名：本用例会写进程级 `GLOBAL_JAILS`，其他并行用例不得受影响。
        let name = "inbound-enabled-sync-test";
        let mut ex = fixture(&log, name);
        assert!(ex.registry.contains_path(&log));

        let jail_info = |enabled: bool| http_exporter::JailInfo {
            name: name.to_string(),
            enabled,
            max_retries: 1,
            findtime: 600,
            ban_time: 60,
        };

        // 模拟 Web UI 关闭该 jail：只改 `GLOBAL_JAILS`，执行体下一轮桥接并重建监视集合。
        http_exporter::set_global_jails(vec![jail_info(false)]);
        ex.sync_jail_enabled();
        assert!(
            !ex.registry.contains_path(&log),
            "禁用的 jail 不应继续监视其日志"
        );

        // 再打开：监视恢复。
        http_exporter::set_global_jails(vec![jail_info(true)]);
        ex.sync_jail_enabled();
        assert!(ex.registry.contains_path(&log), "重新启用后应恢复监视");

        // 不把条目留在全局态里。
        http_exporter::set_global_jails(Vec::new());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn ban_intent_is_mapped_to_ban_info_field_by_field() {
        // 「意图 → 缓存条目」的字段映射是执行体唯一的转发契约，逐字段对照。
        let jail: Arc<str> = Arc::from("sshd");
        let plan = plan_ban(-1, 0, 1_700_000_000, 7);
        let intent = BanIntent {
            jail: Arc::clone(&jail),
            ip: "203.0.113.99".parse().expect("测试用 IP 必须合法"),
            source: SourceId::from_raw(0),
            plan,
            reason: "sshd: 7 次失败达到阈值 7".to_string(),
        };

        let info = ban_info_for(&intent).expect("合法 IP 必须能构造缓存条目");
        assert_eq!(info.ip, "203.0.113.99");
        assert_eq!(info.jail_name, "sshd");
        assert_eq!(
            info.reason, "sshd",
            "`reason` 必须是 jail 名（与旧实现逐字一致，前端「原因」列会显示它）"
        );
        assert!(info.is_permanent, "ban_time < 0 必须判为永久");
        assert_eq!(info.expires_at, 0, "永久封禁的过期时刻为 0");
        assert_eq!(info.fail_count, 7);
        assert_eq!(info.ban_count, 1);
        assert!(info.ip_num > 0, "IPv4 必须带上网络字节序整数索引");
    }
}
