//! 接收回路与请求/响应路由。
//!
//! 本模块把「一条报文该给谁」与「从 socket 上取报文」分开：
//!
//! - [`Router`] 是**纯状态机**，不含任何 I/O。给它 `(portid, payload)`，它决定
//!   这条报文是某次在途请求的回复，还是应推给上层的无序事件；未知类型、解码
//!   失败、无人认领的回复一律计数而不是丢弃。因为不碰 socket，它可以被完整
//!   单元测试（本文件末尾的测试就是这么做的）。
//! - [`Reactor`] 只做 I/O：等到可读、取报文、交给 [`Router`]，外加持有
//!   [`Transport`] 与关停令牌。
//!
//! # 为什么必须区分「回显 seq 的回复」与「内核自增序号的推送」
//!
//! 内核里有**两套**序号来源（见 `fw_netlink.c`）：
//!
//! - **回显请求 seq**：`DaemonRegisterAck` / `ConfigAck` / `StatsResponse` /
//!   `AnalysisResponse` / 三个 `List*Response`。这些是对某次请求的直接回复，
//!   请求侧发出的 `seq` 被原样带回，因此可以按 `(类型, seq)` 配对。
//! - **内核自增序号**：`DdosEvent` / `BanStateChange` / `WhitelistStateChange` /
//!   `ConfigChange` 用 `atomic_inc_return(&fw_nl_seq)`，**并且是广播**；
//!   `CmdResult` 同样是自增序号（单播给失败命令的发起方）。
//!
//! 后一组的 `seq` 与请求侧的 `seq` 是**两个独立计数器**，取值必然碰撞。若把
//! `CmdResult` 也拿去配对，一条「封禁失败」通知就可能被误认成某次 LIST 请求的
//! 回复，把它从事件流里吞掉。故 [`is_seq_echoed_reply`] 是配对白名单，只列第一组；
//! 这个划分有测试守着，且测试的输入直接取自内核的发送函数清单。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::contract::MsgType;
use crate::kernel::codec::{self, DecodeError, Incoming};
use crate::kernel::transport::{RecvError, Transport};
use crate::runtime::{Backpressure, Receiver, RecvTimeoutError, Sender, Shutdown};

/// 轮询间隔：决定关停的最坏延迟，也是「无数据时」的回归周期。
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// 内核推送队列容量。
///
/// 满时按 [`Backpressure::Reject`] 拒绝并计数。选择拒绝而非阻塞：接收线程一旦
/// 被上层阻塞，socket 缓冲区会跟着积压，最终内核丢弃事件——那是不可见的丢失，
/// 比「明确拒绝并计数」更糟。
const EVENT_QUEUE: usize = 4096;

/// 在途请求表容量上限。
pub const MAX_IN_FLIGHT: usize = 64;

// ============================================================================
// 统计
// ============================================================================

/// 接收路径计数。
///
/// 每一项都对应一个**可真实发生**的线上情形，且都能被上层读出来做告警；
/// 没有「静默丢弃」这一类。
#[derive(Debug, Default)]
pub struct RouterStats {
    received: AtomicU64,
    foreign_portid: AtomicU64,
    malformed: AtomicU64,
    unknown_type: AtomicU64,
    decode_errors: AtomicU64,
    unmatched_replies: AtomicU64,
    reply_undelivered: AtomicU64,
    pending_full: AtomicU64,
    seq_collisions: AtomicU64,
    link_down: AtomicU64,
}

impl RouterStats {
    /// 通过校验并进入路由的报文数。
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }

    /// 发送方 portid 非内核（非 0）而被丢弃的报文数。
    pub fn foreign_portid(&self) -> u64 {
        self.foreign_portid.load(Ordering::Relaxed)
    }

    /// 公共头解析失败（魔数、长度、长度不足）的报文数。
    pub fn malformed(&self) -> u64 {
        self.malformed.load(Ordering::Relaxed)
    }

    /// `msg_type` 不在契约内的报文数。
    pub fn unknown_type(&self) -> u64 {
        self.unknown_type.load(Ordering::Relaxed)
    }

    /// 类型已知但字段解码失败的报文数。
    pub fn decode_errors(&self) -> u64 {
        self.decode_errors.load(Ordering::Relaxed)
    }

    /// 回显 `seq` 的回复找不到对应在途请求的次数（客户端已超时放弃）。
    pub fn unmatched_replies(&self) -> u64 {
        self.unmatched_replies.load(Ordering::Relaxed)
    }

    /// 已认领到请求但交付失败的次数。
    pub fn reply_undelivered(&self) -> u64 {
        self.reply_undelivered.load(Ordering::Relaxed)
    }

    /// 在途表已满导致无法登记新请求的次数。
    pub fn pending_full(&self) -> u64 {
        self.pending_full.load(Ordering::Relaxed)
    }

    /// `(类型, seq)` 已被占用导致登记被拒的次数。
    ///
    /// 出现非零说明序号被复用；若不拒绝，后登记者会**顶掉**先登记者，
    /// 使先到的那条回复投给错误的等待方。
    pub fn seq_collisions(&self) -> u64 {
        self.seq_collisions.load(Ordering::Relaxed)
    }

    /// 因接收侧已退出导致登记被拒的次数。
    ///
    /// 出现非零说明有人在内核链路已断的情况下继续下指令；这些指令**没有**
    /// 发出去，必须与「发出去但内核没回」区分开。
    pub fn link_down(&self) -> u64 {
        self.link_down.load(Ordering::Relaxed)
    }
}

// ============================================================================
// 配对
// ============================================================================

/// 接收侧的存活标志。
///
/// 与事件通道的断开是**两件事**：事件通道断开说明上层已停止消费，通常也是
/// reactor 退出的**原因**；而本标志直接标注 reactor 本身是否还在运行。
///
/// 为什么必须有它：在途请求的回复通道由 [`ReplyHandle`] 与 [`PendingTable`]
/// 共同持有，所以 reactor 消失**不会**让这个通道断开——等待方只会一直等到
/// 超时，无法区分「内核没回」与「已经没人收报文了」。没有这个标志，
/// [`crate::kernel::client::RequestError::LinkDown`] 就是不可达状态。
///
/// 由 [`LivenessGuard`] 显式翻转，**不是**在析构里按克隆计数翻转：
/// [`Router`] 会被 `Client` 长期共享，若按最后一根引用的销毁来判「链路断开」，
/// 就永远不会触发。
#[derive(Debug, Clone)]
pub struct ReactorLiveness(Arc<AtomicBool>);

impl ReactorLiveness {
    /// 接收侧是否仍在运行。
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// 接收侧的存活凭据，由 [`Reactor`] 持有；销毁即宣告接收侧已退出。
///
/// 只在 `Reactor` 被析构时翻转（正常关停、线程 panic 导致的 unwind、或从未
/// 启动），因此它描述的是「这条接收回路还在不在」，与谁持有了 [`Router`] 无关。
///
/// 销毁时做两件事，缺一不可，否则「链路失联」就漏一半：
///
/// 1. 置死标志——此后**新**的登记被拒（见 [`PendingTable::insert`]）；
/// 2. 清空在途登记——丢弃各请求的回复发送端，使**已在等待**的调用方立即
///    拿到「已断开」，而不是空等到自己的超时。
///
/// 注意「是否存活」不能靠 `Arc` 的析构计数来判：接收侧的凭据只有这一份，而
/// [`Router`] 会被 `Client` 长期共享，按引用计数判断就永远不会触发。
#[derive(Debug)]
pub struct LivenessGuard {
    alive: Arc<AtomicBool>,
    pending: Arc<PendingTable>,
}

impl LivenessGuard {
    fn new() -> Self {
        let alive = Arc::new(AtomicBool::new(true));
        let pending = Arc::new(PendingTable::new(Arc::clone(&alive)));
        Self { alive, pending }
    }

    /// 与 [`Router`] 共享的在途请求表。
    fn pending(&self) -> Arc<PendingTable> {
        Arc::clone(&self.pending)
    }

    /// 出一个只读存活句柄，交给 [`Router`] 分发给各 [`ReplyHandle`]。
    fn handle(&self) -> ReactorLiveness {
        ReactorLiveness(Arc::clone(&self.alive))
    }
}

impl Drop for LivenessGuard {
    fn drop(&mut self) {
        // 顺序要紧：先置死，再清表。否则「置死与清表之间」到达的登记会插进
        // 空表并一直等下去。
        self.alive.store(false, Ordering::Release);
        self.pending.clear();
    }
}

/// 在途请求的配对键：`(msg_type 原始取值, seq)`。
///
/// 用整数而非 `MsgType` 作键，避免让配对逻辑依赖契约枚举是否实现了 `Hash`。
type ReplyKey = (u16, u32);

/// 该类型是否以「回显请求 `seq`」的方式回复，因而可以与在途请求配对。
///
/// 见模块文档：`CmdResult` 虽然也是单播，但它用内核自增序号，**不在**此列。
#[must_use]
pub fn is_seq_echoed_reply(msg_type: MsgType) -> bool {
    matches!(
        msg_type,
        MsgType::DaemonRegisterAck
            | MsgType::ConfigAck
            | MsgType::StatsResponse
            | MsgType::AnalysisResponse
            | MsgType::ListBansResponse
            | MsgType::ListWhitelistResponse
            | MsgType::ListRatesResponse
    )
}

/// 登记在途请求失败的原因。
///
/// 三种原因对上层是三种处置：链路失联要告警、表满要退避重试、序号复用要查
/// 逻辑 bug。所以这里给出具名原因，而不是笼统的「失败了」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    /// 接收侧已退出：回复永远不会到达。
    LinkDown,
    /// 表已满（[`MAX_IN_FLIGHT`]）。
    Full,
    /// 该 `(类型, seq)` 已被占用：复用序号会让两条回复互相串台。
    Duplicate,
}

/// 在途请求表。由 [`Router`] 与 [`ReplyHandle`] 共享。
#[derive(Debug)]
struct PendingTable {
    map: Mutex<HashMap<ReplyKey, Sender<Incoming>>>,
    /// 接收侧存活标志；置死后拒绝新登记，回复永远不会到达。
    alive: Arc<AtomicBool>,
}

impl PendingTable {
    fn new(alive: Arc<AtomicBool>) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            alive,
        }
    }

    fn claim(&self, key: ReplyKey) -> Option<Sender<Incoming>> {
        // 中毒只可能来自持锁者 panic；表本身是普通 HashMap，取回数据继续用是安全的。
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key)
    }

    /// 登记一条在途请求。
    ///
    /// 两条拒绝规则，都是「宁可报错也不静默出错」：
    ///
    /// - 已存在的键**拒绝**而不是覆盖：覆盖会让先前那条请求的回复投给后来的
    ///   等待方，属于静默串台。
    /// - 接收侧已退出时**拒绝**：没有谁能再收到回复，登记只会让调用方白等。
    ///
    /// 存活判断与插入在同一把锁内完成，故与 [`LivenessGuard`] 的置死+清表之间
    /// 不存在「插进空表然后干等」的竞态窗口。
    fn insert(&self, key: ReplyKey, tx: Sender<Incoming>) -> Result<(), RegisterError> {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if !self.alive.load(Ordering::Acquire) {
            return Err(RegisterError::LinkDown);
        }
        if map.len() >= MAX_IN_FLIGHT {
            return Err(RegisterError::Full);
        }
        if map.contains_key(&key) {
            return Err(RegisterError::Duplicate);
        }
        map.insert(key, tx);
        Ok(())
    }

    fn remove(&self, key: ReplyKey) {
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key);
    }

    fn len(&self) -> usize {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    /// 丢弃全部在途登记，使各等待方立即收到「已断开」。
    ///
    /// 接收侧退出时调用：此后不会再有回复，让等待方干等到超时毫无意义。
    fn clear(&self) {
        self.map.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

/// 等一次请求回复的凭据。
///
/// 持有期间该 `(类型, seq)` 在在途表里占位；[`Drop`] 时撤销登记，故此后的迟到
/// 回复会被计成 [`RouterStats::unmatched_replies`] 而不是无限堆积。
#[derive(Debug)]
pub struct ReplyHandle {
    key: ReplyKey,
    pending: Arc<PendingTable>,
    rx: Receiver<Incoming>,
    liveness: ReactorLiveness,
}

impl ReplyHandle {
    /// 配对键 `(msg_type 原始取值, seq)`。
    #[must_use]
    pub fn key(&self) -> ReplyKey {
        self.key
    }

    /// 最多等待 `timeout` 接收回复。
    ///
    /// 返回值区分三种情形：收到回复；**接收侧已不存在**（[`RecvTimeoutError::
    /// Disconnected`]，上层应据此判定链路失联而非普通超时）；等待超时
    /// （[`RecvTimeoutError::Timeout`]）。
    ///
    /// # Errors
    ///
    /// 见上。
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Incoming, RecvTimeoutError> {
        match self.rx.recv_timeout(timeout) {
            // 收到消息。
            Ok(msg) => Ok(msg),
            // 回复通道被关闭：接收侧退出，且不会再有任何回复。
            Err(RecvTimeoutError::Disconnected) => Err(RecvTimeoutError::Disconnected),
            // 等不到消息时，先看接收侧是否还在跑：不在跑就是链路失联，
            // 而不是「内核没回」。
            Err(RecvTimeoutError::Timeout) => {
                if self.liveness.is_alive() {
                    Err(RecvTimeoutError::Timeout)
                } else {
                    Err(RecvTimeoutError::Disconnected)
                }
            }
        }
    }
}

impl Drop for ReplyHandle {
    fn drop(&mut self) {
        self.pending.remove(self.key);
    }
}

// ============================================================================
// 路由器
// ============================================================================

/// 报文路由器：纯状态机，不含 I/O。
#[derive(Debug)]
pub struct Router {
    events: Sender<Incoming>,
    pending: Arc<PendingTable>,
    stats: Arc<RouterStats>,
    liveness: ReactorLiveness,
}

impl Router {
    /// 新建路由器；无序事件（内核推送、命令失败通知、广播配置变更）投进 `events`。
    ///
    /// 返回的 [`LivenessGuard`] 必须交给 [`Reactor`] 持有：接收侧退出（凭据销毁）
    /// 之后，等待中的请求会立刻看到「链路失联」信号，而不是空等到超时。
    #[must_use]
    pub fn new(events: Sender<Incoming>) -> (Self, LivenessGuard) {
        let guard = LivenessGuard::new();
        let router = Self {
            events,
            pending: guard.pending(),
            stats: Arc::new(RouterStats::default()),
            liveness: guard.handle(),
        };
        (router, guard)
    }

    /// 接收侧计数。
    #[must_use]
    pub fn stats(&self) -> &Arc<RouterStats> {
        &self.stats
    }

    /// 当前在途请求数。
    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.pending.len()
    }

    /// 为一次请求登记配对。
    ///
    /// 被拒时返回具名原因（见 [`RegisterError`]），调用方应视为「请求未发出」，
    /// 而不是发出去却无法收回复。各原因同时计入
    /// [`RouterStats::link_down`] / [`RouterStats::pending_full`] /
    /// [`RouterStats::seq_collisions`]，便于监控把「该重试」与「该告警」分开。
    ///
    /// # Errors
    ///
    /// 见 [`RegisterError`]。
    pub fn register(&self, msg_type: MsgType, seq: u32) -> Result<ReplyHandle, RegisterError> {
        let key = (msg_type.to_raw(), seq);
        // 回复只可能有一条，容量 1 足够。
        let (tx, rx, _stats) =
            crate::runtime::channel::bounded::<Incoming>(1, Backpressure::Reject);
        match self.pending.insert(key, tx) {
            Ok(()) => {}
            Err(RegisterError::LinkDown) => {
                self.stats.link_down.fetch_add(1, Ordering::Relaxed);
                return Err(RegisterError::LinkDown);
            }
            Err(RegisterError::Full) => {
                self.stats.pending_full.fetch_add(1, Ordering::Relaxed);
                return Err(RegisterError::Full);
            }
            Err(RegisterError::Duplicate) => {
                self.stats.seq_collisions.fetch_add(1, Ordering::Relaxed);
                crate::logger::warn!(
                    crate::logger::get(),
                    "netlink 请求序号被复用，登记被拒";
                    "msg_type" => key.0,
                    "seq" => key.1
                );
                return Err(RegisterError::Duplicate);
            }
        }
        Ok(ReplyHandle {
            key,
            pending: Arc::clone(&self.pending),
            rx,
            liveness: self.liveness.clone(),
        })
    }

    /// 交付一条已剥离 `nlmsghdr` 的报文。
    ///
    /// 这是本模块的全部行为所在，也是测试的入口。
    pub fn route(&self, portid: u32, payload: &[u8]) {
        if portid != 0 {
            // 只有内核（portid 0）的报文可信。本机其他进程也可能是合法发送方
            // （内核只校验 CAP_NET_ADMIN），故这里只按「内核来源」分流。
            self.stats.foreign_portid.fetch_add(1, Ordering::Relaxed);
            crate::logger::warn!(
                crate::logger::get(),
                "丢弃非内核来源的 netlink 报文";
                "portid" => portid
            );
            return;
        }

        let (hdr, body) = match codec::decode_header(payload) {
            Ok(parts) => parts,
            Err(e) => {
                self.stats.malformed.fetch_add(1, Ordering::Relaxed);
                crate::logger::warn!(
                    crate::logger::get(),
                    "netlink 公共头解析失败";
                    "error" => %e
                );
                return;
            }
        };

        self.stats.received.fetch_add(1, Ordering::Relaxed);

        let Some(msg_type) = hdr.msg_type() else {
            self.stats.unknown_type.fetch_add(1, Ordering::Relaxed);
            crate::logger::warn!(
                crate::logger::get(),
                "netlink 报文类型不在契约内";
                "msg_type" => hdr.msg_type_raw
            );
            return;
        };

        // 回显 seq 的回复按 (类型, seq) 认领；其余一律进事件队列。
        if is_seq_echoed_reply(msg_type) {
            if let Some(tx) = self.pending.claim((hdr.msg_type_raw, hdr.seq)) {
                match codec::decode_incoming(msg_type, body) {
                    Ok(msg) => {
                        if tx.send(msg).is_err() {
                            // 等待方在认领与交付之间退出（已超时放弃）。
                            self.stats.reply_undelivered.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    Err(e) => self.record_decode_error(msg_type, &e),
                }
                return;
            }
            // 无人在等：可能是客户端已超时放弃的迟到回复。计数而不推给事件流，
            // 否则一大页 LIST 结果会被当成健康事件灌进上层。
            self.stats.unmatched_replies.fetch_add(1, Ordering::Relaxed);
            crate::logger::debug!(
                crate::logger::get(),
                "没有在途请求认领该回复";
                "msg_type" => hdr.msg_type_raw,
                "seq" => hdr.seq
            );
            return;
        }

        match codec::decode_incoming(msg_type, body) {
            Ok(msg) => {
                if let Err(msg) = self.events.send(msg) {
                    // 队列满：事件被明确拒绝。计数器在队列自身的统计里，
                    // 这里再记一条日志，避免「内核说发了、上层说没收到」无从对账。
                    crate::logger::warn!(
                        crate::logger::get(),
                        "内核推送队列已满，事件被拒绝";
                        "msg_type" => msg.msg_type_name()
                    );
                }
            }
            Err(e) => self.record_decode_error(msg_type, &e),
        }
    }

    /// 记录一次字段解码失败。类型已知而字段不合法，说明契约与内核实现分叉了。
    fn record_decode_error(&self, msg_type: MsgType, err: &DecodeError) {
        self.stats.decode_errors.fetch_add(1, Ordering::Relaxed);
        crate::logger::warn!(
            crate::logger::get(),
            "netlink 报文解码失败";
            "msg_type" => msg_type.to_raw(),
            "error" => %err
        );
    }
}

// ============================================================================
// 接收回路
// ============================================================================

/// 接收执行体：把 socket 上的报文持续交给 [`Router`]。
pub struct Reactor {
    transport: Arc<Transport>,
    shutdown: Shutdown,
    router: Router,
    /// 本接收侧的存活凭据；`Reactor` 销毁即宣告接收侧退出。
    _liveness: LivenessGuard,
}

impl Reactor {
    /// 组装接收执行体。
    #[must_use]
    pub fn new(
        transport: Arc<Transport>,
        shutdown: Shutdown,
        router: Router,
        liveness: LivenessGuard,
    ) -> Self {
        Self {
            transport,
            shutdown,
            router,
            _liveness: liveness,
        }
    }

    /// 运行直到 [`Shutdown`] 被请求。应在自己的线程里跑（见 [`crate::runtime::Supervisor`]）。
    pub fn run(self) {
        while !self.shutdown.is_shutdown() {
            match self.transport.wait_readable(POLL_INTERVAL, &self.shutdown) {
                Ok(false) => continue,
                Ok(true) => {}
                Err(e) => {
                    // poll 层面的错误（例如 socket 被关闭）。记录后继续：单个
                    // 错误不应让接收线程静默退出，否则上层只看到「事件停了」。
                    crate::logger::error!(
                        crate::logger::get(),
                        "等待 netlink 可读失败";
                        "error" => %e
                    );
                    // 避免错误条件下空转占满 CPU。
                    let _ = self.shutdown.wait_timeout(Duration::from_millis(100));
                    continue;
                }
            }

            // 一次可读事件可能对应多条数据报，排空再回到 poll。
            loop {
                match self.transport.recv() {
                    Ok(Some(dg)) => self.router.route(dg.portid, &dg.payload),
                    Ok(None) => break,
                    Err(e) => {
                        self.log_recv_error(&e);
                        break;
                    }
                }
            }
        }
    }

    fn log_recv_error(&self, err: &RecvError) {
        match err {
            RecvError::Truncated { .. } | RecvError::Malformed { .. } => {
                crate::logger::error!(
                    crate::logger::get(),
                    "netlink 报文不合法，已丢弃";
                    "error" => %err
                );
            }
            RecvError::Failed(e) => {
                crate::logger::error!(
                    crate::logger::get(),
                    "收取 netlink 报文失败";
                    "error" => %e
                );
            }
        }
    }

    /// 便于测试与诊断：接收侧计数。
    #[must_use]
    pub fn stats(&self) -> &Arc<RouterStats> {
        self.router.stats()
    }
}

/// 便于测试：构造一对「事件接收端 + 路由器」，并同时返回存活凭据。
#[must_use]
pub fn event_channel(
    capacity: usize,
) -> (
    Router,
    Receiver<Incoming>,
    Arc<crate::runtime::QueueStats>,
    LivenessGuard,
) {
    let (tx, rx, stats) = crate::runtime::channel::bounded(capacity, Backpressure::Reject);
    let (router, liveness) = Router::new(tx);
    (router, rx, stats, liveness)
}

/// 内核推送队列的默认容量（供组合根使用）。
#[must_use]
pub const fn default_event_queue() -> usize {
    EVENT_QUEUE
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::codec::{encode_header_only, HDR_LEN};
    use crate::runtime::TryRecvError;

    /// 组装一条只有头的报文（用于类型/配对测试）。
    fn header_only(msg_type: MsgType, seq: u32) -> Vec<u8> {
        encode_header_only(msg_type, seq)
    }

    #[test]
    fn seq_echoed_reply_whitelist_excludes_kernel_sequenced_senders() {
        // 内核里用 atomic_inc_return(&fw_nl_seq) 发送的**全部**类型，
        // 一个都不能出现在配对白名单里。
        for mt in [
            MsgType::DdosEvent,
            MsgType::BanStateChange,
            MsgType::WhitelistStateChange,
            MsgType::ConfigChange,
            MsgType::CmdResult,
        ] {
            assert!(
                !is_seq_echoed_reply(mt),
                "{mt:?} 用内核自增序号，不能参与 seq 配对"
            );
        }
        // 回显请求 seq 的回复必须全在名单里。
        for mt in [
            MsgType::DaemonRegisterAck,
            MsgType::ConfigAck,
            MsgType::StatsResponse,
            MsgType::AnalysisResponse,
            MsgType::ListBansResponse,
            MsgType::ListWhitelistResponse,
            MsgType::ListRatesResponse,
        ] {
            assert!(is_seq_echoed_reply(mt), "{mt:?} 回显请求 seq，应可配对");
        }
    }

    #[test]
    fn foreign_portid_is_rejected_and_counted() {
        let (router, rx, _, _live) = event_channel(4);
        router.route(1234, &header_only(MsgType::StatsQuery, 0));
        assert_eq!(router.stats().foreign_portid(), 1);
        assert_eq!(router.stats().received(), 0);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn unknown_type_is_counted_not_silently_dropped() {
        let (router, rx, _, _live) = event_channel(4);
        let mut bytes = header_only(MsgType::StatsQuery, 0);
        bytes[4..6].copy_from_slice(&999u16.to_be_bytes());
        router.route(0, &bytes);
        assert_eq!(router.stats().unknown_type(), 1);
        assert_eq!(router.stats().received(), 1, "长度合法，应算作已收到");
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn malformed_header_is_counted() {
        let (router, _rx, _, _live) = event_channel(4);
        // 长度声明与实长不符。
        let mut bytes = header_only(MsgType::StatsQuery, 0);
        bytes[6..8].copy_from_slice(&64u16.to_be_bytes());
        router.route(0, &bytes);
        assert_eq!(router.stats().malformed(), 1);
        assert_eq!(router.stats().received(), 0);
    }

    #[test]
    fn broadcast_event_reaches_the_event_queue() {
        let (router, rx, _, _live) = event_channel(4);
        // DdosEvent 是广播事件，用内核自增序号：即使 seq 与某次在途请求相同，
        // 也必须走事件队列而不是被认领走。
        let handle = router
            .register(MsgType::StatsResponse, 7)
            .expect("登记在途请求");
        let mut body = vec![0u8; crate::contract::DdosEvent::WIRE_SIZE - HDR_LEN];
        body[0] = crate::contract::AddrFamily::Inet.to_raw();
        let bytes = codec::frame_for_test(MsgType::DdosEvent, 7, &body);
        router.route(0, &bytes);

        let got = rx.try_recv().expect("事件应进入事件队列");
        assert_eq!(got.msg_type_name(), "DdosEvent");
        assert_eq!(
            router.stats().unmatched_replies(),
            0,
            "广播事件不得被当成回复认领"
        );
        drop(handle);
    }

    #[test]
    fn matched_reply_goes_to_the_waiter_not_the_event_queue() {
        let (router, rx, _, _live) = event_channel(4);
        let handle = router
            .register(MsgType::StatsResponse, 42)
            .expect("登记在途请求");

        let mut body = vec![0u8; crate::contract::StatsResponse::WIRE_SIZE - HDR_LEN];
        body[0..8].copy_from_slice(&5u64.to_be_bytes());
        let bytes = codec::frame_for_test(MsgType::StatsResponse, 42, &body);
        router.route(0, &bytes);

        match handle.recv_timeout(Duration::from_millis(100)) {
            Ok(Incoming::StatsResponse(s)) => assert_eq!(s.current_bans, 5),
            other => panic!("等待方应收到 StatsResponse，实得 {other:?}"),
        }
        assert!(
            matches!(rx.try_recv(), Err(TryRecvError::Empty)),
            "回复不应同时进入事件队列"
        );
    }

    #[test]
    fn reply_with_the_wrong_seq_is_unmatched() {
        let (router, rx, _, _live) = event_channel(4);
        let _handle = router
            .register(MsgType::StatsResponse, 42)
            .expect("登记在途请求");
        let bytes = codec::frame_for_test(
            MsgType::StatsResponse,
            43,
            &[0u8; crate::contract::StatsResponse::WIRE_SIZE - HDR_LEN],
        );
        router.route(0, &bytes);
        assert_eq!(router.stats().unmatched_replies(), 1);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn dropping_the_handle_makes_a_late_reply_unmatched() {
        let (router, _rx, _, _live) = event_channel(4);
        let handle = router
            .register(MsgType::ListRatesResponse, 9)
            .expect("登记在途请求");
        drop(handle);
        assert_eq!(router.in_flight(), 0, "撤销登记后不应占位");
        let bytes = header_only(MsgType::ListRatesResponse, 9);
        router.route(0, &bytes);
        assert_eq!(router.stats().unmatched_replies(), 1);
    }

    #[test]
    fn in_flight_table_refuses_beyond_capacity_instead_of_overwriting() {
        let (router, _rx, _, _live) = event_channel(4);
        let mut held = Vec::new();
        for i in 0..MAX_IN_FLIGHT {
            held.push(
                router
                    .register(MsgType::StatsResponse, i as u32 + 1)
                    .unwrap_or_else(|e| panic!("第 {i} 个在途请求应能登记，实得 {e:?}")),
            );
        }
        assert_eq!(
            router.register(MsgType::StatsResponse, 9999).unwrap_err(),
            RegisterError::Full,
            "超出容量必须拒绝而不是覆盖已有请求"
        );
        assert_eq!(router.stats().pending_full(), 1);
        assert_eq!(router.in_flight(), MAX_IN_FLIGHT);
    }

    #[test]
    fn a_duplicate_key_is_refused_and_counted_as_a_collision() {
        // 覆盖会让先前那条请求的回复投给后来的等待方，故必须是「拒绝」。
        let (router, _rx, _, _live) = event_channel(4);
        let _held = router
            .register(MsgType::StatsResponse, 77)
            .expect("首次登记应成功");
        assert_eq!(
            router.register(MsgType::StatsResponse, 77).unwrap_err(),
            RegisterError::Duplicate
        );
        assert_eq!(router.stats().seq_collisions(), 1);
        assert_eq!(router.in_flight(), 1, "被拒不得影响已有登记");
    }

    #[test]
    fn dropping_the_liveness_guard_refuses_new_registrations_immediately() {
        // 接收侧退出后新登记必须**立即**被拒（而不是登记成功、白等到超时）。
        let (router, _rx, _stats, live) = event_channel(4);
        drop(live);
        assert_eq!(
            router.register(MsgType::StatsResponse, 1).unwrap_err(),
            RegisterError::LinkDown
        );
        assert_eq!(router.stats().link_down(), 1);
    }

    #[test]
    fn dropping_the_liveness_guard_wakes_waiters_instead_of_letting_them_time_out() {
        // 已在等待的请求必须被立刻唤醒并看到「已断开」，而不是空等满超时。
        let (router, _rx, _stats, live) = event_channel(4);
        let handle = router
            .register(MsgType::StatsResponse, 3)
            .expect("登记在途请求");
        drop(live);
        let start = std::time::Instant::now();
        assert!(matches!(
            handle.recv_timeout(Duration::from_secs(30)),
            Err(RecvTimeoutError::Disconnected)
        ));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "失联唤醒必须是即时的，实耗 {:?}",
            start.elapsed()
        );
        assert_eq!(router.in_flight(), 0, "失联时必须清空在途表");
    }

    #[test]
    fn pending_claims_are_independent_per_seq() {
        // 并发 LIST 请求不再共用全局单槽：两个不同 seq 各自收到自己的回复。
        let (router, _rx, _, _live) = event_channel(4);
        let a = router.register(MsgType::StatsResponse, 1).expect("登记 A");
        let b = router.register(MsgType::StatsResponse, 2).expect("登记 B");

        let mk = |count: u64| {
            let mut body = vec![0u8; crate::contract::StatsResponse::WIRE_SIZE - HDR_LEN];
            body[0..8].copy_from_slice(&count.to_be_bytes());
            codec::frame_for_test(MsgType::StatsResponse, 0, &body)
        };
        let (mut ba, mut bb) = (mk(11), mk(22));
        // 把 seq 写进公共头（frame 的 seq 参数被复用不便于表意，这里显式改）。
        ba[8..12].copy_from_slice(&1u32.to_be_bytes());
        bb[8..12].copy_from_slice(&2u32.to_be_bytes());

        router.route(0, &bb);
        router.route(0, &ba);

        match b.recv_timeout(Duration::from_millis(100)) {
            Ok(Incoming::StatsResponse(s)) => assert_eq!(s.current_bans, 22, "B 应收到自己的回复"),
            other => panic!("B 的回复应可配对，实得 {other:?}"),
        }
        match a.recv_timeout(Duration::from_millis(100)) {
            Ok(Incoming::StatsResponse(s)) => assert_eq!(s.current_bans, 11, "A 应收到自己的回复"),
            other => panic!("A 的回复应可配对，实得 {other:?}"),
        }
    }

    #[test]
    fn cmd_result_is_delivered_as_an_event_never_claimed_as_a_reply() {
        // 关键回归：CmdResult 用内核自增序号，即使 seq 撞上在途请求也必须进事件流。
        let (router, rx, _, _live) = event_channel(4);
        let _handle = router
            .register(MsgType::StatsResponse, 5)
            .expect("登记在途请求");
        let mut body = vec![0u8; crate::contract::CmdResult::WIRE_SIZE - HDR_LEN];
        body[0..2].copy_from_slice(&MsgType::BanIp.to_raw().to_be_bytes());
        let bytes = codec::frame_for_test(MsgType::CmdResult, 5, &body);
        router.route(0, &bytes);
        let got = rx.try_recv().expect("CmdResult 应进入事件队列");
        assert_eq!(got.msg_type_name(), "CmdResult");
        assert_eq!(router.stats().unmatched_replies(), 0);
    }
}
