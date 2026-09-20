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
use std::sync::atomic::{AtomicU64, Ordering};
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
}

// ============================================================================
// 配对
// ============================================================================

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

/// 在途请求表。由 [`Router`] 与 [`ReplyHandle`] 共享。
#[derive(Debug, Default)]
struct PendingTable {
    map: Mutex<HashMap<ReplyKey, Sender<Incoming>>>,
}

impl PendingTable {
    fn claim(&self, key: ReplyKey) -> Option<Sender<Incoming>> {
        // 中毒只可能来自持锁者 panic；表本身是普通 HashMap，取回数据继续用是安全的。
        self.map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&key)
    }

    fn insert(&self, key: ReplyKey, tx: Sender<Incoming>) -> bool {
        let mut map = self.map.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_IN_FLIGHT {
            return false;
        }
        map.insert(key, tx);
        true
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
}

impl ReplyHandle {
    /// 配对键 `(msg_type 原始取值, seq)`。
    #[must_use]
    pub fn key(&self) -> ReplyKey {
        self.key
    }

    /// 最多等待 `timeout` 接收回复。
    ///
    /// 返回值区分「超时」与「回复通道断开」：后者说明 reactor 已退出，
    /// 上层应据此判定链路失联，而不是当成一次普通超时重试。
    ///
    /// # Errors
    ///
    /// 超时返回 [`RecvTimeoutError::Timeout`]；reactor 已退出返回
    /// [`RecvTimeoutError::Disconnected`]。
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Incoming, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
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
}

impl Router {
    /// 新建路由器；无序事件（内核推送、命令失败通知、广播配置变更）投进 `events`。
    #[must_use]
    pub fn new(events: Sender<Incoming>) -> Self {
        Self {
            events,
            pending: Arc::new(PendingTable::default()),
            stats: Arc::new(RouterStats::default()),
        }
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
    /// 返回 `None` 表示在途表已满（[`MAX_IN_FLIGHT`]），调用方应视为「请求未发出」
    /// 并计入 [`RouterStats::pending_full`]，而不是发出去却无法收回复。
    #[must_use]
    pub fn register(&self, msg_type: MsgType, seq: u32) -> Option<ReplyHandle> {
        let key = (msg_type.to_raw(), seq);
        // 回复只可能有一条，容量 1 足够；满时拒绝（不会发生，见下）。
        let (tx, rx, _stats) =
            crate::runtime::channel::bounded::<Incoming>(1, Backpressure::Reject);
        if !self.pending.insert(key, tx) {
            self.stats.pending_full.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        Some(ReplyHandle {
            key,
            pending: Arc::clone(&self.pending),
            rx,
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
}

impl Reactor {
    /// 组装接收执行体。
    #[must_use]
    pub fn new(transport: Arc<Transport>, shutdown: Shutdown, router: Router) -> Self {
        Self {
            transport,
            shutdown,
            router,
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

/// 便于测试：构造一对「事件接收端 + 路由器」。
#[must_use]
pub fn event_channel(
    capacity: usize,
) -> (Router, Receiver<Incoming>, Arc<crate::runtime::QueueStats>) {
    let (tx, rx, stats) = crate::runtime::channel::bounded(capacity, Backpressure::Reject);
    (Router::new(tx), rx, stats)
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
        let (router, rx, _) = event_channel(4);
        router.route(1234, &header_only(MsgType::StatsQuery, 0));
        assert_eq!(router.stats().foreign_portid(), 1);
        assert_eq!(router.stats().received(), 0);
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn unknown_type_is_counted_not_silently_dropped() {
        let (router, rx, _) = event_channel(4);
        let mut bytes = header_only(MsgType::StatsQuery, 0);
        bytes[4..6].copy_from_slice(&999u16.to_be_bytes());
        router.route(0, &bytes);
        assert_eq!(router.stats().unknown_type(), 1);
        assert_eq!(router.stats().received(), 1, "长度合法，应算作已收到");
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
    }

    #[test]
    fn malformed_header_is_counted() {
        let (router, _rx, _) = event_channel(4);
        // 长度声明与实长不符。
        let mut bytes = header_only(MsgType::StatsQuery, 0);
        bytes[6..8].copy_from_slice(&64u16.to_be_bytes());
        router.route(0, &bytes);
        assert_eq!(router.stats().malformed(), 1);
        assert_eq!(router.stats().received(), 0);
    }

    #[test]
    fn broadcast_event_reaches_the_event_queue() {
        let (router, rx, _) = event_channel(4);
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
        let (router, rx, _) = event_channel(4);
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
        let (router, rx, _) = event_channel(4);
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
        let (router, _rx, _) = event_channel(4);
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
        let (router, _rx, _) = event_channel(4);
        let mut held = Vec::new();
        for i in 0..MAX_IN_FLIGHT {
            held.push(
                router
                    .register(MsgType::StatsResponse, i as u32 + 1)
                    .unwrap_or_else(|| panic!("第 {i} 个在途请求应能登记")),
            );
        }
        assert!(
            router.register(MsgType::StatsResponse, 9999).is_none(),
            "超出容量必须拒绝而不是覆盖已有请求"
        );
        assert_eq!(router.stats().pending_full(), 1);
        assert_eq!(router.in_flight(), MAX_IN_FLIGHT);
    }

    #[test]
    fn pending_claims_are_independent_per_seq() {
        // 并发 LIST 请求不再共用全局单槽：两个不同 seq 各自收到自己的回复。
        let (router, _rx, _) = event_channel(4);
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
        let (router, rx, _) = event_channel(4);
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
