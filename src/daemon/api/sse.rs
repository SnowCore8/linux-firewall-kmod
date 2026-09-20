//! SSE 推送：**按域序列化** + **慢消费者隔离**（修缺陷 F）。
//!
//! # 缺陷 F 是什么
//!
//! 旧 `web_ui/sse.rs` 每个 tick 把 5 份载荷（stats/bans/jails/whitelist/rates）
//! **全量**重新 `serde_json::to_string`，无论有没有变化；而且这段序列化在每条连接
//! 的循环里各做一遍。成本是「连接数 × 域数 × 每秒一次」，payload 越大越明显。
//!
//! # 本模块的两条结构性保证
//!
//! 1. **只序列化变化的域**。连接持有 [`Versions`]，每轮对比出真正变化的域，
//!    只对它们调用渲染器。初次连接发全部域（新连接需要完整初值）。
//! 2. **慢消费者不拖慢全局**。写侧（`state::hub`）只做「推进版本 + `watch`
//!    覆盖式通知」，**不等待任何订阅者**；序列化与发送都发生在**每条连接自己的
//!    任务**里，中间隔一个有界缓冲。缓冲满即判定消费者过慢，**断开该连接**，
//!    而不是无限排队或让写侧阻塞。
//!
//! 第 2 条是结构性的而非尽力而为：`watch` 只保留最新值、`send_replace` 不阻塞，
//! 所以「有多少条连接、其中几条卡住」对写侧完全不可见。

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio::sync::{mpsc, watch};
use tokio_stream::Stream;

use crate::state::hub::{Domain, Versions};

use super::payloads::{SseStatusResponse, SseStreamStatus};

/// `/api/v1/events` 的连接上限（契约 `sse.max_connections`）。
pub const MAX_SSE_CONNECTIONS: usize = 10;

/// `/api/v1/logs/stream` 的连接上限（契约；与上一条**各自独立**）。
pub const MAX_LOG_SSE_CONNECTIONS: usize = 5;

/// keep-alive 间隔（秒），契约 `keepalive_secs`。
pub const KEEPALIVE_SECS: u64 = 15;

/// 单条连接的发送缓冲深度。
///
/// 取值只需要「略大于一屏突发」：够吸收一次多域同时变更的突发，又不至于把
/// 慢消费者的积压藏起来。溢出即视为消费者过慢。
pub const PER_CONNECTION_BUFFER: usize = 32;

/// 连接位已满时返回给客户端的状态码（契约 `alt_status`）。
pub const LIMIT_REACHED_STATUS: StatusCode = StatusCode::SERVICE_UNAVAILABLE;

/// 要把快照渲染成 JSON 的对象。
///
/// 抽成 trait 有两个目的：一是让本模块不必知道任何具体载荷类型（具体载荷由上
/// 层装配代码渲染）；二是让「只序列化变化的域」这条保证可以被测试直接计数验证，
/// 而不必起 HTTP 连接。
pub trait DomainRenderer: Send + Sync + 'static {
    /// 渲染某个域的当前快照。返回 `None` 表示该域当前无内容可发（例如无 Jail）。
    fn render(&self, domain: Domain) -> Option<String>;
}

/// 连接结束的原因。
///
/// 显式区分而不是都退化成「流结束」：慢消费者的断开是需要被看见的运行事件，
/// 混杂在「写侧已关停」里就再也分不出来。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disconnect {
    /// 消费端已被丢弃（客户端断开）。
    ConsumerGone,
    /// 发送缓冲满——消费者过慢，按设计断开而非阻塞写侧。
    SlowConsumer,
    /// 版本发布点已关闭（进程正在关停）。
    HubClosed,
}

/// 两条流各自的连接计数与上限。
///
/// 两条流的上限**独立**（10 / 5），诊断端点必须分别报告——缺陷
/// `HTTP_SSE_STATUS_INCOMPLETE` 就是「用一条流的上限推断另一条」。
#[derive(Debug)]
pub struct SseStatus {
    events: Arc<StreamCounter>,
    logs: Arc<StreamCounter>,
}

impl Default for SseStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl SseStatus {
    /// 构造两条全空的流计数。
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Arc::new(StreamCounter::new(MAX_SSE_CONNECTIONS)),
            logs: Arc::new(StreamCounter::new(MAX_LOG_SSE_CONNECTIONS)),
        }
    }

    /// 尝试占用一个 `/api/v1/events` 连接位。
    #[must_use]
    pub fn acquire_events(&self) -> Option<ConnectionGuard> {
        self.events.acquire()
    }

    /// 尝试占用一个 `/api/v1/logs/stream` 连接位。
    #[must_use]
    pub fn acquire_logs(&self) -> Option<ConnectionGuard> {
        self.logs.acquire()
    }

    /// 当前两条流的状态（供 `/api/v1/stats/sse-status`）。
    #[must_use]
    pub fn snapshot(&self) -> SseStatusResponse {
        SseStatusResponse {
            events: self.events.status(),
            logs: self.logs.status(),
        }
    }
}

/// 单条流的连接计数。
#[derive(Debug)]
struct StreamCounter {
    current: AtomicUsize,
    max: usize,
}

impl StreamCounter {
    const fn new(max: usize) -> Self {
        Self {
            current: AtomicUsize::new(0),
            max,
        }
    }

    /// 原子地占一个位：满了返回 `None`。
    ///
    /// 用 `compare_exchange_weak` 循环而不是「先读后写」，是为了消除检查与递增
    /// 之间的窗口——否则并发建连时可能一起越过上限。
    fn acquire(self: &Arc<Self>) -> Option<ConnectionGuard> {
        let mut current = self.current.load(Ordering::Relaxed);
        loop {
            if current >= self.max {
                return None;
            }
            match self.current.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(ConnectionGuard {
                        counter: Arc::clone(self),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn status(&self) -> SseStreamStatus {
        SseStreamStatus::new(self.current.load(Ordering::Relaxed), self.max)
    }
}

/// 连接位守卫：随流结束（客户端断开或服务端停止）自动归还。
#[derive(Debug)]
pub struct ConnectionGuard {
    counter: Arc<StreamCounter>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.counter.current.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 一条待发事件（事件名 + JSON 载荷）。
///
/// 核心循环只产出本类型，`axum::response::sse::Event` 的构造留给最外层转换。
/// 这样「发了哪些事件、每个域渲染了几次」可以在测试里直接断言，而不必去解构
/// `Event`（它没有暴露 getter）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMessage {
    /// SSE 事件名（契约里的事件集）。
    pub event: String,
    /// JSON 载荷。
    pub data: String,
}

impl StreamMessage {
    /// 构造一条事件。
    #[must_use]
    pub fn new(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            event: event.into(),
            data: data.into(),
        }
    }

    /// 转成 axum 的 SSE 事件。
    pub fn into_event(self) -> Event {
        Event::default().event(self.event).data(self.data)
    }
}

/// 尝试投递一条事件：缓冲满或消费端已走都返回 `Err`。
///
/// 两者在此处**故意合并**：对调用方而言「没人接」与「接得比发得慢」的处置相同
/// ——断开这条连接，绝不让写侧等待。
fn try_send_message(tx: &mpsc::Sender<StreamMessage>, msg: StreamMessage) -> Result<(), ()> {
    match tx.try_send(msg) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
            Err(())
        }
    }
}

/// 一条管理事件流的任务：订阅版本，只推变化的域。
///
/// 返回结束原因，便于调用方统计（尤其是 [`Disconnect::SlowConsumer`]）。
pub async fn drive_events_stream(
    mut versions: watch::Receiver<Versions>,
    renderer: Arc<dyn DomainRenderer>,
    tx: mpsc::Sender<StreamMessage>,
) -> Disconnect {
    // 先发连接确认：前端据此认为流已就绪，早于任何数据事件。
    let hello = StreamMessage::new("connected", "SSE 连接已建立");
    if try_send_message(&tx, hello).is_err() {
        return Disconnect::ConsumerGone;
    }

    // `None` 表示「本连接还没发过任何快照」，此时发全部域。
    let mut sent: Option<Versions> = None;
    loop {
        let current = *versions.borrow_and_update();
        let domains: Vec<Domain> = match sent {
            None => Domain::ALL.to_vec(),
            Some(previous) => current.changed(previous),
        };

        for domain in domains {
            let Some(json) = renderer.render(domain) else {
                continue;
            };
            if try_send_message(&tx, StreamMessage::new(domain.name(), json)).is_err() {
                return Disconnect::SlowConsumer;
            }
        }
        sent = Some(current);

        // 等下一次版本推进。`watch` 只保留最新值：落在这期间的多次变更会合并成
        // 一次唤醒，下一次循环按 `sent` 差集补发——这正是「中间态可丢、最新态必到」。
        if versions.changed().await.is_err() {
            return Disconnect::HubClosed;
        }
    }
}

/// 构造 SSE 响应：每条连接一个生产者任务 + 一个有界缓冲。
///
/// `guard` 由调用方在成功占位后传入，随流一起存活——流被丢弃时归还连接位。
pub fn events_response(
    versions: watch::Receiver<Versions>,
    renderer: Arc<dyn DomainRenderer>,
    guard: ConnectionGuard,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (tx, mut rx) = mpsc::channel::<StreamMessage>(PER_CONNECTION_BUFFER);
    tokio::spawn(async move {
        let _guard = guard;
        if drive_events_stream(versions, renderer, tx).await == Disconnect::SlowConsumer {
            crate::logger::warn!(
                crate::logger::get(),
                "SSE 连接因消费过慢被断开";
                "buffer" => PER_CONNECTION_BUFFER
            );
        }
    });

    let stream = async_stream::stream! {
        while let Some(msg) = rx.recv().await {
            yield Ok(msg.into_event());
        }
    };

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(KEEPALIVE_SECS))
            .text("keep-alive"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::hub::Hub;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 记下每个域被渲染了几次，用于断言「只序列化变化的域」。
    struct CountingRenderer {
        calls: Mutex<HashMap<Domain, usize>>,
    }

    impl CountingRenderer {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(HashMap::new()),
            })
        }

        fn count(&self, domain: Domain) -> usize {
            self.calls
                .lock()
                .expect("锁未中毒")
                .get(&domain)
                .copied()
                .unwrap_or(0)
        }
    }

    impl DomainRenderer for CountingRenderer {
        fn render(&self, domain: Domain) -> Option<String> {
            *self
                .calls
                .lock()
                .expect("锁未中毒")
                .entry(domain)
                .or_insert(0) += 1;
            Some(format!("{{\"domain\":\"{}\"}}", domain.name()))
        }
    }

    /// 永不返回内容的渲染器：验证「无内容可发的域不发事件」。
    struct SilentRenderer;

    impl DomainRenderer for SilentRenderer {
        fn render(&self, _domain: Domain) -> Option<String> {
            None
        }
    }

    fn hub() -> Arc<Hub> {
        Arc::new(Hub::new())
    }

    fn all_domain_names_sorted() -> Vec<String> {
        let mut names: Vec<String> = Domain::ALL.iter().map(|d| d.name().to_string()).collect();
        names.sort();
        names
    }

    /// 读掉 `connected`，再读满全部 5 个域，返回排好序的域事件名。
    async fn drain_initial(rx: &mut mpsc::Receiver<StreamMessage>) -> Vec<String> {
        let first = rx.recv().await.expect("应有 connected");
        assert_eq!(first.event, "connected");
        let mut names = Vec::new();
        for _ in 0..Domain::ALL.len() {
            names.push(rx.recv().await.expect("应有域事件").event);
        }
        names.sort();
        names
    }

    #[tokio::test]
    async fn a_fresh_connection_receives_every_domain_once() {
        let hub = hub();
        let renderer = CountingRenderer::new();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(drive_events_stream(
            hub.subscribe(),
            Arc::clone(&renderer) as Arc<dyn DomainRenderer>,
            tx,
        ));

        let names = drain_initial(&mut rx).await;
        assert_eq!(names, all_domain_names_sorted(), "新连接应收到全部 5 个域");
        assert_eq!(renderer.count(Domain::Bans), 1);

        handle.abort();
    }

    #[tokio::test]
    async fn only_changed_domains_are_serialized_after_the_first_tick() {
        let hub = hub();
        let renderer = CountingRenderer::new();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(drive_events_stream(
            hub.subscribe(),
            Arc::clone(&renderer) as Arc<dyn DomainRenderer>,
            tx,
        ));
        let _ = drain_initial(&mut rx).await;

        // 只推进 Bans。
        hub.publish(Domain::Bans);
        let msg = rx.recv().await.expect("应有事件");
        assert_eq!(msg.event, "bans");
        assert_eq!(renderer.count(Domain::Bans), 2);

        // 其余域不得被重新序列化。
        for domain in Domain::ALL {
            if domain != Domain::Bans {
                assert_eq!(
                    renderer.count(domain),
                    1,
                    "{domain:?} 未变化却被重新序列化（缺陷 F）"
                );
            }
        }

        handle.abort();
    }

    #[tokio::test]
    async fn several_publishes_coalesce_into_one_render_of_the_latest_state() {
        // 中间态可丢、最新态必到：三次连推只应触发一次补发。
        let hub = hub();
        let renderer = CountingRenderer::new();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(drive_events_stream(
            hub.subscribe(),
            Arc::clone(&renderer) as Arc<dyn DomainRenderer>,
            tx,
        ));
        let _ = drain_initial(&mut rx).await;

        hub.publish(Domain::Rates);
        hub.publish(Domain::Rates);
        hub.publish(Domain::Rates);
        let msg = rx.recv().await.expect("应有事件");
        assert_eq!(msg.event, "rates");
        // 连推三次只应补发一次（下一次唤醒时按差集）。
        let extra = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(extra.is_err(), "合并后的重复推送不应产生额外事件");

        handle.abort();
    }

    #[tokio::test]
    async fn a_domain_with_nothing_to_send_produces_no_event() {
        let hub = hub();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(drive_events_stream(
            hub.subscribe(),
            Arc::new(SilentRenderer) as Arc<dyn DomainRenderer>,
            tx,
        ));

        let first = rx.recv().await.expect("应有 connected");
        assert_eq!(first.event, "connected");

        hub.publish(Domain::Jails);
        // 静默渲染器不产生任何域事件。
        let nothing = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(nothing.is_err(), "无内容可发的域不应产生事件");

        handle.abort();
    }

    #[tokio::test]
    async fn a_slow_consumer_is_disconnected_rather_than_blocking() {
        // 缓冲极小且无人消费：生产者必须结束，而不是无限等待。
        let hub = hub();
        let renderer = CountingRenderer::new();
        let (tx, _idle) = mpsc::channel::<StreamMessage>(1);
        let reason = drive_events_stream(
            hub.subscribe(),
            Arc::clone(&renderer) as Arc<dyn DomainRenderer>,
            tx,
        )
        .await;
        // connected 占满缓冲，第一个域事件即溢出。
        assert_eq!(reason, Disconnect::SlowConsumer);
    }

    #[tokio::test]
    async fn a_closed_hub_ends_the_connection() {
        let hub = hub();
        let renderer = CountingRenderer::new();
        let (tx, mut rx) = mpsc::channel(64);
        let handle = tokio::spawn(drive_events_stream(
            hub.subscribe(),
            Arc::clone(&renderer) as Arc<dyn DomainRenderer>,
            tx,
        ));
        let _ = drain_initial(&mut rx).await;
        drop(hub);
        // 发布点消失后，连接应结束而不是空转。
        let reason = handle.await.expect("任务应正常结束");
        assert_eq!(reason, Disconnect::HubClosed);
    }

    #[tokio::test]
    async fn the_connection_guard_returns_its_slot_on_drop() {
        let status = SseStatus::new();
        assert_eq!(status.snapshot().events.current_connections, 0);
        let guard = status.acquire_events().expect("首次占位应成功");
        assert_eq!(status.snapshot().events.current_connections, 1);
        drop(guard);
        assert_eq!(
            status.snapshot().events.current_connections,
            0,
            "守卫析构必须归还连接位"
        );
    }

    #[test]
    fn each_stream_has_its_own_limit_and_they_are_independent() {
        let status = SseStatus::new();
        // 占满日志流（5）。
        let logs: Vec<ConnectionGuard> = (0..MAX_LOG_SSE_CONNECTIONS)
            .map(|_| status.acquire_logs().expect("未满时应成功"))
            .collect();
        assert!(status.acquire_logs().is_none(), "日志流满后应拒绝");
        assert!(
            status.snapshot().events.current_connections == 0,
            "日志流满不得影响管理流计数"
        );
        assert!(status.snapshot().logs.limit_reached);
        assert!(!status.snapshot().events.limit_reached);
        drop(logs);
        assert!(!status.snapshot().logs.limit_reached, "归还后应恢复");
    }

    #[test]
    fn the_events_stream_refuses_the_eleventh_connection() {
        let status = SseStatus::new();
        let guards: Vec<ConnectionGuard> = (0..MAX_SSE_CONNECTIONS)
            .map(|_| status.acquire_events().expect("未满时应成功"))
            .collect();
        assert!(
            status.acquire_events().is_none(),
            "第 11 条连接必须被拒绝（契约上限 10）"
        );
        drop(guards);
        assert!(status.acquire_events().is_some(), "全部归还后应能再占");
    }
}
