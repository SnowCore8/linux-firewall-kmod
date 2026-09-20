//! 有界队列 + 显式背压策略。
//!
//! 设计文档要求「每条队列都必须显式声明满时行为，不允许静默丢弃」。本模块把这条
//! 要求变成类型：构造队列时必须给出 [`Backpressure`]，`send` 按策略行事；
//! [`Backpressure::Reject`] 的拒绝次数进入 [`QueueStats`]，可被监控暴露。
//!
//! - [`Backpressure::Block`]：满时阻塞生产者。用于日志行、失败事件、审计数据等
//!   **证据源**——宁可让上游读慢一点，也不丢消息。
//! - [`Backpressure::Reject`]：满时立即返回 `Err`。用于「不能无界堆积、但拒绝必须
//!   可见」的路径（如封禁下发），由调用方计数、告警并驱动重试。
//!
//! 消费者在主链路里以「`recv()` 返回 `Disconnected` 即退出」的方式级联关停：
//! 上游执行体退出时其 `Sender` 被丢弃，下游据此排空并退出，无需轮询。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// 队列满时的行为。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backpressure {
    /// 阻塞生产者直到有空位。
    Block,
    /// 立即拒绝，把消息交还生产者。
    Reject,
}

/// 发送统计。`sent` 成功入队数；`rejected` 因队列满被拒数。
#[derive(Debug, Default)]
pub struct QueueStats {
    sent: AtomicU64,
    rejected: AtomicU64,
}

impl QueueStats {
    /// 成功入队计数。
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// 因满被拒计数。
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }
}

/// 队列发送端。可克隆，克隆共享同一个底层队列与统计。
#[derive(Debug)]
pub struct Sender<T> {
    inner: crossbeam::channel::Sender<T>,
    policy: Backpressure,
    stats: Arc<QueueStats>,
}

/// 队列接收端。
#[derive(Debug)]
pub struct Receiver<T> {
    inner: crossbeam::channel::Receiver<T>,
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            policy: self.policy,
            stats: self.stats.clone(),
        }
    }
}

/// 新建容量为 `capacity` 的有界队列及发送统计。
///
/// `capacity == 0` 是合法的「会合」队列：`send` 直到消费者接收才返回。
pub fn bounded<T>(
    capacity: usize,
    policy: Backpressure,
) -> (Sender<T>, Receiver<T>, Arc<QueueStats>) {
    let (tx, rx) = crossbeam::channel::bounded(capacity);
    let stats = Arc::new(QueueStats::default());
    (
        Sender {
            inner: tx,
            policy,
            stats: stats.clone(),
        },
        Receiver { inner: rx },
        stats,
    )
}

impl<T> Sender<T> {
    /// 按背压策略投递一条消息。
    ///
    /// - `Block`：队列满时阻塞。
    /// - `Reject`：队列满时返回 `Err(msg)` 并累加 `rejected`。
    ///
    /// 两种策略下，接收端全部退出（`Disconnected`）都返回 `Err(msg)`。
    pub fn send(&self, msg: T) -> Result<(), T> {
        match self.policy {
            Backpressure::Block => match self.inner.send(msg) {
                Ok(()) => {
                    self.stats.sent.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(crossbeam::channel::SendError(m)) => Err(m),
            },
            Backpressure::Reject => match self.inner.try_send(msg) {
                Ok(()) => {
                    self.stats.sent.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }
                Err(crossbeam::channel::TrySendError::Full(m)) => {
                    self.stats.rejected.fetch_add(1, Ordering::Relaxed);
                    Err(m)
                }
                Err(crossbeam::channel::TrySendError::Disconnected(m)) => Err(m),
            },
        }
    }

    /// 当前队列长度。
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 当前队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// 背压策略。
    pub fn policy(&self) -> Backpressure {
        self.policy
    }
}

impl<T> Receiver<T> {
    /// 阻塞接收一条消息；所有发送端退出后返回 `Err`（消费者据此级联退出）。
    pub fn recv(&self) -> Result<T, RecvError> {
        self.inner.recv().map_err(|_| RecvError)
    }

    /// 最多等待 `timeout` 接收一条消息。
    pub fn recv_timeout(&self, timeout: Duration) -> Result<T, RecvTimeoutError> {
        self.inner.recv_timeout(timeout).map_err(|e| match e {
            crossbeam::channel::RecvTimeoutError::Timeout => RecvTimeoutError::Timeout,
            crossbeam::channel::RecvTimeoutError::Disconnected => RecvTimeoutError::Disconnected,
        })
    }

    /// 非阻塞接收。
    pub fn try_recv(&self) -> Result<T, TryRecvError> {
        self.inner.try_recv().map_err(|e| match e {
            crossbeam::channel::TryRecvError::Empty => TryRecvError::Empty,
            crossbeam::channel::TryRecvError::Disconnected => TryRecvError::Disconnected,
        })
    }

    /// 当前队列长度。
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 当前队列是否为空。
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// `recv` 失败：所有发送端已退出。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecvError;

/// `recv_timeout` 失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvTimeoutError {
    /// 超时内无消息。
    Timeout,
    /// 所有发送端已退出。
    Disconnected,
}

/// `try_recv` 失败原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TryRecvError {
    /// 队列为空。
    Empty,
    /// 所有发送端已退出。
    Disconnected,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_policy_returns_message_and_counts_when_full() {
        let (tx, _rx, stats) = bounded::<u32>(1, Backpressure::Reject);
        assert!(tx.send(1).is_ok());
        // 容量 1 已满：第二次应被拒并计数，且消息被交还。
        assert_eq!(tx.send(2), Err(2));
        assert_eq!(stats.rejected(), 1);
        assert_eq!(stats.sent(), 1);
    }

    #[test]
    fn block_policy_never_loses_messages() {
        let (tx, rx, stats) = bounded::<u32>(2, Backpressure::Block);
        const N: u32 = 200;
        let producer = std::thread::spawn(move || {
            for i in 0..N {
                // Block 策略下 send 只在接收端全部退出时才 Err。
                tx.send(i).expect("阻塞发送不应失败");
            }
        });
        // 消费端慢速接收，迫使生产者持续阻塞。
        let mut got = Vec::new();
        while let Ok(v) = rx.recv() {
            got.push(v);
            if got.len() as u32 == N {
                break;
            }
        }
        producer.join().expect("生产者不应 panic");
        assert_eq!(got.len(), N as usize, "阻塞背压不得丢消息");
        assert_eq!(got, (0..N).collect::<Vec<_>>(), "顺序必须保持");
        assert_eq!(stats.rejected(), 0, "阻塞策略不产生拒绝");
    }

    #[test]
    fn consumer_sees_disconnect_when_all_senders_drop() {
        let (tx, rx, _stats) = bounded::<u32>(4, Backpressure::Block);
        tx.send(7).expect("入队失败");
        drop(tx);
        assert_eq!(rx.recv(), Ok(7));
        assert_eq!(rx.recv(), Err(RecvError), "发送端退出后应观察到断开");
    }

    #[test]
    fn try_recv_distinguishes_empty_from_disconnected() {
        let (tx, rx, _stats) = bounded::<u32>(4, Backpressure::Block);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Empty));
        drop(tx);
        assert_eq!(rx.try_recv(), Err(TryRecvError::Disconnected));
    }

    #[test]
    fn clones_share_stats() {
        let (tx, _rx, stats) = bounded::<u32>(1, Backpressure::Reject);
        let tx2 = tx.clone();
        tx.send(1).expect("入队失败");
        assert_eq!(tx2.send(2), Err(2), "克隆应看到同一队列已满");
        assert_eq!(stats.rejected(), 1, "克隆与原始共享统计");
    }
}
