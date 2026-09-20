//! 执行体登记与按依赖逆序关停。
//!
//! 重写的关停不变量是「netlink 停止后才允许 flush 持久化」。要真正成立，就不能
//! 一次性把停止信号发给所有执行体——那样下游与上游同时开始收尾，无法保证
//! 「上游已完全停止」这一前提。因此本模块**逐段串行停止**：
//!
//! 1. 每个执行体持有**自己的** [`Shutdown`] 令牌；
//! 2. `shutdown()` 按**登记逆序**处理，对当前段 `request()` 后 `join` 到结束，
//!    才停止下一段。
//!
//! 登记顺序 = 依赖顺序（下游先登记）。例如：
//! ```ignore
//! let mut sup = Supervisor::new();
//! sup.spawn("persist", persist_token, || persist_body())?;  // 下游，最后停
//! sup.spawn("reactor", reactor_token, || reactor_body())?;
//! sup.spawn("ingest",  ingest_token,  || ingest_body())?;    // 上游，最先停
//! sup.shutdown(Duration::from_secs(5));  // ingest 完全停 → reactor → persist
//! ```
//!
//! 逆序串行还消除了一类死锁：上游（先停）若阻塞向队列投递，此时下游（后停）仍在
//! 消费，投递得以完成；上游排空退出后，才轮到下游收尾。

use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::shutdown::Shutdown;

/// 单个执行体的关停结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// 正常退出并已 `join`。
    Joined,
    /// 超时未退出；句柄被丢弃（线程可能仍在运行）。
    TimedOut,
}

/// 一个已登记的执行体。
struct Executor {
    /// 人类可读名字，用于日志与结果回报。
    name: String,
    /// 该执行体专属的关停令牌。
    token: Shutdown,
    /// join 句柄。
    handle: JoinHandle<()>,
}

/// 执行体登记表。
pub struct Supervisor {
    /// 按**依赖顺序**保存（下游在前）；关停时逆序处理。
    executors: Vec<Executor>,
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl Supervisor {
    /// 新建空登记表。
    pub fn new() -> Self {
        Self {
            executors: Vec::new(),
        }
    }

    /// 已登记执行体数量。
    pub fn len(&self) -> usize {
        self.executors.len()
    }

    /// 登记表是否为空。
    pub fn is_empty(&self) -> bool {
        self.executors.is_empty()
    }

    /// 登记一个执行体。`token` 是该执行体**专属**的关停令牌；`body` 应监视它并自行退出。
    ///
    /// **登记顺序即依赖顺序**：先登记的（下游）在关停时最后停。
    ///
    /// # Errors
    /// 线程创建失败时返回 `std::io::Error`。
    pub fn spawn<F>(&mut self, name: &str, token: Shutdown, body: F) -> std::io::Result<()>
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new().name(name.to_string()).spawn(body)?;
        self.executors.push(Executor {
            name: name.to_string(),
            token,
            handle,
        });
        Ok(())
    }

    /// 按**登记逆序**逐段串行关停，每段等待上限 `timeout`。
    ///
    /// 返回 `(name, outcome)` 列表，顺序即实际关停顺序。调用方应在关停前已让信号层
    /// 触发本方法（例如主线程等待 SIGTERM 后调用）。
    pub fn shutdown(&mut self, timeout: Duration) -> Vec<(String, StopOutcome)> {
        let mut results = Vec::with_capacity(self.executors.len());
        // 逆序：最后登记的（最上游、如 ingest）最先停。
        while let Some(exec) = self.executors.pop() {
            // 只停止当前段；下游段此间仍在运行，保证上游排空时不丢消息。
            exec.token.request();
            let outcome = join_with_timeout(exec.handle, timeout);
            results.push((exec.name, outcome));
        }
        results
    }
}

/// 在 `timeout` 内等待 `handle` 结束；超时返回 [`StopOutcome::TimedOut`]。
///
/// `JoinHandle` 没有带超时的 join，故用 `is_finished()` 探针：完成后立即 `join`
/// 取回（并吞掉 panic——执行体 panic 不应让关停流程崩掉）。
fn join_with_timeout(handle: JoinHandle<()>, timeout: Duration) -> StopOutcome {
    let start = Instant::now();
    loop {
        if handle.is_finished() {
            let _ = handle.join();
            return StopOutcome::Joined;
        }
        if start.elapsed() >= timeout {
            return StopOutcome::TimedOut;
        }
        // 探针间隔远小于 timeout，保证既不过度自旋也不明显拖后关停。
        let remaining = timeout.saturating_sub(start.elapsed());
        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    /// 每个执行体在退出瞬间写入 `(退出序号, 名字)` 的槽位。
    type ExitSlot = Arc<Mutex<Option<(u32, String)>>>;

    #[test]
    fn shutdown_order_is_reverse_of_registration() {
        let mut sup = Supervisor::new();
        // 退出顺序计数器：谁先退出谁拿更小的序号。逐段串行停下，故序号是确定的。
        let counter = Arc::new(AtomicU32::new(0));
        let mut exit_slots: Vec<ExitSlot> = Vec::new();

        for name in ["A", "B", "C"] {
            let token = Shutdown::new();
            let c = counter.clone();
            let slot: ExitSlot = Arc::new(Mutex::new(None));
            exit_slots.push(slot.clone());
            let n = name.to_string();
            let watch = token.clone();
            let body_name = n.clone();
            sup.spawn(&n, token, move || {
                watch.wait();
                let seq = c.fetch_add(1, Ordering::SeqCst);
                *slot.lock().unwrap() = Some((seq, body_name));
            })
            .expect("线程创建失败");
        }

        let results = sup.shutdown(Duration::from_secs(5));
        let stop_order: Vec<&str> = results.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(stop_order, vec!["C", "B", "A"], "关停必须按登记逆序");
        assert!(
            results.iter().all(|(_, o)| *o == StopOutcome::Joined),
            "所有执行体应正常退出: {:?}",
            results
        );

        // 逐段串行停止 ⇒ 退出序号严格为 C<B<A。
        let seq_of = |name: &str| -> u32 {
            exit_slots
                .iter()
                .filter_map(|s| s.lock().unwrap().clone())
                .find(|(_, n)| n == name)
                .unwrap_or_else(|| panic!("缺少 {} 的退出记录", name))
                .0
        };
        assert!(seq_of("C") < seq_of("B"), "C 应在 B 之前退出");
        assert!(seq_of("B") < seq_of("A"), "B 应在 A 之前退出");
    }

    #[test]
    fn upstream_is_fully_stopped_before_downstream_stops() {
        // 下游（先登记）记录：自己停止时，上游（后登记）是否已停止。
        let downstream_token = Shutdown::new();
        let upstream_token = Shutdown::new();
        let mut sup = Supervisor::new();

        let upstream_seen_stopped = Arc::new(AtomicU32::new(0));
        let recorded = Arc::new(Mutex::new(false));

        // 下游：先登记 → 最后停。它停止时应观察到上游已停止。
        let recorded_d = recorded.clone();
        let up = upstream_seen_stopped.clone();
        sup.spawn("downstream", downstream_token.clone(), move || {
            downstream_token.wait();
            *recorded_d.lock().unwrap() = up.load(Ordering::SeqCst) == 1;
        })
        .expect("线程创建失败");

        // 上游：后登记 → 最先停。它停止时把标志置 1。
        let up2 = upstream_seen_stopped.clone();
        sup.spawn("upstream", upstream_token.clone(), move || {
            upstream_token.wait();
            up2.store(1, Ordering::SeqCst);
        })
        .expect("线程创建失败");

        sup.shutdown(Duration::from_secs(5));
        assert!(
            *recorded.lock().unwrap(),
            "下游停止时上游必须已完全停止（否则不变量失效）"
        );
    }

    #[test]
    fn shutdown_reports_timeout_for_a_stuck_executor() {
        let stuck_token = Shutdown::new();
        let mut sup = Supervisor::new();
        // 不监视关停令牌的执行体：模拟卡死。
        sup.spawn("stuck", stuck_token, || {
            std::thread::sleep(Duration::from_secs(30));
        })
        .expect("线程创建失败");

        let start = Instant::now();
        let results = sup.shutdown(Duration::from_millis(50));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, StopOutcome::TimedOut);
        // 不应为了等待卡死执行体而超出 timeout 太多。
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "超时应快速返回，实际 {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn empty_supervisor_shuts_down_cleanly() {
        let mut sup = Supervisor::new();
        assert!(sup.is_empty());
        let results = sup.shutdown(Duration::from_millis(10));
        assert!(results.is_empty());
    }
}
