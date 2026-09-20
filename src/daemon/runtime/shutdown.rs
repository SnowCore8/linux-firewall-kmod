//! 协作式关停令牌。
//!
//! 旧实现把信号写进全局 `AtomicBool`，执行体每轮循环轮询它，并依赖 `poll` 被信号
//! 打断返回 `EINTR` 这一隐式协议。两个问题：轮询间隔决定关停延迟；阻塞在
//! `read`/`recv` 上的执行体在下一轮之前看不到标志。
//!
//! 本类型用「原子标志 + 条件变量」：`request()` 立即置位并唤醒全部等待者。
//! 执行体可以
//! - `is_shutdown()` 轮询（配合带超时的 `poll` 使用），或
//! - `wait()` / `wait_until(deadline)` 精确等待（调度线程睡到下一个定时器到期点）。
//!
//! 克隆廉价：所有克隆共享同一标志与唤醒通道。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// 一次运行期的关停令牌。可廉价克隆，克隆共享同一标志与唤醒通道。
#[derive(Clone)]
pub struct Shutdown {
    /// 供 `is_shutdown()` 无锁快速读取。
    flag: Arc<AtomicBool>,
    /// 与 `flag` 配对的监视器；`Mutex<bool>` 里的布尔是同一语义的受保护副本，
    /// 用于条件变量等待，避免等待者与置位者各看一份状态而丢唤醒。
    cv: Arc<(Mutex<bool>, Condvar)>,
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl Shutdown {
    /// 新建未关停的令牌。
    pub fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            cv: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    /// 请求关停：置位标志并唤醒全部等待者。幂等，可重复调用。
    pub fn request(&self) {
        self.flag.store(true, Ordering::SeqCst);
        let (lock, cv) = &*self.cv;
        // 持锁者在等待期间不可能持锁，故中毒只可能来自持锁者 panic；此时仍取回数据。
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        *ready = true;
        cv.notify_all();
    }

    /// 是否已请求关停。执行体每轮循环调用它，配合 `poll` 超时即可。
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// 阻塞直到被请求关停。
    pub fn wait(&self) {
        let (lock, cv) = &*self.cv;
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        while !*ready {
            ready = cv.wait(ready).unwrap_or_else(|e| e.into_inner());
        }
    }

    /// 最多等待 `timeout`；返回 `true` 表示已被请求关停。
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &*self.cv;
        let mut ready = lock.lock().unwrap_or_else(|e| e.into_inner());
        // 循环以抵御虚假唤醒：只有置位或真正超时才返回。
        while !*ready {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let (guard, _) = cv
                .wait_timeout(ready, deadline - now)
                .unwrap_or_else(|e| e.into_inner());
            ready = guard;
        }
        true
    }

    /// 睡到 `deadline`（单调时钟）或被请求关停为止；返回 `true` 表示被关停。
    pub fn wait_until(&self, deadline: Instant) -> bool {
        let now = Instant::now();
        if deadline <= now {
            return self.is_shutdown();
        }
        self.wait_timeout(deadline - now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_token_is_not_shutdown() {
        let t = Shutdown::new();
        assert!(!t.is_shutdown());
        assert!(!t.wait_timeout(Duration::from_millis(1)));
    }

    #[test]
    fn request_wakes_a_blocked_waiter() {
        let t = Shutdown::new();
        let waker = t.clone();
        let started = Instant::now();
        let handle = std::thread::spawn(move || {
            waker.wait();
            started.elapsed()
        });
        // 给等待线程时间进入 wait()，再请求关停（不依赖固定 sleep 判定结果）。
        std::thread::sleep(Duration::from_millis(20));
        assert!(!handle.is_finished(), "wait() 不应在请求前返回");
        t.request();
        let elapsed = handle.join().expect("等待线程不应 panic");
        assert!(elapsed < Duration::from_secs(5), "关停后应立即唤醒，实际 {:?}", elapsed);
    }

    #[test]
    fn request_is_idempotent_and_visible_to_all_clones() {
        let t = Shutdown::new();
        let other = t.clone();
        t.request();
        t.request();
        assert!(other.is_shutdown(), "克隆应看到关停状态");
    }

    #[test]
    fn wait_until_returns_false_when_deadline_passes() {
        let t = Shutdown::new();
        let woke = t.wait_until(Instant::now() + Duration::from_millis(10));
        assert!(!woke, "到期未关停应返回 false");
    }

    #[test]
    fn wait_until_returns_true_when_already_shutdown() {
        let t = Shutdown::new();
        t.request();
        // 死线已过：应直接看到关停状态而不是等待。
        assert!(t.wait_until(Instant::now()));
    }
}
