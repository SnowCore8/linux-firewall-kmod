//! 单调时钟（`Instant`）定时器表。
//!
//! 旧实现用 `SystemTime` 记录「上次执行时间」，在主循环里靠 `poll` 超时逐个比较
//! 经过秒数。两个后果：时钟回拨会让定时器停摆；`poll` 超时受事件到达影响，
//! 事件洪泛时维护任务被不断推后（结构问题 A）。
//!
//! 本表以**单调时钟**为唯一时间源，且 `fire_due(now)` 是纯函数：
//! 输入「当前时刻」返回到期集合，不读时钟、不睡觉——因此可在测试里用合成时刻
//! 精确验证「不漂移」。周期定时器到期后按**原定时刻 + 周期**重排，而不是
//! 「实际触发时刻 + 周期」，所以长期运行不累积漂移。

use std::time::{Duration, Instant};

use super::shutdown::Shutdown;
use super::supervisor::Supervisor;

/// 定时器句柄。`cancel` 后该 id 失效；槽位会被后续登记复用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TimerId(usize);

/// 一个到期事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fired {
    /// 一次性定时器到期，已从表中移除。
    OneShot(TimerId),
    /// 周期定时器到期，已重排到下一个周期。
    Repeat(TimerId),
}

/// 定时器槽位。
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// 下次到期时刻（单调时钟）。
    deadline: Instant,
    /// `None` = 一次性；`Some(period)` = 周期。
    period: Option<Duration>,
}

/// 固定容量的单调时钟定时器表。
///
/// 容量在构造期确定，登记满载时 `every`/`at` 返回 `None`（调用方决定如何处理，
/// 不静默丢弃）。定时器数量在编译期可数，故用固定表而非堆分配结构。
#[derive(Debug)]
pub struct TimerTable {
    slots: Vec<Option<Slot>>,
}

impl TimerTable {
    /// 新建容量为 `max_timers` 的表。
    pub fn new(max_timers: usize) -> Self {
        Self {
            slots: (0..max_timers).map(|_| None).collect(),
        }
    }

    /// 登记一个从 `first_fire` 起、每 `period` 触发一次的周期定时器。
    ///
    /// `first_fire` 显式传入（而非内部读时钟），使调用方与测试都能精确控制相位。
    /// 表满时返回 `None`。
    pub fn every(&mut self, period: Duration, first_fire: Instant) -> Option<TimerId> {
        self.insert(Slot {
            deadline: first_fire,
            period: Some(period),
        })
    }

    /// 登记一个在 `deadline` 触发的一次性定时器。表满时返回 `None`。
    pub fn at(&mut self, deadline: Instant) -> Option<TimerId> {
        self.insert(Slot {
            deadline,
            period: None,
        })
    }

    /// 取消定时器。对已取消 / 不存在的 id 调用是幂等的空操作。
    pub fn cancel(&mut self, id: TimerId) {
        if let Some(slot) = self.slots.get_mut(id.0) {
            *slot = None;
        }
    }

    /// 最近的下次到期时刻；无活动定时器时返回 `None`。
    /// 调度线程据此决定睡到何时。
    pub fn next_deadline(&self) -> Option<Instant> {
        self.slots
            .iter()
            .flatten()
            .map(|s| s.deadline)
            .min()
    }

    /// 取出所有 `deadline <= now` 的定时器并推进其状态。纯函数，不读时钟。
    ///
    /// - 一次性：从表中移除，返回 [`Fired::OneShot`]。
    /// - 周期：重排到 `原定时刻 + period`；若已落后超过一个周期（例如线程被长时间
    ///   阻塞），则跳到 `now + period`——**不补发**历史欠账，避免唤醒后突发一串回调。
    pub fn fire_due(&mut self, now: Instant) -> Vec<Fired> {
        let mut fired = Vec::new();
        for idx in 0..self.slots.len() {
            // `Slot` 是 `Copy`，按值取出即可，不持有对表的借用。
            let Some(slot) = self.slots[idx] else { continue };
            if slot.deadline > now {
                continue;
            }
            match slot.period {
                None => {
                    self.slots[idx] = None;
                    fired.push(Fired::OneShot(TimerId(idx)));
                }
                Some(period) => {
                    let mut next = slot.deadline + period;
                    if next <= now {
                        next = now + period;
                    }
                    self.slots[idx] = Some(Slot {
                        deadline: next,
                        period: Some(period),
                    });
                    fired.push(Fired::Repeat(TimerId(idx)));
                }
            }
        }
        fired
    }

    /// 找到空闲槽位并写入，返回其 id；满载返回 `None`。
    fn insert(&mut self, slot: Slot) -> Option<TimerId> {
        let idx = self.slots.iter().position(|s| s.is_none())?;
        self.slots[idx] = Some(slot);
        Some(TimerId(idx))
    }
}

/// 在 `supervisor` 下登记一个 `scheduler` 执行体，按 `table` 到期时间唤醒并调用
/// `on_fire`。
///
/// `token` 是该执行体专属的关停令牌（`Shutdown::new()` 新建，或复用既有令牌）。
/// 调度线程睡到 `next_deadline()`（由关停令牌的精确等待实现），因此
/// **事件吞吐不影响定时器准时性**；无定时器时以 1s 上限轮询等待新登记
/// （当前实现定时器在启动期一次性登记，此处为后续动态登记预留）。
///
/// # Errors
/// 线程创建失败时返回 `std::io::Error`。
pub fn spawn_scheduler(
    sup: &mut Supervisor,
    token: Shutdown,
    mut table: TimerTable,
    mut on_fire: impl FnMut(Fired) + Send + 'static,
) -> std::io::Result<()> {
    let watch = token.clone();
    sup.spawn("scheduler", token, move || {
        while !watch.is_shutdown() {
            for fired in table.fire_due(Instant::now()) {
                on_fire(fired);
            }
            match table.next_deadline() {
                Some(deadline) => {
                    if watch.wait_until(deadline) {
                        break;
                    }
                }
                None => {
                    if watch.wait_timeout(Duration::from_secs(1)) {
                        break;
                    }
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_fires_once_then_is_removed() {
        let mut t = TimerTable::new(4);
        let t0 = Instant::now();
        t.at(t0 + Duration::from_millis(100)).expect("登记失败");

        assert!(t.fire_due(t0).is_empty(), "未到期不应触发");
        let fired = t.fire_due(t0 + Duration::from_millis(100));
        assert_eq!(fired.len(), 1, "到期应触发一次");
        assert!(matches!(fired[0], Fired::OneShot(_)));
        assert!(t.next_deadline().is_none(), "一次性定时器触发后应被移除");
        assert!(
            t.fire_due(t0 + Duration::from_secs(10)).is_empty(),
            "不应二次触发"
        );
    }

    #[test]
    fn repeating_timer_is_drift_free_over_many_steps() {
        let mut t = TimerTable::new(4);
        let t0 = Instant::now();
        let period = Duration::from_millis(100);
        t.every(period, t0 + period).expect("登记失败");

        let mut count = 0;
        for k in 1..=20u32 {
            count += t.fire_due(t0 + period * k).len();
        }
        assert_eq!(count, 20, "每步应各触发一次");
        // 关键：第 21 次到期是 20*period + period，与原定序列严格对齐，无累积漂移。
        assert_eq!(
            t.next_deadline().unwrap(),
            t0 + period * 21,
            "重排必须基于原定时刻 + 周期，不得基于实际触发时刻"
        );
    }

    #[test]
    fn late_wakeup_does_not_burst() {
        let mut t = TimerTable::new(4);
        let t0 = Instant::now();
        let period = Duration::from_secs(1);
        t.every(period, t0 + period).expect("登记失败");

        // 线程被阻塞了 5 个周期以上才醒来：只触发一次，不补发欠账。
        let fired = t.fire_due(t0 + Duration::from_secs(5) + Duration::from_millis(100));
        assert_eq!(fired.len(), 1, "落后时不应突发补发");
        let nd = t.next_deadline().unwrap();
        assert!(nd > t0 + Duration::from_secs(5), "下次到期应在当前时刻之后");
        assert!(
            nd <= t0 + Duration::from_secs(6) + Duration::from_millis(100),
            "下次到期应在一个周期内"
        );
    }

    #[test]
    fn cancel_is_idempotent_and_frees_the_slot() {
        let mut t = TimerTable::new(1);
        let t0 = Instant::now();
        let id = t.at(t0 + Duration::from_secs(1)).expect("登记失败");
        assert!(t.at(t0).is_none(), "容量为 1 时第二次登记应失败");

        t.cancel(id);
        t.cancel(id); // 幂等
        assert!(t.next_deadline().is_none());
        assert!(
            t.at(t0 + Duration::from_secs(2)).is_some(),
            "取消后应释放槽位"
        );
    }

    #[test]
    fn multiple_timers_fire_by_deadline_order() {
        let mut t = TimerTable::new(4);
        let t0 = Instant::now();
        let late = t.at(t0 + Duration::from_secs(10)).unwrap();
        let early = t.at(t0 + Duration::from_secs(1)).unwrap();

        let fired = t.fire_due(t0 + Duration::from_secs(1));
        assert_eq!(fired, vec![Fired::OneShot(early)]);
        assert_eq!(t.next_deadline(), Some(t0 + Duration::from_secs(10)));
        let _ = late;
    }

    #[test]
    fn running_scheduler_fires_on_time_while_producers_churn() {
        use crate::runtime::Shutdown;
        use crate::runtime::Supervisor;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;

        // 高吞吐生产者线程持续制造活动，模拟「事件洪泛」；调度线程必须仍按时触发。
        let shutdown = Shutdown::new();
        let churn_stop = Arc::new(AtomicU32::new(0));
        let churn = {
            let stop = churn_stop.clone();
            std::thread::spawn(move || {
                let mut x: u64 = 0;
                while stop.load(Ordering::Relaxed) == 0 {
                    // 纯 CPU 活动，制造调度压力。
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    std::hint::black_box(x);
                }
            })
        };

        let mut sup = Supervisor::new();
        let token = Shutdown::new();
        let ticks = Arc::new(AtomicU32::new(0));
        let period = Duration::from_millis(10);
        let mut table = TimerTable::new(4);
        // 首个到期点显式给定，之后每 period 一次。
        table
            .every(period, Instant::now() + period)
            .expect("登记定时器失败");
        let ticks_cb = ticks.clone();
        spawn_scheduler(&mut sup, token, table, move |_f| {
            ticks_cb.fetch_add(1, Ordering::SeqCst);
        })
        .expect("登记调度线程失败");

        // 事件驱动等待：轮询真实计数递增，而不是固定 sleep 后碰运气。
        let start = Instant::now();
        while ticks.load(Ordering::SeqCst) < 5 {
            if start.elapsed() > Duration::from_secs(5) {
                churn_stop.store(1, Ordering::Relaxed);
                churn.join().ok();
                panic!("定时器未在合理时间内触发 5 次（事件洪泛下被饿死）");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let elapsed = start.elapsed();

        // 停调度线程与生产者。
        churn_stop.store(1, Ordering::Relaxed);
        let results = sup.shutdown(Duration::from_secs(2));
        churn.join().ok();
        let _ = shutdown;

        // 5 次 10ms 周期：理论上 ~50ms，给调度与 CI 抖动留足余量，但必须远小于
        // 「被饿死」的量级。这证明定时器到期与事件吞吐解耦。
        assert!(
            elapsed < Duration::from_millis(500),
            "定时器明显滞后于事件吞吐: {:?}",
            elapsed
        );
        assert_eq!(results[0].1, crate::runtime::StopOutcome::Joined, "调度线程应正常退出");
    }
}
