//! 运行时骨架：执行体生命周期、单调时钟定时器、有界队列契约。
//!
//! 本模块是 Phase 2 重写的公共底座，由组合根（`main.rs`）装配：
//!
//! - [`shutdown`]：协作式关停令牌。请求立即置位并唤醒等待者，执行体既可轮询
//!   `is_shutdown()`，也可精确 `wait_until(deadline)`（供调度线程睡到下一个到期点）。
//! - [`supervisor`]：执行体登记与**按依赖逆序**关停，逐个 `join` 完成后才关下一个。
//!   「netlink 停止后才允许 flush 持久化」由**顺序**保证，而不是靠注释提醒。
//! - [`timers`]：单调时钟（`Instant`）定时器表。到期判据是经过时间，与事件吞吐无关，
//!   消除「事件洪泛时维护任务被饿死」这一结构问题。
//! - [`scheduler`]：组合根的周期任务集合（计数器镜像、过期封禁清理），按上面的定时器
//!   表节拍驱动。
//! - [`channel`]：有界队列 + 显式背压策略（阻塞 / 拒绝并计数），禁止静默丢弃。

pub mod channel;
pub mod scheduler;
pub mod shutdown;
pub mod supervisor;
pub mod timers;

pub use channel::{
    bounded, Backpressure, QueueStats, Receiver, RecvError, RecvTimeoutError, Sender, TryRecvError,
};
pub use scheduler::spawn_periodic;
pub use shutdown::Shutdown;
pub use supervisor::{StopOutcome, Supervisor};
pub use timers::{spawn_scheduler, Fired, TimerId, TimerTable};
