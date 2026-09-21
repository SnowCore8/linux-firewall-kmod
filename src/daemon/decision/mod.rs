//! 判定层：失败窗口 + 封禁策略。
//!
//! 拆成「有状态」与「纯函数」两半，是这一层最关键的分界：
//!
//! | 子模块 | 职责 | 状态 |
//! |--------|------|------|
//! | [`window`] | 每 jail 的失败时间戳窗口 | 该 jail 判定执行体独占，无锁 |
//! | [`policy`] | 有效阈值、渐进式时长、封禁计划 | 无（纯函数） |
//! | [`ddos`] | 内核推送的 DDoS 事件：计数、每 IP 违规跟踪、日志 | 自持锁；只写 `DDOS_STATS` |
//!
//! 旧实现把前两者绞在 `failed_tracker::handle_failed_attempt_for_jail` 一个函数里，还顺带
//! 访问信誉分 store、`BAN_HISTORY`、`ACTIVE_BAN_CACHE` 三个全局态并调用 netlink 下发。
//! 这里只保留「算与记」：**是否下发由调用方决定**，本层不发任何报文、不碰封禁表。
//!
//! [`ddos`] 与另外两半的纯粹性不同：内核已自行完成封禁，守护进程在这里只写
//! `DDOS_STATS` 与日志，不做决策也不下发。它仍留在本层，是因为三者共同构成判定
//! 语义，且消费方 [`crate::inbound`] 需要在同一处取用。

pub mod ddos;
pub mod policy;
pub mod window;

pub use ddos::DdosDecisionEngine;
pub use policy::{
    effective_threshold, is_internal, is_peak_hours, plan_ban, progressive_duration,
    reputation_multiplier, BanPlan,
};
pub use window::{FailureWindow, Verdict, MAX_TIMESTAMPS_PER_IP};
