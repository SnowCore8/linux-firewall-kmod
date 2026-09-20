//! 组合根的周期任务调度：把「按固定周期跑的维护任务」从执行循环里摘出来。
//!
//! 旧实现把这些任务挂在 `file_monitor::monitor_loop` 的 `poll` 超时分支上，靠
//! `SystemTime` 记录「上次执行时间」再逐个比较经过秒数。两个后果：
//!
//! - 准时性与**事件到达**耦合：`poll` 超时被事件洪泛不断推后，维护任务被饿死
//!   （结构问题 A）；
//! - 时钟回拨会让定时器停摆。
//!
//! 本模块改用 [`super::timers`] 的单调时钟节拍：节拍线程只睡到下一个到期点，
//! 与 netlink / inotify 的吞吐无关。
//!
//! # 为什么是「一个基础节拍 + 各自门控」而不是两条独立定时器
//!
//! 两个子任务的周期不同，但其中周期最长的那个（`stats` 镜像）取自**运行期可改**的
//! `webui.sse_push_interval`（1~60 秒）。而 [`super::timers::TimerId`] 的周期在登记
//! 时钉死，登记后不可改——用两条独立定时器就意味着改配置要重启才生效。基础节拍 +
//! 门控让配置改动在下一轮即生效，与旧 `monitor_loop` 的语义一致。

use std::time::{Duration, Instant};

use super::shutdown::Shutdown;
use super::supervisor::Supervisor;
use super::timers::TimerTable;

/// 基础节拍。其余周期都按它是整数倍门控。
const TICK: Duration = Duration::from_secs(1);

/// 过期封禁清理周期。
///
/// 与旧 `web_ui/ban_ops.rs` 的 `PURGE_INTERVAL_SECS` 同值：清理职责从读路径搬到
/// 这里，节流值不变，故过期条目滞留的最坏时长与旧实现一致。
const PURGE_INTERVAL: Duration = Duration::from_secs(5);

/// 在 `sup` 下登记周期任务执行体（`scheduler` 名下，由 [`super::timers::spawn_scheduler`] 托管）。
///
/// 承载两个子任务：
///
/// 1. **计数器镜像**：按 `webui.sse_push_interval` 把旧全局计数器等值搬进新状态并推进
///    `stats` 版本。必须按配置间隔门控——新 SSE 是纯版本驱动（`watch::Receiver::changed`），
///    推进一次版本就发一帧，若每轮都推进就等于把配置的推送间隔架空了。
/// 2. **过期封禁清理**：按 [`PURGE_INTERVAL`] 调 [`crate::state::compose::purge_expired_bans`]，
///    即结构问题 E 的新家（旧实现在 `get_active_bans()` 的读路径上顺手做）。
///
/// # Errors
/// 线程创建失败时返回 [`std::io::Error`]。
pub fn spawn_periodic(sup: &mut Supervisor, token: Shutdown) -> std::io::Result<()> {
    let mut table = TimerTable::new(1);
    // 首个到期点显式给定：容量为 1 的表登记唯一节拍不可能失败，故直接 expect。
    table
        .every(TICK, Instant::now() + TICK)
        .expect("容量 1 的定时器表登记唯一节拍不应失败");

    // 两个子任务各自的上次执行时刻。`None` = 尚未跑过。
    let mut last_stats_tick: Option<Instant> = None;
    let mut last_purge: Option<Instant> = None;

    super::timers::spawn_scheduler(sup, token, table, move |_fired| {
        let now = Instant::now();

        // 每轮都读配置：`config_reloader` 在重载时同步新值，改完下一轮即生效。
        // `max(1)` 与 `set_push_interval` 一致，避免间隔为 0 变成忙轮询。
        let stats_interval =
            Duration::from_secs(crate::state::compose::stats_push_interval_secs().max(1));

        // 显式 match 而非 `Option::is_none_or`：后者需 Rust 1.82，本仓库 MSRV 是 1.75。
        let stats_due = match last_stats_tick {
            None => true,
            Some(t) => now.duration_since(t) >= stats_interval,
        };
        if stats_due {
            last_stats_tick = Some(now);
            crate::state::compose::mirror_stats_tick();
        }

        let purge_due = match last_purge {
            None => true,
            Some(t) => now.duration_since(t) >= PURGE_INTERVAL,
        };
        if purge_due {
            last_purge = Some(now);
            crate::state::compose::purge_expired_bans(crate::types::now_secs());
        }
    })
}
