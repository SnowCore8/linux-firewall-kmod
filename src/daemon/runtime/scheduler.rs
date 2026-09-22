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
use crate::protected_ports::ProtectedPorts;

/// 基础节拍。其余周期都按它是整数倍门控。
const TICK: Duration = Duration::from_secs(1);

/// 过期封禁清理周期。
///
/// 与旧 `web_ui/ban_ops.rs` 的 `PURGE_INTERVAL_SECS` 同值：清理职责从读路径搬到
/// 这里，节流值不变，故过期条目滞留的最坏时长与旧实现一致。
const PURGE_INTERVAL: Duration = Duration::from_secs(5);

/// 对外监听端口重扫周期。
///
/// 端口集合只在进程启停时变化，扫得太勤只是白读四张 net 表再比一次 8KB 位图；
/// 而 30 秒也是「新服务刚暴露到公网」到「纳入速率判定」之间的最长窗口，够短。
const PROTECTED_PORTS_INTERVAL: Duration = Duration::from_secs(30);

/// 在 `sup` 下登记周期任务执行体（`scheduler` 名下，由 [`super::timers::spawn_scheduler`] 托管）。
///
/// 承载四个子任务：
///
/// 1. **计数器镜像**：按 `webui.sse_push_interval` 把旧全局计数器等值搬进新状态并推进
///    `stats` 版本。必须按配置间隔门控——新 SSE 是纯版本驱动（`watch::Receiver::changed`），
///    推进一次版本就发一帧，若每轮都推进就等于把配置的推送间隔架空了。
/// 2. **过期封禁清理**：按 [`PURGE_INTERVAL`] 调 [`crate::state::compose::purge_expired_bans`]，
///    即结构问题 E 的新家（旧实现在 `get_active_bans()` 的读路径上顺手做）。
/// 3. **峰值时段翻转**：`jails` 域的 `is_peak_hours` / `effective_max_retries` 只随
///    [`crate::decision::is_baseline_peak_hours`] 的翻转而变，故在此按翻转发布，
///    与另两个 `jails` 来源（封禁集合变更、jail 开关）共同保证该域有生产者。
/// 4. **对外端口重扫**：按 [`PROTECTED_PORTS_INTERVAL`] 扫本机对外监听端口并下发位图，
///    见 [`refresh_protected_ports`]。首轮即扫（`None` 视为到期），故启动后约一个节拍
///    内就完成首次下发，不等满一个周期。
///
/// # Errors
/// 线程创建失败时返回 [`std::io::Error`]。
pub fn spawn_periodic(sup: &mut Supervisor, token: Shutdown) -> std::io::Result<()> {
    let mut table = TimerTable::new(1);
    // 首个到期点显式给定：容量为 1 的表登记唯一节拍不可能失败，故直接 expect。
    table
        .every(TICK, Instant::now() + TICK)
        .expect("容量 1 的定时器表登记唯一节拍不应失败");

    // 各子任务各自的上次执行时刻。`None` = 尚未跑过（首轮即到期）。
    let mut last_stats_tick: Option<Instant> = None;
    let mut last_purge: Option<Instant> = None;
    let mut last_ports_tick: Option<Instant> = None;
    // 上一次**已成功下发**的内容。`None` = 本次进程还没下发过。
    let mut last_published_ports: Option<Published> = None;
    // 上一次观察到的峰值时段标志。jails 载荷含 `is_peak_hours` 与由它算出的
    // `effective_max_retries`，二者只随这个标志变化，故按「标志翻转」发布而不是
    // 每轮发布——否则安静时段每秒一帧恒定载荷。
    let mut last_peak_hours = crate::decision::is_baseline_peak_hours();

    super::timers::spawn_scheduler(sup, token, table, move |_fired| {
        let now = Instant::now();

        // 峰值时段翻转：只在跨越边界时推进 jails。跨日收敛由 `is_peak_hours` 自身完成
        // （它按当前小时判定），本处只负责「变了才发」。
        let peak_hours = crate::decision::is_baseline_peak_hours();
        if peak_hours != last_peak_hours {
            last_peak_hours = peak_hours;
            crate::state::publish_jails_changed();
        }

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

        let ports_due = match last_ports_tick {
            None => true,
            Some(t) => now.duration_since(t) >= PROTECTED_PORTS_INTERVAL,
        };
        if ports_due {
            last_ports_tick = Some(now);
            refresh_protected_ports(&mut last_published_ports);
        }
    })
}

/// 上一次**已成功下发**的内容。
///
/// 把「已下发全零」与「已下发某集合」分成两个变体，而不是用一个「空集哨兵」——
/// 后者在本进程启动早期会出错：调度器登记（`main.rs`）先于决策引擎装配，
/// 首轮 tick 若读不到配置会按默认「开启」下发真实集合；等引擎接上、发现配置是
/// 「关闭」时，`Some(空集)` 与「已下发过」的判断撞在一起，全零位图就再发不出去。
#[derive(Debug, Clone, PartialEq, Eq)]
enum Published {
    /// 已下发全零位图（`protect_open_ports == false`，检测面为空）。
    AllZero,
    /// 已下发该集合。
    Ports(ProtectedPorts),
}

/// 重扫本机对外监听端口，**仅在结果变化时**下发位图。
///
/// # 为什么「变化才发」
///
/// 位图 8KB，走的是单向下行 netlink 通道（无 ACK 配对）。每 30 秒无脑重发只是
/// 浪费内核侧一次 `kzalloc` + RCU 换表，故以结果相等为门控（[`ProtectedPorts`] 是
/// 升序 `BTreeSet`，`Eq` 即语义相等）。
///
/// # 三条失败/边界路径
///
/// - **`protect_open_ports == false`**：下发**全零**位图。这与「从未下发」不同——
///   全零表示检测面为空（没有任何端口参与速率判定），用于排查与对照测试。
/// - **扫描失败**：不下发。内核保持上一次收到的集合；若本次进程从未成功下发过，
///   内核仍处「未下发 = 全端口受保护」的失败安全态。凭残缺扫描收窄保护面，
///   比沿用旧集合或维持全端口防护都更坏。
/// - **内核链路未就绪**（`Skipped`）：不记账，下一轮重试。否则启动初期的一次
///   `Skipped` 会让这一轮的结果被当成「已下发」，此后再不重发。
fn refresh_protected_ports(last_published: &mut Option<Published>) {
    let desired = if protect_open_ports_enabled() {
        match crate::protected_ports::scan_external_ports() {
            Ok(ports) => Published::Ports(ports),
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "对外端口扫描失败，保留上一次已下发的保护集合"; "error" => %e
                );
                return;
            }
        }
    } else {
        Published::AllZero
    };

    if last_published.as_ref() == Some(&desired) {
        return;
    }

    let bitmap = match &desired {
        Published::AllZero => [0u8; crate::protected_ports::BITMAP_BYTES],
        Published::Ports(ports) => ports.to_bitmap(),
    };

    match crate::config_sync::sync_protected_ports(bitmap) {
        Ok(crate::config_sync::SyncOutcome::Sent) => {
            match &desired {
                Published::AllZero => crate::logger::info!(
                    crate::logger::get(),
                    "对外端口保护已关闭，已下发全零位图（检测面为空）"
                ),
                Published::Ports(ports) => crate::logger::info!(
                    crate::logger::get(),
                    "对外端口保护集合已下发"; "ports" => ports.len()
                ),
            }
            *last_published = Some(desired);
        }
        Ok(crate::config_sync::SyncOutcome::Skipped) => {}
        Err(e) => {
            crate::logger::warn!(
                crate::logger::get(),
                "下发对外端口保护位图失败"; "error" => %e
            );
        }
    }
}

/// 当前的 `ddos.protect_open_ports`。引擎未装配时返回 `true`。
///
/// 默认 `true` 而非 `false`：该值决定「要不要收窄检测面」，而收窄需要显式依据。
/// 配置尚未就绪时按本特性引入前的行为（全端口受保护）走，与内核侧未下发位图的
/// 失败安全默认一致。
fn protect_open_ports_enabled() -> bool {
    crate::http_exporter::get_global_decision_engine()
        .map_or(true, |engine| engine.current_config().protect_open_ports)
}
