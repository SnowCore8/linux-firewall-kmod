//! `firewall-daemon` 二进制入口:CLI 解析 → 配置加载 → 信号层 → 守护进程化 → 入站主链路
//!
//! # 启动流程
//!
//! 1. **CLI 解析** ([`config::parse_config_args`]):`--help` 时直接 `Ok(())` 退出
//! 2. **信号层** ([`signal::SignalFd::new`]):阻塞 SIGTERM/SIGINT/SIGHUP/SIGUSR1 并建 signalfd
//! 3. **配置加载** ([`config::parse_config_file`] / [`load_config_directory`]):支持文件 / 目录两种源
//! 4. **智能默认 + 校验** ([`jail::apply_smart_defaults_to_all`] / [`jail::config_validate`])
//! 5. **procfs 前置检查**:`/proc/firewall` 存在性 + `/proc/firewall/bans` 存在性
//! 6. **守护进程化** ([`daemonizer::daemonize_process`]):双 fork + setsid + chdir / + 写 PID + 重定向 fd
//! 7. **入站主链路装配** ([`pipeline::executor::InboundExecutor::new`]):编译规则集 + 挂 inotify watch
//! 8. **Metrics 导出器启动** ([`http_exporter::start_http_exporter`])
//! 9. **入站执行体登记** + 主线程阻塞在终止令牌上（收到 SIGTERM/SIGINT 时由执行体置位）
//! 10. **清理** ([`cleanup`]):停 HTTP → 停 runtime 执行体（含入站与内核链路）→ 关 db → 删 PID 文件
//!
//! # 关键不变量
//!
//! - **信号必须在建线程之前阻塞**:阻塞是线程属性，新线程继承创建者的掩码。`SignalFd`
//!   在配置加载前创建，logger / HTTP / 执行体线程都在其后启动，故信号一律进 signalfd，
//!   不会被未阻塞它的线程按默认动作处理（旧实现靠 `sigaction` + 全局原子标志）。
//! - **配置所有权在入站执行体**:它是唯一改配置的线程（自动重载 / 回滚 / 启用状态同步），
//!   组合根通过 [`pipeline::executor::InboundExecutor::cfg`] 读它装配其余组件。
//! - **清理顺序**:先停 runtime 执行体（含入站与内核接收执行体）,再关 db——否则停机窗口内
//!   的事件会写进已关闭的写队列而被静默丢弃
//! - **PID 文件 `O_NOFOLLOW`**:防止符号链接攻击覆盖其他进程
//! - **SIGPIPE 忽略**:HTTP 导出器在客户端断开时不应被信号杀死
//!
//! # 入站主链路（2.I）
//!
//! `ingest`（inotify + 按源增量读）→ `parse`（行切分 / 规则匹配）→ `decision`（阈值与
//! 封禁计划）→ `pipeline`（装配体）→ `ban`（netlink 下发）。四段由**一个**执行体
//! （[`pipeline::executor::InboundExecutor`]）顺序驱动，信号与 inotify 在同一个 `poll`
//! 上等待；周期维护走单调时钟定时器，不再挂在 `poll` 超时上。
//!
//! # 内核链路（2.H-3）
//!
//! 内核通信由 `crate::kernel`（传输层）+ `crate::inbound`（消费层）+
//! `crate::kernel_poll`（周期任务与租约）组成，组合根负责装配。三条不变量：
//!
//! 1. **同一 socket 只有一条读线程**：`Reactor` 独占接收侧，跑在 `Supervisor` 里；
//! 2. **`Client` 与 `Reactor` 共享同一张在途配对表**（`Arc<Router>`）——否则请求登记
//!    不进去、回复永远落空；
//! 3. **启动快照同步拉取，且在可信 IP 写入之前**：`init_trusted_ips` 会往本地白名单
//!    缓存追加条目，快照若后到会用内核旧表整体覆盖它。

use std::env;
use std::fs;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{bail, Result};
use slog::{error, info, warn};

use firewall_daemon::ban;
use firewall_daemon::config;
use firewall_daemon::config_reloader;
use firewall_daemon::daemonizer::daemonize_process;
use firewall_daemon::decision::DdosDecisionEngine;
use firewall_daemon::history_snapshot;
use firewall_daemon::http_exporter;
use firewall_daemon::inbound;
use firewall_daemon::jail;
use firewall_daemon::kernel;
use firewall_daemon::kernel_poll;
use firewall_daemon::logger;
use firewall_daemon::pipeline::executor::InboundExecutor;
use firewall_daemon::runtime::{self, Shutdown, Supervisor};
use firewall_daemon::runtime_status;
use firewall_daemon::signal::{ignore_sigpipe, SignalFd};
use firewall_daemon::types::{Config, DAEMON_STATS};
use firewall_daemon::web_ui;

/// 内核模块 procfs 根目录。启动期存在性检查
const PROCFS_DIR: &str = "/proc/firewall";
/// 内核模块封禁命令接口。启动期存在性检查
const BANS_PATH: &str = "/proc/firewall/bans";

/// 优雅清理：停 HTTP → 关 db → 删 PID 文件。
///
/// 顺序要求：内核链路与入站链路的执行体必须在 `close_history_db` **之前**停止（由调用方在
/// `supervisor.shutdown` 里完成，其登记顺序即依赖顺序）。否则停机窗口内收到的事件会
/// 写进已关闭的写队列（`enqueue_db_write` 报一次 warn 后丢弃），造成内存状态与磁盘
/// 持久化不一致。`close_history_db` 自身会 join 写线程、把已入队的持久化全部落盘后才
/// 关连接，故这里只需保证**没有新的生产者**即可。
fn cleanup() {
    http_exporter::stop_http_exporter();
    history_snapshot::close_history_db();
    if let Err(e) = fs::remove_file("/run/firewall-daemon.pid") {
        crate::logger::debug!(
            crate::logger::get(),
            "删除 PID 文件失败";
            "error" => %e
        );
    }
}

/// `firewall-daemon` 主入口。返回值:
/// - `Ok(())` 正常退出
/// - `Err(_)` 启动失败或运行错误
fn main() -> Result<()> {
    // 注意：logger 在守护进程化之后初始化，避免 fork 导致异步日志线程丢失

    let args: Vec<String> = env::args().collect();

    let (config_path, daemon_mode, strict_mode, rollback) = match config::parse_config_args(&args)?
    {
        Some((path, daemon, strict, rollback)) => (path, daemon, strict, rollback),
        None => return Ok(()),
    };

    // 处理回滚命令
    if rollback {
        return handle_rollback();
    }

    // ---- 信号层：阻塞信号并建 signalfd（**必须在任何线程创建之前**）----
    //
    // 阻塞是**线程属性**：新线程继承创建者的掩码。此处 logger / HTTP / 各执行体线程
    // 都还没起，掩码一装上，随后的所有线程都继承「这四个信号已被阻塞」，信号便一律
    // 投进 signalfd，而不会被某个未阻塞它的线程按默认动作处理。
    //
    // 放在守护进程化之前是安全的：`daemonize_process` 只 fork + setsid（不 exec），
    // fd 与信号掩码都随 fork 继承。这样守护进程化窗口内到达的 SIGHUP/SIGTERM 也不会
    // 丢失——它们排在 fd 里，等主循环第一次 `poll` 时取走（旧实现靠守护进程化后
    // 「清 reload 标志」来掩盖这个窗口）。
    let signals = SignalFd::new()?;
    // SIGPIPE 不交给 signalfd（写端断开用 EPIPE 报错更合适），单独置为 SIG_IGN：
    // HTTP/SSE 客户端断开时不应把守护进程杀死。
    ignore_sigpipe()?;

    let mut cfg = Config {
        strict_mode,
        ..Config::default()
    };
    let path = Path::new(&config_path);
    if path.is_file() {
        config::parse_config_file(&config_path, &mut cfg, strict_mode)?;
        cfg.config_file = Some(config_path.clone());
        info!(logger::get(), "配置文件加载成功"; "path" => %config_path);
    } else if path.is_dir() {
        config::load_config_directory(&config_path, &mut cfg, strict_mode)?;
        cfg.config_dir = Some(config_path.clone());
        info!(logger::get(), "配置目录加载成功"; "path" => %config_path);
    } else {
        error!(logger::get(), "配置路径不存在"; "path" => %config_path);
        bail!("Config path does not exist: {}", config_path);
    }

    // 设置配置持久化目标路径（Web UI 修改后回写到原始 YAML）
    config_reloader::set_config_target_path(&config_path);
    jail::apply_smart_defaults_to_all(&mut cfg);
    if let Err(e) = jail::config_validate(&cfg) {
        error!(logger::get(), "配置验证失败"; "error" => %e);
        return Err(anyhow::anyhow!("{}", e));
    }
    cfg.daemon = daemon_mode;

    // 缓存 trusted_ips 和 capacity 到全局状态（供 persist_runtime_config 使用）
    config_reloader::set_global_trusted_ips(&cfg.trusted_ips);
    config_reloader::set_global_capacity(&cfg.capacity);

    // 应用动态阈值基线配置
    firewall_daemon::types::set_baseline_warmup_samples(cfg.ddos.baseline_warmup_samples);

    if !Path::new(PROCFS_DIR).exists() {
        bail!("Procfs directory not found");
    }

    if !Path::new(BANS_PATH).exists() {
        bail!("Bans procfs interface not found");
    }

    let now = firewall_daemon::types::now_secs() as u64;
    DAEMON_STATS.start_time.store(now, Ordering::Relaxed);

    if cfg.daemon {
        // 守护进程化。fork 会导致异步日志线程丢失，故日志在 fork 之后才初始化；
        // 信号层（signalfd）必须在其之前建好，见上方「信号层」一节。
        daemonize_process()?;
    }

    // 在守护进程化之后初始化日志系统，确保异步日志线程正确运行
    let _log = logger::init_logger(
        cfg.log_file.as_deref(),
        cfg.log_max_size_mb,
        cfg.log_max_files,
    );
    // 设置日志文件路径（供 Web UI 日志查看器使用）
    if let Some(ref log_path) = cfg.log_file {
        if let Err(e) = web_ui::log_viewer::set_log_file(log_path.clone()) {
            warn!(
                logger::get(),
                "设置日志文件路径失败";
                "error" => e,
                "log_file" => %log_path
            );
        }
    }
    info!(logger::get(), "firewall-daemon 启动"; "mode" => if cfg.daemon { "daemon" } else { "foreground" });

    for jail in cfg.jails.iter() {
        if jail.enabled {
            // jail 已启用
        }
    }

    if let Err(e) = jail::init_log_patterns(&mut cfg) {
        warn!(logger::get(), "初始化日志模式失败"; "error" => %e);
    }

    // 初始化历史数据快照数据库
    if let Err(e) = history_snapshot::init_history_db() {
        warn!(logger::get(), "初始化历史数据库失败"; "error" => %e);
    } else {
        info!(logger::get(), "历史数据库初始化成功");
    }

    // 初始化 GeoIP 地理库（可选增强）：缺失/损坏只记日志，不影响启动。
    // 未装配时地理解析整体禁用，攻击源地理分布与 3D 地球显示为空。
    match firewall_daemon::geoip::init(cfg.geoip_db_path.as_deref()) {
        Ok(true) => {
            info!(logger::get(), "GeoIP 数据库已加载"; "path" => cfg.geoip_db_path.clone().unwrap_or_default())
        }
        Ok(false) => info!(logger::get(), "GeoIP 未配置，地理分布功能禁用"),
        Err(e) => warn!(logger::get(), "GeoIP 数据库加载失败，地理分布功能禁用"; "error" => %e),
    }

    // 本机坐标（攻击地图的「本机」标记与弧线终点）：配置优先；未配置且开关打开时
    // 探测一次出口 IP（仅此一次，结果缓存）。探测失败只记日志、按「未配置」处理。
    // 解析层已保证两个坐标成对出现，这里的 match 只是兜底。
    firewall_daemon::geoip::init_server_location(
        match (cfg.server_latitude, cfg.server_longitude) {
            (Some(latitude), Some(longitude)) => Some((latitude, longitude)),
            _ => None,
        },
        cfg.geoip_detect_egress,
        cfg.geoip_egress_probe_url.as_deref(),
    );

    // ---- 组合根：装配入站主链路（2.I）----
    //
    // 旧实现把 inotify 装配放在 `file_monitor::setup_inotify`，把周期维护任务挂在
    // `monitor_loop` 的 `poll` 超时分支上。现在整条入站链路由 `InboundExecutor` 独占：
    // ingest（inotify + 按源增量读）→ parse（行切分 / 规则匹配）→ decision（阈值与
    // 封禁计划）→ pipeline（装配体）四段由**一个**线程顺序驱动，信号与 inotify 合并在
    // 同一个 `poll` 上等待，周期维护改走单调时钟定时器。
    //
    // 装配失败即启动失败：与旧 `setup_inotify` 的 `watched_count == 0` 同义——一个日志
    // 源都挂不上（配置错 / 权限不足 / 内核模块未加载）时不该留一个「界面正常但永不算」
    // 的进程。
    //
    // **配置所有权随之移入执行体**（它是唯一改配置的线程：自动重载 / 回滚 / 启用状态
    // 同步）。组合根后续一律经 `executor.cfg()` 读装配参数，避免重载后两份配置分叉。
    // 这也要求 `cfg` 的最后一次可变借用（`init_log_patterns`）在此行之前完成。
    let executor = InboundExecutor::new(cfg, signals)?;
    let cfg = executor.cfg();

    // 初始化内核通信链路（取代旧 `NetlinkContext`）：一条 socket + 一条接收执行体。
    //
    // 三条装配不变量见文件头「内核链路」一节。这里先开 socket：失败只降级警告，
    // 不让整个 daemon 起不来——Web UI / procfs / 日志监控仍可工作，
    // `/health` 会如实报 `lease_state = "none"`。
    let transport = match kernel::transport::Transport::open() {
        Ok(t) => {
            info!(logger::get(), "内核 netlink socket 已建立");
            Some(Arc::new(t))
        }
        Err(e) => {
            warn!(logger::get(), "内核 netlink socket 建立失败"; "error" => %e);
            None
        }
    };

    // ---- 组合根：装配新状态层 ----
    //
    // 新状态（`state::State` + hub）在**这里**构造并注入，早于任何镜像写入点：下面的
    // 封禁/白名单/统计查询响应会在消费执行体里落进新状态，若注入晚一步，启动期那批
    // 数据就会丢。
    //
    // 注入后 `state::compose` 的镜像函数才不再是空操作。旧全局（`ACTIVE_BAN_CACHE`
    // 等）继续保留给尚未迁入的读者（SPA 分析端点、Prometheus 导出器）——这是
    // 「保留编译，分批迁入」的过渡态，两个方向都在 `state::compose` 里有明确边界。
    match firewall_daemon::state::set_global_state(firewall_daemon::state::State::new()) {
        Ok(()) => {
            firewall_daemon::state::compose::set_start_time(now);
            firewall_daemon::state::compose::set_push_interval(cfg.webui.sse_push_interval);
            info!(logger::get(), "状态层已装配";
                "sse_push_interval" => cfg.webui.sse_push_interval);
        }
        Err(e) => warn!(logger::get(), "状态层装配失败"; "error" => %e),
    }

    // ---- 组合根：租约状态单元 ----
    //
    // `/health` 的 `netlink_ready` / `lease_state` / `lease_losses` 从这里读。即使内核
    // socket 都没建起来也要注入：那样 `/health` 报 `lease_state = "none"`，而不是因
    // 未注入而无法区分「没有执行体」与「执行体尚未注册」。
    let lease_cell = Arc::new(kernel_poll::LeaseCell::new());
    match runtime_status::set_lease_cell(Arc::clone(&lease_cell)) {
        Ok(()) => {}
        Err(e) => warn!(logger::get(), "租约状态单元注入失败"; "error" => %e),
    }

    // ---- 组合根：装配 runtime 骨架（supervisor + 单调时钟调度器）----
    //
    // 周期维护任务（计数器镜像、过期封禁清理）从旧 `file_monitor::monitor_loop` 的
    // poll 超时分支迁到这里的单调时钟节拍上：准时性不再受事件到达影响（结构问题 A），
    // 且 `Bans::purge_expired` 终于有了生产调用者（结构问题 E）。入站侧的周期任务
    // （失败窗口清理、watch 重扫、历史快照、数据清理）由入站执行体自己的 `TimerTable`
    // 驱动——两处各自独占，无重复执行。
    //
    // 装配失败只降级警告、不 panic：调度器缺席时 SSE 的 `stats` 域不再自动刷新、
    // 过期封禁只能靠内核 UNBAN 事件自愈，但主链路（内核链路 / Web UI）照常工作。
    let mut supervisor = Supervisor::new();
    match runtime::spawn_periodic(&mut supervisor, Shutdown::new()) {
        Ok(()) => info!(logger::get(), "runtime 调度器已装配"; "executors" => supervisor.len()),
        Err(e) => warn!(logger::get(), "runtime 调度器装配失败"; "error" => %e),
    }

    // ---- 组合根：装配内核链路（Reactor / 消费体 / Client / 轮询执行体）----
    //
    // 登记顺序 = 依赖顺序（`Supervisor` 逆序关停）：接收执行体最先登记、最后停止，
    // 因为它是「事件生产者」；消费体与轮询体都从它取数据。入站执行体在稍后登记，
    // 故它比整条内核链路先停——两者之间没有队列依赖（入站只单向发指令）。
    if let Some(transport) = transport {
        // `event_channel` 同时产出：共享路由器（`Arc`）、事件接收端、队列统计、存活凭据。
        let (router, events, _queue_stats, liveness) =
            kernel::reactor::event_channel(kernel::reactor::default_event_queue());

        // 接收执行体：一次可读事件可能对应多条数据报，`Reactor::run` 内部排空。
        let reactor_token = Shutdown::new();
        let reactor = kernel::reactor::Reactor::new(
            Arc::clone(&transport),
            reactor_token.clone(),
            Arc::clone(&router),
            liveness,
        );
        match supervisor.spawn("kernel-reactor", reactor_token, move || reactor.run()) {
            Ok(()) => info!(logger::get(), "内核接收执行体已启动"),
            Err(e) => warn!(logger::get(), "内核接收执行体启动失败"; "error" => %e),
        }

        // 消费执行体：把 `Incoming` 搬进缓存与状态镜像。决策引擎在移交前接线，
        // 否则最早那批 DDoS 事件会被静默丢掉。
        let consumer = inbound::Consumer::new();
        let decision_engine = Arc::new(DdosDecisionEngine::new(cfg.ddos.clone()));
        consumer.set_decision_engine(Arc::clone(&decision_engine));
        http_exporter::set_global_decision_engine(decision_engine);
        let consumer_token = Shutdown::new();
        let consumer_watch = consumer_token.clone();
        match supervisor.spawn("inbound-consumer", consumer_token, move || {
            consumer.run(events, consumer_watch)
        }) {
            Ok(()) => info!(logger::get(), "内核事件消费执行体已启动"),
            Err(e) => warn!(logger::get(), "内核事件消费执行体启动失败"; "error" => %e),
        }

        // 全局客户端定位器（过渡物，2.H-4 随旧层一起删除）。
        //
        // `Client` 是 `Clone` 的，克隆之间共享同一 socket 与在途表；这里存一份副本供
        // 封禁操作 / 配置同步等分散调用点取用，避免把 `Client` 一路穿透到那些模块。
        let client = kernel::client::Client::new(Arc::clone(&transport), Arc::clone(&router));
        if let Err(e) = kernel::global::init(client.clone()) {
            warn!(logger::get(), "全局内核客户端注入失败"; "error" => %e);
        }

        // 轮询执行体：启动期同步完成「注册 + 全量快照」，之后交给执行体做周期续约与拉取。
        //
        // 注册被**明确拒绝**（已有活跃守护进程持租）时按用户裁定「立即退出（非零码）」：
        // 让服务管理器的重启策略重试，而不是留一个「界面看着正常、指令全被内核丢掉」的
        // 进程。确认未到达属可自愈，`startup` 内部只告警。
        let mut poller = kernel_poll::Poller::new(client, Arc::clone(&lease_cell));
        if let Err(e) = poller.startup() {
            error!(logger::get(), "内核注册被拒，退出以便服务管理器重试"; "error" => %e);
            return Err(e);
        }
        match kernel_poll::spawn(&mut supervisor, Shutdown::new(), poller) {
            Ok(()) => info!(logger::get(), "内核轮询执行体已启动"),
            Err(e) => warn!(logger::get(), "内核轮询执行体启动失败"; "error" => %e),
        }

        // 初始化可信 IP 白名单。**必须在启动快照之后**：本函数会往本地白名单缓存
        // 追加条目，故不能与「用内核表覆盖本地缓存」的快照拉取并发。
        if !cfg.trusted_ips.is_empty() {
            let failed = ban::init_trusted_ips(&cfg.trusted_ips);
            if !failed.is_empty() {
                warn!(logger::get(), "部分可信 IP 写入白名单失败"; "failed" => ?failed);
            } else {
                info!(logger::get(), "可信 IP 白名单初始化完成"; "count" => cfg.trusted_ips.len());
            }
        }
    }

    // 设置全局 Jail 信息和 Web UI 配置
    {
        let jail_infos: Vec<http_exporter::JailInfo> = cfg
            .jails
            .iter()
            .map(|j| http_exporter::JailInfo {
                name: j.name.clone(),
                enabled: j.enabled,
                max_retries: j.max_retries,
                findtime: j.findtime,
                ban_time: j.ban_time,
            })
            .collect();
        http_exporter::set_global_jails(jail_infos);
        http_exporter::set_global_webui_config(cfg.webui.clone());
        // 缓存 Jail enabled 状态（供 persist_runtime_config 回写时使用）
        let jails_enabled: Vec<(String, bool)> = cfg
            .jails
            .iter()
            .map(|j| (j.name.clone(), j.enabled))
            .collect();
        config_reloader::set_global_jails_enabled(&jails_enabled);
    }

    let mut exporter_handle = None;
    if cfg.metrics_port > 0 {
        exporter_handle = Some(http_exporter::start_http_exporter(cfg.metrics_port, cfg));
        // 等待 HTTP 服务启动（最多 500ms），检测启动失败
        std::thread::sleep(std::time::Duration::from_millis(200));
        if !http_exporter::is_exporter_running() {
            warn!(
                logger::get(),
                "HTTP 服务启动失败，Web UI 和 API 不可用";
                "port" => cfg.metrics_port
            );
        }
    }

    // ---- 组合根：登记入站执行体 ----
    //
    // 登记顺序 = 依赖顺序（`Supervisor` 逆序关停）：入站执行体是**上游生产者**（唯一
    // 的日志/封禁事件源），故登记在最后 ⇒ 关停时最先停。它的下游是持久化写线程——那个
    // 线程不属于 supervisor，由 `close_history_db` 在**所有**执行体停完之后 join，所以
    // 「上游先停、下游排空」这一不变量仍然成立。
    //
    // 它同时是让主线程醒来的一方：收到 SIGTERM/SIGINT（或链路异常）时置位终止令牌，
    // 主线程便从 `terminate.wait()` 返回并进入清理。
    let inbound_token = Shutdown::new();
    let terminate = Shutdown::new();
    let inbound_stop = inbound_token.clone();
    let inbound_terminate = terminate.clone();
    if let Err(e) = supervisor.spawn("inbound", inbound_token, move || {
        executor.run(inbound_stop, inbound_terminate)
    }) {
        // 起不了入站线程就没有任何信号消费者，静默等下去会变成「不可 Ctrl-C 的僵尸」，
        // 故按启动失败处理。
        bail!("入站执行体启动失败: {e}");
    }
    info!(logger::get(), "入站执行体已启动");

    // 主线程在此阻塞：没有别的唤醒源，终止令牌只由入站执行体置位。
    terminate.wait();
    info!(logger::get(), "开始清理流程");

    // 先按依赖逆序停 runtime 执行体，再走既有清理流程。
    //
    // 顺序要求：入站执行体（上游生产者，最后登记）最先停，随后内核轮询体与消费体停，
    // 内核接收执行体（内核链路里的生产者）最后停——故停机窗口内不再有生产者往会关闭
    // 的写队列里投递。调度器只碰内存镜像与原子计数、不碰持久化，排在 `cleanup` 的
    // 关库之前停即可。
    for (name, outcome) in supervisor.shutdown(std::time::Duration::from_secs(5)) {
        info!(logger::get(), "runtime 执行体已停止"; "name" => name, "outcome" => ?outcome);
    }
    cleanup();

    if let Some(handle) = exporter_handle {
        // 给 HTTP 导出器线程最多 2 秒优雅退出
        let start = std::time::Instant::now();
        loop {
            if handle.is_finished() {
                if let Err(e) = handle.join() {
                    warn!(logger::get(), "HTTP metrics 导出器线程 join 失败"; "error" => ?e);
                }
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(2) {
                warn!(logger::get(), "HTTP metrics 导出器线程超时，强制继续");
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    Ok(())
}

// ============================================================================
// 回滚命令处理
// ============================================================================

/// 处理 `--rollback` 命令
///
/// 通过向正在运行的守护进程发送 SIGUSR1 信号触发配置回滚。
/// 守护进程接收到 SIGUSR1 后会回滚到上一个配置版本并重新加载。
fn handle_rollback() -> Result<()> {
    println!("正在请求配置回滚...");

    // 查找正在运行的 firewall-daemon 进程（排除自身 PID）
    let my_pid = std::process::id();
    let pid = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("firewall-daemon")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8(output.stdout).ok().and_then(|s| {
                s.lines()
                    .filter_map(|l| l.parse::<u32>().ok())
                    .find(|&p| p != my_pid)
                    .map(|p| p.to_string())
            })
        });

    match pid {
        Some(pid_str) => {
            let pid_num: i32 = pid_str.parse().unwrap_or(0);
            if pid_num <= 0 {
                println!("错误: 无法获取有效的守护进程 PID");
                return Err(anyhow::anyhow!("Invalid daemon PID"));
            }

            // 发送 SIGUSR1 信号触发回滚（守护进程侧由 signalfd 接住并分派为 Signal::Rollback）
            println!("向守护进程 (PID: {}) 发送回滚信号...", pid_num);
            let status = std::process::Command::new("kill")
                .arg("-USR1")
                .arg(pid_num.to_string())
                .status();

            match status {
                Ok(s) if s.success() => {
                    println!("回滚请求已发送，等待守护进程处理...");
                    // 等待守护进程处理
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    println!("回滚完成");
                    Ok(())
                }
                _ => {
                    println!("错误: 发送信号失败");
                    Err(anyhow::anyhow!("Failed to send rollback signal"))
                }
            }
        }
        None => {
            println!("错误: 未找到正在运行的 firewall-daemon 进程");
            println!("提示: 请先启动守护进程: firewall-daemon -d");
            Err(anyhow::anyhow!("Daemon not running"))
        }
    }
}
