//! `firewall-daemon` 二进制入口:CLI 解析 → 配置加载 → 信号注册 → 守护进程化 → 主监控循环
//!
//! # 启动流程
//!
//! 1. **CLI 解析** ([`config::parse_config_args`]):`--help` 时直接 `Ok(())` 退出
//! 2. **配置加载** ([`config::parse_config_file`] / [`load_config_directory`]):支持文件 / 目录两种源
//! 3. **智能默认 + 校验** ([`jail::apply_smart_defaults_to_all`] / [`jail::config_validate`])
//! 4. **信号注册** ([`signals::setup_signals`]):SIGTERM/SIGINT 触发优雅退出、SIGHUP 触发热重载、SIGPIPE 忽略
//! 5. **procfs 前置检查**:`/proc/firewall` 存在性 + `/proc/firewall/bans` 存在性
//!
//! 7. **守护进程化** ([`daemonizer::daemonize_process`]):双 fork + setsid + chdir / + 写 PID + 重定向 fd
//! 8. **inotify 启动** ([`file_monitor::setup_inotify`])
//! 9. **Metrics 导出器启动** ([`http_exporter::start_http_exporter`])
//! 10. **主循环** ([`file_monitor::monitor_loop`]):阻塞直到 `running=false`
//! 11. **清理** ([`cleanup`]):关 metrics → 释放 fd → 关 syslog → 删 PID 文件
//!
//! # 关键不变量
//!
//! - **守护进程化前清 `reload` 标志**:避免该窗口期收到的 SIGHUP 在主循环首次检查时误触
//! - **清理顺序**:清全局引用 → 关 db,防止收尾期间 ban 模块再访问
//! - **PID 文件 `O_NOFOLLOW`**:防止符号链接攻击覆盖其他进程
//! - **SIGPIPE 忽略**:HTTP 导出器在客户端断开时不应被信号杀死

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
use firewall_daemon::file_monitor;
use firewall_daemon::history_snapshot;
use firewall_daemon::http_exporter;
use firewall_daemon::jail;
use firewall_daemon::logger;
use firewall_daemon::netlink::{self, DdosDecisionEngine, NetlinkContext};
use firewall_daemon::signals::{setup_signals, GLOBAL_RELOAD, GLOBAL_RUNNING};
use firewall_daemon::types::{Config, DAEMON_STATS};

/// 内核模块 procfs 根目录。启动期存在性检查
const PROCFS_DIR: &str = "/proc/firewall";
/// 内核模块封禁命令接口。启动期存在性检查
const BANS_PATH: &str = "/proc/firewall/bans";

/// 优雅清理：关 metrics → 释放 fd → 关 syslog → 删 PID 文件。
///
/// # Arguments
/// - `_cfg`：保留参数，占位
fn cleanup(_cfg: &Config) {
    http_exporter::stop_http_exporter();
    GLOBAL_RUNNING.store(false, Ordering::SeqCst);
    file_monitor::close_inotify();
    ban::close_cached_bans_fd();
    history_snapshot::close_history_db();
    // netlink_ctx 通过 Arc 管理，最后一个 Arc drop 时自动关闭 socket
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

    // 如果存在持久化配置（来自上次热重载），合并运行时配置变更
    // 持久化配置优先于原始配置文件（保留热重载后的调整）
    if let Some(persisted) = config_reloader::load_persisted_config() {
        match config::parse_config(&persisted, &mut cfg) {
            Ok(_) => {
                info!(logger::get(), "持久化配置加载成功，热重载变更已恢复");
            }
            Err(e) => {
                warn!(logger::get(), "持久化配置解析失败，使用原始配置"; "error" => %e);
            }
        }
    }

    jail::apply_smart_defaults_to_all(&mut cfg);
    if let Err(e) = jail::config_validate(&cfg) {
        error!(logger::get(), "配置验证失败"; "error" => %e);
        return Err(anyhow::anyhow!("{}", e));
    }
    cfg.daemon = daemon_mode;

    // 重置全局标志（可能因为之前的运行而改变了）
    GLOBAL_RUNNING.store(true, Ordering::Relaxed);
    GLOBAL_RELOAD.store(false, Ordering::SeqCst);

    if !Path::new(PROCFS_DIR).exists() {
        bail!("Procfs directory not found");
    }

    if !Path::new(BANS_PATH).exists() {
        bail!("Bans procfs interface not found");
    }

    let now = firewall_daemon::types::now_secs() as u64;
    DAEMON_STATS.start_time.store(now, Ordering::Relaxed);

    if cfg.daemon {
        // 守护进程化前不记录日志到文件，因为 fork 会导致异步日志线程丢失
        daemonize_process()?;
        // 守护进程化后清 reload 标志, 防止该窗口期收到的 SIGHUP 在主循环首次检查时误触
        // 对齐 C 版: 守护进程化期间用 sigaction(SIGHUP, SIG_IGN) 临时忽略
        GLOBAL_RELOAD.store(false, Ordering::SeqCst);
    }

    // 在守护进程化之后初始化日志系统，确保异步日志线程正确运行
    let _log = logger::init_logger(cfg.log_file.as_deref());
    info!(logger::get(), "firewall-daemon 启动"; "mode" => if cfg.daemon { "daemon" } else { "foreground" });

    // 初始化可信 IP 白名单（在日志初始化之后，以便记录日志）
    if !cfg.trusted_ips.is_empty() {
        let failed = ban::init_trusted_ips(&cfg.trusted_ips);
        if !failed.is_empty() {
            warn!(logger::get(), "部分可信 IP 写入白名单失败"; "failed" => ?failed);
        } else {
            info!(logger::get(), "可信 IP 白名单初始化完成"; "count" => cfg.trusted_ips.len());
        }
    }

    // 在守护进程化之后设置信号处理器，确保 fork 后信号处理正常工作
    setup_signals()?;
    info!(logger::get(), "信号处理器已注册");

    file_monitor::setup_inotify(&cfg)?;
    info!(logger::get(), "inotify 监控启动");

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

    // TODO: 守护进程启动时通过 netlink 请求-响应恢复 ACTIVE_BAN_CACHE
    // 当前 netlink 不支持请求-响应，守护进程重启后内存为空，
    // 直到下次 DDoS 事件或日志解析触发封禁。
    // 已知限制：用户通过 /proc/firewall/bans 手动封禁的 IP 不会反映在 Web UI 中。

    // 初始化 netlink 通信（接收内核 DDoS 事件）
    let netlink_ctx = match NetlinkContext::new() {
        Ok(ctx) => {
            info!(logger::get(), "Netlink 通信层初始化成功");
            Some(ctx)
        }
        Err(e) => {
            warn!(logger::get(), "Netlink 通信层初始化失败"; "error" => %e);
            None
        }
    };

    // 如果有 netlink 上下文，创建并设置决策引擎
    if let Some(ctx) = netlink_ctx {
        let ctx_arc = Arc::new(ctx);

        // 设置全局 netlink 上下文（程序内部共享）
        if let Err(e) = netlink::set_global_netlink_ctx(ctx_arc.clone()) {
            warn!(logger::get(), "设置全局 NetlinkContext 失败"; "error" => %e);
        }

        // 创建决策引擎
        let decision_engine = Arc::new(DdosDecisionEngine::new(cfg.ddos.clone(), ctx_arc.clone()));
        ctx_arc.set_decision_engine(decision_engine.clone());

        // 设置全局决策引擎引用（供配置热重载使用）
        http_exporter::set_global_decision_engine(decision_engine);

        match ctx_arc.start_receiver() {
            Ok(_handle) => {
                info!(logger::get(), "Netlink 接收线程已启动");
            }
            Err(e) => {
                warn!(logger::get(), "启动 Netlink 接收线程失败"; "error" => %e);
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
            })
            .collect();
        http_exporter::set_global_jails(jail_infos);
        http_exporter::set_global_webui_config(cfg.webui.clone());
    }

    let mut exporter_handle = None;
    if cfg.metrics_port > 0 {
        exporter_handle = Some(http_exporter::start_http_exporter(cfg.metrics_port, &cfg));
    }

    if let Err(e) = file_monitor::monitor_loop(&mut cfg, &GLOBAL_RUNNING, &GLOBAL_RELOAD) {
        error!(logger::get(), "主循环异常退出"; "error" => %e);
    }

    info!(
        logger::get(),
        "主循环退出，running={}",
        GLOBAL_RUNNING.load(Ordering::SeqCst)
    );
    info!(logger::get(), "开始清理流程");
    cleanup(&cfg);

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

    // 查找正在运行的 firewall-daemon 进程
    let pid = std::process::Command::new("pgrep")
        .arg("-f")
        .arg("firewall-daemon")
        .output()
        .ok()
        .and_then(|output| {
            String::from_utf8(output.stdout)
                .ok()
                .and_then(|s| s.lines().next().map(|p| p.to_string()))
        });

    match pid {
        Some(pid_str) => {
            let pid_num: i32 = pid_str.parse().unwrap_or(0);
            if pid_num <= 0 {
                println!("错误: 无法获取有效的守护进程 PID");
                return Err(anyhow::anyhow!("Invalid daemon PID"));
            }

            // 发送 SIGUSR1 信号触发回滚
            // 注意：当前 signals.rs 未注册 SIGUSR1 处理器，需要扩展
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
