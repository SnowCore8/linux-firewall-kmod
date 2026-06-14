//! `firewall-daemon` 二进制入口:CLI 解析 → 配置加载 → 信号注册 → 守护进程化 → 主监控循环
//!
//! # 启动流程
//!
//! 1. **CLI 解析** ([`config::parse_config_args`]):`--help` 时直接 `Ok(())` 退出
//! 2. **配置加载** ([`config::parse_config_file`] / [`load_config_directory`]):支持文件 / 目录两种源
//! 3. **智能默认 + 校验** ([`jail::apply_smart_defaults_to_all`] / [`jail::config_validate`])
//! 4. **信号注册** ([`signals::setup_signals`]):SIGTERM/SIGINT 触发优雅退出、SIGHUP 触发热重载、SIGPIPE 忽略
//! 5. **procfs 前置检查**:`/proc/firewall` 存在性 + `/proc/firewall/bans` 存在性
//! 6. **SQLite 初始化** (可选):加载 → 注册全局 → 恢复所有永久黑名单到内核
//! 7. **守护进程化** ([`daemonizer::daemonize_process`]):双 fork + setsid + chdir / + 写 PID + 重定向 fd
//! 8. **inotify 启动** ([`file_monitor::setup_inotify`])
//! 9. **Metrics 导出器启动** ([`http_exporter::start_http_exporter`])
//! 10. **主循环** ([`file_monitor::monitor_loop`]):阻塞直到 `running=false`
//! 11. **清理** ([`cleanup`]):关 metrics → 释放 fd → 关闭 SQLite → 关 syslog → 删 PID 文件
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

use anyhow::{bail, Result};
use slog::{error, info, warn};

use firewall_daemon::ban;
use firewall_daemon::config;
use firewall_daemon::daemonizer::daemonize_process;
use firewall_daemon::file_monitor;
use firewall_daemon::http_exporter;
use firewall_daemon::jail;
use firewall_daemon::logger;
use firewall_daemon::signals::{setup_signals, GLOBAL_RELOAD, GLOBAL_RUNNING};
use firewall_daemon::sqlite;
use firewall_daemon::sqlite_writer;
use firewall_daemon::types::{Config, DAEMON_STATS};

/// 内核模块 procfs 根目录。启动期存在性检查
const PROCFS_DIR: &str = "/proc/firewall";
/// 内核模块封禁命令接口。启动期存在性检查
const BANS_PATH: &str = "/proc/firewall/bans";

/// 优雅清理：关 metrics → 释放 fd → 关闭 SQLite → 关 syslog → 删 PID 文件。
///
/// 顺序敏感：先清全局引用再关 db，防止收尾期间 ban 模块再访问。
///
/// # Arguments
/// - `_cfg`：保留参数，占位
/// - `sqlite_db`：可选 db 句柄（来自 [`sqlite::sqlite_init`]）
fn cleanup(_cfg: &Config, sqlite_db: &Option<std::sync::Arc<sqlite::SqliteDb>>) {
    http_exporter::stop_http_exporter();
    GLOBAL_RUNNING.store(false, Ordering::SeqCst);
    ban::close_cached_bans_fd();
    // 清理顺序：先清全局引用，再关 db，防止收尾期间 ban 模块再访问
    sqlite::clear_global_db();
    if let Some(db) = sqlite_db {
        sqlite::sqlite_close(db);
    }
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

    let (config_path, daemon_mode, strict_mode) = match config::parse_config_args(&args)? {
        Some((path, daemon, strict)) => (path, daemon, strict),
        None => return Ok(()),
    };
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

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    DAEMON_STATS.start_time.store(now, Ordering::Relaxed);

    let mut sqlite_db: Option<std::sync::Arc<sqlite::SqliteDb>> = None;
    if cfg.permanent_ban_enabled {
        if let Some(ref db_path) = cfg.permanent_db_path {
            match sqlite::sqlite_init(db_path) {
                Ok(db) => {
                    info!(logger::get(), "SQLite 数据库初始化成功"; "path" => %db_path);
                    sqlite::set_global_db(db.clone());
                    sqlite_db = Some(db);

                    if let Some(ref db) = sqlite_db {
                        match sqlite::sqlite_load_all_permanent_bans(db) {
                            Ok(entries) if !entries.is_empty() => {
                                let mut fail_count = 0u32;
                                for entry in &entries {
                                    // 用 ban::ban_ip_permanent 而非手写 procfs 命令:
                                    //   1) 内核 procfs 不识别 "permanent" 前缀, 只认 "<ip> 0"
                                    //   2) 复用 execute_ban_action 自动写 SQLite + 更新 ips_banned 计数
                                    if let Err(e) = ban::ban_ip_permanent(&entry.ip) {
                                        fail_count += 1;
                                        error!(logger::get(), "恢复永久封禁失败（安全规则缺失）"; "ip" => &entry.ip, "error" => %e);
                                    }
                                }
                                if fail_count > 0 {
                                    error!(logger::get(), "永久封禁恢复存在失败"; "failed" => fail_count, "total" => entries.len());
                                }
                            }
                            Ok(_) => {}
                            Err(e) => {
                                eprintln!("[ERROR] 加载永久封禁列表失败: {e}");
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[ERROR] SQLite 数据库初始化失败（永久封禁持久化不可用）: {e}");
                }
            }
        }
    }

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

    // 在守护进程化之后设置信号处理器，确保 fork 后信号处理正常工作
    setup_signals()?;
    info!(logger::get(), "信号处理器已注册");

    // 初始化混合存储表结构并恢复活跃封禁
    if let Some(ref db) = sqlite_db {
        let conn = sqlite::get_conn(db);
        if let Err(e) = sqlite_writer::init_tables(&conn) {
            error!(logger::get(), "初始化混合存储表失败（致命错误，守护进程无法正常运行）"; "error" => %e);
            bail!("Failed to initialize SQLite tables: {}", e);
        } else {
            info!(logger::get(), "混合存储表初始化成功");

            // 从 ban_history 恢复活跃封禁到内存缓存 + 内核
            match sqlite_writer::load_active_bans(&conn) {
                Ok(bans) if !bans.is_empty() => {
                    info!(logger::get(), "恢复活跃封禁条目"; "count" => bans.len());
                    let mut restored_count = 0;
                    let mut skipped_count = 0;
                    for ban_info in &bans {
                        // 跳过空 IP（防御性检查，防止脏数据导致恢复失败）
                        if ban_info.ip.is_empty() {
                            warn!(logger::get(), "跳过空 IP 封禁记录（脏数据）"; "jail" => &ban_info.jail_name);
                            skipped_count += 1;
                            continue;
                        }

                        // 重新写入内核 procfs
                        if let Err(e) = ban::ban_ip(&ban_info.ip) {
                            error!(logger::get(), "恢复封禁到内核失败（安全规则缺失）"; "ip" => &ban_info.ip, "error" => %e);
                            skipped_count += 1;
                            continue;
                        }

                        // 插入内存缓存
                        firewall_daemon::types::ACTIVE_BAN_CACHE
                            .get_or_init(firewall_daemon::types::ActiveBanCache::new)
                            .insert(ban_info.clone());

                        restored_count += 1;
                    }
                    info!(logger::get(), "活跃封禁恢复完成"; "restored" => restored_count, "skipped" => skipped_count, "total" => bans.len());
                }
                Ok(_) => {
                    info!(logger::get(), "无活跃封禁条目需要恢复");
                }
                Err(e) => {
                    error!(logger::get(), "加载活跃封禁条目失败（重启后安全规则可能缺失）"; "error" => %e);
                }
            }
        }
    }

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
    cleanup(&cfg, &sqlite_db);

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
