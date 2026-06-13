//! `firewall-daemon` 二进制入口:CLI 解析 → 配置加载 → 信号注册 → 守护进程化 → 主监控循环
//!
//! # 启动流程
//!
//! 1. **CLI 解析** ([`config::parse_config_args`]):`--help` 时直接 `Ok(())` 退出
//! 2. **配置加载** ([`config::parse_config_file`] / [`load_config_directory`]):支持文件 / 目录两种源
//! 3. **智能默认 + 校验** ([`jail::apply_smart_defaults_to_all`] / [`jail::config_validate`])
//! 4. **信号注册** ([`setup_signals`]):SIGTERM/SIGINT 触发优雅退出、SIGHUP 触发热重载、SIGPIPE 忽略
//! 5. **procfs 前置检查**:`/proc/firewall` 存在性 + `/proc/firewall/bans` 存在性
//! 6. **SQLite 初始化** (可选):加载 → 注册全局 → 恢复所有永久黑名单到内核
//! 7. **守护进程化** ([`daemonize_process`]):双 fork + setsid + chdir / + 写 PID + 重定向 fd
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
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};

use firewall_daemon::ban;
use firewall_daemon::config;
use firewall_daemon::file_monitor;
use firewall_daemon::http_exporter;
use firewall_daemon::jail;
use firewall_daemon::sqlite;
use firewall_daemon::types::{Config, DAEMON_STATS};
use std::sync::Arc;

/// 构造 `running` 标志原子。SIGINT/SIGTERM 触发置 false,主循环退出。
fn make_running() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(true))
}

/// 构造 `reload` 标志原子。SIGHUP 触发置 true,主循环超时分支检测到后
/// 调 [`file_monitor::reload_configuration`].
fn make_reload_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

/// 内核模块 procfs 根目录。启动期存在性检查
const PROCFS_DIR: &str = "/proc/firewall";
/// 内核模块封禁命令接口。启动期存在性检查
const BANS_PATH: &str = "/proc/firewall/bans";

/// 注册 4 个信号到 atomic 标志。
///
/// - `SIGTERM` / `SIGINT` → `running` (主循环退出)
/// - `SIGHUP` → `reload_config` (主循环触发热重载)
/// - `SIGPIPE` → 忽略 (HTTP 客户端断开时不被信号杀死)
///
/// # Arguments
/// - `running`: 主循环运行标志
/// - `reload_config`: 配置重载标志
///
/// # Errors
/// `signal_hook::flag::register` 失败
fn setup_signals(running: Arc<AtomicBool>, reload_config: Arc<AtomicBool>) -> Result<()> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGPIPE, SIGTERM};

    signal_hook::flag::register(SIGTERM, running.clone())?;
    signal_hook::flag::register(SIGINT, running)?;

    signal_hook::flag::register(SIGHUP, reload_config)?;

    // SIGPIPE 忽略: HTTP 导出器在客户端断开时不应被信号杀死
    signal_hook::flag::register(SIGPIPE, Arc::new(AtomicBool::new(true)))?;

    Ok(())
}

/// 守护进程化:双 fork + setsid + chdir / + 写 PID + 重定向 fd。
///
/// 经典 Unix 守护进程化模式,故意用 `process::exit` 而非 `std::process::exit`
/// 以避免刷新 stdio 缓冲区(fork 后的子进程中 stdio 状态未定义)。
///
/// # Errors
/// 任何 fork 失败
fn daemonize_process() -> Result<()> {
    use nix::unistd::{fork, setsid, ForkResult};
    use std::process;

    // 第一次 fork: 父进程退出
    // SAFETY: `fork` 是 POSIX 进程创建原语,无内存安全前置条件;
    // `ForkResult` 区分父子进程使父进程可立即 exit (避免 stdio 缓冲区双写)
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {}
        Ok(ForkResult::Parent { child: _, .. }) => {
            // _exit 避免刷新 stdio 缓冲区 (fork 后的子进程中 stdio 状态未定义)
            process::exit(0);
        }
        Err(e) => bail!("fork failed: {}", e),
    }

    setsid().context("setsid failed")?;

    // 第二次 fork: 防止重新获得控制终端, 创建非会话领头进程
    // SAFETY: 同上
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {}
        Ok(ForkResult::Parent { .. }) => {
            process::exit(0);
        }
        Err(e) => bail!("second fork failed: {}", e),
    }

    if let Err(_e) = std::env::set_current_dir("/") {}

    // PID 文件用 O_NOFOLLOW 防止符号链接攻击覆盖其他进程
    let pid = process::id();
    let pid_path = "/run/firewall-daemon.pid";
    // SAFETY: `pid_path` 是 `&'static str` 常量,无 NUL 字节。`open` 标志是
    // 合法 libc 常量。`mode 0o644` 只在 `O_CREAT` 时生效。
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(pid_path).unwrap().as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd >= 0 {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;
        // SAFETY: `fd` 是上一行 `libc::open` 返回的有效 fd,且未通过其他
        // 途径转移所有权,直接包装为 `File` 取得独占所有权。
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        let _ = writeln!(f, "{}", pid);
        let _ = f.flush();
    }

    // 标准 fd 重定向到 /dev/null
    if let Ok(devnull) = fs::File::open("/dev/null") {
        use std::os::unix::io::IntoRawFd;
        let fd = devnull.into_raw_fd();
        // SAFETY: `devnull.into_raw_fd()` 返回的 fd 来自刚 `File::open` 成功的
        // `/dev/null`,仍是有效文件描述符。`dup2` 复制 fd 后原 fd 仍可独立 close。
        // 目标 fd 0/1/2 必为进程启动时的 stdin/stdout/stderr 有效 fd。
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                // SAFETY: 上面 dup2 已复制,原 fd 可安全关闭(非 stdio 三个之一)
                libc::close(fd);
            }
        }
    }

    Ok(())
}

/// 优雅清理:关 metrics → 释放 fd → 关闭 SQLite → 关 syslog → 删 PID 文件。
///
/// 顺序敏感:先清全局引用再关 db,防止收尾期间 ban 模块再访问。
///
/// # Arguments
/// - `running`: 运行标志 (置 false 以防主循环死灰复燃)
/// - `_cfg`: 保留参数,占位
/// - `sqlite_db`: 可选 db 句柄 (来自 [`sqlite::sqlite_init`])
fn cleanup(
    running: &Arc<AtomicBool>,
    _cfg: &Config,
    sqlite_db: &Option<std::sync::Arc<sqlite::SqliteDb>>,
) {
    http_exporter::stop_http_exporter();
    running.store(false, Ordering::Relaxed);
    ban::close_cached_bans_fd();
    // 清理顺序: 先清全局引用, 再关 db, 防止收尾期间 ban 模块再访问
    sqlite::clear_global_db();
    if let Some(db) = sqlite_db {
        sqlite::sqlite_close(db);
    }
    let _ = fs::remove_file("/run/firewall-daemon.pid");
}

/// `firewall-daemon` 主入口。返回值:
/// - `Ok(())` 正常退出
/// - `Err(_)` 启动失败或运行错误
fn main() -> Result<()> {
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
    } else if path.is_dir() {
        config::load_config_directory(&config_path, &mut cfg, strict_mode)?;
        cfg.config_dir = Some(config_path.clone());
    } else {
        bail!("Config path does not exist: {}", config_path);
    }

    jail::apply_smart_defaults_to_all(&mut cfg);
    jail::config_validate(&cfg).map_err(|e| anyhow::anyhow!("{}", e))?;
    cfg.daemon = daemon_mode;

    let running = make_running();
    let reload_config = make_reload_flag();
    setup_signals(running.clone(), reload_config.clone())?;

    if !Path::new(PROCFS_DIR).exists() {
        bail!("Procfs directory not found");
    }

    if !Path::new(BANS_PATH).exists() {
        bail!("Bans procfs interface not found");
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    DAEMON_STATS.start_time.store(now, Ordering::Relaxed);

    let mut sqlite_db: Option<std::sync::Arc<sqlite::SqliteDb>> = None;
    if cfg.permanent_ban_enabled {
        if let Some(ref db_path) = cfg.permanent_db_path {
            match sqlite::sqlite_init(db_path) {
                Ok(db) => {
                    sqlite::set_global_db(db.clone());
                    sqlite_db = Some(db);

                    if let Some(ref db) = sqlite_db {
                        match sqlite::sqlite_load_all_permanent_bans(db) {
                            Ok(entries) if !entries.is_empty() => {
                                for entry in &entries {
                                    // 用 ban::ban_ip_permanent 而非手写 procfs 命令:
                                    //   1) 内核 procfs 不识别 "permanent" 前缀, 只认 "<ip> 0"
                                    //   2) 复用 execute_ban_action 自动写 SQLite + 更新 ips_banned 计数
                                    let _ = ban::ban_ip_permanent(&entry.ip);
                                }
                            }
                            Ok(_) => {}
                            Err(_e) => {}
                        }
                    }
                }
                Err(_e) => {}
            }
        }
    }

    if cfg.daemon {
        daemonize_process()?;
        // 守护进程化后清 reload 标志, 防止该窗口期收到的 SIGHUP 在主循环首次检查时误触
        // 对齐 C 版: 守护进程化期间用 sigaction(SIGHUP, SIG_IGN) 临时忽略
        reload_config.store(false, Ordering::Relaxed);
    }

    file_monitor::setup_inotify(&cfg)?;

    for jail in cfg.jails.iter() {
        if jail.enabled {
            // jail 已启用
        }
    }

    if let Err(_e) = jail::init_log_patterns(&mut cfg) {
        // 正则编译失败,继续使用旧正则
    }

    let mut exporter_handle = None;
    if cfg.metrics_port > 0 {
        exporter_handle = Some(http_exporter::start_http_exporter(cfg.metrics_port, &cfg));
    }

    if let Err(_e) = file_monitor::monitor_loop(&mut cfg, &running, &reload_config) {}

    cleanup(&running, &cfg, &sqlite_db);

    if let Some(handle) = exporter_handle {
        let _ = handle.join();
    }

    Ok(())
}
