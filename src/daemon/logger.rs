//! 基于 slog 的结构化日志系统
//!
//! # 设计
//!
//! 使用 `slog-scope` 设置全局 logger，所有模块可直接使用 `info!`, `warn!`, `error!`, `debug!` 宏。
//! 输出格式为 JSON Lines（每行一条 JSON 对象），写入 `/var/log/firewall-daemon.log`，
//! 适合日志收集器（filebeat、Vector 等）处理。
//!
//! # JSON Lines 格式
//!
//! 字段顺序：`ts` → `level` → `msg` → `version` → 其他字段（由 slog_json 自动管理）
//!
//! ```json
//! {"ts":"2024-01-13T02:15:30.123Z","level":"INFO","msg":"启动成功","version":"2.2.0","component":"main"}
//! {"ts":"2024-01-13T02:15:31.456Z","level":"INFO","msg":"IP 封禁成功","version":"2.2.0","ip":"192.168.1.100","jail":"sshd"}
//! ```
//!
//! # 使用示例
//!
//! ```rust
//! use firewall_daemon::logger;
//! use slog::{info, warn, error};
//!
//! // 在 main.rs 中初始化
//! logger::init_logger();
//!
//! // 在任何模块中使用
//! info!(logger::get(), "启动成功"; "module" => "main");
//! warn!(logger::get(), "配置警告"; "detail" => "某字段缺失");
//! ```

use slog::{self, Drain, Logger};
use slog_async::Async;
use slog_json::Json;
use std::fs::OpenOptions;

/// 全局 logger 实例（使用 parking_lot::Mutex 避免 std::sync::Mutex 中毒问题）
///
/// std::sync::Mutex 在线程 panic 时会中毒，导致后续所有 lock() 返回 Err，
/// 日志静默丢失。parking_lot::Mutex 不支持 poisoning，更安全。
static GLOBAL_LOGGER: parking_lot::Mutex<Option<Logger>> = parking_lot::Mutex::new(None);

/// 日志文件路径
const LOG_FILE_PATH: &str = "/var/log/firewall-daemon.log";

/// 初始化全局 logger
///
/// 创建 JSON Lines 格式的 slog logger，输出到日志文件（异步模式）。
/// 应在程序启动时调用一次。如果在 fork 后调用，会重新创建文件句柄和异步线程。
pub fn init_logger() -> Logger {
    // 打开日志文件（追加模式，不存在则创建）
    let file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(LOG_FILE_PATH)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "警告: 无法打开日志文件 {}: {}，回退到 stderr",
                LOG_FILE_PATH, e
            );
            // 回退到 stderr
            use std::os::unix::io::FromRawFd;
            unsafe { std::fs::File::from_raw_fd(2) } // fd 2 = stderr
        }
    };

    // 创建 JSON Lines 格式的 drain
    // 输出到文件，适合日志收集器处理
    // slog_json 会自动按照 ts → level → msg → 全局字段 → 其他字段 的顺序输出
    let drain = Json::default(file).fuse();

    // 包装为异步 drain
    let drain = Async::new(drain).build().fuse();

    // 创建根 logger，添加全局字段（version 会在 ts/level/msg 之后输出）
    let logger = Logger::root(
        drain,
        slog::o!(
            "version" => env!("CARGO_PKG_VERSION")
        ),
    );

    // 设置为全局 logger（slog_scope 只能设置一次，后续调用会忽略）
    let _guard = slog_scope::set_global_logger(logger.clone());
    std::mem::forget(_guard);

    // 存储到全局 Mutex（支持 fork 后重新初始化）
    {
        let mut global_logger = GLOBAL_LOGGER.lock();
        *global_logger = Some(logger.clone());
    }

    logger
}

/// 获取全局 logger 实例
///
/// 如果 logger 未初始化，返回一个静默 logger（丢弃所有日志）。
/// 建议在初始化后使用。
pub fn get() -> Logger {
    GLOBAL_LOGGER
        .lock()
        .clone()
        .unwrap_or_else(|| Logger::root(slog::Discard, slog::o!()))
}

/// 重新导出 slog 的日志宏，方便其他模块使用
pub use slog::{debug, error, info, warn};
