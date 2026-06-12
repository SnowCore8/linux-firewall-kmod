//! 基于 slog 的结构化日志系统
//!
//! # 设计
//!
//! 使用 `slog-scope` 设置全局 logger，所有模块可直接使用 `info!`, `warn!`, `error!`, `debug!` 宏。
//! 输出格式为 JSON Lines（每行一条 JSON 对象），适合日志收集器（filebeat、Vector 等）处理。
//!
//! # JSON Lines 格式
//!
//! ```json
//! {"timestamp":"2024-01-13T02:15:30.123Z","level":"INFO","component":"main","message":"启动成功","version":"2.2.0"}
//! {"timestamp":"2024-01-13T02:15:31.456Z","level":"INFO","component":"ban","message":"IP 封禁成功","ip":"192.168.1.100","jail":"sshd"}
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
use std::sync::OnceLock;

/// 全局 logger 实例
static GLOBAL_LOGGER: OnceLock<Logger> = OnceLock::new();

/// 初始化全局 logger
///
/// 创建 JSON Lines 格式的 slog logger，输出到 stderr（异步模式）。
/// 应在程序启动时调用一次。
pub fn init_logger() -> Logger {
    // 创建 JSON Lines 格式的 drain
    // 输出到 stderr，适合 systemd/journald 捕获
    let drain = Json::default(std::io::stderr()).fuse();

    // 包装为异步 drain
    let drain = Async::new(drain).build().fuse();

    // 创建根 logger，添加全局字段
    let logger = Logger::root(
        drain,
        slog::o!(
            "version" => env!("CARGO_PKG_VERSION")
        ),
    );

    // 设置为全局 logger
    let _guard = slog_scope::set_global_logger(logger.clone());

    // 存储到全局 OnceLock
    let _ = GLOBAL_LOGGER.set(logger.clone());

    logger
}

/// 获取全局 logger 实例
///
/// 如果 logger 未初始化，返回一个静默 logger（丢弃所有日志）。
/// 建议在初始化后使用。
pub fn get() -> Logger {
    GLOBAL_LOGGER
        .get()
        .cloned()
        .unwrap_or_else(|| Logger::root(slog::Discard, slog::o!()))
}

/// 重新导出 slog 的日志宏，方便其他模块使用
pub use slog::{debug, error, info, warn};
