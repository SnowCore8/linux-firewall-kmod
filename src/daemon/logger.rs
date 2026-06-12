//! 基于 slog 的结构化日志系统
//!
//! # 设计
//!
//! 使用 `slog-scope` 设置全局 logger，所有模块可直接使用 `info!`, `warn!`, `error!`, `debug!` 宏。
//! 输出目的地为 stderr（异步模式），格式包含时间戳、日志级别、模块名和消息。
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
use slog_term::{FullFormat, TermDecorator};
use std::sync::OnceLock;

/// 全局 logger 实例
static GLOBAL_LOGGER: OnceLock<Logger> = OnceLock::new();

/// 初始化全局 logger
///
/// 创建异步终端输出的 slog logger，并设置为全局 logger。
/// 应在程序启动时调用一次。
pub fn init_logger() -> Logger {
    // 创建终端装饰器
    let decorator = TermDecorator::new().stderr().build();

    // 创建完整格式化的 drain（包含时间戳、级别、模块等）
    let drain = FullFormat::new(decorator).build().fuse();

    // 包装为异步 drain
    let drain = Async::new(drain).build().fuse();

    // 创建根 logger
    let logger = Logger::root(drain, slog::o!("version" => env!("CARGO_PKG_VERSION")));

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
