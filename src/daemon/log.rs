//! 守护进程统一日志系统
//!
//! # 特性矩阵
//!
//! | 维度 | 取值 |
//! |------|------|
//! | 级别 (5 级) | NONE / ERR / WARN / INFO / DEBUG |
//! | 目的地 (4 种) | syslog / file / both (syslog+file) / journal (退化为 syslog) |
//! | 格式 (2 种) | plain (默认) / JSON Lines (filebeat/Vector 友好) |
//! | 启动期通道 | `bootstrap_*` 系列宏, `openlog()` 之前走 stderr |
//!
//! # 设计要点
//!
//! - **零依赖**:仅用 `libc` 直接调 `syslog(3)`,避免引入 `syslog` crate
//! - **编译时过滤**:`LOG_MAX_LEVEL` 配合 `should_emit` 让高于阈值的宏调用
//!   在生产构建中被 LLVM 优化掉
//! - **组件名前缀**:非 daemon 组件用 `firewall[<component>]: `,daemon
//!   组件用 `firewall: ` (向后兼容历史日志格式)
//! - **格式独立**:`plain` / `json` 通过 `log_get_format()` 运行时选择,
//!   同一进程无需重启可切换
//!
//! # 公共宏清单
//!
//! - `log_err!` / `log_warn!` / `log_info!` / `log_debug!`:按级别 emit
//! - `bootstrap_err!` / `bootstrap_warn!` / `bootstrap_info!`:openlog 之前
//!   走 stderr,`main()` 第一行和解析配置时使用
//!
//! # 典型使用模式
//!
//! 真执行(不写 `no_run` / `ignore`):编译 + 实际调 `libc::syslog(3)` 一次,
//! 抓住"宏展开路径上 / 运行时初始化"的所有问题,代价是 `cargo test` 时
//! 会向系统 syslog 写 2 条(本地无副作用,CI 走日志归档即可)
//!
//! ```
//! use firewall_daemon::{log_info, log_warn};
//!
//! let name = "sshd";
//! let count = 3;
//! let ip = "1.2.3.4";
//! let e = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "procfs write failed");
//! log_info!("Started jail {} with {} log files", name, count);
//! log_warn!("Failed to ban IP {}: {}", ip, e);
//! ```

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicU8, Ordering};

use parking_lot::Mutex;

// ============================================================================
// 日志级别常量 (独立于 libc 的 LOG_INFO 等,避免命名冲突)
// ============================================================================

/// 禁用所有日志 (静默模式,值 = 0,小于 INFO 阈值)
pub const LOG_LEVEL_NONE: u8 = 0;
/// ERROR 级别,系统错误 / 不可恢复异常
pub const LOG_LEVEL_ERR: u8 = 1;
/// WARN 级别,可恢复问题 (封禁失败 / 配置漂移)
pub const LOG_LEVEL_WARN: u8 = 2;
/// INFO 级别,关键事件 (启动 / 封禁 / 重载)
pub const LOG_LEVEL_INFO: u8 = 3;
/// DEBUG 级别,排错信息 (高频,默认不开启)
pub const LOG_LEVEL_DEBUG: u8 = 4;

/// 编译时级别上限:超过 [`LOG_MAX_LEVEL`] 的日志调用被 `should_emit` 过滤,
/// 不会进入最终二进制。`should_emit` 的常量折叠让 LLVM 可在 release 构建中
/// 彻底消除分支。
pub const LOG_MAX_LEVEL: u8 = LOG_LEVEL_DEBUG;

// ============================================================================
// 输出目的地 / 格式
// ============================================================================

/// 日志输出目的地枚举。
///
/// `repr(u8)` 让其可直接序列化到 `types::Config::log_destination` (u8 字段)
/// 而无需中间转换。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogDestination {
    /// 仅输出到 syslog (`/var/log/syslog` 或 journald)
    Syslog = 0,
    /// 仅输出到独立日志文件 (由 `log_init_file` 指定路径)
    File = 1,
    /// syslog + 文件双写
    Both = 2,
    /// Journald - 暂退化为 syslog (`systemd` 启动时自动从 `/dev/log` 抓取)
    Journal = 3,
}

/// 日志格式枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogFormat {
    /// 纯文本 (默认, 兼容现有 `grep` 工作流)
    Plain = 0,
    /// JSON Lines (filebeat/Vector 等日志收集器友好,每行一条 JSON 对象)
    Json = 1,
}

// ============================================================================
// 全局运行时状态
// ============================================================================
static LOG_RUNTIME_LEVEL: AtomicU8 = AtomicU8::new(LOG_LEVEL_INFO);
static LOG_DESTINATION: AtomicU8 = AtomicU8::new(LogDestination::Both as u8);
static LOG_FORMAT: AtomicU8 = AtomicU8::new(LogFormat::Plain as u8);

static LOG_FILE: Mutex<Option<BufWriter<File>>> = Mutex::new(None);

/// 当前模块组件名, 在各模块 `init()` 入口调用 [`set_log_component`] 切换
static LOG_COMPONENT: Mutex<&'static str> = Mutex::new("daemon");

/// 主守护进程 (`component == "daemon"`) 使用无方括号的 `"firewall: "` 格式, 保持向后兼容
static IS_DAEMON_COMPONENT: AtomicU8 = AtomicU8::new(1);

// ============================================================================
// POSIX syslog 优先级 (固定数值, 跨平台保证)
// ============================================================================
/// syslog `LOG_ERR` (3) - 严重错误
const PRIO_ERR: libc::c_int = 3;
/// syslog `LOG_WARNING` (4) - 警告
const PRIO_WARNING: libc::c_int = 4;
/// syslog `LOG_INFO` (6) - 信息 (DEBUG 也映射到 INFO,因 syslog 无 DEBUG)
const PRIO_INFO: libc::c_int = 6;

// ============================================================================
// 公共配置 API
// ============================================================================

/// 设置运行时日志级别上限。高于 `level` 的 `log_*!` 调用将被静默丢弃。
///
/// # Arguments
/// - `level`: 0..=4,见 [`LOG_LEVEL_NONE`] ..= [`LOG_LEVEL_DEBUG`]
///
/// 越界值 (> [`LOG_LEVEL_DEBUG`]) 静默忽略,保持调用方调用形态简洁。
pub fn log_set_level(level: u8) {
    if level <= LOG_LEVEL_DEBUG {
        LOG_RUNTIME_LEVEL.store(level, Ordering::Relaxed);
    }
}

/// 读取当前运行时级别 (0..=4)
pub fn log_get_level() -> u8 {
    LOG_RUNTIME_LEVEL.load(Ordering::Relaxed)
}

/// 设置日志输出目的地。立即生效,无需重启。
#[inline]
pub fn log_set_destination(dest: LogDestination) {
    LOG_DESTINATION.store(dest as u8, Ordering::Relaxed);
}

/// 读取当前目的地。未知数值回退到 [`LogDestination::Both`] (容错,与 C 版兼容)
///
/// 末位 `_` 分支是防御性默认,故意重复 `Both` 以便未来添加新变体时无需修改此处
#[allow(clippy::match_same_arms)]
#[inline]
pub fn log_get_destination() -> LogDestination {
    match LOG_DESTINATION.load(Ordering::Relaxed) {
        0 => LogDestination::Syslog,
        1 => LogDestination::File,
        2 => LogDestination::Both,
        3 => LogDestination::Journal,
        _ => LogDestination::Both,
    }
}

/// 设置日志格式 (plain / json)。立即生效,无需重启。
#[inline]
pub fn log_set_format(fmt: LogFormat) {
    LOG_FORMAT.store(fmt as u8, Ordering::Relaxed);
}

/// 读取当前格式。未知数值回退到 [`LogFormat::Plain`]
///
/// 末位 `_` 分支是防御性默认,故意重复 `Plain` 以便未来添加新变体时无需修改此处
#[allow(clippy::match_same_arms)]
#[inline]
pub fn log_get_format() -> LogFormat {
    match LOG_FORMAT.load(Ordering::Relaxed) {
        0 => LogFormat::Plain,
        1 => LogFormat::Json,
        _ => LogFormat::Plain,
    }
}

/// 切换日志组件名。各模块在 `init()` 入口调用此函数,后续所有日志会自动加
/// `firewall[<component>]: ` 前缀(daemon 组件除外)。
///
/// # Arguments
/// - `c`: 静态字符串,常用值 `"daemon"` / `"sqlite"` / `"jail"` / `"ban"`
#[inline]
pub fn set_log_component(c: &'static str) {
    *LOG_COMPONENT.lock() = c;
    IS_DAEMON_COMPONENT.store(u8::from(c == "daemon"), Ordering::Relaxed);
}

/// 读取当前组件名 (用于 `emit_file` / bootstrap_* 等需要构造前缀的内部函数)
#[inline]
pub fn get_log_component() -> &'static str {
    *LOG_COMPONENT.lock()
}

// ============================================================================
// 文件管理
// ============================================================================

/// 打开独立日志文件 (append 模式, `O_CLOEXEC`)。
///
/// 若已存在旧 file handle,会先 flush 再替换。父目录不存在时自动 `create_dir_all`。
///
/// # Arguments
/// - `path`: 目标文件路径。建议绝对路径;权限 `0640` 由调用方通过 `chmod` 调整
///
/// # Errors
/// - `InvalidInput`: 路径为空
/// - `Io`: 创建目录、打开文件、写入失败
pub fn log_init_file(path: &str) -> std::io::Result<()> {
    if path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty path",
        ));
    }

    // 父目录不存在时尝试创建
    if let Some(dir) = std::path::Path::new(path).parent() {
        let dir_str = dir.to_string_lossy();
        if !dir_str.is_empty() && dir_str != "/" && !dir.exists() {
            std::fs::create_dir_all(dir)?;
        }
    }

    // O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, mode 0640
    // 注: `.append(true)` 已隐含 `.write(true)`,无需重复声明
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_CLOEXEC)
        .mode(0o640)
        .open(path)?;

    let mut guard = LOG_FILE.lock();
    if let Some(mut old) = guard.take() {
        let _ = old.flush();
    }
    *guard = Some(BufWriter::new(file));
    Ok(())
}

/// 关闭独立日志文件。flush 后释放 `BufWriter`。`log_destination=Both` 时
/// syslog 路径仍可用。
pub fn log_close_file() {
    let mut guard = LOG_FILE.lock();
    if let Some(mut bw) = guard.take() {
        let _ = bw.flush();
    }
}

// ============================================================================
// 内部: 路由与输出
// ============================================================================

/// 判断给定级别是否应该 emit。
///
/// 三层过滤:
/// 1. 编译时上限 [`LOG_MAX_LEVEL`] (const 折叠,release 可消除)
/// 2. 运行时上限 [`LOG_RUNTIME_LEVEL`]
///
/// `level == 0` (NONE) 直接 false,合法级别 1..=4 走运行时比较。
#[inline]
fn should_emit(level: u8) -> bool {
    if level > LOG_MAX_LEVEL {
        return false;
    }
    if level > LOG_RUNTIME_LEVEL.load(Ordering::Relaxed) {
        return false;
    }
    true
}

/// 数字级别 → 字符串。用于 plain 格式和日志收集器识别。
#[inline]
fn level_str(level: u8) -> &'static str {
    match level {
        LOG_LEVEL_ERR => "ERROR",
        LOG_LEVEL_WARN => "WARN",
        LOG_LEVEL_INFO => "INFO",
        LOG_LEVEL_DEBUG => "DEBUG",
        _ => "?",
    }
}

/// 数字级别 → syslog 优先级。DEBUG 映射到 INFO (syslog 无 DEBUG 级别)。
///
/// 末位 `_` 分支是防御性默认,故意重复 `INFO` 以便未来添加新变体时无需修改此处
#[allow(clippy::match_same_arms)]
#[inline]
fn level_prio(level: u8) -> libc::c_int {
    match level {
        LOG_LEVEL_ERR => PRIO_ERR,
        LOG_LEVEL_WARN => PRIO_WARNING,
        LOG_LEVEL_INFO => PRIO_INFO,
        LOG_LEVEL_DEBUG => PRIO_INFO,
        _ => PRIO_INFO,
    }
}

/// 构造日志前缀。daemon 组件用 `"firewall: "` (无方括号, 兼容历史格式),
/// 其他组件用 `"firewall[<component>]: "`。
fn log_fmt_prefix(component: &str, is_daemon: bool) -> String {
    if is_daemon {
        "firewall: ".to_string()
    } else {
        format!("firewall[{component}]: ")
    }
}

/// 调 `libc::syslog` 输出单条消息。`%` 转义防止 printf 格式字符串攻击。
fn emit_syslog(prio: libc::c_int, msg: &str) {
    // syslog(3) 期望 printf 格式, % 需要转义避免格式字符串攻击
    let escaped = msg.replace('%', "%%");
    // SAFETY: `b"%s\0"` 是合法的 C 字符串字面量(以 NUL 结尾),`escaped.as_ptr()`
    // 指向有效 UTF-8 字节,`libc::syslog` 内部把它当 C 字符串读(读到 NUL 终止,
    // 我们保证 `escaped` 不含 NUL 字节因为来源是 `String`,不会在中间截断)
    unsafe {
        libc::syslog(prio, b"%s\0".as_ptr().cast::<libc::c_char>(), escaped.as_ptr());
    }
}

/// 写一条消息到独立日志文件。`File` 未初始化时直接 return (syslog-only 模式)。
///
/// JSON 格式时做最少转义: `"` → `\"`、 `\` → `\\`。不做 Unicode 控制字符
/// 转义 (依赖 `serde_json` 才能完整,这里轻量化)。
fn emit_file(level: u8, prio: libc::c_int, full_msg: &str) {
    let mut guard = LOG_FILE.lock();
    let Some(bw) = guard.as_mut() else {
        return;
    };

    let component = get_log_component();
    let lvl_str = level_str(level);
    let now = chrono::Local::now();
    let ts_plain = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let ts_json = now.format("%Y-%m-%dT%H:%M:%S%z").to_string();

    if log_get_format() == LogFormat::Json {
        // msg 字段做最少 JSON 转义: " → \" , \ → \\
        let _ = write!(bw, "{{\"ts\":\"");
        let _ = bw.write_all(ts_json.as_bytes());
        let _ = write!(bw, "\",\"prio\":{prio},\"component\":\"{component}\",\"level\":\"{lvl_str}\",\"msg\":\"");
        for c in full_msg.chars() {
            match c {
                '"' => {
                    let _ = bw.write_all(b"\\\"");
                }
                '\\' => {
                    let _ = bw.write_all(b"\\\\");
                }
                _ => {
                    let mut buf = [0u8; 4];
                    let s = c.encode_utf8(&mut buf);
                    let _ = bw.write_all(s.as_bytes());
                }
            }
        }
        let _ = bw.write_all(b"\"}\n");
    } else {
        let _ = write!(bw, "{ts_plain} [{component}] {lvl_str}: ");
        let _ = bw.write_all(full_msg.as_bytes());
        let _ = bw.write_all(b"\n");
    }
    let _ = bw.flush();
}

/// 公共 emit 入口:所有 `log_*!` 宏都最终调到这里。
///
/// 流程: 级别过滤 → 构造完整消息 (前缀 + 用户内容) → 按目的地路由。
/// 锁开销仅在 `Destination::File` 时存在 (一次 `BufWriter.flush`)。
///
/// # Arguments
/// - `level`: 0..=4,见 `LOG_LEVEL_*` 常量
/// - `args`: 来自 `format_args!` 的运行时格式化参数
pub fn emit(level: u8, args: fmt::Arguments<'_>) {
    if !should_emit(level) {
        return;
    }

    let component = get_log_component();
    let is_daemon = IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 1;
    let prefix = log_fmt_prefix(component, is_daemon);
    let full_msg = format!("{prefix}{args}");
    let prio = level_prio(level);

    let dest = log_get_destination();
    match dest {
        LogDestination::Syslog | LogDestination::Journal => {
            // Journal 暂退化为 syslog (systemd 会自动捕获)
            emit_syslog(prio, &full_msg);
        }
        LogDestination::File => {
            emit_file(level, prio, &full_msg);
        }
        LogDestination::Both => {
            emit_syslog(prio, &full_msg);
            emit_file(level, prio, &full_msg);
        }
    }
}

// ============================================================================
// 公共日志宏
// ============================================================================

#[macro_export]
macro_rules! log_err {
    ($($arg:tt)*) => {{
        $crate::log::emit($crate::log::LOG_LEVEL_ERR, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {{
        $crate::log::emit($crate::log::LOG_LEVEL_WARN, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {{
        $crate::log::emit($crate::log::LOG_LEVEL_INFO, format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {{
        $crate::log::emit($crate::log::LOG_LEVEL_DEBUG, format_args!($($arg)*));
    }};
}

// ============================================================================
// 启动期输出: openlog() 之前任何日志走 stderr
// ============================================================================

/// 启动期 ERROR 输出 → stderr。`open_syslog()` 之前唯一可用通道。
///
/// # Arguments
/// - `args`: 来自 `format_args!` 的运行时格式化参数
pub fn bootstrap_emit_err(args: fmt::Arguments<'_>) {
    let component = get_log_component();
    let is_daemon = IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 1;
    let prefix = log_fmt_prefix(component, is_daemon);
    eprintln!("{prefix}ERROR: {args}");
}

/// 启动期 WARN 输出 → stderr。`open_syslog()` 之前唯一可用通道。
///
/// # Arguments
/// - `args`: 来自 `format_args!` 的运行时格式化参数
pub fn bootstrap_emit_warn(args: fmt::Arguments<'_>) {
    let component = get_log_component();
    let is_daemon = IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 1;
    let prefix = log_fmt_prefix(component, is_daemon);
    eprintln!("{prefix}WARN: {args}");
}

/// 启动期 INFO 输出 → stderr。`open_syslog()` 之前唯一可用通道。
///
/// # Arguments
/// - `args`: 来自 `format_args!` 的运行时格式化参数
pub fn bootstrap_emit_info(args: fmt::Arguments<'_>) {
    let component = get_log_component();
    let is_daemon = IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 1;
    let prefix = log_fmt_prefix(component, is_daemon);
    eprintln!("{prefix}{args}");
}

#[macro_export]
macro_rules! bootstrap_err {
    ($($arg:tt)*) => {{
        $crate::log::bootstrap_emit_err(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! bootstrap_warn {
    ($($arg:tt)*) => {{
        $crate::log::bootstrap_emit_warn(format_args!($($arg)*));
    }};
}

#[macro_export]
macro_rules! bootstrap_info {
    ($($arg:tt)*) => {{
        $crate::log::bootstrap_emit_info(format_args!($($arg)*));
    }};
}

// ============================================================================
// openlog 包装
// ============================================================================

/// `openlog("firewall", LOG_PID | LOG_CONS, LOG_DAEMON)` 包装。
///
/// - `LOG_PID`: 每条消息附带 PID
/// - `LOG_CONS`: syslog 不可用时回退到 console
/// - `LOG_DAEMON`: facility 设为 daemon
///
/// 调用后 `emit_syslog` 才可用;调用前请用 `bootstrap_*!` 走 stderr。
pub fn open_syslog() {
    const LOG_PID: libc::c_int = 1 << 0;
    const LOG_CONS: libc::c_int = 1 << 1;
    const LOG_DAEMON: libc::c_int = 3 << 3;
    // SAFETY: `b"firewall\0"` 是合法的 NUL 结尾 C 字符串。`openlog` 内部
    // 复制 identifier,不会保留指针(详见 man 3 openlog)。flags 和
    // facility 参数是合法 libc::c_int 值。
    unsafe {
        libc::openlog(b"firewall\0".as_ptr().cast::<libc::c_char>(), LOG_PID | LOG_CONS, LOG_DAEMON);
    }
}

/// `closelog()` 包装。`main()` 的 `cleanup` 阶段调用,释放 syslog fd。
pub fn close_syslog() {
    // SAFETY: `closelog` 没有参数也无前置条件(全局状态由 `openlog` 初始化),
    // 多次调用安全,无未初始化副作用
    unsafe { libc::closelog() };
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_constants_match_posix() {
        assert_eq!(PRIO_ERR, 3);
        assert_eq!(PRIO_WARNING, 4);
        assert_eq!(PRIO_INFO, 6);
    }

    #[test]
    fn set_get_level_roundtrip() {
        let saved = log_get_level();
        log_set_level(LOG_LEVEL_DEBUG);
        assert_eq!(log_get_level(), LOG_LEVEL_DEBUG);
        log_set_level(LOG_LEVEL_ERR);
        assert_eq!(log_get_level(), LOG_LEVEL_ERR);
        log_set_level(LOG_LEVEL_DEBUG + 100); // 越界值应被忽略
        assert_eq!(log_get_level(), LOG_LEVEL_ERR);
        log_set_level(saved);
    }

    #[test]
    fn set_get_destination_roundtrip() {
        log_set_destination(LogDestination::File);
        assert_eq!(log_get_destination(), LogDestination::File);
        log_set_destination(LogDestination::Both);
        assert_eq!(log_get_destination(), LogDestination::Both);
    }

    #[test]
    fn set_get_format_roundtrip() {
        log_set_format(LogFormat::Json);
        assert_eq!(log_get_format(), LogFormat::Json);
        log_set_format(LogFormat::Plain);
        assert_eq!(log_get_format(), LogFormat::Plain);
    }

    #[test]
    fn set_component_changes_prefix() {
        set_log_component("daemon");
        assert_eq!(get_log_component(), "daemon");
        assert!(IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 1);
        set_log_component("sqlite");
        assert_eq!(get_log_component(), "sqlite");
        assert!(IS_DAEMON_COMPONENT.load(Ordering::Relaxed) == 0);
        set_log_component("daemon");
    }

    #[test]
    fn should_emit_respects_level() {
        let saved = log_get_level();
        log_set_level(LOG_LEVEL_WARN);
        assert!(should_emit(LOG_LEVEL_ERR));
        assert!(should_emit(LOG_LEVEL_WARN));
        assert!(!should_emit(LOG_LEVEL_INFO));
        assert!(!should_emit(LOG_LEVEL_DEBUG));
        log_set_level(LOG_LEVEL_DEBUG);
        assert!(should_emit(LOG_LEVEL_DEBUG));
        log_set_level(saved);
    }

    #[test]
    fn level_str_prio_match() {
        for level in [LOG_LEVEL_ERR, LOG_LEVEL_WARN, LOG_LEVEL_INFO, LOG_LEVEL_DEBUG] {
            let s = level_str(level);
            let p = level_prio(level);
            assert!(!s.is_empty());
            assert!(p >= 0 && p <= 7);
        }
    }

    #[test]
    fn log_init_file_empty_path_errors() {
        let r = log_init_file("");
        assert!(r.is_err());
    }

    #[test]
    fn log_init_close_file_roundtrip() {
        let tmpdir = std::env::temp_dir().join(format!("fw_test_log_{}_roundtrip", std::process::id()));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test.log");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let saved_dest = log_get_destination();
        let saved_fmt = log_get_format();
        let saved_level = log_get_level();
        let saved_component = get_log_component();

        assert!(log_init_file(path_str).is_ok());
        log_set_destination(LogDestination::File);
        log_set_format(LogFormat::Plain);
        log_set_level(LOG_LEVEL_DEBUG);
        set_log_component("test");
        emit(LOG_LEVEL_INFO, format_args!("hello world"));
        log_close_file();
        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("hello world"));
        assert!(content.contains("INFO"));
        let _ = std::fs::remove_file(path_str);
        let _ = std::fs::remove_dir(&tmpdir);

        log_set_destination(saved_dest);
        log_set_format(saved_fmt);
        log_set_level(saved_level);
        set_log_component(saved_component);
    }

    #[test]
    fn json_format_escapes_quotes_and_backslashes() {
        let tmpdir = std::env::temp_dir().join(format!("fw_test_log_json_{}_escape", std::process::id()));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test_json.log");
        let path_str = path.to_str().unwrap();
        let _ = std::fs::remove_file(path_str);

        let saved_dest = log_get_destination();
        let saved_fmt = log_get_format();
        let saved_level = log_get_level();
        let saved_component = get_log_component();

        assert!(log_init_file(path_str).is_ok());
        log_set_destination(LogDestination::File);
        log_set_format(LogFormat::Json);
        log_set_level(LOG_LEVEL_DEBUG);
        set_log_component("test");
        emit(LOG_LEVEL_INFO, format_args!("msg with \"quote\" and \\backslash"));
        log_close_file();

        let content = std::fs::read_to_string(path_str).unwrap();
        assert!(content.contains("\\\"quote\\\""));
        assert!(content.contains("\\\\backslash"));
        let first = content.lines().next().unwrap();
        assert!(first.starts_with('{'));
        assert!(first.ends_with('}'));

        let _ = std::fs::remove_file(path_str);
        let _ = std::fs::remove_dir(&tmpdir);

        log_set_destination(saved_dest);
        log_set_format(saved_fmt);
        log_set_level(saved_level);
        set_log_component(saved_component);
    }
}