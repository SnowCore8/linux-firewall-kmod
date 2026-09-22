//! 基于 slog 的结构化日志系统
//!
//! # 设计
//!
//! 使用 `slog-scope` 设置全局 logger，所有模块可直接使用 `info!`, `warn!`, `error!`, `debug!` 宏。
//! 输出格式为 JSON Lines（每行一条 JSON 对象），写入日志文件。
//!
//! # 原子写入保证
//!
//! 自定义 `AtomicFileDrain` 替代 `slog_json` + `slog_async` 组合：
//! 1. 将每条日志（**含行尾换行**）编码进一个 `Vec<u8>` 缓冲区（内存中完成 JSON 构建）
//! 2. 在进程内 `Mutex` 保护下用**单次** `write_all` 写出整行
//!
//! 换行必须与正文同处一次 `write()`：`File` 以 `O_APPEND` 打开时，单次写对常规文件
//! 保持按行原子；拆成两次 `write()` 会让并发写者（另一进程、另一 fd）的记录插进中间，
//! 产出「两条记录并成一行 + 空行」。进程内 `Mutex` 对跨进程写者不生效。
//!
//! 相对原方案消除了两个问题：
//! - `slog_json` 的 `serde_json::Serializer` 逐 token 对 `File` 写入（实测每条记录约 69 次
//!   `write()`），交错粒度细到字段级；
//! - `slog_async` 的默认通道（`chan_size` 128、非阻塞）在通道满或进程 `exit` 时**整条丢弃**
//!   记录（实测单进程 20 万条仅落盘约 1.7%）。
//!
//! # JSON Lines 格式
//!
//! 字段顺序：`ts` → `level` → `msg` → `version` → 其他字段
//!
//! ```json
//! {"ts":"2024-01-13T02:15:30.123Z","level":"INFO","msg":"启动成功","version":"2.2.0","component":"main"}
//! ```
//!
//! # 使用示例
//!
//! ```rust,no_run
//! use firewall_daemon::logger;
//! use slog::{info, warn, error};
//!
//! logger::init_logger(None);
//! info!(logger::get(), "启动成功"; "module" => "main");
//! ```

use slog::{self, Logger};
use std::fmt::Write as FmtWrite;
use std::fs::OpenOptions;
use std::io::Write as IoWrite;
use std::sync::atomic::{AtomicI64, Ordering};
use std::{fmt, io, result};

/// 日志节流器：限制相同消息的输出频率
pub struct LogThrottler {
    last_log_time: AtomicI64,
    interval: i64,
}

impl LogThrottler {
    pub fn new(interval: i64) -> Self {
        Self {
            last_log_time: AtomicI64::new(0),
            interval,
        }
    }

    pub fn can_log(&self) -> bool {
        let now = crate::types::now_secs();
        let last_time = self.last_log_time.load(Ordering::Relaxed);
        if now - last_time >= self.interval {
            self.last_log_time.store(now, Ordering::Relaxed);
            true
        } else {
            false
        }
    }
}

static GLOBAL_LOGGER: parking_lot::Mutex<Option<Logger>> = parking_lot::Mutex::new(None);

const DEFAULT_LOG_FILE_PATH: &str = "/var/log/firewall-daemon.log";

// ─── ValueSerializer：slog::Serializer → Vec<(String, serde_json::Value)> ───

/// 将 slog 的 KV 对捕获为 `(String, serde_json::Value)` 列表，
/// 保留原始类型（数字→Number，布尔→Bool，字符串→String）。
struct ValueSerializer {
    pairs: Vec<(String, serde_json::Value)>,
}

impl ValueSerializer {
    fn new() -> Self {
        Self {
            pairs: Vec::with_capacity(8),
        }
    }
}

impl slog::Serializer for ValueSerializer {
    fn emit_bool(&mut self, key: slog::Key, val: bool) -> slog::Result {
        let k: &str = key;
        self.pairs
            .push((k.to_owned(), serde_json::Value::Bool(val)));
        Ok(())
    }
    fn emit_char(&mut self, key: slog::Key, val: char) -> slog::Result {
        let k: &str = key;
        self.pairs
            .push((k.to_owned(), serde_json::Value::String(val.to_string())));
        Ok(())
    }
    fn emit_unit(&mut self, key: slog::Key) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::Value::Null));
        Ok(())
    }
    fn emit_none(&mut self, key: slog::Key) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::Value::Null));
        Ok(())
    }
    fn emit_u8(&mut self, key: slog::Key, val: u8) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_i8(&mut self, key: slog::Key, val: i8) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_u16(&mut self, key: slog::Key, val: u16) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_i16(&mut self, key: slog::Key, val: i16) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_usize(&mut self, key: slog::Key, val: usize) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_isize(&mut self, key: slog::Key, val: isize) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_u32(&mut self, key: slog::Key, val: u32) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_i32(&mut self, key: slog::Key, val: i32) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_f32(&mut self, key: slog::Key, val: f32) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_u64(&mut self, key: slog::Key, val: u64) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_i64(&mut self, key: slog::Key, val: i64) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_f64(&mut self, key: slog::Key, val: f64) -> slog::Result {
        let k: &str = key;
        self.pairs.push((k.to_owned(), serde_json::json!(val)));
        Ok(())
    }
    fn emit_u128(&mut self, key: slog::Key, val: u128) -> slog::Result {
        let k: &str = key;
        self.pairs
            .push((k.to_owned(), serde_json::json!(val.to_string())));
        Ok(())
    }
    fn emit_i128(&mut self, key: slog::Key, val: i128) -> slog::Result {
        let k: &str = key;
        self.pairs
            .push((k.to_owned(), serde_json::json!(val.to_string())));
        Ok(())
    }
    fn emit_str(&mut self, key: slog::Key, val: &str) -> slog::Result {
        let k: &str = key;
        self.pairs
            .push((k.to_owned(), serde_json::Value::String(val.to_owned())));
        Ok(())
    }
    fn emit_arguments(&mut self, key: slog::Key, val: &fmt::Arguments<'_>) -> slog::Result {
        let k: &str = key;
        let mut buf = String::with_capacity(64);
        buf.write_fmt(*val).unwrap();
        self.pairs
            .push((k.to_owned(), serde_json::Value::String(buf)));
        Ok(())
    }
}

// ─── AtomicFileDrain：同步、逐行原子写入 ───

/// 同步 JSON Lines drain，保证每条记录原子写入。
///
/// 每条日志：
/// 1. 用 `ValueSerializer` 收集 KV 对为 `(键, serde_json::Value)` 列表（保持插入顺序）
/// 2. 手工编码 JSON 到单个 `Vec<u8>`（含行尾 `\n`）
/// 3. 在进程内 `Mutex<File>` 保护下单次 `write_all` 写出
///
/// 不使用 `slog_async`——异步通道（`chan_size` 128、非阻塞）在通道满或进程退出时
/// 整条丢弃记录。
struct AtomicFileDrain {
    file: std::sync::Mutex<std::fs::File>,
}

impl AtomicFileDrain {
    /// 单次 `write_all` 写出整行（换行已并入 `line` 尾部）。
    ///
    /// 必须是一次 `write()`：`O_APPEND` 打开时单次写对常规文件按行原子，
    /// 拆成两次会让并发写者的记录插进中间。
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        file.write_all(line)
    }
}

/// 按插入顺序把 KV 列表编码为一行 JSON（不含换行）。
///
/// 不用 `serde_json::Map`——它默认是 `BTreeMap`，会把字段按字典序重排，
/// 与文档承诺的 `ts` → `level` → `msg` → `version` → 其他 顺序不符。
fn encode_json_line(pairs: &[(String, serde_json::Value)]) -> io::Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    buf.push(b'{');
    for (i, (key, value)) in pairs.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        serde_json::to_writer(&mut buf, key)?;
        buf.push(b':');
        serde_json::to_writer(&mut buf, value)?;
    }
    buf.push(b'}');
    buf.push(b'\n');
    Ok(buf)
}

impl slog::Drain for AtomicFileDrain {
    type Ok = ();
    type Err = slog::Never;

    fn log(
        &self,
        record: &slog::Record<'_>,
        logger_values: &slog::OwnedKVList,
    ) -> result::Result<(), slog::Never> {
        let mut ser = ValueSerializer::new();

        // 默认字段：ts → level → msg
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        ser.pairs.push(("ts".into(), serde_json::Value::String(ts)));
        ser.pairs.push((
            "level".into(),
            serde_json::Value::String(record.level().as_short_str().to_owned()),
        ));
        ser.pairs.push((
            "msg".into(),
            serde_json::Value::String(format!("{}", record.msg())),
        ));

        // 全局 KV（version 等）+ 日志语句自身 KV
        let _ = slog::KV::serialize(logger_values, record, &mut ser);
        let _ = slog::KV::serialize(&record.kv(), record, &mut ser);

        // 按插入顺序编码为完整一行，单次 write 写出
        if let Ok(line) = encode_json_line(&ser.pairs) {
            let _ = self.write_line(&line);
        }
        Ok(())
    }
}

// ─── 公共 API ───

/// 为 drain 打开日志文件；失败时回退到 stderr 的**独立副本**。
///
/// 回退必须拿到一个自有 fd：`nix::unistd::dup(2)` 复制 fd 2；若 dup 失败则打开
/// `/dev/stderr`（同样是新 fd）。**绝不**直接对 fd 2 调 `from_raw_fd`——那会接管
/// 原始 stderr，`File` drop 时把 fd 2 一起关掉。
fn open_sink(path: &str) -> io::Result<std::fs::File> {
    match OpenOptions::new().create(true).append(true).open(path) {
        Ok(f) => Ok(f),
        Err(e) => {
            eprintln!("警告: 无法打开日志文件 {}: {}，回退到 stderr", path, e);
            if let Ok(fd) = nix::unistd::dup(2) {
                // SAFETY: fd 来自 nix::unistd::dup(2)，是有效的、自有的文件描述符。
                return Ok(unsafe {
                    <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd)
                });
            }
            OpenOptions::new().write(true).open("/dev/stderr")
        }
    }
}

/// 初始化全局 logger
///
/// 创建原子写入的 JSON Lines drain，直接同步写入日志文件。
/// 应在程序启动时调用一次。如果在 fork 后调用，会重新创建文件句柄。
///
/// # Arguments
/// - `log_file_override`: 可选的日志路径覆盖（来自配置 `log_file` 字段）。
///   为 `None` 或空字符串时使用默认路径 `/var/log/firewall-daemon.log`。
pub fn init_logger(log_file_override: Option<&str>) -> Logger {
    let log_path = match log_file_override {
        Some(p) if !p.is_empty() => p,
        _ => DEFAULT_LOG_FILE_PATH,
    };

    // 文件与 stderr 副本都打不开时，退化为丢弃（不 panic，不接管 fd 2）
    let logger = match open_sink(log_path) {
        Ok(file) => Logger::root(
            slog::Fuse(AtomicFileDrain {
                file: std::sync::Mutex::new(file),
            }),
            slog::o!("version" => env!("CARGO_PKG_VERSION")),
        ),
        Err(e) => {
            eprintln!("警告: 日志无处可写（{}），后续日志将被丢弃", e);
            Logger::root(
                slog::Discard,
                slog::o!("version" => env!("CARGO_PKG_VERSION")),
            )
        }
    };

    let _guard = slog_scope::set_global_logger(logger.clone());
    std::mem::forget(_guard);

    {
        let mut global_logger = GLOBAL_LOGGER.lock();
        *global_logger = Some(logger.clone());
    }

    logger
}

/// 获取全局 logger 实例
///
/// 如果 logger 未初始化，返回一个静默 logger（丢弃所有日志）。
///
/// # 性能优化
///
/// 使用 thread-local 缓存避免每次调用都获取全局 Mutex 锁。
pub fn get() -> Logger {
    use std::cell::RefCell;

    thread_local! {
        static CACHED_LOGGER: RefCell<Option<Logger>> = RefCell::new(None);
    }

    CACHED_LOGGER.with(|cache| {
        let mut cache = cache.borrow_mut();
        if cache.is_none() {
            *cache = GLOBAL_LOGGER
                .lock()
                .clone()
                .or_else(|| Some(Logger::root(slog::Discard, slog::o!())));
        }
        cache.as_ref().unwrap().clone()
    })
}

pub use slog::{debug, error, info, warn};

#[macro_export]
macro_rules! log_throttled {
    ($level:expr, $logger:expr, $msg:expr, $interval:expr, $($args:tt)*) => {{
        use $crate::logger::LogThrottler;
        use std::sync::{Mutex, OnceLock};

        static THROTTLER: OnceLock<Mutex<LogThrottler>> = OnceLock::new();

        let throttler = THROTTLER.get_or_init(|| Mutex::new(LogThrottler::new($interval)));
        if throttler.lock().unwrap().can_log() {
            slog::log!($logger, $level, $msg, $($args)*);
        }
    }};
}

#[macro_export]
macro_rules! info_throttled {
    ($logger:expr, $msg:expr, $interval:expr, $($args:tt)*) => {
        log_throttled!(slog::Level::Info, $logger, $msg, $interval, $($args)*)
    };
}

#[macro_export]
macro_rules! warn_throttled {
    ($logger:expr, $msg:expr, $interval:expr, $($args:tt)*) => {
        log_throttled!(slog::Level::Warning, $logger, $msg, $interval, $($args)*)
    };
}

#[macro_export]
macro_rules! error_throttled {
    ($logger:expr, $msg:expr, $interval:expr, $($args:tt)*) => {
        log_throttled!(slog::Level::Error, $logger, $msg, $interval, $($args)*)
    };
}

#[macro_export]
macro_rules! debug_throttled {
    ($logger:expr, $msg:expr, $interval:expr, $($args:tt)*) => {
        log_throttled!(slog::Level::Debug, $logger, $msg, $interval, $($args)*)
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 编码结果必须是完整一行：合法 JSON、以单个换行结尾、正文内无换行。
    #[test]
    fn encode_json_line_is_single_valid_line() {
        let pairs = vec![
            ("ts".to_owned(), serde_json::json!("2026-01-01T00:00:00Z")),
            ("level".to_owned(), serde_json::json!("INFO")),
            ("msg".to_owned(), serde_json::json!("含\n换行的消息")),
        ];
        let line = encode_json_line(&pairs).expect("编码失败");

        assert_eq!(*line.last().unwrap(), b'\n', "必须以换行结尾");
        assert_eq!(
            line.iter().filter(|&&b| b == b'\n').count(),
            1,
            "正文换行必须被转义，整行只有一个结尾换行"
        );

        let text = std::str::from_utf8(&line).expect("必须是 UTF-8");
        let parsed: serde_json::Value =
            serde_json::from_str(text.trim_end()).expect("必须是合法 JSON");
        assert_eq!(parsed["msg"], "含\n换行的消息");
    }

    /// 字段顺序按插入顺序保留（不是字典序）。
    #[test]
    fn encode_json_line_preserves_insertion_order() {
        let pairs = vec![
            ("ts".to_owned(), serde_json::json!("T")),
            ("level".to_owned(), serde_json::json!("INFO")),
            ("msg".to_owned(), serde_json::json!("m")),
            ("version".to_owned(), serde_json::json!("2.2.0")),
        ];
        let line = encode_json_line(&pairs).unwrap();
        let text = String::from_utf8(line).unwrap();
        assert!(
            text.starts_with(r#"{"ts":"T","level":"INFO","msg":"m","version":"2.2.0"}"#),
            "顺序应为插入序，实际: {text}"
        );
    }

    /// `ts` 必须是 RFC3339 且以 `Z` 结尾（与旧 date-time 形态兼容）。
    #[test]
    fn timestamp_is_rfc3339_utc() {
        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        assert!(ts.ends_with('Z'), "ts 应以 Z 结尾: {ts}");
        assert!(
            chrono::DateTime::parse_from_rfc3339(&ts).is_ok(),
            "ts 应可被 RFC3339 解析: {ts}"
        );
    }

    // ── 多进程原子性 ──
    //
    // 缺陷的真实场景是「多写者」（两个 daemon 进程 / pytest 起的实例同时追加同一文件）。
    // 进程内 Mutex 对跨进程写者不生效，唯一保证是「整行（含换行）一次 write()」。
    // 本测试起 4 个子进程各写 N 行，断言读回后每行都是合法 JSON 且无空行。

    const CHILD_PATH_ENV: &str = "FIREWALL_LOGGER_TEST_CHILD_PATH";
    const CHILD_LINES_ENV: &str = "FIREWALL_LOGGER_TEST_CHILD_LINES";

    /// 子进程写入端；仅由 `multi_writer_produces_only_valid_lines` 显式拉起。
    #[test]
    #[ignore = "由 multi_writer_produces_only_valid_lines 拉起，不单独运行"]
    fn child_writer() {
        let Ok(path) = std::env::var(CHILD_PATH_ENV) else {
            return;
        };
        let lines: usize = std::env::var(CHILD_LINES_ENV)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .expect("子进程打开日志失败");
        let drain = AtomicFileDrain {
            file: std::sync::Mutex::new(file),
        };

        // 每条记录刻意包含逗号、引号、换行等易混淆字符
        for i in 0..lines {
            let pairs = vec![
                ("ts".to_owned(), serde_json::json!("2026-01-01T00:00:00Z")),
                ("level".to_owned(), serde_json::json!("INFO")),
                (
                    "msg".to_owned(),
                    serde_json::json!(format!(
                        "child={} line={} 含,逗\"引\n换行",
                        std::process::id(),
                        i
                    )),
                ),
            ];
            let line = encode_json_line(&pairs).expect("编码失败");
            drain.write_line(&line).expect("写入失败");
        }
    }

    #[test]
    fn multi_writer_produces_only_valid_lines() {
        let dir = std::env::temp_dir().join(format!("fw-logger-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("firewall-test.log");
        let _ = std::fs::remove_file(&log_path);

        const PROCS: usize = 4;
        const LINES: usize = 2000;

        let exe = std::env::current_exe().expect("取当前测试二进制路径失败");
        let children: Vec<_> = (0..PROCS)
            .map(|_| {
                std::process::Command::new(&exe)
                    .args([
                        "--exact",
                        "logger::tests::child_writer",
                        "--ignored",
                        "--nocapture",
                    ])
                    .env(CHILD_PATH_ENV, &log_path)
                    .env(CHILD_LINES_ENV, LINES.to_string())
                    .spawn()
                    .expect("拉起子进程失败")
            })
            .collect();

        for mut child in children {
            let status = child.wait().expect("等待子进程失败");
            assert!(status.success(), "子进程退出码非 0: {status}");
        }

        let content = std::fs::read_to_string(&log_path).expect("读回日志失败");
        // 尾随换行产生一个空片段，去掉它；任何**中间**空行都是缺陷
        let body = content.strip_suffix('\n').unwrap_or(&content);
        let lines: Vec<&str> = body.split('\n').collect();

        assert_eq!(
            lines.len(),
            PROCS * LINES,
            "行数不符（说明有行被并合或丢失）"
        );
        let mut bad = 0;
        for (i, line) in lines.iter().enumerate() {
            if serde_json::from_str::<serde_json::Value>(line).is_err() {
                bad += 1;
                if bad <= 3 {
                    eprintln!("非法行 #{i}: {line:?}");
                }
            }
        }
        assert_eq!(bad, 0, "存在 {bad} 行非法 JSON（多写者撕裂）");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
