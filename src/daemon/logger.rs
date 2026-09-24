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
//! logger::init_logger(None, 10, 10);
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

// ─── AtomicFileDrain：同步、逐行原子写入 + 按大小轮转 ───

/// `<base>.<n>` 形式的轮转片路径（`n` 越大越旧）。
fn rotated_path(base: &std::path::Path, n: u32) -> std::path::PathBuf {
    let mut s = base.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    std::path::PathBuf::from(s)
}

/// 受一把锁保护的写入状态：文件句柄 + 轮转所需的元数据。
///
/// 轮转（删最旧、依次改名、重开）必须与写入在同一把锁内完成，否则并发写者会在
/// 换名之后继续写旧 inode——新片缺记录、旧片混进新记录。
struct Sink {
    file: std::fs::File,
    path: std::path::PathBuf,
    /// 当前文件已有字节数（打开时用 `metadata().len()` 播种）
    written: u64,
    /// 单片字节上限。`0` = 不轮转（stderr 回退用）
    max_bytes: u64,
    /// 保留片数上限（含当前文件）。轮转时删最旧的一片
    max_files: u32,
}

impl Sink {
    /// 轮转一次：删最旧片 → 依次改名 → 当前片改名 `.1` → 开新文件。
    ///
    /// 片名范围 `.1`（最新）… `.max_files-1`（最旧）。`max_files == 1` 表示只保留
    /// 当前片，此时没有可保留的历史，直接截断。
    fn rotate(&mut self) -> io::Result<()> {
        if self.max_files <= 1 {
            self.file.set_len(0)?;
            self.written = 0;
            return Ok(());
        }
        let _ = std::fs::remove_file(rotated_path(&self.path, self.max_files - 1));
        for i in (1..self.max_files - 1).rev() {
            let from = rotated_path(&self.path, i);
            if from.exists() {
                std::fs::rename(&from, rotated_path(&self.path, i + 1))?;
            }
        }
        std::fs::rename(&self.path, rotated_path(&self.path, 1))?;
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

/// 同步 JSON Lines drain：按大小轮转 + 逐行原子写入。
///
/// 每条日志：
/// 1. 用 `ValueSerializer` 收集 KV 对为 `(键, serde_json::Value)` 列表（保持插入顺序）
/// 2. 手工编码 JSON 到单个 `Vec<u8>`（含行尾 `\n`）
/// 3. 在进程内 `Mutex<Sink>` 保护下单次 `write_all` 写出；本次若会超出单片上限，
///    先在锁内完成轮转
///
/// 不使用 `slog_async`——异步通道（`chan_size` 128、非阻塞）在通道满或进程退出时
/// 整条丢弃记录。
struct AtomicFileDrain {
    sink: std::sync::Mutex<Sink>,
}

impl AtomicFileDrain {
    /// 打开（或创建）日志文件，并用其当前大小播种轮转计数。
    ///
    /// 播种很重要：进程重启后接手一个已超限的旧文件时，下一次写入即触发轮转，
    /// 不必等它再从 0 长到上限。
    fn new(path: &str, max_size_mb: u32, max_files: u32) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            sink: std::sync::Mutex::new(Sink {
                file,
                path: std::path::PathBuf::from(path),
                written,
                max_bytes: (max_size_mb as u64).saturating_mul(1024 * 1024),
                max_files: max_files.max(1),
            }),
        })
    }

    /// 回退 sink：写 stderr 的**独立副本**，**不轮转**。
    ///
    /// 必须拿到自有 fd：`dup(2)` 复制 fd 2，失败则打开 `/dev/stderr`。**绝不**直接对
    /// fd 2 调 `from_raw_fd`——那会接管原始 stderr，`File` drop 时把 fd 2 一起关掉。
    fn stderr() -> io::Result<Self> {
        let file = match nix::unistd::dup(2) {
            // SAFETY: fd 由 nix::unistd::dup(2) 返回，是有效的、自有的文件描述符；
            // 所有权在此转移给 File。
            Ok(fd) => unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(fd) },
            Err(_) => OpenOptions::new().write(true).open("/dev/stderr")?,
        };
        Ok(Self {
            sink: std::sync::Mutex::new(Sink {
                file,
                path: std::path::PathBuf::new(),
                written: 0,
                max_bytes: 0,
                max_files: 1,
            }),
        })
    }

    /// 单次 `write_all` 写出整行（换行已并入 `line` 尾部）。
    ///
    /// 必须是一次 `write()`：`O_APPEND` 打开时单次写对常规文件按行原子，
    /// 拆成两次会让并发写者的记录插进中间。
    ///
    /// 轮转判定在锁内、本行写入之前。`written > 0` 保证单条超长记录不会被反复轮转
    /// （始终允许写出至少一条），也让刚打开的空文件不会立刻轮转。
    fn write_line(&self, line: &[u8]) -> io::Result<()> {
        let mut sink = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        if sink.max_bytes > 0
            && sink.written > 0
            && sink.written + line.len() as u64 > sink.max_bytes
        {
            sink.rotate()?;
        }
        sink.file.write_all(line)?;
        sink.written += line.len() as u64;
        Ok(())
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

/// 初始化全局 logger
///
/// 创建「按大小轮转 + 逐行原子写入」的 JSON Lines drain。应在程序启动时调用一次。
///
/// # Arguments
/// - `log_file_override`: 日志路径（来自配置 `log_file`）。`None` 或空串 → 默认路径
/// - `log_max_size_mb`: 单片大小上限 (MB)。`0` = 不轮转
/// - `log_max_files`: 保留片数上限（**含当前文件**）。轮转时删最旧的一片
pub fn init_logger(
    log_file_override: Option<&str>,
    log_max_size_mb: u32,
    log_max_files: u32,
) -> Logger {
    let log_path = match log_file_override {
        Some(p) if !p.is_empty() => p,
        _ => DEFAULT_LOG_FILE_PATH,
    };

    // 打开日志文件；失败回退到 stderr（不轮转）；连 stderr 都拿不到则丢弃
    let drain = match AtomicFileDrain::new(log_path, log_max_size_mb, log_max_files) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("警告: 无法打开日志文件 {}: {}，回退到 stderr", log_path, e);
            match AtomicFileDrain::stderr() {
                Ok(d) => d,
                Err(e2) => {
                    eprintln!("警告: 日志无处可写（{}），后续日志将被丢弃", e2);
                    return Logger::root(
                        slog::Discard,
                        slog::o!("version" => env!("CARGO_PKG_VERSION")),
                    );
                }
            }
        }
    };

    let logger = Logger::root(
        slog::Fuse(drain),
        slog::o!("version" => env!("CARGO_PKG_VERSION")),
    );

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
        if let Some(logger) = cache.as_ref() {
            return logger.clone();
        }
        // 只在全局 logger 已装配时写入缓存。装配前调用（主线程在 `init_logger`
        // 之前就会记配置加载日志）若把 Discard 兜底缓存下来，该线程此后即使
        // `init_logger` 已执行也永远读缓存里的静默实例——主线程的全部启动日志
        // （含「已向 <url> 探测出口 IP」这类必须可见的声明）都会被静默丢弃。
        match GLOBAL_LOGGER.lock().clone() {
            Some(logger) => {
                *cache = Some(logger.clone());
                logger
            }
            None => Logger::root(slog::Discard, slog::o!()),
        }
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

    // ── 按大小轮转 ──

    /// 每个测试独立的临时目录（同一进程内测试并行跑，不能用 pid 单键）。
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("fw-logger-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// `<base>` 与 `<base>.<n>` 的合集，按名字排序（`base.log` < `base.log.1` < ...）。
    fn rotation_files(path: &std::path::Path) -> Vec<std::path::PathBuf> {
        let dir = path.parent().unwrap();
        let base = path.file_name().unwrap().to_string_lossy().to_string();
        let mut v: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.file_name()
                    .map(|n| n.to_string_lossy().starts_with(&base))
                    .unwrap_or(false)
            })
            .collect();
        v.sort();
        v
    }

    /// 建一个字节级上限的 drain（生产用 MB，测试要小片才能快速触发轮转）。
    fn drain_with_max_bytes(path: &str, max_bytes: u64, max_files: u32) -> AtomicFileDrain {
        let d = AtomicFileDrain::new(path, 0, max_files).unwrap();
        d.sink.lock().unwrap().max_bytes = max_bytes;
        d
    }

    #[test]
    fn rotation_keeps_at_most_max_files_and_drops_oldest() {
        let dir = temp_dir("rot-count");
        let path = dir.join("fw.log");
        let max_files = 4u32;
        let max_bytes = 200u64;
        let drain = drain_with_max_bytes(path.to_str().unwrap(), max_bytes, max_files);

        // 每行 ~50 字节 → 每片约 4 行；写 60 行足以轮转十余次
        for i in 0..60u32 {
            let line = format!("{{\"n\":{i:04},\"pad\":\"{}\"}}\n", "x".repeat(30));
            drain.write_line(line.as_bytes()).unwrap();
        }

        let files = rotation_files(&path);
        assert_eq!(
            files.len() as u32,
            max_files,
            "应恰好保留 {max_files} 片，实际: {files:?}"
        );

        // 当前片不超过上限（末行可能略微超过，但不应再装下一行）
        let cur_len = std::fs::metadata(&path).unwrap().len();
        assert!(
            cur_len <= max_bytes,
            "当前片 {cur_len} 字节超过上限 {max_bytes}"
        );

        // 最旧的记录（第 0 行）应已被删除；最新的记录应存在
        let all: String = files
            .iter()
            .map(|f| std::fs::read_to_string(f).unwrap())
            .collect();
        assert!(!all.contains("\"n\":0000"), "最旧片应被删除");
        assert!(all.contains("\"n\":0059"), "最新记录应存在");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rotation_renames_current_to_dot_1_in_order() {
        let dir = temp_dir("rot-order");
        let path = dir.join("fw.log");
        let drain = drain_with_max_bytes(path.to_str().unwrap(), 120, 3);

        // 每行 ~40 字节 → 每片 3 行
        for i in 0..9u32 {
            let line = format!("{{\"n\":{i:04},\"pad\":\"{}\"}}\n", "y".repeat(20));
            drain.write_line(line.as_bytes()).unwrap();
        }

        // `.1` 比 `.2` 新：`.1` 的首行编号应大于 `.2` 的
        let dot1 = std::fs::read_to_string(rotated_path(&path, 1)).unwrap();
        let dot2 = std::fs::read_to_string(rotated_path(&path, 2)).unwrap();
        let first_in = |s: &str| -> u32 {
            s.split("\"n\":")
                .nth(1)
                .unwrap()
                .chars()
                .take(4)
                .collect::<String>()
                .parse()
                .unwrap()
        };
        assert!(
            first_in(&dot1) > first_in(&dot2),
            "`.1` 应比 `.2` 新（.1={}, .2={}）",
            first_in(&dot1),
            first_in(&dot2)
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_size_zero_disables_rotation() {
        let dir = temp_dir("rot-off");
        let path = dir.join("fw.log");
        let drain = AtomicFileDrain::new(path.to_str().unwrap(), 0, 10).unwrap();

        for i in 0..500u32 {
            drain
                .write_line(format!("{{\"n\":{i}}}\n").as_bytes())
                .unwrap();
        }

        assert_eq!(rotation_files(&path).len(), 1, "关闭轮转时不应产生分片");
        assert!(
            std::fs::metadata(&path).unwrap().len() > 0,
            "关闭轮转时内容应全部留在同一文件"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn max_files_one_truncates_current() {
        let dir = temp_dir("rot-one");
        let path = dir.join("fw.log");
        let max_bytes = 120u64;
        let drain = drain_with_max_bytes(path.to_str().unwrap(), max_bytes, 1);

        for i in 0..30u32 {
            drain
                .write_line(format!("{{\"n\":{i:04},\"pad\":\"{}\"}}\n", "z".repeat(20)).as_bytes())
                .unwrap();
        }

        let files = rotation_files(&path);
        assert_eq!(files.len(), 1, "max_files=1 只应有当前片");
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(len <= max_bytes, "截断后不应超过上限，实际 {len}");
        // 只保留最新内容
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\"n\":0029"), "应保留最新记录");
        assert!(!content.contains("\"n\":0000"), "最旧记录应被丢弃");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 接手一个已超限的旧文件时，下一次写入应先轮转（不靠 `written` 从 0 重新计）。
    #[test]
    fn oversized_existing_file_rotates_on_first_write() {
        let dir = temp_dir("rot-seed");
        let path = dir.join("fw.log");
        std::fs::write(&path, "x".repeat(5000)).unwrap();

        let drain = drain_with_max_bytes(path.to_str().unwrap(), 100, 3);
        drain.write_line(b"{\"first\":true}\n").unwrap();

        // 5000 字节的旧内容应被挪到 `.1`
        let dot1 = std::fs::read_to_string(rotated_path(&path, 1)).unwrap();
        assert_eq!(dot1.len(), 5000, "旧内容应完整挪到 `.1`");
        let cur = std::fs::read_to_string(&path).unwrap();
        assert!(cur.contains("\"first\":true"), "新行应写进新片");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 轮转后每个分片仍是完整合法 JSON，且保留的记录编号**连续**（只按整片淘汰，
    /// 不丢行、不重复）。
    #[test]
    fn rotated_slices_remain_valid_jsonl() {
        let dir = temp_dir("rot-valid");
        let path = dir.join("fw.log");
        let max_files = 5u32;
        let drain = drain_with_max_bytes(path.to_str().unwrap(), 180, max_files);

        let total = 80u32;
        for i in 0..total {
            let mut line = serde_json::json!({ "n": i, "msg": "含,逗\"引\n换行" }).to_string();
            line.push('\n');
            drain.write_line(line.as_bytes()).unwrap();
        }

        let files = rotation_files(&path);
        assert!(
            files.len() as u32 <= max_files,
            "分片数 {} 超过上限 {max_files}",
            files.len()
        );

        let mut seen = Vec::new();
        for f in &files {
            let content = std::fs::read_to_string(f).unwrap();
            for line in content.strip_suffix('\n').unwrap_or(&content).split('\n') {
                let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
                    panic!("{} 中出现非法 JSON 行: {line:?} ({e})", f.display())
                });
                seen.push(v["n"].as_u64().unwrap() as u32);
            }
        }

        seen.sort_unstable();
        let expect_first = total - seen.len() as u32;
        let expected: Vec<u32> = (expect_first..total).collect();
        assert_eq!(
            seen, expected,
            "保留的编号应是连续的后缀（整片淘汰，不丢行/不重复）"
        );
        assert!(seen.contains(&(total - 1)), "最新记录应存在");

        let _ = std::fs::remove_dir_all(&dir);
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

        // 关闭轮转（max_size_mb=0）：本测试只验证多写者下的行原子性
        let drain = AtomicFileDrain::new(&path, 0, 10).expect("子进程打开日志失败");

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

    // ── 装配前的 get() 不得毒化该线程的日志 ──

    const EARLY_GET_PATH_ENV: &str = "FIREWALL_LOGGER_TEST_EARLY_GET_PATH";

    /// 子进程：**先**调 `get()`（装配前），**再** `init_logger`，然后记一行。
    ///
    /// 复现主线程的真实时序：`main` 在 `init_logger` 之前就会为「配置文件加载成功」
    /// 这类事件取 logger，若那一刻的 Discard 兜底被 thread-local 缓存下来，此后该
    /// 线程的全部日志（含启动声明）都进不了日志文件。
    #[test]
    #[ignore = "由 early_get_does_not_poison_the_thread 拉起，不单独运行"]
    fn child_early_get_then_init() {
        let Ok(path) = std::env::var(EARLY_GET_PATH_ENV) else {
            return;
        };

        // 装配前取一次 logger（主线程在解析配置时就是这么做的）。
        let before = get();
        slog::info!(before, "装配前的日志（预期丢弃）");

        let _log = init_logger(Some(&path), 0, 10);

        // 装配后同一线程再取：必须拿到真实 logger 而不是缓存里的 Discard。
        let after = get();
        slog::info!(after, "装配后的日志（预期落盘）");
    }

    /// 装配前调用过 `get()` 的线程，在 `init_logger` 之后必须能正常落盘。
    #[test]
    fn early_get_does_not_poison_the_thread() {
        let dir = temp_dir("early-get");
        let log_path = dir.join("firewall-early-get.log");

        let exe = std::env::current_exe().expect("取当前测试二进制路径失败");
        let status = std::process::Command::new(&exe)
            .args([
                "--exact",
                "logger::tests::child_early_get_then_init",
                "--ignored",
                "--nocapture",
            ])
            .env(EARLY_GET_PATH_ENV, &log_path)
            .status()
            .expect("拉起子进程失败");
        assert!(status.success(), "子进程退出码非 0: {status}");

        let content = std::fs::read_to_string(&log_path).expect("读回日志失败");
        assert!(
            content.contains("装配后的日志（预期落盘）"),
            "装配后同一线程的日志被丢弃（thread-local 缓存了 Discard）；实际内容: {content:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
