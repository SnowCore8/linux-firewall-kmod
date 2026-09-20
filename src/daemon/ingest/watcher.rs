//! inotify 监视：fd 的唯一所有权与事件读取。
//!
//! 本模块是 inotify fd 的**唯一所有者**：fd 不借出、不被 `Drop` 之外的路径关闭，
//! 调用方只拿到「已脱离 fd 的事件」。旧实现把 `Inotify` 句柄和 `raw_fd` 拆成两份
//! 全局状态（`INOTIFY_STATE.fd` + `INOTIFY_STATE.raw_fd`），`poll` 期间不能借出句柄，
//! 于是「同一份状态两处记账」成了必须靠约定维持的隐式契约。这里把 fd、读缓冲与
//! `poll` 收敛进一个类型。

use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;
use std::time::Duration;

use inotify::{EventMask, Inotify, WatchDescriptor, WatchMask};

/// inotify 事件读缓冲大小。
///
/// 内核要求缓冲至少容纳一个 `struct inotify_event` 加路径名；4 KiB 足以覆盖典型
/// 日志目录的一批事件，且读满后下一轮 `read_events` 会继续取走剩余事件。
const EVENT_BUFFER_BYTES: usize = 4096;

/// 日志（或配置）文件 watch 掩码：内容变更 + 自身被移走/删除。
///
/// 监视的是**文件**而非目录：`CREATE` / `DELETE` / `MOVED_FROM` / `MOVED_TO` 是
/// 目录项事件，对文件 watch 基本无效，轮转后还容易误判、盯死旧 inode。
#[must_use]
pub fn log_file_watch_mask() -> WatchMask {
    WatchMask::MODIFY
        | WatchMask::ATTRIB
        | WatchMask::CLOSE_WRITE
        | WatchMask::MOVE_SELF
        | WatchMask::DELETE_SELF
}

/// 一次唤醒里读出的原始事件，已脱离 fd（不借用读缓冲、不借用句柄）。
#[derive(Debug, Clone)]
pub struct WatchEvent {
    /// 事件来源的 watch 描述符。
    pub wd: WatchDescriptor,
    /// 事件掩码。
    pub mask: EventMask,
}

impl WatchEvent {
    /// 内容是否可能变多（需要读取新增字节）。
    #[must_use]
    pub fn is_content_change(&self) -> bool {
        self.mask
            .intersects(EventMask::MODIFY | EventMask::CLOSE_WRITE | EventMask::ATTRIB)
    }

    /// 文件自身是否被移走或删除（轮转信号：持有的 fd 已指向旧 inode）。
    #[must_use]
    pub fn is_self_gone(&self) -> bool {
        self.mask
            .intersects(EventMask::MOVE_SELF | EventMask::DELETE_SELF)
    }
}

/// inotify 实例的唯一所有者：fd、读缓冲、`poll` 都收在这里。
#[derive(Debug)]
pub struct Watcher {
    /// 内核 inotify 实例。`inotify::init` 以 `IN_NONBLOCK` 建立，
    /// 故 `read_events` 永不阻塞——阻塞等待由 [`Watcher::wait_readable`] 负责。
    inotify: Inotify,
    /// 事件读缓冲，跨轮复用，避免每次唤醒重新分配。
    buffer: Vec<u8>,
}

impl Watcher {
    /// 新建 inotify 实例。
    ///
    /// # Errors
    /// `inotify_init1` 失败（fd 耗尽等）时返回底层错误。
    pub fn new() -> io::Result<Self> {
        Ok(Self {
            inotify: Inotify::init()?,
            buffer: vec![0u8; EVENT_BUFFER_BYTES],
        })
    }

    /// 为 `path` 添加 watch，返回内核分配的 watch 描述符。
    ///
    /// # Errors
    /// 路径不存在或权限不足时返回底层错误；调用方决定是「跳过并重试」还是致命。
    pub fn add(&mut self, path: &Path, mask: WatchMask) -> io::Result<WatchDescriptor> {
        self.inotify.watches().add(path, mask)
    }

    /// 摘除一个 watch。
    ///
    /// # Errors
    /// wd 已失效（文件已被删除）时返回底层错误；调用方通常只记日志。
    pub fn remove(&mut self, wd: WatchDescriptor) -> io::Result<()> {
        self.inotify.watches().remove(wd)
    }

    /// 底层 fd，供调用方与其它 fd 一起 `poll`（例如把信号 fd 并入同一集合）。
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.inotify.as_raw_fd()
    }

    /// 非阻塞读取本轮可用事件；无事件时返回空 `Vec`。
    ///
    /// # Errors
    /// 读缓冲过小（`InvalidInput`）或 fd 已损坏时返回底层错误。
    pub fn read_events(&mut self) -> io::Result<Vec<WatchEvent>> {
        match self.inotify.read_events(&mut self.buffer) {
            Ok(events) => Ok(events
                .map(|e| WatchEvent {
                    wd: e.wd,
                    mask: e.mask,
                })
                .collect()),
            // 非阻塞 fd 上没有事件：不是错误，只是本轮无变化。
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(Vec::new()),
            Err(e) => Err(e),
        }
    }

    /// 等待 fd 可读，最多等 `timeout`；返回 `true` 表示有事件可读。
    ///
    /// `EINTR` 按「本轮无事件」处理并返回 `false`：本实现不依赖信号打断 `poll`
    /// 来推进状态（信号由组合根的 `signalfd` 统一读走），被打断只意味着该重新等。
    ///
    /// # Errors
    /// `poll` 本身失败（fd 无效等）时返回底层错误。
    pub fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        // 毫秒上限：`poll` 的 timeout 是 i32 毫秒；Duration 转毫秒后钳到 i32 上界，
        // 避免大 timeout 溢出后变成负数（负数 = 无限等待）。
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        let mut fds = libc::pollfd {
            fd: self.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `fds` 是栈上的单个 `pollfd`，`nfds = 1` 与数组长度严格一致；
        // fd 来自 `inotify::init` 且由本类型独占持有，在调用期间保持有效。
        let result = unsafe { libc::poll(&mut fds, 1, millis) };
        if result < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(err);
        }
        Ok(result > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_readable_times_out_without_events() {
        let w = Watcher::new().expect("inotify 初始化失败");
        let start = std::time::Instant::now();
        let ready = w.wait_readable(Duration::from_millis(30)).expect("poll 失败");
        assert!(!ready, "无事件时不应报告可读");
        // 必须真的等过一轮超时，而不是立即返回（否则会变成忙轮询）。
        assert!(
            start.elapsed() >= Duration::from_millis(20),
            "poll 应立即阻塞到超时，实际 {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn watch_a_temp_file_reports_modify_on_write() {
        let dir = tempdir();
        let path = dir.join("a.log");
        std::fs::write(&path, b"line\n").expect("写测试文件失败");

        let mut w = Watcher::new().expect("inotify 初始化失败");
        w.add(&path, log_file_watch_mask())
            .expect("添加 watch 失败");

        // 追加内容，触发 MODIFY / CLOSE_WRITE。
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("追加打开失败");
            f.write_all(b"more\n").expect("追加失败");
            f.sync_all().expect("sync 失败");
        }

        // 事件驱动等待：轮询真实可读状态，不用固定 sleep 猜时间。
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut masks = Vec::new();
        while std::time::Instant::now() < deadline {
            if w.wait_readable(Duration::from_millis(50)).unwrap_or(false) {
                masks.extend(w.read_events().expect("读事件失败").into_iter().map(|e| e.mask));
                if masks.iter().any(|m| m.intersects(EventMask::MODIFY)) {
                    break;
                }
            }
        }
        assert!(
            masks.iter().any(|m| m.intersects(EventMask::MODIFY)),
            "追加写入后应收到 MODIFY，实际 {:?}",
            masks
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 在系统临时目录里建唯一子目录，避免污染仓库与其它测试。
    fn tempdir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-ingest-test-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }
}
