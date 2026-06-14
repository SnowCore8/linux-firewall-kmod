//! 文件监控状态定义
//!
//! 包含 [`FileState`] 结构体和全局静态变量，用于跟踪被监控日志文件的状态。

use std::sync::atomic::{AtomicBool, AtomicI32};

use inotify::{Inotify, WatchDescriptor};
use parking_lot::RwLock;

// ============================================================================
// 文件状态
// ============================================================================

/// 单个被监控日志文件的运行时状态。`FILE_STATES` 索引 = `FileState.wd` 在
/// inotify 事件中的对应位置。
#[derive(Debug)]
pub struct FileState {
    /// 日志文件路径
    pub path: String,
    /// 下次 read 的起始字节偏移
    pub offset: u64,
    /// 文件 inode (用于检测轮转)
    pub inode: u64,
    /// inotify watch descriptor
    pub wd: Option<WatchDescriptor>,
    /// 关联的 jail 在 `Config.jails` 中的索引
    pub jail_idx: usize,
    /// 文件被检测为符号链接,标记后跳过
    pub symlink_detected: bool,
}

impl Default for FileState {
    fn default() -> Self {
        Self::new()
    }
}

impl FileState {
    /// 构造空 `FileState`,所有字段为默认值
    #[must_use]
    pub fn new() -> Self {
        Self {
            path: String::new(),
            offset: 0,
            inode: 0,
            wd: None,
            jail_idx: 0,
            symlink_detected: false,
        }
    }
}

// ============================================================================
// 全局静态变量
// ============================================================================

/// 全局:所有被监控文件的 `FileState` 列表
pub static FILE_STATES: RwLock<Vec<FileState>> = RwLock::new(Vec::new());
/// 全局:inotify 句柄。`reload_configuration` 期间会替换
pub static INOTIFY_FD: RwLock<Option<Inotify>> = RwLock::new(None);
/// 全局:inotify raw fd,单独存以便 [`monitor_loop`] 的 `poll` 调用避开借出整个 `Inotify` 句柄
pub static INOTIFY_RAW_FD: AtomicI32 = AtomicI32::new(-1);
/// 全局:监控循环运行标志 (备用,实际由 `main()` 持有的 `Arc<AtomicBool>` 控制)
pub static MONITOR_RUNNING: AtomicBool = AtomicBool::new(true);
