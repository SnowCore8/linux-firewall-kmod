//! 文件监控状态定义
//!
//! 包含 [`FileState`] 结构体和全局静态变量，用于跟踪被监控日志文件的状态。

use std::sync::atomic::AtomicI32;

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
    /// 是否为配置文件（非日志文件）
    pub is_config: bool,
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
            is_config: false,
        }
    }
}

// ============================================================================
// inotify 状态
// ============================================================================

/// inotify 状态聚合 — 将 `Inotify` 句柄和 raw fd 绑定为一个逻辑单元。
///
/// `raw_fd` 单独存储是因为 `monitor_loop` 的 `poll()` 需要 raw fd，
/// 但 `poll` 期间不能同时借出整个 `Inotify` 句柄。
pub struct InotifyState {
    /// inotify 句柄（watch 操作使用）
    pub fd: RwLock<Option<Inotify>>,
    /// inotify raw fd（poll 使用）
    pub raw_fd: AtomicI32,
}

impl Default for InotifyState {
    fn default() -> Self {
        Self::new()
    }
}

impl InotifyState {
    /// 构造空的 inotify 状态
    #[must_use]
    pub const fn new() -> Self {
        Self {
            fd: RwLock::new(None),
            raw_fd: AtomicI32::new(-1),
        }
    }
}

// ============================================================================
// 全局静态变量
// ============================================================================

/// 全局:所有被监控文件的 `FileState` 列表
pub static FILE_STATES: RwLock<Vec<FileState>> = RwLock::new(Vec::new());
/// 全局:inotify 状态（句柄 + raw fd）
pub static INOTIFY_STATE: InotifyState = InotifyState::new();
