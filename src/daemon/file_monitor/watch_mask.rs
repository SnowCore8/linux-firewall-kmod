//! 日志文件 inotify 监视掩码
//!
//! 监视的是**文件**而非目录：应使用 `MOVE_SELF` / `DELETE_SELF`。
//! `CREATE` / `DELETE` / `MOVED_FROM` / `MOVED_TO` 是目录项事件，
//! 对文件 watch 基本无效，轮转后还容易误判、盯死旧 inode。

use inotify::WatchMask;

/// 日志（或配置）文件 watch 掩码：内容变更 + 自身被移走/删除。
pub fn log_file_watch_mask() -> WatchMask {
    WatchMask::MODIFY
        | WatchMask::ATTRIB
        | WatchMask::CLOSE_WRITE
        | WatchMask::MOVE_SELF
        | WatchMask::DELETE_SELF
}
