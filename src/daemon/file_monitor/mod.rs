//! inotify 监控日志文件 → 行分割 → 主循环 (poll + SIGHUP 重载)
//!
//! # 模块结构
//!
//! 1. **文件状态**：`FileState` 跟踪每个监控文件的 path/offset/inode/watch descriptor
//! 2. **inotify 设置**：`setup_inotify` 给所有 enabled jail 的日志文件加 watch
//! 3. **新行处理**：`process_new_lines` 读自上次 offset 的新内容
//! 4. **主循环**：`monitor_loop` 调 `poll` 等待 inotify 事件 / SIGHUP / 周期维护
//!
//! 行处理逻辑 → [`crate::line_processor`]
//! 日志轮转处理 → [`crate::log_rotation`]
//! 配置热重载 → [`crate::config_reloader`]
//!
//! # 关键不变量
//!
//! - 每个日志文件 inode 在 `setup_inotify` 时记录,变化时认为是轮转
//! - 单行硬上限 8KB,异常超长行会跳过 (避免 OOM)
//! - `O_NOFOLLOW` 防止日志文件被替换为符号链接后 readlink 到攻击者文件

pub mod inotify_setup;
pub mod monitor_loop;
pub mod periodic_tasks;
pub mod processor;
pub mod state;

pub use inotify_setup::setup_inotify;
pub use monitor_loop::monitor_loop;
pub use periodic_tasks::{check_and_handle_ddos, perform_data_cleanup, write_stats_snapshot};
pub use processor::process_new_lines;
pub use state::{FileState, InotifyState, FILE_STATES, INOTIFY_STATE};

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_state_new() {
        let state = FileState::new();
        assert!(state.path.is_empty());
        assert_eq!(state.offset, 0);
        assert_eq!(state.inode, 0);
        assert!(state.wd.is_none());
        assert!(!state.symlink_detected);
    }
}
