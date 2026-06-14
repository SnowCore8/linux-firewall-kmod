//! Jail 管理模块
//!
//! # 核心职责
//!
//! - 服务名智能匹配 + 默认参数推断
//! - 正则表达式安全验证 + 编译
//! - Jail CRUD 操作 + 配置克隆/验证
//! - 失败条目迁移

// 模块声明
mod config_ops;
mod operations;
mod regex;
mod service_match;

// 公共导出
pub use config_ops::{config_clone, config_validate, free_config_partial, migrate_failed_entries};
pub use operations::{
    cleanup_all_jails, clone_jail, destroy_jail, find_or_create_jail, free_log_patterns,
    init_log_patterns,
};
pub use regex::{compile_jail_regex, free_jail_regex_full};
pub use service_match::{apply_smart_defaults_single, apply_smart_defaults_to_all};

// 内部导出 (跨模块调用)
