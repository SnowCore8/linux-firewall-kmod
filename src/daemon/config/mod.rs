//! YAML 配置解析 + 路径安全 3 重检查 + 严格模式 key 白名单 + 失败回滚 + CLI 参数
//!
//! # 核心特性
//!
//! - **路径安全 3 重检查**:
//!   1. `..` 路径遍历
//!   2. `%2e` / `%2f` / `%5c` URL 编码绕过
//!   3. shell 元字符命令注入
//!
//!   故意不做白名单检查,与 C 版 `validate_and_normalize_path` 行为等价
//! - **严格模式 key 白名单**:`--strict` (默认) 时任何未知 key 直接 bail
//! - **失败回滚**:先快照所有可回滚字段,中途失败时整体恢复
//! - **CLI 双形式支持**:`-c FILE` / `--config=FILE` 两种参数风格都接受

// 模块声明
mod args;
mod file_loader;
mod parser;

// 公共导出
pub use args::parse_config_args;
pub use file_loader::{load_config_directory, parse_config_file};
pub use parser::{parse_config, validate_and_normalize_path};
