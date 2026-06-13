//! 封禁/解封操作 + 安全 procfs 写入 + bans fd 缓存
//!
//! # 核心职责
//!
//! - 与内核模块 `/proc/firewall/bans` procfs 接口通信 (写命令)
//! - IP 合法性校验 (拒绝 loopback/multicast/link-local 等)
//! - 缓存 bans fd (R9-9 优化) 避免每次封禁都 `open`/`close`
//! - Permanent/UnbanPerm 同步写 `SQLite` 永久黑名单
//! # 子模块划分
//!
//! - [`procfs`][]: 安全 procfs 文件操作 + fd 缓存
//! - [`ip_validation`][]: IP 合法性校验
//! - [`operations`][]: 封禁/解封操作
//!
//! # procfs 命令格式
//!
//! | 操作 | 命令格式 | 示例 |
//! |------|----------|------|
//! | 临时封禁 | `<ip>\n` | `1.2.3.4\n` |
//! | 永久封禁 | `<ip> 0\n` | `1.2.3.4 0\n` |
//! | 解封 (Temp/Perm 共用) | `unban <ip>\n` | `unban 1.2.3.4\n` |
//!
//! # 安全模型
//!
//! 三道防线防止恶意输入击穿到 procfs:
//! 1. **路径白名单**:只能写 `/proc/firewall/` 下的路径
//! 2. **字符白名单**:文件名仅允许 `[A-Za-z0-9/_.-]`
//! 3. **fd 重定向检查**:`/proc/self/fd/N` readlink 必须解析到 `/proc/firewall/`
//!
//! 即使攻击者通过环境变量 / 配置文件注入 `../../etc/passwd`,也会在第 1 道
//! 关被拒。

// 模块声明

mod ip_validation;
mod operations;
mod procfs;

// 公共导出
pub use ip_validation::{validate_ip, validate_ipv4, ValidatedIp};
pub use operations::{
    ban_ip, ban_ip_permanent, cleanup_expired_bans, execute_ban_action, unban_ip,
    unban_permanent_ip,
};
pub use procfs::{close_cached_bans_fd, secure_procfs_write};

// ============================================================================
// 常量
// ============================================================================

/// 内核模块 procfs 根目录。所有 `secure_procfs_write` 只能在此目录下写入。
pub const PROCFS_DIR: &str = "/proc/firewall";

/// 封禁命令的 procfs 文件。命令格式见模块级文档。
pub const BANS_PATH: &str = "/proc/firewall/bans";

// ============================================================================
// 封禁/解封操作类型
// ============================================================================

/// 封禁/解封操作枚举。所有动作经 [`execute_ban_action`] 统一分发。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanAction {
    /// 临时封禁 (写 `<ip>\n`,内核按 `ban_time` 自动解封)
    Temp,
    /// 永久封禁 (写 `<ip> 0\n`,同时写 `SQLite`)
    Permanent,
    /// 解封临时封禁 (写 `unban <ip>\n`)
    Unban,
    /// 解封永久封禁 (写 `unban <ip>\n`,同时 `SQLite` `is_active=0`)
    UnbanPerm,
}
// Re-export 所有公共类型和函数
pub use ip_validation::{validate_ip, validate_ipv4, ValidatedIp};
pub use operations::{
    ban_ip, ban_ip_permanent, ban_ip_permanent_with_history, ban_ip_with_history,
    cleanup_expired_bans, execute_ban_action, unban_ip, unban_ip_with_history, unban_permanent_ip,
    BanAction,
};
pub use procfs::{close_cached_bans_fd, secure_procfs_write, BANS_PATH, PROCFS_DIR};
