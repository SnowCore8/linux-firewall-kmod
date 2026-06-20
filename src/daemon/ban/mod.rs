//! 封禁/解封操作 + 安全 procfs 写入 + bans fd 缓存
//!
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
//! | 解封（Temp/Perm 共用） | `unban <ip>\n` | `unban 1.2.3.4\n` |
//!
//! # 安全模型
//!
//! 三道防线防止恶意输入击穿到 procfs：
//! 1. **路径白名单**：只能写 `/proc/firewall/` 下的路径
//! 2. **字符白名单**：文件名仅允许 `[A-Za-z0-9/_.-]`
//! 3. **fd 重定向检查**：`/proc/self/fd/N` readlink 必须解析到 `/proc/firewall/`

// 模块声明
mod ip_validation;
mod operations;
mod procfs;

// Re-export 所有公共类型和函数
pub use ip_validation::{validate_ip, validate_ipv4, ValidatedIp};
pub use operations::{
    ban_ip, ban_ip_permanent, ban_ip_with_history, cleanup_expired_bans, execute_ban_action,
    unban_ip, unban_permanent_ip,
};
pub use procfs::{close_cached_bans_fd, secure_procfs_write};

// ============================================================================
// 常量
// ============================================================================

/// 内核模块 procfs 根目录。所有 `secure_procfs_write` 只能在此目录下写入。
pub const PROCFS_DIR: &str = "/proc/firewall";

/// 封禁命令的 procfs 文件。命令格式见模块级文档。
pub const BANS_PATH: &str = "/proc/firewall/bans";

/// 白名单的 procfs 文件。
pub const WHITELIST_PATH: &str = "/proc/firewall/whitelist";

// ============================================================================
// 可信 IP 白名单初始化
// ============================================================================

/// 将可信 IP 列表写入内核白名单。
///
/// # Arguments
/// - `trusted_ips`: 可信 IP 或 CIDR 列表
///
/// # Errors
/// 返回写入失败的 IP 列表（不中断其他 IP 的写入）
pub fn init_trusted_ips(trusted_ips: &[String]) -> Vec<String> {
    let mut failed = Vec::new();
    let mut success_count = 0u64;
    for ip in trusted_ips {
        let (ip_addr, prefix_len) = parse_cidr(ip);
        // 优先走 netlink（程序内部通信走 netlink）
        if let Some(netlink_ctx) = crate::netlink::get_global_netlink_ctx() {
            if let Err(e) = netlink_ctx.send_add_whitelist(&ip_addr, prefix_len, "") {
                crate::logger::warn!(
                    crate::logger::get(),
                    "netlink 添加白名单失败，降级到 procfs";
                    "ip" => %ip,
                    "error" => %e
                );
                // 降级到 procfs
                if let Err(e2) = secure_procfs_write(WHITELIST_PATH, format!("{}\n", ip).as_bytes())
                {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "写入可信 IP 到白名单失败";
                        "ip" => %ip,
                        "error" => %e2
                    );
                    failed.push(ip.clone());
                } else {
                    success_count += 1;
                }
            } else {
                crate::logger::info!(
                    crate::logger::get(),
                    "已添加可信 IP 到白名单（netlink）";
                    "ip" => %ip
                );
                success_count += 1;
            }
        } else {
            // netlink 不可用，直接写 procfs
            let data = format!("{}\n", ip);
            if let Err(e) = secure_procfs_write(WHITELIST_PATH, data.as_bytes()) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "写入可信 IP 到白名单失败";
                    "ip" => %ip,
                    "error" => %e
                );
                failed.push(ip.clone());
            } else {
                success_count += 1;
            }
        }
    }
    // 更新白名单计数器
    if success_count > 0 {
        crate::types::DAEMON_STATS
            .whitelist_count
            .fetch_add(success_count, std::sync::atomic::Ordering::Relaxed);
    }
    failed
}

/// 从内核白名单移除可信 IP。
///
/// # Arguments
/// - `trusted_ips`: 要移除的可信 IP 或 CIDR 列表
///
/// # Errors
/// 返回移除失败的 IP 列表
pub fn remove_trusted_ips(trusted_ips: &[String]) -> Vec<String> {
    let mut failed = Vec::new();
    let mut success_count = 0u64;
    for ip in trusted_ips {
        let (ip_addr, prefix_len) = parse_cidr(ip);
        // 优先走 netlink（程序内部通信走 netlink）
        if let Some(netlink_ctx) = crate::netlink::get_global_netlink_ctx() {
            if let Err(e) = netlink_ctx.send_remove_whitelist(&ip_addr, prefix_len) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "netlink 移除白名单失败，降级到 procfs";
                    "ip" => %ip,
                    "error" => %e
                );
                // 降级到 procfs
                let data = format!("remove {}\n", ip);
                if let Err(e2) = secure_procfs_write(WHITELIST_PATH, data.as_bytes()) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "从白名单移除可信 IP 失败";
                        "ip" => %ip,
                        "error" => %e2
                    );
                    failed.push(ip.clone());
                } else {
                    success_count += 1;
                }
            } else {
                crate::logger::info!(
                    crate::logger::get(),
                    "已从白名单移除可信 IP（netlink）";
                    "ip" => %ip
                );
                success_count += 1;
            }
        } else {
            // netlink 不可用，直接写 procfs
            let data = format!("remove {}\n", ip);
            if let Err(e) = secure_procfs_write(WHITELIST_PATH, data.as_bytes()) {
                crate::logger::warn!(
                    crate::logger::get(),
                    "从白名单移除可信 IP 失败";
                    "ip" => %ip,
                    "error" => %e
                );
                failed.push(ip.clone());
            } else {
                success_count += 1;
            }
        }
    }
    // 更新白名单计数器
    if success_count > 0 {
        crate::types::DAEMON_STATS
            .whitelist_count
            .fetch_sub(success_count, std::sync::atomic::Ordering::Relaxed);
    }
    failed
}

/// 解析 CIDR 格式，返回 (IP地址, 前缀长度)
fn parse_cidr(ip: &str) -> (String, u8) {
    if let Some(pos) = ip.find('/') {
        let ip_addr = &ip[..pos];
        let prefix_len =
            ip[pos + 1..]
                .parse::<u8>()
                .unwrap_or(if ip.contains(':') { 128 } else { 32 });
        (ip_addr.to_string(), prefix_len)
    } else if ip.contains(':') {
        (ip.to_string(), 128)
    } else {
        (ip.to_string(), 32)
    }
}

// ============================================================================
// 封禁/解封操作类型
// ============================================================================

/// 封禁/解封操作枚举。所有动作经 [`execute_ban_action`] 统一分发。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanAction {
    /// 临时封禁（写 `<ip>\n`，内核按 `ban_time` 自动解封）
    Temp,
    /// 永久封禁（写 `<ip> 0\n`）
    Permanent,
    /// 解封临时封禁（写 `unban <ip>\n`）
    Unban,
    /// 解封永久封禁（写 `unban <ip>\n`）
    UnbanPerm,
}
