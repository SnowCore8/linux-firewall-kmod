//! 封禁/解封操作 + IP 校验
//!
//! # 子模块划分
//!
//! - `ip_validation`: IP 合法性校验
//! - `operations`: 封禁/解封操作（通过 netlink 与内核通信）

// 模块声明
mod ip_validation;
mod operations;

// Re-export 所有公共类型和函数
pub use ip_validation::{validate_ip, validate_ipv4, ValidatedIp};
pub use operations::{ban_ip, ban_ip_permanent, execute_ban_action, unban_ip, unban_permanent_ip};

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
    let netlink_ctx = match crate::netlink::get_global_netlink_ctx() {
        Some(ctx) => ctx,
        None => {
            crate::logger::error!(
                crate::logger::get(),
                "Netlink 未初始化，无法添加可信 IP 白名单"
            );
            return trusted_ips.to_vec();
        }
    };
    for ip in trusted_ips {
        let (ip_addr, prefix_len) = parse_cidr(ip);
        if let Err(e) = netlink_ctx.send_add_whitelist(&ip_addr, prefix_len, "") {
            crate::logger::warn!(
                crate::logger::get(),
                "netlink 添加白名单失败";
                "ip" => %ip,
                "error" => %e
            );
            failed.push(ip.clone());
        } else {
            crate::logger::info!(
                crate::logger::get(),
                "已添加可信 IP 到白名单";
                "ip" => %ip
            );
            success_count += 1;
            append_whitelist_cache(&ip_addr, prefix_len);
        }
    }
    if success_count > 0 {
        crate::types::DAEMON_STATS
            .whitelist_count
            .fetch_add(success_count, std::sync::atomic::Ordering::Relaxed);
    }
    failed
}

/// 向 WHITELIST_CACHE 追加条目（用于守护进程自己添加白名单时的本地缓存同步）。
///
/// 由于 ListWhitelistResponse 是请求-响应模式，启动后可能因 race condition 错过，
/// 导致缓存为空。本函数保证 init_trusted_ips / remove_trusted_ips 后缓存立即一致。
fn append_whitelist_cache(ip: &str, prefix_len: u8) {
    let cidr = if ip.contains(':') {
        format!("{}/{}", ip, if prefix_len == 0 { 128 } else { prefix_len })
    } else if prefix_len == 32 || prefix_len == 0 {
        ip.to_string()
    } else {
        format!("{}/{}", ip, prefix_len)
    };
    // HashMap insert 天然幂等，重复写入即覆盖
    crate::types::WHITELIST_CACHE.write().insert(
        cidr.clone(),
        crate::types::WhitelistEntry {
            cidr,
            device: String::new(),
        },
    );
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
    let netlink_ctx = match crate::netlink::get_global_netlink_ctx() {
        Some(ctx) => ctx,
        None => {
            crate::logger::error!(
                crate::logger::get(),
                "Netlink 未初始化，无法移除可信 IP 白名单"
            );
            return trusted_ips.to_vec();
        }
    };
    for ip in trusted_ips {
        let (ip_addr, prefix_len) = parse_cidr(ip);
        if let Err(e) = netlink_ctx.send_remove_whitelist(&ip_addr, prefix_len) {
            crate::logger::warn!(
                crate::logger::get(),
                "netlink 移除白名单失败";
                "ip" => %ip,
                "error" => %e
            );
            failed.push(ip.clone());
        } else {
            crate::logger::info!(
                crate::logger::get(),
                "已从白名单移除可信 IP";
                "ip" => %ip
            );
            success_count += 1;
            remove_whitelist_cache(&ip_addr, prefix_len);
        }
    }
    if success_count > 0 {
        crate::types::DAEMON_STATS
            .whitelist_count
            .fetch_sub(success_count, std::sync::atomic::Ordering::Relaxed);
    }
    failed
}

/// 从 WHITELIST_CACHE 移除条目
fn remove_whitelist_cache(ip: &str, prefix_len: u8) {
    let cidr = if ip.contains(':') {
        format!("{}/{}", ip, if prefix_len == 0 { 128 } else { prefix_len })
    } else if prefix_len == 32 || prefix_len == 0 {
        ip.to_string()
    } else {
        format!("{}/{}", ip, prefix_len)
    };
    crate::types::WHITELIST_CACHE.write().remove(&cidr);
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
    /// 临时封禁（写 `<ip> <duration>\n`，duration 为秒数）
    Temp(u64),
    /// 永久封禁（写 `<ip> 0\n`）
    Permanent,
    /// 解封临时封禁（写 `unban <ip>\n`）
    Unban,
    /// 解封永久封禁（写 `unban <ip>\n`）
    UnbanPerm,
}
