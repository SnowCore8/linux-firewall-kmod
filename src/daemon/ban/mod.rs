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
pub use ip_validation::{is_internal_ip, validate_ip, validate_ipv4, ValidatedIp};
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
        let (ip_addr, prefix_len) = match parse_cidr(ip) {
            Ok(v) => v,
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "解析可信 IP CIDR 失败";
                    "ip" => %ip,
                    "error" => %e
                );
                failed.push(ip.clone());
                continue;
            }
        };
        // 检查本地缓存：已存在则跳过，避免重复添加导致计数器膨胀
        let cidr_key = build_cidr_key(&ip_addr, prefix_len);
        if crate::types::WHITELIST_CACHE.read().contains_key(&cidr_key) {
            continue;
        }
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
    let cidr = build_cidr_key(ip, prefix_len);
    // HashMap insert 天然幂等，重复写入即覆盖
    crate::types::WHITELIST_CACHE.write().insert(
        cidr.clone(),
        crate::types::WhitelistEntry {
            cidr,
            device: String::new(),
        },
    );
}

/// 构建 CIDR 缓存键（与 WHITELIST_CACHE 的 key 格式一致）
fn build_cidr_key(ip: &str, prefix_len: u8) -> String {
    if ip.contains(':') {
        format!("{}/{}", ip, if prefix_len == 0 { 128 } else { prefix_len })
    } else if prefix_len == 32 || prefix_len == 0 {
        ip.to_string()
    } else {
        format!("{}/{}", ip, prefix_len)
    }
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
        let (ip_addr, prefix_len) = match parse_cidr(ip) {
            Ok(v) => v,
            Err(e) => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "解析可信 IP CIDR 失败";
                    "ip" => %ip,
                    "error" => %e
                );
                failed.push(ip.clone());
                continue;
            }
        };
        // 检查本地缓存：不存在则跳过，避免移除不存在的条目导致计数器下溢
        let cidr_key = build_cidr_key(&ip_addr, prefix_len);
        if !crate::types::WHITELIST_CACHE.read().contains_key(&cidr_key) {
            continue;
        }
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
    let cidr = build_cidr_key(ip, prefix_len);
    crate::types::WHITELIST_CACHE.write().remove(&cidr);
}

/// 解析 CIDR 格式，返回 (IP地址, 前缀长度)。
///
/// 无效前缀（如 `/abc`、`/256`）返回错误而非静默使用默认值。
fn parse_cidr(ip: &str) -> anyhow::Result<(String, u8)> {
    if let Some(pos) = ip.find('/') {
        let ip_addr = &ip[..pos];
        let max_prefix = if ip.contains(':') { 128u8 } else { 32u8 };
        let prefix_len: u8 = ip[pos + 1..]
            .parse()
            .map_err(|e| anyhow::anyhow!("无效 CIDR 前缀 '{}': {}", &ip[pos + 1..], e))?;
        if prefix_len > max_prefix {
            anyhow::bail!(
                "CIDR 前缀 {} 超出 {} 地址范围上限 /{}",
                prefix_len,
                if max_prefix == 128 { "IPv6" } else { "IPv4" },
                max_prefix
            );
        }
        Ok((ip_addr.to_string(), prefix_len))
    } else if ip.contains(':') {
        Ok((ip.to_string(), 128))
    } else {
        Ok((ip.to_string(), 32))
    }
}

// ============================================================================
// sysfs 内核参数写入（共享工具函数）
// ============================================================================

/// 写入布尔值到内核模块参数（/sys/module/firewall/parameters/）
///
/// 用于同步 DDoS 检测开关到内核。写入失败时记录警告日志。
pub fn write_sysfs_bool_param(param_name: &str, value: bool) {
    let path = format!("/sys/module/firewall/parameters/{param_name}");
    if let Err(e) = std::fs::write(&path, if value { "1" } else { "0" }) {
        crate::logger::warn!(
            crate::logger::get(),
            "写入内核参数失败";
            "param" => param_name,
            "error" => %e
        );
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
