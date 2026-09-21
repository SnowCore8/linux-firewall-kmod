//! 封禁/解封操作 + IP 校验
//!
//! # 子模块划分
//!
//! - `ip_validation`: IP 合法性校验
//! - `operations`: 封禁/解封操作（通过 netlink 与内核通信）
//!
//! # 可信 IP 的 CIDR 归一
//!
//! 本模块的入口收的是用户写的文本（YAML 的 `trusted_ips`、HTTP 的 `cidr` 字段），
//! 而内核白名单表存的是**网络地址**且只做整体比较（`fw_wl.c` 的 `fw_wl_find_locked`）。
//! 归一因此只能有一处：[`CidrKey`]。它同时是本地缓存的键类型与 HTTP 响应的 `cidr`
//! 取值，所以「下发内核的地址」与「界面上看到的键」必然一致。

// 模块声明
mod ip_validation;
mod operations;

// Re-export 所有公共类型和函数
pub use ip_validation::{is_internal_ip, validate_ip, validate_ipv4, ValidatedIp};
pub use operations::{ban_ip, ban_ip_permanent, execute_ban_action, unban_ip, unban_permanent_ip};

use crate::state::CidrKey;

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
    let client = match crate::kernel::global::get() {
        Some(client) => client,
        None => {
            crate::logger::error!(
                crate::logger::get(),
                "内核链路未就绪，无法添加可信 IP 白名单"
            );
            return trusted_ips.to_vec();
        }
    };
    for ip in trusted_ips {
        let key = match CidrKey::parse(ip) {
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
        if crate::types::WHITELIST_CACHE
            .read()
            .contains_key(key.as_str())
        {
            continue;
        }
        // 内核侧白名单键不含设备维度（旧 `send_add_whitelist` 亦传空串），故这里传 `""`。
        if let Err(e) = add_whitelist_to_kernel(&client, &key) {
            crate::logger::warn!(
                crate::logger::get(),
                "内核添加白名单失败";
                "ip" => %ip,
                "error" => %e
            );
            failed.push(ip.clone());
        } else {
            crate::logger::info!(
                crate::logger::get(),
                "已添加可信 IP 到白名单";
                "ip" => %ip,
                "cidr" => key.as_str()
            );
            success_count += 1;
            append_whitelist_cache(&key);
        }
    }
    if success_count > 0 {
        crate::types::DAEMON_STATS
            .whitelist_count
            .fetch_add(success_count, std::sync::atomic::Ordering::Relaxed);
    }
    failed
}

/// 把一条已归一的键投递给内核白名单。
///
/// 下发的是 [`CidrKey`] 里的**网络地址 + 前缀**：内核不做主机位归一就直接入表，
/// 若下发子网内任意地址，同一条子网会被写成两条表项（且按归一地址 remove 查不到）。
fn add_whitelist_to_kernel(
    client: &crate::kernel::client::Client,
    key: &CidrKey,
) -> Result<(), String> {
    client
        .add_whitelist(
            key.addr(),
            key.prefix_len(),
            "",
            crate::kernel::REQUEST_TIMEOUT,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// 从内核白名单移除一条已归一的键。
fn remove_whitelist_from_kernel(
    client: &crate::kernel::client::Client,
    key: &CidrKey,
) -> Result<(), String> {
    client
        .remove_whitelist(
            key.addr(),
            key.prefix_len(),
            "",
            crate::kernel::REQUEST_TIMEOUT,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// 向 WHITELIST_CACHE 追加条目（用于守护进程自己添加白名单时的本地缓存同步）。
///
/// 由于 ListWhitelistResponse 是请求-响应模式，启动后可能因 race condition 错过，
/// 导致缓存为空。本函数保证 init_trusted_ips / remove_trusted_ips 后缓存立即一致。
fn append_whitelist_cache(key: &CidrKey) {
    // HashMap insert 天然幂等，重复写入即覆盖
    crate::types::WHITELIST_CACHE.write().insert(
        key.as_str().to_string(),
        crate::types::WhitelistEntry {
            cidr: key.as_str().to_string(),
            device: String::new(),
        },
    );
    crate::state::compose::mirror_whitelist_insert(key.clone(), "");
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
    let client = match crate::kernel::global::get() {
        Some(client) => client,
        None => {
            crate::logger::error!(
                crate::logger::get(),
                "内核链路未就绪，无法移除可信 IP 白名单"
            );
            return trusted_ips.to_vec();
        }
    };
    for ip in trusted_ips {
        let key = match CidrKey::parse(ip) {
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
        if !crate::types::WHITELIST_CACHE
            .read()
            .contains_key(key.as_str())
        {
            continue;
        }
        if let Err(e) = remove_whitelist_from_kernel(&client, &key) {
            crate::logger::warn!(
                crate::logger::get(),
                "内核移除白名单失败";
                "ip" => %ip,
                "error" => %e
            );
            failed.push(ip.clone());
        } else {
            crate::logger::info!(
                crate::logger::get(),
                "已从白名单移除可信 IP";
                "ip" => %ip,
                "cidr" => key.as_str()
            );
            success_count += 1;
            remove_whitelist_cache(&key);
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
fn remove_whitelist_cache(key: &CidrKey) {
    crate::types::WHITELIST_CACHE.write().remove(key.as_str());
    crate::state::compose::mirror_whitelist_remove(key);
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
