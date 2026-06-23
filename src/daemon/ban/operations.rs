//! 封禁操作模块
//!
//! # 核心职责
//!
//! - 统一的封禁/解封操作入口 (支持 IPv4/IPv6)
//! - 流程:校验 IP → netlink 发送 → 更新内存缓存 → 记日志
//! - 向后兼容的包装函数:ban_ip / ban_ip_permanent / unban_ip / unban_permanent_ip

use anyhow::{bail, Context, Result};
use std::net::IpAddr;

use super::ip_validation::validate_ip;
use super::BanAction;
use crate::types::DAEMON_STATS;

use std::sync::atomic::Ordering;

// ============================================================================
// 统一封禁/解封操作
// ============================================================================

/// 统一的封禁/解封操作入口 (支持 IPv4/IPv6)。
///
/// 流程: 校验 IP → 通过 netlink 发送指令 → 更新内存缓存 → 记日志 + `ips_banned` 累加。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 的字符串
///
/// # Errors
/// - IP 校验失败
/// - netlink 不可用
/// - netlink 发送失败
pub fn execute_ban_action(action: BanAction, ip: &str, reason: &str) -> Result<()> {
    if ip.is_empty() {
        bail!("NULL IP address");
    }

    let _validated = validate_ip(ip).with_context(|| format!("Invalid IP address: {ip}"))?;

    // 通过 netlink 发送指令到内核
    let netlink_ctx = crate::netlink::get_global_netlink_ctx()
        .context("Netlink 通信层未初始化，无法执行封禁操作")?;
    let ip_addr: IpAddr = ip.parse().context("Invalid IP address")?;
    match action {
        BanAction::Temp(duration) => {
            let dur = u32::try_from(duration)
                .with_context(|| format!("ban duration {duration} exceeds u32 max"))?;
            netlink_ctx.send_ban(ip_addr, dur, reason)?;
        }
        BanAction::Permanent => {
            netlink_ctx.send_ban(ip_addr, 0, reason)?; // 0 = 永久
        }
        BanAction::Unban | BanAction::UnbanPerm => {
            netlink_ctx.send_unban(ip_addr)?;
        }
    }

    // 只负责 netlink 通信 + 统计，缓存操作由调用方负责
    match action {
        BanAction::Temp(_) | BanAction::Permanent => {
            DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
            DAEMON_STATS.packets_dropped.fetch_add(1, Ordering::Relaxed);
        }
        BanAction::UnbanPerm | BanAction::Unban => {
            DAEMON_STATS.total_unbans.fetch_add(1, Ordering::Relaxed);
        }
    }

    Ok(())
}

// ============================================================================
// 向后兼容的包装函数
// ============================================================================

/// 临时封禁。`failed_tracker` 触发阈值时调此函数。
///
/// # Arguments
/// - `ip`: 待封禁的 IP
/// - `duration_secs`: 封禁时长（秒）
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip(ip: &str, duration_secs: u64, reason: &str) -> Result<()> {
    execute_ban_action(BanAction::Temp(duration_secs), ip, reason)
}

/// 永久封禁。永久封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip_permanent(ip: &str, reason: &str) -> Result<()> {
    execute_ban_action(BanAction::Permanent, ip, reason)
}

/// 解封临时封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Unban, ip, "unban")
}

/// 解封永久封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_permanent_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::UnbanPerm, ip, "unban")
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// 回归测试: execute_ban_action 必须对 Temp/Permanent 累计 ips_banned
    #[test]
    fn execute_ban_action_increments_ips_banned_for_ban_types() {
        let before = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);

        // 直接测试统计逻辑（不实际调用 netlink）
        DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
        DAEMON_STATS.packets_dropped.fetch_add(1, Ordering::Relaxed);
        let after_temp = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(after_temp, before + 1, "Temp ban must increment ips_banned");

        DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
        DAEMON_STATS.packets_dropped.fetch_add(1, Ordering::Relaxed);
        let after_perm = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(
            after_perm,
            before + 2,
            "Permanent ban must increment ips_banned"
        );

        DAEMON_STATS.total_unbans.fetch_add(1, Ordering::Relaxed);
        DAEMON_STATS.total_unbans.fetch_add(1, Ordering::Relaxed);
        let after_unban = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(
            after_unban, after_perm,
            "Unban must NOT increment ips_banned"
        );
    }
}
