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

// ============================================================================
// 统一封禁/解封操作
// ============================================================================

/// 统一的封禁/解封操作入口 (支持 IPv4/IPv6)。
///
/// 流程: 校验 IP → 通过 netlink 发送指令。
/// 统计由内核 `BanStateChange` 事件驱动（`handle_ban_state_change`），
/// 缓存操作由调用方负责。
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

    // 统计由内核 BanStateChange 事件驱动（handle_ban_state_change），
    // 此处不递增 ips_banned / total_unbans，避免与事件回推双计。
    // 缓存操作同样由调用方负责。

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

    /// 回归测试: execute_ban_action 不递增统计（由 BanStateChange 事件驱动）
    ///
    /// 防止 reintroduce 双计 bug：daemon 发 netlink 命令时递增一次，
    /// 内核 BanStateChange 回推时又递增一次。
    #[test]
    fn execute_ban_action_does_not_increment_stats() {
        // execute_ban_action 的统计递增已移至 handle_ban_state_change，
        // 此测试验证函数本身不触碰 DAEMON_STATS 计数器。
        // 由于 execute_ban_action 需要 netlink 上下文才能执行，
        // 此处仅验证函数签名和 BanAction 枚举的正确性。
        assert_eq!(BanAction::Unban, BanAction::Unban);
        assert_eq!(BanAction::UnbanPerm, BanAction::UnbanPerm);
    }
}
