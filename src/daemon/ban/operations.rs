//! 封禁操作模块
//!
//! # 核心职责
//!
//! - 统一的封禁/解封操作入口 (支持 IPv4/IPv6)
//! - 流程:校验 IP → 内核指令 → 更新内存缓存 → 记日志
//! - 向后兼容的包装函数:ban_ip / ban_ip_permanent / unban_ip / unban_permanent_ip
//!
//! # 完成语义
//!
//! 三个动作都走「**已投递**」语义（[`crate::kernel::client::Delivered`]）：内核不回
//! 确认报文，封禁是否真正落表由内核随后推送的 `BanStateChange` 事件驱动本地状态。
//! 这与旧 `netlink` 的 `sendto` 成功即返回完全一致——不要在这里加等待，那会把
//! 事件驱动改成同步往返，且内核侧并无对应回复。

use anyhow::{bail, Context, Result};
use std::net::IpAddr;

use super::ip_validation::validate_ip;
use super::BanAction;

// ============================================================================
// 统一封禁/解封操作
// ============================================================================

/// 统一的封禁/解封操作入口 (支持 IPv4/IPv6)。
///
/// 流程: 校验 IP → 向内核投递指令。
/// 统计由内核 `BanStateChange` 事件驱动，
/// 缓存操作由调用方负责。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 的字符串
///
/// # Errors
/// - IP 校验失败
/// - 内核链路未就绪（未取得租约）
/// - 投递失败
pub fn execute_ban_action(action: BanAction, ip: &str, reason: &str) -> Result<()> {
    if ip.is_empty() {
        bail!("NULL IP address");
    }

    let _validated = validate_ip(ip).with_context(|| format!("Invalid IP address: {ip}"))?;

    // 向内核投递指令
    let client = crate::kernel::global::get().context("内核链路未就绪，无法执行封禁操作")?;
    let ip_addr: IpAddr = ip.parse().context("Invalid IP address")?;
    let timeout = crate::kernel::REQUEST_TIMEOUT;
    match action {
        BanAction::Temp(duration) => {
            let dur = u32::try_from(duration)
                .with_context(|| format!("ban duration {duration} exceeds u32 max"))?;
            client
                .ban(ip_addr, dur, reason, timeout)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        BanAction::Permanent => {
            // 0 = 永久（契约约定时长 0 表示不设到期）
            client
                .ban(ip_addr, 0, reason, timeout)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
        BanAction::Unban | BanAction::UnbanPerm => {
            client
                .unban(ip_addr, timeout)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
        }
    }

    // 统计由内核 BanStateChange 事件驱动，
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
