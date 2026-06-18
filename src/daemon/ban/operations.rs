//! 封禁操作模块
//!
//! # 核心职责
//!
//! - 统一的封禁/解封操作入口 (支持 IPv4/IPv6)
//! - 流程:校验 IP → 格式化命令 → procfs 写入 →
//! - 向后兼容的包装函数:ban_ip / ban_ip_permanent / unban_ip / unban_permanent_ip

use anyhow::{bail, Context, Result};

use super::ip_validation::validate_ip;
use super::procfs::secure_procfs_write;
use super::{BanAction, BANS_PATH};
use crate::types::{ActiveBanCache, BanInfo, BanReason, DAEMON_STATS, ACTIVE_BAN_CACHE};

use std::sync::atomic::Ordering;

// ============================================================================
// 封禁命令格式化
// ============================================================================

/// 格式化内核模块识别的命令字符串。命令总长硬上限 80 字节。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 校验的字符串
///
/// # Errors
/// - 格式化后命令 > 80 字节 (实际不可能,IP 长度上限 46 + 前缀 7 = 53)
fn format_ban_command(action: BanAction, ip: &str) -> Result<String> {
    let cmd = match action {
        BanAction::Temp => format!("{ip}\n"),
        BanAction::Permanent => format!("{ip} 0\n"),
        BanAction::Unban | BanAction::UnbanPerm => format!("unban {ip}\n"),
    };

    if cmd.len() > 80 {
        bail!("Command buffer overflow for IP {ip}");
    }

    Ok(cmd)
}

// ============================================================================
// 统一封禁/解封操作
// ============================================================================

/// 统一的封禁/解封操作入口 (支持 IPv4/IPv6)。
///
/// 流程: 校验 IP → 格式化命令 → `secure_procfs_write` → 记日志 + `ips_banned` 累加。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 的字符串
///
/// # Errors
/// - IP 校验失败
/// - procfs 写入失败
/// -
pub fn execute_ban_action(action: BanAction, ip: &str) -> Result<()> {
    if ip.is_empty() {
        bail!("NULL IP address");
    }

    let _validated = validate_ip(ip).with_context(|| format!("Invalid IP address: {ip}"))?;

    let cmd = format_ban_command(action, ip)?;
    secure_procfs_write(BANS_PATH, cmd.as_bytes())
        .with_context(|| format!("Failed to write to {BANS_PATH}"))?;

    match action {
        BanAction::Permanent | BanAction::Temp => {
            // 内核封禁已通过 procfs 写入完成
        }
        BanAction::UnbanPerm | BanAction::Unban => {
            // 从内存缓存移除
            if let Some(cache) = crate::types::ACTIVE_BAN_CACHE.get() {
                cache.remove(ip);
            }
        }
    }

    log_ban_action(action, ip);

    Ok(())
}

/// 内部:累加 `ips_banned` 统计并 emit 用户可见的日志。
///
/// Temp / Permanent 都累加,Prometheus `ips_banned_total` 来源。
fn log_ban_action(action: BanAction, _ip: &str) {
    if matches!(action, BanAction::Temp | BanAction::Permanent) {
        DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// 向后兼容的包装函数
// ============================================================================

/// 临时封禁。`failed_tracker` 触发阈值时调此函数。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Temp, ip)
}

/// 永久封禁。永久封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip_permanent(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Permanent, ip)
}

/// 解封临时封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Unban, ip)
}

/// 解封永久封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_permanent_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::UnbanPerm, ip)
}

/// 封禁 IP 并记录封禁历史（供 DDoS 检测器等模块使用）。
///
/// 当前实现：`ban_duration == 0` 时走永久封禁，否则走临时封禁。
/// 临时封禁会更新 `ACTIVE_BAN_CACHE` 并标记 dirty。
///
/// # Arguments
/// - `ip`：待封禁的 IP
/// - `reason`：封禁原因（审计用）
/// - `jail_name`：关联 jail 名称（用于 /api/bans 和 Prometheus 指标）
/// - `ban_duration`：封禁时长（秒），0 表示永久封禁
pub fn ban_ip_with_history(
    ip: &str,
    _reason: &str,
    jail_name: &str,
    ban_duration: u64,
) -> Result<()> {
    if ban_duration == 0 {
        ban_ip_permanent(ip)
    } else {
        let now = crate::types::now_secs();
        // 复用 validate_ip 统一处理 IPv4/IPv6，验证失败时返回错误而非静默使用 0
        let validated =
            validate_ip(ip).with_context(|| format!("Invalid IP for ban history: {ip}"))?;
        let ip_num = validated.ip_num;
        // 防止整数溢出: ban_duration 转为 i64 后与 now 相加可能超出 i64 范围
        // 使用 saturating_add 确保 expires_at 不会回绕为负数
        let duration_i64 = if ban_duration > i64::MAX as u64 {
            crate::logger::warn!(
                crate::logger::get(),
                "ban_duration 超出 i64 范围，截断为 i64::MAX";
                "ban_duration" => ban_duration
            );
            i64::MAX
        } else {
            ban_duration as i64
        };
        let expires_at = now.saturating_add(duration_i64);
        let ban_info = crate::types::BanInfo {
            ip: ip.to_string(),
            ip_num,
            jail_name: jail_name.to_string(),
            reason: crate::types::BanReason::DDoSRateLimit,
            banned_at: now,
            expires_at,
            is_permanent: false,
            fail_count: 0,
        };

        // 原子性检查并插入缓存：消除 check-then-act 竞态条件
        let cache = crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
        if !cache.try_insert(ban_info.clone()) {
            // 已被其他线程先行封禁，跳过本次操作
            return Ok(());
        }

        if let Err(e) = ban_ip(ip) {
            // 内核封禁失败，回滚缓存标记（允许下次重试）
            cache.remove(ip);
            return Err(e).context("Failed to ban IP in kernel");
        }

        Ok(())
    }
}

/// 占位函数: 内核模块负责定期清理过期封禁, 用户态无需轮询。
pub fn cleanup_expired_bans() {
    // 内核模块负责定期清理, 此处仅占位
}

/// 从内核模块同步现有封禁列表到内存缓存
///
/// 解析 `/proc/firewall/bans` 输出，将封禁 IP 同步到 `ACTIVE_BAN_CACHE`。
/// 用于守护进程启动时恢复内核模块的封禁状态。
///
/// # Returns
/// 同步的封禁数量
pub fn sync_bans_from_kernel() -> Result<usize> {
    use std::fs;

    // 读取 /proc/firewall/bans
    let content = fs::read_to_string("/proc/firewall/bans")
        .context("Failed to read /proc/firewall/bans")?;

    let cache = ACTIVE_BAN_CACHE.get_or_init(ActiveBanCache::new);
    let now = crate::types::now_secs();
    let mut synced = 0;

    // 解析格式：
    // Banned IP List:
    // -------------------
    // 1.2.3.4                            (expires in 300 seconds)
    // 5.6.7.8                            (permanent)
    // -------------------
    // Total: 2 active bans (1 permanent, 1 temporary)
    for line in content.lines() {
        let line = line.trim();

        // 跳过标题、分隔线、统计行
        if line.is_empty()
            || line.starts_with("Banned IP List")
            || line.starts_with("---")
            || line.starts_with("Total:")
        {
            continue;
        }

        // 解析 IP 和过期信息
        // 格式: "1.2.3.4                            (expires in 300 seconds)"
        //    或: "1.2.3.4                            (permanent)"
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        let ip = parts[0];

        // 验证 IP 格式
        if validate_ip(ip).is_err() {
            continue;
        }

        // 判断是否已存在
        if cache.contains(ip) {
            continue;
        }

        // 解析过期时间
        let (is_permanent, expires_at) = if line.contains("(permanent)") {
            (true, 0)
        } else if let Some(idx) = line.find("expires in") {
            // 提取秒数
            let rest = &line[idx + 10..];
            if let Some(secs_str) = rest.split_whitespace().next() {
                if let Ok(secs) = secs_str.parse::<i64>() {
                    (false, now + secs)
                } else {
                    (false, now + 600) // 默认 10 分钟
                }
            } else {
                (false, now + 600)
            }
        } else {
            (false, now + 600) // 默认 10 分钟
        };

        // 创建 BanInfo
        let ban_info = BanInfo {
            ip: ip.to_string(),
            ip_num: 0, // IPv6 或暂不计算
            jail_name: "kernel".to_string(), // 内核模块封禁的归为 "kernel" jail
            reason: BanReason::DDoSRateLimit, // 假设是 DDoS 检测触发
            banned_at: now,
            expires_at,
            is_permanent,
            fail_count: 0,
        };

        cache.insert(ban_info);
        synced += 1;
    }

    Ok(synced)
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_ban_command_temp() {
        let cmd = format_ban_command(BanAction::Temp, "1.2.3.4").unwrap();
        assert_eq!(cmd, "1.2.3.4\n");
    }

    #[test]
    fn format_ban_command_permanent() {
        let cmd = format_ban_command(BanAction::Permanent, "1.2.3.4").unwrap();
        assert_eq!(cmd, "1.2.3.4 0\n");
    }

    #[test]
    fn format_ban_command_unban() {
        let cmd = format_ban_command(BanAction::Unban, "1.2.3.4").unwrap();
        assert_eq!(cmd, "unban 1.2.3.4\n");
    }

    #[test]
    fn format_ban_command_unban_perm() {
        let cmd = format_ban_command(BanAction::UnbanPerm, "1.2.3.4").unwrap();
        assert_eq!(cmd, "unban 1.2.3.4\n");
    }

    /// 回归测试 P0-3: log_ban_action 必须对 Temp/Permanent 累计 ips_banned
    /// 防止误把 fetch_add 注释掉导致 Prometheus ips_banned_total 永远为 0
    #[test]
    fn log_ban_action_increments_ips_banned_for_ban_types() {
        let before = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);

        log_ban_action(BanAction::Temp, "10.0.0.1");
        let after_temp = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(after_temp, before + 1, "Temp ban must increment ips_banned");

        log_ban_action(BanAction::Permanent, "10.0.0.2");
        let after_perm = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(
            after_perm,
            before + 2,
            "Permanent ban must increment ips_banned"
        );

        log_ban_action(BanAction::Unban, "10.0.0.1");
        log_ban_action(BanAction::UnbanPerm, "10.0.0.2");
        let after_unban = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(
            after_unban, after_perm,
            "Unban must NOT increment ips_banned"
        );
    }
}
