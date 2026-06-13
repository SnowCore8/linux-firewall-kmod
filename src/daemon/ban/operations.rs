//! 封禁操作模块
//!
//! # 核心职责
//!
//! - 统一的封禁/解封操作入口 (支持 IPv4/IPv6)
//! - 流程:校验 IP → 格式化命令 → procfs 写入 → 同步 SQLite (仅 Permanent/UnbanPerm)
//! - 向后兼容的包装函数:ban_ip / ban_ip_permanent / unban_ip / unban_permanent_ip
//! 封禁/解封操作 (临时/永久/解封 + 混合存储)

use std::sync::atomic::Ordering;
use std::time::SystemTime;

use anyhow::{bail, Context, Result};

use super::ip_validation::validate_ip;
use super::procfs::secure_procfs_write;
use super::{BanAction, BANS_PATH};
use crate::sqlite;
use crate::types::DAEMON_STATS;

use std::sync::atomic::Ordering;
use super::procfs::{secure_procfs_write, BANS_PATH};
use crate::sqlite;
use crate::sqlite_writer;
use crate::types::{ActiveBanCache, BanInfo, BanReason, DAEMON_STATS};

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
/// 流程: 校验 IP → 格式化命令 → `secure_procfs_write` → 同步 `SQLite`
/// (仅 Permanent/UnbanPerm) → 记日志 + `ips_banned` 累加。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 的字符串
///
/// # Errors
/// - IP 校验失败
/// - procfs 写入失败
/// - `SQLite` 写入失败 (仅 Permanent/UnbanPerm)
pub fn execute_ban_action(action: BanAction, ip: &str) -> Result<()> {
    if ip.is_empty() {
        bail!("NULL IP address");
    }

    let validated = validate_ip(ip).with_context(|| format!("Invalid IP address: {ip}"))?;

    let cmd = format_ban_command(action, ip)?;
    secure_procfs_write(BANS_PATH, cmd.as_bytes())
        .with_context(|| format!("Failed to write to {BANS_PATH}"))?;

    match action {
        BanAction::Permanent => {
            if let Some(rc) = sqlite::with_global_db(|db| {
                sqlite::sqlite_add_permanent_ban(
                    db,
                    ip,
                    validated.ip_num,
                    "manual permanent ban",
                    "manual",
                )
            }) {
                rc.with_context(|| {
                    format!("SQLite add_permanent_ban failed for permanent ban {ip}")
                })?;
            }
            // 全局 db 未注册 (sqlite_init 失败) → 静默跳过, 等同 C 版 sqlite_db==NULL
            crate::logger::info!(
                crate::logger::get(),
                "永久封禁";
                "ip" => ip,
                "type" => "permanent"
            );
        }
        BanAction::UnbanPerm => {
            if let Some(rc) =
                sqlite::with_global_db(|db| sqlite::sqlite_remove_permanent_ban(db, ip))
            {
                rc.with_context(|| {
                    format!("SQLite remove_permanent_ban failed for permanent unban {ip}")
                })?;
            }
        }
        _ => {}
            crate::logger::info!(
                crate::logger::get(),
                "解除永久封禁";
                "ip" => ip,
                "type" => "unban_permanent"
            );
        }
        BanAction::Temp => {
            crate::logger::info!(
                crate::logger::get(),
                "临时封禁";
                "ip" => ip,
                "type" => "temporary"
            );
        }
        BanAction::Unban => {
            crate::logger::info!(
                crate::logger::get(),
                "解除临时封禁";
                "ip" => ip,
                "type" => "unban"
            );
        }
    }

    log_ban_action(action, ip);

    Ok(())
}

/// 内部:累加 `ips_banned` 统计并 emit 用户可见的日志。
///
/// Temp / Permanent 都累加,Prometheus `ips_banned_total` 来源。
fn log_ban_action(action: BanAction, ip: &str) {
    if matches!(action, BanAction::Temp | BanAction::Permanent) {
        DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
    }

    let _ = action;
    let _ = ip;
/// 内部:累加 `ips_banned` 统计。
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

/// 永久封禁。启动时从 `SQLite` 恢复永久黑名单用此函数。
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

/// 解封永久封禁 (同步写 `SQLite` `is_active=0`)。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_permanent_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::UnbanPerm, ip)
}

/// 占位函数: 内核模块负责定期清理过期封禁, 用户态无需轮询。
pub fn cleanup_expired_bans() {
    // 内核模块负责定期清理, 此处仅占位
}

// ============================================================================
// 混合存储: 内存缓存 + SQLite 持久化
// ============================================================================

/// 临时封禁 (带历史记录) — 更新内存缓存 + 标记 dirty 等定时器写入 SQLite
///
/// # 参数
///
/// - `ip`: 要封禁的 IP 地址
/// - `jail_name`: 触发封禁的 jail 名称
/// - `fail_count`: 触发封禁前的失败次数
/// - `duration_secs`: 封禁时长 (秒),0 = 永久
///
/// # 行为
///
/// 1. 调用 `ban_ip()` 写 procfs (内核立即生效, 内部已累加 `DAEMON_STATS.ips_banned`)
/// 2. 创建 `BanInfo` 插入 `ACTIVE_BAN_CACHE`
/// 3. 调用 `sqlite_writer::mark_dirty()` 标记待同步
///
/// # Errors
///
/// 同 [`ban_ip`]
pub fn ban_ip_with_history(
    ip: &str,
    jail_name: &str,
    fail_count: u32,
    duration_secs: u64,
) -> Result<()> {
    use std::time::UNIX_EPOCH;

    // 1. 写 procfs (内核立即生效)
    ban_ip(ip)?;

    // 2. 创建 BanInfo
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let validated = validate_ip(ip)?;
    let expires_at = if duration_secs > 0 {
        now + duration_secs as i64
    } else {
        0 // 0 = 永久
    };

    let info = BanInfo {
        ip: ip.to_string(),
        ip_num: validated.ip_num,
        jail_name: jail_name.to_string(),
        reason: BanReason::FailedAttempts,
        banned_at: now,
        expires_at,
        is_permanent: duration_secs == 0,
        fail_count,
    };

    // 3. 插入内存缓存
    crate::types::ACTIVE_BAN_CACHE
        .get_or_init(ActiveBanCache::new)
        .insert(info);

    // 4. 标记 dirty (定时器会批量写入 SQLite)
    sqlite_writer::mark_dirty();

    slog::info!(
        crate::logger::get(),
        "IP 封禁成功 (混合存储)";
        "ip" => ip,
        "jail" => jail_name,
        "fail_count" => fail_count,
        "duration_secs" => duration_secs,
        "expires_at" => expires_at,
    );

    Ok(())
}

/// 永久封禁 (带历史记录) — 同步写 SQLite 永久黑名单 + 更新内存缓存
///
/// # 参数
///
/// - `ip`: 要封禁的 IP 地址
/// - `jail_name`: 触发封禁的 jail 名称
/// - `reason`: 封禁原因
///
/// # 行为
///
/// 1. 调用 `ban_ip_permanent()` 写 procfs + SQLite 永久黑名单 (内部已累加 `DAEMON_STATS.ips_banned`)
/// 2. 创建 `BanInfo` 插入 `ACTIVE_BAN_CACHE` (is_permanent=true)
/// 3. 调用 `sqlite_writer::mark_dirty()` 标记待同步
///
/// # Errors
///
/// 同 [`ban_ip_permanent`]
pub fn ban_ip_permanent_with_history(ip: &str, jail_name: &str, reason: BanReason) -> Result<()> {
    use std::time::UNIX_EPOCH;

    // 1. 写 procfs + SQLite 永久黑名单
    ban_ip_permanent(ip)?;

    // 2. 创建 BanInfo
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let validated = validate_ip(ip)?;

    let info = BanInfo {
        ip: ip.to_string(),
        ip_num: validated.ip_num,
        jail_name: jail_name.to_string(),
        reason,
        banned_at: now,
        expires_at: 0, // 永久封禁
        is_permanent: true,
        fail_count: 0,
    };

    // 3. 插入内存缓存
    crate::types::ACTIVE_BAN_CACHE
        .get_or_init(ActiveBanCache::new)
        .insert(info);

    // 4. 标记 dirty
    sqlite_writer::mark_dirty();

    slog::info!(
        crate::logger::get(),
        "IP 永久封禁成功 (混合存储)";
        "ip" => ip,
        "jail" => jail_name,
        "reason" => reason.as_str(),
    );

    Ok(())
}

/// 解封 (带历史记录) — 从内存缓存移除 + 标记 dirty 等定时器更新 SQLite
///
/// # 参数
///
/// - `ip`: 要解封的 IP 地址
/// - `manual`: 是否手动解封 (true) 或自动过期 (false)
///
/// # 行为
///
/// 1. 调用 `unban_ip()` 写 procfs
/// 2. 从 `ACTIVE_BAN_CACHE` 移除
/// 3. 调用 `sqlite_writer::mark_dirty()` 标记待同步 (定时器会更新 ban_history.status)
///
/// # Errors
///
/// 同 [`unban_ip`]
pub fn unban_ip_with_history(ip: &str, manual: bool) -> Result<()> {
    use std::time::UNIX_EPOCH;

    // 1. 写 procfs
    unban_ip(ip)?;

    // 2. 从内存缓存移除
    if let Some(info) = crate::types::ACTIVE_BAN_CACHE
        .get_or_init(ActiveBanCache::new)
        .remove(ip)
    {
        let duration = info.duration_secs(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
        );

        // 记录封禁时长到 histogram（Prometheus 指标）
        crate::types::record_ban_duration(duration);

        slog::info!(
            crate::logger::get(),
            "IP 解封成功 (混合存储)";
            "ip" => ip,
            "jail" => info.jail_name,
            "manual" => manual,
            "duration_secs" => duration,
        );
    }

    // 3. 标记 dirty (定时器会更新 ban_history.status)
    sqlite_writer::mark_dirty();

    Ok(())
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
