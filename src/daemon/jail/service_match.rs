//! 服务名智能匹配 + 默认参数推断
//!
//! 根据 jail 名称自动识别 SSH/WEB/FTP/MAIL/FRP/DB 服务类型,套用合理默认参数

use crate::types::{Config, Jail};

// ============================================================================
// 服务名称模式
// ============================================================================

/// 匹配 `ssh` / `sshd` 及以 `ssh-` / `-ssh` 连接的变体
const SSH_PATTERNS: &[&str] = &["ssh", "sshd"];
/// 匹配 `nginx` / `apache` / `http` 及变体
const WEB_PATTERNS: &[&str] = &["nginx", "apache", "http"];
/// 匹配 `ftp` / `vsftpd` / `proftpd` 及变体
const FTP_PATTERNS: &[&str] = &["ftp", "vsftpd", "proftpd"];
/// 匹配 `postfix` / `dovecot` / `mail` 及变体
const MAIL_PATTERNS: &[&str] = &["postfix", "dovecot", "mail"];
/// 匹配 `frp` (Fast Reverse Proxy) 及变体
const FRP_PATTERNS: &[&str] = &["frp"];
/// 匹配 `mysql` / `mariadb` / `postgres` 及变体
const DB_PATTERNS: &[&str] = &["mysql", "mariadb", "postgres"];

// ============================================================================
// 服务名称匹配
// ============================================================================

/// 判断 `name` 是否命中 `patterns` 中的任一服务类型。
pub(crate) fn is_service_name_match(name: &str, patterns: &[&str]) -> bool {
    for &pattern in patterns {
        let name_len = name.len();
        let pattern_len = pattern.len();

        if name == pattern {
            return true;
        }

        if name_len > pattern_len
            && name.starts_with(pattern)
            && name.as_bytes()[pattern_len] == b'-'
        {
            return true;
        }

        if name_len > pattern_len
            && name.ends_with(pattern)
            && name.as_bytes()[name_len - pattern_len - 1] == b'-'
        {
            return true;
        }

        if let Some(pos) = name.find(pattern) {
            let at_start = pos == 0;
            let at_end = pos + pattern_len == name_len;
            let char_before_ok = at_start || name.as_bytes()[pos - 1] == b'-';
            let char_after_ok = at_end || name.as_bytes()[pos + pattern_len] == b'-';

            if char_before_ok && char_after_ok {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// 智能默认参数
// ============================================================================

pub(crate) fn apply_service_defaults(
    jail: &mut Jail,
    _name: &str,
    _service_type: &str,
    retries: u32,
    findtime: u32,
    ban_time: i32,
) {
    if !jail.max_retries_set {
        jail.max_retries = retries;
    }
    if !jail.findtime_set {
        jail.findtime = findtime;
    }
    if !jail.ban_time_set {
        jail.ban_time = ban_time;
    }
}

/// 对单个 jail 套用智能默认。匹配优先级: SSH > WEB > FTP > MAIL > FRP > DB > 全局默认。
///
/// 默认值表见模块级文档。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
/// - `default_max_retries` / `default_findtime` / `default_ban_time`: 全局默认
///   (用户未匹配任何服务类型时使用)
pub fn apply_smart_defaults_single(
    jail: &mut Jail,
    default_max_retries: u32,
    default_findtime: u32,
    default_ban_time: i32,
) {
    let name = jail.name.clone();

    if is_service_name_match(&name, SSH_PATTERNS) {
        apply_service_defaults(jail, &name, "SSH", 5, 600, 900);
    } else if is_service_name_match(&name, WEB_PATTERNS) {
        apply_service_defaults(jail, &name, "WEB", 10, 300, 1800);
    } else if is_service_name_match(&name, FTP_PATTERNS) {
        apply_service_defaults(jail, &name, "FTP", 5, 600, 1800);
    } else if is_service_name_match(&name, MAIL_PATTERNS) {
        apply_service_defaults(jail, &name, "MAIL", 5, 300, 1800);
    } else if is_service_name_match(&name, FRP_PATTERNS) {
        apply_service_defaults(jail, &name, "FRP", 10, 300, 1800);
    } else if is_service_name_match(&name, DB_PATTERNS) {
        apply_service_defaults(jail, &name, "DB", 3, 300, 3600);
    } else {
        if !jail.max_retries_set {
            jail.max_retries = default_max_retries;
        }
        if !jail.findtime_set {
            jail.findtime = default_findtime;
        }
        if !jail.ban_time_set {
            jail.ban_time = default_ban_time;
        }
    }
}

/// 对整个 `Config` 的所有 jail 套用智能默认。`main()` 在 `parse_config_file`
/// 之后、`config_validate` 之前调用。
///
/// # Arguments
/// - `target_cfg`: 待处理的配置 (可变引用)
pub fn apply_smart_defaults_to_all(target_cfg: &mut Config) {
    let default_max_retries = target_cfg.default_max_retries;
    let default_findtime = target_cfg.default_findtime;
    let default_ban_time = target_cfg.default_ban_time;
    for jail in &mut target_cfg.jails {
        apply_smart_defaults_single(
            jail,
            default_max_retries,
            default_findtime,
            default_ban_time,
        );
    }
}
