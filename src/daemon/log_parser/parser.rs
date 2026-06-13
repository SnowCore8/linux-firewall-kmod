//! 日志行解析: 正则匹配 → 回退字符串匹配 → IP 提取与校验

use std::net::IpAddr;
use std::sync::atomic::Ordering;

use crate::types::{Jail, DAEMON_STATS};

use super::ip_extract::{extract_ip, validate_ip_candidate};

// ============================================================================
// 公共 API
// ============================================================================

/// 解析日志行:先尝试 jail 的正则,失败时回退字符串匹配。
///
/// 行长度 > 8192 直接返回 `None` 并记 WARN,避免异常超长行阻塞主循环。
///
/// # Arguments
/// - `jail`: 用于匹配的正则集
/// - `line`: 单行日志 (不含 `\n`)
///
/// # Returns
/// 提取到的 IP 字符串;无匹配或超长时返回 `None`。
pub fn parse_log_line(jail: &Jail, line: &str) -> Option<String> {
    let line_len = line.len();
    if line_len > 8192 {
        return None;
    }

    if !jail.regexes.is_empty() {
        if let Some(ip) = match_regex(jail, line) {
            return Some(ip);
        }
    }

    fallback_string_match(line)
}

/// 顶层入口:解析 + 校验 + 累加统计。
///
/// 供 [`crate::file_monitor::process_single_line`] 调用,完成"行 → IP"全过程。
///
/// # Arguments
/// - `jail`: 用于匹配的正则集
/// - `line`: 单行日志
///
/// # Returns
/// 校验通过的 IP 字符串;`DAEMON_STATS.ips_extracted` 自增 1。
pub fn extract_and_validate_ip(jail: &Jail, line: &str) -> Option<String> {
    let ip_buf = parse_log_line(jail, line)?;

    match ip_buf.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let octets = v4.octets();
            if octets[0] == 0
                || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
                || octets[0] == 127
                || (octets[0] >= 224 && octets[0] <= 239)
            {
                return None;
            }
        }
        Ok(IpAddr::V6(v6)) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xFFC0 == 0xFE80)
            {
                return None;
            }
        }
        Err(_) => return None,
    }

    DAEMON_STATS.ips_extracted.fetch_add(1, Ordering::Relaxed);
    Some(ip_buf)
}

// ============================================================================
// 内部: 正则匹配 / 回退
// ============================================================================

/// 从后往前遍历捕获组,最后一个有效 IP 作为结果。
///
/// 与 C 版 fail2ban 行为一致:日志格式为 `Failed password for root from
/// 192.168.1.100 port 22`,主匹配组 (整体) + 子匹配组 (user / IP) 共 3 组,
/// 倒序扫描确保取到最右侧、最具体的 IP,避免误把用户名中的数字当 IP。
///
/// 成功匹配时累加 `DAEMON_STATS.regex_matches`;所有捕获组都无效时记 WARN。
fn match_regex(jail: &Jail, line: &str) -> Option<String> {
    for regex_info in &jail.regexes {
        let Some(re) = &regex_info.compiled else {
            continue;
        };

        if let Some(captures) = re.captures(line) {
            for g in (1..captures.len()).rev() {
                if let Some(m) = captures.get(g) {
                    let capture = m.as_str();
                    let capture_len = capture.len();
                    if (7..46).contains(&capture_len) && capture.as_bytes()[0].is_ascii_hexdigit() {
                        if let Some(ip) = validate_ip_candidate(capture) {
                            DAEMON_STATS.regex_matches.fetch_add(1, Ordering::Relaxed);
                            return Some(ip.to_string());
                        }
                    }
                }
            }
        }
    }

    None
}

/// 字符串关键字回退。命中 `Failed password for` (sshd) 或
/// `authentication failure` (PAM/dovecot) 后调 [`extract_ip`]。
fn fallback_string_match(line: &str) -> Option<String> {
    if line.contains("Failed password for") || line.contains("authentication failure") {
        extract_ip(line)
    } else {
        None
    }
}
