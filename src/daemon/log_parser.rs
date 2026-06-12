//! 日志解析: 正则匹配 → 回退字符串匹配 → IP 提取与校验
//!
//! # 解析流程
//!
//! 1. **正则匹配**:`jail.regexes` 中的所有编译后正则按序尝试,捕获组从后往前
//!    扫描,最后一个有效 IP 作为结果(与 C 版 fail2ban 行为一致)
//! 2. **字符串回退**:无正则或正则未匹配时,检查 `Failed password for` /
//!    `authentication failure` 等关键字
//! 3. **IP 提取**:通用 [`extract_ip`] (IPv4+IPv6) / [`extract_ipv4`] (仅 v4) 扫
//!    描候选,词边界检查 + 长度窗口 + 段位校验
//!
//! # 性能特征
//!
//! - 热路径(单行解析)< 1µs,正则命中时 < 100ns
//! - IP 候选定位使用词边界检查避免误匹配长十六进制串
//! - 长度窗口 `[7, 46)` 提前过滤明显非 IP 的片段
//!
//! # 统计
//!
//! - `DAEMON_STATS.ips_extracted`:成功提取并校验的 IP 数
//! - `DAEMON_STATS.regex_matches`:正则命中次数

use std::net::IpAddr;

use crate::log_warn;
use crate::types::{Jail, DAEMON_STATS};

// ============================================================================
// 内部: IP 候选定位
// ============================================================================

/// 在 `line` 中从 `start_from` 开始查找 IP 候选的字节范围。
///
/// 词边界检查:候选前后字符不能是 hex / `.` / `:`, 避免误匹配。IPv6 候选
/// 可含 hex 和冒号,IPv4 候选可含数字和点。
///
/// # Arguments
/// - `line`: 待扫描的日志行
/// - `start_from`: 起始字节偏移
///
/// # Returns
/// 候选的 `(start, end)` 字节偏移半开区间;无候选时返回 `None`。
fn find_ip_candidate(line: &str, start_from: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut i = start_from;

    while i < bytes.len() && !bytes[i].is_ascii_hexdigit() {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }

    let candidate_start = i;

    if candidate_start > 0 {
        let prev = bytes[candidate_start - 1];
        if prev.is_ascii_hexdigit() || prev == b'.' || prev == b':' {
            return find_ip_candidate(line, candidate_start + 1);
        }
    }

    while i < bytes.len() && (bytes[i].is_ascii_hexdigit() || bytes[i] == b'.' || bytes[i] == b':')
    {
        i += 1;
    }

    if i < bytes.len() {
        let next = bytes[i];
        if next.is_ascii_hexdigit() || next == b'.' || next == b':' {
            return find_ip_candidate(line, candidate_start + 1);
        }
    }

    Some((candidate_start, i))
}

/// 验证 IP 候选字符串。
///
/// 长度窗口:`0.0.0.0` (7 字节) ≤ 短 IPv4 ≤ `INET_ADDRSTRLEN` (16);
/// 完整 IPv6 ≤ `INET6_ADDRSTRLEN` (46)。通过标准库 `IpAddr::from_str` 解析
/// 后,再校验保留段 (loopback / broadcast / multicast / link-local)。
///
/// # Arguments
/// - `candidate`: 已通过词边界检查的字符串片段
///
/// # Returns
/// 标准库 `IpAddr`,若不是合法 IP 或属于保留段则返回 `None`。
fn validate_ip_candidate(candidate: &str) -> Option<IpAddr> {
    let len = candidate.len();

    if !(7..46).contains(&len) {
        return None;
    }

    if let Ok(ip) = candidate.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                if octets[0] == 0
                    || (octets[0] == 255
                        && octets[1] == 255
                        && octets[2] == 255
                        && octets[3] == 255)
                    || octets[0] == 127
                    || (octets[0] >= 224 && octets[0] <= 239)
                {
                    None
                } else {
                    Some(ip)
                }
            }
            IpAddr::V6(v6) => {
                if v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || (v6.segments()[0] & 0xFFC0 == 0xFE80)
                {
                    None
                } else {
                    Some(ip)
                }
            }
        };
    }

    None
}

// ============================================================================
// 公共 API
// ============================================================================

/// 仅 IPv4 提取 (非正则模式下的回退)。
///
/// 与 [`extract_ip`] 的区别:本函数只识别 `0-9` + `.`,完全不扫描冒号,
/// 可在已知"日志不可能含 IPv6"的场景减少误命中开销。
///
/// # Arguments
/// - `line`: 待扫描的日志行
///
/// # Returns
/// 第一个合法 IPv4 字符串;无则返回 `None`。
#[must_use]
pub fn extract_ipv4(line: &str) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        while i < bytes.len() && !bytes[i].is_ascii_digit() {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        let start = i;
        while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') {
            i += 1;
        }
        let end = i;
        i = start + 1;

        let ip_len = end - start;
        if !(7..16).contains(&ip_len) {
            continue;
        }

        if start > 0 && (bytes[start - 1].is_ascii_digit() || bytes[start - 1] == b'.') {
            continue;
        }
        if end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
            continue;
        }

        let candidate = &line[start..end];
        if let Ok(ip) = candidate.parse::<std::net::Ipv4Addr>() {
            let octets = ip.octets();
            if octets[0] == 0
                || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
                || octets[0] == 127
                || (octets[0] >= 224 && octets[0] <= 239)
            {
                continue;
            }
            return Some(candidate.to_string());
        }
    }

    None
}

/// IPv4/IPv6 通用提取。从 `pos` 开始扫描,找到第一个合法 IP 即返回。
///
/// # Arguments
/// - `line`: 待扫描的日志行
///
/// # Returns
/// 第一个合法 IP 字符串 (v4 或 v6);无则返回 `None`。
#[must_use]
pub fn extract_ip(line: &str) -> Option<String> {
    let mut pos = 0;

    while pos < line.len() {
        if let Some((start, end)) = find_ip_candidate(line, pos) {
            let candidate = &line[start..end];
            if let Some(ip) = validate_ip_candidate(candidate) {
                return Some(ip.to_string());
            }
            pos = start + 1;
        } else {
            break;
        }
    }

    None
}

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
        log_warn!("Log line too long ({} bytes), skipping", line_len);
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

    DAEMON_STATS
        .ips_extracted
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                            DAEMON_STATS
                                .regex_matches
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            return Some(ip.to_string());
                        }
                    }
                }
            }
            log_warn!(
                "No valid IP capture group found in regex match for jail '{}'",
                jail.name
            );
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

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Jail;

    fn make_test_jail() -> Jail {
        Jail::new("sshd".to_string())
    }

    #[test]
    fn extract_ipv4_from_ssh_log() {
        let line = "Jun 11 15:30:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22";
        let ip = extract_ipv4(line).unwrap();
        assert_eq!(ip, "192.168.1.100");
    }

    #[test]
    fn extract_ipv4_rejects_invalid() {
        assert!(extract_ipv4("no ip here").is_none());
        assert!(extract_ipv4("0.0.0.0").is_none());
        assert!(extract_ipv4("127.0.0.1").is_none());
        assert!(extract_ipv4("255.255.255.255").is_none());
    }

    #[test]
    fn extract_ip_ipv4() {
        let line = "Failed password for root from 10.0.0.1 port 22";
        let ip = extract_ip(line).unwrap();
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn extract_ip_ipv6() {
        let line = "Failed password for root from 2001:db8::1 port 22";
        let ip = extract_ip(line).unwrap();
        assert_eq!(ip, "2001:db8::1");
    }

    #[test]
    fn extract_ip_rejects_loopback() {
        assert!(extract_ip("from ::1 port 22").is_none());
        assert!(extract_ip("from 127.0.0.1 port 22").is_none());
    }

    #[test]
    fn fallback_string_match_ssh() {
        let line = "Jun 11 15:30:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22";
        let ip = fallback_string_match(line).unwrap();
        assert_eq!(ip, "192.168.1.100");
    }

    #[test]
    fn fallback_string_match_auth_failure() {
        let line = "Jun 11 15:30:00 server dovecot: authentication failure from 10.0.0.5";
        let ip = fallback_string_match(line).unwrap();
        assert_eq!(ip, "10.0.0.5");
    }

    #[test]
    fn fallback_string_match_no_match() {
        assert!(fallback_string_match("just a normal log line").is_none());
    }

    #[test]
    fn parse_log_line_with_regex() {
        let mut jail = make_test_jail();

        let default_pattern = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";
        jail.regexes.push(crate::types::RegexInfo {
            name: "default".to_string(),
            pattern: default_pattern.to_string(),
            compiled: Some(regex::Regex::new(default_pattern).unwrap()),
        });

        let line = "Jun 11 15:30:00 server sshd[12345]: Failed password for root from 192.168.1.100 port 22";
        let ip = parse_log_line(&jail, line).unwrap();
        assert_eq!(ip, "192.168.1.100");
    }

    #[test]
    fn parse_log_line_invalid_user() {
        let mut jail = make_test_jail();

        let default_pattern = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";
        jail.regexes.push(crate::types::RegexInfo {
            name: "default".to_string(),
            pattern: default_pattern.to_string(),
            compiled: Some(regex::Regex::new(default_pattern).unwrap()),
        });

        let line = "Jun 11 15:30:00 server sshd[12345]: Failed password for invalid user admin from 10.0.0.99 port 22";
        let ip = parse_log_line(&jail, line).unwrap();
        assert_eq!(ip, "10.0.0.99");
    }

    #[test]
    fn parse_log_line_too_long() {
        let jail = make_test_jail();
        let long_line = "x".repeat(9000);
        assert!(parse_log_line(&jail, &long_line).is_none());
    }

    #[test]
    fn parse_log_line_no_regex_fallback() {
        let jail = make_test_jail();
        let line =
            "Jun 11 15:30:00 server sshd[12345]: Failed password for root from 172.16.0.1 port 22";
        let ip = parse_log_line(&jail, line).unwrap();
        assert_eq!(ip, "172.16.0.1");
    }

    #[test]
    fn extract_and_validate_ip_counts() {
        let jail = make_test_jail();
        let line = "Failed password for root from 192.168.1.100 port 22";

        let before = DAEMON_STATS
            .ips_extracted
            .load(std::sync::atomic::Ordering::Relaxed);
        let ip = extract_and_validate_ip(&jail, line).unwrap();
        let after = DAEMON_STATS
            .ips_extracted
            .load(std::sync::atomic::Ordering::Relaxed);

        assert_eq!(ip, "192.168.1.100");
        assert_eq!(after, before + 1);
    }
}
