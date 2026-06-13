//! 日志解析: 正则匹配 → 回退字符串匹配 → IP 提取与校验
//!
//! # 模块结构
//!
//! - `ip_extract`: IP 候选定位 + IPv4/IPv6 提取 + 校验
//! - `parser`: 日志行解析 + 正则匹配 + 统计
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

mod ip_extract;
mod parser;

pub use ip_extract::{extract_ip, extract_ipv4};
pub use parser::{extract_and_validate_ip, parse_log_line};

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Jail, DAEMON_STATS};

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
