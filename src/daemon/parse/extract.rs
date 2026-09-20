//! IP 提取：候选定位、校验、v4/v6 通用提取。**纯函数，无全局状态。**
//!
//! 语义与旧 `log_parser::ip_extract` 逐条对齐（词边界、长度窗口、保留段拒绝），
//! 因为它是判定链路上唯一「从任意文本里认出 IP」的环节，行为漂移会直接改变封禁
//! 对象——对照测试见本文件末尾。
//!
//! 与旧实现的两点差别只在**接口形状**，不在语义：
//! - 返回 [`IpAddr`] 而不是 `String`：调用方需要的是一个 IP，不是它的文本；
//!   需要文本时自己 `to_string()`，从而省掉热路径上的字符串分配。
//! - 不读写 `DAEMON_STATS`：计数由调用方按结果累加，本模块保持可重入、可单测。

use std::net::{IpAddr, Ipv4Addr};

/// 长度窗口下界：短 IPv4 最短 7 字节（`0.0.0.0`）。
const MIN_CANDIDATE_LEN: usize = 7;
/// 长度窗口上界（不含）：完整 IPv6 最长为 `INET6_ADDRSTRLEN` = 46。
const MAX_CANDIDATE_LEN: usize = 46;

/// 在 `line` 中从 `start_from` 开始查找 IP 候选的字节范围。
///
/// 词边界检查：候选前后字符不能是 hex / `.` / `:`，避免把长十六进制串或
/// `1.2.3.4.5` 这类非 IP 片段误判成 IP。
///
/// 先跳过所有非 hex 字符定位起点；起点前一字节若是 hex / `.` / `:`，说明这是某个
/// 更长 token 的中间部分，从起点后移一位继续找（递归）。
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

/// 校验一个已通过词边界检查的候选串。
///
/// 长度窗口 `[7, 46)`；解析后拒绝保留段：v4 的 `0.0.0.0` / `127/8` / 组播
/// `224-239` / 广播 `255.255.255.255`，v6 的 loopback / unspecified / multicast /
/// `fe80::/10` 链路本地。
#[must_use]
pub fn validate_candidate(candidate: &str) -> Option<IpAddr> {
    let len = candidate.len();
    if !(MIN_CANDIDATE_LEN..MAX_CANDIDATE_LEN).contains(&len) {
        return None;
    }

    let ip = candidate.parse::<IpAddr>().ok()?;
    if is_reserved(ip) {
        None
    } else {
        Some(ip)
    }
}

/// 是否为**永不作为封禁对象**的保留地址。
///
/// 抽成独立函数，使「提取」与「判定」两侧共用同一份判据，避免两处逻辑漂移
/// （这正是结构问题 M 在另一处的形态）。
#[must_use]
pub fn is_reserved(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_reserved_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 链路本地。
                || (v6.segments()[0] & 0xFFC0 == 0xFE80)
        }
    }
}

/// IPv4 保留段判据。
#[must_use]
fn is_reserved_v4(v4: Ipv4Addr) -> bool {
    let octets = v4.octets();
    octets[0] == 0                                   // 0.0.0.0/8「本网络」
        || (octets[0] == 255 && octets[1] == 255 && octets[2] == 255 && octets[3] == 255)
        || octets[0] == 127                          // 环回
        || (224..=239).contains(&octets[0]) // 组播
}

/// 从 `line` 中提取第一个合法 IP（v4 或 v6）。
///
/// 命中保留段时**继续向后扫描**（而不是整体放弃），与旧实现一致：一行里可能有
/// `from 127.0.0.1` 这类噪声在前、真实来源 IP 在后。
#[must_use]
pub fn extract_ip(line: &str) -> Option<IpAddr> {
    let mut pos = 0;
    while pos < line.len() {
        let (start, end) = find_ip_candidate(line, pos)?;
        if let Some(ip) = validate_candidate(&line[start..end]) {
            return Some(ip);
        }
        pos = start + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试用 IP 必须合法")
    }

    #[test]
    fn extracts_ipv4_from_ssh_log() {
        let line =
            "Jun 11 15:30:00 host sshd[1]: Failed password for root from 192.168.1.100 port 22";
        assert_eq!(extract_ip(line), Some(ip("192.168.1.100")));
    }

    #[test]
    fn extracts_ipv6() {
        assert_eq!(
            extract_ip("from 2001:db8::1 port 22"),
            Some(ip("2001:db8::1"))
        );
    }

    #[test]
    fn skips_reserved_addresses_and_keeps_scanning() {
        // 前面是噪声（环回），后面才是真实来源：不能因为第一个候选被拒就放弃整行。
        assert_eq!(
            extract_ip("from 127.0.0.1 then from 10.0.0.1"),
            Some(ip("10.0.0.1"))
        );
        assert_eq!(extract_ip("from ::1 port 22"), None);
        assert_eq!(extract_ip("no ip here"), None);
    }

    #[test]
    fn rejects_malformed_shapes() {
        // 词边界：`1.2.3.4.5` 与 `abcd1.2.3.4` 都不是合法 IP 片段。
        assert_eq!(extract_ip("1.2.3.4.5"), None);
        assert_eq!(extract_ip("deadbeef1.2.3.4"), None);
        // 长度窗口下界：`1.2.3` 太短。
        assert_eq!(extract_ip("from 1.2.3"), None);
    }

    #[test]
    fn reserved_predicate_matches_legacy_set() {
        for reserved in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "224.0.0.1",
            "239.255.255.255",
            "255.255.255.255",
            "::1",
            "::",
            "ff02::1",
            "fe80::1",
        ] {
            assert!(is_reserved(ip(reserved)), "{reserved} 应判为保留段");
        }
        for global in ["10.0.0.1", "192.168.1.100", "1.1.1.1", "2001:db8::1"] {
            assert!(!is_reserved(ip(global)), "{global} 不应判为保留段");
        }
    }

    /// 运行期对照：新 `extract_ip` 与旧 `log_parser::extract_ip` 在同一语料上必须
    /// 逐行一致。旧模块在 2.C 收尾（旧链路退役）时删除，本测试同时退役。
    #[test]
    fn parity_with_legacy_extract_ip_on_corpus() {
        let corpus: &[&str] = &[
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            "Failed password for invalid user admin from 10.0.0.99 port 22",
            "from 2001:db8::1 port 22",
            "from ::1 port 22",
            "from 127.0.0.1 then from 10.0.0.1",
            "no ip here",
            "1.2.3.4.5",
            "deadbeef1.2.3.4",
            "from 1.2.3",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "fe80::1",
            "accepted 1.1.1.1 from 2.2.2.2",
            "",
            ":::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
        ];
        for line in corpus {
            assert_eq!(
                extract_ip(line).map(|ip| ip.to_string()),
                crate::log_parser::extract_ip(line),
                "与旧实现不一致: {line:?}"
            );
        }
    }
}
