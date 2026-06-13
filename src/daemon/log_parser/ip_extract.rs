//! IP 候选定位 + IPv4/IPv6 提取 + 校验

use std::net::IpAddr;

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
pub(super) fn validate_ip_candidate(candidate: &str) -> Option<IpAddr> {
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
