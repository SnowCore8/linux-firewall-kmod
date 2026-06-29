//! IP 验证模块
//!
//! # 核心职责
//!
//! - 校验 IPv4 字符串：拒绝 loopback/broadcast/multicast/全 0 地址
//! - 校验通用 IP（IPv4 或 IPv6）：先尝试 IPv4，失败回退 IPv6
//! - IPv6 时额外拒绝 loopback/multicast/unspecified/link-local
//! - 分类 IP 为内网/外网（用于阈值放宽策略）

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

// ============================================================================
// ValidatedIp 结构
// ============================================================================

/// 校验通过的 IP 描述。
#[derive(Debug, Clone)]
pub struct ValidatedIp {
    /// 标准库 `IpAddr` 表示
    pub ip: IpAddr,
    /// 仅 IPv4 有效（网络字节序）。IPv6 时为 0
    pub ip_num: u32,
}

// ============================================================================
// IP 分类函数
// ============================================================================

/// 判断 IP 是否为内网地址（私有地址段）
///
/// # 内网地址范围
/// - IPv4: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - IPv6: fc00::/7 (unique local addresses)
///
/// # Arguments
/// - `ip`: IP 地址字符串
///
/// # Returns
/// - `true`: 内网地址
/// - `false`: 外网地址或无效地址
pub fn is_internal_ip(ip: &str) -> bool {
    // 尝试 IPv4
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        let octets = addr.octets();
        let first = octets[0];
        let second = octets[1];

        // 10.0.0.0/8
        if first == 10 {
            return true;
        }
        // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if first == 172 && (16..=31).contains(&second) {
            return true;
        }
        // 192.168.0.0/16
        if first == 192 && second == 168 {
            return true;
        }
        return false;
    }

    // 尝试 IPv6
    if let Ok(addr) = ip.parse::<Ipv6Addr>() {
        let segments = addr.segments();
        let first = segments[0];

        // fc00::/7 (unique local addresses)
        // 前 7 位为 1111110，即 0xFC00 - 0xFDFF
        if (first & 0xFE00) == 0xFC00 {
            return true;
        }
        return false;
    }

    false
}

// ============================================================================
// IP 验证函数
// ============================================================================

/// 校验 IPv4 字符串。拒绝 loopback / broadcast / multicast / link-local / 全 0 地址。
///
/// # Arguments
/// - `ip`: 待校验的 IPv4 字符串
///
/// # Returns
/// - `Ok(ValidatedIp)`: 校验通过,内含原生 `IpAddr` 和网络字节序数值
///
/// # Errors
/// - 长度越界 (空或 ≥16 字节, `INET_ADDRSTRLEN`)
/// - 解析失败 (非合法 IPv4 点分十进制)
/// - 地址属于保留段 (0.0.0.0 / 255.255.255.255 / 127.0.0.0/8 / 224.0.0.0/4 / 169.254.0.0/16)
pub fn validate_ipv4(ip: &str) -> Result<ValidatedIp> {
    if ip.is_empty() || ip.len() >= 16 {
        // INET_ADDRSTRLEN = 16
        bail!("invalid IPv4 length");
    }

    let addr: Ipv4Addr = ip
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid IPv4: {e}"))?;
    let ip_num = u32::from_ne_bytes(addr.octets());
    let ip_num_host = u32::from_be(ip_num);

    let first_octet = (ip_num_host >> 24) & 0xFF;
    let second_octet = (ip_num_host >> 16) & 0xFF;
    if ip_num_host == 0
        || ip_num_host == 0xFFFF_FFFF
        || first_octet == 127
        || (224..=239).contains(&first_octet)
        || (first_octet == 169 && second_octet == 254)
    {
        bail!("rejected IPv4 address: {ip} (loopback/broadcast/multicast/link-local)");
    }

    Ok(ValidatedIp {
        ip: IpAddr::V4(addr),
        ip_num,
    })
}

/// 校验通用 IP (IPv4 或 IPv6) 字符串。先尝试 IPv4,失败回退 IPv6。
///
/// IPv6 时额外拒绝 loopback / multicast / unspecified / link-local (`fe80::/10`)。
///
/// # Arguments
/// - `ip`: 待校验的 IP 字符串
///
/// # Errors
/// - 长度越界 (空或 ≥46 字节, `INET6_ADDRSTRLEN`)
/// - 解析失败 (既不是合法 IPv4 也不是合法 IPv6)
/// - 地址属于 IPv6 保留段
pub fn validate_ip(ip: &str) -> Result<ValidatedIp> {
    if ip.is_empty() || ip.len() >= 46 {
        // INET6_ADDRSTRLEN = 46
        bail!("invalid IP length");
    }

    if let Ok(validated) = validate_ipv4(ip) {
        return Ok(validated);
    }

    let addr: Ipv6Addr = ip
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid IPv6: {e}"))?;

    if addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unspecified()
        || (addr.segments()[0] & 0xFFC0 == 0xFE80)
    {
        // fe80::/10 link-local: 前 10 位为 1111111010
        bail!("rejected IPv6 address: {ip} (loopback/multicast/unspecified/link-local)");
    }

    Ok(ValidatedIp {
        ip: IpAddr::V6(addr),
        ip_num: 0,
    })
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ipv4_valid() {
        let v = validate_ipv4("192.168.1.100").unwrap();
        assert!(matches!(v.ip, IpAddr::V4(_)));
        assert!(v.ip_num != 0);
    }

    #[test]
    fn validate_ipv4_reject_loopback() {
        assert!(validate_ipv4("127.0.0.1").is_err());
    }

    #[test]
    fn validate_ipv4_reject_broadcast() {
        assert!(validate_ipv4("255.255.255.255").is_err());
    }

    #[test]
    fn validate_ipv4_reject_zero() {
        assert!(validate_ipv4("0.0.0.0").is_err());
    }

    #[test]
    fn validate_ipv4_reject_multicast() {
        assert!(validate_ipv4("224.0.0.1").is_err());
        assert!(validate_ipv4("239.255.255.255").is_err());
    }

    #[test]
    fn validate_ipv4_reject_link_local() {
        assert!(validate_ipv4("169.254.0.1").is_err());
        assert!(validate_ipv4("169.254.255.255").is_err());
        // 边界：169.253 和 169.255 不属于链路本地
        assert!(validate_ipv4("169.253.0.1").is_ok());
        assert!(validate_ipv4("169.255.0.1").is_ok());
    }

    #[test]
    fn validate_ip_ipv6_valid() {
        let v = validate_ip("2001:db8::1").unwrap();
        assert!(matches!(v.ip, IpAddr::V6(_)));
        assert_eq!(v.ip_num, 0);
    }

    #[test]
    fn validate_ip_ipv6_reject_loopback() {
        assert!(validate_ip("::1").is_err());
    }

    #[test]
    fn validate_ip_ipv6_reject_unspecified() {
        assert!(validate_ip("::").is_err());
    }

    #[test]
    fn validate_ip_ipv6_reject_link_local() {
        assert!(validate_ip("fe80::1").is_err());
    }

    #[test]
    fn validate_ip_invalid() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("999.999.999.999").is_err());
    }
}
