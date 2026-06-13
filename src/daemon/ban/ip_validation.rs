//! IP 验证模块
//!
//! # 核心职责
//!
//! - 校验 IPv4 字符串:拒绝 loopback/broadcast/multicast/全 0 地址
//! - 校验通用 IP (IPv4 或 IPv6):先尝试 IPv4,失败回退 IPv6
//! - IPv6 时额外拒绝 loopback/multicast/unspecified/link-local
//! IP 合法性校验 (拒绝 loopback/multicast/link-local 等)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

// ============================================================================
// IP 验证
// ValidatedIp 结构
// ============================================================================

/// 校验通过的 IP 描述。
#[derive(Debug, Clone)]
pub struct ValidatedIp {
    /// 标准库 `IpAddr` 表示
    pub ip: IpAddr,
    /// 仅 IPv4 有效 (网络字节序)。IPv6 时为 0
    pub ip_num: u32,
}

// ============================================================================
// IP 验证函数
// ============================================================================

/// 校验 IPv4 字符串。拒绝 loopback / broadcast / multicast / 全 0 地址。
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
/// - 地址属于保留段 (0.0.0.0 / 255.255.255.255 / 127.0.0.0/8 / 224.0.0.0/4)
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
    if ip_num_host == 0
        || ip_num_host == 0xFFFF_FFFF
        || first_octet == 127
        || (224..=239).contains(&first_octet)
    {
        bail!("rejected IPv4 address: {ip} (loopback/broadcast/multicast)");
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

/// 校验通过的 IP 描述。
#[derive(Debug, Clone)]
pub struct ValidatedIp {
    /// 标准库 `IpAddr` 表示
    pub ip: IpAddr,
    /// 仅 IPv4 有效 (网络字节序)。IPv6 时为 0
    pub ip_num: u32,
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
