//! 表单验证工具函数

/// 验证 IPv4 地址格式
pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        p.parse::<u8>().is_ok()
    })
}

/// 验证 IPv6 地址格式(简化版,检查包含冒号)
pub fn is_valid_ipv6(ip: &str) -> bool {
    ip.contains(':') && ip.len() >= 2
}

/// 验证 IP 地址(IPv4 或 IPv6)
pub fn is_valid_ip(ip: &str) -> bool {
    is_valid_ipv4(ip) || is_valid_ipv6(ip)
}

/// 验证 CIDR 格式(IPv4/8 或 IPv6/64)
pub fn is_valid_cidr(cidr: &str) -> bool {
    if let Some((ip, prefix)) = cidr.split_once('/') {
        if !is_valid_ip(ip) {
            return false;
        }
        if let Ok(p) = prefix.parse::<u32>() {
            if is_valid_ipv4(ip) {
                return p <= 32;
            } else if is_valid_ipv6(ip) {
                return p <= 128;
            }
        }
        false
    } else {
        // 允许不带前缀的 CIDR(默认/32 或/128)
        is_valid_ip(cidr)
    }
}

/// 验证时长范围(0-86400 秒,0=永久)
pub fn is_valid_duration(duration: &str) -> bool {
    if duration.is_empty() {
        return true; // 空值使用默认值
    }
    if let Ok(d) = duration.parse::<i64>() {
        return d >= 0 && d <= 86400; // 0 秒到 24 小时
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_ipv4() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(is_valid_ipv4("10.0.0.0"));
        assert!(!is_valid_ipv4("999.999.999.999"));
        assert!(!is_valid_ipv4("abc"));
        assert!(!is_valid_ipv4("1.2.3"));
    }

    #[test]
    fn test_is_valid_ipv6() {
        assert!(is_valid_ipv6("::1"));
        assert!(is_valid_ipv6("fe80::1"));
        assert!(is_valid_ipv6("fd9f:92ca:fd45::b2c"));
        assert!(!is_valid_ipv6("192.168.1.1"));
    }

    #[test]
    fn test_is_valid_cidr() {
        assert!(is_valid_cidr("192.168.8.0/24"));
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("::1/128"));
        assert!(is_valid_cidr("fd9f:92ca:fd45::b2c/128"));
        assert!(!is_valid_cidr("192.168.1.1/33"));
        assert!(!is_valid_cidr("::1/129"));
        assert!(!is_valid_cidr("invalid"));
    }

    #[test]
    fn test_is_valid_duration() {
        assert!(is_valid_duration(""));
        assert!(is_valid_duration("0"));
        assert!(is_valid_duration("600"));
        assert!(is_valid_duration("86400"));
        assert!(!is_valid_duration("-1"));
        assert!(!is_valid_duration("86401"));
        assert!(!is_valid_duration("abc"));
    }
}
