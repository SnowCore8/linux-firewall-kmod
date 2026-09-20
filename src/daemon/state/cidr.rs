//! 白名单 CIDR 的**唯一**规范化实现。
//!
//! # 为什么单独成模块
//!
//! 旧实现有三处各自构造 CIDR 缓存键，规则互不相同：
//!
//! | 位置 | 规则 |
//! |------|------|
//! | `netlink/handlers.rs` LIST 响应 | 恒拼 `"{ip}/{prefix}"` |
//! | `netlink/handlers.rs` 状态变更事件 | `/32`、`/128`、`/0` 时**不拼**前缀 |
//! | `ban/mod.rs::build_cidr_key` | IPv6 `/0` 改写为 `/128`，IPv4 `/32` 与 `/0` 不加前缀 |
//!
//! 键即用户可见的 `cidr` 字段，也是 `DELETE /api/v1/whitelist/:cidr` 的路径参数，
//! 同一子网因此可能拿到两个不同的键：LIST 覆盖与事件移除互不抵消。
//!
//! # 判据来自内核，不是约定
//!
//! 内核在非热路径上先把地址按 `prefix_len` 归一化再入表（`fw_addr_normalize`，
//! `fw_types.h`）：白名单表存的是**主机位清零后的网络地址**，查表只做整体比较。
//! 所以 daemon 侧若不归一化主机位，HTTP 写入的 `10.0.0.5/24` 与内核实际存的
//! `10.0.0.0/24` 就永远匹配不上。而「精确主机条目」的判据在内核里是
//! `fw_wl_is_full_prefix`（IPv4 `/32`、IPv6 `/128`，`fw_wl.c`）。
//!
//! 归一化输出因此固定为 `"{网络地址}/{prefix_len}"`，无特例：
//! `10.0.0.5/24` → `10.0.0.0/24`，`10.0.0.1` → `10.0.0.1/32`，
//! `2001:db8::1/64` → `2001:db8::/64`，`::1` → `::1/128`。
//!
//! # 键是类型，不是字符串
//!
//! [`CidrKey`] 只能经 [`CidrKey::new`] 或 [`CidrKey::parse`] 构造，两者都过同一
//! 条规范化路径。缓存以 `CidrKey`（而非 `String`）作为键类型后，「插了一个未
//! 规范化的键」这件事不再可表达——这正是缺陷 M 的根因。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// IPv4 前缀长度上限（与内核 `fw_wl_max_prefix` 一致）。
const IPV4_MAX_PREFIX: u8 = 32;
/// IPv6 前缀长度上限（与内核 `fw_wl_max_prefix` 一致）。
const IPV6_MAX_PREFIX: u8 = 128;

/// CIDR 解析/规范化失败。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// 输入为空（或只有空白）。
    Empty,
    /// 斜杠超过一个，无法判断哪段是前缀。
    MultipleSlashes,
    /// 地址部分无法解析。
    InvalidAddr(String),
    /// 前缀部分不是合法整数。
    InvalidPrefix(String),
    /// 前缀长度超出该地址族上限。
    PrefixTooLarge {
        /// 地址族名称（`"IPv4"` / `"IPv6"`）。
        family: &'static str,
        /// 上限值。
        max: u8,
        /// 实际给出的值。
        got: u16,
    },
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "CIDR 不能为空"),
            Self::MultipleSlashes => write!(f, "CIDR 含多个 '/'，无法确定前缀长度"),
            Self::InvalidAddr(s) => write!(f, "无法解析地址部分: {s}"),
            Self::InvalidPrefix(s) => write!(f, "无法解析前缀长度: {s}"),
            Self::PrefixTooLarge { family, max, got } => {
                write!(f, "{family} 前缀长度上限 {max}，实得 {got}")
            }
        }
    }
}

impl std::error::Error for CidrError {}

/// 规范化后的白名单键，形如 `"{网络地址}/{prefix_len}"`。
///
/// 构造即规范化：外部无法构造出未归一化的键，故 `HashMap<CidrKey, _>` 里不可能
/// 同时存在同一子网的两个写法。
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CidrKey(String);

impl CidrKey {
    /// 由地址与前缀长度构造（主机位清零，恒带 `/prefix_len`）。
    ///
    /// 前缀长度超过该地址族上限时会被**钳制**到上限而不是报错：netlink 路径上的
    /// 取值来自内核，钳制保证「超出即按全主机处理」这一退化行为可预测，而不是
    /// 生成一个永远匹配不上的键。
    #[must_use]
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        match addr {
            IpAddr::V4(v4) => {
                let prefix = prefix_len.min(IPV4_MAX_PREFIX);
                let network = mask_v4(v4, prefix);
                Self(format!("{network}/{prefix}"))
            }
            IpAddr::V6(v6) => {
                let prefix = prefix_len.min(IPV6_MAX_PREFIX);
                let network = mask_v6(v6, prefix);
                Self(format!("{network}/{prefix}"))
            }
        }
    }

    /// 解析文本 CIDR；无 `/` 时按该地址族的全长前缀处理。
    ///
    /// # Errors
    ///
    /// 空输入、斜杠过多、地址或前缀无法解析、前缀超上限时返回 [`CidrError`]。
    pub fn parse(text: &str) -> Result<Self, CidrError> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(CidrError::Empty);
        }

        let mut parts = trimmed.split('/');
        let addr_part = parts.next().unwrap_or_default();
        let prefix_part = parts.next();
        if parts.next().is_some() {
            return Err(CidrError::MultipleSlashes);
        }

        let addr = IpAddr::from_str(addr_part)
            .map_err(|_| CidrError::InvalidAddr(addr_part.to_string()))?;

        let prefix = match prefix_part {
            None => match addr {
                IpAddr::V4(_) => IPV4_MAX_PREFIX,
                IpAddr::V6(_) => IPV6_MAX_PREFIX,
            },
            Some(s) => {
                let parsed = s
                    .trim()
                    .parse::<u16>()
                    .map_err(|_| CidrError::InvalidPrefix(s.trim().to_string()))?;
                let (family, max) = match addr {
                    IpAddr::V4(_) => ("IPv4", IPV4_MAX_PREFIX),
                    IpAddr::V6(_) => ("IPv6", IPV6_MAX_PREFIX),
                };
                if parsed > u16::from(max) {
                    return Err(CidrError::PrefixTooLarge {
                        family,
                        max,
                        got: parsed,
                    });
                }
                // 上面已断言 `parsed <= max`，故此处不会截断。
                parsed as u8
            }
        };

        Ok(Self::new(addr, prefix))
    }

    /// 规范化后的文本形式（`"{网络地址}/{prefix_len}"`）。
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CidrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CidrKey {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// 清掉 IPv4 主机位。
fn mask_v4(addr: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::from(0_u32);
    }
    let mask = u32::MAX << (IPV4_MAX_PREFIX - prefix);
    Ipv4Addr::from(u32::from(addr) & mask)
}

/// 清掉 IPv6 主机位。
fn mask_v6(addr: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    let mut octets = addr.octets();
    let full = usize::from(prefix / 8);
    let rem = prefix % 8;
    let start = if rem == 0 {
        full
    } else {
        octets[full] &= 0xFF_u8 << (8 - rem);
        full + 1
    };
    for b in &mut octets[start..] {
        *b = 0;
    }
    Ipv6Addr::from(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试输入应为合法 IP")
    }

    #[test]
    fn an_ipv4_subnet_zeroes_the_host_bits() {
        // 内核存的是归一化后的网络地址，daemon 必须对齐，否则永远匹配不上。
        assert_eq!(CidrKey::new(ip("10.0.0.5"), 24).as_str(), "10.0.0.0/24");
        assert_eq!(
            CidrKey::parse("10.0.0.5/24").expect("可解析").as_str(),
            "10.0.0.0/24"
        );
    }

    #[test]
    fn an_already_normalized_subnet_is_unchanged() {
        assert_eq!(
            CidrKey::parse("10.0.0.0/24").expect("可解析").as_str(),
            "10.0.0.0/24"
        );
    }

    #[test]
    fn a_bare_ipv4_address_becomes_a_full_prefix_host_entry() {
        // 「精确主机条目」的判据在内核里是 fw_wl_is_full_prefix：IPv4 /32。
        assert_eq!(
            CidrKey::parse("10.0.0.1").expect("可解析").as_str(),
            "10.0.0.1/32"
        );
        assert_eq!(CidrKey::new(ip("10.0.0.1"), 32).as_str(), "10.0.0.1/32");
    }

    #[test]
    fn a_bare_ipv6_address_becomes_a_full_prefix_host_entry() {
        assert_eq!(CidrKey::parse("::1").expect("可解析").as_str(), "::1/128");
        assert_eq!(CidrKey::new(ip("::1"), 128).as_str(), "::1/128");
    }

    #[test]
    fn a_default_route_keeps_its_slash_zero_prefix() {
        // 旧实现三处对 /0 给出三个答案（裸地址、/0、/128）；本实现只有一个。
        assert_eq!(
            CidrKey::parse("0.0.0.0/0").expect("可解析").as_str(),
            "0.0.0.0/0"
        );
        assert_eq!(CidrKey::parse("::/0").expect("可解析").as_str(), "::/0");
        // 任意 IPv4 加 /0 都归一化到同一个键。
        assert_eq!(CidrKey::new(ip("203.0.113.7"), 0).as_str(), "0.0.0.0/0");
    }

    #[test]
    fn an_ipv6_subnet_zeroes_the_host_bits() {
        assert_eq!(
            CidrKey::parse("2001:db8::1/64").expect("可解析").as_str(),
            "2001:db8::/64"
        );
    }

    #[test]
    fn an_ipv6_prefix_that_is_not_a_byte_multiple_is_masked_correctly() {
        // /60 落在第 8 字节的高 4 位，必须按位掩码而不是整字节。
        assert_eq!(
            CidrKey::parse("2001:db8:1:2f::1/60")
                .expect("可解析")
                .as_str(),
            "2001:db8:1:20::/60"
        );
    }

    #[test]
    fn normalization_is_idempotent() {
        for text in [
            "10.0.0.5/24",
            "10.0.0.1",
            "2001:db8::1/64",
            "::/0",
            "0.0.0.0/0",
        ] {
            let once = CidrKey::parse(text).expect("可解析");
            let twice = CidrKey::parse(once.as_str()).expect("规范化结果应仍可解析");
            assert_eq!(once, twice, "{text} 二次规范化应不变");
        }
    }

    #[test]
    fn the_same_subnet_written_two_ways_yields_one_key() {
        // 缺陷 M 的核心断言：同一子网的两种写法必须落到同一个键上。
        let a = CidrKey::parse("10.0.0.5/24").expect("可解析");
        let b = CidrKey::parse("10.0.0.0/24").expect("可解析");
        assert_eq!(a, b);
    }

    #[test]
    fn a_prefix_beyond_the_family_maximum_is_refused_on_the_text_path() {
        assert_eq!(
            CidrKey::parse("10.0.0.1/33"),
            Err(CidrError::PrefixTooLarge {
                family: "IPv4",
                max: 32,
                got: 33
            })
        );
        assert_eq!(
            CidrKey::parse("::1/129"),
            Err(CidrError::PrefixTooLarge {
                family: "IPv6",
                max: 128,
                got: 129
            })
        );
    }

    #[test]
    fn a_prefix_beyond_the_family_maximum_is_clamped_on_the_struct_path() {
        // netlink 路径的取值来自内核，钳制而不是报错：退化行为可预测。
        assert_eq!(CidrKey::new(ip("10.0.0.1"), 200).as_str(), "10.0.0.1/32");
        assert_eq!(CidrKey::new(ip("::1"), 200).as_str(), "::1/128");
    }

    #[test]
    fn malformed_input_is_reported_rather_than_guessed() {
        assert_eq!(CidrKey::parse("   "), Err(CidrError::Empty));
        assert_eq!(
            CidrKey::parse("10.0.0.1/24/8"),
            Err(CidrError::MultipleSlashes)
        );
        assert_eq!(
            CidrKey::parse("not-an-ip"),
            Err(CidrError::InvalidAddr("not-an-ip".to_string()))
        );
        assert_eq!(
            CidrKey::parse("10.0.0.1/x"),
            Err(CidrError::InvalidPrefix("x".to_string()))
        );
    }

    #[test]
    fn whitespace_around_a_valid_cidr_is_tolerated() {
        assert_eq!(
            CidrKey::parse("  10.0.0.5/24  ").expect("可解析").as_str(),
            "10.0.0.0/24"
        );
    }

    #[test]
    fn the_key_formats_with_a_slash_even_for_host_entries() {
        // 键形态恒为「网络地址/前缀」，前端展示与 DELETE 路径参数都取这个值。
        let key = CidrKey::parse("192.168.1.7").expect("可解析");
        assert!(key.as_str().contains('/'));
        assert_eq!(key.to_string(), key.as_str());
    }
}
