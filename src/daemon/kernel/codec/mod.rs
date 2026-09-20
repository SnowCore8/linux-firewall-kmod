//! netlink 线格式编解码：契约与实现之间的唯一转义层。
//!
//! 本模块不持有 socket、不做 I/O，只负责「字节 ↔ 语义类型」。全部字节布局、
//! 字段偏移与页容量都取自 [`crate::contract`]（`contract/generated/netlink_contract.rs`），
//! 因此「契约与实现一致」由**编译器**保证，而不是靠人肉比对或注释约定。
//!
//! # 报文形状
//!
//! 一个 netlink 数据报的字节流是 `[nlmsghdr 16 字节][自定义载荷]`。自定义载荷
//! 自身以 12 字节公共头 [`crate::contract::MsgHdr`] 开头，其 `msg_len` 是
//! **载荷总长（含该 12 字节头、不含 nlmsghdr）**——与内核 `fw_nl_init_hdr` 的
//! 写法一致。前 16 字节的剥离与构造由 [`crate::kernel::transport`] 负责。
//!
//! # 字节序
//!
//! 契约承诺全部多字节整数为**大端**。本模块对每个多字节字段显式
//! `from_be`/`to_be`，不依赖宿主字节序，也不依赖 `packed` 结构体的内存表示。
//! 唯一的例外是 [`decode_packed`]：它按字节搬运 `packed` 结构体以获得契约给出的
//! 字段**偏移**，搬完即逐字段转成宿主字节序；未经转换的原始字节不会流出本模块。

use std::fmt;
use std::net::IpAddr;

use crate::contract;

pub mod messages;

pub use messages::*;

/// 自定义公共头长度（`MsgHdr::WIRE_SIZE`，契约给出为 12）。
pub const HDR_LEN: usize = contract::MsgHdr::WIRE_SIZE;

/// 线格式魔数。
pub const MAGIC: u32 = contract::FW_NL_MAGIC;

// ============================================================================
// 错误
// ============================================================================

/// 解码失败。每一种失败都对应一个可判定的、能真实触发的线上情形。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 载荷短于所需长度。
    TooShort {
        /// 所需字节数。
        need: usize,
        /// 实得字节数。
        got: usize,
    },
    /// 魔数不是 [`MAGIC`]。
    BadMagic {
        /// 实得的魔数。
        got: u32,
    },
    /// 声明的长度与实际长度不符。
    ///
    /// 两种用法：头解析时 `declared` 是头里声明的 `msg_len`，`got` 是整段载荷长度；
    /// 定长结构体解析时 `declared` 是契约给出的期望字节数，`got` 是实得字节数。
    /// 旧实现解析了 `msg_len` 却从不校验，长度错位只能表现为后续解析失败。
    LenMismatch {
        /// 声明的（期望）长度。
        declared: u16,
        /// 实际长度。
        got: usize,
    },
    /// 公共头里的 `msg_type` 取值不在契约的 `MsgType` 里。
    UnknownMsgType {
        /// 实得的类型值。
        got: u16,
    },
    /// 地址族取值不在契约的 `AddrFamily` 里。
    UndefinedAddrFamily {
        /// 实得的地址族值。
        got: u8,
    },
    /// 封禁动作取值不在契约的 `BanAction` 里。
    UndefinedBanAction {
        /// 实得的动作值。
        got: u8,
    },
    /// 白名单动作取值不在契约的 `WhitelistAction` 里。
    UndefinedWhitelistAction {
        /// 实得的动作值。
        got: u8,
    },
    /// 分页响应的条目数超出契约给出的单页上限。
    TailCountOutOfRange {
        /// 头里声明的条目数。
        count: u32,
        /// 契约允许的单页上限。
        max: usize,
    },
    /// 分页响应的尾部字节数与声明的条目数不符（数据被截断或有多余）。
    ///
    /// 这是「静默截断」缺陷的直接防线：旧实现只按 `count` 走一遍，多出的字节
    /// 或不足的字节都不会被发现。
    TailLenMismatch {
        /// 声明的条目数。
        count: u32,
        /// 按声明应有的尾部字节数。
        need: usize,
        /// 实得的尾部字节数。
        got: usize,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { need, got } => write!(f, "载荷过短：需要 {need} 字节，实得 {got}"),
            Self::BadMagic { got } => write!(f, "魔数不匹配：0x{got:08x}"),
            Self::LenMismatch { declared, got } => {
                write!(f, "msg_len 声明的 {declared} 与实际 {got} 不符")
            }
            Self::UnknownMsgType { got } => write!(f, "未知消息类型：{got}"),
            Self::UndefinedAddrFamily { got } => write!(f, "未定义的地址族：{got}"),
            Self::UndefinedBanAction { got } => write!(f, "未定义的封禁动作：{got}"),
            Self::UndefinedWhitelistAction { got } => write!(f, "未定义的白名单动作：{got}"),
            Self::TailCountOutOfRange { count, max } => {
                write!(f, "分页条目数 {count} 超出契约单页上限 {max}")
            }
            Self::TailLenMismatch { count, need, got } => {
                write!(f, "{count} 条尾部条目需要 {need} 字节，实得 {got} 字节")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

// ============================================================================
// 公共头
// ============================================================================

/// 解析后的自定义公共头。
///
/// `msg_type_raw` 保留原始整数而不是直接给出枚举：内核主动推送的事件与响应
/// 都用同一个 socket 送来，认不出的类型必须能被上层**计数并告警**，不能因为
/// 枚举转换失败就丢掉整条报文。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WireHdr {
    /// `msg_type` 的原始取值。
    pub msg_type_raw: u16,
    /// 载荷总长（含 12 字节公共头）。
    pub msg_len: u16,
    /// 请求/响应配对序列号；0 表示不参与配对。
    pub seq: u32,
}

impl WireHdr {
    /// 把原始类型值转成契约枚举；未定义时返回 `None`。
    #[must_use]
    pub fn msg_type(self) -> Option<contract::MsgType> {
        contract::MsgType::from_raw(self.msg_type_raw)
    }

    /// 该头是否参与请求/响应配对。
    #[must_use]
    pub const fn is_correlated(self) -> bool {
        self.seq != 0
    }
}

/// 解析自定义公共头，返回头与载荷体（头之后的部分）。
///
/// `data` 必须是**整段自定义载荷**（即 nlmsghdr 之后的全部字节）。函数会校验
/// 头里声明的 `msg_len` 与实际长度一致；不一致直接报错，而不是任其错位解析。
///
/// # Errors
///
/// 长度不足、魔数不符或 `msg_len` 与实际长度不符时返回 [`DecodeError`]。
pub fn decode_header(data: &[u8]) -> Result<(WireHdr, &[u8]), DecodeError> {
    if data.len() < HDR_LEN {
        return Err(DecodeError::TooShort {
            need: HDR_LEN,
            got: data.len(),
        });
    }
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != MAGIC {
        return Err(DecodeError::BadMagic { got: magic });
    }
    let msg_type_raw = u16::from_be_bytes([data[4], data[5]]);
    let msg_len = u16::from_be_bytes([data[6], data[7]]);
    let seq = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    if usize::from(msg_len) != data.len() {
        return Err(DecodeError::LenMismatch {
            declared: msg_len,
            got: data.len(),
        });
    }
    Ok((
        WireHdr {
            msg_type_raw,
            msg_len,
            seq,
        },
        &data[HDR_LEN..],
    ))
}

/// 组装公共头。`msg_len` 是载荷总长（含本头），与内核侧一致。
const fn header(msg_type: contract::MsgType, seq: u32, msg_len: u16) -> contract::MsgHdr {
    contract::MsgHdr {
        magic: MAGIC.to_be(),
        msg_type: msg_type.to_raw().to_be(),
        msg_len: msg_len.to_be(),
        seq: seq.to_be(),
    }
}

/// 组装一条「只有头、无载荷」的报文（`StatsQuery` / `AnalysisQuery` /
/// `DaemonRegister`）。
fn encode_header_only(msg_type: contract::MsgType, seq: u32) -> Vec<u8> {
    let wire = contract::MsgHdr::WIRE_SIZE;
    let raw = header(msg_type, seq, u16::try_from(wire).unwrap_or(u16::MAX));
    packed_bytes(&raw, wire)
}

// ============================================================================
// packed 结构体的字节搬运
// ============================================================================

/// 把 `packed` 结构体按字节搬出成 Vec。
///
/// 契约生成的报文结构体全是 `#[repr(C, packed)]` 且字段都是整数/字节数组，
/// 无内部指针、无填充，故「按字节读取」即等价于「网络字节流的字段序」。
///
/// 返回值里的多字节字段仍是**大端字节串**，调用方负责逐字段转换；这是本模块
/// 内部约定，函数不导出。
fn packed_bytes<T>(value: &T, wire: usize) -> Vec<u8> {
    let mut out = vec![0u8; wire];
    // SAFETY: value 指向一个大小恰为 wire 的 packed 结构体（wire 由契约的
    // WIRE_SIZE 给出，调用点保证与类型匹配）；out 有 wire 字节可写，两块内存
    // 不重叠，且源只读。
    unsafe {
        std::ptr::copy_nonoverlapping((value as *const T).cast::<u8>(), out.as_mut_ptr(), wire);
    }
    out
}

/// 把定长载荷按字节搬进 `packed` 结构体，以获得契约给出的字段偏移。
///
/// 契约对**报文**给出的 `FIELD_OFFSETS` 含 12 字节公共头，而接收侧拿到的是头之后
/// 的载荷体，故写入位置相对结构体起点偏移 [`HDR_LEN`]；对**尾部条目**（无公共头）
/// 则从 0 写入。两种情况都先整块归零，避免 `assume_init` 面对未初始化的头字节。
///
/// # Errors
///
/// `body.len() != expect` 时返回 [`DecodeError::LenMismatch`]。
fn decode_at<T>(body: &[u8], expect: usize, at: usize) -> Result<T, DecodeError> {
    if body.len() != expect {
        return Err(DecodeError::LenMismatch {
            declared: u16::try_from(expect).unwrap_or(u16::MAX),
            got: body.len(),
        });
    }
    let wire = at + expect;
    let mut out = std::mem::MaybeUninit::<T>::uninit();
    // SAFETY: body 恰有 expect 字节且只读；out 是未初始化的 T，其大小等于
    // at + expect（调用点以契约的 WIRE_SIZE 保证），故 dst 可写 wire 字节且
    // 目标区间全在 out 内。归零后每个字节都已定义（T 的字段全是整数/字节数组，
    // packed 无填充），再把 body 覆盖到偏移 at，assume_init 成立。
    unsafe {
        let dst = out.as_mut_ptr().cast::<u8>();
        std::ptr::write_bytes(dst, 0, wire);
        std::ptr::copy_nonoverlapping(body.as_ptr(), dst.add(at), expect);
        Ok(out.assume_init())
    }
}

/// 解码一条**报文**的载荷体（公共头之后的部分），字段偏移含公共头。
fn decode_packed_body<T>(body: &[u8], wire: usize) -> Result<T, DecodeError> {
    decode_at::<T>(body, wire - HDR_LEN, HDR_LEN)
}

/// 解码一个**尾部条目**（无公共头），字段偏移从 0 起。
fn decode_packed_elem<T>(body: &[u8], wire: usize) -> Result<T, DecodeError> {
    decode_at::<T>(body, wire, 0)
}

// ============================================================================
// 定长字段辅助
// ============================================================================

/// 定长 NUL 结尾字符串字段 → `String`（丢掉尾部 NUL）。
fn fixed_str<const N: usize>(raw: &[u8; N]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(N);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// `String` → 定长 NUL 结尾字符串字段。
///
/// 超出容量时按契约「定长字节数组」的语义截断，并**预留一个字节**放结束符，
/// 保证解码侧一定读到 NUL 结尾。
fn fixed_bytes<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let src = s.as_bytes();
    let n = src.len().min(N.saturating_sub(1));
    out[..n].copy_from_slice(&src[..n]);
    out
}

/// IP → 契约地址族的原始取值。
fn family_raw(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => contract::AddrFamily::Inet.to_raw(),
        IpAddr::V6(_) => contract::AddrFamily::Inet6.to_raw(),
    }
}

/// IP → 契约的 16 字节地址缓冲（IPv4 占前 4 字节，其余为 0）。
fn addr_bytes(ip: IpAddr) -> contract::addr16 {
    let mut out = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => out[..4].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.copy_from_slice(&v6.octets()),
    }
    out
}

/// 地址族 + 16 字节缓冲 → IP。地址族未定义时返回 `None`。
fn addr_ip(family_raw: u8, raw: &contract::addr16) -> Option<IpAddr> {
    match contract::AddrFamily::from_raw(family_raw)? {
        contract::AddrFamily::Inet => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            raw[0], raw[1], raw[2], raw[3],
        ))),
        contract::AddrFamily::Inet6 => Some(IpAddr::V6(std::net::Ipv6Addr::from(*raw))),
    }
}

// ============================================================================
// 接收侧统一入口
// ============================================================================

/// 内核 → daemon 的全部报文，解码成宿主字节序的语义类型。
#[derive(Debug, Clone)]
pub enum Incoming {
    /// DDoS 违规事件。
    DdosEvent(Box<DdosEvent>),
    /// 封禁状态变更。
    BanStateChange(Box<BanStateChange>),
    /// 白名单状态变更。
    WhitelistStateChange(Box<WhitelistStateChange>),
    /// 命令执行失败。
    CmdResult(Box<CmdResult>),
    /// 配置更新确认。
    ConfigAck(Box<ConfigAck>),
    /// procfs 配置变更广播。
    ConfigChange(Box<ConfigChange>),
    /// 统计响应。
    StatsResponse(Box<StatsResponse>),
    /// 封禁列表分页响应。
    ListBansResponse(Box<PagedBans>),
    /// 白名单分页响应。
    ListWhitelistResponse(Box<PagedWhitelist>),
    /// 速率分页响应。
    ListRatesResponse(Box<PagedRates>),
    /// 分析数据响应。
    AnalysisResponse(Box<AnalysisResponse>),
    /// 注册确认/拒绝。
    DaemonRegisterAck(Box<DaemonRegisterAck>),
}

impl Incoming {
    /// 报文对应的类型。
    #[must_use]
    pub fn msg_type_name(&self) -> &'static str {
        match self {
            Self::DdosEvent(_) => "DdosEvent",
            Self::BanStateChange(_) => "BanStateChange",
            Self::WhitelistStateChange(_) => "WhitelistStateChange",
            Self::CmdResult(_) => "CmdResult",
            Self::ConfigAck(_) => "ConfigAck",
            Self::ConfigChange(_) => "ConfigChange",
            Self::StatsResponse(_) => "StatsResponse",
            Self::ListBansResponse(_) => "ListBansResponse",
            Self::ListWhitelistResponse(_) => "ListWhitelistResponse",
            Self::ListRatesResponse(_) => "ListRatesResponse",
            Self::AnalysisResponse(_) => "AnalysisResponse",
            Self::DaemonRegisterAck(_) => "DaemonRegisterAck",
        }
    }
}

/// 按类型解码一条接收报文。
///
/// 只接受内核 → daemon 方向的类型；请求类型出现在接收方向属于协议违例，
/// 返回 [`DecodeError::UnknownMsgType`]。
///
/// # Errors
///
/// 类型未知或任一字段解码失败时返回 [`DecodeError`]。
pub fn decode_incoming(msg_type: contract::MsgType, body: &[u8]) -> Result<Incoming, DecodeError> {
    Ok(match msg_type {
        contract::MsgType::DdosEvent => Incoming::DdosEvent(Box::new(DdosEvent::decode(body)?)),
        contract::MsgType::BanStateChange => {
            Incoming::BanStateChange(Box::new(BanStateChange::decode(body)?))
        }
        contract::MsgType::WhitelistStateChange => {
            Incoming::WhitelistStateChange(Box::new(WhitelistStateChange::decode(body)?))
        }
        contract::MsgType::CmdResult => Incoming::CmdResult(Box::new(CmdResult::decode(body)?)),
        contract::MsgType::ConfigAck => Incoming::ConfigAck(Box::new(ConfigAck::decode(body)?)),
        contract::MsgType::ConfigChange => {
            Incoming::ConfigChange(Box::new(ConfigChange::decode(body)?))
        }
        contract::MsgType::StatsResponse => {
            Incoming::StatsResponse(Box::new(StatsResponse::decode(body)?))
        }
        contract::MsgType::ListBansResponse => {
            Incoming::ListBansResponse(Box::new(PagedBans::decode(body)?))
        }
        contract::MsgType::ListWhitelistResponse => {
            Incoming::ListWhitelistResponse(Box::new(PagedWhitelist::decode(body)?))
        }
        contract::MsgType::ListRatesResponse => {
            Incoming::ListRatesResponse(Box::new(PagedRates::decode(body)?))
        }
        contract::MsgType::AnalysisResponse => {
            Incoming::AnalysisResponse(Box::new(AnalysisResponse::decode(body)?))
        }
        contract::MsgType::DaemonRegisterAck => {
            Incoming::DaemonRegisterAck(Box::new(DaemonRegisterAck::decode(body)?))
        }
        other => {
            return Err(DecodeError::UnknownMsgType {
                got: other.to_raw(),
            });
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一条最小合法报文（只有头）。
    fn header_only(msg_type: contract::MsgType, seq: u32) -> Vec<u8> {
        encode_header_only(msg_type, seq)
    }

    #[test]
    fn header_len_matches_contract() {
        assert_eq!(HDR_LEN, 12);
    }

    #[test]
    fn header_round_trips_type_and_seq() {
        let bytes = header_only(contract::MsgType::StatsQuery, 0x0102_0304);
        let (hdr, body) = decode_header(&bytes).expect("合法头应能解析");
        assert_eq!(hdr.msg_type(), Some(contract::MsgType::StatsQuery));
        assert_eq!(hdr.seq, 0x0102_0304);
        assert_eq!(hdr.msg_len, 12);
        assert!(body.is_empty());
    }

    #[test]
    fn short_payload_is_rejected_with_requirement() {
        let err = decode_header(&[0u8; 11]).expect_err("11 字节不足以构成公共头");
        assert_eq!(err, DecodeError::TooShort { need: 12, got: 11 });
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let mut bytes = header_only(contract::MsgType::StatsQuery, 1);
        bytes[0] = 0xff;
        let err = decode_header(&bytes).expect_err("魔数被改坏应被拒");
        assert!(matches!(err, DecodeError::BadMagic { .. }));
    }

    #[test]
    fn declared_len_disagreeing_with_actual_is_rejected() {
        // 旧实现解析 msg_len 后直接丢弃，长度错位只能拖到后续解析失败；
        // 这里必须在头解析阶段就拒绝，且两个方向都要能拒绝。
        let mut too_long = header_only(contract::MsgType::StatsQuery, 1);
        too_long[6..8].copy_from_slice(&64u16.to_be_bytes());
        assert_eq!(
            decode_header(&too_long).expect_err("声明过长应被拒"),
            DecodeError::LenMismatch {
                declared: 64,
                got: 12
            }
        );

        let mut too_short = header_only(contract::MsgType::StatsQuery, 1);
        too_short[6..8].copy_from_slice(&4u16.to_be_bytes());
        assert_eq!(
            decode_header(&too_short).expect_err("声明过短应被拒"),
            DecodeError::LenMismatch {
                declared: 4,
                got: 12
            }
        );
    }

    #[test]
    fn unknown_msg_type_is_observable_not_silently_dropped() {
        let mut bytes = header_only(contract::MsgType::StatsQuery, 1);
        bytes[4..6].copy_from_slice(&999u16.to_be_bytes());
        let (hdr, _body) = decode_header(&bytes).expect("头本身是合法的");
        assert_eq!(hdr.msg_type(), None, "未知类型必须能被上层看见");
        assert_eq!(hdr.msg_type_raw, 999);
    }

    #[test]
    fn unpairable_header_reports_seq_zero() {
        let bytes = header_only(contract::MsgType::StatsQuery, 0);
        let (hdr, _) = decode_header(&bytes).expect("合法头");
        assert!(!hdr.is_correlated());
    }

    #[test]
    fn fixed_str_stops_at_first_nul() {
        let raw = *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
        assert_eq!(fixed_str(&raw), "sshd");
    }

    #[test]
    fn fixed_bytes_always_leaves_a_terminator() {
        let out: [u8; 4] = fixed_bytes("abcdef");
        assert_eq!(out, *b"abc\0");
    }

    #[test]
    fn addr_round_trips_both_families() {
        for ip in ["192.0.2.7", "2001:db8::1"] {
            let parsed: IpAddr = ip.parse().expect("测试地址应可解析");
            let raw = addr_bytes(parsed);
            assert_eq!(addr_ip(family_raw(parsed), &raw), Some(parsed));
        }
    }

    #[test]
    fn undefined_addr_family_yields_no_ip() {
        assert_eq!(addr_ip(77, &[0u8; 16]), None);
    }

    #[test]
    fn decode_packed_rejects_wrong_length() {
        let err = decode_packed_elem::<contract::MsgHdr>(&[0u8; 11], contract::MsgHdr::WIRE_SIZE)
            .expect_err("长度不符应被拒");
        assert_eq!(
            err,
            DecodeError::LenMismatch {
                declared: 12,
                got: 11
            }
        );
    }

    #[test]
    fn decode_incoming_rejects_request_direction_types() {
        let err = decode_incoming(contract::MsgType::BanIp, &[])
            .expect_err("BanIp 是发送方向，不应出现在接收侧");
        assert_eq!(
            err,
            DecodeError::UnknownMsgType {
                got: contract::MsgType::BanIp.to_raw()
            }
        );
    }
}
