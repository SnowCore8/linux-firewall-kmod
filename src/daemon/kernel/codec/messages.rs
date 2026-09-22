//! 契约里各消息类型的语义结构：解码成宿主字节序，或编码成线格式。
//!
//! 约定：
//!
//! - **接收方向**（内核 → daemon）每个类型一个 `decode`，逐字段从契约生成的结构体
//!   取值——字段名与偏移都由契约给出，本文件不复述。多字节字段一律 `from_be`，
//!   对外暴露的是宿主字节序的普通类型；地址族、动作等枚举走
//!   `from_raw`，未定义取值表现为 `None` 而不是默默当成某个分支。
//! - **发送方向**（daemon → 内核）每个类型一个 `encode`，先按契约字段类型填一份
//!   `packed` 结构体（多字节字段 `to_be`），再按字节搬出。`msg_len` 一律写成
//!   契约的 `WIRE_SIZE`，即「载荷总长（含 12 字节公共头）」。
//! - 变长响应（封禁/白名单/速率三张表）的尾部条目数与字节数必须**精确**相符，
//!   页上限取自契约的 `MAX_TAIL_ENTRIES`。

use std::net::IpAddr;

use super::{
    addr_bytes, addr_ip, decode_at, decode_packed_body, decode_packed_elem, encode_header_only,
    family_raw, fixed_bytes, fixed_str, header, packed_bytes, DecodeError, HDR_LEN,
};
use crate::contract;

/// 定长报文的**载荷体**（公共头之后）字节数。
///
/// 契约里的 `WIRE_SIZE` 含 12 字节公共头，而接收侧拿到的是头之后的部分，故定长
/// 解码一律以 `WIRE_SIZE - HDR_LEN` 为期望长度。
const fn body_len(wire: usize) -> usize {
    wire - HDR_LEN
}

/// 定长结构体字节数 → `msg_len` 字段取值。
///
/// 契约里最大的报文（`AnalysisResponse` 4756、分页上限 65508）都小于 `u16` 上限；
/// 越界立即失败，而不是静默截断。
fn wire_u16(wire: usize) -> u16 {
    u16::try_from(wire).expect("契约报文长度应落在 u16 上限之内")
}

// ============================================================================
// 接收方向：内核 → daemon
// ============================================================================

/// DDoS 违规事件（`MsgType::DdosEvent`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DdosEvent {
    /// 地址族；取值未定义时为 `None`。
    pub af: Option<contract::AddrFamily>,
    /// 违规原因（定长字符串）。
    pub reason: String,
    /// 触发时该 IP 的实测速率（包/秒）。
    pub rate_pps: u32,
    /// 触发 IP；地址族未定义时为 `None`。
    pub addr: Option<IpAddr>,
}

impl DdosEvent {
    /// 解码载荷体（公共头之后的部分）。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::DdosEvent>(body, contract::DdosEvent::WIRE_SIZE)?;
        let reason_field = raw.reason;
        let addr_field = raw.addr;
        Ok(Self {
            af: contract::AddrFamily::from_raw(raw.af),
            reason: fixed_str(&reason_field),
            rate_pps: u32::from_be(raw.rate_pps),
            addr: addr_ip(raw.af, &addr_field),
        })
    }
}

/// 封禁状态变更（`MsgType::BanStateChange`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanStateChange {
    /// 动作（封禁/解封）；取值未定义时为 `None`。
    pub action: Option<contract::BanAction>,
    /// 地址族；取值未定义时为 `None`。
    pub af: Option<contract::AddrFamily>,
    /// 封禁时长（秒）。**0 表示永久**——这是事件路径的历史语义。
    pub duration_secs: u32,
    /// 涉及 IP；地址族未定义时为 `None`。
    pub addr: Option<IpAddr>,
    /// 封禁原因。
    pub reason: String,
    /// Jail 名称；空串表示由 daemon 推断。
    pub jail_name: String,
    /// 累计丢弃包数。
    pub packets_dropped: u64,
    /// 累计接受包数。
    pub packets_accepted: u64,
    /// 当前封禁总数。
    pub current_bans: u32,
    /// 当前白名单总数。
    pub whitelist_count: u32,
}

impl BanStateChange {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::BanStateChange>(
            body,
            contract::BanStateChange::WIRE_SIZE,
        )?;
        let addr_field = raw.addr;
        let reason_field = raw.reason;
        let jail_field = raw.jail_name;
        Ok(Self {
            action: contract::BanAction::from_raw(raw.action),
            af: contract::AddrFamily::from_raw(raw.af),
            duration_secs: u32::from_be(raw.duration_secs),
            addr: addr_ip(raw.af, &addr_field),
            reason: fixed_str(&reason_field),
            jail_name: fixed_str(&jail_field),
            packets_dropped: u64::from_be(raw.packets_dropped),
            packets_accepted: u64::from_be(raw.packets_accepted),
            current_bans: u32::from_be(raw.current_bans),
            whitelist_count: u32::from_be(raw.whitelist_count),
        })
    }

    /// 该事件是否表示「永久封禁」。
    #[must_use]
    pub const fn is_permanent(&self) -> bool {
        self.duration_secs == 0
    }
}

/// 白名单状态变更（`MsgType::WhitelistStateChange`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistStateChange {
    /// 动作（增/删）；取值未定义时为 `None`。
    pub action: Option<contract::WhitelistAction>,
    /// 地址族；取值未定义时为 `None`。
    pub af: Option<contract::AddrFamily>,
    /// 前缀长度。IPv4 由掩码换算，IPv6 直接使用。
    pub prefix_len: u8,
    /// 涉及 IP；地址族未定义时为 `None`。
    pub addr: Option<IpAddr>,
    /// 限定设备；空串表示不限定。
    pub device: String,
    /// 变更后的白名单总数。
    pub whitelist_count: u32,
}

impl WhitelistStateChange {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::WhitelistStateChange>(
            body,
            contract::WhitelistStateChange::WIRE_SIZE,
        )?;
        let addr_field = raw.addr;
        let device_field = raw.device;
        Ok(Self {
            action: contract::WhitelistAction::from_raw(raw.action),
            af: contract::AddrFamily::from_raw(raw.af),
            prefix_len: raw.prefix_len,
            addr: addr_ip(raw.af, &addr_field),
            device: fixed_str(&device_field),
            whitelist_count: u32::from_be(raw.whitelist_count),
        })
    }
}

/// 命令执行失败通知（`MsgType::CmdResult`），仅失败时推送。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdResult {
    /// 触发失败的原命令类型；取值未定义时为 `None`。
    pub original_cmd: Option<contract::MsgType>,
    /// 触发失败的原命令类型的原始取值（诊断用，枚举认不出时仍有信息）。
    pub original_cmd_raw: u16,
    /// 内核返回的负值错误码。
    pub error_code: i32,
    /// 地址族；取值未定义时为 `None`。
    pub af: Option<contract::AddrFamily>,
    /// 涉及 IP；地址族未定义时为 `None`。
    pub addr: Option<IpAddr>,
}

impl CmdResult {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::CmdResult>(body, contract::CmdResult::WIRE_SIZE)?;
        let addr_field = raw.addr;
        // 契约把 `original_cmd` 声明为线上整数，必须先转宿主字节序再查枚举，
        // 否则本机小端会把 2 读成 512，动作类型直接查不出来。
        let original_cmd = u16::from_be(raw.original_cmd);
        Ok(Self {
            original_cmd: contract::MsgType::from_raw(original_cmd),
            original_cmd_raw: original_cmd,
            error_code: i32::from_be(raw.error_code),
            af: contract::AddrFamily::from_raw(raw.af),
            addr: addr_ip(raw.af, &addr_field),
        })
    }
}

/// 配置更新确认（`MsgType::ConfigAck`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigAck {
    /// 实际生效的 `ConfigFlags` 位。
    pub applied_flags: u32,
    /// 被内核拒绝的 `ConfigFlags` 位。
    pub rejected_flags: u32,
}

impl ConfigAck {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::ConfigAck>(body, contract::ConfigAck::WIRE_SIZE)?;
        Ok(Self {
            applied_flags: u32::from_be(raw.applied_flags),
            rejected_flags: u32::from_be(raw.rejected_flags),
        })
    }

    /// 内核是否全部接受。
    #[must_use]
    pub const fn fully_applied(&self) -> bool {
        self.rejected_flags == 0
    }
}

/// procfs 写入配置后的广播（`MsgType::ConfigChange`）。
///
/// 契约声明其载荷布局与 [`SetConfig`] 完全一致，故同一段字节直接按 `SetConfig`
/// 解出，而不是再抄一份逐字段代码——两份布局若哪天分叉，测试会立刻失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigChange(pub SetConfig);

impl ConfigChange {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::SetConfig>(body, contract::SetConfig::WIRE_SIZE)?;
        Ok(Self(SetConfig::from_raw(&raw)))
    }
}

/// 统计响应（`MsgType::StatsResponse`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsResponse {
    /// 当前封禁数。
    pub current_bans: u64,
    /// 累计封禁数。
    pub total_bans: u64,
    /// 累计解封数。
    pub total_unbans: u64,
    /// 当前白名单数。
    pub whitelist_count: u64,
    /// 累计丢弃包数。
    pub packets_dropped: u64,
    /// 累计接受包数。
    pub packets_accepted: u64,
}

impl StatsResponse {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::StatsResponse>(
            body,
            contract::StatsResponse::WIRE_SIZE,
        )?;
        Ok(Self {
            current_bans: u64::from_be(raw.current_bans),
            total_bans: u64::from_be(raw.total_bans),
            total_unbans: u64::from_be(raw.total_unbans),
            whitelist_count: u64::from_be(raw.whitelist_count),
            packets_dropped: u64::from_be(raw.packets_dropped),
            packets_accepted: u64::from_be(raw.packets_accepted),
        })
    }
}

/// 注册确认/拒绝（`MsgType::DaemonRegisterAck`）。
///
/// 旧实现没有这个结构、也没有解析分支，注册报文落进「未知消息类型」日志里；
/// 有了它，「注册是否被内核接受」才是可判定的事实。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonRegisterAck {
    /// 内核是否接受本次注册并建立唯一租约。
    pub accepted: bool,
}

impl DaemonRegisterAck {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::DaemonRegisterAck>(
            body,
            contract::DaemonRegisterAck::WIRE_SIZE,
        )?;
        Ok(Self {
            accepted: raw.accepted != 0,
        })
    }
}

// ============================================================================
// 变长尾部
// ============================================================================

/// 按契约给出的单页上限解析变长尾部条目。
///
/// 尾部长度必须与声明条目数**精确**相符：多出的字节与不足的字节都报错。旧实现
/// 只按 `count` 走一遍，两种情形都不会被发现，于是「表大于一页」表现为静默截断。
///
/// 元素解码交给 `decode_one`，故本函数不关心元素类型，只负责切分与计数校验。
fn decode_tail<Out>(
    tail: &[u8],
    count: u32,
    max: usize,
    elem: usize,
    decode_one: impl Fn(&[u8]) -> Result<Out, DecodeError>,
) -> Result<Vec<Out>, DecodeError> {
    let n = usize::try_from(count).unwrap_or(usize::MAX);
    if n > max {
        return Err(DecodeError::TailCountOutOfRange { count, max });
    }
    let need = n * elem;
    if tail.len() != need {
        return Err(DecodeError::TailLenMismatch {
            count,
            need,
            got: tail.len(),
        });
    }
    (0..n)
        .map(|i| decode_one(&tail[i * elem..(i + 1) * elem]))
        .collect()
}

/// 封禁列表条目（`ListBansResponse` 的尾部元素）。
///
/// 地址族与地址原始字节保留为私有字段，经 [`BanEntry::af`] / [`BanEntry::addr`]
/// 转换——「未定义地址族」因此是可见的 `None`，不会被当成 IPv4。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    af_raw: u8,
    addr_raw: contract::addr16,
    /// 是否永久封禁。
    pub is_permanent: bool,
    /// 封禁时长（秒）。
    pub duration_secs: u32,
    /// 封禁时刻（Unix 秒）。
    pub banned_at: u64,
    /// Jail 名称。
    pub jail_name: String,
    /// 封禁原因。
    pub reason: String,
}

impl BanEntry {
    fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_elem::<contract::BanEntry>(body, contract::BanEntry::WIRE_SIZE)?;
        let addr_field = raw.addr;
        let jail_field = raw.jail_name;
        let reason_field = raw.reason;
        Ok(Self {
            af_raw: raw.af,
            addr_raw: addr_field,
            is_permanent: raw.is_permanent != 0,
            duration_secs: u32::from_be(raw.duration_secs),
            banned_at: u64::from_be(raw.banned_at),
            jail_name: fixed_str(&jail_field),
            reason: fixed_str(&reason_field),
        })
    }

    /// 地址族；取值未定义时为 `None`。
    #[must_use]
    pub fn af(&self) -> Option<contract::AddrFamily> {
        contract::AddrFamily::from_raw(self.af_raw)
    }

    /// 涉及的 IP；地址族未定义时为 `None`。
    #[must_use]
    pub fn addr(&self) -> Option<IpAddr> {
        addr_ip(self.af_raw, &self.addr_raw)
    }
}

/// 白名单条目（`ListWhitelistResponse` 的尾部元素）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistEntry {
    af_raw: u8,
    addr_raw: contract::addr16,
    /// 前缀长度。
    pub prefix_len: u8,
    /// 限定设备；空串表示不限定。
    pub device: String,
}

impl WhitelistEntry {
    fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_elem::<contract::WhitelistEntry>(
            body,
            contract::WhitelistEntry::WIRE_SIZE,
        )?;
        let addr_field = raw.addr;
        let device_field = raw.device;
        Ok(Self {
            af_raw: raw.af,
            addr_raw: addr_field,
            prefix_len: raw.prefix_len,
            device: fixed_str(&device_field),
        })
    }

    /// 地址族；取值未定义时为 `None`。
    #[must_use]
    pub fn af(&self) -> Option<contract::AddrFamily> {
        contract::AddrFamily::from_raw(self.af_raw)
    }

    /// 涉及的 IP；地址族未定义时为 `None`。
    #[must_use]
    pub fn addr(&self) -> Option<IpAddr> {
        addr_ip(self.af_raw, &self.addr_raw)
    }
}

/// 速率统计条目（`ListRatesResponse` 的尾部元素）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateEntry {
    af_raw: u8,
    addr_raw: contract::addr16,
    /// 包总数。
    pub packets: u64,
    /// 字节总数。
    pub bytes: u64,
    /// SYN 包数。
    pub syn_packets: u64,
    /// UDP 包数。
    pub udp_packets: u64,
    /// ICMP 包数。
    pub icmp_packets: u64,
    /// ACK 包数。
    pub ack_packets: u64,
    /// RST 包数。
    pub rst_packets: u64,
    /// FIN 包数。
    pub fin_packets: u64,
}

impl RateEntry {
    fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_elem::<contract::RateEntry>(body, contract::RateEntry::WIRE_SIZE)?;
        let addr_field = raw.addr;
        Ok(Self {
            af_raw: raw.af,
            addr_raw: addr_field,
            packets: u64::from_be(raw.packets),
            bytes: u64::from_be(raw.bytes),
            syn_packets: u64::from_be(raw.syn_packets),
            udp_packets: u64::from_be(raw.udp_packets),
            icmp_packets: u64::from_be(raw.icmp_packets),
            ack_packets: u64::from_be(raw.ack_packets),
            rst_packets: u64::from_be(raw.rst_packets),
            fin_packets: u64::from_be(raw.fin_packets),
        })
    }

    /// 地址族；取值未定义时为 `None`。
    #[must_use]
    pub fn af(&self) -> Option<contract::AddrFamily> {
        contract::AddrFamily::from_raw(self.af_raw)
    }

    /// 涉及的 IP；地址族未定义时为 `None`。
    #[must_use]
    pub fn addr(&self) -> Option<IpAddr> {
        addr_ip(self.af_raw, &self.addr_raw)
    }
}

/// 分页响应的定长头部（三个 LIST 响应同形：`count`/`total`/`offset` 在最前面）。
///
/// 头部本身是**报文**结构体（契约 `FIELD_OFFSETS` 含公共头），故其字节同样要落到
/// 结构体偏移 [`HDR_LEN`] 处。长度不足时报 [`DecodeError::TooShort`]；超出定长部分
/// 即尾部条目。
fn decode_paged_head<T>(body: &[u8], fixed: usize) -> Result<T, DecodeError> {
    if body.len() < fixed {
        return Err(DecodeError::TooShort {
            need: fixed,
            got: body.len(),
        });
    }
    decode_at::<T>(&body[..fixed], fixed, HDR_LEN)
}

/// 封禁列表单页（`MsgType::ListBansResponse`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedBans {
    /// 内核当前总条目数。**必须保留**：丢弃它就看不出「本页之外还有数据」。
    pub total: u32,
    /// 本页起始下标。
    pub offset: u32,
    /// 本页条目。
    pub entries: Vec<BanEntry>,
}

impl PagedBans {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 定长部分长度不足、条目数超出契约单页上限，或尾部字节数与条目数不符时
    /// 返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        // 契约的 `FIXED_SIZE` 含 12 字节公共头，而载荷体不含，故须再减去 `HDR_LEN`。
        let fixed = body_len(contract::ListBansResponse::FIXED_SIZE);
        let head = decode_paged_head::<contract::ListBansResponse>(body, fixed)?;
        let entries = decode_tail(
            &body[fixed..],
            u32::from_be(head.count),
            contract::ListBansResponse::MAX_TAIL_ENTRIES,
            contract::BanEntry::WIRE_SIZE,
            BanEntry::decode,
        )?;
        Ok(Self {
            total: u32::from_be(head.total),
            offset: u32::from_be(head.offset),
            entries,
        })
    }
}

/// 白名单单页（`MsgType::ListWhitelistResponse`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedWhitelist {
    /// 内核当前总条目数。
    pub total: u32,
    /// 本页起始下标。
    pub offset: u32,
    /// 本页条目。
    pub entries: Vec<WhitelistEntry>,
}

impl PagedWhitelist {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 见 [`PagedBans::decode`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let fixed = body_len(contract::ListWhitelistResponse::FIXED_SIZE);
        let head = decode_paged_head::<contract::ListWhitelistResponse>(body, fixed)?;
        let entries = decode_tail(
            &body[fixed..],
            u32::from_be(head.count),
            contract::ListWhitelistResponse::MAX_TAIL_ENTRIES,
            contract::WhitelistEntry::WIRE_SIZE,
            WhitelistEntry::decode,
        )?;
        Ok(Self {
            total: u32::from_be(head.total),
            offset: u32::from_be(head.offset),
            entries,
        })
    }
}

/// 速率统计单页（`MsgType::ListRatesResponse`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PagedRates {
    /// 内核当前总条目数。
    pub total: u32,
    /// 本页起始下标。
    pub offset: u32,
    /// 全局平均包速率。
    pub global_pps: u64,
    /// 全局平均字节速率。
    pub global_bps: u64,
    /// 本页条目。
    pub entries: Vec<RateEntry>,
}

impl PagedRates {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 见 [`PagedBans::decode`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let fixed = body_len(contract::ListRatesResponse::FIXED_SIZE);
        let head = decode_paged_head::<contract::ListRatesResponse>(body, fixed)?;
        let entries = decode_tail(
            &body[fixed..],
            u32::from_be(head.count),
            contract::ListRatesResponse::MAX_TAIL_ENTRIES,
            contract::RateEntry::WIRE_SIZE,
            RateEntry::decode,
        )?;
        Ok(Self {
            total: u32::from_be(head.total),
            offset: u32::from_be(head.offset),
            global_pps: u64::from_be(head.global_pps),
            global_bps: u64::from_be(head.global_bps),
            entries,
        })
    }
}

/// 速率表的**完整**快照：翻完所有页之后的结果。
///
/// 与 [`PagedRates`] 的区别在于这里没有分页概念——它代表「整张表」。
/// 全局 `pps`/`bps` 取最后一页的值：它们表示「自上次查询以来的平均速率」，
/// 是同一个窗口的量，逐页累加会失真。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateSnapshot {
    /// 全局平均包速率（自上次查询以来的窗口）。
    pub global_pps: u64,
    /// 全局平均字节速率（自上次查询以来的窗口）。
    pub global_bps: u64,
    /// 全部条目，按内核给出的顺序拼接。
    pub entries: Vec<RateEntry>,
}

// ============================================================================
// 分析数据响应
// ============================================================================

/// UDP 端口分布条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPortItem {
    /// 端口号。
    pub port: u16,
    /// 包数。
    pub packets: u64,
    /// 字节数。
    pub bytes: u64,
    /// 最近出现时刻（Unix 秒）。
    pub last_seen_secs: u64,
}

/// ICMP 类型分布条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpTypeItem {
    /// ICMP type。
    pub icmp_type: u8,
    /// ICMP code。
    pub code: u8,
    /// 包数。
    pub packets: u64,
    /// 字节数。
    pub bytes: u64,
    /// 最近出现时刻（Unix 秒）。
    pub last_seen_secs: u64,
}

/// 端口扫描者 / 服务探测者条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScannerItem {
    /// 地址族；取值未定义时为 `None`。
    pub af: Option<contract::AddrFamily>,
    /// 涉及 IP；地址族未定义时为 `None`。
    pub addr: Option<IpAddr>,
    /// 端口扫描为唯一端口数；服务探测为协议种类数。
    pub metric: u32,
    /// 包数。
    pub packets: u64,
}

/// 分析数据响应（`MsgType::AnalysisResponse`），全定长。
///
/// 「条目数」与「数组容量」分开保留：内核声明的条目数可能大于本结构体的数组，
/// 上层需要看得见这个差，而不是被静默 clamp。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisResponse {
    /// 包大小分布桶。
    pub pkt_sizes: [u64; 5],
    /// TTL 分布桶。
    pub ttl_dist: [u64; 6],
    /// 分片总数。
    pub ip_frag_total: u64,
    /// 分片计数。
    pub ip_frag_count: u64,
    /// UDP 端口条目数。
    pub udp_port_count: u32,
    /// UDP 端口数组容量。
    pub udp_port_capacity: u32,
    /// UDP 端口分布。
    pub udp_ports: [UdpPortItem; 64],
    /// ICMP 类型条目数。
    pub icmp_type_count: u32,
    /// ICMP 类型数组容量。
    pub icmp_type_capacity: u32,
    /// ICMP 类型分布。
    pub icmp_types: [IcmpTypeItem; 64],
    /// 端口扫描者条目数。
    pub port_scan_count: u32,
    /// 端口扫描判定阈值。
    pub port_scan_threshold: u32,
    /// 端口扫描者。
    pub port_scanners: [ScannerItem; 20],
    /// 服务探测者条目数。
    pub service_probe_count: u32,
    /// 服务探测判定阈值。
    pub service_probe_threshold: u32,
    /// 服务探测者。
    pub service_probes: [ScannerItem; 20],
}

impl AnalysisResponse {
    /// 解码载荷体。
    ///
    /// # Errors
    ///
    /// 载荷体长度与契约不符时返回 [`DecodeError`]。
    pub fn decode(body: &[u8]) -> Result<Self, DecodeError> {
        let raw = decode_packed_body::<contract::AnalysisResponse>(
            body,
            contract::AnalysisResponse::WIRE_SIZE,
        )?;
        // packed 字段按值取出（`Copy`）后再逐个索引，避免对未对齐字段取引用。
        let pkt_sizes = raw.pkt_sizes;
        let ttl_dist = raw.ttl_dist;
        let udp_ports = raw.udp_ports;
        let icmp_types = raw.icmp_types;
        let port_scanners = raw.port_scanners;
        let service_probes = raw.service_probes;
        Ok(Self {
            pkt_sizes: pkt_sizes.map(u64::from_be),
            ttl_dist: ttl_dist.map(u64::from_be),
            ip_frag_total: u64::from_be(raw.ip_frag_total),
            ip_frag_count: u64::from_be(raw.ip_frag_count),
            udp_port_count: u32::from_be(raw.udp_port_count),
            udp_port_capacity: u32::from_be(raw.udp_port_capacity),
            udp_ports: std::array::from_fn(|i| UdpPortItem {
                port: u16::from_be(udp_ports[i].port),
                packets: u64::from_be(udp_ports[i].packets),
                bytes: u64::from_be(udp_ports[i].bytes),
                last_seen_secs: u64::from_be(udp_ports[i].last_seen_secs),
            }),
            icmp_type_count: u32::from_be(raw.icmp_type_count),
            icmp_type_capacity: u32::from_be(raw.icmp_type_capacity),
            icmp_types: std::array::from_fn(|i| IcmpTypeItem {
                icmp_type: icmp_types[i].r#type,
                code: icmp_types[i].code,
                packets: u64::from_be(icmp_types[i].packets),
                bytes: u64::from_be(icmp_types[i].bytes),
                last_seen_secs: u64::from_be(icmp_types[i].last_seen_secs),
            }),
            port_scan_count: u32::from_be(raw.port_scan_count),
            port_scan_threshold: u32::from_be(raw.port_scan_threshold),
            port_scanners: std::array::from_fn(|i| scanner_item(&port_scanners[i])),
            service_probe_count: u32::from_be(raw.service_probe_count),
            service_probe_threshold: u32::from_be(raw.service_probe_threshold),
            service_probes: std::array::from_fn(|i| scanner_item(&service_probes[i])),
        })
    }

    /// 实际有效的 UDP 端口条目数（受数组容量限制）。
    #[must_use]
    pub fn udp_ports_in_use(&self) -> usize {
        effective_len(self.udp_port_count, self.udp_ports.len())
    }

    /// 实际有效的 ICMP 类型条目数。
    #[must_use]
    pub fn icmp_types_in_use(&self) -> usize {
        effective_len(self.icmp_type_count, self.icmp_types.len())
    }

    /// 实际有效的端口扫描者条目数。
    #[must_use]
    pub fn port_scanners_in_use(&self) -> usize {
        effective_len(self.port_scan_count, self.port_scanners.len())
    }

    /// 实际有效的服务探测者条目数。
    #[must_use]
    pub fn service_probes_in_use(&self) -> usize {
        effective_len(self.service_probe_count, self.service_probes.len())
    }
}

/// 声明条目数与数组容量的有效交集。
fn effective_len(declared: u32, capacity: usize) -> usize {
    usize::try_from(declared)
        .unwrap_or(usize::MAX)
        .min(capacity)
}

/// 契约扫描者条目 → 语义条目。
fn scanner_item(raw: &contract::ScannerItem) -> ScannerItem {
    let addr_field = raw.addr;
    ScannerItem {
        af: contract::AddrFamily::from_raw(raw.af),
        addr: addr_ip(raw.af, &addr_field),
        metric: u32::from_be(raw.metric),
        packets: u64::from_be(raw.packets),
    }
}

// ============================================================================
// 发送方向：daemon → 内核
// ============================================================================

/// 封禁 IP（`MsgType::BanIp`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanIp {
    /// 目标 IP。
    pub addr: IpAddr,
    /// 封禁时长（秒）；0 表示永久。
    pub duration_secs: u32,
    /// 封禁原因。
    pub reason: String,
}

impl BanIp {
    /// 编码整条报文（含公共头），`seq` 由调用方分配。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::BanIp::WIRE_SIZE;
        let raw = contract::BanIp {
            hdr: header(contract::BanIp::MSG_TYPE, seq, wire_u16(wire)),
            af: family_raw(self.addr),
            duration_secs: self.duration_secs.to_be(),
            addr: addr_bytes(self.addr),
            reason: fixed_bytes(&self.reason),
        };
        packed_bytes(&raw, wire)
    }
}

/// 解封 IP（`MsgType::UnbanIp`）。
///
/// 契约规定它与 [`BanIp`] 共用同一载荷布局，未使用的字段由发送方置 0。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanIp {
    /// 目标 IP。
    pub addr: IpAddr,
}

impl UnbanIp {
    /// 编码整条报文（含公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::UnbanIp::WIRE_SIZE;
        let raw = contract::UnbanIp {
            hdr: header(contract::UnbanIp::MSG_TYPE, seq, wire_u16(wire)),
            af: family_raw(self.addr),
            duration_secs: 0,
            addr: addr_bytes(self.addr),
            reason: [0u8; 32],
        };
        packed_bytes(&raw, wire)
    }
}

/// 配置下发（`MsgType::SetConfig`）。
///
/// 字段与契约一一对应，不做任何语义加工；`flags` 决定内核实际采纳哪些项。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SetConfig {
    /// `ConfigFlags` 位集。
    pub flags: u32,
    /// 封禁时长（秒）。
    pub ban_time: u32,
    /// 速率窗口（秒）。
    pub rate_window_seconds: u32,
    /// 每秒最大包数。
    pub max_packets_per_second: u64,
    /// 每秒最大字节数。
    pub max_bytes_per_second: u64,
    /// 每秒最大 SYN。
    pub max_syn_per_second: u64,
    /// 每秒最大 UDP。
    pub max_udp_per_second: u64,
    /// 每秒最大 ICMP。
    pub max_icmp_per_second: u64,
    /// 每秒最大 ACK。
    pub max_ack_per_second: u64,
    /// 每秒最大 RST。
    pub max_rst_per_second: u64,
    /// 每秒最大 FIN。
    pub max_fin_per_second: u64,
    /// `DynThresholdFlags` 位集。
    pub dynamic_threshold_flags: u32,
    /// 动态阈值倍数 ×100（定点）。
    pub dynamic_threshold_ratio_x100: u32,
    /// 基线包速率。
    pub baseline_pps: u64,
    /// 基线字节速率。
    pub baseline_bps: u64,
    /// DDoS 封禁时长（秒）。
    pub ddos_ban_duration: u32,
}

impl SetConfig {
    /// 从契约结构体读取（发送与广播两个方向共用同一布局）。
    fn from_raw(raw: &contract::SetConfig) -> Self {
        Self {
            flags: u32::from_be(raw.flags),
            ban_time: u32::from_be(raw.ban_time),
            rate_window_seconds: u32::from_be(raw.rate_window_seconds),
            max_packets_per_second: u64::from_be(raw.max_packets_per_second),
            max_bytes_per_second: u64::from_be(raw.max_bytes_per_second),
            max_syn_per_second: u64::from_be(raw.max_syn_per_second),
            max_udp_per_second: u64::from_be(raw.max_udp_per_second),
            max_icmp_per_second: u64::from_be(raw.max_icmp_per_second),
            max_ack_per_second: u64::from_be(raw.max_ack_per_second),
            max_rst_per_second: u64::from_be(raw.max_rst_per_second),
            max_fin_per_second: u64::from_be(raw.max_fin_per_second),
            dynamic_threshold_flags: u32::from_be(raw.dynamic_threshold_flags),
            dynamic_threshold_ratio_x100: u32::from_be(raw.dynamic_threshold_ratio_x100),
            baseline_pps: u64::from_be(raw.baseline_pps),
            baseline_bps: u64::from_be(raw.baseline_bps),
            ddos_ban_duration: u32::from_be(raw.ddos_ban_duration),
        }
    }

    /// 编码整条报文（含公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::SetConfig::WIRE_SIZE;
        let raw = contract::SetConfig {
            hdr: header(contract::SetConfig::MSG_TYPE, seq, wire_u16(wire)),
            flags: self.flags.to_be(),
            ban_time: self.ban_time.to_be(),
            rate_window_seconds: self.rate_window_seconds.to_be(),
            max_packets_per_second: self.max_packets_per_second.to_be(),
            max_bytes_per_second: self.max_bytes_per_second.to_be(),
            max_syn_per_second: self.max_syn_per_second.to_be(),
            max_udp_per_second: self.max_udp_per_second.to_be(),
            max_icmp_per_second: self.max_icmp_per_second.to_be(),
            max_ack_per_second: self.max_ack_per_second.to_be(),
            max_rst_per_second: self.max_rst_per_second.to_be(),
            max_fin_per_second: self.max_fin_per_second.to_be(),
            dynamic_threshold_flags: self.dynamic_threshold_flags.to_be(),
            dynamic_threshold_ratio_x100: self.dynamic_threshold_ratio_x100.to_be(),
            baseline_pps: self.baseline_pps.to_be(),
            baseline_bps: self.baseline_bps.to_be(),
            ddos_ban_duration: self.ddos_ban_duration.to_be(),
        };
        packed_bytes(&raw, wire)
    }
}

/// 受保护端口位图（`MsgType::SetProtectedPorts`）。
///
/// daemon 扫描本机对外监听端口后下发；语义是「纳入防护」：置位端口的入站流量
/// 参与 DDoS 速率判定。位图固定 8192 字节（65536 位，位 i = 端口 i 受保护），
/// `count` 只是观测字段——内核会自行重算置位数，不采信这里的值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetProtectedPorts {
    /// 置位端口数（观测用；内核重算）。
    pub count: u32,
    /// 65536 位位图，位 i = 端口 i 受保护。
    pub bitmap: [u8; PROTECTED_PORTS_BITMAP_BYTES],
}

/// 位图字节数（65536 位）。与契约 `SetProtectedPorts.bitmap` 的 `u8[8192]` 一致，
/// 下面的断言保证两者不会各自漂移。
pub const PROTECTED_PORTS_BITMAP_BYTES: usize = 8192;

const _: () = assert!(
    PROTECTED_PORTS_BITMAP_BYTES
        == contract::SetProtectedPorts::WIRE_SIZE - contract::MsgHdr::WIRE_SIZE - 4
);

impl SetProtectedPorts {
    /// 编码整条报文（含公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::SetProtectedPorts::WIRE_SIZE;
        let mut raw = contract::SetProtectedPorts {
            hdr: header(contract::SetProtectedPorts::MSG_TYPE, seq, wire_u16(wire)),
            count: self.count.to_be(),
            bitmap: [0u8; PROTECTED_PORTS_BITMAP_BYTES],
        };
        raw.bitmap.copy_from_slice(&self.bitmap);
        packed_bytes(&raw, wire)
    }
}

/// 分页查询参数。三个 LIST 查询共用。
///
/// `limit == 0` 的含义是「内核取默认页大小」，**不是**「不限量」——这是契约里
/// 明确的历史语义，写错会静默退化成单页。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageQuery {
    /// 起始下标。
    pub offset: u32,
    /// 本页上限；0 表示内核取默认页大小。
    pub limit: u32,
}

/// 为「载荷只有 offset/limit 两个 u32」的查询生成编码实现。
macro_rules! page_query_encode {
    ($ty:ident, $contract:ident) => {
        impl $ty {
            /// 编码整条报文（含公共头）。
            #[must_use]
            pub fn encode(&self, seq: u32) -> Vec<u8> {
                let wire = contract::$contract::WIRE_SIZE;
                let raw = contract::$contract {
                    hdr: header(contract::$contract::MSG_TYPE, seq, wire_u16(wire)),
                    offset: self.0.offset.to_be(),
                    limit: self.0.limit.to_be(),
                };
                packed_bytes(&raw, wire)
            }
        }
    };
}

/// 封禁列表分页查询（`MsgType::ListBansQuery`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListBansQuery(pub PageQuery);

/// 白名单分页查询（`MsgType::ListWhitelistQuery`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListWhitelistQuery(pub PageQuery);

/// 速率统计分页查询（`MsgType::ListRatesQuery`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListRatesQuery(pub PageQuery);

page_query_encode!(ListBansQuery, ListBansQuery);
page_query_encode!(ListWhitelistQuery, ListWhitelistQuery);
page_query_encode!(ListRatesQuery, ListRatesQuery);

/// 添加白名单（`MsgType::AddWhitelist`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddWhitelist {
    /// 目标网段。
    pub addr: IpAddr,
    /// 前缀长度。
    pub prefix_len: u8,
    /// 限定设备；空串表示不限定。
    pub device: String,
}

impl AddWhitelist {
    /// 编码整条报文（含公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::AddWhitelist::WIRE_SIZE;
        let raw = contract::AddWhitelist {
            hdr: header(contract::AddWhitelist::MSG_TYPE, seq, wire_u16(wire)),
            af: family_raw(self.addr),
            prefix_len: self.prefix_len,
            addr: addr_bytes(self.addr),
            device: fixed_bytes(&self.device),
        };
        packed_bytes(&raw, wire)
    }
}

/// 移除白名单（`MsgType::RemoveWhitelist`）。
///
/// 契约规定它与 [`AddWhitelist`] 共用同一载荷布局。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoveWhitelist {
    /// 目标网段。
    pub addr: IpAddr,
    /// 前缀长度。
    pub prefix_len: u8,
    /// 限定设备；空串表示不限定。
    pub device: String,
}

impl RemoveWhitelist {
    /// 编码整条报文（含公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let wire = contract::RemoveWhitelist::WIRE_SIZE;
        let raw = contract::RemoveWhitelist {
            hdr: header(contract::RemoveWhitelist::MSG_TYPE, seq, wire_u16(wire)),
            af: family_raw(self.addr),
            prefix_len: self.prefix_len,
            addr: addr_bytes(self.addr),
            device: fixed_bytes(&self.device),
        };
        packed_bytes(&raw, wire)
    }
}

/// 统计查询（`MsgType::StatsQuery`），无载荷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsQuery;

impl StatsQuery {
    /// 编码整条报文（仅公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        encode_header_only(contract::StatsQuery::MSG_TYPE, seq)
    }
}

/// 分析数据查询（`MsgType::AnalysisQuery`），无载荷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisQuery;

impl AnalysisQuery {
    /// 编码整条报文（仅公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        encode_header_only(contract::AnalysisQuery::MSG_TYPE, seq)
    }
}

/// 注册为唯一守护进程（`MsgType::DaemonRegister`），无载荷。
///
/// 注册结果由内核以 [`DaemonRegisterAck`] 显式回传，**不能**把 `sendto` 成功
/// 当成注册成功。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DaemonRegister;

impl DaemonRegister {
    /// 编码整条报文（仅公共头）。
    #[must_use]
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        encode_header_only(contract::DaemonRegister::MSG_TYPE, seq)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{
        decode_header, decode_incoming, encode_header_only, header, packed_bytes, Incoming, HDR_LEN,
    };
    use super::*;

    /// 取契约里的字段偏移（报文用绝对偏移，尾部条目用条目内偏移）。
    fn raw_off(field_offsets: &[(&str, usize)], name: &str) -> usize {
        field_offsets
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, o)| *o)
            .unwrap_or_else(|| panic!("契约里没有字段 {name}"))
    }

    /// 含公共头的报文：字段在**载荷体**中的偏移。
    fn body_off(field_offsets: &[(&str, usize)], name: &str) -> usize {
        raw_off(field_offsets, name) - HDR_LEN
    }

    /// 尾部条目：字段相对条目起点的偏移。
    fn elem_off(field_offsets: &[(&str, usize)], name: &str) -> usize {
        raw_off(field_offsets, name)
    }

    /// 在指定偏移写入一段字节。
    fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// 用真实头编码器拼出一条报文，保证测试走的编码路径与生产一致。
    fn frame(msg_type: contract::MsgType, seq: u32, body: &[u8]) -> Vec<u8> {
        let wire = HDR_LEN + body.len();
        let hdr = header(
            msg_type,
            seq,
            u16::try_from(wire).expect("测试报文应短于 u16"),
        );
        let mut bytes = packed_bytes(&hdr, HDR_LEN);
        bytes.extend_from_slice(body);
        bytes
    }

    /// 解码一条接收报文并断言其变体。
    fn decode_one(bytes: &[u8]) -> Incoming {
        let (hdr, body) = decode_header(bytes).expect("报文头应合法");
        decode_incoming(hdr.msg_type().expect("类型应在契约内"), body).expect("载荷应能解码")
    }

    #[test]
    fn paged_responses_fit_the_u16_length_field() {
        // 传输层按 u16 长度字段分配缓冲；契约给出的「单页上限」必须真的装得下。
        for (fixed, cap, elem) in [
            (
                contract::ListBansResponse::FIXED_SIZE,
                contract::ListBansResponse::MAX_TAIL_ENTRIES,
                contract::BanEntry::WIRE_SIZE,
            ),
            (
                contract::ListWhitelistResponse::FIXED_SIZE,
                contract::ListWhitelistResponse::MAX_TAIL_ENTRIES,
                contract::WhitelistEntry::WIRE_SIZE,
            ),
            (
                contract::ListRatesResponse::FIXED_SIZE,
                contract::ListRatesResponse::MAX_TAIL_ENTRIES,
                contract::RateEntry::WIRE_SIZE,
            ),
        ] {
            let max_wire = fixed + cap * elem;
            assert!(
                max_wire <= usize::from(u16::MAX),
                "最大单页 {max_wire} 字节超出 u16 长度字段"
            );
        }
    }

    #[test]
    fn page_caps_come_from_the_contract() {
        assert_eq!(contract::ListBansResponse::MAX_TAIL_ENTRIES, 696);
        assert_eq!(contract::ListWhitelistResponse::MAX_TAIL_ENTRIES, 1926);
        assert_eq!(contract::ListRatesResponse::MAX_TAIL_ENTRIES, 779);
    }

    #[test]
    fn ddos_event_decodes_every_field() {
        let off = contract::DdosEvent::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::DdosEvent::WIRE_SIZE)];
        body[body_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        put(
            &mut body,
            body_off(off, "reason"),
            &fixed_bytes::<32>("SYN flood"),
        );
        put(&mut body, body_off(off, "rate_pps"), &1234u32.to_be_bytes());
        put(
            &mut body,
            body_off(off, "addr"),
            &addr_bytes("198.51.100.9".parse().expect("测试地址")),
        );

        let event = match decode_one(&frame(contract::MsgType::DdosEvent, 0, &body)) {
            Incoming::DdosEvent(e) => *e,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(event.af, Some(contract::AddrFamily::Inet));
        assert_eq!(event.reason, "SYN flood");
        assert_eq!(event.rate_pps, 1234);
        assert_eq!(event.addr, Some("198.51.100.9".parse().expect("测试地址")));
    }

    #[test]
    fn undefined_address_family_does_not_become_ipv4() {
        let off = contract::DdosEvent::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::DdosEvent::WIRE_SIZE)];
        body[body_off(off, "af")] = 77;
        let event = match decode_one(&frame(contract::MsgType::DdosEvent, 0, &body)) {
            Incoming::DdosEvent(e) => *e,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(event.af, None);
        assert_eq!(event.addr, None, "未定义地址族不得被当成 IPv4");
    }

    #[test]
    fn ban_state_change_decodes_cumulative_stats() {
        let off = contract::BanStateChange::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::BanStateChange::WIRE_SIZE)];
        body[body_off(off, "action")] = contract::BanAction::Ban.to_raw();
        body[body_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        put(
            &mut body,
            body_off(off, "duration_secs"),
            &600u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "addr"),
            &addr_bytes("203.0.113.5".parse().expect("测试地址")),
        );
        put(
            &mut body,
            body_off(off, "reason"),
            &fixed_bytes::<32>("bad"),
        );
        put(
            &mut body,
            body_off(off, "jail_name"),
            &fixed_bytes::<32>("sshd"),
        );
        put(
            &mut body,
            body_off(off, "packets_dropped"),
            &7u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "packets_accepted"),
            &9u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "current_bans"),
            &3u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "whitelist_count"),
            &4u32.to_be_bytes(),
        );

        let change = match decode_one(&frame(contract::MsgType::BanStateChange, 0, &body)) {
            Incoming::BanStateChange(c) => *c,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(change.action, Some(contract::BanAction::Ban));
        assert_eq!(change.duration_secs, 600);
        assert!(!change.is_permanent());
        assert_eq!(change.reason, "bad");
        assert_eq!(change.jail_name, "sshd");
        assert_eq!(change.packets_dropped, 7);
        assert_eq!(change.packets_accepted, 9);
        assert_eq!(change.current_bans, 3);
        assert_eq!(change.whitelist_count, 4);
        assert_eq!(change.addr, Some("203.0.113.5".parse().expect("测试地址")));
    }

    #[test]
    fn zero_duration_on_the_event_path_means_permanent() {
        let off = contract::BanStateChange::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::BanStateChange::WIRE_SIZE)];
        body[body_off(off, "action")] = contract::BanAction::Ban.to_raw();
        body[body_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        let change = match decode_one(&frame(contract::MsgType::BanStateChange, 0, &body)) {
            Incoming::BanStateChange(c) => *c,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert!(change.is_permanent(), "duration_secs == 0 表示永久封禁");
    }

    #[test]
    fn whitelist_state_change_decodes_prefix_and_device() {
        let off = contract::WhitelistStateChange::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::WhitelistStateChange::WIRE_SIZE)];
        body[body_off(off, "action")] = contract::WhitelistAction::Add.to_raw();
        body[body_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        body[body_off(off, "prefix_len")] = 24;
        put(
            &mut body,
            body_off(off, "addr"),
            &addr_bytes("192.168.1.0".parse().expect("测试地址")),
        );
        put(
            &mut body,
            body_off(off, "device"),
            &fixed_bytes::<16>("eth0"),
        );
        put(
            &mut body,
            body_off(off, "whitelist_count"),
            &12u32.to_be_bytes(),
        );

        let change = match decode_one(&frame(contract::MsgType::WhitelistStateChange, 0, &body)) {
            Incoming::WhitelistStateChange(c) => *c,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(change.action, Some(contract::WhitelistAction::Add));
        assert_eq!(change.prefix_len, 24);
        assert_eq!(change.device, "eth0");
        assert_eq!(change.whitelist_count, 12);
        assert_eq!(change.addr, Some("192.168.1.0".parse().expect("测试地址")));
    }

    #[test]
    fn cmd_result_exposes_the_original_command_and_error() {
        let off = contract::CmdResult::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::CmdResult::WIRE_SIZE)];
        put(
            &mut body,
            body_off(off, "original_cmd"),
            &contract::MsgType::BanIp.to_raw().to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "error_code"),
            &(-22i32).to_be_bytes(),
        );
        body[body_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        put(
            &mut body,
            body_off(off, "addr"),
            &addr_bytes("203.0.113.77".parse().expect("测试地址")),
        );

        let result = match decode_one(&frame(contract::MsgType::CmdResult, 0, &body)) {
            Incoming::CmdResult(r) => *r,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(result.original_cmd, Some(contract::MsgType::BanIp));
        assert_eq!(result.original_cmd_raw, 2);
        assert_eq!(result.error_code, -22);
        assert_eq!(result.addr, Some("203.0.113.77".parse().expect("测试地址")));
    }

    #[test]
    fn config_ack_reports_rejected_flags() {
        let off = contract::ConfigAck::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::ConfigAck::WIRE_SIZE)];
        put(
            &mut body,
            body_off(off, "applied_flags"),
            &0b0000_1011u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "rejected_flags"),
            &0b0000_0100u32.to_be_bytes(),
        );
        let ack = match decode_one(&frame(contract::MsgType::ConfigAck, 0, &body)) {
            Incoming::ConfigAck(a) => *a,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(ack.applied_flags, 0b0000_1011);
        assert_eq!(ack.rejected_flags, 0b0000_0100);
        assert!(!ack.fully_applied());

        let mut clean = vec![0u8; body_len(contract::ConfigAck::WIRE_SIZE)];
        put(
            &mut clean,
            body_off(off, "applied_flags"),
            &1u32.to_be_bytes(),
        );
        match decode_one(&frame(contract::MsgType::ConfigAck, 0, &clean)) {
            Incoming::ConfigAck(a) => assert!(a.fully_applied()),
            other => panic!("类型不符：{}", other.msg_type_name()),
        }
    }

    #[test]
    fn stats_response_decodes_all_counters() {
        let off = contract::StatsResponse::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::StatsResponse::WIRE_SIZE)];
        for (name, value) in [
            ("current_bans", 1u64),
            ("total_bans", 2),
            ("total_unbans", 3),
            ("whitelist_count", 4),
            ("packets_dropped", 5),
            ("packets_accepted", 6),
        ] {
            put(&mut body, body_off(off, name), &value.to_be_bytes());
        }
        let stats = match decode_one(&frame(contract::MsgType::StatsResponse, 0, &body)) {
            Incoming::StatsResponse(s) => *s,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(
            stats,
            StatsResponse {
                current_bans: 1,
                total_bans: 2,
                total_unbans: 3,
                whitelist_count: 4,
                packets_dropped: 5,
                packets_accepted: 6,
            }
        );
    }

    #[test]
    fn daemon_register_ack_exposes_both_outcomes() {
        for (raw, expected) in [(1u8, true), (0u8, false)] {
            let ack = match decode_one(&frame(contract::MsgType::DaemonRegisterAck, 0, &[raw])) {
                Incoming::DaemonRegisterAck(a) => *a,
                other => panic!("类型不符：{}", other.msg_type_name()),
            };
            assert_eq!(ack.accepted, expected);
        }
    }

    #[test]
    fn config_change_shares_the_set_config_payload() {
        let config = SetConfig {
            flags: 0b1_0000_0000_0001,
            ban_time: 600,
            rate_window_seconds: 10,
            max_packets_per_second: 1,
            max_bytes_per_second: 2,
            max_syn_per_second: 3,
            max_udp_per_second: 4,
            max_icmp_per_second: 5,
            max_ack_per_second: 6,
            max_rst_per_second: 7,
            max_fin_per_second: 8,
            dynamic_threshold_flags: 1,
            dynamic_threshold_ratio_x100: 250,
            baseline_pps: 11,
            baseline_bps: 22,
            ddos_ban_duration: 33,
        };
        let encoded = config.encode(0);
        assert_eq!(encoded.len(), contract::SetConfig::WIRE_SIZE);

        // 同一份载荷体按 ConfigChange 解出必须等价（契约声明两者同布局）。
        let decoded = ConfigChange::decode(&encoded[HDR_LEN..]).expect("共用布局应能解码");
        assert_eq!(decoded.0, config);

        // 也确认它能完整走一遍接收路径。
        let mut broadcast = encoded;
        put(
            &mut broadcast[4..6],
            0,
            &contract::MsgType::ConfigChange.to_raw().to_be_bytes(),
        );
        match decode_one(&broadcast) {
            Incoming::ConfigChange(c) => assert_eq!(c.0, config),
            other => panic!("类型不符：{}", other.msg_type_name()),
        }
    }

    #[test]
    fn list_bans_response_parses_tail_entries_and_totals() {
        let off = contract::ListBansResponse::FIELD_OFFSETS;
        let ent = contract::BanEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListBansResponse::FIXED_SIZE - HDR_LEN];
        put(&mut body, body_off(off, "count"), &2u32.to_be_bytes());
        put(&mut body, body_off(off, "total"), &5u32.to_be_bytes());
        put(&mut body, body_off(off, "offset"), &1u32.to_be_bytes());
        body.extend_from_slice(&ban_entry_bytes(ent, "198.51.100.1", true, 0, 111, "sshd"));
        body.extend_from_slice(&ban_entry_bytes(
            ent,
            "198.51.100.2",
            false,
            60,
            222,
            "nginx",
        ));

        let page = match decode_one(&frame(contract::MsgType::ListBansResponse, 9, &body)) {
            Incoming::ListBansResponse(p) => *p,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(page.total, 5, "total 必须保留，否则无法判断还有后续页");
        assert_eq!(page.offset, 1);
        assert_eq!(page.entries.len(), 2);
        assert!(page.entries[0].is_permanent);
        assert_eq!(page.entries[0].banned_at, 111);
        assert_eq!(page.entries[0].jail_name, "sshd");
        assert_eq!(
            page.entries[0].addr(),
            Some("198.51.100.1".parse().expect("测试地址"))
        );
        assert!(!page.entries[1].is_permanent);
        assert_eq!(page.entries[1].duration_secs, 60);
        assert_eq!(
            page.entries[1].addr(),
            Some("198.51.100.2".parse().expect("测试地址"))
        );
    }

    /// 造一个封禁条目（94 字节）。
    fn ban_entry_bytes(
        off: &[(&str, usize)],
        addr: &str,
        permanent: bool,
        duration: u32,
        banned_at: u64,
        jail: &str,
    ) -> Vec<u8> {
        let mut out = vec![0u8; contract::BanEntry::WIRE_SIZE];
        out[elem_off(off, "af")] = contract::AddrFamily::Inet.to_raw();
        out[elem_off(off, "is_permanent")] = u8::from(permanent);
        put(
            &mut out,
            elem_off(off, "duration_secs"),
            &duration.to_be_bytes(),
        );
        put(
            &mut out,
            elem_off(off, "banned_at"),
            &banned_at.to_be_bytes(),
        );
        put(
            &mut out,
            elem_off(off, "addr"),
            &addr_bytes(addr.parse().expect("测试地址")),
        );
        put(
            &mut out,
            elem_off(off, "jail_name"),
            &fixed_bytes::<32>(jail),
        );
        out
    }

    #[test]
    fn list_whitelist_response_parses_its_own_page_shape() {
        let off = contract::ListWhitelistResponse::FIELD_OFFSETS;
        let ent = contract::WhitelistEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListWhitelistResponse::FIXED_SIZE - HDR_LEN];
        put(&mut body, body_off(off, "count"), &1u32.to_be_bytes());
        put(&mut body, body_off(off, "total"), &300u32.to_be_bytes());
        put(&mut body, body_off(off, "offset"), &0u32.to_be_bytes());
        let mut entry = vec![0u8; contract::WhitelistEntry::WIRE_SIZE];
        entry[elem_off(ent, "af")] = contract::AddrFamily::Inet.to_raw();
        entry[elem_off(ent, "prefix_len")] = 16;
        put(
            &mut entry,
            elem_off(ent, "addr"),
            &addr_bytes("10.1.0.0".parse().expect("测试地址")),
        );
        put(
            &mut entry,
            elem_off(ent, "device"),
            &fixed_bytes::<16>("eth1"),
        );
        body.extend_from_slice(&entry);

        let page = match decode_one(&frame(contract::MsgType::ListWhitelistResponse, 3, &body)) {
            Incoming::ListWhitelistResponse(p) => *p,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(page.total, 300, "旧实现丢掉了 total，白名单因此被静默截断");
        assert_eq!(page.offset, 0);
        assert_eq!(page.entries.len(), 1);
        assert_eq!(page.entries[0].prefix_len, 16);
        assert_eq!(page.entries[0].device, "eth1");
    }

    #[test]
    fn list_rates_response_parses_global_and_tail() {
        let off = contract::ListRatesResponse::FIELD_OFFSETS;
        let ent = contract::RateEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListRatesResponse::FIXED_SIZE - HDR_LEN];
        put(&mut body, body_off(off, "count"), &1u32.to_be_bytes());
        put(&mut body, body_off(off, "total"), &900u32.to_be_bytes());
        put(&mut body, body_off(off, "offset"), &256u32.to_be_bytes());
        put(
            &mut body,
            body_off(off, "global_pps"),
            &1234u64.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "global_bps"),
            &5678u64.to_be_bytes(),
        );
        let mut entry = vec![0u8; contract::RateEntry::WIRE_SIZE];
        entry[elem_off(ent, "af")] = contract::AddrFamily::Inet.to_raw();
        put(&mut entry, elem_off(ent, "packets"), &10u64.to_be_bytes());
        put(
            &mut entry,
            elem_off(ent, "syn_packets"),
            &3u64.to_be_bytes(),
        );
        put(
            &mut entry,
            elem_off(ent, "addr"),
            &addr_bytes("198.51.100.50".parse().expect("测试地址")),
        );
        body.extend_from_slice(&entry);

        let page = match decode_one(&frame(contract::MsgType::ListRatesResponse, 4, &body)) {
            Incoming::ListRatesResponse(p) => *p,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(page.total, 900);
        assert_eq!(page.offset, 256);
        assert_eq!(page.global_pps, 1234);
        assert_eq!(page.global_bps, 5678);
        assert_eq!(page.entries[0].packets, 10);
        assert_eq!(page.entries[0].syn_packets, 3);
        assert_eq!(
            page.entries[0].addr(),
            Some("198.51.100.50".parse().expect("测试地址"))
        );
    }

    #[test]
    fn page_count_above_the_contract_cap_is_rejected() {
        let off = contract::ListBansResponse::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListBansResponse::FIXED_SIZE - HDR_LEN];
        let too_many =
            u32::try_from(contract::ListBansResponse::MAX_TAIL_ENTRIES).expect("上限") + 1;
        put(&mut body, body_off(off, "count"), &too_many.to_be_bytes());
        let bytes = frame(contract::MsgType::ListBansResponse, 1, &body);
        let (hdr, payload) = decode_header(&bytes).expect("报文头应合法");
        let err = decode_incoming(hdr.msg_type().expect("类型合法"), payload)
            .expect_err("超出契约单页上限应被拒");
        assert_eq!(
            err,
            DecodeError::TailCountOutOfRange {
                count: too_many,
                max: contract::ListBansResponse::MAX_TAIL_ENTRIES,
            }
        );
    }

    #[test]
    fn truncated_tail_is_rejected_instead_of_silently_short() {
        let off = contract::ListWhitelistResponse::FIELD_OFFSETS;
        let ent = contract::WhitelistEntry::FIELD_OFFSETS;
        let mut body = vec![0u8; contract::ListWhitelistResponse::FIXED_SIZE - HDR_LEN];
        put(&mut body, body_off(off, "count"), &2u32.to_be_bytes());
        // 只放 1 条，却声明了 2 条。
        let mut entry = vec![0u8; contract::WhitelistEntry::WIRE_SIZE];
        entry[elem_off(ent, "af")] = contract::AddrFamily::Inet.to_raw();
        body.extend_from_slice(&entry);

        let bytes = frame(contract::MsgType::ListWhitelistResponse, 2, &body);
        let (hdr, payload) = decode_header(&bytes).expect("报文头应合法");
        let err = decode_incoming(hdr.msg_type().expect("类型合法"), payload)
            .expect_err("声明 2 条却只给 1 条，必须报错而不是静默截断");
        assert_eq!(
            err,
            DecodeError::TailLenMismatch {
                count: 2,
                need: 2 * contract::WhitelistEntry::WIRE_SIZE,
                got: contract::WhitelistEntry::WIRE_SIZE,
            }
        );
    }

    #[test]
    fn a_full_default_page_of_bans_parses() {
        // 内核默认页 256 条：整份响应必须能解析，不能像旧实现那样在很小的一页
        // 上限处就整份丢掉。
        let off = contract::ListBansResponse::FIELD_OFFSETS;
        let ent = contract::BanEntry::FIELD_OFFSETS;
        let count: u32 = 256;
        let mut body = vec![0u8; contract::ListBansResponse::FIXED_SIZE - HDR_LEN];
        put(&mut body, body_off(off, "count"), &count.to_be_bytes());
        put(&mut body, body_off(off, "total"), &count.to_be_bytes());
        for i in 0..count {
            let addr = format!("198.51.100.{}", (i % 250) + 1);
            body.extend_from_slice(&ban_entry_bytes(ent, &addr, false, 600, 1, "sshd"));
        }
        let page = match decode_one(&frame(contract::MsgType::ListBansResponse, 7, &body)) {
            Incoming::ListBansResponse(p) => *p,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(page.entries.len(), usize::try_from(count).expect("条目数"));
        assert_eq!(page.total, count);
    }

    #[test]
    fn body_length_longer_or_shorter_than_the_type_requires_is_rejected() {
        // StatsResponse 的载荷体恒为 48 字节；声称 40 字节必须报错。
        let err = decode_incoming(contract::MsgType::StatsResponse, &[0u8; 40])
            .expect_err("载荷体长度不符应被拒");
        assert_eq!(
            err,
            DecodeError::LenMismatch {
                declared: u16::try_from(body_len(contract::StatsResponse::WIRE_SIZE))
                    .expect("长度"),
                got: 40,
            }
        );
    }

    #[test]
    fn analysis_response_reports_counts_separately_from_capacity() {
        let off = contract::AnalysisResponse::FIELD_OFFSETS;
        let mut body = vec![0u8; body_len(contract::AnalysisResponse::WIRE_SIZE)];
        put(
            &mut body,
            body_off(off, "udp_port_count"),
            &3u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "udp_port_capacity"),
            &64u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "port_scan_count"),
            &2u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "service_probe_count"),
            &0u32.to_be_bytes(),
        );
        put(
            &mut body,
            body_off(off, "port_scan_threshold"),
            &99u32.to_be_bytes(),
        );
        // 声明数超过数组容量时，能看见的真实条目数应被容量截住。
        put(
            &mut body,
            body_off(off, "icmp_type_count"),
            &100u32.to_be_bytes(),
        );

        let analysis = match decode_one(&frame(contract::MsgType::AnalysisResponse, 5, &body)) {
            Incoming::AnalysisResponse(a) => *a,
            other => panic!("类型不符：{}", other.msg_type_name()),
        };
        assert_eq!(analysis.udp_port_count, 3);
        assert_eq!(analysis.udp_port_capacity, 64);
        assert_eq!(analysis.udp_ports_in_use(), 3);
        assert_eq!(
            analysis.icmp_type_count, 100,
            "声明值原样保留以便发现不一致"
        );
        assert_eq!(analysis.icmp_types_in_use(), 64, "可用条目数受数组容量限制");
        assert_eq!(analysis.port_scanners_in_use(), 2);
        assert_eq!(analysis.service_probes_in_use(), 0);
        assert_eq!(analysis.port_scan_threshold, 99);
    }

    #[test]
    fn ban_ip_encodes_the_kernel_expected_layout() {
        let message = BanIp {
            addr: "203.0.113.8".parse().expect("测试地址"),
            duration_secs: 3600,
            reason: "ssh brute force".to_string(),
        };
        let bytes = message.encode(0x0a0b_0c0d);
        assert_eq!(bytes.len(), contract::BanIp::WIRE_SIZE);
        let (hdr, body) = decode_header(&bytes).expect("自己编的报文应能解析");
        assert_eq!(hdr.msg_type(), Some(contract::MsgType::BanIp));
        assert_eq!(hdr.seq, 0x0a0b_0c0d);
        assert_eq!(
            hdr.msg_len,
            u16::try_from(contract::BanIp::WIRE_SIZE).expect("长度")
        );

        let off = contract::BanIp::FIELD_OFFSETS;
        assert_eq!(
            body[body_off(off, "af")],
            contract::AddrFamily::Inet.to_raw()
        );
        let at = body_off(off, "addr");
        assert_eq!(
            &body[at..at + 4],
            &[203, 0, 113, 8],
            "IPv4 占地址缓冲前 4 字节"
        );
        let dur = body_off(off, "duration_secs");
        assert_eq!(
            u32::from_be_bytes(body[dur..dur + 4].try_into().expect("4 字节")),
            3600
        );
        let reason = body_off(off, "reason");
        let reason_field: [u8; 32] = body[reason..reason + 32].try_into().expect("reason 字段");
        assert_eq!(fixed_str(&reason_field), "ssh brute force");
    }

    #[test]
    fn unban_ip_shares_the_ban_payload_layout() {
        let addr = "198.51.100.4".parse().expect("测试地址");
        let unban = UnbanIp { addr }.encode(1);
        let ban = BanIp {
            addr,
            duration_secs: 0,
            reason: String::new(),
        }
        .encode(1);
        // 两者只在 msg_type 上不同，载荷体必须逐字节相同（契约声明的共用布局）。
        assert_eq!(unban[HDR_LEN..], ban[HDR_LEN..]);
        assert_ne!(unban[4..6], ban[4..6], "msg_type 必须区分两种命令");
    }

    #[test]
    fn page_queries_encode_offset_and_limit_big_endian() {
        let query = ListWhitelistQuery(PageQuery {
            offset: 0x0102_0304,
            limit: 256,
        });
        let bytes = query.encode(0);
        assert_eq!(bytes.len(), contract::ListWhitelistQuery::WIRE_SIZE);
        let (hdr, body) = decode_header(&bytes).expect("自己编的报文应能解析");
        assert_eq!(hdr.msg_type(), Some(contract::MsgType::ListWhitelistQuery));
        assert_eq!(hdr.msg_len, 20);
        let off = contract::ListWhitelistQuery::FIELD_OFFSETS;
        let at = body_off(off, "offset");
        assert_eq!(&body[at..at + 4], &0x0102_0304u32.to_be_bytes());
        let lt = body_off(off, "limit");
        assert_eq!(&body[lt..lt + 4], &256u32.to_be_bytes());
    }

    #[test]
    fn add_and_remove_whitelist_share_the_payload_layout() {
        let addr = "10.0.0.0".parse().expect("测试地址");
        let a = AddWhitelist {
            addr,
            prefix_len: 8,
            device: "eth0".to_string(),
        }
        .encode(0);
        let r = RemoveWhitelist {
            addr,
            prefix_len: 8,
            device: "eth0".to_string(),
        }
        .encode(0);
        assert_eq!(a[HDR_LEN..], r[HDR_LEN..], "契约声明两者载荷布局一致");
        assert_ne!(a[4..6], r[4..6]);
    }

    #[test]
    fn header_only_requests_are_exactly_twelve_bytes() {
        for (bytes, expected, seq) in [
            (StatsQuery.encode(1), contract::MsgType::StatsQuery, 1u32),
            (AnalysisQuery.encode(2), contract::MsgType::AnalysisQuery, 2),
            (
                DaemonRegister.encode(3),
                contract::MsgType::DaemonRegister,
                3,
            ),
        ] {
            assert_eq!(bytes.len(), HDR_LEN);
            let (hdr, body) = decode_header(&bytes).expect("应能解析");
            assert!(body.is_empty());
            assert_eq!(hdr.msg_len, 12);
            assert_eq!(hdr.msg_type(), Some(expected));
            assert_eq!(hdr.seq, seq);
        }
    }

    #[test]
    fn ipv6_addresses_survive_the_round_trip() {
        let ip: IpAddr = "2001:db8::dead:beef".parse().expect("测试地址");
        let bytes = AddWhitelist {
            addr: ip,
            prefix_len: 64,
            device: String::new(),
        }
        .encode(0);
        let body = &bytes[HDR_LEN..];
        let off = contract::AddWhitelist::FIELD_OFFSETS;
        assert_eq!(
            body[body_off(off, "af")],
            contract::AddrFamily::Inet6.to_raw()
        );
        let at = body_off(off, "addr");
        let raw: contract::addr16 = body[at..at + 16].try_into().expect("16 字节");
        assert_eq!(
            addr_ip(contract::AddrFamily::Inet6.to_raw(), &raw),
            Some(ip)
        );
    }

    #[test]
    fn request_direction_types_are_not_decodable_as_incoming() {
        for msg_type in [
            contract::MsgType::BanIp,
            contract::MsgType::SetConfig,
            contract::MsgType::ListBansQuery,
            contract::MsgType::StatsQuery,
            contract::MsgType::DaemonRegister,
        ] {
            let err = decode_incoming(msg_type, &[]).expect_err("发送方向不应出现在接收侧");
            assert_eq!(
                err,
                DecodeError::UnknownMsgType {
                    got: msg_type.to_raw()
                }
            );
        }
    }

    #[test]
    fn header_only_encoding_is_the_same_bytes_as_an_empty_frame() {
        // `encode_header_only` 与测试辅助 `frame` 必须产出同样的头，否则测试的
        // 构造路径就与生产的编码路径分叉了。
        for msg_type in [
            contract::MsgType::StatsQuery,
            contract::MsgType::DaemonRegister,
        ] {
            assert_eq!(encode_header_only(msg_type, 77), frame(msg_type, 77, &[]));
        }
    }
}
