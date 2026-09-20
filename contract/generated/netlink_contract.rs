// 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。
// 单一真相源: netlink.fwidl

#![allow(dead_code)]
#![allow(non_camel_case_types)]

/// 契约承诺的字节序：全部多字节整数为大端。
pub const FW_CONTRACT_ENDIAN: &str = "big";

pub const FW_NL_MAGIC: u32 = 0x46574C4E;

pub type addr16 = [u8; 16];

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrFamily {
    Inet = 2,
    Inet6 = 10,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanAction {
    Ban = 1,
    Unban = 2,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistAction {
    Add = 1,
    Remove = 2,
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    DdosEvent = 1,
    BanIp = 2,
    UnbanIp = 3,
    SetConfig = 4,
    BanStateChange = 5,
    ListBansQuery = 6,
    ListBansResponse = 7,
    StatsQuery = 8,
    StatsResponse = 9,
    ListWhitelistQuery = 10,
    ListWhitelistResponse = 11,
    AddWhitelist = 12,
    RemoveWhitelist = 13,
    ConfigAck = 14,
    ListRatesQuery = 15,
    ListRatesResponse = 16,
    WhitelistStateChange = 17,
    CmdResult = 18,
    ConfigChange = 19,
    AnalysisQuery = 20,
    AnalysisResponse = 21,
    DaemonRegister = 22,
    DaemonRegisterAck = 23,
}

pub mod config_flags {
    pub const BAN_TIME: u32 = 1 << 0;
    pub const RATE_WINDOW: u32 = 1 << 1;
    pub const MAX_PPS: u32 = 1 << 2;
    pub const MAX_BPS: u32 = 1 << 3;
    pub const MAX_SYN: u32 = 1 << 4;
    pub const MAX_UDP: u32 = 1 << 5;
    pub const MAX_ICMP: u32 = 1 << 6;
    pub const MAX_ACK: u32 = 1 << 7;
    pub const MAX_RST: u32 = 1 << 8;
    pub const MAX_FIN: u32 = 1 << 9;
    pub const DYNAMIC_THRESHOLD: u32 = 1 << 10;
    pub const BASELINE_UPDATE: u32 = 1 << 11;
    pub const DDOS_BAN_DURATION: u32 = 1 << 12;
}

pub mod dyn_threshold_flags {
    pub const ENABLED: u32 = 1 << 0;
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MsgHdr {
    pub magic: u32,
    pub msg_type: u16,
    pub msg_len: u16,
    pub seq: u32,
}

impl MsgHdr {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 12;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("magic", 0),
        ("msg_type", 4),
        ("msg_len", 6),
        ("seq", 8),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DdosEvent {
    pub hdr: MsgHdr,
    pub af: u8,
    pub reason: [u8; 32],
    pub rate_pps: u32,
    pub addr: addr16,
}

impl DdosEvent {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 65;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::DdosEvent;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 12),
        ("reason", 13),
        ("rate_pps", 45),
        ("addr", 49),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BanStateChange {
    pub hdr: MsgHdr,
    pub action: u8,
    pub af: u8,
    pub duration_secs: u32,
    pub addr: addr16,
    pub reason: [u8; 32],
    pub jail_name: [u8; 32],
    pub packets_dropped: u64,
    pub packets_accepted: u64,
    pub current_bans: u32,
    pub whitelist_count: u32,
}

impl BanStateChange {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 122;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::BanStateChange;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("action", 12),
        ("af", 13),
        ("duration_secs", 14),
        ("addr", 18),
        ("reason", 34),
        ("jail_name", 66),
        ("packets_dropped", 98),
        ("packets_accepted", 106),
        ("current_bans", 114),
        ("whitelist_count", 118),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct WhitelistStateChange {
    pub hdr: MsgHdr,
    pub action: u8,
    pub af: u8,
    pub prefix_len: u8,
    pub addr: addr16,
    pub device: [u8; 16],
    pub whitelist_count: u32,
}

impl WhitelistStateChange {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 51;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::WhitelistStateChange;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("action", 12),
        ("af", 13),
        ("prefix_len", 14),
        ("addr", 15),
        ("device", 31),
        ("whitelist_count", 47),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CmdResult {
    pub hdr: MsgHdr,
    pub original_cmd: u16,
    pub pad: i16,
    pub error_code: i32,
    pub af: u8,
    pub addr: addr16,
}

impl CmdResult {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 37;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::CmdResult;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("original_cmd", 12),
        ("pad", 14),
        ("error_code", 16),
        ("af", 20),
        ("addr", 21),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigAck {
    pub hdr: MsgHdr,
    pub applied_flags: u32,
    pub rejected_flags: u32,
}

impl ConfigAck {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 20;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ConfigAck;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("applied_flags", 12),
        ("rejected_flags", 16),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ConfigChange {
    pub hdr: MsgHdr,
    pub flags: u32,
    pub ban_time: u32,
    pub rate_window_seconds: u32,
    pub max_packets_per_second: u64,
    pub max_bytes_per_second: u64,
    pub max_syn_per_second: u64,
    pub max_udp_per_second: u64,
    pub max_icmp_per_second: u64,
    pub max_ack_per_second: u64,
    pub max_rst_per_second: u64,
    pub max_fin_per_second: u64,
    pub dynamic_threshold_flags: u32,
    pub dynamic_threshold_ratio_x100: u32,
    pub baseline_pps: u64,
    pub baseline_bps: u64,
    pub ddos_ban_duration: u32,
}

impl ConfigChange {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 116;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ConfigChange;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("flags", 12),
        ("ban_time", 16),
        ("rate_window_seconds", 20),
        ("max_packets_per_second", 24),
        ("max_bytes_per_second", 32),
        ("max_syn_per_second", 40),
        ("max_udp_per_second", 48),
        ("max_icmp_per_second", 56),
        ("max_ack_per_second", 64),
        ("max_rst_per_second", 72),
        ("max_fin_per_second", 80),
        ("dynamic_threshold_flags", 88),
        ("dynamic_threshold_ratio_x100", 92),
        ("baseline_pps", 96),
        ("baseline_bps", 104),
        ("ddos_ban_duration", 112),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BanEntry {
    pub af: u8,
    pub is_permanent: u8,
    pub duration_secs: u32,
    pub banned_at: u64,
    pub addr: addr16,
    pub jail_name: [u8; 32],
    pub reason: [u8; 32],
}

impl BanEntry {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 94;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 0),
        ("is_permanent", 1),
        ("duration_secs", 2),
        ("banned_at", 6),
        ("addr", 14),
        ("jail_name", 30),
        ("reason", 62),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListBansResponse {
    pub hdr: MsgHdr,
    pub count: u32,
    pub total: u32,
    pub offset: u32,
}

impl ListBansResponse {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 24;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListBansResponse;
    /// 定长部分字节数
    pub const FIXED_SIZE: usize = 24;
    /// 尾部元素类型与其字节数
    pub const TAIL_ELEM_SIZE: usize = 94;
    /// u16 长度上限内可承载的最大尾部条目数
    pub const MAX_TAIL_ENTRIES: usize = 696;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("count", 12),
        ("total", 16),
        ("offset", 20),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StatsResponse {
    pub hdr: MsgHdr,
    pub current_bans: u64,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub whitelist_count: u64,
    pub packets_dropped: u64,
    pub packets_accepted: u64,
}

impl StatsResponse {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 60;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::StatsResponse;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("current_bans", 12),
        ("total_bans", 20),
        ("total_unbans", 28),
        ("whitelist_count", 36),
        ("packets_dropped", 44),
        ("packets_accepted", 52),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct WhitelistEntry {
    pub af: u8,
    pub prefix_len: u8,
    pub addr: addr16,
    pub device: [u8; 16],
}

impl WhitelistEntry {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 34;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 0),
        ("prefix_len", 1),
        ("addr", 2),
        ("device", 18),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListWhitelistResponse {
    pub hdr: MsgHdr,
    pub count: u32,
    pub total: u32,
    pub offset: u32,
}

impl ListWhitelistResponse {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 24;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListWhitelistResponse;
    /// 定长部分字节数
    pub const FIXED_SIZE: usize = 24;
    /// 尾部元素类型与其字节数
    pub const TAIL_ELEM_SIZE: usize = 34;
    /// u16 长度上限内可承载的最大尾部条目数
    pub const MAX_TAIL_ENTRIES: usize = 1926;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("count", 12),
        ("total", 16),
        ("offset", 20),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RateEntry {
    pub af: u8,
    pub pad: [u8; 3],
    pub packets: u64,
    pub bytes: u64,
    pub syn_packets: u64,
    pub udp_packets: u64,
    pub icmp_packets: u64,
    pub ack_packets: u64,
    pub rst_packets: u64,
    pub fin_packets: u64,
    pub addr: addr16,
}

impl RateEntry {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 84;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 0),
        ("pad", 1),
        ("packets", 4),
        ("bytes", 12),
        ("syn_packets", 20),
        ("udp_packets", 28),
        ("icmp_packets", 36),
        ("ack_packets", 44),
        ("rst_packets", 52),
        ("fin_packets", 60),
        ("addr", 68),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListRatesResponse {
    pub hdr: MsgHdr,
    pub count: u32,
    pub total: u32,
    pub offset: u32,
    pub global_pps: u64,
    pub global_bps: u64,
}

impl ListRatesResponse {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 40;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListRatesResponse;
    /// 定长部分字节数
    pub const FIXED_SIZE: usize = 40;
    /// 尾部元素类型与其字节数
    pub const TAIL_ELEM_SIZE: usize = 84;
    /// u16 长度上限内可承载的最大尾部条目数
    pub const MAX_TAIL_ENTRIES: usize = 779;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("count", 12),
        ("total", 16),
        ("offset", 20),
        ("global_pps", 24),
        ("global_bps", 32),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UdpPortItem {
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

impl UdpPortItem {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 26;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("port", 0),
        ("packets", 2),
        ("bytes", 10),
        ("last_seen_secs", 18),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct IcmpTypeItem {
    pub r#type: u8,
    pub code: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

impl IcmpTypeItem {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 26;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("type", 0),
        ("code", 1),
        ("packets", 2),
        ("bytes", 10),
        ("last_seen_secs", 18),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ScannerItem {
    pub af: u8,
    pub pad: [u8; 3],
    pub addr: addr16,
    pub metric: u32,
    pub packets: u64,
}

impl ScannerItem {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 32;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 0),
        ("pad", 1),
        ("addr", 4),
        ("metric", 20),
        ("packets", 24),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AnalysisResponse {
    pub hdr: MsgHdr,
    pub pkt_sizes: [u64; 5],
    pub ttl_dist: [u64; 6],
    pub ip_frag_total: u64,
    pub ip_frag_count: u64,
    pub udp_port_count: u32,
    pub udp_port_capacity: u32,
    pub udp_ports: [UdpPortItem; 64],
    pub icmp_type_count: u32,
    pub icmp_type_capacity: u32,
    pub icmp_types: [IcmpTypeItem; 64],
    pub port_scan_count: u32,
    pub port_scan_threshold: u32,
    pub port_scanners: [ScannerItem; 20],
    pub service_probe_count: u32,
    pub service_probe_threshold: u32,
    pub service_probes: [ScannerItem; 20],
}

impl AnalysisResponse {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 4756;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::AnalysisResponse;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("pkt_sizes", 12),
        ("ttl_dist", 52),
        ("ip_frag_total", 100),
        ("ip_frag_count", 108),
        ("udp_port_count", 116),
        ("udp_port_capacity", 120),
        ("udp_ports", 124),
        ("icmp_type_count", 1788),
        ("icmp_type_capacity", 1792),
        ("icmp_types", 1796),
        ("port_scan_count", 3460),
        ("port_scan_threshold", 3464),
        ("port_scanners", 3468),
        ("service_probe_count", 4108),
        ("service_probe_threshold", 4112),
        ("service_probes", 4116),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DaemonRegisterAck {
    pub hdr: MsgHdr,
    pub accepted: u8,
}

impl DaemonRegisterAck {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 13;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::DaemonRegisterAck;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("accepted", 12),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BanIp {
    pub hdr: MsgHdr,
    pub af: u8,
    pub duration_secs: u32,
    pub addr: addr16,
    pub reason: [u8; 32],
}

impl BanIp {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 65;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::BanIp;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 12),
        ("duration_secs", 13),
        ("addr", 17),
        ("reason", 33),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct UnbanIp {
    pub hdr: MsgHdr,
    pub af: u8,
    pub duration_secs: u32,
    pub addr: addr16,
    pub reason: [u8; 32],
}

impl UnbanIp {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 65;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::UnbanIp;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 12),
        ("duration_secs", 13),
        ("addr", 17),
        ("reason", 33),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SetConfig {
    pub hdr: MsgHdr,
    pub flags: u32,
    pub ban_time: u32,
    pub rate_window_seconds: u32,
    pub max_packets_per_second: u64,
    pub max_bytes_per_second: u64,
    pub max_syn_per_second: u64,
    pub max_udp_per_second: u64,
    pub max_icmp_per_second: u64,
    pub max_ack_per_second: u64,
    pub max_rst_per_second: u64,
    pub max_fin_per_second: u64,
    pub dynamic_threshold_flags: u32,
    pub dynamic_threshold_ratio_x100: u32,
    pub baseline_pps: u64,
    pub baseline_bps: u64,
    pub ddos_ban_duration: u32,
}

impl SetConfig {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 116;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::SetConfig;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("flags", 12),
        ("ban_time", 16),
        ("rate_window_seconds", 20),
        ("max_packets_per_second", 24),
        ("max_bytes_per_second", 32),
        ("max_syn_per_second", 40),
        ("max_udp_per_second", 48),
        ("max_icmp_per_second", 56),
        ("max_ack_per_second", 64),
        ("max_rst_per_second", 72),
        ("max_fin_per_second", 80),
        ("dynamic_threshold_flags", 88),
        ("dynamic_threshold_ratio_x100", 92),
        ("baseline_pps", 96),
        ("baseline_bps", 104),
        ("ddos_ban_duration", 112),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListBansQuery {
    pub hdr: MsgHdr,
    pub offset: u32,
    pub limit: u32,
}

impl ListBansQuery {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 20;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListBansQuery;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("offset", 12),
        ("limit", 16),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListWhitelistQuery {
    pub hdr: MsgHdr,
    pub offset: u32,
    pub limit: u32,
}

impl ListWhitelistQuery {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 20;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListWhitelistQuery;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("offset", 12),
        ("limit", 16),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ListRatesQuery {
    pub hdr: MsgHdr,
    pub offset: u32,
    pub limit: u32,
}

impl ListRatesQuery {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 20;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::ListRatesQuery;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("offset", 12),
        ("limit", 16),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AddWhitelist {
    pub hdr: MsgHdr,
    pub af: u8,
    pub prefix_len: u8,
    pub addr: addr16,
    pub device: [u8; 16],
}

impl AddWhitelist {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 46;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::AddWhitelist;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 12),
        ("prefix_len", 13),
        ("addr", 14),
        ("device", 30),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RemoveWhitelist {
    pub hdr: MsgHdr,
    pub af: u8,
    pub prefix_len: u8,
    pub addr: addr16,
    pub device: [u8; 16],
}

impl RemoveWhitelist {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 46;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::RemoveWhitelist;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
        ("af", 12),
        ("prefix_len", 13),
        ("addr", 14),
        ("device", 30),
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct StatsQuery {
    pub hdr: MsgHdr,
}

impl StatsQuery {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 12;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::StatsQuery;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct AnalysisQuery {
    pub hdr: MsgHdr,
}

impl AnalysisQuery {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 12;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::AnalysisQuery;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
    ];
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct DaemonRegister {
    pub hdr: MsgHdr,
}

impl DaemonRegister {
    /// 线格式字节数（packed，无填充；变长消息为定长部分）
    pub const WIRE_SIZE: usize = 12;
    /// 对应的 MsgType 取值
    pub const MSG_TYPE: MsgType = MsgType::DaemonRegister;
    /// 逐字段偏移（不含变长尾部；供一致性测试对照 offsetof）
    pub const FIELD_OFFSETS: &[(&str, usize)] = &[
    ];
}
