//! Netlink 查询/响应协议定义
//!
//! 守护进程启动时恢复状态的请求-响应类型，
//! 以及白名单操作命令、配置确认、速率统计等。
//!
//! 核心消息类型（FwNlMsgHdr、FwNlMsgType 等）定义在 protocol.rs。

use anyhow::Result;

use super::protocol::{FwNlMsgHdr, FwNlMsgType, FW_NL_MAGIC};

// ============================================================================
// 请求 - 响应协议（守护进程启动时恢复状态）
// ============================================================================

/// 封禁列表查询请求（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListBansQuery {
    pub hdr: FwNlMsgHdr,
}

impl FwNlListBansQuery {
    pub fn new(seq: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::ListBansQuery as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: seq.to_be(),
            },
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

/// 封禁条目（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlBanEntry {
    pub af: u8,
    pub is_permanent: u8,
    pub duration_secs: u32,
    pub banned_at: u64,
    pub addr: [u8; 16],
    pub jail_name: [u8; 32], // Jail 名称
    pub reason: [u8; 32],    // 封禁原因
}

/// 封禁列表响应（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListBansResponse {
    pub hdr: FwNlMsgHdr,
    pub count: u32,
    // 后面紧跟 count 个 FwNlBanEntry
}

/// 封禁表最大条目数（与内核 MAX_BAN_ENTRIES 一致）
const MAX_BAN_ENTRIES: usize = 4096;
/// 白名单表最大条目数（与内核 WHITELIST_MAX_ENTRIES 一致）
const MAX_WHITELIST_ENTRIES: usize = 64;
/// 速率表最大条目数（与内核 RATE_HASH_SIZE 一致）
const MAX_RATE_ENTRIES: usize = 4096;

impl FwNlListBansResponse {
    pub fn from_bytes(data: &[u8]) -> Result<(Self, Vec<FwNlBanEntry>)> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("响应数据太短");
        }

        let resp: Self = unsafe {
            // SAFETY: data 长度已验证 >= size_of::<Self>()，
            // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
            std::ptr::read(data.as_ptr() as *const Self)
        };
        let count = u32::from_be(resp.count) as usize;
        if count > MAX_BAN_ENTRIES {
            anyhow::bail!("封禁条目数 {} 超出上限 {}", count, MAX_BAN_ENTRIES);
        }
        let entries_data = &data[std::mem::size_of::<Self>()..];

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * std::mem::size_of::<FwNlBanEntry>();
            if offset + std::mem::size_of::<FwNlBanEntry>() > entries_data.len() {
                anyhow::bail!("封禁条目数据不完整");
            }
            let entry: FwNlBanEntry = unsafe {
                // SAFETY: 上方已验证 offset + size_of::<FwNlBanEntry>() <= entries_data.len()，
                // FwNlBanEntry 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝。
                std::ptr::read(entries_data.as_ptr().add(offset) as *const FwNlBanEntry)
            };
            entries.push(entry);
        }

        Ok((resp, entries))
    }

    pub fn ip_str(entry: &FwNlBanEntry) -> String {
        if entry.af == 2 {
            format!(
                "{}.{}.{}.{}",
                entry.addr[0], entry.addr[1], entry.addr[2], entry.addr[3]
            )
        } else if entry.af == 10 {
            let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(entry.addr);
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 获取 Jail 名称字符串
    pub fn jail_name_str(entry: &FwNlBanEntry) -> String {
        let end = entry
            .jail_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(entry.jail_name.len());
        String::from_utf8_lossy(&entry.jail_name[..end]).to_string()
    }

    /// 获取封禁原因字符串
    pub fn reason_str(entry: &FwNlBanEntry) -> String {
        let end = entry
            .reason
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(entry.reason.len());
        String::from_utf8_lossy(&entry.reason[..end]).to_string()
    }
}

/// 统计数据查询请求（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlStatsQuery {
    pub hdr: FwNlMsgHdr,
}

impl FwNlStatsQuery {
    pub fn new(seq: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::StatsQuery as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: seq.to_be(),
            },
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

/// 统计数据响应（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlStatsResponse {
    pub hdr: FwNlMsgHdr,
    pub current_bans: u64,
    pub total_bans: u64,
    pub total_unbans: u64,
    pub whitelist_count: u64,
    pub packets_dropped: u64,
    pub packets_accepted: u64,
}

impl FwNlStatsResponse {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("统计数据响应太短");
        }

        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let resp: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(resp)
    }

    pub fn current_bans(&self) -> u64 {
        u64::from_be(self.current_bans)
    }

    pub fn total_bans(&self) -> u64 {
        u64::from_be(self.total_bans)
    }

    pub fn total_unbans(&self) -> u64 {
        u64::from_be(self.total_unbans)
    }

    pub fn whitelist_count(&self) -> u64 {
        u64::from_be(self.whitelist_count)
    }

    pub fn packets_dropped(&self) -> u64 {
        u64::from_be(self.packets_dropped)
    }

    pub fn packets_accepted(&self) -> u64 {
        u64::from_be(self.packets_accepted)
    }
}

// ============================================================================
// 白名单查询协议
// ============================================================================

/// 白名单列表查询请求（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListWhitelistQuery {
    pub hdr: FwNlMsgHdr,
}

impl FwNlListWhitelistQuery {
    pub fn new(seq: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::ListWhitelistQuery as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: seq.to_be(),
            },
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

/// 白名单条目（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlWhitelistEntry {
    pub af: u8,
    pub prefix_len: u8,
    pub addr: [u8; 16],
    pub device: [u8; 16],
}

/// 白名单列表响应（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListWhitelistResponse {
    pub hdr: FwNlMsgHdr,
    pub count: u32,
    // 后面紧跟 count 个 FwNlWhitelistEntry
}

impl FwNlListWhitelistResponse {
    pub fn from_bytes(data: &[u8]) -> Result<(Self, Vec<FwNlWhitelistEntry>)> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("白名单响应数据太短");
        }

        let resp: Self = unsafe {
            // SAFETY: data 长度已验证 >= size_of::<Self>()，
            // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
            std::ptr::read(data.as_ptr() as *const Self)
        };
        let count = u32::from_be(resp.count) as usize;
        if count > MAX_WHITELIST_ENTRIES {
            anyhow::bail!("白名单条目数 {} 超出上限 {}", count, MAX_WHITELIST_ENTRIES);
        }
        let entries_data = &data[std::mem::size_of::<Self>()..];

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * std::mem::size_of::<FwNlWhitelistEntry>();
            if offset + std::mem::size_of::<FwNlWhitelistEntry>() > entries_data.len() {
                anyhow::bail!("白名单条目数据不完整");
            }
            let entry: FwNlWhitelistEntry = unsafe {
                // SAFETY: 上方已验证 offset + size_of::<FwNlWhitelistEntry>() <= entries_data.len()，
                // FwNlWhitelistEntry 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝。
                std::ptr::read(entries_data.as_ptr().add(offset) as *const FwNlWhitelistEntry)
            };
            entries.push(entry);
        }

        Ok((resp, entries))
    }
}

// ============================================================================
// 白名单操作命令
// ============================================================================

/// 白名单操作命令（守护进程 → 内核）
/// 用于添加或移除白名单条目
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlWhitelistCmd {
    pub hdr: FwNlMsgHdr,
    pub af: u8,           // 地址族
    pub prefix_len: u8,   // 前缀长度
    pub addr: [u8; 16],   // IP 地址
    pub device: [u8; 16], // 网络设备名称
}

impl FwNlWhitelistCmd {
    /// 创建添加白名单命令
    pub fn new_add(ip: &str, prefix_len: u8, device: &str) -> Result<Self> {
        let (af, addr) = Self::parse_ip(ip)?;
        let mut dev = [0u8; 16];
        let dev_bytes = device.as_bytes();
        let copy_len = dev_bytes.len().min(15);
        dev[..copy_len].copy_from_slice(&dev_bytes[..copy_len]);

        Ok(Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::AddWhitelist as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            af,
            prefix_len,
            addr,
            device: dev,
        })
    }

    /// 创建移除白名单命令
    pub fn new_remove(ip: &str, prefix_len: u8) -> Result<Self> {
        let (af, addr) = Self::parse_ip(ip)?;

        Ok(Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::RemoveWhitelist as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            af,
            prefix_len,
            addr,
            device: [0u8; 16],
        })
    }

    /// 解析 IP 地址
    fn parse_ip(ip: &str) -> Result<(u8, [u8; 16])> {
        let addr: std::net::IpAddr = ip.parse().map_err(|_| anyhow::anyhow!("无效 IP 地址"))?;
        match addr {
            std::net::IpAddr::V4(v4) => {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&v4.octets());
                Ok((2, a)) // AF_INET
            }
            std::net::IpAddr::V6(v6) => Ok((10, v6.octets())), // AF_INET6
        }
    }

    /// 转换为字节数组
    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

// ============================================================================
// 配置确认响应
// ============================================================================

/// 配置更新确认（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlConfigAck {
    pub hdr: FwNlMsgHdr,
    /// 实际生效的配置项标志位
    pub applied_flags: u32,
    /// 被拒绝的配置项标志位（如 ban_time=0）
    pub rejected_flags: u32,
}

impl FwNlConfigAck {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("配置确认数据太短");
        }
        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let ack: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(ack)
    }

    pub fn applied_flags(&self) -> u32 {
        u32::from_be(self.applied_flags)
    }

    pub fn rejected_flags(&self) -> u32 {
        u32::from_be(self.rejected_flags)
    }
}

// ============================================================================
// 速率统计查询/响应
// ============================================================================

/// 速率统计查询请求（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListRatesQuery {
    pub hdr: FwNlMsgHdr,
}

impl FwNlListRatesQuery {
    pub fn new(seq: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::ListRatesQuery as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: seq.to_be(),
            },
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

/// 速率统计条目（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlRateEntry {
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
    pub addr: [u8; 16],
}

/// 速率统计响应（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlListRatesResponse {
    pub hdr: FwNlMsgHdr,
    pub count: u32,
    pub total: u32,      /* 内核中实际条目总数（用于感知截断） */
    pub global_pps: u64, /* 全局 PPS（自上次查询以来的平均包速率） */
    pub global_bps: u64, /* 全局 BPS（自上次查询以来的平均字节速率） */
                         // 后面紧跟 count 个 FwNlRateEntry
}

impl FwNlListRatesResponse {
    pub fn from_bytes(data: &[u8]) -> Result<(Self, Vec<FwNlRateEntry>)> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("响应数据太短");
        }

        let resp: Self = unsafe {
            // SAFETY: data 长度已验证 >= size_of::<Self>()，
            // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
            std::ptr::read(data.as_ptr() as *const Self)
        };
        let count = u32::from_be(resp.count) as usize;
        if count > MAX_RATE_ENTRIES {
            anyhow::bail!("速率条目数 {} 超出上限 {}", count, MAX_RATE_ENTRIES);
        }
        let entries_data = &data[std::mem::size_of::<Self>()..];

        let mut entries = Vec::with_capacity(count);
        for i in 0..count {
            let offset = i * std::mem::size_of::<FwNlRateEntry>();
            if offset + std::mem::size_of::<FwNlRateEntry>() > entries_data.len() {
                anyhow::bail!("速率条目数据不完整");
            }
            let entry: FwNlRateEntry = unsafe {
                // SAFETY: 上方已验证 offset + size_of::<FwNlRateEntry>() <= entries_data.len()，
                // FwNlRateEntry 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝。
                std::ptr::read(entries_data.as_ptr().add(offset) as *const FwNlRateEntry)
            };
            entries.push(entry);
        }

        Ok((resp, entries))
    }

    pub fn ip_str(entry: &FwNlRateEntry) -> String {
        if entry.af == 2 {
            // AF_INET
            format!(
                "{}.{}.{}.{}",
                entry.addr[0], entry.addr[1], entry.addr[2], entry.addr[3]
            )
        } else if entry.af == 10 {
            // AF_INET6
            let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(entry.addr);
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 获取全局 PPS（字节序转换）
    pub fn global_pps(&self) -> u64 {
        u64::from_be(self.global_pps)
    }

    /// 获取全局 BPS（字节序转换）
    pub fn global_bps(&self) -> u64 {
        u64::from_be(self.global_bps)
    }
}

// ============================================================================
// 分析数据查询协议（替代 7 个 procfs 文本接口）
// ============================================================================

/// 分析数据 UDP 端口条目
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlUdpPortItem {
    pub port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// 分析数据 ICMP 类型条目
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlIcmpTypeItem {
    pub r#type: u8,
    pub code: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_secs: u64,
}

/// 分析数据端口扫描/服务探测条目
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlScannerItem {
    pub af: u8,
    pub pad: [u8; 3],
    pub addr: [u8; 16],
    pub metric: u32,
    pub packets: u64,
}

/// 分析数据查询请求（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlAnalysisQuery {
    pub hdr: FwNlMsgHdr,
}

impl FwNlAnalysisQuery {
    pub fn new(seq: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::AnalysisQuery as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: seq.to_be(),
            },
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}

/// 分析数据响应（内核 → 守护进程）
///
/// 将包大小分布、TTL 分布、IP 分片、UDP 端口分布、ICMP 类型分布、
/// 端口扫描者、服务探测者一次性打包返回。
#[repr(C, packed)]
pub struct FwNlAnalysisResponse {
    pub hdr: FwNlMsgHdr,
    pub pkt_sizes: [u64; 5],
    pub ttl_dist: [u64; 6],
    pub ip_frag_total: u64,
    pub ip_frag_count: u64,
    pub udp_port_count: u32,
    pub udp_port_capacity: u32,
    pub udp_ports: [FwNlUdpPortItem; 64],
    pub icmp_type_count: u32,
    pub icmp_type_capacity: u32,
    pub icmp_types: [FwNlIcmpTypeItem; 64],
    pub port_scan_count: u32,
    pub port_scan_threshold: u32,
    pub port_scanners: [FwNlScannerItem; 20],
    pub service_probe_count: u32,
    pub service_probe_threshold: u32,
    pub service_probes: [FwNlScannerItem; 20],
}

impl FwNlAnalysisResponse {
    pub fn from_bytes(data: &[u8]) -> Result<&Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!(
                "分析数据响应太短: {} < {}",
                data.len(),
                std::mem::size_of::<Self>()
            );
        }
        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，返回的引用生命周期受 data 约束。
        let resp: &Self = unsafe { &*(data.as_ptr() as *const Self) };
        Ok(resp)
    }
}
