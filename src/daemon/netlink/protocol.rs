//! Netlink 消息协议定义
//!
//! 与内核模块 netlink.c 中的结构体保持一致

use anyhow::Result;
use std::net::IpAddr;

/// Netlink 消息魔数（与内核模块一致）
pub const FW_NL_MAGIC: u32 = 0x46574C4E; // "FWLN"

/// 消息类型
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwNlMsgType {
    /// 内核 → 守护进程：DDoS 违规事件
    DdosEvent = 1,
    /// 守护进程 → 内核：封禁 IP
    BanIp = 2,
    /// 守护进程 → 内核：解封 IP
    UnbanIp = 3,
    /// 守护进程 → 内核：配置更新
    SetConfig = 4,
    /// 内核 → 守护进程：封禁状态变更（用户通过 procfs 操作时推送）
    BanStateChange = 5,
    /// 守护进程 → 内核：查询封禁列表
    ListBansQuery = 6,
    /// 内核 → 守护进程：封禁列表响应
    ListBansResponse = 7,
    /// 守护进程 → 内核：查询统计数据
    StatsQuery = 8,
    /// 内核 → 守护进程：统计数据响应
    StatsResponse = 9,
    /// 守护进程 → 内核：查询白名单列表
    ListWhitelistQuery = 10,
    /// 内核 → 守护进程：白名单列表响应
    ListWhitelistResponse = 11,
    /// 守护进程 → 内核：添加白名单条目
    AddWhitelist = 12,
    /// 守护进程 → 内核：移除白名单条目
    RemoveWhitelist = 13,
    /// 内核 → 守护进程：配置更新确认
    ConfigAck = 14,
    /// 守护进程 → 内核：查询速率统计
    ListRatesQuery = 15,
    /// 内核 → 守护进程：速率统计响应
    ListRatesResponse = 16,
    /// 内核 → 守护进程：白名单状态变更
    WhitelistStateChange = 17,
    /// 内核 → 守护进程：命令执行失败
    CmdResult = 18,
    /// 内核 → 守护进程：procfs 配置变更
    ConfigChange = 19,
    /// 守护进程 → 内核：查询分析数据
    AnalysisQuery = 20,
    /// 内核 → 守护进程：分析数据响应
    AnalysisResponse = 21,
}

impl FwNlMsgType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::DdosEvent),
            2 => Some(Self::BanIp),
            3 => Some(Self::UnbanIp),
            4 => Some(Self::SetConfig),
            5 => Some(Self::BanStateChange),
            6 => Some(Self::ListBansQuery),
            7 => Some(Self::ListBansResponse),
            8 => Some(Self::StatsQuery),
            9 => Some(Self::StatsResponse),
            10 => Some(Self::ListWhitelistQuery),
            11 => Some(Self::ListWhitelistResponse),
            12 => Some(Self::AddWhitelist),
            13 => Some(Self::RemoveWhitelist),
            14 => Some(Self::ConfigAck),
            15 => Some(Self::ListRatesQuery),
            16 => Some(Self::ListRatesResponse),
            17 => Some(Self::WhitelistStateChange),
            18 => Some(Self::CmdResult),
            19 => Some(Self::ConfigChange),
            20 => Some(Self::AnalysisQuery),
            21 => Some(Self::AnalysisResponse),
            _ => None,
        }
    }
}

/// 消息头结构（20 字节）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlMsgHdr {
    pub magic: u32,
    pub msg_type: u16,
    pub msg_len: u16,
    pub seq: u32,
}

/// DDoS 事件载荷（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlDdosEvent {
    pub hdr: FwNlMsgHdr,
    pub af: u8,
    pub reason: [u8; 32],
    pub rate_pps: u32,
    pub addr: [u8; 16],
}

impl FwNlDdosEvent {
    /// 从字节数组解析
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("数据太短");
        }

        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    /// 获取 IP 地址字符串
    pub fn ip_str(&self) -> String {
        if self.af == 2 {
            // AF_INET
            format!(
                "{}.{}.{}.{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3]
            )
        } else if self.af == 10 {
            // AF_INET6
            let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(self.addr);
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 获取原因字符串
    pub fn reason_str(&self) -> String {
        let end = self
            .reason
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.reason.len());
        String::from_utf8_lossy(&self.reason[..end]).to_string()
    }

    /// 获取速率（pps），大端转本机字节序
    pub fn rate_pps(&self) -> u32 {
        u32::from_be(self.rate_pps)
    }
}

/// 封禁状态变更事件（内核 → 守护进程）
/// 当用户通过 /proc/firewall/bans 手动封禁/解封时推送
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlBanStateChange {
    pub hdr: FwNlMsgHdr,
    pub action: u8, // 1=ban, 2=unban
    pub af: u8,
    pub duration_secs: u32,
    pub addr: [u8; 16],
    pub reason: [u8; 32],    // 封禁原因
    pub jail_name: [u8; 32], // Jail 名称（空串表示由守护进程推断）
    /// 实时统计字段（事件驱动同步，消除轮询延迟）
    pub packets_dropped: u64,
    pub packets_accepted: u64,
    pub current_bans: u32,
    pub whitelist_count: u32,
}

impl FwNlBanStateChange {
    /// 从字节数组解析
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("数据太短");
        }

        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    /// 获取 IP 地址字符串
    pub fn ip_str(&self) -> String {
        if self.af == 2 {
            // AF_INET
            format!(
                "{}.{}.{}.{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3]
            )
        } else if self.af == 10 {
            // AF_INET6
            let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(self.addr);
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 获取封禁时长（秒），转换字节序
    pub fn duration_secs(&self) -> u32 {
        u32::from_be(self.duration_secs)
    }

    /// 是否为封禁操作
    pub fn is_ban(&self) -> bool {
        self.action == 1
    }

    /// 是否为解封操作
    pub fn is_unban(&self) -> bool {
        self.action == 2
    }

    /// 获取封禁原因字符串
    pub fn reason_str(&self) -> String {
        let end = self
            .reason
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.reason.len());
        String::from_utf8_lossy(&self.reason[..end]).to_string()
    }

    /// 获取 Jail 名称字符串（空串返回 None）
    pub fn jail_name_str(&self) -> Option<String> {
        let end = self
            .jail_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.jail_name.len());
        if end == 0 {
            None
        } else {
            Some(String::from_utf8_lossy(&self.jail_name[..end]).to_string())
        }
    }

    /// 获取丢弃包数（大端转换）
    pub fn packets_dropped(&self) -> u64 {
        u64::from_be(self.packets_dropped)
    }

    /// 获取接受包数（大端转换）
    pub fn packets_accepted(&self) -> u64 {
        u64::from_be(self.packets_accepted)
    }

    /// 获取当前封禁数（大端转换）
    #[allow(dead_code)]
    pub fn current_bans(&self) -> u32 {
        u32::from_be(self.current_bans)
    }

    /// 获取当前白名单数（大端转换）
    pub fn whitelist_count(&self) -> u32 {
        u32::from_be(self.whitelist_count)
    }
}

/// 白名单状态变更事件（内核 → 守护进程）
/// 当白名单条目被添加或移除时推送
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlWhitelistStateChange {
    pub hdr: FwNlMsgHdr,
    pub action: u8, // 1=add, 2=remove
    pub af: u8,
    pub prefix_len: u8,
    pub addr: [u8; 16],
    pub device: [u8; 16],
    /// 实时统计字段
    pub whitelist_count: u32,
}

impl FwNlWhitelistStateChange {
    /// 从字节数组解析
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("数据太短");
        }
        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    /// 获取 IP 地址字符串
    pub fn ip_str(&self) -> String {
        if self.af == 2 {
            format!(
                "{}.{}.{}.{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3]
            )
        } else if self.af == 10 {
            let addr = std::net::Ipv6Addr::from(self.addr);
            addr.to_string()
        } else {
            "unknown".to_string()
        }
    }

    /// 获取设备名字符串
    pub fn device_str(&self) -> String {
        let end = self
            .device
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.device.len());
        String::from_utf8_lossy(&self.device[..end]).to_string()
    }

    /// 是否为添加操作
    pub fn is_add(&self) -> bool {
        self.action == 1
    }

    /// 是否为移除操作
    pub fn is_remove(&self) -> bool {
        self.action == 2
    }

    /// 获取当前白名单数（大端转换）
    pub fn whitelist_count(&self) -> u32 {
        u32::from_be(self.whitelist_count)
    }
}

/// 命令执行失败事件（内核 → 守护进程）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlCmdResult {
    pub hdr: FwNlMsgHdr,
    pub original_cmd: u16,
    pub pad: i16,
    pub error_code: i32,
    pub af: u8,
    pub addr: [u8; 16],
}

impl FwNlCmdResult {
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("CmdResult 数据太短");
        }
        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    pub fn original_cmd(&self) -> u16 {
        u16::from_be(self.original_cmd)
    }

    pub fn error_code(&self) -> i32 {
        i32::from_be(self.error_code)
    }

    pub fn ip_str(&self) -> String {
        if self.af == 2 {
            format!(
                "{}.{}.{}.{}",
                self.addr[0], self.addr[1], self.addr[2], self.addr[3]
            )
        } else if self.af == 10 {
            std::net::Ipv6Addr::from(self.addr).to_string()
        } else {
            "unknown".to_string()
        }
    }

    pub fn cmd_name(&self) -> &'static str {
        match self.original_cmd() {
            2 => "BanIp",
            3 => "UnbanIp",
            12 => "AddWhitelist",
            13 => "RemoveWhitelist",
            _ => "Unknown",
        }
    }
}

/// 封禁/解封命令载荷（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlBanCmd {
    pub hdr: FwNlMsgHdr,
    pub af: u8,
    pub duration_secs: u32,
    pub addr: [u8; 16],
    pub reason: [u8; 32], // 封禁原因
}

/// 配置更新载荷（守护进程 → 内核）
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct FwNlConfigUpdate {
    pub hdr: FwNlMsgHdr,
    /// 配置项标志位（哪些字段有效）
    pub flags: u32,
    /// 封禁时长（秒）
    pub ban_time: u32,
    /// 速率检测窗口（秒）
    pub rate_window_seconds: u32,
    /// 每秒最大数据包数
    pub max_packets_per_second: u64,
    /// 每秒最大字节数
    pub max_bytes_per_second: u64,
    /// 每秒最大 SYN 包数
    pub max_syn_per_second: u64,
    /// 每秒最大 UDP 包数
    pub max_udp_per_second: u64,
    /// 每秒最大 ICMP 包数
    pub max_icmp_per_second: u64,
    /// 每秒最大 ACK 包数
    pub max_ack_per_second: u64,
    /// 每秒最大 RST 包数
    pub max_rst_per_second: u64,
    /// 每秒最大 FIN 包数
    pub max_fin_per_second: u64,
    /// 动态阈值标志（bit0: enabled）
    pub dynamic_threshold_flags: u32,
    /// 动态阈值倍数 × 100
    pub dynamic_threshold_ratio_x100: u32,
    /// 基线 PPS（用于动态阈值更新）
    pub baseline_pps: u64,
    /// 基线 BPS（用于动态阈值更新）
    pub baseline_bps: u64,
    /// DDoS 封禁时长（秒）
    pub ddos_ban_duration: u32,
}

/// 配置项标志位（与内核 `netlink.c` 中 `FW_NL_CFG_*` 一一对应）
#[allow(dead_code)]
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

impl FwNlBanCmd {
    /// 创建封禁命令
    pub fn new_ban(ip: IpAddr, duration_secs: u32, reason: &str) -> Self {
        let (af, addr) = match ip {
            IpAddr::V4(v4) => (2u8, {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&v4.octets());
                a
            }),
            IpAddr::V6(v6) => (10u8, v6.octets()),
        };

        let mut reason_bytes = [0u8; 32];
        let reason_str = reason.as_bytes();
        let copy_len = reason_str.len().min(31); // 保留一个字节给 null terminator
        reason_bytes[..copy_len].copy_from_slice(&reason_str[..copy_len]);

        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::BanIp as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            af,
            duration_secs: duration_secs.to_be(),
            addr,
            reason: reason_bytes,
        }
    }

    /// 创建解封命令
    pub fn new_unban(ip: IpAddr) -> Self {
        let (af, addr) = match ip {
            IpAddr::V4(v4) => (2u8, {
                let mut a = [0u8; 16];
                a[..4].copy_from_slice(&v4.octets());
                a
            }),
            IpAddr::V6(v6) => (10u8, v6.octets()),
        };

        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::UnbanIp as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            af,
            duration_secs: 0,
            addr,
            reason: [0u8; 32],
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

impl FwNlConfigUpdate {
    /// 创建配置更新消息
    pub fn new(flags: u32) -> Self {
        Self {
            hdr: FwNlMsgHdr {
                magic: FW_NL_MAGIC.to_be(),
                msg_type: (FwNlMsgType::SetConfig as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            flags: flags.to_be(),
            ban_time: 0,
            rate_window_seconds: 0,
            max_packets_per_second: 0,
            max_bytes_per_second: 0,
            max_syn_per_second: 0,
            max_udp_per_second: 0,
            max_icmp_per_second: 0,
            max_ack_per_second: 0,
            max_rst_per_second: 0,
            max_fin_per_second: 0,
            dynamic_threshold_flags: 0,
            dynamic_threshold_ratio_x100: 0,
            baseline_pps: 0,
            baseline_bps: 0,
            ddos_ban_duration: 0,
        }
    }

    /// 设置封禁时长
    pub fn with_ban_time(mut self, secs: u32) -> Self {
        self.ban_time = secs.to_be();
        self
    }

    /// 设置速率窗口
    pub fn with_rate_window(mut self, secs: u32) -> Self {
        self.rate_window_seconds = secs.to_be();
        self
    }

    /// 设置最大 PPS
    pub fn with_max_pps(mut self, pps: u64) -> Self {
        self.max_packets_per_second = pps.to_be();
        self
    }

    /// 设置最大 BPS
    pub fn with_max_bps(mut self, bps: u64) -> Self {
        self.max_bytes_per_second = bps.to_be();
        self
    }

    /// 设置最大 SYN/s
    pub fn with_max_syn(mut self, syn: u64) -> Self {
        self.max_syn_per_second = syn.to_be();
        self
    }

    /// 设置最大 UDP/s
    pub fn with_max_udp(mut self, udp: u64) -> Self {
        self.max_udp_per_second = udp.to_be();
        self
    }

    /// 设置最大 ICMP/s
    pub fn with_max_icmp(mut self, icmp: u64) -> Self {
        self.max_icmp_per_second = icmp.to_be();
        self
    }

    /// 设置基线 PPS/BPS（用于动态阈值更新）
    pub fn with_baseline(mut self, pps: u64, bps: u64) -> Self {
        self.baseline_pps = pps.to_be();
        self.baseline_bps = bps.to_be();
        self
    }

    /// 设置 DDoS 封禁时长
    pub fn with_ddos_ban_duration(mut self, secs: u32) -> Self {
        self.ddos_ban_duration = secs.to_be();
        self
    }

    /// 转换为字节数组
    pub fn to_bytes(self) -> Vec<u8> {
        let ptr = &self as *const Self as *const u8;
        // SAFETY: &self 是有效的已初始化结构体引用，#[repr(C, packed)] 保证连续内存布局，
        // size_of::<Self>() 不会超出结构体范围，to_vec() 拷贝数据后原始引用不再需要。
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }

    /// 从字节数组解析（用于 ConfigChange 事件）
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < std::mem::size_of::<Self>() {
            anyhow::bail!("ConfigUpdate 数据太短");
        }
        // SAFETY: data 长度已验证 >= size_of::<Self>()，
        // Self 是 #[repr(C, packed)] 无对齐要求，ptr::read 按值拷贝不保留别名。
        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    /// 获取配置标志位
    pub fn flags(&self) -> u32 {
        u32::from_be(self.flags)
    }

    /// 获取 ban_time
    pub fn ban_time(&self) -> u32 {
        u32::from_be(self.ban_time)
    }
}
