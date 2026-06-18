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
}

impl FwNlMsgType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::DdosEvent),
            2 => Some(Self::BanIp),
            3 => Some(Self::UnbanIp),
            4 => Some(Self::SetConfig),
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

        let event: Self = unsafe { std::ptr::read(data.as_ptr() as *const Self) };
        Ok(event)
    }

    /// 获取 IP 地址字符串
    pub fn ip_str(&self) -> String {
        if self.af == 2 {
            // AF_INET
            format!("{}.{}.{}.{}", self.addr[0], self.addr[1], self.addr[2], self.addr[3])
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
        let end = self.reason.iter().position(|&b| b == 0).unwrap_or(self.reason.len());
        String::from_utf8_lossy(&self.reason[..end]).to_string()
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
}

impl FwNlBanCmd {
    /// 创建封禁命令
    pub fn new_ban(ip: IpAddr, duration_secs: u32) -> Self {
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
                msg_type: (FwNlMsgType::BanIp as u16).to_be(),
                msg_len: (std::mem::size_of::<Self>() as u16).to_be(),
                seq: 0,
            },
            af,
            duration_secs: duration_secs.to_be(),
            addr,
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
        }
    }

    /// 转换为字节数组
    pub fn to_bytes(&self) -> Vec<u8> {
        let ptr = self as *const Self as *const u8;
        unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<Self>()).to_vec() }
    }
}
