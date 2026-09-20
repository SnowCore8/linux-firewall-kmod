//! Netlink 发送命令
//!
//! 所有 `send_*` 方法均为 `NetlinkContext` 的实例方法，
//! 通过 `send_command` 发送原始 netlink 消息到内核。

use anyhow::Result;
use std::net::IpAddr;

use super::protocol::{FwNlBanCmd, FwNlConfigUpdate, FwNlMsgHdr, FwNlMsgType, FW_NL_MAGIC};
use super::responses::{
    FwNlAnalysisQuery, FwNlListBansQuery, FwNlListRatesQuery, FwNlListWhitelistQuery,
    FwNlStatsQuery, FwNlWhitelistCmd,
};

impl super::NetlinkContext {
    /// 发送封禁指令到内核
    pub fn send_ban(&self, ip: IpAddr, duration_secs: u32, reason: &str) -> Result<()> {
        let cmd = FwNlBanCmd::new_ban(ip, duration_secs, reason);
        self.send_command(&cmd.to_bytes())
    }

    /// 发送解封指令到内核
    pub fn send_unban(&self, ip: IpAddr) -> Result<()> {
        let cmd = FwNlBanCmd::new_unban(ip);
        self.send_command(&cmd.to_bytes())
    }

    /// 发送配置更新到内核
    pub fn send_config_update(&self, config: &FwNlConfigUpdate) -> Result<()> {
        self.send_command(&config.to_bytes())
    }

    /// 发送封禁列表查询（可分页；limit=0 表示内核默认页大小）
    pub fn send_list_bans_query(&self, seq: u32) -> Result<()> {
        self.send_list_bans_query_page(seq, 0, 0)
    }

    pub fn send_list_bans_query_page(&self, seq: u32, offset: u32, limit: u32) -> Result<()> {
        let query = FwNlListBansQuery::new(seq, offset, limit);
        self.send_command(&query.to_bytes())
    }

    /// 发送统计数据查询（启动时恢复状态）
    pub fn send_stats_query(&self, seq: u32) -> Result<()> {
        let query = FwNlStatsQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送白名单列表查询（启动时恢复状态；取内核默认页）
    pub fn send_list_whitelist_query(&self, seq: u32) -> Result<()> {
        let query = FwNlListWhitelistQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送白名单列表分页查询（offset/limit；limit=0 表示内核默认页大小）
    pub fn send_list_whitelist_query_page(
        &self,
        seq: u32,
        offset: u32,
        limit: u32,
    ) -> Result<()> {
        let query = FwNlListWhitelistQuery::new_page(seq, offset, limit);
        self.send_command(&query.to_bytes())
    }

    /// 发送添加白名单命令到内核
    pub fn send_add_whitelist(&self, ip: &str, prefix_len: u8, device: &str) -> Result<()> {
        let cmd = FwNlWhitelistCmd::new_add(ip, prefix_len, device)?;
        self.send_command(&cmd.to_bytes())
    }

    /// 发送移除白名单命令到内核
    pub fn send_remove_whitelist(&self, ip: &str, prefix_len: u8) -> Result<()> {
        let cmd = FwNlWhitelistCmd::new_remove(ip, prefix_len)?;
        self.send_command(&cmd.to_bytes())
    }

    /// 发送速率统计查询（取内核默认页）
    pub fn send_list_rates_query(&self, seq: u32) -> Result<()> {
        let query = FwNlListRatesQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送速率统计分页查询（offset/limit；limit=0 表示内核默认页大小）
    pub fn send_list_rates_query_page(&self, seq: u32, offset: u32, limit: u32) -> Result<()> {
        let query = FwNlListRatesQuery::new_page(seq, offset, limit);
        self.send_command(&query.to_bytes())
    }

    /// 发送分析数据查询（包大小/TTL/分片/UDP/ICMP/端口扫描/服务探测）
    pub fn send_analysis_query(&self, seq: u32) -> Result<()> {
        let query = FwNlAnalysisQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 向内核注册为唯一守护进程
    pub fn send_register(&self) -> Result<()> {
        let hdr = FwNlMsgHdr {
            magic: FW_NL_MAGIC.to_be(),
            msg_type: (FwNlMsgType::DaemonRegister as u16).to_be(),
            msg_len: (std::mem::size_of::<FwNlMsgHdr>() as u16).to_be(),
            seq: 0u32.to_be(),
        };
        // SAFETY: FwNlMsgHdr 是 #[repr(C, packed)] 结构体，
        // 将其内存布局直接作为字节切片发送是安全的。
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &hdr as *const FwNlMsgHdr as *const u8,
                std::mem::size_of::<FwNlMsgHdr>(),
            )
        };
        self.send_command(bytes)
    }
}
