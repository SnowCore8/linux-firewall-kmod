//! Netlink 通信模块
//!
//! 实现守护进程与内核模块的双向通信：
//! - 接收内核推送的 DDoS 检测事件
//! - 向内核发送封禁/解封指令

mod decision;
mod protocol;

use anyhow::Result;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use protocol::{
    FwNlBanCmd, FwNlBanStateChange, FwNlConfigAck, FwNlConfigUpdate, FwNlDdosEvent,
    FwNlListBansQuery, FwNlListBansResponse, FwNlListWhitelistQuery, FwNlListWhitelistResponse,
    FwNlMsgType, FwNlStatsQuery, FwNlStatsResponse, FwNlWhitelistCmd, FW_NL_MAGIC,
};

pub use decision::DdosDecisionEngine;
pub use protocol::{config_flags, FwNlConfigUpdate as ConfigUpdate};

/// Netlink 协议号（NETLINK_USERSOCK）
const NETLINK_USERSOCK: i32 = 2;

/// 全局 NetlinkContext 实例（程序内部共享）
static GLOBAL_NETLINK_CTX: OnceLock<Arc<NetlinkContext>> = OnceLock::new();

/// 获取全局 NetlinkContext
pub fn get_global_netlink_ctx() -> Option<Arc<NetlinkContext>> {
    GLOBAL_NETLINK_CTX.get().cloned()
}

/// 设置全局 NetlinkContext（仅在启动时调用一次）
pub fn set_global_netlink_ctx(ctx: Arc<NetlinkContext>) -> Result<()> {
    GLOBAL_NETLINK_CTX
        .set(ctx)
        .map_err(|_| anyhow::anyhow!("Global NetlinkContext already set"))
}

/// Netlink 通信上下文
pub struct NetlinkContext {
    fd: i32,
    running: Arc<AtomicBool>,
    decision_engine: Mutex<Option<Arc<DdosDecisionEngine>>>,
}

impl NetlinkContext {
    /// 创建 Netlink 通信上下文
    pub fn new() -> Result<Self> {
        use nix::libc::{AF_NETLINK, SOCK_RAW};

        // 创建 netlink socket
        let fd = unsafe { nix::libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK) };
        if fd < 0 {
            return Err(anyhow::anyhow!("创建 netlink socket 失败"));
        }

        // 绑定到 netlink 地址
        let mut addr: nix::libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // 让内核分配
        addr.nl_groups = 1; // 监听组 1（内核广播组）

        let ret = unsafe {
            nix::libc::bind(
                fd,
                &addr as *const nix::libc::sockaddr_nl as *const nix::libc::sockaddr,
                std::mem::size_of::<nix::libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            unsafe { nix::libc::close(fd) };
            return Err(anyhow::anyhow!("绑定 netlink socket 失败"));
        }

        // 设置非阻塞模式
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) };

        Ok(Self {
            fd,
            running: Arc::new(AtomicBool::new(false)),
            decision_engine: Mutex::new(None),
        })
    }

    /// 设置 DDoS 决策引擎（线程安全）
    pub fn set_decision_engine(&self, engine: Arc<DdosDecisionEngine>) {
        if let Ok(mut de) = self.decision_engine.lock() {
            *de = Some(engine);
        }
    }

    /// 启动接收线程
    pub fn start_receiver(&self) -> Result<thread::JoinHandle<()>> {
        let fd = self.fd;
        let running = self.running.clone();
        let decision_engine = self.decision_engine.lock().ok().and_then(|de| de.clone());
        running.store(true, Ordering::SeqCst);

        let handle = thread::spawn(move || {
            let mut buf = vec![0u8; 4096];
            let mut pollfd = nix::libc::pollfd {
                fd,
                events: nix::libc::POLLIN,
                revents: 0,
            };

            while running.load(Ordering::Relaxed) {
                // 等待数据可读（100ms 超时）
                let ret = unsafe { nix::libc::poll(&mut pollfd, 1, 100) };

                if ret == 0 {
                    continue; // 超时
                }

                if ret < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() != std::io::ErrorKind::Interrupted {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "poll 失败";
                            "error" => %err
                        );
                    }
                    continue;
                }

                if pollfd.revents & nix::libc::POLLIN != 0 {
                    // 读取数据
                    let n =
                        unsafe { nix::libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };

                    if n > 0 {
                        if let Err(e) = Self::handle_message(&buf[..n as usize], &decision_engine) {
                            crate::logger::warn!(
                                crate::logger::get(),
                                "处理 netlink 消息失败";
                                "error" => %e
                            );
                        }
                    } else if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::WouldBlock {
                            crate::logger::error!(
                                crate::logger::get(),
                                "接收 netlink 消息失败";
                                "error" => %err
                            );
                        }
                    }
                }
            }
        });

        Ok(handle)
    }

    /// 处理接收到的消息
    fn handle_message(
        data: &[u8],
        decision_engine: &Option<Arc<DdosDecisionEngine>>,
    ) -> Result<()> {
        use nix::libc::nlmsghdr;

        if data.len() < std::mem::size_of::<nlmsghdr>() {
            anyhow::bail!("消息太短");
        }

        // 解析 netlink 消息头
        let _nlh: &nlmsghdr = unsafe { &*(data.as_ptr() as *const nlmsghdr) };

        // 获取自定义消息头（从 nlmsghdr 之后开始）
        let hdr_data = &data[std::mem::size_of::<nlmsghdr>()..];

        // 解析魔数
        let magic = u32::from_be_bytes([hdr_data[0], hdr_data[1], hdr_data[2], hdr_data[3]]);
        if magic != FW_NL_MAGIC {
            anyhow::bail!("魔数不匹配：0x{:08x}", magic);
        }

        let msg_type = u16::from_be_bytes([hdr_data[4], hdr_data[5]]);
        let _msg_len = u16::from_be_bytes([hdr_data[6], hdr_data[7]]);

        match FwNlMsgType::from_u16(msg_type) {
            Some(FwNlMsgType::DdosEvent) => {
                // 解析 DDoS 事件（从 hdr_data 起始位置读取完整结构）
                if hdr_data.len() < std::mem::size_of::<FwNlDdosEvent>() {
                    anyhow::bail!("DDoS 事件数据太短");
                }

                let event = FwNlDdosEvent::from_bytes(hdr_data)?;
                let ip_str = event.ip_str();
                let reason = event.reason_str();
                let rate_pps = event.rate_pps;

                crate::logger::info!(
                    crate::logger::get(),
                    "收到 DDoS 事件";
                    "ip" => &ip_str,
                    "reason" => &reason,
                    "rate_pps" => rate_pps
                );

                // 调用决策引擎
                if let Some(engine) = decision_engine {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        engine.handle_event(ip, &reason, rate_pps);
                    } else {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "无法解析 IP 地址";
                            "ip" => &ip_str
                        );
                    }
                }
            }
            Some(FwNlMsgType::BanStateChange) => {
                // 解析封禁状态变更事件（从 hdr_data 起始位置读取完整结构）
                if hdr_data.len() < std::mem::size_of::<FwNlBanStateChange>() {
                    anyhow::bail!("BanStateChange 事件数据太短");
                }

                let event = FwNlBanStateChange::from_bytes(hdr_data)?;
                let ip_str = event.ip_str();

                if event.is_ban() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "收到封禁状态变更：封禁";
                        "ip" => &ip_str,
                        "duration_secs" => event.duration_secs()
                    );

                    // 更新 ACTIVE_BAN_CACHE
                    let cache = crate::types::ACTIVE_BAN_CACHE
                        .get_or_init(crate::types::ActiveBanCache::new);
                    let now = crate::types::now_secs();
                    let ban_info = crate::types::BanInfo {
                        ip: ip_str.clone(),
                        ip_num: 0,
                        jail_name: "kernel".to_string(),
                        reason: crate::types::BanReason::ManualBan,
                        banned_at: now,
                        expires_at: if event.duration_secs() == 0 {
                            0
                        } else {
                            now + event.duration_secs() as i64
                        },
                        is_permanent: event.duration_secs() == 0,
                        fail_count: 0,
                    };
                    cache.insert(ban_info);
                    // 更新 DAEMON_STATS 计数器
                    crate::types::DAEMON_STATS
                        .ips_banned
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    crate::logger::info!(
                        crate::logger::get(),
                        "已更新 ACTIVE_BAN_CACHE";
                        "ip" => &ip_str,
                        "cache_len" => cache.len()
                    );
                } else if event.is_unban() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "收到封禁状态变更：解封";
                        "ip" => &ip_str
                    );

                    // 从 ACTIVE_BAN_CACHE 移除
                    let cache = crate::types::ACTIVE_BAN_CACHE
                        .get_or_init(crate::types::ActiveBanCache::new);
                    cache.remove(&ip_str);
                    // 更新 DAEMON_STATS 计数器
                    crate::types::DAEMON_STATS
                        .total_unbans
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Some(FwNlMsgType::ListBansResponse) => {
                // 处理封禁列表响应
                if hdr_data.len() < std::mem::size_of::<FwNlListBansResponse>() {
                    anyhow::bail!("封禁列表响应数据太短");
                }

                let (_resp, entries) = FwNlListBansResponse::from_bytes(hdr_data)?;
                crate::logger::info!(
                    crate::logger::get(),
                    "收到封禁列表响应";
                    "count" => entries.len()
                );

                // 更新 ACTIVE_BAN_CACHE
                let cache =
                    crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);

                for entry in &entries {
                    let ip_str = FwNlListBansResponse::ip_str(entry);
                    let duration = u32::from_be(entry.duration_secs);
                    let is_permanent = entry.is_permanent != 0;
                    // 使用内核提供的实际封禁时间（unix 时间戳）
                    let banned_at = u64::from_be(entry.banned_at) as i64;

                    let ban_info = crate::types::BanInfo {
                        ip: ip_str.clone(),
                        ip_num: 0,
                        jail_name: "kernel".to_string(),
                        reason: crate::types::BanReason::ManualBan,
                        banned_at,
                        expires_at: if is_permanent {
                            0
                        } else {
                            banned_at + duration as i64
                        },
                        is_permanent,
                        fail_count: 0,
                    };
                    cache.insert(ban_info);
                }

                crate::logger::info!(
                    crate::logger::get(),
                    "已恢复封禁状态";
                    "restored_count" => entries.len(),
                    "cache_len" => cache.len()
                );
            }
            Some(FwNlMsgType::StatsResponse) => {
                // 处理统计数据响应
                if hdr_data.len() < std::mem::size_of::<FwNlStatsResponse>() {
                    anyhow::bail!("统计数据响应太短");
                }

                let stats = FwNlStatsResponse::from_bytes(hdr_data)?;
                crate::logger::info!(
                    crate::logger::get(),
                    "收到统计数据响应";
                    "current_bans" => stats.current_bans(),
                    "total_bans" => stats.total_bans(),
                    "total_unbans" => stats.total_unbans(),
                    "whitelist_count" => stats.whitelist_count(),
                    "packets_dropped" => stats.packets_dropped(),
                    "packets_accepted" => stats.packets_accepted()
                );

                // 更新 DAEMON_STATS
                crate::types::DAEMON_STATS
                    .total_unbans
                    .store(stats.total_unbans(), std::sync::atomic::Ordering::Relaxed);
                crate::types::DAEMON_STATS.whitelist_count.store(
                    stats.whitelist_count(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                crate::types::DAEMON_STATS.packets_dropped.store(
                    stats.packets_dropped(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                crate::types::DAEMON_STATS.packets_accepted.store(
                    stats.packets_accepted(),
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            Some(FwNlMsgType::ListWhitelistResponse) => {
                // 处理白名单列表响应
                if hdr_data.len() < std::mem::size_of::<FwNlListWhitelistResponse>() {
                    anyhow::bail!("白名单列表响应数据太短");
                }

                let (_resp, entries) = FwNlListWhitelistResponse::from_bytes(hdr_data)?;
                crate::logger::info!(
                    crate::logger::get(),
                    "收到白名单列表响应";
                    "count" => entries.len()
                );

                // 更新 DAEMON_STATS.whitelist_count
                crate::types::DAEMON_STATS
                    .whitelist_count
                    .store(entries.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            Some(FwNlMsgType::ConfigAck) => {
                // 处理配置更新确认
                if hdr_data.len() < std::mem::size_of::<FwNlConfigAck>() {
                    anyhow::bail!("配置确认数据太短");
                }

                let ack = FwNlConfigAck::from_bytes(hdr_data)?;
                let applied = ack.applied_flags();
                let rejected = ack.rejected_flags();

                if rejected != 0 {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "配置更新部分被拒绝";
                        "applied_flags" => format!("0x{:x}", applied),
                        "rejected_flags" => format!("0x{:x}", rejected)
                    );
                } else {
                    crate::logger::info!(
                        crate::logger::get(),
                        "配置更新已确认";
                        "applied_flags" => format!("0x{:x}", applied)
                    );
                }
            }
            _ => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "未知消息类型";
                    "msg_type" => msg_type
                );
            }
        }

        Ok(())
    }

    /// 发送封禁指令到内核
    pub fn send_ban(&self, ip: IpAddr, duration_secs: u32) -> Result<()> {
        let cmd = FwNlBanCmd::new_ban(ip, duration_secs);
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

    /// 发送封禁列表查询（启动时恢复状态）
    pub fn send_list_bans_query(&self, seq: u32) -> Result<()> {
        let query = FwNlListBansQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送统计数据查询（启动时恢复状态）
    pub fn send_stats_query(&self, seq: u32) -> Result<()> {
        let query = FwNlStatsQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送白名单列表查询（启动时恢复状态）
    pub fn send_list_whitelist_query(&self, seq: u32) -> Result<()> {
        let query = FwNlListWhitelistQuery::new(seq);
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

    /// 发送原始命令到内核
    fn send_command(&self, data: &[u8]) -> Result<()> {
        use nix::libc::{nlmsghdr, sockaddr_nl, AF_NETLINK};

        // 构造标准 nlmsghdr + 自定义消息
        let nlmsg_len = std::mem::size_of::<nlmsghdr>() + data.len();
        let mut buf = vec![0u8; nlmsg_len];

        // 填充 nlmsghdr
        let nlh: &mut nlmsghdr = unsafe { &mut *(buf.as_mut_ptr() as *mut nlmsghdr) };
        nlh.nlmsg_len = nlmsg_len as u32;
        nlh.nlmsg_type = 0; // 自定义消息类型
        nlh.nlmsg_flags = 0;
        nlh.nlmsg_seq = 0;
        nlh.nlmsg_pid = 0;

        // 复制自定义消息到 nlmsghdr 之后
        buf[std::mem::size_of::<nlmsghdr>()..].copy_from_slice(data);

        // 构造内核地址（pid=0 表示内核）
        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // 内核

        let n = unsafe {
            nix::libc::sendto(
                self.fd,
                buf.as_ptr() as *const _,
                buf.len(),
                0,
                &addr as *const sockaddr_nl as *const _,
                std::mem::size_of::<sockaddr_nl>() as u32,
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            return Err(anyhow::anyhow!("发送 netlink 消息失败: {}", err));
        }

        if n as usize != buf.len() {
            return Err(anyhow::anyhow!(
                "发送 netlink 消息不完整: {} / {}",
                n,
                buf.len()
            ));
        }

        Ok(())
    }

    /// 停止接收线程
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

impl Drop for NetlinkContext {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { nix::libc::close(self.fd) };
        }
    }
}
