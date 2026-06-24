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
    FwNlBanCmd, FwNlBanStateChange, FwNlCmdResult, FwNlConfigAck, FwNlConfigUpdate, FwNlDdosEvent,
    FwNlListBansQuery, FwNlListBansResponse, FwNlListRatesQuery, FwNlListRatesResponse,
    FwNlListWhitelistQuery, FwNlListWhitelistResponse, FwNlMsgType, FwNlStatsQuery,
    FwNlStatsResponse, FwNlWhitelistCmd, FwNlWhitelistStateChange, FW_NL_MAGIC,
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
        // SAFETY: socket() 是 POSIX 系统调用，AF_NETLINK/SOCK_RAW 是合法参数组合，
        // 返回值 fd 在后续 bind 失败时通过 close(fd) 释放，不泄露文件描述符。
        let fd = unsafe { nix::libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK) };
        if fd < 0 {
            return Err(anyhow::anyhow!("创建 netlink socket 失败"));
        }

        // 绑定到 netlink 地址
        // SAFETY: sockaddr_nl 是 POD 类型，zeroed() 后手动设置各字段是安全的，
        // nl_pid=0 让内核分配，nl_groups=1 监听内核广播组。
        let mut addr: nix::libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // 让内核分配
        addr.nl_groups = 1; // 监听组 1（内核广播组）

        // SAFETY: fd 是有效的 socket 文件描述符，addr 已正确初始化，
        // size_of::<sockaddr_nl>() 是合法的地址长度。bind 失败时走 close(fd) 清理路径。
        let ret = unsafe {
            nix::libc::bind(
                fd,
                &addr as *const nix::libc::sockaddr_nl as *const nix::libc::sockaddr,
                std::mem::size_of::<nix::libc::sockaddr_nl>() as u32,
            )
        };

        if ret < 0 {
            // SAFETY: fd 是有效的 socket 文件描述符，close 释放资源。
            // 此处是错误清理路径，close 返回值不影响后续错误传播。
            unsafe { nix::libc::close(fd) };
            return Err(anyhow::anyhow!("绑定 netlink socket 失败"));
        }

        // 设置非阻塞模式
        // SAFETY: fd 是有效的 socket 文件描述符，F_GETFL/F_SETFL 是合法的 fcntl 命令，
        // O_NONBLOCK 是合法的文件标志。fcntl 返回值在下一步使用。
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
            // 512KB 缓冲区：ListBansResponse 最大约 385KB（4096 条目 × ~94 字节）
            let mut buf = vec![0u8; 512 * 1024];
            let mut pollfd = nix::libc::pollfd {
                fd,
                events: nix::libc::POLLIN,
                revents: 0,
            };

            while running.load(Ordering::Relaxed) {
                // 等待数据可读（100ms 超时）
                // SAFETY: pollfd 是有效的 pollfd 结构体指针，nfds=1 表示监控一个 fd，
                // timeout=100ms 是合法的超时值。poll 返回值用于判断超时/错误/数据就绪。
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
                    // 读取数据（MSG_TRUNC 标志使 recv 返回实际消息长度，即使被截断）
                    // SAFETY: fd 是有效的 socket 文件描述符，buf.as_mut_ptr() 指向
                    // 256KB 的有效缓冲区，buf.len() 是合法的缓冲区大小。
                    // recv 返回值 n 用于切片 buf[..n]，负值表示错误。
                    let n = unsafe {
                        nix::libc::recv(
                            fd,
                            buf.as_mut_ptr() as *mut _,
                            buf.len(),
                            nix::libc::MSG_TRUNC,
                        )
                    };

                    if n > 0 {
                        let n = n as usize;
                        // 检测截断：MSG_TRUNC 使 recv 返回实际消息长度
                        // netlink 消息已被消费，无法重新读取，只能丢弃
                        if n > buf.len() {
                            crate::logger::error!(
                                crate::logger::get(),
                                "netlink 消息被截断丢弃：实际 {} 字节，缓冲区 {} 字节",
                                n,
                                buf.len()
                            );
                            crate::types::DAEMON_STATS
                                .netlink_recv_errors
                                .fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        crate::types::DAEMON_STATS
                            .netlink_messages_received
                            .fetch_add(1, Ordering::Relaxed);

                        if let Err(e) = Self::handle_message(&buf[..n], &decision_engine) {
                            crate::logger::warn!(
                                crate::logger::get(),
                                "处理 netlink 消息失败";
                                "error" => %e
                            );
                            crate::types::DAEMON_STATS
                                .netlink_recv_errors
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    } else if n < 0 {
                        let err = std::io::Error::last_os_error();
                        if err.kind() != std::io::ErrorKind::WouldBlock {
                            crate::logger::error!(
                                crate::logger::get(),
                                "接收 netlink 消息失败";
                                "error" => %err
                            );
                            crate::types::DAEMON_STATS
                                .netlink_recv_errors
                                .fetch_add(1, Ordering::Relaxed);
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
        // SAFETY: data 长度已验证 >= size_of::<nlmsghdr>()，
        // data.as_ptr() 指向有效的字节缓冲区，转换为 &nlmsghdr 只读引用。
        // nlmsghdr 是 POD 类型，无对齐问题（x86_64 上对齐要求 <= 8 字节）。
        let _nlh: &nlmsghdr = unsafe { &*(data.as_ptr() as *const nlmsghdr) };

        // 获取自定义消息头（从 nlmsghdr 之后开始）
        let hdr_data = &data[std::mem::size_of::<nlmsghdr>()..];

        // 验证自定义消息头长度（至少需要 8 字节：magic + type + len）
        if hdr_data.len() < 8 {
            anyhow::bail!("自定义消息头太短: {} 字节", hdr_data.len());
        }

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
                let reason_str = event.reason_str();

                if event.is_ban() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "收到封禁状态变更：封禁";
                        "ip" => &ip_str,
                        "duration_secs" => event.duration_secs(),
                        "reason" => &reason_str
                    );

                    // 优先使用内核传递的 jail_name，为空时根据 reason 推断
                    let (actual_reason, jail_name) = if let Some(jn) = event.jail_name_str() {
                        // 内核提供了明确的 jail_name，直接使用
                        (reason_str.clone(), jn)
                    } else if reason_str.starts_with("api:") {
                        // API 封禁：reason 格式为 "api:用户自定义的reason"
                        let actual = reason_str.strip_prefix("api:").unwrap_or(&reason_str);
                        (actual.to_string(), "api".to_string())
                    } else if reason_str.contains("SYN flood")
                        || reason_str.contains("UDP flood")
                        || reason_str.contains("ICMP flood")
                        || reason_str.contains("total rate")
                        || reason_str.contains("ddos")
                    {
                        (reason_str.clone(), "ddos".to_string())
                    } else if reason_str == "procfs"
                        || reason_str == "manual"
                        || reason_str == "api"
                        || reason_str == "restored"
                    {
                        (reason_str.clone(), "api".to_string())
                    } else if reason_str == "expired"
                        || reason_str == "unban"
                        || reason_str == "whitelist"
                    {
                        (reason_str.clone(), "system".to_string())
                    } else {
                        // 无法推断 jail 来源，统一归为 "api"
                        (reason_str.clone(), "api".to_string())
                    };

                    // 更新 ACTIVE_BAN_CACHE（try_insert: 已有条目不覆盖，保留 API 写入的正确 jail_name）
                    let cache = crate::types::ACTIVE_BAN_CACHE
                        .get_or_init(crate::types::ActiveBanCache::new);
                    let now = crate::types::now_secs();
                    let ban_info = crate::types::BanInfo {
                        ip: ip_str.clone(),
                        ip_num: 0,
                        jail_name,
                        reason: actual_reason,
                        banned_at: now,
                        expires_at: if event.duration_secs() == 0 {
                            0
                        } else {
                            now + event.duration_secs() as i64
                        },
                        is_permanent: event.duration_secs() == 0,
                        fail_count: 0,
                    };
                    cache.try_insert(ban_info);
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

                // 实时同步统计数据（事件驱动，消除轮询延迟）
                crate::types::DAEMON_STATS.packets_dropped.store(
                    event.packets_dropped(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                crate::types::DAEMON_STATS.packets_accepted.store(
                    event.packets_accepted(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                crate::types::DAEMON_STATS.whitelist_count.store(
                    event.whitelist_count() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
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
                    let raw_jail = FwNlListBansResponse::jail_name_str(entry);
                    let reason = FwNlListBansResponse::reason_str(entry);

                    // 内核 jail_name="kernel" 表示来源不明确，需从 reason 推断
                    // 非 "kernel" 的值（如 "sshd"/"nginx"）来自 state-persist，直接使用
                    let jail_name = if raw_jail.is_empty() || raw_jail == "kernel" {
                        let r = if reason.is_empty() {
                            "restored"
                        } else {
                            &reason
                        };
                        if r.contains("flood") || r.contains("ddos") || r.contains("total rate") {
                            "ddos".to_string()
                        } else {
                            "api".to_string()
                        }
                    } else {
                        raw_jail
                    };
                    let final_reason = if reason.is_empty() {
                        "restored".to_string()
                    } else {
                        reason
                    };

                    let ban_info = crate::types::BanInfo {
                        ip: ip_str.clone(),
                        ip_num: 0,
                        jail_name,
                        reason: final_reason,
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

                // 更新 packets 计数（来自 netlink StatsResponse，由后台线程周期性 send_stats_query 触发）
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

                // 更新 WHITELIST_CACHE
                let whitelist_entries: std::collections::HashMap<
                    String,
                    crate::types::WhitelistEntry,
                > = entries
                    .iter()
                    .map(|e| {
                        let ip_str = if e.af == 2 {
                            // AF_INET
                            format!("{}.{}.{}.{}", e.addr[0], e.addr[1], e.addr[2], e.addr[3])
                        } else if e.af == 10 {
                            // AF_INET6
                            let addr: std::net::Ipv6Addr = std::net::Ipv6Addr::from(e.addr);
                            addr.to_string()
                        } else {
                            "unknown".to_string()
                        };

                        // 构建 CIDR 格式
                        let cidr = format!("{}/{}", ip_str, e.prefix_len);

                        // 设备名（null 结尾的字节数组）
                        let device = String::from_utf8_lossy(&e.device)
                            .trim_end_matches('\0')
                            .to_string();

                        (cidr.clone(), crate::types::WhitelistEntry { cidr, device })
                    })
                    .collect();

                *crate::types::WHITELIST_CACHE.write() = whitelist_entries;

                // 更新 DAEMON_STATS.whitelist_count
                crate::types::DAEMON_STATS
                    .whitelist_count
                    .store(entries.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            Some(FwNlMsgType::ListRatesResponse) => {
                // 处理速率统计响应
                if hdr_data.len() < std::mem::size_of::<FwNlListRatesResponse>() {
                    anyhow::bail!("速率统计响应数据太短");
                }

                let (resp, entries) = FwNlListRatesResponse::from_bytes(hdr_data)?;

                // 提取全局流量速率（内核 atomic64_xchg 读取并重置）
                let global_pps = resp.global_pps();
                let global_bps = resp.global_bps();

                // 更新速率基线（EWMA α=0.01 平滑，用于动态阈值）
                if global_pps > 0 || global_bps > 0 {
                    crate::types::update_traffic_baseline(global_pps, global_bps);
                }

                // 更新 RATE_CACHE 并计算总速率
                let mut total_pps = 0u64;
                let mut total_bps = 0u64;
                let rate_entries: Vec<crate::types::RateEntry> = entries
                    .iter()
                    .map(|e| {
                        let pps = u64::from_be(e.packets);
                        let bps = u64::from_be(e.bytes);
                        total_pps += pps;
                        total_bps += bps;
                        crate::types::RateEntry {
                            ip: FwNlListRatesResponse::ip_str(e),
                            packets_per_sec: pps,
                            bytes_per_sec: bps,
                            syn_packets_per_sec: u64::from_be(e.syn_packets),
                            udp_packets_per_sec: u64::from_be(e.udp_packets),
                            icmp_packets_per_sec: u64::from_be(e.icmp_packets),
                            ack_packets_per_sec: u64::from_be(e.ack_packets),
                            rst_packets_per_sec: u64::from_be(e.rst_packets),
                            fin_packets_per_sec: u64::from_be(e.fin_packets),
                        }
                    })
                    .collect();

                *crate::types::RATE_CACHE.write() = rate_entries;

                // 记录速率历史快照（每 2 秒一次，保留 1 小时）
                crate::types::record_rate_history(total_pps, total_bps, entries.len() as u32);

                crate::logger::debug!(
                    crate::logger::get(),
                    "收到速率统计响应";
                    "count" => entries.len(),
                    "total_pps" => total_pps,
                    "total_bps" => total_bps,
                    "global_pps" => global_pps,
                    "global_bps" => global_bps
                );
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
                    crate::logger::debug!(
                        crate::logger::get(),
                        "配置更新已确认";
                        "applied_flags" => format!("0x{:x}", applied)
                    );
                }
            }
            Some(FwNlMsgType::WhitelistStateChange) => {
                // 处理白名单状态变更事件
                if hdr_data.len() < std::mem::size_of::<FwNlWhitelistStateChange>() {
                    anyhow::bail!("白名单状态变更事件数据太短");
                }

                let event = FwNlWhitelistStateChange::from_bytes(hdr_data)?;
                let ip_str = event.ip_str();
                let device_str = event.device_str();
                let prefix_len = event.prefix_len;

                // 构建 CIDR 格式
                let cidr = if ip_str.contains(':') {
                    // IPv6
                    if prefix_len == 128 || prefix_len == 0 {
                        ip_str.clone()
                    } else {
                        format!("{}/{}", ip_str, prefix_len)
                    }
                } else {
                    // IPv4
                    if prefix_len == 32 || prefix_len == 0 {
                        ip_str.clone()
                    } else {
                        format!("{}/{}", ip_str, prefix_len)
                    }
                };

                if event.is_add() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "收到白名单状态变更：添加";
                        "ip" => &ip_str,
                        "prefix_len" => prefix_len,
                        "device" => &device_str
                    );

                    // 更新 WHITELIST_CACHE（HashMap insert 天然幂等，补充 device）
                    let mut cache = crate::types::WHITELIST_CACHE.write();
                    match cache.get_mut(&cidr) {
                        Some(entry) if entry.device.is_empty() && !device_str.is_empty() => {
                            entry.device = device_str;
                        }
                        None => {
                            cache.insert(
                                cidr.clone(),
                                crate::types::WhitelistEntry {
                                    cidr,
                                    device: device_str,
                                },
                            );
                        }
                        _ => {}
                    }
                } else if event.is_remove() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "收到白名单状态变更：移除";
                        "ip" => &ip_str,
                        "prefix_len" => prefix_len
                    );

                    // 从 WHITELIST_CACHE 移除
                    crate::types::WHITELIST_CACHE.write().remove(&cidr);
                }

                // 实时更新白名单计数
                crate::types::DAEMON_STATS.whitelist_count.store(
                    event.whitelist_count() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
            }
            Some(FwNlMsgType::CmdResult) => {
                if hdr_data.len() < std::mem::size_of::<FwNlCmdResult>() {
                    anyhow::bail!("CmdResult 数据太短");
                }
                let event = FwNlCmdResult::from_bytes(hdr_data)?;
                crate::logger::warn!(
                    crate::logger::get(),
                    "内核命令执行失败";
                    "cmd" => event.cmd_name(),
                    "error_code" => event.error_code(),
                    "ip" => event.ip_str()
                );
            }
            Some(FwNlMsgType::ConfigChange) => {
                // procfs 配置变更通知——复用 ConfigUpdate 结构体解析
                if hdr_data.len() < std::mem::size_of::<protocol::FwNlConfigUpdate>() {
                    anyhow::bail!("ConfigChange 数据太短");
                }
                let cfg = protocol::FwNlConfigUpdate::from_bytes(hdr_data)?;
                let flags = cfg.flags();
                if flags & protocol::config_flags::BAN_TIME != 0 {
                    let new_ban_time = cfg.ban_time();
                    crate::logger::info!(
                        crate::logger::get(),
                        "内核 ban_time 已通过 procfs 变更";
                        "new_ban_time" => new_ban_time
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

    /// 发送速率统计查询
    pub fn send_list_rates_query(&self, seq: u32) -> Result<()> {
        let query = FwNlListRatesQuery::new(seq);
        self.send_command(&query.to_bytes())
    }

    /// 发送原始命令到内核
    fn send_command(&self, data: &[u8]) -> Result<()> {
        use nix::libc::{nlmsghdr, sockaddr_nl, AF_NETLINK};

        // 构造标准 nlmsghdr + 自定义消息
        let nlmsg_len = std::mem::size_of::<nlmsghdr>() + data.len();
        let mut buf = vec![0u8; nlmsg_len];

        // 填充 nlmsghdr
        // SAFETY: buf 是新分配的 Vec，容量 >= nlmsg_len，
        // buf.as_mut_ptr() 指向有效的可写缓冲区，转换为 &mut nlmsghdr 是安全的。
        // 后续 copy_from_slice 填充 nlmsghdr 之后的数据，不会越界。
        let nlh: &mut nlmsghdr = unsafe { &mut *(buf.as_mut_ptr() as *mut nlmsghdr) };
        nlh.nlmsg_len = nlmsg_len as u32;
        nlh.nlmsg_type = 0; // 自定义消息类型
        nlh.nlmsg_flags = 0;
        nlh.nlmsg_seq = 0;
        nlh.nlmsg_pid = 0;

        // 复制自定义消息到 nlmsghdr 之后
        buf[std::mem::size_of::<nlmsghdr>()..].copy_from_slice(data);

        // 构造内核地址（pid=0 表示内核）
        // SAFETY: sockaddr_nl 是 POD 类型，zeroed() 后手动设置各字段是安全的，
        // nl_pid=0 表示发送给内核。
        let mut addr: sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = AF_NETLINK as u16;
        addr.nl_pid = 0; // 内核

        // SAFETY: self.fd 是有效的 socket 文件描述符，buf 是有效的只读缓冲区，
        // addr 已正确初始化，size_of::<sockaddr_nl>() 是合法的地址长度。
        // sendto 返回值 n 用于验证发送是否完整。
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
            crate::types::DAEMON_STATS
                .netlink_send_errors
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!("发送 netlink 消息失败: {}", err));
        }

        if n as usize != buf.len() {
            crate::types::DAEMON_STATS
                .netlink_send_errors
                .fetch_add(1, Ordering::Relaxed);
            return Err(anyhow::anyhow!(
                "发送 netlink 消息不完整: {} / {}",
                n,
                buf.len()
            ));
        }

        crate::types::DAEMON_STATS
            .netlink_messages_sent
            .fetch_add(1, Ordering::Relaxed);

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
            // SAFETY: self.fd 是有效的 socket 文件描述符（>= 0 已验证），
            // Drop 保证只执行一次，close 释放内核资源。
            // close 返回值不影响析构语义，忽略即可。
            unsafe { nix::libc::close(self.fd) };
        }
    }
}
