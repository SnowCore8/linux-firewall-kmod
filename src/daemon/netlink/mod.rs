//! Netlink 通信模块
//!
//! 实现守护进程与内核模块的双向通信：
//! - 接收内核推送的 DDoS 检测事件
//! - 向内核发送封禁/解封指令

mod commands;
mod decision;
mod handlers;
mod protocol;
mod responses;

use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;

use protocol::{FwNlMsgType, FW_NL_MAGIC};

pub use decision::DdosDecisionEngine;
pub use protocol::{config_flags, FwNlConfigUpdate as ConfigUpdate};

/// Netlink 协议号（NETLINK_USERSOCK）
const NETLINK_USERSOCK: i32 = 2;

/// 全局 Netlink Context 实例（程序内部共享）
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
        // SAFETY: fd 是有效的 socket 文件描述符，F_SETFL 设置 O_NONBLOCK 是合法操作。
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

    /// 处理接收到的消息（分发器）
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
            Some(FwNlMsgType::DdosEvent) => Self::handle_ddos_event(hdr_data, decision_engine),
            Some(FwNlMsgType::BanStateChange) => Self::handle_ban_state_change(hdr_data),
            Some(FwNlMsgType::ListBansResponse) => Self::handle_list_bans_response(hdr_data),
            Some(FwNlMsgType::StatsResponse) => Self::handle_stats_response(hdr_data),
            Some(FwNlMsgType::ListWhitelistResponse) => {
                Self::handle_list_whitelist_response(hdr_data)
            }
            Some(FwNlMsgType::ListRatesResponse) => Self::handle_list_rates_response(hdr_data),
            Some(FwNlMsgType::ConfigAck) => Self::handle_config_ack(hdr_data),
            Some(FwNlMsgType::WhitelistStateChange) => {
                Self::handle_whitelist_state_change(hdr_data)
            }
            Some(FwNlMsgType::CmdResult) => Self::handle_cmd_result(hdr_data),
            Some(FwNlMsgType::ConfigChange) => Self::handle_config_change(hdr_data),
            Some(FwNlMsgType::AnalysisResponse) => Self::handle_analysis_response(hdr_data),
            _ => {
                crate::logger::warn!(
                    crate::logger::get(),
                    "未知消息类型";
                    "msg_type" => msg_type
                );
                Ok(())
            }
        }
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
