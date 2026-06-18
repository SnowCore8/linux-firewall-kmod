//! Netlink 通信模块
//!
//! 实现守护进程与内核模块的双向通信：
//! - 接收内核推送的 DDoS 检测事件
//! - 向内核发送封禁/解封指令

mod protocol;

use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use protocol::{FwNlDdosEvent, FwNlMsgType, FW_NL_MAGIC};

/// Netlink 协议号（NETLINK_USERSOCK）
const NETLINK_USERSOCK: i32 = 2;

/// Netlink 通信上下文
pub struct NetlinkContext {
    fd: i32,
    running: Arc<AtomicBool>,
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
        })
    }

    /// 启动接收线程
    pub fn start_receiver(&self) -> Result<thread::JoinHandle<()>> {
        let fd = self.fd;
        let running = self.running.clone();
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
                    let n = unsafe {
                        nix::libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0)
                    };

                    if n > 0 {
                        if let Err(e) = Self::handle_message(&buf[..n as usize]) {
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
    fn handle_message(data: &[u8]) -> Result<()> {
        use nix::libc::nlmsghdr;

        if data.len() < std::mem::size_of::<nlmsghdr>() {
            anyhow::bail!("消息太短");
        }

        // 解析 netlink 消息头
        let nlh: &nlmsghdr = unsafe { &*(data.as_ptr() as *const nlmsghdr) };

        // 获取自定义消息头
        let hdr_data = &data[std::mem::size_of::<nlmsghdr>()..];
        if hdr_data.len() < 12 {
            anyhow::bail!("自定义消息头太短");
        }

        // 解析魔数、类型、长度
        let magic = u32::from_be_bytes([hdr_data[0], hdr_data[1], hdr_data[2], hdr_data[3]]);
        if magic != FW_NL_MAGIC {
            anyhow::bail!("魔数不匹配: 0x{:08x}", magic);
        }

        let msg_type = u16::from_be_bytes([hdr_data[4], hdr_data[5]]);
        let _msg_len = u16::from_be_bytes([hdr_data[6], hdr_data[7]]);

        match FwNlMsgType::from_u16(msg_type) {
            Some(FwNlMsgType::DdosEvent) => {
                // 解析 DDoS 事件
                let event_data = &hdr_data[12..];
                if event_data.len() < std::mem::size_of::<FwNlDdosEvent>() - 12 {
                    anyhow::bail!("DDoS 事件数据太短");
                }

                let event = FwNlDdosEvent::from_bytes(event_data)?;
                crate::logger::info!(
                    crate::logger::get(),
                    "收到 DDoS 事件";
                    "ip" => event.ip_str(),
                    "reason" => event.reason_str(),
                    "rate_pps" => event.rate_pps
                );

                // TODO: 触发封禁决策
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
