//! netlink socket 的**唯一所有者**。
//!
//! 本模块只做三件事：创建并绑定 socket、把一段自定义载荷发出去、收下一条报文。
//! 它不解析语义、不做路由、不持有任何请求状态——那是 [`super::reactor`] 与
//! [`super::client`] 的职责。
//!
//! # 长度以 nlmsghdr 为准，不以收包字节数为准
//!
//! netlink 的数据报在 skb 里按 4 字节对齐，故「`recvmsg` 收到的字节数」可能比
//! `nlmsghdr.nlmsg_len` 多出最多 3 个填充字节。内核自己就是按
//! `payload = nlh->nlmsg_len - NLMSG_HDRLEN` 取载荷的（见 `fw_netlink.c`
//! `fw_nl_recv_msg`），本模块必须采用**同一**规则，否则自定义公共头里声明的
//! `msg_len` 会与「按收包字节数切出的长度」不符，每一条报文都会被判成长度错位。
//!
//! 另注：`nlmsghdr` 的 `nlmsg_len`/`nlmsg_type`/`nlmsg_seq`/`nlmsg_pid` 都是
//! **宿主字节序**（netlink 惯例），与自定义载荷里的大端字段不同。

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

use nix::libc;

use crate::runtime::Shutdown;

/// Netlink 协议号：契约固定为 `NETLINK_USERSOCK`。
const NETLINK_USERSOCK: i32 = 2;

/// 内核广播组号（契约固定为 1）。
const NETLINK_GROUP: u32 = 1;

/// `struct nlmsghdr` 的字节数。
const NLMSGHDR_LEN: usize = 16;

/// 接收缓冲区字节数。
///
/// 契约用 `u16` 承载 `msg_len`，故单条自定义载荷最大 65535 字节，加上
/// `nlmsghdr` 共 65551。取 128 KiB 留出充足余量，同时让「报文超过缓冲区」
/// 只可能来自非契约行为，而不是正常分页。
pub const RECV_BUF: usize = 128 * 1024;

/// 检查 `u16` 长度域能否容纳一条报文（供测试与文档引用）。
#[must_use]
pub const fn max_payload_bytes() -> usize {
    u16::MAX as usize
}

// ============================================================================
// 错误
// ============================================================================

/// 建立 socket 失败的原因。
#[derive(Debug)]
pub enum TransportError {
    /// `socket(2)` 失败。
    Socket(io::Error),
    /// `bind(2)` 失败。
    Bind(io::Error),
    /// 设置非阻塞标志失败。
    NonBlocking(io::Error),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(e) => write!(f, "创建 netlink socket 失败：{e}"),
            Self::Bind(e) => write!(f, "绑定 netlink socket 失败：{e}"),
            Self::NonBlocking(e) => write!(f, "设置 netlink socket 非阻塞失败：{e}"),
        }
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Socket(e) | Self::Bind(e) | Self::NonBlocking(e) => Some(e),
        }
    }
}

/// 收取一条报文失败的原因。
#[derive(Debug)]
pub enum RecvError {
    /// 内核发来的数据报超过接收缓冲，内容不完整。
    Truncated {
        /// `recvmsg` 报告的实际长度。
        actual: usize,
        /// 接收缓冲区大小。
        buffer: usize,
    },
    /// `nlmsghdr` 自相矛盾：声明的长度不足一个头，或超过实得字节数。
    Malformed {
        /// `nlmsghdr.nlmsg_len` 的取值。
        nlmsg_len: usize,
        /// 实得字节数。
        received: usize,
    },
    /// `recvmsg` 失败。`EAGAIN` 与 `EINTR` 不走这里（分别映射为「无数据」与重试）。
    Failed(io::Error),
}

impl fmt::Display for RecvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { actual, buffer } => {
                write!(f, "netlink 数据报 {actual} 字节超过接收缓冲 {buffer} 字节")
            }
            Self::Malformed {
                nlmsg_len,
                received,
            } => write!(
                f,
                "nlmsghdr 声明的长度 {nlmsg_len} 与实得 {received} 字节自相矛盾"
            ),
            Self::Failed(e) => write!(f, "收取 netlink 报文失败：{e}"),
        }
    }
}

impl std::error::Error for RecvError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Failed(e) => Some(e),
            Self::Truncated { .. } | Self::Malformed { .. } => None,
        }
    }
}

// ============================================================================
// 报文
// ============================================================================

/// 一条已剥离 `nlmsghdr` 的接收报文。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// 发送方的 netlink portid。内核为 0；非 0 表示本机其他进程，
    /// 其内容不可信（内核侧同样要求 `CAP_NET_ADMIN`，但那不等于本进程可信）。
    pub portid: u32,
    /// 自定义载荷，含 12 字节公共头。
    pub payload: Vec<u8>,
}

// ============================================================================
// socket
// ============================================================================

/// netlink socket 的唯一所有者。
///
/// # 单写者
///
/// 发送侧只有一把互斥锁 [`Transport::write_lock`]，作用**不是**保护共享状态，
/// 而是保证每次 `sendto` 的数据报整体原子：控制面（封禁/配置下发的 `Client`）
/// 与注册租约（`Lease`）可能来自不同线程，共用同一个 socket。接收侧不取此锁，
/// 且全进程只有 [`super::reactor`] 一个读线程。
pub struct Transport {
    fd: OwnedFd,
    write_lock: std::sync::Mutex<()>,
}

impl fmt::Debug for Transport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("fd", &self.fd.as_raw_fd())
            .finish_non_exhaustive()
    }
}

impl Transport {
    /// 创建并绑定 netlink socket。
    ///
    /// `nl_pid = 0` 交由内核分配 portid，`nl_groups = 1` 订阅内核广播组。
    ///
    /// # Errors
    ///
    /// socket 创建、绑定或设置非阻塞标志失败时返回 [`TransportError`]。
    pub fn open() -> Result<Self, TransportError> {
        // SAFETY: socket() 是 POSIX 调用，AF_NETLINK/SOCK_RAW 与 NETLINK_USERSOCK
        // 是合法组合；失败返回负值，成功返回的 fd 立即交给 OwnedFd 托管。
        let raw = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_USERSOCK) };
        if raw < 0 {
            return Err(TransportError::Socket(io::Error::last_os_error()));
        }
        // SAFETY: raw >= 0 且由 socket() 新建，尚无其他所有者。
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // SAFETY: sockaddr_nl 是 POD；zeroed 后逐字段赋值是合法的。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;
        addr.nl_groups = NETLINK_GROUP;

        // SAFETY: fd 有效；addr 已初始化；长度取自类型本身。
        let ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            return Err(TransportError::Bind(io::Error::last_os_error()));
        }

        // 非阻塞：poll 报告可读之后仍有极小概率被抢走，此时 recvmsg 应返回
        // EAGAIN 而不是让接收线程永久挂住。
        // SAFETY: fd 有效；F_GETFL/F_SETFL 是合法命令。
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(TransportError::NonBlocking(io::Error::last_os_error()));
        }
        // SAFETY: 同上；O_NONBLOCK 是合法标志位。
        let ret = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            return Err(TransportError::NonBlocking(io::Error::last_os_error()));
        }

        Ok(Self {
            fd,
            write_lock: std::sync::Mutex::new(()),
        })
    }

    /// socket 文件描述符。
    #[must_use]
    pub fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// 发送一段自定义载荷（内部补 `nlmsghdr`）。
    ///
    /// `nlmsg_type` 与 `nlmsg_seq` 均写 0：内核按**自定义头**里的 `msg_type`
    /// 分派（见 `fw_netlink.c` 的 `fw_nl_recv_msg`，它读的是 `nlmsg_data` 之后的
    /// 自定义头），`nlmsg_seq` 则从未被内核读取。
    ///
    /// # Errors
    ///
    /// `sendto` 失败或未写满整条数据报时返回错误。**成功仅表示已投递到内核**，
    /// 不代表命令已被执行——需要执行确认的路径必须单独等待回复（见
    /// [`super::client`]）。
    pub fn send(&self, payload: &[u8]) -> io::Result<()> {
        let total = NLMSGHDR_LEN + payload.len();
        let total_u32 =
            u32::try_from(total).map_err(|_| io::Error::other("netlink 报文超过 u32 长度域"))?;
        let mut buf = vec![0u8; total];

        // 手写 nlmsghdr 字段而不用 &mut 投影：buf 是普通 Vec<u8>，对齐只保证到 1
        // 字节，写成结构体引用会有对齐问题；逐字段写字节序明确的整数最稳。
        buf[0..4].copy_from_slice(&total_u32.to_ne_bytes());
        buf[4..6].copy_from_slice(&0u16.to_ne_bytes()); // nlmsg_type
        buf[6..8].copy_from_slice(&0u16.to_ne_bytes()); // nlmsg_flags
        buf[8..12].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_seq
        buf[12..16].copy_from_slice(&0u32.to_ne_bytes()); // nlmsg_pid
        buf[NLMSGHDR_LEN..].copy_from_slice(payload);

        // SAFETY: sockaddr_nl 是 POD；zeroed 后赋值合法。nl_pid=0 即内核。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_pid = 0;

        // 取锁保证整条数据报原子（多个控制面线程共用本 socket 时）。
        // 锁中毒只可能来自持锁者 panic，此时数据报尚未发出，继续尝试是安全的。
        let _guard = self.write_lock.lock().unwrap_or_else(|e| e.into_inner());

        // SAFETY: fd 有效；buf 是有效只读缓冲区；addr 已初始化。
        let n = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast(),
                buf.len(),
                0,
                std::ptr::addr_of!(addr).cast::<libc::sockaddr>(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != buf.len() {
            return Err(io::Error::other(format!(
                "netlink 报文只写出 {n}/{} 字节",
                buf.len()
            )));
        }
        Ok(())
    }

    /// 等待 socket 可读。
    ///
    /// 返回 `Ok(true)` 表示有数据待取；`Ok(false)` 表示 `timeout` 内无数据、
    /// 被信号打断、或已被请求关停。返回 `Err` 时调用方应记录并决定是否继续。
    ///
    /// # Errors
    ///
    /// `poll` 报告不可恢复的 socket 错误时返回错误。
    pub fn wait_readable(&self, timeout: Duration, shutdown: &Shutdown) -> io::Result<bool> {
        if shutdown.is_shutdown() {
            return Ok(false);
        }
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // 超过 i32::MAX 毫秒的等待没有实际意义，直接饱和。
        let ms = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        // SAFETY: pfd 指向栈上有效的 pollfd；nfds=1 与指针一致。
        let ret = unsafe { libc::poll(std::ptr::addr_of_mut!(pfd), 1, ms) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                // 被信号打断不是错误：交回循环，好让关停标志立刻被观察到。
                return Ok(false);
            }
            return Err(err);
        }
        if ret == 0 {
            return Ok(false);
        }
        if pfd.revents & libc::POLLIN != 0 {
            return Ok(true);
        }
        if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other(format!(
                "netlink socket 报告错误事件 revents=0x{:x}",
                pfd.revents
            )));
        }
        Ok(false)
    }

    /// 收取一条报文。
    ///
    /// 返回 `Ok(None)` 表示当前无数据（`EAGAIN` 或被信号打断）。
    ///
    /// # Errors
    ///
    /// 数据报被截断、`nlmsghdr` 自相矛盾或 `recvmsg` 失败时返回 [`RecvError`]。
    pub fn recv(&self) -> Result<Option<Datagram>, RecvError> {
        // 每次调用分配缓冲是最简单且无跨调用状态的做法；接收路径不是热路径
        // （控制面请求按秒计），不值得为此保留一块可变缓冲并加锁。
        let mut buf = vec![0u8; RECV_BUF];
        // SAFETY: sockaddr_nl 是 POD。
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: msghdr 是 POD；清零后逐字段赋值。
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = std::ptr::addr_of_mut!(addr).cast();
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
        msg.msg_iov = std::ptr::addr_of_mut!(iov);
        msg.msg_iovlen = 1;

        // MSG_TRUNC 让 recvmsg 返回数据报的真实长度（即使大于缓冲区），
        // 从而能把「被截断」与「正常收完」区分开，而不是静默拿到半条。
        // SAFETY: fd 有效；msg 指向栈上已初始化的 msghdr，其 iov/name 均有效。
        let n = unsafe {
            libc::recvmsg(
                self.fd.as_raw_fd(),
                std::ptr::addr_of_mut!(msg),
                libc::MSG_TRUNC,
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
                _ => Err(RecvError::Failed(err)),
            };
        }
        let received = n as usize;
        if received > buf.len() {
            return Err(RecvError::Truncated {
                actual: received,
                buffer: buf.len(),
            });
        }
        if received < NLMSGHDR_LEN {
            return Err(RecvError::Malformed {
                nlmsg_len: 0,
                received,
            });
        }

        // 长度取自 nlmsghdr 自身（宿主字节序），与内核 fw_nl_recv_msg 的取值方式一致。
        let nlmsg_len = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if nlmsg_len < NLMSGHDR_LEN || nlmsg_len > received {
            return Err(RecvError::Malformed {
                nlmsg_len,
                received,
            });
        }

        Ok(Some(Datagram {
            portid: addr.nl_pid,
            payload: buf[NLMSGHDR_LEN..nlmsg_len].to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receive_buffer_covers_the_largest_contract_message() {
        // 单条自定义载荷受 u16 长度域约束，缓冲区必须能容纳它加 nlmsghdr，
        // 否则正常分页响应会走「被截断」分支。
        assert!(
            RECV_BUF > max_payload_bytes() + NLMSGHDR_LEN,
            "接收缓冲 {RECV_BUF} 必须大于最大报文 {}",
            max_payload_bytes() + NLMSGHDR_LEN
        );
    }

    #[test]
    fn transport_open_binds_a_usersock_socket() {
        // 不需要 CAP_NET_ADMIN 即可创建并绑定 NETLINK_USERSOCK，
        // 因此本测试在普通环境下也应成立。
        let t = Transport::open().expect("创建 netlink socket 失败");
        assert!(t.raw_fd() >= 0);
    }

    #[test]
    fn wait_readable_reports_shutdown_without_waiting() {
        let t = Transport::open().expect("创建 netlink socket 失败");
        let shutdown = Shutdown::new();
        shutdown.request();
        let start = std::time::Instant::now();
        let ready = t
            .wait_readable(Duration::from_secs(5), &shutdown)
            .expect("poll 不应失败");
        assert!(!ready, "已关停时不应报告可读");
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "关停应立即使等待返回，实际 {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn wait_readable_times_out_on_an_idle_socket() {
        let t = Transport::open().expect("创建 netlink socket 失败");
        let shutdown = Shutdown::new();
        let ready = t
            .wait_readable(Duration::from_millis(20), &shutdown)
            .expect("poll 不应失败");
        assert!(!ready, "空闲 socket 上不应报告可读");
    }

    #[test]
    fn recv_on_an_idle_socket_reports_no_data() {
        let t = Transport::open().expect("创建 netlink socket 失败");
        // 非阻塞 + 无对端发包：应为「无数据」而不是错误。
        assert_eq!(t.recv().expect("不应报错"), None);
    }
}
