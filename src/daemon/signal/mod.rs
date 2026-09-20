//! `signalfd` 信号层。
//!
//! 旧实现用 `sigaction` + `sa_handler` 写全局原子布尔，并**特意不使用 `SA_RESTART`**，
//! 依赖 `poll`/`read` 被信号打断返回 `EINTR` 这一隐式协议把控制权交回主循环。
//! 问题：`EINTR` 无处不在（任何被中断的系统调用都要处理），语义脆弱；信号处理函数
//! 里只能碰异步信号安全的东西；关停依赖轮询间隔。
//!
//! 本模块把信号变成**普通 fd**：`SignalFd` 阻塞并接管 SIGTERM/SIGINT/SIGHUP/SIGUSR1，
//! 由内核把信号投递成可读事件。主循环把它和 inotify fd 放进**同一个 `poll`** 等待，
//! 被唤醒时用 [`SignalFd::poll_read`] 取信号并显式分派。不再有 `EINTR` 隐式协议，
//! 也不再需要异步信号处理器。

use std::io;
use std::os::fd::RawFd;

use anyhow::{bail, Context, Result};

/// 运行时信号，语义化后交给主循环分派。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// SIGTERM / SIGINT：请求优雅退出。
    Terminate,
    /// SIGHUP：热重载配置。
    Reload,
    /// SIGUSR1：配置回滚。
    Rollback,
}

/// `signalfd` 句柄。构造时阻塞四个信号，析构时恢复原信号掩码并关闭 fd。
pub struct SignalFd {
    fd: RawFd,
    /// 构造前的信号掩码，析构时恢复，避免把进程的掩码改动外泄给调用方。
    old_mask: libc::sigset_t,
}

impl SignalFd {
    /// 阻塞 SIGTERM/SIGINT/SIGHUP/SIGUSR1 并创建非阻塞 `signalfd`。
    ///
    /// 顺序很重要：必须**先**阻塞信号再创建 fd，否则信号会按默认（或旧处理器）
    /// 动作投递，而不会进入 fd。
    ///
    /// # Errors
    /// `pthread_sigmask` 或 `signalfd` 失败。
    pub fn new() -> Result<Self> {
        // SAFETY: `sigset_t` 清零后经 sigemptyset/sigaddset 构造是合法的；
        // 传出的 oldset 指针指向栈上有效内存。
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGUSR1] {
                if libc::sigaddset(&mut set, sig) != 0 {
                    bail!("sigaddset({}) failed: {}", sig, io::Error::last_os_error());
                }
            }

            let mut old_mask: libc::sigset_t = std::mem::zeroed();
            let rc = libc::pthread_sigmask(libc::SIG_BLOCK, &set, &mut old_mask);
            if rc != 0 {
                bail!("pthread_sigmask 失败: {}", io::Error::from_raw_os_error(rc));
            }

            let fd = libc::signalfd(-1, &set, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
            if fd < 0 {
                // 创建失败：立刻恢复掩码，不把副作用留在进程上。
                libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut());
                bail!("signalfd 失败: {}", io::Error::last_os_error());
            }

            Ok(Self { fd, old_mask })
        }
    }

    /// 底层 raw fd，供与 inotify fd 一起 `poll` 使用。
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }

    /// 非阻塞读取一个待处理信号；无信号返回 `Ok(None)`。
    ///
    /// # Errors
    /// 读取失败或收到未注册的信号。
    pub fn poll_read(&self) -> Result<Option<Signal>> {
        let mut info: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
        // SAFETY: info 是栈上有效的 signalfd_siginfo，长度严格匹配其类型大小。
        let n = unsafe {
            libc::read(
                self.fd,
                &mut info as *mut libc::signalfd_siginfo as *mut libc::c_void,
                std::mem::size_of::<libc::signalfd_siginfo>(),
            )
        };
        if n < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(err).context("读取 signalfd 失败");
        }
        if n as usize != std::mem::size_of::<libc::signalfd_siginfo>() {
            bail!("signalfd 返回长度异常: {}", n);
        }

        let sig = info.ssi_signo as i32;
        let signal = match sig {
            libc::SIGTERM | libc::SIGINT => Signal::Terminate,
            libc::SIGHUP => Signal::Reload,
            libc::SIGUSR1 => Signal::Rollback,
            other => bail!("收到未注册的信号 {}", other),
        };
        Ok(Some(signal))
    }

    /// 阻塞直到有一个已注册信号可读，返回之。
    ///
    /// 供事件循环主体调用；由于 fd 是非阻塞的，这里用 `poll(fd, -1)` 等待。
    /// 若要把信号与其它 fd 合并到同一个等待里，请改用 [`SignalFd::raw_fd`] +
    /// [`SignalFd::poll_read`]。
    ///
    /// # Errors
    /// `poll` 失败或读取失败。
    pub fn next(&self) -> Result<Signal> {
        loop {
            if let Some(s) = self.poll_read()? {
                return Ok(s);
            }
            let mut pfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: pfd 是栈上有效的单个 pollfd，nfds=1 与之匹配。
            let rc = unsafe { libc::poll(&mut pfd, 1, -1) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                // 被其它信号打断：重试，而不是把 EINTR 当错误。
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("poll signalfd 失败");
            }
        }
    }
}

impl Drop for SignalFd {
    fn drop(&mut self) {
        // SAFETY: fd 由本结构独占，close 后不再使用。
        unsafe {
            libc::close(self.fd);
            // 恢复进程原信号掩码，避免把「信号已阻塞」这一副作用留给调用方。
            libc::pthread_sigmask(libc::SIG_SETMASK, &self.old_mask, std::ptr::null_mut());
        }
    }
}

/// 忽略 SIGPIPE。
///
/// HTTP/SSE 写端在客户端断开时不应被信号杀死。signalfd 不接管 SIGPIPE（它以
/// `EPIPE` 报错更合适），故单独置为 `SIG_IGN`。
///
/// # Errors
/// `sigaction` 失败。
pub fn ignore_sigpipe() -> Result<()> {
    // SAFETY: 设置 SIG_IGN 不需要有效处理器；sigaction 参数均为有效指针。
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        if libc::sigaction(libc::SIGPIPE, &sa, std::ptr::null_mut()) != 0 {
            bail!("sigaction(SIGPIPE) failed: {}", io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 事件驱动等待：轮询真实输出，不做固定 sleep 判定。
    fn wait_for_signal(fd: &SignalFd) -> Option<Signal> {
        for _ in 0..2000 {
            match fd.poll_read() {
                Ok(Some(s)) => return Some(s),
                Ok(None) => std::thread::sleep(Duration::from_millis(1)),
                Err(_) => return None,
            }
        }
        None
    }

    #[test]
    fn no_pending_signal_reads_none() {
        let fd = SignalFd::new().expect("signalfd 创建失败");
        assert_eq!(fd.poll_read().expect("读取失败"), None);
        // raw_fd 应为有效 fd。
        assert!(fd.raw_fd() >= 0);
    }

    #[test]
    fn blocked_signal_is_delivered_through_the_fd() {
        let fd = SignalFd::new().expect("signalfd 创建失败");
        // 掩码已阻塞 SIGUSR1；raise 只针对当前线程，信号转 pending。
        // SAFETY: raise 对自身进程/线程发信号，无需额外前置条件。
        unsafe {
            libc::raise(libc::SIGUSR1);
        }
        assert_eq!(
            wait_for_signal(&fd),
            Some(Signal::Rollback),
            "被阻塞的 SIGUSR1 应经 signalfd 投递"
        );
    }

    #[test]
    fn sigterm_maps_to_terminate() {
        let fd = SignalFd::new().expect("signalfd 创建失败");
        // SAFETY: 同上。
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        assert_eq!(wait_for_signal(&fd), Some(Signal::Terminate));
    }

    #[test]
    fn sighup_maps_to_reload() {
        let fd = SignalFd::new().expect("signalfd 创建失败");
        // SAFETY: 同上。
        unsafe {
            libc::raise(libc::SIGHUP);
        }
        assert_eq!(wait_for_signal(&fd), Some(Signal::Reload));
    }

    #[test]
    fn ignore_sigpipe_sets_ignore() {
        assert!(ignore_sigpipe().is_ok());
    }
}
