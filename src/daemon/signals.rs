//! 信号处理模块
//!
//! 注册和管理 POSIX 信号处理器，控制守护进程的运行时行为。

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};

// ============================================================================
// 全局状态标志
// ============================================================================

/// 全局运行标志，供信号处理器访问
pub static GLOBAL_RUNNING: AtomicBool = AtomicBool::new(true);
/// 全局重载标志，供信号处理器访问
pub static GLOBAL_RELOAD: AtomicBool = AtomicBool::new(false);
/// 全局回滚标志，供信号处理器访问
pub static GLOBAL_ROLLBACK: AtomicBool = AtomicBool::new(false);

// ============================================================================
// 信号处理器
// ============================================================================

/// SIGTERM/SIGINT 信号处理器：设置全局运行标志为 false
extern "C" fn handle_sigterm(_sig: libc::c_int) {
    GLOBAL_RUNNING.store(false, Ordering::SeqCst);
}

/// SIGHUP 信号处理器：设置全局重载标志为 true
extern "C" fn handle_sighup(_sig: libc::c_int) {
    GLOBAL_RELOAD.store(true, Ordering::SeqCst);
}

/// SIGUSR1 信号处理器：设置全局回滚标志为 true
extern "C" fn handle_sigusr1(_sig: libc::c_int) {
    GLOBAL_ROLLBACK.store(true, Ordering::SeqCst);
}

// ============================================================================
// 信号注册
// ============================================================================

/// 注册 5 个信号到全局原子标志。
///
/// - `SIGTERM` / `SIGINT` → `GLOBAL_RUNNING` (主循环退出)
/// - `SIGHUP` → `GLOBAL_RELOAD` (主循环触发热重载)
/// - `SIGUSR1` → `GLOBAL_ROLLBACK` (主循环触发配置回滚)
/// - `SIGPIPE` → 忽略 (HTTP 客户端断开时不被信号杀死)
///
/// # Errors
/// `sigaction` 失败
pub fn setup_signals() -> Result<()> {
    // SAFETY: `sigaction` 是 POSIX 标准系统调用。`sigaction_t` 结构体初始化为零是合法的。
    // 信号处理器函数指针是 `extern "C"` 函数，符合 C ABI。
    // 注意：不使用 SA_RESTART，这样 poll() 等系统调用会被信号中断返回 EINTR，
    // 主循环可以在 EINTR 时检查 running 标志并退出。
    unsafe {
        // SIGTERM 处理器
        let mut sa_term: libc::sigaction = std::mem::zeroed();
        sa_term.sa_sigaction = handle_sigterm as *const () as usize;
        sa_term.sa_flags = 0; // 不使用 SA_RESTART，让 poll() 被中断
        libc::sigemptyset(&mut sa_term.sa_mask);
        if libc::sigaction(libc::SIGTERM, &sa_term, std::ptr::null_mut()) != 0 {
            bail!(
                "sigaction(SIGTERM) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // SIGINT 处理器
        let mut sa_int: libc::sigaction = std::mem::zeroed();
        sa_int.sa_sigaction = handle_sigterm as *const () as usize;
        sa_int.sa_flags = 0; // 不使用 SA_RESTART
        libc::sigemptyset(&mut sa_int.sa_mask);
        if libc::sigaction(libc::SIGINT, &sa_int, std::ptr::null_mut()) != 0 {
            bail!(
                "sigaction(SIGINT) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // SIGHUP 处理器
        let mut sa_hup: libc::sigaction = std::mem::zeroed();
        sa_hup.sa_sigaction = handle_sighup as *const () as usize;
        sa_hup.sa_flags = 0; // 不使用 SA_RESTART
        libc::sigemptyset(&mut sa_hup.sa_mask);
        if libc::sigaction(libc::SIGHUP, &sa_hup, std::ptr::null_mut()) != 0 {
            bail!(
                "sigaction(SIGHUP) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // SIGUSR1 处理器（配置回滚）
        let mut sa_usr1: libc::sigaction = std::mem::zeroed();
        sa_usr1.sa_sigaction = handle_sigusr1 as *const () as usize;
        sa_usr1.sa_flags = 0; // 不使用 SA_RESTART
        libc::sigemptyset(&mut sa_usr1.sa_mask);
        if libc::sigaction(libc::SIGUSR1, &sa_usr1, std::ptr::null_mut()) != 0 {
            bail!(
                "sigaction(SIGUSR1) failed: {}",
                std::io::Error::last_os_error()
            );
        }

        // SIGPIPE 忽略
        let mut sa_pipe: libc::sigaction = std::mem::zeroed();
        sa_pipe.sa_sigaction = libc::SIG_IGN;
        if libc::sigaction(libc::SIGPIPE, &sa_pipe, std::ptr::null_mut()) != 0 {
            bail!(
                "sigaction(SIGPIPE) failed: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    Ok(())
}
