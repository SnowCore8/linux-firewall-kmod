//! 守护进程化模块
//!
//! 实现经典 Unix 双 fork 守护进程化流程。

use std::fs;

use anyhow::{bail, Context, Result};
use nix::unistd::{fork, setsid, ForkResult};

// ============================================================================
// 守护进程化
// ============================================================================

/// 守护进程化:双 fork + setsid + chdir / + 写 PID + 重定向 fd。
///
/// 经典 Unix 守护进程化模式,故意用 `process::exit` 而非 `std::process::exit`
/// 以避免刷新 stdio 缓冲区(fork 后的子进程中 stdio 状态未定义)。
///
/// # Errors
/// 任何 fork 失败
pub fn daemonize_process() -> Result<()> {
    use std::process;

    // 第一次 fork: 父进程退出
    // SAFETY: `fork` 是 POSIX 进程创建原语,无内存安全前置条件;
    // `ForkResult` 区分父子进程使父进程可立即 exit (避免 stdio 缓冲区双写)
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {}
        Ok(ForkResult::Parent { child: _, .. }) => {
            // _exit 避免刷新 stdio 缓冲区 (fork 后的子进程中 stdio 状态未定义)
            process::exit(0);
        }
        Err(e) => bail!("fork failed: {}", e),
    }

    setsid().context("setsid failed")?;

    // 第二次 fork: 防止重新获得控制终端, 创建非会话领头进程
    // SAFETY: 同上
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {}
        Ok(ForkResult::Parent { .. }) => {
            process::exit(0);
        }
        Err(e) => bail!("second fork failed: {}", e),
    }

    if let Err(e) = std::env::set_current_dir("/") {
        crate::logger::warn!(
            crate::logger::get(),
            "切换工作目录到 / 失败";
            "error" => %e
        );
    }

    // PID 文件用 O_NOFOLLOW 防止符号链接攻击覆盖其他进程
    // 使用 flock 排他锁确保单实例——第二个实例启动时 flock 会失败
    let pid = process::id();
    let pid_path = "/run/firewall-daemon.pid";
    // SAFETY: `pid_path` 是 `&'static str` 常量,无 NUL 字节。`open` 标志是
    // 合法 libc 常量。`mode 0o644` 只在 `O_CREAT` 时生效。
    let fd = unsafe {
        libc::open(
            std::ffi::CString::new(pid_path)
                .expect("路径无 NUL 字节")
                .as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC | libc::O_NOFOLLOW,
            0o644,
        )
    };
    if fd >= 0 {
        // 尝试排他锁（非阻塞）——失败说明已有实例在运行
        // SAFETY: `fd` 是有效的打开文件描述符，`LOCK_EX | LOCK_NB` 是合法 flock 操作
        let lock_ret = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if lock_ret != 0 {
            let errno = std::io::Error::last_os_error();
            // SAFETY: fd 是上方 libc::open 返回的有效文件描述符，flock 失败后需释放资源。
            // close 返回值不影响错误传播（bail! 已携带 flock 错误信息）。
            unsafe { libc::close(fd) };
            bail!(
                "守护进程已在运行（flock 失败: {}）。PID 文件: {}",
                errno,
                pid_path
            );
        }

        use std::io::Write;
        use std::os::unix::io::FromRawFd;
        // SAFETY: `fd` 是上一行 `libc::open` 返回的有效 fd,且未通过其他
        // 途径转移所有权,直接包装为 `File` 取得独占所有权。
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        if let Err(e) = writeln!(f, "{}", pid) {
            crate::logger::warn!(
                crate::logger::get(),
                "写入 PID 文件失败";
                "error" => %e
            );
        }
        if let Err(e) = f.flush() {
            crate::logger::warn!(
                crate::logger::get(),
                "刷新 PID 文件失败";
                "error" => %e
            );
        }
        // 故意不 drop(f)——保持 fd 打开以维持 flock 锁
        // 进程退出时内核自动释放 flock 和关闭 fd
        std::mem::forget(f);
    } else {
        // PID 文件创建失败，记录错误但继续运行（非致命错误）
        let errno = std::io::Error::last_os_error();
        crate::logger::warn!(
            crate::logger::get(),
            "创建 PID 文件失败（守护进程仍正常运行）";
            "path" => pid_path,
            "error" => %errno
        );
    }

    // 标准 fd 重定向到 /dev/null
    if let Ok(devnull) = fs::File::open("/dev/null") {
        use std::os::unix::io::IntoRawFd;
        let fd = devnull.into_raw_fd();
        // SAFETY: `devnull.into_raw_fd()` 返回的 fd 来自刚 `File::open` 成功的
        // `/dev/null`,仍是有效文件描述符。`dup2` 复制 fd 后原 fd 仍可独立 close。
        // 目标 fd 0/1/2 必为进程启动时的 stdin/stdout/stderr 有效 fd。
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                // SAFETY: 上面 dup2 已复制,原 fd 可安全关闭(非 stdio 三个之一)
                libc::close(fd);
            }
        }
    }

    Ok(())
}
