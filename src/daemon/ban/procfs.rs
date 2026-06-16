//! procfs 安全写入模块
//!
//! # 核心职责
//!
//! - 缓存 bans fd（R9-9 优化）避免每次封禁都 open/close
//! - 安全 procfs 写入：路径白名单 + 字符白名单 + fd 重定向检查
//! - 三道防线防止恶意输入击穿到 procfs

use std::ffi::CString;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{bail, Context, Result};
use parking_lot::Mutex;

use super::{BANS_PATH, PROCFS_DIR};

// ============================================================================
// 缓存的 bans procfs fd（R9-9 优化：避免每次封禁都 open/close）
// ============================================================================

/// 当前缓存的 `/proc/firewall/bans` fd。`-1` 表示无效。
///
/// 注意:此 fd 只对 [`BANS_PATH`] 生效;其他 procfs 文件每次 `secure_procfs_write`
/// 仍走完整 `open` → `verify` → `write` → `close` 流程。
static CACHED_BANS_FD: AtomicI32 = AtomicI32::new(-1);
/// 缓存 fd 重建互斥锁。双重检查锁定模式避免并发 open 风暴。
static BANS_FD_MUTEX: Mutex<()> = const { Mutex::new(()) };

/// 获取缓存的 bans procfs fd。无效或被外部关闭时自动重新打开并重新校验。
///
/// # Errors
/// - `open()` 失败 (`ENOENT` / `EACCES`)
/// - `verify_procfs_fd` 失败 (fd 被攻击者重定向)
///
/// # Panics
/// `CString::new(BANS_PATH)` 仅当 `BANS_PATH` 含 NUL 字节时 panic,
/// 而 `BANS_PATH` 是 `&'static str` 常量,实际不可能
fn get_cached_bans_fd() -> Result<RawFd> {
    let fd = CACHED_BANS_FD.load(Ordering::SeqCst);
    if fd >= 0 && verify_procfs_fd(fd).is_ok() {
        return Ok(fd);
    }
    if fd >= 0 {
        // SAFETY: fd 来自先前的 `libc::open` 或另一个成功 `open`,我们已先检查 `fd >= 0`
        // 并通过 `verify_procfs_fd` 确认它仍指向合法 procfs 路径。关闭后立即重置全局。
        unsafe { libc::close(fd) };
        CACHED_BANS_FD.store(-1, Ordering::SeqCst);
    }

    let _guard = BANS_FD_MUTEX.lock();
    let fd = CACHED_BANS_FD.load(Ordering::SeqCst);
    if fd >= 0 && verify_procfs_fd(fd).is_ok() {
        return Ok(fd);
    }
    if fd >= 0 {
        // SAFETY: 同上,锁内再次检查 fd 仍合法才关闭
        unsafe { libc::close(fd) };
    }

    let path = match CString::new(BANS_PATH) {
        Ok(p) => p,
        Err(_) => bail!("BANS_PATH contains NUL byte"),
    };
    // SAFETY: `BANS_PATH` 是 `&'static str` 常量,不含 NUL,`CString::new` 已 unwrap 验证。
    // `O_WRONLY | O_NOFOLLOW` 不需要额外权限
    let new_fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW) };
    if new_fd < 0 {
        let err = std::io::Error::last_os_error();
        bail!("open {BANS_PATH} failed: {err}");
    }

    if verify_procfs_fd(new_fd).is_err() {
        // SAFETY: new_fd 是本函数刚 `open` 的有效 fd,验证失败需要立即释放
        unsafe { libc::close(new_fd) };
        bail!("fd verification failed for {BANS_PATH}");
    }

    CACHED_BANS_FD.store(new_fd, Ordering::SeqCst);
    Ok(new_fd)
}

/// 主动关闭并清空缓存 fd。`main()` 的 `cleanup` 阶段调用。
pub fn close_cached_bans_fd() {
    let fd = CACHED_BANS_FD.swap(-1, Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: `swap` 已保证 fd 是之前 `get_cached_bans_fd` 写入的有效值
        unsafe { libc::close(fd) };
    }
}

// ============================================================================
// 安全 procfs 文件操作
// ============================================================================

/// 校验 procfs 路径是否在 [`PROCFS_DIR`] 下且字符安全。
///
/// 三重检查:
/// 1. 必须以 `/proc/firewall/` 开头
/// 2. 不含 `..` 路径遍历
/// 3. 文件名仅允许 `[A-Za-z0-9/_.-]`
///
/// 故意不做白名单(只接受 `bans` / `whitelist` 等已知名),与 C 版
/// `validate_and_normalize_path` 行为等价。
///
/// # Errors
/// - 路径不在 `/proc/firewall/` 下
/// - 包含 `..`
/// - 包含非法字符
/// - 以 `/` 结尾
fn validate_procfs_path(path: &str) -> Result<()> {
    if !path.starts_with(&format!("{PROCFS_DIR}/")) {
        bail!("path outside {PROCFS_DIR}");
    }

    if path.contains("..") {
        bail!("path traversal attempt");
    }

    // 跳过 PROCFS_DIR 前缀后逐字符验证
    let safe_start = PROCFS_DIR.len() + 1;
    for c in path[safe_start..].chars() {
        if !c.is_ascii_alphanumeric() && !matches!(c, '/' | '-' | '_' | '.') {
            bail!("invalid character in path");
        }
    }

    if path.ends_with('/') {
        bail!("path ends with '/'");
    }

    Ok(())
}

/// 通过 `/proc/self/fd/N` readlink 验证 fd 确实指向 `/proc/firewall/`。
/// 防止 fd 被攻击者 `close`+`dup2` 重定向到任意文件。
///
/// # Arguments
/// - `fd`: 待验证的文件描述符
///
/// # Errors
/// - readlink 失败 (fd 已关闭)
/// - 解析后路径不在 `/proc/firewall/` 下
fn verify_procfs_fd(fd: RawFd) -> Result<()> {
    let proc_fd_path = format!("/proc/self/fd/{fd}");
    let link_target = std::fs::read_link(&proc_fd_path)
        .with_context(|| format!("Failed to read link for fd {fd}"))?;

    let target_str = link_target.to_string_lossy();
    if !target_str.starts_with("/proc/firewall/") {
        bail!("fd points to non-procfs path");
    }

    Ok(())
}

/// 阻塞写整个 `data` 到 `fd`。EINTR / EAGAIN 自动重试。
///
/// # Safety
/// 调用方必须确保 `fd` 是有效的文件描述符，并且指向正确的 procfs 文件
///
/// # Errors
/// - 非 EINTR/EAGAIN 的 write 错误
unsafe fn write_to_fd(fd: RawFd, data: &[u8]) -> Result<()> {
    let mut total_written: usize = 0;
    while total_written < data.len() {
        // 使用 libc::write 系统调用来写入数据
        let written = libc::write(
            fd,
            data.as_ptr().add(total_written).cast::<libc::c_void>(),
            data.len() - total_written,
        );

        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted
                || err.kind() == std::io::ErrorKind::WouldBlock
            {
                continue; // EINTR / EAGAIN → 重试
            }
            return Err(err.into());
        }

        total_written += written as usize;
    }

    // 确保数据被写入（对于 procfs 文件可能不需要，但为了安全起见）
    libc::fsync(fd);

    Ok(())
}

/// 安全写 procfs 文件。`BANS_PATH` 走 fd 缓存,其他文件每次 open+verify+close。
///
/// # Arguments
/// - `path`: 必须在 `/proc/firewall/` 下
/// - `data`: 1..=64 字节
///
/// # Errors
/// - `data` 为空或 > 64 字节
/// - 路径校验失败
/// - `open` / `write` / fd 校验失败
///
/// # Panics
/// `CString::new(path)` 仅当 `path` 含 NUL 字节时 panic。
/// 内部 `validate_procfs_path` 已禁止非 `[A-Za-z0-9/_.-]` 字符,实际不可能
pub fn secure_procfs_write(path: &str, data: &[u8]) -> Result<()> {
    if data.is_empty() {
        bail!("empty data");
    }
    if data.len() > 64 {
        bail!("data too long");
    }

    validate_procfs_path(path)?;

    let using_cached = path == BANS_PATH;
    let fd: RawFd = if using_cached {
        get_cached_bans_fd()?
    } else {
        let path_c = match CString::new(path) {
            Ok(p) => p,
            Err(_) => bail!("procfs path contains NUL byte: {path}"),
        };
        // SAFETY: `path` 已通过 `validate_procfs_path` 校验 (白名单目录 + 字符白名单 + 无 NUL),
        // CString::new 成功表示无内嵌 NUL 字节。O_WRONLY | O_NOFOLLOW 不会触发额外权限要求。
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            bail!("open {path} failed: {err}");
        }
        if let Err(e) = verify_procfs_fd(fd) {
            // SAFETY: fd 是本函数刚 `open` 拿到的有效值,验证失败立即释放
            unsafe { libc::close(fd) };
            bail!("fd verification failed for {path}: {e}");
        }
        fd
    };

    let write_result = unsafe { write_to_fd(fd, data) };
    if write_result.is_err() {
        if using_cached {
            // 缓存 fd 写入失败时关闭并标记为无效, 下次重新打开
            CACHED_BANS_FD.store(-1, Ordering::SeqCst);
            // SAFETY: fd 来自 `get_cached_bans_fd` 仍可能合法的 fd,失败时关闭并重置
            unsafe { libc::close(fd) };
        } else {
            // SAFETY: 非缓存 fd，需要手动关闭
            unsafe { libc::close(fd) };
        }
        return write_result;
    }

    if !using_cached {
        // SAFETY: fd 是本函数 `open` 拿到的非缓存 fd,作用域结束必须 close
        let close_result = unsafe { libc::close(fd) };
        if close_result != 0 {
            crate::logger::warn!(
                crate::logger::get(),
                "关闭 procfs fd 失败";
                "fd" => fd,
                "path" => path
            );
        }
    }

    Ok(())
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_procfs_path_valid() {
        assert!(validate_procfs_path("/proc/firewall/bans").is_ok());
        assert!(validate_procfs_path("/proc/firewall/whitelist").is_ok());
        assert!(validate_procfs_path("/proc/firewall/stats").is_ok());
    }

    #[test]
    fn validate_procfs_path_reject_outside() {
        assert!(validate_procfs_path("/etc/passwd").is_err());
        assert!(validate_procfs_path("/proc/firewall").is_err()); // 无尾随 /
    }

    #[test]
    fn validate_procfs_path_reject_traversal() {
        assert!(validate_procfs_path("/proc/firewall/../bans").is_err());
    }

    #[test]
    fn validate_procfs_path_reject_trailing_slash() {
        assert!(validate_procfs_path("/proc/firewall/bans/").is_err());
    }
}
