//! 封禁/解封操作 + 安全 procfs 写入 + bans fd 缓存
//!
//! # 核心职责
//!
//! - 与内核模块 `/proc/firewall/bans` procfs 接口通信 (写命令)
//! - IP 合法性校验 (拒绝 loopback/multicast/link-local 等)
//! - 缓存 bans fd (R9-9 优化) 避免每次封禁都 `open`/`close`
//! - Permanent/UnbanPerm 同步写 `SQLite` 永久黑名单
//!
//! # procfs 命令格式
//!
//! | 操作 | 命令格式 | 示例 |
//! |------|----------|------|
//! | 临时封禁 | `<ip>\n` | `1.2.3.4\n` |
//! | 永久封禁 | `<ip> 0\n` | `1.2.3.4 0\n` |
//! | 解封 (Temp/Perm 共用) | `unban <ip>\n` | `unban 1.2.3.4\n` |
//!
//! # 安全模型
//!
//! 三道防线防止恶意输入击穿到 procfs:
//! 1. **路径白名单**:只能写 `/proc/firewall/` 下的路径
//! 2. **字符白名单**:文件名仅允许 `[A-Za-z0-9/_.-]`
//! 3. **fd 重定向检查**:`/proc/self/fd/N` readlink 必须解析到 `/proc/firewall/`
//!
//! 即使攻击者通过环境变量 / 配置文件注入 `../../etc/passwd`,也会在第 1 道
//! 关被拒。

use std::ffi::CString;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicI32, Ordering};

use anyhow::{Context, Result, bail};
use parking_lot::Mutex;

use crate::{log_err, log_info, log_warn};
use crate::sqlite_store;
use crate::types::DAEMON_STATS;

// ============================================================================
// 常量
// ============================================================================

/// 内核模块 procfs 根目录。所有 `secure_procfs_write` 只能在此目录下写入。
pub const PROCFS_DIR: &str = "/proc/firewall";

/// 封禁命令的 procfs 文件。命令格式见模块级文档。
pub const BANS_PATH: &str = "/proc/firewall/bans";

// ============================================================================
// 封禁/解封操作类型
// ============================================================================

/// 封禁/解封操作枚举。所有动作经 [`execute_ban_action`] 统一分发。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanAction {
    /// 临时封禁 (写 `<ip>\n`,内核按 `ban_time` 自动解封)
    Temp,
    /// 永久封禁 (写 `<ip> 0\n`,同时写 `SQLite`)
    Permanent,
    /// 解封临时封禁 (写 `unban <ip>\n`)
    Unban,
    /// 解封永久封禁 (写 `unban <ip>\n`,同时 `SQLite` `is_active=0`)
    UnbanPerm,
}

/// 校验通过的 IP 描述。
#[derive(Debug, Clone)]
pub struct ValidatedIp {
    /// 标准库 `IpAddr` 表示
    pub ip: IpAddr,
    /// 仅 IPv4 有效 (网络字节序)。IPv6 时为 0
    pub ip_num: u32,
}

// ============================================================================
// 缓存的 bans procfs fd (R9-9 优化: 避免每次封禁都 open/close)
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

    let path = CString::new(BANS_PATH).unwrap();
    // SAFETY: `BANS_PATH` 是 `&'static str` 常量,不含 NUL,`CString::new` 已 unwrap 验证。
    // `O_WRONLY | O_NOFOLLOW` 不需要额外权限
    let new_fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW) };
    if new_fd < 0 {
        let err = std::io::Error::last_os_error();
        log_err!("Failed to open {}: {}", BANS_PATH, err);
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
// IP 验证
// ============================================================================

/// 校验 IPv4 字符串。拒绝 loopback / broadcast / multicast / 全 0 地址。
///
/// # Arguments
/// - `ip`: 待校验的 IPv4 字符串
///
/// # Returns
/// - `Ok(ValidatedIp)`: 校验通过,内含原生 `IpAddr` 和网络字节序数值
///
/// # Errors
/// - 长度越界 (空或 ≥16 字节, `INET_ADDRSTRLEN`)
/// - 解析失败 (非合法 IPv4 点分十进制)
/// - 地址属于保留段 (0.0.0.0 / 255.255.255.255 / 127.0.0.0/8 / 224.0.0.0/4)
pub fn validate_ipv4(ip: &str) -> Result<ValidatedIp> {
    if ip.is_empty() || ip.len() >= 16 {
        // INET_ADDRSTRLEN = 16
        bail!("invalid IPv4 length");
    }

    let addr: Ipv4Addr = ip.parse().map_err(|e| anyhow::anyhow!("invalid IPv4: {e}"))?;
    let ip_num = u32::from_ne_bytes(addr.octets());
    let ip_num_host = u32::from_be(ip_num);

    let first_octet = (ip_num_host >> 24) & 0xFF;
    if ip_num_host == 0
        || ip_num_host == 0xFFFF_FFFF
        || first_octet == 127
        || (224..=239).contains(&first_octet)
    {
        bail!("rejected IPv4 address: {ip} (loopback/broadcast/multicast)");
    }

    Ok(ValidatedIp {
        ip: IpAddr::V4(addr),
        ip_num,
    })
}

/// 校验通用 IP (IPv4 或 IPv6) 字符串。先尝试 IPv4,失败回退 IPv6。
///
/// IPv6 时额外拒绝 loopback / multicast / unspecified / link-local (`fe80::/10`)。
///
/// # Arguments
/// - `ip`: 待校验的 IP 字符串
///
/// # Errors
/// - 长度越界 (空或 ≥46 字节, `INET6_ADDRSTRLEN`)
/// - 解析失败 (既不是合法 IPv4 也不是合法 IPv6)
/// - 地址属于 IPv6 保留段
pub fn validate_ip(ip: &str) -> Result<ValidatedIp> {
    if ip.is_empty() || ip.len() >= 46 {
        // INET6_ADDRSTRLEN = 46
        bail!("invalid IP length");
    }

    if let Ok(validated) = validate_ipv4(ip) {
        return Ok(validated);
    }

    let addr: Ipv6Addr = ip.parse().map_err(|e| anyhow::anyhow!("invalid IPv6: {e}"))?;

    if addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unspecified()
        || (addr.segments()[0] & 0xFFC0 == 0xFE80)
    {
        // fe80::/10 link-local: 前 10 位为 1111111010
        bail!(
            "rejected IPv6 address: {ip} (loopback/multicast/unspecified/link-local)"
        );
    }

    Ok(ValidatedIp {
        ip: IpAddr::V6(addr),
        ip_num: 0,
    })
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
        log_err!("secure_procfs_write: path outside {}: {}", PROCFS_DIR, path);
        bail!("path outside {PROCFS_DIR}");
    }

    if path.contains("..") {
        log_err!("secure_procfs_write: path traversal attempt: {}", path);
        bail!("path traversal attempt");
    }

    // 跳过 PROCFS_DIR 前缀后逐字符验证
    let safe_start = PROCFS_DIR.len() + 1;
    for (i, c) in path[safe_start..].chars().enumerate() {
        if !c.is_ascii_alphanumeric() && !matches!(c, '/' | '-' | '_' | '.') {
            log_err!(
                "secure_procfs_write: invalid character in path: {} (char: '{}' at offset {})",
                path,
                c,
                safe_start + i
            );
            bail!("invalid character in path");
        }
    }

    if path.ends_with('/') {
        log_err!("secure_procfs_write: path ends with '/': {}", path);
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
        log_err!(
            "secure_procfs_write: fd {} points to non-procfs path: {} (expected /proc/firewall/...)",
            fd,
            target_str
        );
        bail!("fd points to non-procfs path");
    }

    Ok(())
}

/// 阻塞写整个 `data` 到 `fd`。EINTR / EAGAIN 自动重试。
///
/// # Errors
/// - 非 EINTR/EAGAIN 的 write 错误
fn write_to_fd(fd: RawFd, data: &[u8]) -> Result<()> {
    let mut total_written: usize = 0;
    while total_written < data.len() {
        // SAFETY: `data.as_ptr().add(total_written)` 算术安全,因为循环不变量
        // `total_written <= data.len()` 始终成立 (初始化 + 每次 `total_written += written`
        // 后 `written <= data.len() - total_written` 由 libc::write 契约保证)。
        // 长度参数 `data.len() - total_written` 是剩余字节数,不会越界。
        // fd 在调用方 (`secure_procfs_write`) 已通过 `verify_procfs_fd` 校验。
        let written = unsafe {
            libc::write(fd, data.as_ptr().add(total_written).cast::<libc::c_void>(), data.len() - total_written)
        };
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted || err.kind() == std::io::ErrorKind::WouldBlock {
                continue; // EINTR / EAGAIN → 重试
            }
            log_err!("Failed to write to procfs fd {}: {}", fd, err);
            bail!("write failed: {err}");
        }
        total_written += written as usize;
    }
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
        log_err!("Invalid parameters to secure_procfs_write");
        bail!("empty data");
    }
    if data.len() > 64 {
        log_err!("Data too long for procfs write ({} bytes, max 64)", data.len());
        bail!("data too long");
    }

    validate_procfs_path(path)?;

    let using_cached = path == BANS_PATH;
    let fd: RawFd = if using_cached {
        get_cached_bans_fd()?
    } else {
        let path_c = CString::new(path).unwrap();
        // SAFETY: `path` 已通过 `validate_procfs_path` 校验 (白名单目录 + 字符白名单 + 无 NUL),
        // CString::new 成功表示无内嵌 NUL 字节。O_WRONLY | O_NOFOLLOW 不会触发额外权限要求。
        let fd = unsafe { libc::open(path_c.as_ptr(), libc::O_WRONLY | libc::O_NOFOLLOW) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            log_err!("Failed to open {}: {}", path, err);
            bail!("open {path} failed: {err}");
        }
        if verify_procfs_fd(fd).is_err() {
            // SAFETY: fd 是本函数刚 `open` 拿到的有效值,验证失败立即释放
            unsafe { libc::close(fd) };
            bail!("fd verification failed for {path}");
        }
        fd
    };

    let write_result = write_to_fd(fd, data);
    if write_result.is_err() {
        if using_cached {
            // 缓存 fd 写入失败时关闭并标记为无效, 下次重新打开
            CACHED_BANS_FD.store(-1, Ordering::SeqCst);
            // SAFETY: fd 来自 `get_cached_bans_fd` 仍可能合法的 fd,失败时关闭并重置
            unsafe { libc::close(fd) };
        }
        return write_result;
    }

    if !using_cached {
        // SAFETY: fd 是本函数 `open` 拿到的非缓存 fd,作用域结束必须 close
        let close_result = unsafe { libc::close(fd) };
        if close_result < 0 {
            let err = std::io::Error::last_os_error();
            log_warn!("Failed to close {}: {}", path, err);
        }
    }

    Ok(())
}

// ============================================================================
// 封禁命令格式化
// ============================================================================

/// 格式化内核模块识别的命令字符串。命令总长硬上限 80 字节。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 校验的字符串
///
/// # Errors
/// - 格式化后命令 > 80 字节 (实际不可能,IP 长度上限 46 + 前缀 7 = 53)
fn format_ban_command(action: BanAction, ip: &str) -> Result<String> {
    let cmd = match action {
        BanAction::Temp => format!("{ip}\n"),
        BanAction::Permanent => format!("{ip} 0\n"),
        BanAction::Unban | BanAction::UnbanPerm => format!("unban {ip}\n"),
    };

    if cmd.len() > 80 {
        bail!("Command buffer overflow for IP {ip}");
    }

    Ok(cmd)
}

// ============================================================================
// 统一封禁/解封操作
// ============================================================================

/// 统一的封禁/解封操作入口 (支持 IPv4/IPv6)。
///
/// 流程: 校验 IP → 格式化命令 → `secure_procfs_write` → 同步 `SQLite`
/// (仅 Permanent/UnbanPerm) → 记日志 + `ips_banned` 累加。
///
/// # Arguments
/// - `action`: 见 [`BanAction`]
/// - `ip`: 已通过 [`validate_ip`] 的字符串
///
/// # Errors
/// - IP 校验失败
/// - procfs 写入失败
/// - `SQLite` 写入失败 (仅 Permanent/UnbanPerm)
pub fn execute_ban_action(action: BanAction, ip: &str) -> Result<()> {
    if ip.is_empty() {
        log_err!("NULL IP address provided to execute_ban_action");
        bail!("NULL IP address");
    }

    let validated = validate_ip(ip).with_context(|| format!("Invalid IP address: {ip}"))?;

    let cmd = format_ban_command(action, ip)?;
    secure_procfs_write(BANS_PATH, cmd.as_bytes())
        .with_context(|| format!("Failed to write to {BANS_PATH}"))?;

    match action {
        BanAction::Permanent => {
            if let Some(rc) =
                sqlite_store::with_global_db(|db| sqlite_store::sqlite_add_permanent_ban(
                    db,
                    ip,
                    validated.ip_num,
                    "manual permanent ban",
                    "manual",
                ))
            {
                rc.with_context(|| {
                    format!("SQLite add_permanent_ban failed for permanent ban {ip}")
                })?;
            }
            // 全局 db 未注册 (sqlite_init 失败) → 静默跳过, 等同 C 版 sqlite_db==NULL
        }
        BanAction::UnbanPerm => {
            if let Some(rc) = sqlite_store::with_global_db(|db| {
                sqlite_store::sqlite_remove_permanent_ban(db, ip)
            }) {
                rc.with_context(|| {
                    format!("SQLite remove_permanent_ban failed for permanent unban {ip}")
                })?;
            }
        }
        _ => {}
    }

    log_ban_action(action, ip);

    Ok(())
}

/// 内部:累加 `ips_banned` 统计并 emit 用户可见的日志。
///
/// Temp / Permanent 都累加,Prometheus `ips_banned_total` 来源。
fn log_ban_action(action: BanAction, ip: &str) {
    if matches!(action, BanAction::Temp | BanAction::Permanent) {
        DAEMON_STATS.ips_banned.fetch_add(1, Ordering::Relaxed);
    }

    match action {
        BanAction::Temp => log_info!("Banned IP {}", ip),
        BanAction::Permanent => log_info!("Permanently banned IP {}", ip),
        BanAction::Unban => log_info!("Unbanned IP {}", ip),
        BanAction::UnbanPerm => log_info!("Removed permanent ban for IP {}", ip),
    }
}

// ============================================================================
// 向后兼容的包装函数
// ============================================================================

/// 临时封禁。`failed_tracker` 触发阈值时调此函数。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Temp, ip)
}

/// 永久封禁。启动时从 `SQLite` 恢复永久黑名单用此函数。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn ban_ip_permanent(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Permanent, ip)
}

/// 解封临时封禁。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::Unban, ip)
}

/// 解封永久封禁 (同步写 `SQLite` `is_active=0`)。
///
/// # Errors
/// 同 [`execute_ban_action`]
pub fn unban_permanent_ip(ip: &str) -> Result<()> {
    execute_ban_action(BanAction::UnbanPerm, ip)
}

/// 占位函数: 内核模块负责定期清理过期封禁, 用户态无需轮询。
pub fn cleanup_expired_bans() {
    // 内核模块负责定期清理, 此处仅占位
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_ipv4_valid() {
        let v = validate_ipv4("192.168.1.100").unwrap();
        assert!(matches!(v.ip, IpAddr::V4(_)));
        assert!(v.ip_num != 0);
    }

    #[test]
    fn validate_ipv4_reject_loopback() {
        assert!(validate_ipv4("127.0.0.1").is_err());
    }

    #[test]
    fn validate_ipv4_reject_broadcast() {
        assert!(validate_ipv4("255.255.255.255").is_err());
    }

    #[test]
    fn validate_ipv4_reject_zero() {
        assert!(validate_ipv4("0.0.0.0").is_err());
    }

    #[test]
    fn validate_ipv4_reject_multicast() {
        assert!(validate_ipv4("224.0.0.1").is_err());
        assert!(validate_ipv4("239.255.255.255").is_err());
    }

    #[test]
    fn validate_ip_ipv6_valid() {
        let v = validate_ip("2001:db8::1").unwrap();
        assert!(matches!(v.ip, IpAddr::V6(_)));
        assert_eq!(v.ip_num, 0);
    }

    #[test]
    fn validate_ip_ipv6_reject_loopback() {
        assert!(validate_ip("::1").is_err());
    }

    #[test]
    fn validate_ip_ipv6_reject_unspecified() {
        assert!(validate_ip("::").is_err());
    }

    #[test]
    fn validate_ip_ipv6_reject_link_local() {
        assert!(validate_ip("fe80::1").is_err());
    }

    #[test]
    fn validate_ip_invalid() {
        assert!(validate_ip("").is_err());
        assert!(validate_ip("not-an-ip").is_err());
        assert!(validate_ip("999.999.999.999").is_err());
    }

    #[test]
    fn format_ban_command_temp() {
        let cmd = format_ban_command(BanAction::Temp, "1.2.3.4").unwrap();
        assert_eq!(cmd, "1.2.3.4\n");
    }

    #[test]
    fn format_ban_command_permanent() {
        let cmd = format_ban_command(BanAction::Permanent, "1.2.3.4").unwrap();
        assert_eq!(cmd, "1.2.3.4 0\n");
    }

    #[test]
    fn format_ban_command_unban() {
        let cmd = format_ban_command(BanAction::Unban, "1.2.3.4").unwrap();
        assert_eq!(cmd, "unban 1.2.3.4\n");
    }

    #[test]
    fn format_ban_command_unban_perm() {
        let cmd = format_ban_command(BanAction::UnbanPerm, "1.2.3.4").unwrap();
        assert_eq!(cmd, "unban 1.2.3.4\n");
    }

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

    /// 回归测试 P0-3: log_ban_action 必须对 Temp/Permanent 累计 ips_banned
    /// 防止误把 fetch_add 注释掉导致 Prometheus ips_banned_total 永远为 0
    #[test]
    fn log_ban_action_increments_ips_banned_for_ban_types() {
        use std::sync::atomic::Ordering;
        let before = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);

        log_ban_action(BanAction::Temp, "10.0.0.1");
        let after_temp = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(after_temp, before + 1, "Temp ban must increment ips_banned");

        log_ban_action(BanAction::Permanent, "10.0.0.2");
        let after_perm = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(after_perm, before + 2, "Permanent ban must increment ips_banned");

        log_ban_action(BanAction::Unban, "10.0.0.1");
        log_ban_action(BanAction::UnbanPerm, "10.0.0.2");
        let after_unban = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
        assert_eq!(after_unban, after_perm, "Unban must NOT increment ips_banned");
    }
}
