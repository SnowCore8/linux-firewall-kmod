//! inotify 监控日志文件 → 行分割 (不完整行缓冲) → 日志轮转检测 (inode/大小) → 主循环 (poll + SIGHUP 重载)
//!
//! # 模块结构
//!
//! 1. **文件状态**:`FileState` 跟踪每个监控文件的 path/offset/inode/watch descriptor
//! 2. **inotify 设置**:`setup_inotify` 给所有 enabled jail 的日志文件加 watch
//! 3. **行处理**:`process_single_line` / `process_lines_in_buffer` /
//!    `store_partial_line` / `flush_partial_line` 处理不完整行缓冲
//! 4. **新行处理**:`process_new_lines` 读自上次 offset 的新内容
//! 5. **轮转处理**:`handle_log_rotation` 检测 truncate/rename/inode 变化
//! 6. **主循环**:`monitor_loop` 调 `poll` 等待 inotify 事件 / SIGHUP / 周期维护
//! 7. **配置重载**:`reload_configuration` SIGHUP 触发的双缓冲热重载
//!
//! # 关键不变量
//!
//! - 每个日志文件 inode 在 `setup_inotify` 时记录,变化时认为是轮转
//! - 单行硬上限 8KB,异常超长行会跳过 (避免 OOM)
//! - `O_NOFOLLOW` 防止日志文件被替换为符号链接后 readlink 到攻击者文件
//! - `recent_head` 模式下 `partial_line_buffer` 容量 8KB

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use anyhow::{Context, Result};
use inotify::{Inotify, WatchDescriptor, WatchMask};
use parking_lot::RwLock;

use crate::types::{Config, Jail, DAEMON_STATS};
use crate::failed_tracker;
use crate::log_parser;
use crate::{log_debug, log_err, log_info, log_warn};

// ============================================================================
// 文件状态
// ============================================================================

/// 单个被监控日志文件的运行时状态。`FILE_STATES` 索引 = `FileState.wd` 在
/// inotify 事件中的对应位置。
#[derive(Debug)]
pub struct FileState {
    /// 日志文件路径
    pub path: String,
    /// 下次 read 的起始字节偏移
    pub offset: u64,
    /// 文件 inode (用于检测轮转)
    pub inode: u64,
    /// inotify watch descriptor
    pub wd: Option<WatchDescriptor>,
    /// 关联的 jail 在 `Config.jails` 中的索引
    pub jail_idx: usize,
    /// 文件被检测为符号链接,标记后跳过
    pub symlink_detected: bool,
}

impl Default for FileState {
    fn default() -> Self {
        Self::new()
    }
}

impl FileState {
    /// 构造空 `FileState`,所有字段为默认值
    #[must_use] 
    pub fn new() -> Self {
        Self {
            path: String::new(),
            offset: 0,
            inode: 0,
            wd: None,
            jail_idx: 0,
            symlink_detected: false,
        }
    }
}

/// 全局:所有被监控文件的 `FileState` 列表
pub static FILE_STATES: RwLock<Vec<FileState>> = RwLock::new(Vec::new());
/// 全局:inotify 句柄。`reload_configuration` 期间会替换
pub static INOTIFY_FD: RwLock<Option<Inotify>> = RwLock::new(None);
/// 全局:inotify raw fd,单独存以便 [`monitor_loop`] 的 `poll` 调用避开借出整个 `Inotify` 句柄
pub static INOTIFY_RAW_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);
/// 全局:监控循环运行标志 (备用,实际由 `main()` 持有的 `Arc<AtomicBool>` 控制)
pub static MONITOR_RUNNING: AtomicBool = AtomicBool::new(true);

// ============================================================================
// inotify 设置
// ============================================================================

/// 为 `Config` 中所有 enabled jail 的日志文件建立 inotify watch。
///
/// 启动时拒绝符号链接(攻击者可借此动态切换目标);运行期改用 `O_NOFOLLOW`
/// 二次防御。
///
/// # Arguments
/// - `cfg`: 全局配置
///
/// # Returns
/// 至少 1 个文件 watch 成功即返回 `Ok`
///
/// # Errors
/// 没有任何文件能被 watch (配置错误 / kmod 未加载 / 权限不足)
pub fn setup_inotify(cfg: &Config) -> Result<()> {
    let inotify = Inotify::init()
        .context("Failed to initialize inotify")?;

    let mut file_states = Vec::new();
    let mut watched_count = 0;
    let mut total_files = 0;

    for (j_idx, jail) in cfg.jails.iter().enumerate() {
        if !jail.enabled {
            log_info!("Skipping disabled jail: {}", jail.name);
            continue;
        }

        for log_file in &jail.log_files {
            total_files += 1;

            let mut state = FileState::new();
            state.path.clone_from(log_file);
            state.jail_idx = j_idx;

            // 启动时拒绝符号链接日志文件: 攻击者可借此动态切换目标
            let path = Path::new(log_file);
            if path.is_symlink() {
                log_warn!("Log file is a symlink, rejecting: {}", log_file);
                continue;
            }

            if let Ok(metadata) = path.metadata() {
                state.inode = metadata.ino();
                state.offset = metadata.len();
                log_info!(
                    "Initial offset for {} (jail={}): {} bytes",
                    log_file, jail.name, state.offset
                );
            }

            let mask = WatchMask::MODIFY
                | WatchMask::MOVED_FROM
                | WatchMask::MOVED_TO
                | WatchMask::DELETE
                | WatchMask::CREATE;

            match inotify.watches().add(log_file, mask) {
                Ok(wd) => {
                    state.wd = Some(wd.clone());
                    watched_count += 1;
                    log_info!("Watching {} (jail={}, wd={:?})", log_file, jail.name, wd);
                }
                Err(e) => {
                    log_warn!(
                        "Failed to watch {} (jail={}): {} (skipping)",
                        log_file, jail.name, e
                    );
                }
            }

            file_states.push(state);
        }
    }

    *FILE_STATES.write() = file_states;
    let raw_fd = inotify.as_raw_fd();
    *INOTIFY_FD.write() = Some(inotify);
    INOTIFY_RAW_FD.store(raw_fd, Ordering::Relaxed);

    log_info!(
        "Watching {}/{} log files across {} jails",
        watched_count, total_files, cfg.jails.len()
    );

    // 一个文件都没监控成功: 启动无意义, 直接退出
    if watched_count == 0 {
        log_err!("No log files could be watched initially");
        return Err(anyhow::anyhow!("No log files could be watched initially"));
    }

    Ok(())
}

// ============================================================================
// 行处理
// ============================================================================

/// 处理单行日志:长度校验 + 解析 + 失败计数。空行直接跳过;>8KB 跳过并
/// 累加 `lines_skipped`。
///
/// # Arguments
/// - `jail`: 关联 jail (正则集)
/// - `line`: 不含 `\n` 的单行
/// - `log_path`: 源文件路径 (日志用)
/// - `max_retries` / `findtime`: 失败阈值参数 (透传给 `failed_tracker`)
pub fn process_single_line(jail: &Jail, line: &str, log_path: &str, max_retries: u32, findtime: u32) {
    if line.is_empty() {
        return;
    }

    let len = line.len();
    if len >= 8192 {
        log_warn!("Line too long ({} bytes) in {}, skipping", len, log_path);
        DAEMON_STATS.lines_skipped.fetch_add(1, Ordering::Relaxed);
        return;
    }

    DAEMON_STATS.lines_parsed.fetch_add(1, Ordering::Relaxed);

    if let Some(ip) = log_parser::extract_and_validate_ip(jail, line) {
        failed_tracker::handle_failed_attempt_for_jail(jail, &ip, max_retries, findtime);
    }
}

/// 按 `\n` 分割 `data` 缓冲,逐行调 [`process_single_line`],返回 `consumed`
/// (已处理字节数) 给调用方用于 partial 行缓冲。
///
/// # Arguments
/// - `jail`: 关联 jail
/// - `data`: 字节缓冲
/// - `log_path`: 源文件路径
/// - `consumed`: 出参,已消费的字节数 (= 完整行总长)
/// - `max_retries` / `findtime`: 失败阈值
pub fn process_lines_in_buffer(
    jail: &Jail,
    data: &[u8],
    log_path: &str,
    consumed: &mut usize,
    max_retries: u32,
    findtime: u32,
) {
    let mut line_start = 0;
    let len = data.len();

    *consumed = 0;

    while line_start < len {
        if let Some(pos) = data[line_start..].iter().position(|&b| b == b'\n') {
            let line_end = line_start + pos;
            let line_len = line_end - line_start;

            if line_len >= 8192 {
                log_warn!("Extremely long line ({} bytes) in {}, skipping", line_len, log_path);
            } else {
                let line = std::str::from_utf8(&data[line_start..line_end]).unwrap_or("");
                process_single_line(jail, line, log_path, max_retries, findtime);
            }

            line_start = line_end + 1;
        } else {
            break;
        }
    }

    *consumed = line_start;
}

/// 追加 `data` 到 `jail.partial_line_buffer`。接近 8KB 上限前主动 flush 旧数据。
///
/// # Arguments
/// - `jail`: 关联 jail
/// - `data`: 待追加的字节片段 (不完整行尾)
/// - `log_path`: 源文件路径
/// - `max_retries` / `findtime`: 失败阈值
pub fn store_partial_line(
    jail: &Jail,
    data: &[u8],
    log_path: &str,
    max_retries: u32,
    findtime: u32,
) {
    if data.is_empty() {
        return;
    }

    if data.len() >= 8192 {
        log_warn!("Partial line too long ({} bytes) in {}, discarding", data.len(), log_path);
        jail.partial_line_buffer.write().clear();
        return;
    }

    let mut buf = jail.partial_line_buffer.write();
    let current_len = buf.len();

    if current_len + data.len() >= 8192 {
        // 缓冲区将溢出: 先处理累积数据, 再写入新片段
        if current_len > 0 {
            let temp = buf.clone();
            drop(buf);
            if let Ok(line) = std::str::from_utf8(&temp) {
                process_single_line(jail, line, log_path, max_retries, findtime);
            }
            buf = jail.partial_line_buffer.write();
        }

        buf.clear();
        buf.extend_from_slice(data);
    } else {
        buf.extend_from_slice(data);
    }
}

/// 强制 flush partial 行缓冲 (将残余不完整行作为完整行处理)。
///
/// 文件关闭 / truncate 之前调用,避免丢失最后一个不完整行。
///
/// # Arguments
/// - `jail`: 关联 jail
/// - `log_path`: 源文件路径
/// - `max_retries` / `findtime`: 失败阈值
pub fn flush_partial_line(jail: &Jail, log_path: &str, max_retries: u32, findtime: u32) {
    let mut buf = jail.partial_line_buffer.write();
    if buf.is_empty() {
        return;
    }

    let old_len = buf.len();
    let temp = buf.clone();
    buf.clear();
    drop(buf);

    log_debug!("Flushing partial line buffer with {} bytes from {}", old_len, log_path);
    if let Ok(line) = std::str::from_utf8(&temp) {
        process_single_line(jail, line, log_path, max_retries, findtime);
    }
}

// ============================================================================
// 处理新行
// ============================================================================

/// 处理 `FILE_STATES[idx]` 文件从 `offset` 起的新增内容。
///
/// 流程:打开 (`O_NOFOLLOW`) → 检测轮转 (inode 变化 / size 缩小) → seek 到
/// `offset` → 批量 read → 行分割 + 失败计数 → 更新 `offset`。
///
/// # Arguments
/// - `idx`: `FILE_STATES` 索引
/// - `cfg`: 全局配置
///
/// # Returns
/// `Ok(())` 即便内部错误 (e.g. `O_NOFOLLOW` 撞到 symlink),会标记 `symlink_detected`
/// 但不 bail
///
/// # Errors
/// - `idx` 越界 (即 `FILE_STATES.len() <= idx`)
/// - `jail_idx` 越界
pub fn process_new_lines(idx: usize, cfg: &Config) -> Result<()> {
    // 256KB 批量读: 平衡系统调用次数与内存占用
    const BATCH_READ_MAX: usize = 256 * 1024;

    let file_states = FILE_STATES.read();
    let state = file_states.get(idx).ok_or_else(|| anyhow::anyhow!("Invalid index {idx}"))?;

    if state.symlink_detected {
        return Ok(());
    }

    let log_path = state.path.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        log_err!("Invalid jail index {} in process_new_lines", jail_idx);
        return Ok(());
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    let mut local_partial_buf = jail.partial_line_buffer.read().clone();
    jail.partial_line_buffer.write().clear();
    // 复制完后 NLL 立即释放锁, 后续 file.open() 等 IO 操作可与其他 reader 并发

    // O_NOFOLLOW: 启动后文件若被替换为符号链接, 拒绝 follow
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&log_path)
    {
        Ok(f) => f,
        Err(e) => {
            // ELOOP = O_NOFOLLOW 撞到符号链接, 标记后跳过避免重复报错
            if e.raw_os_error() == Some(libc::ELOOP) {
                let mut file_states = FILE_STATES.write();
                if let Some(state) = file_states.get_mut(idx) {
                    state.symlink_detected = true;
                }
                log_warn!("Log file is a symlink, skipping and marking: {}", log_path);
            } else {
                log_err!("Failed to open {}: {}", log_path, e);
            }
            return Ok(());
        }
    };

    // 轮转检测: inode 变化 或 文件大小缩小 (truncate/rotate)
    if let Ok(metadata) = file.metadata() {
        let current_inode = metadata.ino();
        let current_size = metadata.len();

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            if state.inode != 0 && current_inode != state.inode {
                log_info!("Log file rotated: {}", log_path);
                state.inode = current_inode;
                state.offset = 0;
                local_partial_buf.clear();
            } else if current_size < state.offset {
                log_info!("Log file truncated: {}", log_path);
                state.inode = current_inode;
                state.offset = 0;
                local_partial_buf.clear();
            }
        }
    }

    let current_offset = {
        let file_states = FILE_STATES.read();
        file_states.get(idx).map_or(0, |s| s.offset)
    };

    if current_offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(current_offset))
            .with_context(|| format!("Failed to seek in {log_path}"))?;
    }

    // 256KB 批量读: 平衡系统调用次数与内存占用
    let mut batch_buf = vec![0u8; BATCH_READ_MAX];
    let mut batch_total = 0;

    loop {
        match file.read(&mut batch_buf[batch_total..]) {
            Ok(0) => break,
            Ok(n) => {
                batch_total += n;
                if batch_total >= BATCH_READ_MAX - 1 {
                    break;
                }
            }
            Err(e) => {
                log_warn!("Read error in {}: {}", log_path, e);
                return Ok(());
            }
        }
    }

    if batch_total > 0 {
        let mut process_buf = Vec::new();
        if local_partial_buf.is_empty() {
            process_buf.extend_from_slice(&batch_buf[..batch_total]);
        } else {
            process_buf.reserve(local_partial_buf.len() + batch_total);
            process_buf.extend_from_slice(&local_partial_buf);
            process_buf.extend_from_slice(&batch_buf[..batch_total]);
            local_partial_buf.clear();
        }

        let jail = &cfg.jails[jail_idx];
        let mut consumed = 0;
        process_lines_in_buffer(
            jail,
            &process_buf,
            &log_path,
            &mut consumed,
            max_retries,
            findtime,
        );

        if consumed < process_buf.len() {
            store_partial_line(jail, &process_buf[consumed..], &log_path, max_retries, findtime);
        }

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = current_offset + batch_total as u64;
        }
    }

    Ok(())
}

// ============================================================================
// 日志轮转处理
// ============================================================================

/// 处理日志轮转:inotify DELETE / `MOVED_FROM` 事件触发,先 flush partial 行,
/// 再更新 inode + offset,最后重新注册 inotify watch。
///
/// # Arguments
/// - `idx`: `FILE_STATES` 索引
/// - `cfg`: 全局配置
pub fn handle_log_rotation(idx: usize, cfg: &Config) {
    let file_states = FILE_STATES.read();
    let Some(state) = file_states.get(idx) else {
        return;
    };

    let path = state.path.clone();
    let wd = state.wd.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        return;
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    let mut buf = jail.partial_line_buffer.write();
    if buf.is_empty() {
        drop(buf);
    } else {
        let temp = buf.clone();
        buf.clear();
        drop(buf);

        if let Ok(line) = std::str::from_utf8(&temp) {
            process_single_line(jail, line, &path, max_retries, findtime);
        }
    }

    DAEMON_STATS.log_rotations.fetch_add(1, Ordering::Relaxed);

    let path_obj = Path::new(&path);
    if !path_obj.exists() {
        log_warn!("Log file disappeared: {}", path);
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = 0;
        }
        return;
    }

    if let Ok(metadata) = path_obj.metadata() {
        let current_inode = metadata.ino();
        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            if current_inode != state.inode {
                log_info!("Log file rotated: {}", path);
                state.inode = current_inode;
                state.offset = 0;

                if let Some(inotify) = INOTIFY_FD.write().as_mut() {
                    if let Some(old_wd) = wd {
                        let _ = inotify.watches().remove(old_wd);
                    }

                    let mask = WatchMask::MODIFY
                        | WatchMask::MOVED_FROM
                        | WatchMask::MOVED_TO
                        | WatchMask::DELETE
                        | WatchMask::CREATE;

                    match inotify.watches().add(&path, mask) {
                        Ok(new_wd) => {
                            state.wd = Some(new_wd.clone());
                            log_info!("Re-added watch for {} (wd={:?})", path, new_wd);
                        }
                        Err(e) => {
                            log_err!("Failed to re-add watch for {}: {}", path, e);
                            state.wd = None;
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// 主监控循环
// ============================================================================

/// 主事件循环:`poll` 等待 inotify fd / SIGHUP / 周期维护触发。
///
/// 主循环每次迭代:
/// 1. `poll(timeout=interval*1000ms)` 阻塞等待
/// 2. 唤醒时分类处理:有事件 → 读 inotify 事件分发;超时 → 检查
///    SIGHUP/周期清理/新增文件
/// 3. `running` 标志为 false 时优雅退出
///
/// # Arguments
/// - `cfg`: 全局配置 (可变,`cfg.interval` 实时生效)
/// - `running`: SIGINT/SIGTERM 控制的运行标志
/// - `reload_config`: SIGHUP 控制的重载标志
///
/// # Returns
/// 正常退出或不可恢复的 poll 错误
///
/// # Errors
/// `reload_configuration` 失败时记 WARN 后继续,不 bail;只有
/// `setup_inotify` 重建失败才向上抛
pub fn monitor_loop(
    cfg: &mut Config,
    running: &Arc<AtomicBool>,
    reload_config: &Arc<AtomicBool>,
) -> Result<()> {
    log_info!("Starting monitoring loop");

    let mut last_partial_cleanup = SystemTime::now();
    let mut last_new_file_check = SystemTime::now();

    let raw_fd = INOTIFY_RAW_FD.load(Ordering::Relaxed);
    if raw_fd < 0 {
        log_err!("No inotify fd available");
        return Ok(());
    }

    while running.load(Ordering::Relaxed) {
        let current_interval = cfg.interval;

        let mut poll_fds = libc::pollfd {
            fd: raw_fd,
            events: libc::POLLIN,
            revents: 0,
        };

        let timeout_ms = (current_interval as i32) * 1000;
        let poll_result = unsafe { libc::poll(&mut poll_fds, 1, timeout_ms) };

        // poll_result 分 3 段处理: > 0 = 有事件 / = 0 = 超时 / < 0 = 错误
        // 用 if-else 链比 match 更易读,因为错误分支还需要 i32 比较
        if poll_result > 0 {
            if let Some(inotify) = INOTIFY_FD.write().as_mut() {
                let mut buffer = [0u8; 4096];
                if let Ok(events) = inotify.read_events(&mut buffer) {
                    // 每次成功 read 增 1, 与事件数无关, 反映 inotify 唤醒频率
                    DAEMON_STATS.inotify_events.fetch_add(1, Ordering::Relaxed);
                    for event in events {
                        let wd = event.wd;
                        let file_states = FILE_STATES.read();
                        for (idx, state) in file_states.iter().enumerate() {
                            if state.wd.as_ref() == Some(&wd) {
                                if event.mask.contains(inotify::EventMask::MODIFY)
                                    || event.mask.contains(inotify::EventMask::MOVED_TO)
                                {
                                    let _ = process_new_lines(idx, cfg);
                                }
                                if event.mask.contains(inotify::EventMask::DELETE)
                                    || event.mask.contains(inotify::EventMask::MOVED_FROM)
                                {
                                    handle_log_rotation(idx, cfg);
                                }
                                break;
                            }
                        }
                    }
                }
            }
        } else if poll_result == 0 {
            // 超时: 利用间隙检查 SIGHUP 和周期维护
            if reload_config.load(Ordering::Relaxed) {
                reload_config.store(false, Ordering::Relaxed);
                log_info!("SIGHUP received, reloading configuration...");
                if let Err(e) = reload_configuration(cfg) {
                    log_err!("Configuration reload failed: {}", e);
                } else {
                    log_info!("Configuration reloaded successfully");
                }
                continue;
            }

            let now = SystemTime::now();
            if now.duration_since(last_partial_cleanup).unwrap_or_default().as_secs() >= 60 {
                last_partial_cleanup = now;
                cleanup_partial_line_buffer(cfg);
            }

            if now.duration_since(last_new_file_check).unwrap_or_default().as_secs() >= 60 {
                last_new_file_check = now;
                check_for_new_log_files(cfg);
            }
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR: 信号唤醒, 重试
            }
            log_err!("poll error: {}", err);
            break;
        }
    }

    log_info!("Monitoring loop exited");
    Ok(())
}

/// SIGHUP 热重载 (双缓冲):任何步骤失败旧配置不受影响。
///
/// 步骤: clone 旧 → 解析到新 → 应用默认 → 验证 → 迁移 `failed_hash` →
/// 编译正则 → 原子替换 → 重建 inotify。
///
/// # Arguments
/// - `cfg`: 旧配置 (会被新配置原子替换)
///
/// # Returns
/// 成功时 `Ok(())`,`DAEMON_STATS.config_reloads` +1
///
/// # Errors
/// 配置源缺失 / 解析失败 / 验证失败 / inotify 重建失败
pub fn reload_configuration(cfg: &mut Config) -> Result<()> {
    use crate::config_parser;
    use crate::jail;

    let config_path = if let Some(ref f) = cfg.config_file {
        f.clone()
    } else if let Some(ref d) = cfg.config_dir {
        d.clone()
    } else {
        return Err(anyhow::anyhow!("No config file or directory specified for reload"));
    };

    let old_cfg = jail::config_clone(cfg);

    // 保留 config_file / config_dir 供 SIGHUP 后继 reload 复用
    let mut new_cfg = crate::types::Config {
        config_file: old_cfg.config_file.clone(),
        config_dir: old_cfg.config_dir.clone(),
        ..crate::types::Config::default()
    };

    let path = std::path::Path::new(&config_path);
    if path.is_file() {
        config_parser::parse_config_file(&config_path, &mut new_cfg, cfg.strict_mode)?;
    } else if path.is_dir() {
        config_parser::load_config_directory(&config_path, &mut new_cfg, cfg.strict_mode)?;
    } else {
        return Err(anyhow::anyhow!("Config path does not exist: {config_path}"));
    }

    jail::apply_smart_defaults_to_all(&mut new_cfg);
    jail::config_validate(&new_cfg).map_err(|e| anyhow::anyhow!("{e}"))?;

    for old_jail in &old_cfg.jails {
        for new_jail in &mut new_cfg.jails {
            if old_jail.name == new_jail.name {
                let mut old_hash = old_jail.failed_hash.write();
                let mut new_hash = new_jail.failed_hash.write();
                for (ip, entry) in old_hash.drain() {
                    new_hash.insert(ip, entry);
                }
                log_info!("Migrated failed entries for jail '{}'", new_jail.name);
                break;
            }
        }
    }

    if let Err(e) = jail::init_log_patterns(&mut new_cfg) {
        log_warn!("Some jail regex patterns failed to compile during reload: {}", e);
    }

    *cfg = new_cfg;
    DAEMON_STATS.config_reloads.fetch_add(1, Ordering::Relaxed);
    setup_inotify(cfg)?;

    log_info!("Configuration reloaded: {} jails", cfg.jails.len());
    Ok(())
}

/// 周期维护: flush 所有 jail 的 partial 行缓冲。`monitor_loop` 超时 60s 触发。
///
/// 防止 partial 缓冲无限增长(异常日志最后一行无 `\n`)。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn cleanup_partial_line_buffer(cfg: &Config) {
    for jail in &cfg.jails {
        let mut buf = jail.partial_line_buffer.write();
        if !buf.is_empty() {
            log_debug!(
                "Flushing partial line buffer with {} bytes from jail '{}' (periodic_cleanup)",
                buf.len(),
                jail.name
            );
            buf.clear();
        }
    }
}

fn check_for_new_log_files(cfg: &Config) {
    let file_states = FILE_STATES.read();
    let mut needs_resetup = false;

    for jail in &cfg.jails {
        if !jail.enabled {
            continue;
        }
        for log_file in &jail.log_files {
            if Path::new(log_file).exists() {
                let already_watched = file_states.iter().any(|s| s.wd.is_some() && s.path == *log_file);
                if !already_watched {
                    log_info!("New log file detected: {} (jail={}), will re-setup inotify", log_file, jail.name);
                    needs_resetup = true;
                }
            }
        }
    }

    if needs_resetup {
        log_info!("Re-setting up inotify for new log files");
        drop(file_states);
        if let Err(e) = setup_inotify(cfg) {
            log_warn!("Failed to re-setup inotify for new log files: {}", e);
        } else {
            log_info!("Successfully re-setup inotify with new log files");
        }
    }
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Jail;

    #[test]
    fn process_single_line_empty() {
        let jail = Jail::new("test".to_string());
        process_single_line(&jail, "", "/var/log/test.log", 3, 600);
        assert_eq!(DAEMON_STATS.lines_parsed.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn process_single_line_too_long() {
        let jail = Jail::new("test".to_string());
        let long_line = "x".repeat(9000);
        process_single_line(&jail, &long_line, "/var/log/test.log", 3, 600);
        assert!(DAEMON_STATS.lines_skipped.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn file_state_new() {
        let state = FileState::new();
        assert!(state.path.is_empty());
        assert_eq!(state.offset, 0);
        assert_eq!(state.inode, 0);
        assert!(state.wd.is_none());
        assert!(!state.symlink_detected);
    }

    #[test]
    fn store_partial_line_respects_limit() {
        let jail = Jail::new("test".to_string());
        let data = vec![b'a'; 9000];
        store_partial_line(&jail, &data, "/var/log/test.log", 3, 600);
        assert!(jail.partial_line_buffer.read().is_empty());
    }
}
