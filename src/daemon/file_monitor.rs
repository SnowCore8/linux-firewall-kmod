//! inotify 监控日志文件 → 行分割 → 主循环 (poll + SIGHUP 重载)
//!
//! # 模块结构
//!
//! 1. **文件状态**：`FileState` 跟踪每个监控文件的 path/offset/inode/watch descriptor
//! 2. **inotify 设置**：`setup_inotify` 给所有 enabled jail 的日志文件加 watch
//! 3. **新行处理**：`process_new_lines` 读自上次 offset 的新内容
//! 4. **主循环**：`monitor_loop` 调 `poll` 等待 inotify 事件 / SIGHUP / 周期维护
//!
//! 行处理逻辑 → [`crate::line_processor`]
//! 日志轮转处理 → [`crate::log_rotation`]
//! 配置热重载 → [`crate::config_reloader`]
//!
//! # 关键不变量
//!
//! - 每个日志文件 inode 在 `setup_inotify` 时记录,变化时认为是轮转
//! - 单行硬上限 8KB,异常超长行会跳过 (避免 OOM)
//! - `O_NOFOLLOW` 防止日志文件被替换为符号链接后 readlink 到攻击者文件

use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::SystemTime;

use anyhow::{Context, Result};
use inotify::{Inotify, WatchDescriptor, WatchMask};
use parking_lot::RwLock;

use crate::config_reloader::{cleanup_partial_line_buffer, reload_configuration};
use crate::line_processor::{process_lines_in_buffer, store_partial_line};
use crate::log_rotation::{check_for_new_log_files, handle_log_rotation};
use crate::types::{Config, DAEMON_STATS};

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
pub static INOTIFY_RAW_FD: AtomicI32 = AtomicI32::new(-1);
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
    let inotify = Inotify::init().context("Failed to initialize inotify")?;

    let mut file_states = Vec::new();
    let mut watched_count = 0;

    for (j_idx, jail) in cfg.jails.iter().enumerate() {
        if !jail.enabled {
            continue;
        }

        for log_file in &jail.log_files {
            let mut state = FileState::new();
            state.path.clone_from(log_file);
            state.jail_idx = j_idx;

            // 启动时拒绝符号链接日志文件
            let path = Path::new(log_file);
            if path.is_symlink() {
                crate::logger::warn!(
                    crate::logger::get(),
                    "跳过符号链接日志文件";
                    "path" => log_file
                );
                continue;
            }

            if let Ok(metadata) = path.metadata() {
                state.inode = metadata.ino();
                state.offset = metadata.len();
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
                }
                Err(e) => {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "添加 inotify watch 失败";
                        "path" => log_file,
                        "error" => %e
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

    // 一个文件都没监控成功: 启动无意义, 直接退出
    if watched_count == 0 {
        return Err(anyhow::anyhow!("No log files could be watched initially"));
    }

    Ok(())
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
    let state = file_states
        .get(idx)
        .ok_or_else(|| anyhow::anyhow!("Invalid index {idx}"))?;

    if state.symlink_detected {
        return Ok(());
    }

    let log_path = state.path.clone();
    let jail_idx = state.jail_idx;
    drop(file_states);

    if jail_idx >= cfg.jails.len() {
        crate::logger::warn!(
            crate::logger::get(),
            "jail_idx 越界";
            "jail_idx" => jail_idx,
            "jails_count" => cfg.jails.len()
        );
        return Ok(());
    }

    let jail = &cfg.jails[jail_idx];
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;

    let mut local_partial_buf = {
        let mut buf = jail.partial_line_buffer.write();
        std::mem::take(&mut *buf)
    };
    // mem::take 后 NLL 立即释放锁, 后续 file.open() 等 IO 操作可与其他 reader 并发

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
                crate::logger::warn!(
                    crate::logger::get(),
                    "检测到符号链接，跳过文件";
                    "path" => &log_path
                );
            } else {
                crate::logger::debug!(
                    crate::logger::get(),
                    "打开日志文件失败";
                    "path" => &log_path,
                    "error" => %e
                );
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
            if (state.inode != 0 && current_inode != state.inode) || current_size < state.offset {
                // inode 变化或文件缩小，重置状态
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
                crate::logger::debug!(
                    crate::logger::get(),
                    "读取日志文件失败";
                    "path" => &log_path,
                    "error" => %e
                );
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
            store_partial_line(
                jail,
                &process_buf[consumed..],
                &log_path,
                max_retries,
                findtime,
            );
        }

        let mut file_states = FILE_STATES.write();
        if let Some(state) = file_states.get_mut(idx) {
            state.offset = current_offset + batch_total as u64;
        }
    }

    Ok(())
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
pub fn monitor_loop(
    cfg: &mut Config,
    running: &AtomicBool,
    reload_config: &AtomicBool,
) -> Result<()> {
    let mut last_partial_cleanup = SystemTime::now();
    let mut last_new_file_check = SystemTime::now();
    let mut last_sqlite_sync = SystemTime::now();
    let mut last_stats_snapshot = SystemTime::now();
    let mut last_data_cleanup = SystemTime::now();
    let mut last_ddos_check = SystemTime::now();

    let raw_fd = INOTIFY_RAW_FD.load(Ordering::Relaxed);
    if raw_fd < 0 {
        crate::logger::error!(
            crate::logger::get(),
            "inotify raw fd 无效";
            "raw_fd" => raw_fd
        );
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
        // SAFETY: `poll_fds` 是栈上的 `pollfd` 数组,fds 字段是 `setup_inotify` 中
        // 已打开并通过 inotify API 管理的 fd。`nfds=1` 严格匹配数组长度。
        // `timeout_ms` 是 i32 类型且 config_validate 保证 `current_interval ∈ [1, 60]`,
        // 乘 1000 后仍在 i32 正数范围 (`60 * 1000 = 60000 << i32::MAX`)。
        let poll_result = unsafe { libc::poll(&mut poll_fds, 1, timeout_ms) };

        // poll_result 分 3 段处理: > 0 = 有事件 / = 0 = 超时 / < 0 = 错误
        if poll_result > 0 {
            // 1. 读取 inotify 事件到 Vec 后立即释放 INOTIFY_FD 写锁
            let collected_events: Vec<(WatchDescriptor, inotify::EventMask)> = {
                if let Some(inotify) = INOTIFY_FD.write().as_mut() {
                    let mut buffer = [0u8; 4096];
                    if let Ok(events) = inotify.read_events(&mut buffer) {
                        DAEMON_STATS.inotify_events.fetch_add(1, Ordering::Relaxed);
                        events.map(|e| (e.wd, e.mask)).collect()
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                }
            };

            // 2. 事件分发: 不持有任何全局锁调用处理函数
            for (wd, mask) in collected_events {
                let file_idx = {
                    let file_states = FILE_STATES.read();
                    file_states
                        .iter()
                        .enumerate()
                        .find(|(_, state)| state.wd.as_ref() == Some(&wd))
                        .map(|(idx, _)| idx)
                };

                let Some(idx) = file_idx else { continue };

                if mask.contains(inotify::EventMask::MODIFY)
                    || mask.contains(inotify::EventMask::MOVED_TO)
                {
                    if let Err(e) = process_new_lines(idx, cfg) {
                        crate::logger::debug!(
                            crate::logger::get(),
                            "处理日志行失败";
                            "error" => %e
                        );
                    }
                }
                if mask.contains(inotify::EventMask::DELETE)
                    || mask.contains(inotify::EventMask::MOVED_FROM)
                {
                    handle_log_rotation(idx, cfg);
                }
            }
        } else if poll_result == 0 {
            if reload_config.load(Ordering::Relaxed) {
                reload_config.store(false, Ordering::Relaxed);

                if let Err(e) = reload_configuration(cfg) {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "配置重载失败";
                        "error" => %e
                    );
                } else {
                    crate::logger::info!(crate::logger::get(), "配置重载成功");
                }
                continue;
            }

            let now = SystemTime::now();
            if now
                .duration_since(last_partial_cleanup)
                .unwrap_or_default()
                .as_secs()
                >= 60
            {
                last_partial_cleanup = now;
                cleanup_partial_line_buffer(cfg);
            }

            if now
                .duration_since(last_new_file_check)
                .unwrap_or_default()
                .as_secs()
                >= 60
            {
                last_new_file_check = now;
                check_for_new_log_files(cfg);
            }

            // SQLite dirty 标志清理（封禁/解封时立即写入，此处仅清理标志）
            if crate::sqlite_writer::is_dirty()
                && now
                    .duration_since(last_sqlite_sync)
                    .unwrap_or_default()
                    .as_secs()
                    >= cfg.storage.writer.flush_interval_secs as u64
            {
                last_sqlite_sync = now;
                crate::sqlite_writer::clear_dirty();
                crate::logger::debug!(crate::logger::get(), "SQLite dirty 标志已清理");
            }

            // Jail 统计快照 (每 60 秒)
            if now
                .duration_since(last_stats_snapshot)
                .unwrap_or_default()
                .as_secs()
                >= 60
            {
                last_stats_snapshot = now;
                if let Some(db) = crate::sqlite::get_global_db() {
                    let conn = crate::sqlite::get_conn(&db);
                    let now_secs = now
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs() as i64;

                    // 写入全局守护进程统计快照
                    let daemon_stats = crate::sqlite_writer::DaemonStatsSnapshot {
                        snapshot_time: now_secs,
                        uptime_seconds: (now_secs
                            - crate::types::DAEMON_STATS
                                .start_time
                                .load(Ordering::Relaxed) as i64)
                            .max(0) as u64,
                        total_lines_parsed: crate::types::DAEMON_STATS
                            .lines_parsed
                            .load(Ordering::Relaxed),
                        total_ips_banned: crate::types::DAEMON_STATS
                            .ips_banned
                            .load(Ordering::Relaxed),
                        total_failed: crate::types::DAEMON_STATS
                            .failed_attempts
                            .load(Ordering::Relaxed),
                        active_ban_count: crate::types::ACTIVE_BAN_CACHE
                            .get()
                            .map(|c| c.len())
                            .unwrap_or(0) as u64,
                        kernel_ban_count: 0,
                    };
                    if let Err(e) = crate::sqlite_writer::insert_daemon_stats(&conn, &daemon_stats)
                    {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "写入守护进程统计快照失败";
                            "error" => %e
                        );
                    }

                    // 写入 per-jail 统计快照
                    if let Some(map) = crate::types::JAIL_STATS.get() {
                        let read_guard = map.read();
                        for (_jail_name, counters) in read_guard.iter() {
                            let snapshot = counters.snapshot();
                            let jail_stats = crate::sqlite_writer::JailStatsSnapshot {
                                jail_name: snapshot.jail_name.clone(),
                                snapshot_time: now_secs,
                                lines_parsed: snapshot.lines_parsed,
                                ips_extracted: snapshot.ips_extracted,
                                bans_triggered: snapshot.bans_triggered,
                                failed_attempts: snapshot.failed_attempts,
                                active_bans: crate::types::ACTIVE_BAN_CACHE
                                    .get()
                                    .map(|cache| cache.get_by_jail(&snapshot.jail_name).len())
                                    .unwrap_or(0)
                                    as u64,
                            };
                            if let Err(e) =
                                crate::sqlite_writer::insert_jail_stats(&conn, &jail_stats)
                            {
                                crate::logger::warn!(
                                    crate::logger::get(),
                                    "写入 jail 统计快照失败";
                                    "jail" => &snapshot.jail_name,
                                    "error" => %e
                                );
                            }
                        }
                    }

                    crate::logger::debug!(crate::logger::get(), "统计快照写入完成");
                } else {
                    // SQLite 不可用时记录警告（降级模式）
                    crate::logger::warn!(
                        crate::logger::get(),
                        "SQLite 全局数据库未初始化，跳过统计快照写入（降级模式）"
                    );
                }
            }

            // 数据清理 (按 retention 策略)
            if now
                .duration_since(last_data_cleanup)
                .unwrap_or_default()
                .as_secs()
                >= cfg.storage.retention.cleanup_interval_secs as u64
            {
                last_data_cleanup = now;

                // 清理过期的临时封禁
                let now_secs = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if let Some(cache) = crate::types::ACTIVE_BAN_CACHE.get() {
                    let expired = cache.purge_expired(now_secs);
                    if !expired.is_empty() {
                        crate::logger::info!(
                            crate::logger::get(),
                            "清理过期临时封禁";
                            "count" => expired.len()
                        );
                        for ban_info in &expired {
                            // 从内核移除
                            if let Err(e) = crate::ban::unban_ip(&ban_info.ip) {
                                crate::logger::warn!(
                                    crate::logger::get(),
                                    "解封过期封禁失败";
                                    "ip" => &ban_info.ip,
                                    "error" => %e
                                );
                            }
                        }
                        // 标记 dirty，同步到 SQLite
                        crate::sqlite_writer::mark_dirty();
                    }
                }

                // 清理各 jail 的 failed_hash 中过期条目（防止内存泄漏）
                let now_secs_for_cleanup = now
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                for jail in cfg.jails.iter() {
                    if jail.enabled {
                        let removed = crate::failed_tracker::cleanup_expired_entries(
                            jail,
                            now_secs_for_cleanup,
                            jail.findtime as i64,
                        );
                        if removed > 0 {
                            crate::logger::debug!(
                                crate::logger::get(),
                                "清理 failed_hash 过期条目";
                                "jail" => &jail.name,
                                "removed" => removed
                            );
                        }
                    }
                }

                if let Some(db) = crate::sqlite::get_global_db() {
                    let conn = crate::sqlite::get_conn(&db);

                    if let Err(e) = crate::sqlite_writer::cleanup_old_data(
                        &conn,
                        cfg.storage.retention.ban_history_days,
                        cfg.storage.retention.failed_logs_days,
                        cfg.storage.retention.jail_stats_days,
                        cfg.storage.retention.ddos_events_days,
                    ) {
                        crate::logger::warn!(
                            crate::logger::get(),
                            "清理过期数据失败";
                            "error" => %e
                        );
                    } else {
                        crate::logger::debug!(
                            crate::logger::get(),
                            "过期数据清理完成";
                            "ban_history_days" => cfg.storage.retention.ban_history_days,
                            "failed_logs_days" => cfg.storage.retention.failed_logs_days
                        );
                    }
                } else {
                    // SQLite 不可用时记录警告（降级模式）
                    crate::logger::warn!(
                        crate::logger::get(),
                        "SQLite 全局数据库未初始化，跳过过期数据清理（降级模式）"
                    );
                }
            }

            // DDoS 检测 (按 check_interval 间隔)
            if cfg.ddos.enabled
                && now
                    .duration_since(last_ddos_check)
                    .unwrap_or_default()
                    .as_secs()
                    >= cfg.ddos.check_interval as u64
            {
                last_ddos_check = now;

                let tracker = crate::ddos_detector::get_conn_rate_tracker();
                let events = tracker.detect(&cfg.ddos);

                if !events.is_empty() {
                    crate::logger::info!(
                        crate::logger::get(),
                        "DDoS 检测完成";
                        "events_detected" => events.len()
                    );

                    for event in &events {
                        if event.action_taken == "ban" && event.ip != "global" {
                            if let Err(e) = crate::ban::ban_ip_with_history(
                                &event.ip,
                                "ddos_detector",
                                0,
                                cfg.ddos.auto_ban_duration as u64,
                            ) {
                                crate::logger::warn!(
                                    crate::logger::get(),
                                    "DDoS 自动封禁失败";
                                    "ip" => &event.ip,
                                    "error" => %e
                                );
                            } else {
                                crate::logger::info!(
                                    crate::logger::get(),
                                    "DDoS 自动封禁成功";
                                    "ip" => &event.ip,
                                    "event_type" => &event.event_type,
                                    "rate" => event.rate_per_second,
                                    "threshold" => event.threshold
                                );
                            }
                        }

                        if let Some(db) = crate::sqlite::get_global_db() {
                            let conn = crate::sqlite::get_conn(&db);
                            if let Err(e) = crate::sqlite_writer::insert_ddos_event(
                                &conn,
                                &event.ip,
                                &event.event_type,
                                event.rate_per_second,
                                event.threshold,
                                event.detected_at,
                                &event.action_taken,
                            ) {
                                crate::logger::warn!(
                                    crate::logger::get(),
                                    "记录 DDoS 事件失败";
                                    "ip" => &event.ip,
                                    "error" => %e
                                );
                            }
                        }
                    }
                }

                tracker.cleanup_stale_entries();
            }
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            crate::logger::error!(
                crate::logger::get(),
                "poll 错误，退出主循环";
                "error" => %err
            );
            break;
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
    fn file_state_new() {
        let state = FileState::new();
        assert!(state.path.is_empty());
        assert_eq!(state.offset, 0);
        assert_eq!(state.inode, 0);
        assert!(state.wd.is_none());
        assert!(!state.symlink_detected);
    }
}
