//! 日志查看器：SSE 实时推送 + REST 历史分页查询
//!
//! # 安全约束
//!
//! - 仅读取 `cfg.log_file` 指定的日志文件（默认 `/var/log/firewall.log`）
//! - 禁止路径遍历（只读固定路径）
//! - 需要 Basic Auth 认证（走现有 auth middleware）
//! - 连接位取自**进程级共享**的 [`crate::api::sse::SseStatus`]，与 `/api/v1/events`
//!   同一实例但**各自独立计数与上限**：日志流 5、管理流 10。一条流满不影响另一条，
//!   `/api/v1/stats/sse-status` 因此能同时报告两者（缺陷 `HTTP_SSE_STATUS_INCOMPLETE`
//!   的修法；此前两条流各持私有计数器，诊断端点只看得见管理流）。

use std::convert::Infallible;
use std::io::{BufRead, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tokio_stream::Stream;

use crate::api::sse::{SseStatus, KEEPALIVE_SECS, LIMIT_REACHED_STATUS};

// ============================================================================
// 全局日志文件路径
// ============================================================================

/// 全局日志文件路径（启动时设置）
static GLOBAL_LOG_FILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// 设置全局日志文件路径（启动时调用）
///
/// # 返回
/// - `Ok(())` — 设置成功
/// - `Err(&str)` — 已被初始化（重复调用）
pub fn set_log_file(path: String) -> Result<(), &'static str> {
    GLOBAL_LOG_FILE
        .set(PathBuf::from(path))
        .map_err(|_| "日志文件路径已设置，重复初始化")
}

/// 获取日志文件路径
fn get_log_file() -> Option<&'static PathBuf> {
    GLOBAL_LOG_FILE.get()
}

// ============================================================================
// SSE 实时日志流
// ============================================================================

/// 处理日志 SSE 连接请求（tail -f 语义）。
///
/// 连接位取自 `shared`（进程级共享的 [`SseStatus`]，与 `/api/v1/events` 同一实例）。
/// 上限独立于管理流：日志流满只拒绝日志连接，`/api/v1/events` 照常。
pub async fn handle_log_stream(shared: Arc<SseStatus>) -> Response {
    // 连接位守卫随流存活：提前返回的两条错误分支也会在此析构时归还。
    let Some(guard) = shared.acquire_logs() else {
        crate::logger::warn!(
            crate::logger::get(),
            "日志流连接数达到上限，拒绝新连接";
        );
        return (LIMIT_REACHED_STATUS, "日志流连接数已达上限\n").into_response();
    };

    let Some(log_path) = get_log_file().cloned() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "日志文件路径未设置\n").into_response();
    };

    // 显式标注 Item：`stream!` 生成器靠第一条 `yield` 的 `Ok` 反推错误类型，
    // 而这里的两条提前返回分支（打开/定位失败）在类型推断之前，故必须写明。
    let stream: std::pin::Pin<Box<dyn Stream<Item = Result<Event, Infallible>> + Send>> =
        Box::pin(async_stream::stream! {
            // guard 在 stream 内部创建，stream 结束（连接断开）时自动 drop
            let _guard = guard;

            // 发送连接确认
            yield Ok(Event::default().event("connected").data("日志流已连接"));

            // 打开日志文件并定位到末尾（tail -f 语义）
            let file = {
                let mut f = match std::fs::File::open(&log_path) {
                    Ok(f) => f,
                    Err(_) => {
                        yield Ok(Event::default().event("error").data("无法打开日志文件"));
                        return;
                    }
                };
                if f.seek(SeekFrom::End(0)).is_err() {
                    yield Ok(Event::default().event("error").data("无法定位日志文件末尾"));
                    return;
                }
                f
            };

            let mut reader = std::io::BufReader::new(file);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        // 没有新行，等待后重试
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        // 重新打开文件以检测轮转
                        if let Ok(f) = std::fs::File::open(&log_path) {
                            if let Ok(meta) = f.metadata() {
                                if let Ok(old_meta) = reader.get_ref().metadata() {
                                    if meta.len() < old_meta.len() {
                                        // 文件被截断（logrotate copytruncate）
                                        if reader.seek(SeekFrom::Start(0)).is_err() {
                                            // seek 失败后放弃当前 reader，重新打开文件
                                            if let Ok(new_f) = std::fs::File::open(&log_path) {
                                                reader = std::io::BufReader::new(new_f);
                                            }
                                        }
                                        continue;
                                    }
                                }
                            }
                            // 文件被替换（logrotate mv + create）
                            if let Ok(new_file) = std::fs::File::open(&log_path) {
                                if let Ok(new_meta) = new_file.metadata() {
                                    if let Ok(old_meta) = reader.get_ref().metadata() {
                                        if new_meta.ino() != old_meta.ino() {
                                            reader = std::io::BufReader::new(new_file);
                                            continue;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {
                        let trimmed = line.trim_end();
                        if !trimmed.is_empty() {
                            yield Ok(Event::default().event("log").data(trimmed));
                        }
                    }
                    Err(_) => {
                        yield Ok(Event::default().event("error").data("读取日志文件失败"));
                        return;
                    }
                }
            }
        });

    Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(std::time::Duration::from_secs(KEEPALIVE_SECS))
                .text("keep-alive"),
        )
        .into_response()
}

// ============================================================================
// REST 历史日志分页查询
// ============================================================================

/// 日志查询参数
#[derive(Deserialize)]
pub struct LogQueryParams {
    /// 页码（从 1 开始，默认 1）
    pub page: Option<u32>,
    /// 每页大小（默认 100，最大 500）
    pub page_size: Option<u32>,
    /// 日志级别过滤（ERROR/WARN/INFO/DEBUG）
    pub level: Option<String>,
    /// 关键词搜索
    pub keyword: Option<String>,
    /// 时间戳过滤（ISO 8601，只返回此时间之后的日志行）
    pub since: Option<String>,
}

/// 日志条目
#[derive(Serialize)]
pub struct LogEntry {
    pub line_number: u64,
    pub content: String,
}

/// 分页响应
#[derive(Serialize)]
pub struct LogPageResponse {
    pub items: Vec<LogEntry>,
    pub total_lines: u64,
    pub page: u32,
    pub page_size: u32,
    pub total_pages: u32,
}

/// 最大扫描行数（防止大文件 OOM，日志文件通常不超过 50K 行）
const MAX_SCAN_LINES: usize = 50_000;

/// 获取历史日志（分页）
pub fn get_log_page(params: &LogQueryParams) -> Result<LogPageResponse, String> {
    let log_path = get_log_file().ok_or_else(|| "日志文件路径未设置".to_string())?;

    let file = std::fs::File::open(log_path).map_err(|e| format!("无法打开日志文件: {e}"))?;

    let reader = std::io::BufReader::new(file);

    let level_filter = params.level.as_deref();
    let keyword_filter = params.keyword.as_deref();
    let keyword_lower = keyword_filter.map(|k| k.to_lowercase());
    let since_filter = params.since.as_deref();

    // 流式扫描：只收集匹配行，上限 MAX_SCAN_LINES 防止大文件 OOM
    let matched_lines: Vec<(u64, String)> = reader
        .lines()
        .take(MAX_SCAN_LINES)
        .enumerate()
        .filter_map(|(i, line)| {
            let line = line.ok()?;
            let line_num = (i + 1) as u64;

            // 时间戳过滤（ISO 8601 可字典序比较）
            if let Some(since) = since_filter {
                // 提取行首时间戳（前 19 字符：2026-07-12T07:17:40）
                let line_ts = line.get(..19).unwrap_or("");
                if line_ts < since {
                    return None;
                }
            }

            // 级别过滤
            if let Some(level) = level_filter {
                let level_upper = level.to_uppercase();
                if !line.contains(&format!("[{level_upper}]"))
                    && !line.contains(&format!(" {level_upper} "))
                {
                    return None;
                }
            }

            // 关键词过滤
            if let Some(ref kw) = keyword_lower {
                if !line.to_lowercase().contains(kw) {
                    return None;
                }
            }

            Some((line_num, line))
        })
        .collect();

    let total_lines = matched_lines.len() as u64;
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params.page_size.unwrap_or(100).clamp(1, 500);
    let total_pages = total_lines.div_ceil(page_size as u64);

    let start = ((page - 1) * page_size) as usize;
    let end = (start + page_size as usize).min(matched_lines.len());

    let items = matched_lines[start..end]
        .iter()
        .map(|(line_num, content)| LogEntry {
            line_number: *line_num,
            content: content.clone(),
        })
        .collect();

    Ok(LogPageResponse {
        items,
        total_lines,
        page,
        page_size,
        total_pages: total_pages as u32,
    })
}
