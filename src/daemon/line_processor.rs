//! 日志行处理模块
//!
//! # 核心职责
//!
//! - 单行处理：长度校验 + IP 提取 + 失败计数
//! - 多行缓冲分割：按 `\n` 分割字节缓冲
//! - 部分行缓冲管理：追加/flush 不完整行
//!
//! # 关键不变量
//!
//! - 单行硬上限 8KB，超长行跳过（避免 OOM）
//! - `partial_line_buffer` 容量 8KB

use std::sync::atomic::Ordering;

use crate::failed_tracker;
use crate::log_parser;
use crate::types::{Jail, DAEMON_STATS};

// ============================================================================
// 单行处理
// ============================================================================

/// 处理单行日志:长度校验 + 解析 + 失败计数。空行直接跳过;>8KB 跳过并
/// 处理单行日志：长度校验 + 解析 + 失败计数。空行直接跳过；>8KB 跳过并
/// 累加 `lines_skipped`。
///
/// # Arguments
/// - `jail`: 关联 jail (正则集)
/// - `line`: 不含 `\n` 的单行
/// - `log_path`: 源文件路径 (日志用)
/// - `max_retries` / `findtime`: 失败阈值参数 (透传给 `failed_tracker`)
pub fn process_single_line(
    jail: &Jail,
    line: &str,
    _log_path: &str,
    max_retries: u32,
    findtime: u32,
) {
    if line.is_empty() {
        return;
    }

    let len = line.len();
    if len >= 8192 {
        crate::logger::debug!(
            crate::logger::get(),
            "跳过超长日志行";
            "length" => len,
            "limit" => 8192
        );
        DAEMON_STATS.lines_skipped.fetch_add(1, Ordering::Relaxed);
        return;
    }

    DAEMON_STATS.lines_parsed.fetch_add(1, Ordering::Relaxed);

    if let Some(ip) = log_parser::extract_and_validate_ip(jail, line) {
        // DDoS 检测：记录连接
        crate::ddos_detector::get_conn_rate_tracker().record_connection(&ip);

        failed_tracker::handle_failed_attempt_for_jail(jail, &ip, max_retries, findtime);
    }
}

// ============================================================================
// 多行缓冲处理
// ============================================================================

/// 按 `\n` 分割 `data` 缓冲,逐行调 [`process_single_line`],返回 `consumed`
/// 按 `\n` 分割 `data` 缓冲，逐行调 [`process_single_line`]，返回 `consumed`
/// (已处理字节数) 给调用方用于 partial 行缓冲。
///
/// # Arguments
/// - `jail`: 关联 jail
/// - `data`: 字节缓冲
/// - `log_path`: 源文件路径
/// - `consumed`: 出参,已消费的字节数 (= 完整行总长)
/// - `consumed`: 出参，已消费的字节数 (= 完整行总长)
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
                // 超长行跳过
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

// ============================================================================
// 部分行缓冲管理
// ============================================================================

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
        jail.partial_line_buffer.write().clear();
        return;
    }

    let mut buf = jail.partial_line_buffer.write();
    let current_len = buf.len();

    if current_len + data.len() >= 8192 {
        // 缓冲区将溢出: 先处理累积数据, 再写入新片段
        // 缓冲区将溢出：先处理累积数据，再写入新片段
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
/// 文件关闭 / truncate 之前调用，避免丢失最后一个不完整行。
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

    let _old_len = buf.len();
    let temp = buf.clone();
    buf.clear();
    drop(buf);

    if let Ok(line) = std::str::from_utf8(&temp) {
        process_single_line(jail, line, log_path, max_retries, findtime);
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
    fn store_partial_line_respects_limit() {
        let jail = Jail::new("test".to_string());
        let data = vec![b'a'; 9000];
        store_partial_line(&jail, &data, "/var/log/test.log", 3, 600);
        assert!(jail.partial_line_buffer.read().is_empty());
    }
}
