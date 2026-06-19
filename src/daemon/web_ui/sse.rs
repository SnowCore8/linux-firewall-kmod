//! SSE（Server-Sent Events）事件推送实现
//!
//! 每次连接收集一轮完整数据后发送，然后关闭连接。
//! 客户端 EventSource 会自动重连，实现"准实时"更新。
//!
//! 这种设计避免了 tiny_http BufWriter 不 flush 的问题：
//! tiny_http 的 respond() 内部用 BufWriter 包装 socket，
//! flush() 仅在 io::copy 返回后调用。对于永不 EOF 的流式 Reader，
//! io::copy 永不返回，导致 HTTP 头和 SSE 数据永远卡在缓冲区中。

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use tiny_http::{Header, Request, Response, StatusCode};

use super::api;
use crate::http_exporter::get_global_jails;

/// SSE 连接数限制（防止资源耗尽攻击）
const MAX_SSE_CONNECTIONS: usize = 10;

/// 全局 SSE 连接计数器
static SSE_CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// 处理 SSE 连接请求
///
/// 收集一轮完整数据后发送响应，然后关闭连接。
/// 客户端 EventSource API 会自动重连。
///
/// # 安全限制
///
/// 全局最多允许 MAX_SSE_CONNECTIONS 个并发连接。超过限制时返回 503。
pub fn handle_sse_connection(request: Request) {
    let current_count = SSE_CONNECTION_COUNT.load(Ordering::Relaxed);
    if current_count >= MAX_SSE_CONNECTIONS {
        crate::logger::warn!(
            crate::logger::get(),
            "SSE 连接数达到上限，拒绝新连接";
            "current" => current_count,
            "max" => MAX_SSE_CONNECTIONS
        );
        let response = Response::new(
            StatusCode(503),
            vec![
                Header::from_bytes("Content-Type", "text/plain").expect("静态 ASCII 头"),
                Header::from_bytes("Retry-After", "60").expect("静态 ASCII 头"),
            ],
            "SSE connection limit reached. Please retry later.".as_bytes(),
            None,
            None,
        );
        let _ = request.respond(response);
        return;
    }

    SSE_CONNECTION_COUNT.fetch_add(1, Ordering::Relaxed);

    struct ConnectionGuard;
    impl Drop for ConnectionGuard {
        fn drop(&mut self) {
            SSE_CONNECTION_COUNT.fetch_sub(1, Ordering::Relaxed);
        }
    }
    let _guard = ConnectionGuard;

    let push_interval = crate::http_exporter::get_global_webui_config()
        .map(|c| c.sse_push_interval as u64)
        .unwrap_or(1);

    // 收集一轮完整数据
    let mut sse_data = Vec::with_capacity(4096);

    // 统计数据
    let stats = api::get_stats();
    if let Ok(stats_json) = serde_json::to_string(&stats) {
        sse_data.extend_from_slice(format!("event: stats\ndata: {}\n\n", stats_json).as_bytes());
    }

    // 封禁列表
    let bans = api::get_active_bans();
    if let Ok(bans_json) = serde_json::to_string(&bans) {
        sse_data.extend_from_slice(format!("event: bans\ndata: {}\n\n", bans_json).as_bytes());
    }

    // Jail 列表
    let jail_infos = get_global_jails();
    if !jail_infos.is_empty() {
        let jails = api::get_jails(&jail_infos);
        if let Ok(jails_json) = serde_json::to_string(&jails) {
            sse_data
                .extend_from_slice(format!("event: jails\ndata: {}\n\n", jails_json).as_bytes());
        }
    }

    // DDoS 速率数据
    let rates = api::get_ddos_rates();
    if let Ok(rates_json) = serde_json::to_string(&rates) {
        sse_data.extend_from_slice(format!("event: rates\ndata: {}\n\n", rates_json).as_bytes());
    }

    // 等待配置间隔后发送
    thread::sleep(Duration::from_secs(push_interval));

    let response = Response::new(
        StatusCode(200),
        vec![
            Header::from_bytes("Content-Type", "text/event-stream").expect("静态 ASCII 头"),
            Header::from_bytes("Cache-Control", "no-cache").expect("静态 ASCII 头"),
            Header::from_bytes("X-Accel-Buffering", "no").expect("静态 ASCII 头"),
        ],
        sse_data.as_slice(),
        Some(sse_data.len()),
        None,
    );

    if let Err(e) = request.respond(response) {
        crate::logger::warn!(
            crate::logger::get(),
            "SSE 响应发送失败";
            "error" => %e
        );
    }
}
