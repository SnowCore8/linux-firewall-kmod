//! SSE（Server-Sent Events）长连接推送实现
//!
//! 使用 axum 原生 SSE 支持，保持连接不间断推送。
//! 按 `sse_push_interval` 配置间隔循环发送数据。
//!
//! 客户端 EventSource 建立一次连接后持续接收，
//! 仅在客户端主动断开、网络中断或服务端停止时关闭。

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use tokio_stream::Stream;

use super::api;
use crate::http_exporter::get_global_jails;

/// SSE 连接数限制（防止资源耗尽攻击）
const MAX_SSE_CONNECTIONS: usize = 10;

/// 获取当前 SSE 连接数和上限（供前端诊断使用）
pub fn get_sse_connection_info() -> (usize, usize) {
    (
        SSE_CONNECTION_COUNT.load(Ordering::Relaxed),
        MAX_SSE_CONNECTIONS,
    )
}

/// 全局 SSE 连接计数器
static SSE_CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// SSE 连接守卫——Drop 时自动减少连接计数
struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        SSE_CONNECTION_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 处理 SSE 连接请求，返回长连接流。
///
/// 连接建立后按配置间隔循环推送完整数据（stats/bans/jails/rates），
/// 永不主动关闭连接。
///
/// # 安全限制
///
/// 全局最多允许 MAX_SSE_CONNECTIONS 个并发连接。超过限制时返回 503。
pub async fn handle_sse() -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, StatusCode>
{
    // 连接数限制检查（原子 compare_exchange 消除 TOCTOU 竞态）
    loop {
        let current = SSE_CONNECTION_COUNT.load(Ordering::Relaxed);
        if current >= MAX_SSE_CONNECTIONS {
            crate::logger::warn!(
                crate::logger::get(),
                "SSE 连接数达到上限，拒绝新连接";
                "current" => current,
                "max" => MAX_SSE_CONNECTIONS
            );
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
        // compare_exchange: 仅当值未变时递增，失败则重试
        if SSE_CONNECTION_COUNT
            .compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            break;
        }
    }
    // guard 不在这里创建——它需要活在 stream 内部，随 stream 结束而 drop

    let stream = async_stream::stream! {
        // guard 在 stream 内部创建，stream 结束（连接断开）时自动 drop
        let _guard = ConnectionGuard;

        // 发送连接确认事件
        yield Ok(Event::default().event("connected").data("SSE 连接已建立"));

        loop {
            // 统计数据
            let stats = api::get_stats();
            if let Ok(stats_json) = serde_json::to_string(&stats) {
                yield Ok(Event::default().event("stats").data(stats_json));
            }

            // 封禁列表
            let bans = api::get_active_bans();
            if let Ok(bans_json) = serde_json::to_string(&bans) {
                yield Ok(Event::default().event("bans").data(bans_json));
            }

            // Jail 列表
            let jail_infos = get_global_jails();
            if !jail_infos.is_empty() {
                let jails = api::get_jails(&jail_infos);
                if let Ok(jails_json) = serde_json::to_string(&jails) {
                    yield Ok(Event::default().event("jails").data(jails_json));
                }
            }

            // 白名单列表
            let whitelist = api::get_whitelist();
            if let Ok(whitelist_json) = serde_json::to_string(&whitelist) {
                yield Ok(Event::default().event("whitelist").data(whitelist_json));
            }

            // DDoS 速率数据
            let rates = api::get_ddos_rates();
            if let Ok(rates_json) = serde_json::to_string(&rates) {
                yield Ok(Event::default().event("rates").data(rates_json));
            }

            // 按配置间隔等待后推送下一轮
            // 每轮重新读取推送间隔，确保配置变更实时生效
            let interval_secs = crate::http_exporter::get_global_webui_config()
                .map(|c| c.sse_push_interval)
                .unwrap_or(1)
                .max(1) as u64;

            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    };

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    ))
}
