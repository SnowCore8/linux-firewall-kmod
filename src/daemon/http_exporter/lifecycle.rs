//! 导出器启动/停止 + 运行状态管理

use std::net::TcpListener;
use std::sync::atomic::Ordering;
use std::thread;

use tiny_http::Server;

use super::handler::handle_request_with_auth;
use super::{EXPORTER_PORT, EXPORTER_RUNNING};
use crate::types::Config;

// ============================================================================
// 启动/停止
// ============================================================================

/// 启动 Prometheus 导出器线程 (后台)。
///
/// 在新线程里 `bind` + 循环处理 `incoming_requests`,直到 `EXPORTER_RUNNING`
/// 被 `stop_http_exporter` 置 false。线程 `JoinHandle` 返回给 `main()` 用于
/// 优雅 join。
///
/// # Arguments
/// - `port`: 监听端口 (`cfg.metrics_port`)
/// - `cfg`: 全局配置 (取 `metrics_*` 字段)
///
/// # Returns
/// 子线程 `JoinHandle<()>`,`main()` 在 cleanup 后 join
#[must_use]
pub fn start_http_exporter(port: u16, cfg: &Config) -> thread::JoinHandle<()> {
    // 全局 Jail 信息和 Web UI 配置已在 main.rs 中设置
    let metrics_user = cfg.metrics_username.clone();
    let metrics_pass = cfg.metrics_password.clone();
    let bind_address = if cfg.metrics_bind_address.is_empty() {
        "127.0.0.1".to_string()
    } else {
        cfg.metrics_bind_address.clone()
    };

    thread::spawn(move || {
        let addr = format!("{bind_address}:{port}");
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[ERROR] HTTP 导出器绑定 {addr} 失败: {e}");
                crate::logger::error!(
                    crate::logger::get(),
                    "HTTP 导出器绑定失败";
                    "address" => &addr,
                    "error" => %e,
                );
                return;
            }
        };

        let server = match Server::from_listener(listener, None) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ERROR] HTTP 导出器启动失败: {e}");
                crate::logger::error!(
                    crate::logger::get(),
                    "HTTP 导出器启动失败";
                    "error" => %e,
                );
                return;
            }
        };

        EXPORTER_RUNNING.store(true, Ordering::Relaxed);
        EXPORTER_PORT.store(port, Ordering::Relaxed);

        loop {
            if !EXPORTER_RUNNING.load(Ordering::Relaxed) {
                break;
            }
            // 使用 try_recv 非阻塞获取请求，避免 SSE 长连接阻塞整个服务器
            match server.try_recv() {
                Ok(Some(request)) => {
                    // 为每个请求创建独立线程处理，避免 SSE 阻塞其他请求
                    let user = metrics_user.clone();
                    let pass = metrics_pass.clone();
                    thread::spawn(move || {
                        handle_request_with_auth(request, user.as_ref(), pass.as_ref());
                    });
                }
                Ok(None) => {
                    // 没有请求，短暂休眠避免 CPU 空转
                    thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(_) => {
                    // 服务器关闭或出错
                    break;
                }
            }
        }

        EXPORTER_RUNNING.store(false, Ordering::Relaxed);
    })
}

/// 优雅停止导出器:置 `EXPORTER_RUNNING=false` + 发 dummy TCP 连接唤醒
/// `incoming_requests` 阻塞。
pub fn stop_http_exporter() {
    EXPORTER_RUNNING.store(false, Ordering::Relaxed);
    // 发个 dummy 连接唤醒阻塞的 incoming_requests()
    let port = EXPORTER_PORT.load(Ordering::Relaxed);
    if port > 0 {
        use std::net::TcpStream;
        use std::time::Duration;
        let addr = format!("127.0.0.1:{port}");
        if let Ok(parsed) = addr.parse() {
            let _ = TcpStream::connect_timeout(&parsed, Duration::from_millis(10));
        }
    }
}
