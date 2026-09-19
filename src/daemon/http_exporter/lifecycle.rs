//! HTTP 服务启动/停止 + tokio runtime 管理

use std::sync::atomic::Ordering;
use std::thread;

use super::handler::build_router;
use super::{EXPORTER_PORT, EXPORTER_RUNNING};
use crate::types::Config;

// ============================================================================
// 启动/停止
// ============================================================================

/// 启动 HTTP 服务线程。
///
/// 在独立线程中创建 `tokio::runtime::Runtime`（`current_thread` 模式），
/// 构建 axum Router 并启动服务。不影响主循环的同步模型。
///
/// # Arguments
/// - `port`: 监听端口 (`cfg.metrics_port`)
/// - `cfg`: 全局配置 (取 `metrics_*` 字段)
///
/// # Returns
/// 子线程 `JoinHandle<()>`，`main()` 在 cleanup 后 join
#[must_use]
pub fn start_http_exporter(port: u16, cfg: &Config) -> thread::JoinHandle<()> {
    let metrics_user = cfg.metrics_username.clone().unwrap_or_default();
    let metrics_pass = cfg.metrics_password.clone().unwrap_or_default();
    let bind_address = if cfg.metrics_bind_address.is_empty() {
        "127.0.0.1".to_string()
    } else {
        cfg.metrics_bind_address.clone()
    };

    thread::spawn(move || {
        let is_loopback = matches!(bind_address.as_str(), "127.0.0.1" | "::1" | "localhost");
        let user_empty = metrics_user.is_empty();
        let pass_empty = metrics_pass.is_empty();

        // 半配置（只给了用户名或只给了密码）→ 拒绝启动。
        // 运行期 check_basic_auth 对半配置按失败处理，这里提前到启动期硬失败，更早暴露配置错误
        if user_empty != pass_empty {
            eprintln!(
                "[ERROR] metrics_username / metrics_password 必须同时配置（当前只配置了其中一项）"
            );
            crate::logger::error!(
                crate::logger::get(),
                "拒绝启动：HTTP 凭据半配置";
                "address" => &bind_address,
            );
            return;
        }

        // 非回环绑定且完全未配置认证 → 拒绝启动（避免管理 API 对全网开放）
        if !is_loopback && user_empty {
            eprintln!(
                "[ERROR] 非回环地址 ({bind_address}) 绑定 HTTP 服务必须配置 metrics_username/metrics_password"
            );
            crate::logger::error!(
                crate::logger::get(),
                "拒绝启动无认证的非回环 HTTP 服务";
                "address" => &bind_address,
            );
            return;
        }

        // 创建多线程 runtime，支持更好的并发性能
        // worker_threads 默认为 CPU 核心数，适合处理 SSE 长连接 + API 请求
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2) // 固定 2 个 worker，平衡资源消耗和并发能力
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("[ERROR] tokio runtime 创建失败: {e}");
                crate::logger::error!(
                    crate::logger::get(),
                    "tokio runtime 创建失败";
                    "error" => %e,
                );
                return;
            }
        };

        // 构建路由（凭据由运行期存储提供，见 set_http_auth_credentials）
        super::set_http_auth_credentials(&metrics_user, &metrics_pass);
        let app = build_router();

        // 绑定并启动服务
        let addr = format!("{bind_address}:{port}");
        rt.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[ERROR] HTTP 服务绑定 {addr} 失败: {e}");
                    crate::logger::error!(
                        crate::logger::get(),
                        "HTTP 服务绑定失败";
                        "address" => &addr,
                        "error" => %e,
                    );
                    return;
                }
            };

            EXPORTER_RUNNING.store(true, Ordering::Relaxed);
            EXPORTER_PORT.store(port, Ordering::Relaxed);

            crate::logger::info!(
                crate::logger::get(),
                "HTTP 服务启动";
                "address" => &addr,
            );

            // 使用 graceful_shutdown 实现优雅停止
            // 当 EXPORTER_RUNNING 被置 false 时，通过 dummy 连接触发 shutdown
            let shutdown = async {
                loop {
                    if !EXPORTER_RUNNING.load(Ordering::Relaxed) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            };

            if let Err(e) = axum::serve(listener, app)
                .with_graceful_shutdown(shutdown)
                .await
            {
                crate::logger::error!(
                    crate::logger::get(),
                    "HTTP 服务运行错误";
                    "error" => %e,
                );
            }

            EXPORTER_RUNNING.store(false, Ordering::Relaxed);
        });
    })
}

/// 优雅停止 HTTP 服务。
///
/// 置 `EXPORTER_RUNNING=false`，tokio runtime 内的 shutdown 循环检测到后
/// 触发 axum 的 graceful_shutdown，等待活跃连接完成后退出。
pub fn stop_http_exporter() {
    EXPORTER_RUNNING.store(false, Ordering::Relaxed);
}
