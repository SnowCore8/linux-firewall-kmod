//! Web UI 模块 - 提供现代化的监控大盘界面
//!
//! # 功能
//! - 静态资源服务（HTML/CSS/JS 嵌入二进制）
//! - JSON API 端点（统计数据、封禁列表、Jail 配置）
//! - SSE 实时推送（Server-Sent Events）
//! - 与现有 HTTP 导出器集成

use rust_embed::RustEmbed;

pub mod analysis;
pub mod api;
pub mod ban_ops;
pub mod ddos_stats;
pub mod log_viewer;
pub mod packet_analysis;
pub mod recommendations;
pub mod sse;
pub mod stats;

/// 嵌入的静态资源
#[derive(RustEmbed)]
#[folder = "src/daemon/web_ui/static/"]
pub struct StaticAssets;

/// 获取静态资源
pub fn get_static_asset(path: &str) -> Option<(Vec<u8>, &'static str)> {
    let path = path.trim_start_matches('/');

    StaticAssets::get(path).map(|file| {
        let mime_type = match path {
            p if p.ends_with(".html") => "text/html; charset=utf-8",
            p if p.ends_with(".css") => "text/css; charset=utf-8",
            p if p.ends_with(".js") => "application/javascript; charset=utf-8",
            p if p.ends_with(".wasm") => "application/wasm",
            p if p.ends_with(".json") => "application/json; charset=utf-8",
            p if p.ends_with(".png") => "image/png",
            p if p.ends_with(".jpg") || p.ends_with(".jpeg") => "image/jpeg",
            p if p.ends_with(".svg") => "image/svg+xml",
            p if p.ends_with(".ico") => "image/x-icon",
            _ => "application/octet-stream",
        };

        (file.data.into_owned(), mime_type)
    })
}

/// 生成 Dashboard HTML 页面
pub fn render_dashboard() -> String {
    match StaticAssets::get("index.html") {
        Some(file) => String::from_utf8_lossy(&file.data).into_owned(),
        None => "<!DOCTYPE html><html><body><h1>Dashboard not found</h1></body></html>".to_string(),
    }
}
