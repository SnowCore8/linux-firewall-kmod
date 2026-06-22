//! 性能监控 - 前端错误捕获

use wasm_bindgen::prelude::*;
use web_sys::window;

// ============================================================================
// 前端错误捕获
// ============================================================================

/// 设置全局错误捕获
pub fn setup_error_handler() {
    // 捕获未处理的 Promise rejection
    if let Some(w) = window() {
        let handler = Closure::wrap(Box::new(move |event: web_sys::PromiseRejectionEvent| {
            let reason = event.reason();
            let msg = if reason.is_string() {
                reason.as_string().unwrap_or_default()
            } else {
                format!("{:?}", reason)
            };
            web_sys::console::error_1(&JsValue::from_str(&format!("[Promise Error] {}", msg)));
        }) as Box<dyn FnMut(web_sys::PromiseRejectionEvent)>);

        let _ = w.add_event_listener_with_callback(
            "unhandledrejection",
            handler.as_ref().unchecked_ref(),
        );
        handler.forget();
    }
}
