//! SSE 客户端 — EventSource 长连接 + Leptos signal 分发

use leptos::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::{BanResponse, JailResponse, RateResponse, StatsResponse, WhitelistEntry};

// ============================================================================
// 全局信号
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Disconnected,
}

thread_local! {
    static SSE_STATUS: RwSignal<ConnectionStatus> = create_rw_signal(ConnectionStatus::Connecting);
    static SSE_STATS: RwSignal<Option<StatsResponse>> = create_rw_signal(None);
    static SSE_BANS: RwSignal<Option<Vec<BanResponse>>> = create_rw_signal(None);
    static SSE_JAILS: RwSignal<Option<Vec<JailResponse>>> = create_rw_signal(None);
    static SSE_RATES: RwSignal<Option<Vec<RateResponse>>> = create_rw_signal(None);
    static SSE_WHITELIST: RwSignal<Option<Vec<WhitelistEntry>>> = create_rw_signal(None);
}

pub fn use_sse_status() -> RwSignal<ConnectionStatus> {
    SSE_STATUS.with(|s| *s)
}

pub fn use_sse_stats() -> RwSignal<Option<StatsResponse>> {
    SSE_STATS.with(|s| *s)
}

pub fn use_sse_bans() -> RwSignal<Option<Vec<BanResponse>>> {
    SSE_BANS.with(|s| *s)
}

pub fn use_sse_jails() -> RwSignal<Option<Vec<JailResponse>>> {
    SSE_JAILS.with(|s| *s)
}

pub fn use_sse_rates() -> RwSignal<Option<Vec<RateResponse>>> {
    SSE_RATES.with(|s| *s)
}

pub fn use_sse_whitelist() -> RwSignal<Option<Vec<WhitelistEntry>>> {
    SSE_WHITELIST.with(|s| *s)
}

// ============================================================================
// 连接管理
// ============================================================================

struct SseHandles {
    source: web_sys::EventSource,
    _callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>>,
}

impl Drop for SseHandles {
    fn drop(&mut self) {
        let _ = self.source.close();
    }
}

thread_local! {
    static SSE_HANDLES: std::cell::RefCell<Option<SseHandles>> = std::cell::RefCell::new(None);
}

/// 建立 SSE 连接，监听 stats/bans/jails/rates 事件并更新全局 signal
///
/// 如果已存在连接则先关闭旧连接，避免重复创建
pub fn connect_sse() {
    // 检查是否已存在连接，避免重复创建
    let existing = SSE_HANDLES.with(|handles| handles.borrow().is_some());
    if existing {
        return;
    }

    let source = web_sys::EventSource::new("/api/v1/events").expect("EventSource::new failed");

    let mut callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>> = Vec::new();

    // connected 事件
    let on_connected =
        Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |_e: web_sys::MessageEvent| {
            SSE_STATUS.with(|s| s.set(ConnectionStatus::Connected));
        });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "connected",
            &on_connected.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_connected);

    // stats 事件
    let on_stats =
        Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
            if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
                let s: String = data.into();
                if let Ok(stats) = serde_json::from_str::<StatsResponse>(&s) {
                    SSE_STATS.with(|sig| sig.set(Some(stats)));
                }
            }
        });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "stats",
            &on_stats.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_stats);

    // bans 事件
    let on_bans = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
            let s: String = data.into();
            if let Ok(bans) = serde_json::from_str::<Vec<BanResponse>>(&s) {
                SSE_BANS.with(|sig| sig.set(Some(bans)));
            }
        }
    });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "bans",
            &on_bans.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_bans);

    // jails 事件
    let on_jails =
        Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
            if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
                let s: String = data.into();
                if let Ok(jails) = serde_json::from_str::<Vec<JailResponse>>(&s) {
                    SSE_JAILS.with(|sig| sig.set(Some(jails)));
                }
            }
        });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "jails",
            &on_jails.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_jails);

    // rates 事件
    let on_rates =
        Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
            if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
                let s: String = data.into();
                if let Ok(rates) = serde_json::from_str::<Vec<RateResponse>>(&s) {
                    SSE_RATES.with(|sig| sig.set(Some(rates)));
                }
            }
        });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "rates",
            &on_rates.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_rates);

    // whitelist 事件
    let on_whitelist =
        Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
            if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
                let s: String = data.into();
                if let Ok(list) = serde_json::from_str::<Vec<WhitelistEntry>>(&s) {
                    SSE_WHITELIST.with(|sig| sig.set(Some(list)));
                }
            }
        });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "whitelist",
            &on_whitelist.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();
    callbacks.push(on_whitelist);

    // onerror — 标记断开
    let on_error = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
        SSE_STATUS.with(|s| s.set(ConnectionStatus::Disconnected));
    });
    source.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    // onerror 不用 addEventListener，直接 set_onerror，但需要保持 closure 存活
    // 这里我们把它也存进 callbacks（类型不同，需要单独处理）
    // 简单做法：leak 这个 closure（它生命周期等于页面）
    on_error.forget();

    SSE_HANDLES.with(|handles| {
        *handles.borrow_mut() = Some(SseHandles {
            source,
            _callbacks: callbacks,
        });
    });
}
