//! SSE 状态管理 — 顶层 context，事件驱动

use leptos::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::{BanResponse, JailResponse, RateResponse, StatsResponse, WhitelistEntry};

// ============================================================================
// 全局状态
// ============================================================================

#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Disconnected,
}

/// 速率历史趋势数据（SSE rates 事件直接追加）
#[derive(Clone, Debug, Default)]
pub struct RateHistory {
    pub labels: Vec<String>,
    pub pps: Vec<u64>,
    pub bps: Vec<u64>,
    pub tracked_ips: Vec<u32>,
}

impl RateHistory {
    pub fn push(&mut self, rates: &[RateResponse]) {
        if rates.is_empty() { return; }
        let total_pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
        let total_bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();
        let now = js_sys::Date::new_0();
        let label = format!("{:02}:{:02}", now.get_minutes(), now.get_seconds());
        const MAX: usize = 300;
        self.labels.push(label);
        self.pps.push(total_pps);
        self.bps.push(total_bps);
        self.tracked_ips.push(rates.len() as u32);
        if self.labels.len() > MAX {
            self.labels.remove(0);
            self.pps.remove(0);
            self.bps.remove(0);
            self.tracked_ips.remove(0);
        }
    }
}

#[derive(Clone)]
pub struct SseState {
    pub status: RwSignal<ConnectionStatus>,
    pub stats: RwSignal<Option<StatsResponse>>,
    pub bans: RwSignal<Option<Vec<BanResponse>>>,
    pub jails: RwSignal<Option<Vec<JailResponse>>>,
    pub rates: RwSignal<Option<Vec<RateResponse>>>,
    pub whitelist: RwSignal<Option<Vec<WhitelistEntry>>>,
    /// 速率历史趋势（SSE rates 事件直接追加，组件只读）
    pub rate_history: RwSignal<RateHistory>,
}

impl SseState {
    pub fn create() -> Self {
        Self {
            status: create_rw_signal(ConnectionStatus::Connecting),
            stats: create_rw_signal(None),
            bans: create_rw_signal(None),
            jails: create_rw_signal(None),
            rates: create_rw_signal(None),
            whitelist: create_rw_signal(None),
            rate_history: create_rw_signal(RateHistory::default()),
        }
    }
}

// ============================================================================
// SSE 连接
// ============================================================================

struct SseSource {
    _source: web_sys::EventSource,
    _callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>>,
}

impl Drop for SseSource {
    fn drop(&mut self) {
        let _ = self._source.close();
    }
}

pub fn connect_sse(state: SseState) {
    let source = match web_sys::EventSource::new("/api/v1/events") {
        Ok(s) => s,
        Err(_) => { state.status.set(ConnectionStatus::Disconnected); return; }
    };

    let mut callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>> = Vec::new();

    // connected
    let status = state.status;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |_| {
        status.set(ConnectionStatus::Connected);
    });
    source.add_event_listener_with_callback("connected", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // stats
    let stats = state.stats;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            if let Ok(data) = serde_json::from_str::<StatsResponse>(&json) {
                stats.set(Some(data));
            }
        }
    });
    source.add_event_listener_with_callback("stats", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // bans
    let bans = state.bans;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            if let Ok(data) = serde_json::from_str::<Vec<BanResponse>>(&json) {
                bans.set(Some(data));
            }
        }
    });
    source.add_event_listener_with_callback("bans", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // jails
    let jails = state.jails;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            if let Ok(data) = serde_json::from_str::<Vec<JailResponse>>(&json) {
                jails.set(Some(data));
            }
        }
    });
    source.add_event_listener_with_callback("jails", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // rates — 同时更新 rates signal 和 rate_history
    let rates = state.rates;
    let history = state.rate_history;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            if let Ok(data) = serde_json::from_str::<Vec<RateResponse>>(&json) {
                // 追加趋势数据
                history.update(|h| h.push(&data));
                // 更新当前 rates
                rates.set(Some(data));
            }
        }
    });
    source.add_event_listener_with_callback("rates", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // whitelist
    let whitelist = state.whitelist;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            if let Ok(data) = serde_json::from_str::<Vec<WhitelistEntry>>(&json) {
                whitelist.set(Some(data));
            }
        }
    });
    source.add_event_listener_with_callback("whitelist", cb.as_ref().unchecked_ref()).unwrap();
    callbacks.push(cb);

    // onerror
    let status_err = state.status;
    let on_error = Closure::<dyn Fn(web_sys::Event)>::new(move |_| {
        status_err.set(ConnectionStatus::Disconnected);
    });
    source.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    on_error.forget();

    use std::cell::RefCell;
    thread_local! {
        static HANDLE: RefCell<Option<SseSource>> = RefCell::new(None);
    }
    HANDLE.with(|h| {
        *h.borrow_mut() = Some(SseSource { _source: source, _callbacks: callbacks });
    });
}
