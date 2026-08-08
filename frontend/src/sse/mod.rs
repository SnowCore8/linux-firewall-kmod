//! SSE 状态管理 — 顶层 context，事件驱动，自动重连

use leptos::*;
use std::cell::Cell;
use std::collections::VecDeque;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::api::{BanResponse, JailResponse, RateResponse, StatsResponse, WhitelistEntry};

// ============================================================================
// 全局状态
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ConnectionStatus {
    Connecting,
    Connected,
    Disconnected,
    ConnectionLimit,
}

const RATE_HISTORY_MAX: usize = 300;

/// 速率历史趋势数据（SSE rates 事件直接追加，环形缓冲）
#[derive(Clone, Debug, Default)]
pub struct RateHistory {
    pub labels: VecDeque<String>,
    pub pps: VecDeque<u64>,
    pub bps: VecDeque<u64>,
    pub tracked_ips: VecDeque<u32>,
}

impl RateHistory {
    pub fn push(&mut self, rates: &[RateResponse]) {
        if rates.is_empty() {
            return;
        }
        let total_pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
        let total_bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();
        let now = js_sys::Date::new_0();
        let label = format!("{:02}:{:02}", now.get_minutes(), now.get_seconds());
        self.labels.push_back(label);
        self.pps.push_back(total_pps);
        self.bps.push_back(total_bps);
        self.tracked_ips.push_back(rates.len() as u32);
        while self.labels.len() > RATE_HISTORY_MAX {
            self.labels.pop_front();
            self.pps.pop_front();
            self.bps.pop_front();
            self.tracked_ips.pop_front();
        }
    }

    pub fn labels_vec(&self) -> Vec<String> {
        self.labels.iter().cloned().collect()
    }

    pub fn pps_vec(&self) -> Vec<u64> {
        self.pps.iter().copied().collect()
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
    /// 重连尝试次数（UI 显示用，连接成功时归零）
    pub reconnect_attempt: RwSignal<u32>,
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
            reconnect_attempt: create_rw_signal(0),
        }
    }
}

// ============================================================================
// SSE 连接（含自动重连）
// ============================================================================

struct SseSource {
    _source: web_sys::EventSource,
    _callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>>,
    _error_callbacks: Vec<Closure<dyn Fn(web_sys::Event)>>,
}

impl Drop for SseSource {
    fn drop(&mut self) {
        self._source.close();
    }
}

thread_local! {
    static HANDLE: std::cell::RefCell<Option<SseSource>> = const { std::cell::RefCell::new(None) };
    /// 每个连接周期的重连防护：防止同一连接的多次 onerror 重复调度
    /// 每次 schedule_reconnect 开始前重置为 false（新周期）
    static RECONNECT_SCHEDULED: Cell<bool> = const { Cell::new(false) };
}

/// 建立 SSE 连接。连接断开时自动指数退避重连。
pub fn connect_sse(state: SseState) {
    // 新连接周期：重置防护标志，允许本轮 onerror 调度重连
    RECONNECT_SCHEDULED.with(|s| s.set(false));

    let source = match web_sys::EventSource::new("/api/v1/events") {
        Ok(s) => s,
        Err(_) => {
            state.status.set(ConnectionStatus::Disconnected);
            schedule_reconnect(state);
            return;
        }
    };

    let mut callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>> = Vec::new();
    let mut error_callbacks: Vec<Closure<dyn Fn(web_sys::Event)>> = Vec::new();

    // open — 浏览器标准连接成功事件，重置重连计数器
    let status_open = state.status;
    let attempt_reset = state.reconnect_attempt;
    let on_open = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
        status_open.set(ConnectionStatus::Connected);
        attempt_reset.set(0);
    });
    source.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    error_callbacks.push(on_open);

    // connected — 服务端自定义事件，重置重连计数器
    let status = state.status;
    let reconnect_attempt = state.reconnect_attempt;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |_| {
        status.set(ConnectionStatus::Connected);
        reconnect_attempt.set(0);
    });
    source
        .add_event_listener_with_callback("connected", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // stats
    let stats = state.stats;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            match serde_json::from_str::<StatsResponse>(&json) {
                Ok(data) => stats.set(Some(data)),
                Err(e) => web_sys::console::warn_1(&format!("SSE stats 解析失败: {e}").into()),
            }
        }
    });
    source
        .add_event_listener_with_callback("stats", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // bans
    let bans = state.bans;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            match serde_json::from_str::<Vec<BanResponse>>(&json) {
                Ok(data) => bans.set(Some(data)),
                Err(e) => web_sys::console::warn_1(&format!("SSE bans 解析失败: {e}").into()),
            }
        }
    });
    source
        .add_event_listener_with_callback("bans", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // jails
    let jails = state.jails;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            match serde_json::from_str::<Vec<JailResponse>>(&json) {
                Ok(data) => jails.set(Some(data)),
                Err(e) => web_sys::console::warn_1(&format!("SSE jails 解析失败: {e}").into()),
            }
        }
    });
    source
        .add_event_listener_with_callback("jails", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // rates — 同时更新 rates signal 和 rate_history
    let rates = state.rates;
    let history = state.rate_history;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            match serde_json::from_str::<Vec<RateResponse>>(&json) {
                Ok(data) => {
                    history.update(|h| h.push(&data));
                    rates.set(Some(data));
                }
                Err(e) => web_sys::console::warn_1(&format!("SSE rates 解析失败: {e}").into()),
            }
        }
    });
    source
        .add_event_listener_with_callback("rates", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // whitelist
    let whitelist = state.whitelist;
    let cb = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if let Ok(s) = e.data().dyn_into::<js_sys::JsString>() {
            let json: String = s.into();
            match serde_json::from_str::<Vec<WhitelistEntry>>(&json) {
                Ok(data) => whitelist.set(Some(data)),
                Err(e) => web_sys::console::warn_1(&format!("SSE whitelist 解析失败: {e}").into()),
            }
        }
    });
    source
        .add_event_listener_with_callback("whitelist", cb.as_ref().unchecked_ref())
        .unwrap();
    callbacks.push(cb);

    // onerror — 连接异常时触发重连
    // RECONNECT_SCHEDULED 防重入：同一连接周期内仅调度一次重连
    // 新连接周期开始时 RECONNECT_SCHEDULED 重置为 false
    let status_err = state.status;
    let state_reconnect = state.clone();
    let on_error = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
        status_err.set(ConnectionStatus::Disconnected);
        let can_schedule = RECONNECT_SCHEDULED.with(|s| {
            if s.get() {
                return false;
            }
            s.set(true);
            true
        });
        if can_schedule {
            schedule_reconnect(state_reconnect.clone());
        }
    });
    source.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    error_callbacks.push(on_error);

    HANDLE.with(|h| {
        *h.borrow_mut() = Some(SseSource {
            _source: source,
            _callbacks: callbacks,
            _error_callbacks: error_callbacks,
        });
    });
}

/// 指数退避重连：delay = min(2^attempt, 30) 秒
/// 重连 3 次后检查 SSE 连接限制状态
fn schedule_reconnect(state: SseState) {
    let attempt = state.reconnect_attempt.get_untracked();
    // 先限制指数，避免 attempt>=64 时移位溢出 panic
    let delay_secs = (1_u64 << attempt.min(5)).min(30);
    state.reconnect_attempt.set(attempt.saturating_add(1));

    spawn_local(async move {
        let promise = js_sys::Promise::new(&mut |resolve, _| {
            web_sys::window()
                .unwrap()
                .set_timeout_with_callback_and_timeout_and_arguments_0(
                    &resolve,
                    (delay_secs * 1000) as i32,
                )
                .unwrap();
        });
        let _ = wasm_bindgen_futures::JsFuture::from(promise).await;

        // 重连 3 次后检查是否达到连接上限
        if attempt >= 2 {
            if let Ok(info) = crate::api::get_sse_status().await {
                if info.limit_reached {
                    state.status.set(ConnectionStatus::ConnectionLimit);
                    // 连接上限时不继续重连，等待现有连接释放
                    return;
                }
            }
        }

        // connect_sse 内部会重置 RECONNECT_SCHEDULED，允许新周期的 onerror 调度
        connect_sse(state);
    });
}
