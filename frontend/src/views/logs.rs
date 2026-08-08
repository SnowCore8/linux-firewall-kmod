//! 系统日志 — 级别分布统计 + SSE 实时流 + 级别过滤 + 关键词搜索

use leptos::*;
use std::cell::{Cell, RefCell};
use std::rc::Rc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::api;
use crate::components::{EmptyState, PageHeader};

const MAX_LOGS: usize = 1000;

#[derive(Clone)]
struct LogEntry {
    line_number: u64,
    time: String,
    level: String,
    message: String,
}

#[component]
pub fn Logs() -> impl IntoView {
    let logs = create_rw_signal(Vec::<LogEntry>::new());
    let loading = create_rw_signal(true);
    let error = create_rw_signal(String::new());
    let streaming = create_rw_signal(true);
    let keyword = create_rw_signal(String::new());
    let active_levels = create_rw_signal(vec![
        "ERROR".to_string(),
        "WARN".to_string(),
        "INFO".to_string(),
    ]);

    // 日志级别统计
    let level_counts = move || {
        let entries = logs.get();
        let mut error = 0_u64;
        let mut warn = 0_u64;
        let mut info = 0_u64;
        let mut debug = 0_u64;
        for e in &entries {
            match e.level.as_str() {
                "ERROR" => error += 1,
                "WARN" => warn += 1,
                "INFO" => info += 1,
                "DEBUG" => debug += 1,
                _ => {}
            }
        }
        (error, warn, info, debug)
    };

    // 加载历史日志（受 clear_logs_at 过滤）
    let logs_resource = create_resource(
        || (),
        |_| async move {
            // 获取配置中的 clear_logs_at 时间戳
            let since = api::get_config()
                .await
                .ok()
                .and_then(|c| c.clear_logs_at)
                .filter(|s| !s.is_empty());
            api::get_logs(1, 100, since.as_deref()).await.ok()
        },
    );

    create_effect(move |_| {
        if let Some(Some(page)) = logs_resource.get() {
            let entries = page
                .items
                .into_iter()
                .map(|item| parse_log_line(item.line_number, &item.content))
                .collect::<Vec<_>>();
            logs.set(entries);
            loading.set(false);
        }
    });

    // SSE 日志流（含自动重连）
    let cancelled = Rc::new(Cell::new(false));
    let reconnect_attempt = Rc::new(Cell::new(0u32));
    let reconnect_guard = Rc::new(Cell::new(false));
    connect_logs_sse(
        logs,
        streaming,
        Rc::clone(&cancelled),
        Rc::clone(&reconnect_attempt),
        Rc::clone(&reconnect_guard),
    );
    on_cleanup({
        let cancelled = Rc::clone(&cancelled);
        move || cancelled.set(true)
    });

    // 过滤后的日志（最新在前）
    let filtered = move || {
        let kw = keyword.get().to_lowercase();
        let levels = active_levels.get();
        let mut result = logs
            .get()
            .into_iter()
            .filter(|l| levels.contains(&l.level))
            .filter(|l| kw.is_empty() || l.message.to_lowercase().contains(&kw))
            .collect::<Vec<_>>();
        result.reverse(); // 最新日志在前
        result
    };

    let toggle_level = move |level: &str| {
        active_levels.update(|v| {
            if let Some(pos) = v.iter().position(|l| l == level) {
                v.remove(pos);
            } else {
                v.push(level.to_string());
            }
        });
    };

    let levels = ["ERROR", "WARN", "INFO", "DEBUG"];

    view! {
        <div class="logs-page">
            <PageHeader title="系统日志" subtitle="级别过滤与实时流"/>
            // 日志级别统计
            <div class="kernel-stats-bar">
                {move || {
                    let (error, warn, info, debug) = level_counts();
                    view! {
                        <>
                            <div class="kernel-stat">
                                <span class="kernel-stat-label text-danger">"ERROR"</span>
                                <span class="kernel-stat-value mono text-danger">{error}</span>
                            </div>
                            <div class="kernel-stat">
                                <span class="kernel-stat-label text-warning">"WARN"</span>
                                <span class="kernel-stat-value mono text-warning">{warn}</span>
                            </div>
                            <div class="kernel-stat">
                                <span class="kernel-stat-label text-cyan">"INFO"</span>
                                <span class="kernel-stat-value mono text-cyan">{info}</span>
                            </div>
                            <div class="kernel-stat">
                                <span class="kernel-stat-label text-muted">"DEBUG"</span>
                                <span class="kernel-stat-value mono">{debug}</span>
                            </div>
                            <div class="kernel-stat">
                                <span class="kernel-stat-label">"TOTAL"</span>
                                <span class="kernel-stat-value mono tabular">{error + warn + info + debug}</span>
                            </div>
                        </>
                    }
                }}
            </div>

            // 工具栏
            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"系统日志"</h2>
                </div>
                <div class="toolbar-right">
                    <div class="level-filters">
                        {levels.iter().map(|level| {
                            let level_str = level.to_string();
                            let lvl_for_class = level_str.clone();
                            let lvl_for_click = level_str.clone();
                            let lvl_for_text = level_str.clone();
                            view! {
                                <button class=move || {
                                    if active_levels.get().contains(&lvl_for_class) {
                                        "btn btn-sm btn-active"
                                    } else {
                                        "btn btn-sm"
                                    }
                                } on:click=move |_| toggle_level(&lvl_for_click)>
                                    {lvl_for_text}
                                </button>
                            }
                        }).collect_view()}
                    </div>
                    <input class="input" placeholder="搜索关键词..."
                        style="width:180px"
                        prop:value=move || keyword.get()
                        on:input=move |e| keyword.set(event_target_value(&e))/>
                    <button class="btn btn-sm" on:click=move |_| streaming.update(|v| *v = !*v)>
                        {move || if streaming.get() { "暂停" } else { "继续" }}
                    </button>
                    <button class="btn btn-sm" on:click=move |_| {
                        let window = web_sys::window().expect("window not available");
                        if window.confirm_with_message("确定要清空所有日志吗？").unwrap_or(false) {
                            // 获取当前时间作为清空时间戳
                            let now = js_sys::Date::new_0();
                            let year = now.get_full_year();
                            let month = format!("{:02}", now.get_month() + 1);
                            let day = format!("{:02}", now.get_date());
                            let hour = format!("{:02}", now.get_hours());
                            let min = format!("{:02}", now.get_minutes());
                            let sec = format!("{:02}", now.get_seconds());
                            let timestamp = format!("{year}-{month}-{day}T{hour}:{min}:{sec}");

                            // 调用配置 API 设置 clear_logs_at
                            let req = api::UpdateConfigRequest {
                                sse_push_interval: None,
                                rate_warning_pps: None,
                                rate_critical_pps: None,
                                rate_warning_syn: None,
                                rate_critical_syn: None,
                                max_syn_per_second: None,
                                max_udp_per_second: None,
                                max_icmp_per_second: None,
                                max_ack_per_second: None,
                                max_rst_per_second: None,
                                max_fin_per_second: None,
                                static_threshold: None,
                                dynamic_threshold: None,
                                ddos_detection: None,
                                max_ban_entries: None,
                                max_whitelist_entries: None,
                                max_rate_entries: None,
                                max_local_ip_cache: None,
                                clear_logs_at: Some(timestamp),
                            };
                            spawn_local(async move {
                                if let Err(e) = api::update_config(req).await {
                                    web_sys::console::error_1(&format!("设置清空时间戳失败：{e}").into());
                                }
                                // 重新加载日志
                                logs_resource.refetch();
                                logs.set(Vec::new());
                            });
                        }
                    }>
                        "清空"
                    </button>
                </div>
            </div>

            <div class="card log-container">
                {move || {
                    if loading.get() {
                        return view! { <EmptyState title="加载日志中..."/> }.into_view();
                    }
                    let entries = filtered();
                    if entries.is_empty() {
                        return view! {
                            {move || {
                                let err = error.get();
                                let title = if err.is_empty() {
                                    "暂无日志".to_string()
                                } else {
                                    err
                                };
                                view! { <EmptyState title=title/> }
                            }}
                        }.into_view();
                    }
                    view! {
                        <div class="log-lines">
                            <For
                                each=move || entries.clone().into_iter()
                                key=|e| e.line_number
                                children=move |log| {
                                    let log_level = log.level.clone();
                                    let log_level_badge = log.level.clone();
                                    let log_level_text = log.level.clone();
                                    let log_time = log.time.clone();
                                    let log_msg = log.message.clone();
                                    let log_num = log.line_number;
                                    view! {
                                        <div class=move || format!("log-line {}", log_level)>
                                            <span class="log-line-num mono">{log_num}</span>
                                            <span class="log-time mono">{log_time}</span>
                                            <span class=move || format!("log-level-badge {}", log_level_badge)>{log_level_text}</span>
                                            <span class="log-message">{log_msg}</span>
                                        </div>
                                    }
                                }
                            />
                        </div>
                    }.into_view()
                }}
            </div>
        </div>
    }
}

// ============================================================================
// 日志 SSE 连接（含自动重连）
// ============================================================================

struct LogsSseSource {
    _source: web_sys::EventSource,
    _callbacks: Vec<Closure<dyn Fn(web_sys::MessageEvent)>>,
    _error_callbacks: Vec<Closure<dyn Fn(web_sys::Event)>>,
}

impl Drop for LogsSseSource {
    fn drop(&mut self) {
        self._source.close();
    }
}

thread_local! {
    static LOGS_HANDLE: RefCell<Option<LogsSseSource>> = const { RefCell::new(None) };
}

fn connect_logs_sse(
    logs: RwSignal<Vec<LogEntry>>,
    streaming: RwSignal<bool>,
    cancelled: Rc<Cell<bool>>,
    reconnect_attempt: Rc<Cell<u32>>,
    reconnect_guard: Rc<Cell<bool>>,
) {
    // 新连接周期：重置防护标志
    reconnect_guard.set(false);

    // 单调递增行号计数器（清空后不回退，防止 For key 碰撞）
    let line_counter = Rc::new(Cell::new(
        logs.get_untracked()
            .iter()
            .map(|e| e.line_number)
            .max()
            .unwrap_or(0),
    ));

    let source = match web_sys::EventSource::new("/api/v1/logs/stream") {
        Ok(s) => s,
        Err(_) => {
            let can_schedule = !reconnect_guard.get() && !cancelled.get();
            if can_schedule {
                reconnect_guard.set(true);
                schedule_logs_reconnect(
                    logs,
                    streaming,
                    cancelled,
                    reconnect_attempt,
                    reconnect_guard,
                );
            }
            return;
        }
    };

    // onopen — 连接成功，重置重连计数器
    let attempt_reset = Rc::clone(&reconnect_attempt);
    let on_open = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
        attempt_reset.set(0);
    });
    source.set_onopen(Some(on_open.as_ref().unchecked_ref()));

    // on_log — 检查 streaming 暂停状态
    let logs_ref = logs;
    let streaming_ref = streaming;
    let counter_ref = Rc::clone(&line_counter);
    let on_log = Closure::<dyn Fn(web_sys::MessageEvent)>::new(move |e: web_sys::MessageEvent| {
        if !streaming_ref.get_untracked() {
            return;
        }
        if let Ok(data) = e.data().dyn_into::<js_sys::JsString>() {
            let line: String = data.into();
            logs_ref.update(|v| {
                let next_line = counter_ref.get() + 1;
                counter_ref.set(next_line);
                let entry = parse_log_line(next_line, &line);
                v.push(entry);
                if v.len() > MAX_LOGS {
                    v.remove(0);
                }
            });
        }
    });
    source
        .add_event_listener_with_callback_and_add_event_listener_options(
            "log",
            on_log.as_ref().unchecked_ref(),
            &{
                let opts = web_sys::AddEventListenerOptions::new();
                opts.set_once(false);
                opts
            },
        )
        .unwrap();

    // onerror — 连接异常时触发重连（reconnect_guard 防重入）
    let logs_reconnect = logs;
    let streaming_reconnect = streaming;
    let cancelled_reconnect = Rc::clone(&cancelled);
    let attempt_counter = Rc::clone(&reconnect_attempt);
    let guard_ref = Rc::clone(&reconnect_guard);
    let on_error = Closure::<dyn Fn(web_sys::Event)>::new(move |_: web_sys::Event| {
        let can_schedule = !guard_ref.get() && !cancelled_reconnect.get();
        if can_schedule {
            guard_ref.set(true);
            schedule_logs_reconnect(
                logs_reconnect,
                streaming_reconnect,
                cancelled_reconnect.clone(),
                attempt_counter.clone(),
                guard_ref.clone(),
            );
        }
    });
    source.set_onerror(Some(on_error.as_ref().unchecked_ref()));

    LOGS_HANDLE.with(|h| {
        *h.borrow_mut() = Some(LogsSseSource {
            _source: source,
            _callbacks: vec![on_log],
            _error_callbacks: vec![on_open, on_error],
        });
    });
}

fn schedule_logs_reconnect(
    logs: RwSignal<Vec<LogEntry>>,
    streaming: RwSignal<bool>,
    cancelled: Rc<Cell<bool>>,
    reconnect_attempt: Rc<Cell<u32>>,
    reconnect_guard: Rc<Cell<bool>>,
) {
    let attempt = reconnect_attempt.get();
    // 先限制指数，避免 attempt>=64 时移位溢出 panic
    let delay_secs = (1_u64 << attempt.min(5)).min(30);
    reconnect_attempt.set(attempt.saturating_add(1));
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
        if cancelled.get() {
            return;
        }
        // connect_logs_sse 内部会重置 reconnect_guard
        connect_logs_sse(
            logs,
            streaming,
            cancelled,
            reconnect_attempt,
            reconnect_guard,
        );
    });
}

fn parse_log_line(line_number: u64, content: &str) -> LogEntry {
    // 优先尝试 JSON 解析（日志文件存储 JSON 格式）
    if content.starts_with('{') {
        let mut ts = String::new();
        let mut level = String::new();
        let mut msg = String::new();

        if let Some(v) = json_field(content, "ts") {
            ts = format_timestamp(&v);
        }
        if let Some(v) = json_field(content, "level") {
            level = v;
        }
        if let Some(v) = json_field(content, "msg") {
            msg = v;
        }

        if !level.is_empty() {
            return LogEntry {
                line_number,
                time: ts,
                level,
                message: msg,
            };
        }
    }

    // 传统日志格式回退：`2026-07-08T03:02:41 [INFO] 收到统计数据`
    if let Some((rest, message)) = content.split_once("] ") {
        if let Some(bracket_pos) = rest.rfind('[') {
            let level = &rest[bracket_pos + 1..];
            let time = rest[..bracket_pos].trim();
            return LogEntry {
                line_number,
                time: time.to_string(),
                level: level.to_string(),
                message: message.to_string(),
            };
        }
    }

    LogEntry {
        line_number,
        time: String::new(),
        level: "INFO".to_string(),
        message: content.to_string(),
    }
}

/// 从 JSON 字符串中提取指定字段的值（轻量解析，不依赖 serde_json）
fn json_field(json: &str, field: &str) -> Option<String> {
    let key = format!("\"{}\"", field);
    let key_pos = json.find(&key)?;
    let rest = &json[key_pos + key.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();

    if rest.starts_with('"') {
        let inner = &rest[1..];
        let end = inner.find('"')?;
        Some(unescape_json(inner[..end].to_string()))
    } else {
        let end = rest.find(|c: char| {
            !c.is_alphanumeric() && c != '.' && c != '-' && c != 'e' && c != 'E' && c != '+'
        })?;
        Some(rest[..end].to_string())
    }
}

/// 反转义 JSON 字符串中的常见转义序列
fn unescape_json(s: String) -> String {
    s.replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\\\", "\\")
}

/// 将 ISO 8601 时间戳格式化为可读格式
fn format_timestamp(ts: &str) -> String {
    let base = if ts.ends_with('Z') {
        &ts[..ts.len().saturating_sub(1)]
    } else if ts.ends_with("+00:00") {
        &ts[..ts.len().saturating_sub(6)]
    } else {
        ts
    };
    let trimmed = if let Some(dot_pos) = base.rfind('.') {
        &base[..dot_pos]
    } else {
        base
    };
    trimmed.replace('T', " ")
}
