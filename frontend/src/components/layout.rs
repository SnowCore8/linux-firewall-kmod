//! 默认布局 — 56px 极窄图标侧边栏 + 顶部栏 + 内容区

use leptos::*;
use leptos_router::*;
use wasm_bindgen::JsCast;

use crate::sse::{self, ConnectionStatus, SseState};
use crate::theme;

#[component]
pub fn DefaultLayout(sse_state: SseState, children: Children) -> impl IntoView {
    let status = sse_state.status;
    let reconnect_attempt = sse_state.reconnect_attempt;
    let sidebar_open = create_rw_signal(false);
    let show_shortcuts = create_rw_signal(false);

    // 全局键盘事件（快捷键）
    if let Some(window) = web_sys::window() {
        let handler =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |e: web_sys::KeyboardEvent| {
                let tag = web_sys::window()
                    .and_then(|w| w.document())
                    .and_then(|d| d.active_element())
                    .map(|el| el.tag_name().to_lowercase())
                    .unwrap_or_default();
                let is_input = tag == "input" || tag == "textarea" || tag == "select";

                if !is_input {
                    if e.key() == "?" {
                        e.prevent_default();
                        show_shortcuts.update(|v| *v = !*v);
                    }
                    if e.key() == "Escape" {
                        show_shortcuts.set(false);
                    }
                }
            }) as Box<dyn FnMut(_)>);
        let _ =
            window.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
        handler.forget();
    }
    // 在 DefaultLayout 挂载时建立 SSE 连接
    let sse_for_connect = sse_state.clone();
    create_effect(move |_| {
        sse::connect_sse(sse_for_connect.clone());
        theme::init_theme();
    });

    // 全局页面切换进度条（NProgress 风格）
    let page_progress = create_rw_signal(0.0_f64);
    let progress_visible = create_rw_signal(false);
    {
        let location = use_location();
        create_effect(move |_| {
            let _path = location.pathname.get();
            // 路由变化时触发进度条
            progress_visible.set(true);
            page_progress.set(0.0);
            // 快速推进到 70%
            set_timeout(
                move || page_progress.set(70.0),
                std::time::Duration::from_millis(50),
            );
            // 完成到 100% 后隐藏
            set_timeout(
                move || {
                    page_progress.set(100.0);
                    set_timeout(
                        move || {
                            progress_visible.set(false);
                            page_progress.set(0.0);
                        },
                        std::time::Duration::from_millis(200),
                    );
                },
                std::time::Duration::from_millis(300),
            );
        });
    }

    // 触摸手势支持
    let touch_start_x = create_rw_signal(0.0);
    let touch_start_y = create_rw_signal(0.0);

    let on_touch_start = move |e: web_sys::TouchEvent| {
        if let Some(touch) = e.touches().item(0) {
            touch_start_x.set(touch.client_x() as f64);
            touch_start_y.set(touch.client_y() as f64);
        }
    };

    let on_touch_end = move |e: web_sys::TouchEvent| {
        if let Some(touch) = e.changed_touches().item(0) {
            let end_x = touch.client_x() as f64;
            let end_y = touch.client_y() as f64;
            let delta_x = end_x - touch_start_x.get();
            let delta_y = (end_y - touch_start_y.get()).abs();

            if delta_x.abs() > 50.0 && delta_x.abs() > delta_y {
                if delta_x > 0.0 {
                    sidebar_open.set(true);
                } else {
                    sidebar_open.set(false);
                }
            }
        }
    };

    let nav_items: Vec<(&str, &str, View)> = vec![
        ("/dashboard", "仪表盘", nav_icon_dashboard().into_view()),
        ("/bans", "封禁管理", nav_icon_bans().into_view()),
        ("/whitelist", "白名单", nav_icon_whitelist().into_view()),
        ("/jails", "Jail 配置", nav_icon_jails().into_view()),
        ("/ddos", "DDoS 监控", nav_icon_ddos().into_view()),
        ("/logs", "日志查看", nav_icon_logs().into_view()),
        ("/settings", "系统设置", nav_icon_settings().into_view()),
    ];

    // 最近访问页面追踪（排除当前页，最多 3 个）
    let recent_pages = create_rw_signal(Vec::<(String, String)>::new());
    let recent_items: Vec<(&str, &str)> = vec![
        ("/dashboard", "仪表盘"),
        ("/bans", "封禁管理"),
        ("/whitelist", "白名单"),
        ("/jails", "Jail 配置"),
        ("/ddos", "DDoS 监控"),
        ("/logs", "日志查看"),
        ("/settings", "系统设置"),
    ];
    create_effect(move |_| {
        let path = use_location().pathname.get();
        let current_label = recent_items
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, l)| *l);
        if let Some(label) = current_label {
            recent_pages.update(|list| {
                // 移除已有的同路径条目
                list.retain(|(p, _)| p != &path);
                // 添加到开头
                list.insert(0, (path.clone(), label.to_string()));
                // 最多保留 3 个
                list.truncate(3);
            });
        }
    });

    let page_title = move || {
        let path = use_location().pathname;
        match path.get().as_str() {
            "/dashboard" => "DASHBOARD",
            "/bans" => "BANS",
            "/whitelist" => "WHITELIST",
            "/jails" => "JAILS",
            "/ddos" => "DDOS MONITOR",
            "/logs" => "SYSTEM LOGS",
            "/settings" => "SETTINGS",
            _ => "FIREWALL",
        }
    };

    view! {
        <div class="app-layout"
            on:touchstart=on_touch_start
            on:touchend=on_touch_end
        >
            // 页面切换进度条
            <Show when=move || progress_visible.get() fallback=|| ()>
                <div class="page-progress-bar">
                    <div class="page-progress-fill" style=move || format!("width:{}%;opacity:{}", page_progress.get(), if page_progress.get() >= 100.0 { 0.0 } else { 1.0 })/>
                </div>
            </Show>
            <div
                class=move || if sidebar_open.get() { "sidebar-overlay visible" } else { "sidebar-overlay" }
                on:click=move |_| sidebar_open.set(false)
            />

            <aside class=move || {
                if sidebar_open.get() { "sidebar open" } else { "sidebar" }
            }>
                <div class="sidebar-header">
                    <A href="/dashboard" class="sidebar-brand">
                        <div class="sidebar-brand-icon">
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
                                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                            </svg>
                        </div>
                    </A>
                </div>

                <nav class="sidebar-nav" aria-label="主导航">
                    {nav_items.into_iter().map(|(path, label, icon)| {
                        let label_owned = label.to_string();
                        view! {
                            <div class="nav-item-wrapper">
                                <A href=path class=move || {
                                    let loc = use_location();
                                    let active = loc.pathname.get() == path;
                                    if active { "nav-item active" } else { "nav-item" }
                                } on:click=move |_| sidebar_open.set(false)>
                                    {icon}
                                </A>
                                <span class="nav-tooltip">{label_owned}</span>
                            </div>
                        }
                    }).collect_view()}
                </nav>

                <div class="sidebar-footer">
                    // 最近访问页面
                    <Show when=move || !recent_pages.get().is_empty()>
                        <div class="sidebar-recent">
                            <span class="sidebar-recent-label">"RECENT"</span>
                            {move || {
                                let pages = recent_pages.get();
                                let current = use_location().pathname.get();
                                pages.into_iter()
                                    .filter(|(p, _)| p != &current)
                                    .take(3)
                                    .map(|(path, label)| {
                                        view! {
                                            <A href=path.clone() class="sidebar-recent-item">
                                                {label}
                                            </A>
                                        }
                                    })
                                    .collect_view()
                            }}
                        </div>
                    </Show>
                    <div class="sse-indicator">
                        <span class=move || {
                            match status.get() {
                                ConnectionStatus::Connected => "sse-dot",
                                _ => "sse-dot disconnected",
                            }
                        }/>
                        <span>{move || match status.get() {
                            ConnectionStatus::Connected => "LIVE",
                            ConnectionStatus::Connecting => "...",
                            ConnectionStatus::Disconnected => "OFF",
                            ConnectionStatus::ConnectionLimit => "LIMIT",
                        }}</span>
                    </div>
                    <a href="/metrics" target="_blank" rel="noopener noreferrer" class="sidebar-metrics-link">
                        "METRICS"
                    </a>
                </div>
            </aside>

            <div class="main-content">
                <Show
                    when=move || matches!(status.get(), ConnectionStatus::Disconnected | ConnectionStatus::ConnectionLimit)
                    fallback=|| ()
                >
                    <div class="offline-banner" role="alert">
                        <span>{move || {
                            if status.get() == ConnectionStatus::ConnectionLimit {
                                "SSE 连接数已达上限，请关闭其他标签页后刷新".to_string()
                            } else {
                                let n = reconnect_attempt.get();
                                if n > 0 {
                                    format!("连接已断开，第 {} 次重连中...", n)
                                } else {
                                    "连接已断开".to_string()
                                }
                            }
                        }}</span>
                    </div>
                </Show>

                <header class="topbar">
                    <div class="topbar-left">
                        <button class="menu-toggle" type="button" aria-label="打开或关闭导航"
                            on:click=move |_| {
                            sidebar_open.update(|v| *v = !*v);
                        }>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
                                <path d="M3 12h18M3 6h18M3 18h18"/>
                            </svg>
                        </button>
                        <h1 class="topbar-title">{page_title}</h1>
                    </div>
                    <div class="topbar-right">
                        <div class="topbar-status" aria-live="polite">
                            <span class=move || {
                                match status.get() {
                                    ConnectionStatus::Connected => "sse-dot",
                                    _ => "sse-dot disconnected",
                                }
                            } aria-hidden="true"/>
                            <span>{move || match status.get() {
                                ConnectionStatus::Connected => "CONNECTED",
                                ConnectionStatus::Connecting => "CONNECTING",
                                ConnectionStatus::Disconnected => "DISCONNECTED",
                                ConnectionStatus::ConnectionLimit => "LIMIT REACHED",
                            }}</span>
                        </div>
                        <button class="btn btn-icon" type="button" aria-label="切换浅色或深色主题"
                            on:click=move |_| theme::toggle_theme()>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13" aria-hidden="true">
                                <circle cx="12" cy="12" r="5"/>
                                <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 4.22l1.42 1.42M18.36 5.64l1.42 1.42"/>
                            </svg>
                        </button>
                        <button class="btn btn-icon btn-shortcut-help" type="button" title="键盘快捷键 (?)"
                            aria-label="显示键盘快捷键"
                            on:click=move |_| show_shortcuts.update(|v| *v = !*v)>
                            "?"
                        </button>
                    </div>
                </header>

                <main class="page-content">
                    {children()}
                </main>
            </div>

            // 快捷键帮助面板
            <Show when=move || show_shortcuts.get() fallback=|| ()>
                <div class="modal-overlay" style="z-index:200" on:click=move |_| show_shortcuts.set(false)>
                    <div class="modal" style="max-width:440px;padding:24px" on:click=|e| e.stop_propagation()>
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
                            <h3 style="font-size:14px;font-weight:700;margin:0">"⌨ 键盘快捷键"</h3>
                            <button class="btn btn-sm" style="padding:4px 8px" on:click=move |_| show_shortcuts.set(false)>"✕"</button>
                        </div>
                        <div style="display:grid;gap:8px">
                            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                                <span style="font-size:12px;color:var(--text-secondary)">"聚焦搜索框"</span>
                                <kbd style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border-default);border-radius:4px;font-family:var(--font-mono)">"/"</kbd>
                            </div>
                            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                                <span style="font-size:12px;color:var(--text-secondary)">"清除搜索 / 关闭弹窗"</span>
                                <kbd style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border-default);border-radius:4px;font-family:var(--font-mono)">"Esc"</kbd>
                            </div>
                            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                                <span style="font-size:12px;color:var(--text-secondary)">"范围选择（封禁列表）"</span>
                                <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono)">"Shift + 点击"</span>
                            </div>
                            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border-subtle)">
                                <span style="font-size:12px;color:var(--text-secondary)">"切换明/暗主题"</span>
                                <span style="font-size:11px;color:var(--text-muted)">"顶栏 ☀ 按钮"</span>
                            </div>
                            <div style="display:flex;justify-content:space-between;padding:6px 0">
                                <span style="font-size:12px;color:var(--text-secondary)">"显示此面板"</span>
                                <kbd style="font-size:11px;padding:2px 8px;background:var(--bg-tertiary);border:1px solid var(--border-default);border-radius:4px;font-family:var(--font-mono)">"?"</kbd>
                            </div>
                        </div>
                        <p style="font-size:11px;color:var(--text-muted);margin-top:12px;text-align:center">
                            "快捷键仅在非输入框状态下生效"
                        </p>
                    </div>
                </div>
            </Show>

            // 命令面板 (Ctrl+K) — 独立组件，避免闭包所有权冲突
            <CommandPalette/>
        </div>
    }
}

/// 命令面板组件 — Ctrl+K 快速导航
#[component]
fn CommandPalette() -> impl IntoView {
    let show = create_rw_signal(false);
    let query = create_rw_signal(String::new());
    let selected = create_rw_signal(0usize);

    // 命令列表
    let cmd_items = || -> Vec<(String, String, &'static str)> {
        vec![
            ("仪表盘".into(), "总览安全态势".into(), "/dashboard"),
            ("封禁管理".into(), "查看/管理封禁 IP".into(), "/bans"),
            ("白名单".into(), "管理可信 IP 白名单".into(), "/whitelist"),
            ("Jail 配置".into(), "服务监控规则配置".into(), "/jails"),
            ("DDoS 监控".into(), "实时流量与攻击分析".into(), "/ddos"),
            ("日志查看".into(), "系统运行日志".into(), "/logs"),
            ("系统设置".into(), "阈值与功能配置".into(), "/settings"),
            (
                "Prometheus 指标".into(),
                "外部监控数据端点".into(),
                "/metrics",
            ),
        ]
    };

    // 过滤（create_memo 返回 Memo<T>，是 Copy Signal，可在任意 move 闭包中自由使用）
    let filtered = create_memo(move |_| {
        let q = query.get().to_lowercase();
        let all = cmd_items();
        if q.is_empty() {
            all
        } else {
            all.into_iter()
                .filter(|(n, d, _)| n.to_lowercase().contains(&q) || d.to_lowercase().contains(&q))
                .collect()
        }
    });

    // 全局 Ctrl+K 监听（仅捕获 Copy 的 show/query）
    if let Some(window) = web_sys::window() {
        let handler =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |e: web_sys::KeyboardEvent| {
                if (e.ctrl_key() || e.meta_key()) && e.key() == "k" {
                    e.prevent_default();
                    show.update(|v| *v = !*v);
                    if !show.get() {
                        query.set(String::new());
                    }
                }
            }) as Box<dyn FnMut(_)>);
        let _ =
            window.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
        handler.forget();
    }

    view! {
        <Show when=move || show.get() fallback=|| ()>
            <div class="modal-overlay" style="z-index:210;align-items:flex-start;padding-top:15vh"
                on:click=move |_| { show.set(false); query.set(String::new()); }>
                <div class="modal" style="max-width:520px;width:100%;padding:0;overflow:hidden"
                    on:click=|e| e.stop_propagation()>
                    <div style="padding:12px 16px;border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;gap:8px">
                        <svg viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" stroke-width="2" width="16" height="16">
                            <circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
                        </svg>
                        <input class="input" style="flex:1;border:none;padding:8px 0;font-size:14px;outline:none;background:transparent"
                            placeholder="搜索页面或操作..."
                            autofocus=true
                            prop:value=move || query.get()
                            on:input=move |e| {
                                query.set(event_target_value(&e));
                                selected.set(0);
                            }
                            on:keydown=move |e| {
                                let res = filtered.get();
                                if e.key() == "Escape" {
                                    show.set(false);
                                    query.set(String::new());
                                } else if e.key() == "Enter" {
                                    if let Some(item) = res.get(selected.get()) {
                                        let p = item.2;
                                        if let Some(w) = web_sys::window() {
                                            let _ = w.location().set_href(p);
                                        }
                                        show.set(false);
                                        query.set(String::new());
                                    }
                                } else if e.key() == "ArrowDown" {
                                    e.prevent_default();
                                    selected.update(|v| *v = (*v + 1).min(res.len().saturating_sub(1)));
                                } else if e.key() == "ArrowUp" {
                                    e.prevent_default();
                                    selected.update(|v| *v = v.saturating_sub(1));
                                }
                            }/>
                        <kbd style="font-size:9px;color:var(--text-muted);padding:2px 6px;background:var(--bg-tertiary);border:1px solid var(--border-default);border-radius:3px;font-family:var(--font-mono)">"ESC"</kbd>
                    </div>
                    <div style="max-height:320px;overflow-y:auto;padding:4px">
                        {move || {
                            let res = filtered.get();
                            if res.is_empty() {
                                return view! { <div style="padding:24px;text-align:center;color:var(--text-muted);font-size:13px">"无匹配结果"</div> }.into_view();
                            }
                            res.into_iter().enumerate().map(|(i, (name, desc, path))| {
                                let is_sel = i == selected.get();
                                view! {
                                    <div class="cmd-item" class:selected=is_sel
                                        on:click={
                                            move |_| {
                                                if path == "/metrics" {
                                                    if let Some(w) = web_sys::window() {
                                                        let _ = w.open_with_url_and_target("/metrics", "_blank");
                                                    }
                                                } else if let Some(w) = web_sys::window() {
                                                    let _ = w.location().set_href(path);
                                                }
                                                show.set(false);
                                                query.set(String::new());
                                            }
                                        }
                                        on:mouseenter=move |_| selected.set(i)>
                                        <div style="flex:1">
                                            <div style="font-size:13px;font-weight:600;color:var(--text-primary)">{name}</div>
                                            <div style="font-size:11px;color:var(--text-muted)">{desc}</div>
                                        </div>
                                        <span style="font-size:10px;color:var(--text-faint);font-family:var(--font-mono)">{path}</span>
                                    </div>
                                }
                            }).collect_view()
                        }}
                    </div>
                </div>
            </div>
        </Show>
    }
}

fn nav_icon_dashboard() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="7" height="7" rx="1"/>
            <rect x="14" y="3" width="7" height="7" rx="1"/>
            <rect x="3" y="14" width="7" height="7" rx="1"/>
            <rect x="14" y="14" width="7" height="7" rx="1"/>
        </svg>
    }
}

fn nav_icon_bans() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M4.93 4.93l14.14 14.14"/>
        </svg>
    }
}

fn nav_icon_whitelist() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 12l2 2 4-4"/>
            <circle cx="12" cy="12" r="10"/>
        </svg>
    }
}

fn nav_icon_jails() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="11" width="18" height="11" rx="2"/>
            <path d="M7 11V7a5 5 0 0110 0v4"/>
        </svg>
    }
}

fn nav_icon_ddos() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
        </svg>
    }
}

fn nav_icon_logs() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/>
            <path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/>
        </svg>
    }
}

fn nav_icon_settings() -> impl IntoView {
    view! {
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="3"/>
            <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/>
        </svg>
    }
}
