//! 默认布局 — 56px 极窄图标侧边栏 + 顶部栏 + 内容区

use leptos::*;
use leptos_router::*;

use crate::sse::{self, ConnectionStatus, SseState};
use crate::theme;

#[component]
pub fn DefaultLayout(sse_state: SseState, children: Children) -> impl IntoView {
    let status = sse_state.status;
    let reconnect_attempt = sse_state.reconnect_attempt;
    let sidebar_open = create_rw_signal(false);
    // 在 DefaultLayout 挂载时建立 SSE 连接
    let sse_for_connect = sse_state.clone();
    create_effect(move |_| {
        sse::connect_sse(sse_for_connect.clone());
        theme::init_theme();
    });

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

    let nav_items: Vec<(&str, View)> = vec![
        ("/dashboard", nav_icon_dashboard().into_view()),
        ("/bans", nav_icon_bans().into_view()),
        ("/whitelist", nav_icon_whitelist().into_view()),
        ("/jails", nav_icon_jails().into_view()),
        ("/ddos", nav_icon_ddos().into_view()),
        ("/logs", nav_icon_logs().into_view()),
        ("/settings", nav_icon_settings().into_view()),
    ];

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

                <nav class="sidebar-nav">
                    {nav_items.into_iter().map(|(path, icon)| {
                        view! {
                            <A href=path class=move || {
                                let loc = use_location();
                                let active = loc.pathname.get() == path;
                                if active { "nav-item active" } else { "nav-item" }
                            } on:click=move |_| sidebar_open.set(false)>
                                {icon}
                            </A>
                        }
                    }).collect_view()}
                </nav>

                <div class="sidebar-footer">
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
                    <a href="/metrics" target="_blank"
                        style="font-size:8px;color:var(--color-cyan);text-decoration:none;font-weight:700;letter-spacing:0.1em;text-transform:uppercase">
                        "METRICS"
                    </a>
                </div>
            </aside>

            <div class="main-content">
                <Show
                    when=move || matches!(status.get(), ConnectionStatus::Disconnected | ConnectionStatus::ConnectionLimit)
                    fallback=|| ()
                >
                    <div class="offline-banner">
                        <span>{move || {
                            if status.get() == ConnectionStatus::ConnectionLimit {
                                "⚠ SSE 连接数已达上限，请关闭其他标签页后刷新".to_string()
                            } else {
                                let n = reconnect_attempt.get();
                                if n > 0 {
                                    format!("⚠ 连接已断开，第 {} 次重连中...", n)
                                } else {
                                    "⚠ 连接已断开".to_string()
                                }
                            }
                        }}</span>
                    </div>
                </Show>

                <header class="topbar">
                    <div class="topbar-left">
                        <button class="menu-toggle" on:click=move |_| {
                            sidebar_open.update(|v| *v = !*v);
                        }>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M3 12h18M3 6h18M3 18h18"/>
                            </svg>
                        </button>
                        <h1 class="topbar-title">{page_title}</h1>
                    </div>
                    <div class="topbar-right">
                        <div class="topbar-status">
                            <span class=move || {
                                match status.get() {
                                    ConnectionStatus::Connected => "sse-dot",
                                    _ => "sse-dot disconnected",
                                }
                            }/>
                            <span>{move || match status.get() {
                                ConnectionStatus::Connected => "CONNECTED",
                                ConnectionStatus::Connecting => "CONNECTING",
                                ConnectionStatus::Disconnected => "DISCONNECTED",
                                ConnectionStatus::ConnectionLimit => "LIMIT REACHED",
                            }}</span>
                        </div>
                        <button class="btn btn-icon" on:click=move |_| theme::toggle_theme()>
                            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="13" height="13">
                                <circle cx="12" cy="12" r="5"/>
                                <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 4.22l1.42 1.42M18.36 5.64l1.42 1.42"/>
                            </svg>
                        </button>
                    </div>
                </header>

                <main class="page-content">
                    {children()}
                </main>
            </div>
        </div>
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
