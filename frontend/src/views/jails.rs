//! Jail 配置展示 — 封禁统计 + 状态控制

use leptos::*;

use crate::api::{self, JailResponse, StatsResponse};
use crate::charts::PieChart;
use crate::sse::SseState;

#[component]
pub fn Jails() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let jails_signal = sse.jails;
    let stats_signal = sse.stats;
    let jails_api = create_resource(|| (), |_| async { api::get_jails().await.ok() });

    let stats_default = move || StatsResponse::default();

    let do_toggle = move |name: String, current_enabled: bool| {
        let new_enabled = !current_enabled;
        let window = web_sys::window().expect("window not available");
        let action = if new_enabled { "启用" } else { "禁用" };
        if !window.confirm_with_message(&format!("确定要{} Jail '{}' 吗?", action, name)).unwrap_or(false) { return; }
        spawn_local(async move {
            match api::update_jail(&name, new_enabled).await {
                Ok(_) => {
                    if let Some(jails) = jails_signal.get() {
                        let updated: Vec<JailResponse> = jails.into_iter().map(|j| {
                            if j.name == name {
                                JailResponse { name: j.name, enabled: new_enabled, ban_count: j.ban_count }
                            } else { j }
                        }).collect();
                        jails_signal.set(Some(updated));
                    }
                }
                Err(_) => {}
            }
        });
    };

    view! {
        <div class="jails-page">
            <div class="card chart-card">
                <div class="chart-header"><h3>"Jail 封禁分布"</h3></div>
                <div class="chart-body" style="height:120px;min-height:120px">
                    {move || {
                        let stats = stats_signal.get().unwrap_or_else(|| stats_default());
                        let total: u64 = stats.jail_distribution.values.iter().sum();
                        if total == 0 {
                            view! {
                                <div style="height:100%;display:flex;align-items:center;justify-content:center;color:var(--text-faint);font-size:13px;letter-spacing:0.05em">"暂无封禁数据"</div>
                            }.into_view()
                        } else {
                            view! {
                                <PieChart
                                    labels=Signal::derive(move || stats.jail_distribution.labels.clone())
                                    data=Signal::derive(move || stats.jail_distribution.values.clone())
                                    size=120
                                />
                            }.into_view()
                        }
                    }}
                </div>
            </div>

            <div class="page-toolbar">
                <div class="toolbar-left"><h2 class="section-title">"Jail 配置"</h2></div>
            </div>

            <div class="jails-grid">
                <Suspense fallback=|| view! { <div class="empty-state"><span>"加载中..."</span></div> }>
                    {move || {
                        let jails = jails_signal.get()
                            .or_else(|| jails_api.get().flatten())
                            .unwrap_or_default();
                        if jails.is_empty() {
                            return view! {
                                <div class="card"><div class="empty-state">
                                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/>
                                    </svg>
                                    <span>"暂无 Jail 配置"</span>
                                </div></div>
                            }.into_view();
                        }
                        view! {
                            <For each=move || jails.clone() key=|j| j.name.clone()
                                children=move |jail: JailResponse| {
                                    let name = jail.name.clone();
                                    view! {
                                        <div class="card jail-card">
                                            <div class="jail-header">
                                                <span class="jail-name">{&jail.name}</span>
                                                <div style="display:flex;gap:8px;align-items:center">
                                                    <span class=move || {
                                                        if jail.enabled { "badge badge-success badge-dot" } else { "badge badge-danger badge-dot" }
                                                    }>
                                                        {move || if jail.enabled { "ENABLED" } else { "DISABLED" }}
                                                    </span>
                                                    <button
                                                        class=move || {
                                                            if jail.enabled { "btn btn-sm btn-danger" } else { "btn btn-sm btn-success" }
                                                        }
                                                        style="padding:4px 8px;font-size:10px"
                                                        on:click=move |_| do_toggle(name.clone(), jail.enabled)>
                                                        {move || if jail.enabled { "禁用" } else { "启用" }}
                                                    </button>
                                                </div>
                                            </div>
                                            <div class="jail-stats">
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"封禁数"</span>
                                                    <span class="jail-stat-value mono">{jail.ban_count}</span>
                                                </div>
                                            </div>
                                        </div>
                                    }
                                }/>
                        }.into_view()
                    }}
                </Suspense>
            </div>
        </div>
    }
}
