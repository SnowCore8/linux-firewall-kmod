//! Jail 配置展示 — 封禁统计 + 状态控制

use leptos::*;

use crate::api::{self, JailResponse, StatsResponse};
use crate::charts::PieChart;
use crate::format::format_number;
use crate::sse;

#[component]
pub fn Jails() -> impl IntoView {
    let jails_signal = sse::use_sse_jails();
    let stats_signal = sse::use_sse_stats();
    let jails_api = create_resource(|| (), |_| async { api::get_jails().await.ok() });

    let stats_default = move || StatsResponse::default();

    view! {
        <div class="jails-page">
            // 顶部 Jail 分布图
            <div class="card chart-card">
                <div class="chart-header">
                    <h3>"Jail 封禁分布"</h3>
                </div>
                <div class="chart-body" style="height:200px">
                    <PieChart
                        labels=Signal::derive(move || {
                            stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).jail_distribution.labels
                        })
                        data=Signal::derive(move || {
                            stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).jail_distribution.values
                        })
                        size=200
                    />
                </div>
            </div>

            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"Jail 配置"</h2>
                </div>
            </div>

            <div class="jails-grid">
                <Suspense fallback=|| view! { <div class="empty-state"><span>"加载中..."</span></div> }>
                    {move || {
                        let jails = jails_signal.get()
                            .or_else(|| jails_api.get().flatten())
                            .unwrap_or_default();

                        if jails.is_empty() {
                            return view! {
                                <div class="card">
                                    <div class="empty-state">
                                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                            <rect x="3" y="11" width="18" height="11" rx="2"/>
                                            <path d="M7 11V7a5 5 0 0110 0v4"/>
                                        </svg>
                                        <span>"暂无 Jail 配置"</span>
                                    </div>
                                </div>
                            }.into_view();
                        }

                        view! {
                            <For
                                each=move || jails.clone()
                                key=|j| j.name.clone()
                                children=move |jail: JailResponse| {
                                    view! {
                                        <div class="card jail-card">
                                            <div class="jail-header">
                                                <span class="jail-name">{&jail.name}</span>
                                                <span class=move || {
                                                    if jail.enabled {
                                                        "badge badge-success badge-dot"
                                                    } else {
                                                        "badge badge-danger badge-dot"
                                                    }
                                                }>
                                                    {move || if jail.enabled { "ENABLED" } else { "DISABLED" }}
                                                </span>
                                            </div>
                                            <div class="jail-stats">
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"封禁数"</span>
                                                    <span class="jail-stat-value mono">{jail.ban_count}</span>
                                                </div>
                                            </div>
                                        </div>
                                    }
                                }
                            />
                        }.into_view()
                    }}
                </Suspense>
            </div>
        </div>
    }
}
