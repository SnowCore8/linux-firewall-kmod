//! Jail 配置展示

use leptos::*;

use crate::api::{self, JailResponse};
use crate::sse;

#[component]
pub fn Jails() -> impl IntoView {
    let jails_signal = sse::use_sse_jails();
    let jails_api = create_resource(|| (), |_| async { api::get_jails().await.ok() });

    view! {
        <div class="jails-page">
            <div class="page-toolbar">
                <h2 class="section-title">"Jail 配置"</h2>
            </div>

            <div class="jails-grid">
                <Suspense fallback=|| view! { <div class="empty-state"><span>"加载中..."</span></div> }>
                    {move || {
                        // 优先使用 SSE 数据，回退到 API 数据
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
                                                <span class="jail-name mono">{&jail.name}</span>
                                                <span class=move || {
                                                    if jail.enabled {
                                                        "badge badge-success"
                                                    } else {
                                                        "badge badge-danger"
                                                    }
                                                }>
                                                    {move || if jail.enabled { "启用" } else { "禁用" }}
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
