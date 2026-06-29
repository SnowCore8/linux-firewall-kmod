//! 白名单管理 — SSE 实时更新 + 设备信息 + 智能推荐

use leptos::*;

use crate::api::{self, WhitelistEntry, WhitelistRecommendation};
use crate::sse::SseState;
use crate::validation;

#[component]
pub fn Whitelist() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let whitelist_signal = sse.whitelist;

    let new_cidr = create_rw_signal(String::new());
    let error = create_rw_signal(String::new());
    let loading = create_rw_signal(false);

    // 智能推荐数据
    let recommendations = create_resource(
        || (),
        |_| async {
            api::get_whitelist_recommendations()
                .await
                .unwrap_or_default()
        },
    );

    let do_add = move |_| {
        let cidr = new_cidr.get().trim().to_string();
        if cidr.is_empty() {
            error.set("CIDR 不能为空".to_string());
            return;
        }
        if !validation::is_valid_cidr(&cidr) {
            error.set("CIDR 格式无效(例如:192.168.1.0/24 或 10.0.0.0/8)".to_string());
            return;
        }
        if let Some(list) = whitelist_signal.get() {
            if list.iter().any(|e| e.cidr == cidr) {
                error.set("该 CIDR 已存在于白名单中".to_string());
                return;
            }
        }
        loading.set(true);
        error.set(String::new());
        spawn_local(async move {
            match api::create_whitelist(&cidr).await {
                Ok(_) => new_cidr.set(String::new()),
                Err(e) => error.set(e),
            }
            loading.set(false);
        });
    };

    let do_remove = move |cidr: String| {
        let window = web_sys::window().expect("window not available");
        if !window
            .confirm_with_message(&format!("确定要移除白名单条目 {} 吗?", cidr))
            .unwrap_or(false)
        {
            return;
        }
        spawn_local(async move {
            if let Err(e) = api::delete_whitelist(&cidr).await {
                let _ = web_sys::window()
                    .and_then(|w| w.alert_with_message(&format!("移除失败：{e}")).ok());
            }
        });
    };

    view! {
        <div class="whitelist-page">
            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"白名单管理"</h2>
                    <span class="badge badge-success badge-dot">
                        {move || format!("{}", whitelist_signal.get().map(|w| w.len()).unwrap_or(0))}
                    </span>
                </div>
            </div>

            <div class="card" style="padding:14px">
                <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;max-width:600px">
                    <div style="flex:1;min-width:200px">
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">"CIDR 地址"</label>
                        <input class="input mono" placeholder="10.0.0.0/8 或 192.168.1.1" style="width:100%"
                            prop:value=move || new_cidr.get()
                            on:input=move |e| new_cidr.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" on:click=do_add
                        disabled=move || loading.get()
                        style="flex-shrink:0;height:36px">
                        {move || if loading.get() { "添加中..." } else { "添加" }}
                    </button>
                    <span style="color:var(--color-red);font-size:11px">{move || error.get()}</span>
                </div>
            </div>

            // 智能白名单推荐
            <Suspense fallback=|| view! { <div/> }>
                {move || {
                    let recs = recommendations.get().unwrap_or_default();
                    if recs.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let rec_count = recs.len();
                    let recs_for = recs.clone();
                    view! {
                        <div class="card" style="padding:14px">
                            <div style="display:flex;align-items:center;gap:8px;margin-bottom:12px">
                                <h3 style="font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-secondary);margin:0">
                                    "智能推荐"
                                </h3>
                                <span class="badge badge-warning" style="font-size:9px">
                                    {format!("{} 条建议", rec_count)}
                                </span>
                            </div>
                            <div class="rec-list">
                                <For each=move || recs_for.clone() key=|r| r.cidr.clone()
                                    children=move |rec: WhitelistRecommendation| {
                                        let cidr = rec.cidr.clone();
                                        let confidence_color = if rec.confidence >= 70 {
                                            "var(--color-green)"
                                        } else if rec.confidence >= 40 {
                                            "var(--color-orange)"
                                        } else {
                                            "var(--text-muted)"
                                        };
                                        view! {
                                            <div class="rec-item">
                                                <div class="rec-info">
                                                    <span class="rec-cidr mono">{&rec.cidr}</span>
                                                    <span class="rec-type">
                                                        {if rec.rec_type == "subnet" { "子网" } else { "单 IP" }}
                                                    </span>
                                                    <span class="rec-reason">{&rec.reason}</span>
                                                </div>
                                                <div class="rec-actions">
                                                    <span class="rec-confidence" style=move || format!("color:{}", confidence_color)>
                                                        {format!("{}%", rec.confidence)}
                                                    </span>
                                                    <button class="btn btn-sm btn-primary"
                                                        on:click=move |_| {
                                                            let cidr = cidr.clone();
                                                            spawn_local(async move {
                                                                if let Err(e) = api::create_whitelist(&cidr).await {
                                                                    let _ = web_sys::window()
                                                                        .and_then(|w| w.alert_with_message(&format!("采纳失败：{e}")).ok());
                                                                }
                                                            });
                                                        }>
                                                        "采纳"
                                                    </button>
                                                </div>
                                            </div>
                                        }
                                    }/>
                            </div>
                        </div>
                    }.into_view()
                }}
            </Suspense>

            <div class="card">
                {move || {
                    let list = whitelist_signal.get().unwrap_or_default();
                    if list.is_empty() {
                        return view! {
                            <div class="empty-state">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M9 12l2 2 4-4"/><circle cx="12" cy="12" r="10"/>
                                </svg>
                                <span>"白名单为空"</span>
                            </div>
                        }.into_view();
                    }
                    view! {
                        <div class="table-container">
                            <table>
                                <thead><tr>
                                    <th style="width:50%">"CIDR"</th>
                                    <th style="width:25%">"设备"</th>
                                    <th style="width:25%">"操作"</th>
                                </tr></thead>
                                <tbody>
                                    <For each=move || list.clone() key=|e| e.cidr.clone()
                                        children=move |entry: WhitelistEntry| {
                                            let cidr = entry.cidr.clone();
                                            view! {
                                                <tr>
                                                    <td class="mono" style="font-weight:600;color:var(--text-primary)">{&entry.cidr}</td>
                                                    <td style="color:var(--text-muted)">{&entry.device}</td>
                                                    <td>
                                                        <button class="btn btn-sm btn-danger"
                                                            on:click=move |_| do_remove(cidr.clone())>
                                                            "移除"
                                                        </button>
                                                    </td>
                                                </tr>
                                            }
                                        }/>
                                </tbody>
                            </table>
                        </div>
                    }.into_view()
                }}
            </div>
        </div>
    }
}
