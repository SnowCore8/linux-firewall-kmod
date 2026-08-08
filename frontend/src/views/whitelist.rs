//! 白名单管理 — SSE 实时更新 + 设备信息 + 智能推荐

use leptos::*;

use crate::api::{self, WhitelistEntry, WhitelistRecommendation};
use crate::components::toast::ToastState;
use crate::components::{EmptyState, PageHeader};
use crate::sse::SseState;
use crate::validation;

#[component]
pub fn Whitelist() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let toast_state = use_context::<ToastState>().expect("ToastState not found");
    let whitelist_signal = sse.whitelist;

    let new_cidr = create_rw_signal(String::new());
    let error = create_rw_signal(String::new());
    let loading = create_rw_signal(false);
    let adopting_cidr = create_rw_signal(String::new());

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
        let cidr_for_success = cidr.clone();
        let toast = toast_state;
        spawn_local(async move {
            match api::create_whitelist(&cidr).await {
                Ok(_) => {
                    new_cidr.set(String::new());
                    toast.success(format!("已添加 {cidr_for_success}"));
                }
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
        let toast = toast_state;
        spawn_local(async move {
            if let Err(e) = api::delete_whitelist(&cidr).await {
                toast.error(format!("移除失败：{e}"));
            }
        });
    };

    view! {
        <div class="whitelist-page">
            <PageHeader title="白名单管理" subtitle="信任地址与子网">
                <span class="badge badge-success badge-dot">
                    {move || format!("{}", whitelist_signal.get().map(|w| w.len()).unwrap_or(0))}
                </span>
            </PageHeader>

            <div class="card section-card">
                <div class="form-row">
                    <div class="form-field">
                        <label class="form-label">"CIDR 地址"</label>
                        <input class="input mono input-fill" placeholder="10.0.0.0/8 或 192.168.1.1"
                            prop:value=move || new_cidr.get()
                            on:input=move |e| new_cidr.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" type="button" on:click=do_add
                        disabled=move || loading.get()>
                        {move || if loading.get() { "添加中..." } else { "添加" }}
                    </button>
                    <span class="form-error">{move || error.get()}</span>
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
                        <div class="card section-card">
                            <div class="toolbar-row">
                                <h3 class="section-card-title" style="margin:0">
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
                                        let cidr2 = cidr.clone();
                                        let cidr3 = cidr.clone();
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
                                                        disabled=move || adopting_cidr.get() == cidr2
                                                        on:click={
                                                            move |_| {
                                                                let cidr = cidr.clone();
                                                                let toast = toast_state;
                                                                adopting_cidr.set(cidr.clone());
                                                                spawn_local(async move {
                                                                    match api::create_whitelist(&cidr).await {
                                                                        Ok(_) => toast.success(format!("已采纳 {cidr}")),
                                                                        Err(e) => toast.error(format!("采纳失败：{e}")),
                                                                    }
                                                                    adopting_cidr.set(String::new());
                                                                });
                                                            }
                                                        }>
                                                        {move || if adopting_cidr.get() == cidr3 { "采纳中..." } else { "采纳" }}
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
                            <EmptyState
                                title="白名单为空"
                                hint="白名单中的 IP/CIDR 不会被封禁。可添加本机或办公网等可信地址。"
                            />
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
