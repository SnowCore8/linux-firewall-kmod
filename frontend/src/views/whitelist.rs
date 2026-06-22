//! 白名单管理 — SSE 实时更新 + 设备信息

use leptos::*;

use crate::api::{self, WhitelistEntry};
use crate::sse;

#[component]
pub fn Whitelist() -> impl IntoView {
    let whitelist_signal = sse::use_sse_whitelist();

    let new_cidr = create_rw_signal(String::new());
    let error = create_rw_signal(String::new());
    let loading = create_rw_signal(false);

    let do_add = move |_| {
        let cidr = new_cidr.get().trim().to_string();
        if cidr.is_empty() {
            error.set("CIDR 不能为空".to_string());
            return;
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
        spawn_local(async move {
            let _ = api::delete_whitelist(&cidr).await;
        });
    };

    view! {
        <div class="whitelist-page">
            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"白名单管理"</h2>
                    <span class="badge badge-success badge-dot">
                        {move || format!("{}", whitelist_signal.try_get().flatten().map(|w| w.len()).unwrap_or(0))}
                    </span>
                </div>
            </div>

            // 添加表单
            <div class="card" style="padding:14px">
                <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
                    <div>
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">
                            "CIDR 地址"
                        </label>
                        <input class="input mono" placeholder="10.0.0.0/8 或 192.168.1.1"
                            style="width:280px"
                            prop:value=move || new_cidr.get()
                            on:input=move |e| new_cidr.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" on:click=do_add
                        disabled=move || loading.get()>
                        {move || if loading.get() { "添加中..." } else { "添加" }}
                    </button>
                    <span style="color:var(--color-red);font-size:11px">{move || error.get()}</span>
                </div>
            </div>

            // 白名单列表
            <div class="card">
                {move || {
                    let list = whitelist_signal.try_get().flatten().unwrap_or_default();
                    if list.is_empty() {
                        return view! {
                            <div class="empty-state">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M9 12l2 2 4-4"/>
                                    <circle cx="12" cy="12" r="10"/>
                                </svg>
                                <span>"白名单为空"</span>
                            </div>
                        }.into_view();
                    }
                    view! {
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>"CIDR"</th>
                                        <th>"设备"</th>
                                        <th>"操作"</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <For
                                        each=move || list.clone()
                                        key=|e| e.cidr.clone()
                                        children=move |entry: WhitelistEntry| {
                                            let cidr = entry.cidr.clone();
                                            view! {
                                                <tr>
                                                    <td class="mono" style="font-weight:600;color:var(--text-primary)">
                                                        {&entry.cidr}
                                                    </td>
                                                    <td style="color:var(--text-muted)">{&entry.device}</td>
                                                    <td>
                                                        <button class="btn btn-sm btn-danger"
                                                            on:click=move |_| do_remove(cidr.clone())>
                                                            "移除"
                                                        </button>
                                                    </td>
                                                </tr>
                                            }
                                        }
                                    />
                                </tbody>
                            </table>
                        </div>
                    }.into_view()
                }}
            </div>
        </div>
    }
}
