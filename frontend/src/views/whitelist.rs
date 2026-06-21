//! 白名单管理

use leptos::*;

use crate::api::{self, WhitelistEntry};

#[component]
pub fn Whitelist() -> impl IntoView {
    let entries = create_resource(|| (), |_| async { api::get_whitelist().await.ok() });

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
                <h2 class="section-title">"白名单管理"</h2>
            </div>

            // 添加表单
            <div class="card" style="padding:16px;margin-bottom:16px">
                <div style="display:flex;gap:8px;align-items:flex-end">
                    <div>
                        <label style="font-size:11px;color:var(--text-muted);display:block;margin-bottom:4px">
                            "CIDR 地址（如 10.0.0.0/8 或 192.168.1.1）"
                        </label>
                        <input class="input" placeholder="10.0.0.0/8"
                            style="width:260px"
                            prop:value=move || new_cidr.get()
                            on:input=move |e| new_cidr.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" on:click=do_add
                        disabled=move || loading.get()>
                        {move || if loading.get() { "添加中..." } else { "添加" }}
                    </button>
                    <span style="color:var(--accent-danger);font-size:12px">{move || error.get()}</span>
                </div>
            </div>

            // 白名单列表
            <div class="card">
                <Suspense fallback=|| view! { <div class="empty-state"><span>"加载中..."</span></div> }>
                    {move || {
                        let list = entries.get().flatten().unwrap_or_default();
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
                </Suspense>
            </div>
        </div>
    }
}
