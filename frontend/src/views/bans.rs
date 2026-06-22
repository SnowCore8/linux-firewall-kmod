//! 封禁管理 — 封禁原因分布 + 封禁趋势 + 表格 + 搜索 + 手动封禁

use leptos::*;

use crate::api::{self, BanResponse, StatsResponse};
use crate::charts::{LineChart, PieChart};
use crate::format::{format_datetime, format_duration};
use crate::sse;

#[component]
pub fn Bans() -> impl IntoView {
    let bans_signal = sse::use_sse_bans();
    let stats_signal = sse::use_sse_stats();

    // 分页状态
    let page = create_rw_signal(1_u32);
    const PAGE_SIZE: u32 = 20;
    let sort_by = create_rw_signal("banned_at_desc".to_string());
    let search = create_rw_signal(String::new());

    // 分页数据
    let paginated = create_resource(
        move || (page.get(), sort_by.get()),
        |(p, s)| async move { api::get_bans(p, PAGE_SIZE, Some(&s)).await.ok() },
    );

    // 搜索过滤
    let filtered_bans = move || {
        let kw = search.get().to_lowercase();
        if kw.is_empty() {
            return bans_signal.try_get().flatten().unwrap_or_default();
        }
        bans_signal
            .get()
            .unwrap_or_default()
            .into_iter()
            .filter(|b| {
                b.ip.to_lowercase().contains(&kw)
                    || b.jail.to_lowercase().contains(&kw)
                    || b.reason.to_lowercase().contains(&kw)
            })
            .collect::<Vec<_>>()
    };

    // 手动封禁表单
    let ban_ip = create_rw_signal(String::new());
    let ban_duration = create_rw_signal(String::new());
    let ban_error = create_rw_signal(String::new());
    let ban_loading = create_rw_signal(false);

    let do_ban = move |_| {
        let ip = ban_ip.get().trim().to_string();
        if ip.is_empty() {
            ban_error.set("IP 地址不能为空".to_string());
            return;
        }
        ban_loading.set(true);
        ban_error.set(String::new());
        let duration = ban_duration.get().parse::<u64>().ok();
        spawn_local(async move {
            match api::create_ban(&ip, duration, Some("API 手动封禁")).await {
                Ok(_) => {
                    ban_ip.set(String::new());
                    ban_duration.set(String::new());
                }
                Err(e) => ban_error.set(e),
            }
            ban_loading.set(false);
        });
    };

    let do_unban = move |ip: String| {
        spawn_local(async move {
            let _ = api::delete_ban(&ip).await;
        });
    };

    let total_pages = move || {
        paginated
            .get()
            .and_then(|p| p.as_ref().map(|p| p.total_pages))
            .unwrap_or(1)
    };

    let stats_default = move || StatsResponse::default();

    view! {
        <div class="bans-page">
            // 顶部统计
            <div class="dashboard-grid">
                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"封禁原因分布"</h3>
                    </div>
                    <div class="chart-body" style="height:180px">
                        <PieChart
                            labels=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).failure_reasons.labels
                            })
                            data=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).failure_reasons.values
                            })
                            size=180
                        />
                    </div>
                </div>

                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"封禁趋势 (24h)"</h3>
                    </div>
                    <div class="chart-body" style="height:180px">
                        <LineChart
                            labels=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).ban_trend.labels
                            })
                            data=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).ban_trend.values
                            })
                            color="var(--color-red)"
                            height=180
                        />
                    </div>
                </div>
            </div>

            // 工具栏
            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"封禁列表"</h2>
                    <span class="badge badge-danger badge-dot">
                        {move || format!("{}", bans_signal.try_get().flatten().map(|b| b.len()).unwrap_or(0))}
                    </span>
                </div>
                <div class="toolbar-right">
                    <input
                        class="input"
                        placeholder="搜索 IP / Jail / 原因..."
                        style="width:220px"
                        prop:value=move || search.get()
                        on:input=move |e| search.set(event_target_value(&e))
                    />
                </div>
            </div>

            // 手动封禁表单
            <div class="card" style="padding:14px">
                <div style="display:flex;gap:8px;align-items:flex-end;flex-wrap:wrap">
                    <div>
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">"IP 地址"</label>
                        <input class="input mono" placeholder="1.2.3.4"
                            style="width:160px"
                            prop:value=move || ban_ip.get()
                            on:input=move |e| ban_ip.set(event_target_value(&e))/>
                    </div>
                    <div>
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">"时长 (秒, 0=永久)"</label>
                        <input class="input mono" placeholder="600"
                            style="width:130px"
                            prop:value=move || ban_duration.get()
                            on:input=move |e| ban_duration.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" on:click=do_ban
                        disabled=move || ban_loading.get()>
                        {move || if ban_loading.get() { "封禁中..." } else { "封禁" }}
                    </button>
                    <span style="color:var(--color-red);font-size:11px">{move || ban_error.get()}</span>
                </div>
            </div>

            // 封禁表格
            <div class="card">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>"IP 地址"</th>
                                <th>"Jail"</th>
                                <th>"原因"</th>
                                <th>"封禁时间"</th>
                                <th>"剩余时间"</th>
                                <th>"操作"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For
                                each=filtered_bans
                                key=|b| b.ip.clone()
                                children=move |ban: BanResponse| {
                                    let ip = ban.ip.clone();
                                    view! {
                                        <tr>
                                            <td class="mono" style="font-weight:600;color:var(--text-primary)">{&ban.ip}</td>
                                            <td><span class="badge badge-info">{&ban.jail}</span></td>
                                            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{&ban.reason}</td>
                                            <td class="mono" style="font-size:11px;color:var(--text-muted)">{format_datetime(ban.banned_at)}</td>
                                            <td class="mono" style="font-size:11px">{format_duration(ban.remaining_seconds)}</td>
                                            <td>
                                                <button class="btn btn-sm btn-danger"
                                                    on:click=move |_| do_unban(ip.clone())>
                                                    "解封"
                                                </button>
                                            </td>
                                        </tr>
                                    }
                                }
                            />
                        </tbody>
                    </table>
                </div>

                <Suspense fallback=|| view! { <div style="padding:20px;text-align:center;color:var(--text-muted)">"加载中..."</div> }>
                    {move || {
                        let tp = total_pages();
                        if tp > 1 {
                            view! {
                                <div class="pagination">
                                    <button class="btn btn-sm" disabled=move || page.get() <= 1
                                        on:click=move |_| page.update(|p| *p = (*p).saturating_sub(1))>
                                        "上一页"
                                    </button>
                                    <span class="page-info">{move || format!("{} / {}", page.get(), total_pages())}</span>
                                    <button class="btn btn-sm" disabled=move || page.get() >= total_pages()
                                        on:click=move |_| page.update(|p| *p += 1)>
                                        "下一页"
                                    </button>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div/> }.into_view()
                        }
                    }}
                </Suspense>
            </div>
        </div>
    }
}
