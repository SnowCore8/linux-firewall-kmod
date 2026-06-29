//! 封禁管理 — 封禁原因分布 + 封禁趋势 + 表格 + 搜索 + 手动封禁 + 封禁详情

use leptos::*;

use crate::api::{self, BanDetailResponse, BanEffectivenessResponse, BanResponse, StatsResponse};
use crate::charts::{LineChart, PieChart};
use crate::format::{format_datetime, format_duration};
use crate::sse::SseState;
use crate::validation;

#[component]
pub fn Bans() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let bans_signal = sse.bans;
    let stats_signal = sse.stats;

    let page = create_rw_signal(1_u32);
    const PAGE_SIZE: u32 = 20;
    let sort_by = create_rw_signal("banned_at_desc".to_string());
    let search = create_rw_signal(String::new());

    // 封禁详情模态框状态
    let detail_ip = create_rw_signal(None::<String>);
    let detail_data = create_rw_signal(None::<BanDetailResponse>);
    let detail_loading = create_rw_signal(false);

    // 打开详情模态框
    let show_detail = move |ip: String| {
        detail_ip.set(Some(ip.clone()));
        detail_loading.set(true);
        detail_data.set(None);
        spawn_local(async move {
            match api::get_ban_detail(&ip).await {
                Ok(detail) => detail_data.set(Some(detail)),
                Err(_) => {}
            }
            detail_loading.set(false);
        });
    };

    // 关闭详情模态框
    let close_detail = move |_| {
        detail_ip.set(None);
        detail_data.set(None);
    };

    // 搜索变化时重置到第 1 页
    create_effect(move |_| {
        let _ = search.get();
        page.set(1);
    });

    // 过滤 + 排序 + 分页（纯客户端，实时跟随 SSE）
    let displayed_bans = create_memo(move |_| {
        let kw = search.get().to_lowercase();
        let sort_key = sort_by.get();
        let current_page = page.get();
        let mut bans = bans_signal.get().unwrap_or_default();

        // 过滤
        if !kw.is_empty() {
            bans = bans
                .into_iter()
                .filter(|b| {
                    b.ip.to_lowercase().contains(&kw)
                        || b.jail.to_lowercase().contains(&kw)
                        || b.reason.to_lowercase().contains(&kw)
                })
                .collect();
        }

        // 排序
        match sort_key.as_str() {
            "ip_asc" => bans.sort_by(|a, b| a.ip.cmp(&b.ip)),
            "ip_desc" => bans.sort_by(|a, b| b.ip.cmp(&a.ip)),
            "banned_at_asc" => bans.sort_by(|a, b| a.banned_at.cmp(&b.banned_at)),
            "remaining_asc" => bans.sort_by(|a, b| a.remaining_seconds.cmp(&b.remaining_seconds)),
            "remaining_desc" => bans.sort_by(|a, b| b.remaining_seconds.cmp(&a.remaining_seconds)),
            _ => bans.sort_by(|a, b| b.banned_at.cmp(&a.banned_at)),
        }

        // 分页
        let total = bans.len();
        let pages = ((total as f64) / (PAGE_SIZE as f64)).ceil().max(1.0) as u32;
        let start = ((current_page.saturating_sub(1)) * PAGE_SIZE) as usize;
        let end = (start + PAGE_SIZE as usize).min(total);
        let page_data = if start < total {
            bans[start..end].to_vec()
        } else {
            vec![]
        };

        (page_data, pages)
    });

    let filtered_bans = move || displayed_bans.get().0;

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
        if !validation::is_valid_ip(&ip) {
            ban_error.set("IP 地址格式无效(例如:192.168.1.1 或 ::1)".to_string());
            return;
        }
        let duration_str = ban_duration.get().trim().to_string();
        if !duration_str.is_empty() && !validation::is_valid_duration(&duration_str) {
            ban_error.set("时长范围无效(0-86400 秒,0或留空=永久)".to_string());
            return;
        }
        if let Some(list) = bans_signal.get() {
            if list.iter().any(|b| b.ip == ip) {
                ban_error.set("该 IP 已被封禁".to_string());
                return;
            }
        }
        ban_loading.set(true);
        ban_error.set(String::new());
        let duration = if duration_str.is_empty() {
            None
        } else {
            duration_str.parse::<u64>().ok()
        };
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
        let window = web_sys::window().expect("window not available");
        if !window
            .confirm_with_message(&format!("确定要解封 IP {} 吗?", ip))
            .unwrap_or(false)
        {
            return;
        }
        spawn_local(async move {
            if let Err(e) = api::delete_ban(&ip).await {
                let _ = web_sys::window()
                    .and_then(|w| w.alert_with_message(&format!("解封失败：{e}")).ok());
            }
        });
    };

    let total_pages = move || displayed_bans.get().1;

    // 封禁效果分析
    let effectiveness_res = create_resource(
        || (),
        |_| async {
            api::get_ban_effectiveness()
                .await
                .unwrap_or(BanEffectivenessResponse {
                    levels: Vec::new(),
                    total_unique_ips: 0,
                    overall_recidivism_rate: 0.0,
                    summary: String::new(),
                })
        },
    );

    // 封禁时长推荐
    let duration_recs_res = create_resource(
        || (),
        |_| async {
            api::get_ban_duration_recommendations().await.unwrap_or(
                api::BanDurationRecommendationResponse {
                    recommendations: vec![],
                    summary: String::new(),
                },
            )
        },
    );

    // 周期性攻击者检测
    let periodic_res = create_resource(
        || (),
        |_| async { api::get_periodic_attackers().await.unwrap_or_default() },
    );

    // 协同攻击检测
    let collab_res = create_resource(
        || (),
        |_| async { api::get_collaborative_attacks().await.unwrap_or_default() },
    );

    // 封禁时长分布直方图
    let histogram_res = create_resource(
        || (),
        |_| async {
            api::get_ban_duration_histogram()
                .await
                .unwrap_or(api::BanDurationHistogramResponse {
                    labels: Vec::new(),
                    counts: Vec::new(),
                    total: 0,
                })
        },
    );

    // IP 信誉分列表
    let reputation_res = create_resource(
        || (),
        |_| async { api::get_reputation().await.unwrap_or_default() },
    );

    // 攻击源网络分布
    let network_res = create_resource(
        || (),
        |_| async { api::get_network_distribution().await.unwrap_or_default() },
    );

    let stats_default = move || StatsResponse::default();

    view! {
        <div class="bans-page">
            <div class="dashboard-grid">
                <div class="card chart-card">
                    <div class="chart-header"><h3>"封禁原因分布"</h3></div>
                    <div class="chart-body" style="height:180px">
                        <PieChart
                            labels=Signal::derive(move || {
                                let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                let mut pairs: Vec<_> = s.failure_reasons.labels.into_iter()
                                    .zip(s.failure_reasons.values.into_iter())
                                    .collect();
                                pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                                pairs.into_iter().map(|(l, _)| l).collect()
                            })
                            data=Signal::derive(move || {
                                let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                let mut pairs: Vec<_> = s.failure_reasons.labels.into_iter()
                                    .zip(s.failure_reasons.values.into_iter())
                                    .collect();
                                pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                                pairs.into_iter().map(|(_, v)| v).collect()
                            })
                            size=180
                        />
                    </div>
                </div>
                <div class="card chart-card">
                    <div class="chart-header"><h3>"封禁趋势 (24h)"</h3></div>
                    <div class="chart-body" style="height:180px">
                        <LineChart
                            labels=Signal::derive(move || stats_signal.get().unwrap_or_else(|| stats_default()).ban_trend.labels)
                            data=Signal::derive(move || stats_signal.get().unwrap_or_else(|| stats_default()).ban_trend.values)
                            color="var(--color-red)"
                            height=180
                        />
                    </div>
                </div>
            </div>

            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"封禁列表"</h2>
                    <span class="badge badge-danger badge-dot">
                        {move || format!("{}", bans_signal.get().map(|b| b.len()).unwrap_or(0))}
                    </span>
                </div>
                <div class="toolbar-right">
                    <select class="input" style="width:140px;margin-right:8px"
                        prop:value=move || sort_by.get()
                        on:change=move |e| sort_by.set(event_target_value(&e))>
                        <option value="banned_at_desc">"封禁时间 ↓"</option>
                        <option value="banned_at_asc">"封禁时间 ↑"</option>
                        <option value="ip_asc">"IP 地址 A-Z"</option>
                        <option value="ip_desc">"IP 地址 Z-A"</option>
                        <option value="remaining_asc">"剩余时间 ↑"</option>
                        <option value="remaining_desc">"剩余时间 ↓"</option>
                    </select>
                    <input class="input" placeholder="搜索 IP / Jail / 原因..."
                        style="width:220px"
                        prop:value=move || search.get()
                        on:input=move |e| search.set(event_target_value(&e))/>
                </div>
            </div>

            <div class="card" style="padding:14px">
                <div style="display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;max-width:600px">
                    <div style="flex:1;min-width:120px">
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">"IP 地址"</label>
                        <input class="input mono" placeholder="1.2.3.4" style="width:100%"
                            prop:value=move || ban_ip.get()
                            on:input=move |e| ban_ip.set(event_target_value(&e))/>
                    </div>
                    <div style="flex:1;min-width:100px">
                        <label style="font-size:9px;color:var(--text-muted);display:block;margin-bottom:4px;font-weight:700;text-transform:uppercase;letter-spacing:0.1em">"时长 (秒, 留空=永久)"</label>
                        <input class="input mono" placeholder="0" style="width:100%"
                            prop:value=move || ban_duration.get()
                            on:input=move |e| ban_duration.set(event_target_value(&e))/>
                    </div>
                    <button class="btn btn-primary" on:click=do_ban
                        disabled=move || ban_loading.get()
                        style="flex-shrink:0;height:36px">
                        {move || if ban_loading.get() { "封禁中..." } else { "封禁" }}
                    </button>
                    <span style="color:var(--color-red);font-size:11px;flex-shrink:0">{move || ban_error.get()}</span>
                </div>
            </div>

            <div class="card">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:16%">"IP 地址"</th>
                                <th style="width:10%">"Jail"</th>
                                <th style="width:16%">"原因"</th>
                                <th style="width:6%">"次数"</th>
                                <th style="width:12%">"封禁时间"</th>
                                <th style="width:12%">"剩余时间"</th>
                                <th style="width:18%">"操作"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each=filtered_bans key=|b| format!("{}:{}", b.ip, b.jail)
                                children=move |ban: BanResponse| {
                                    let ip = ban.ip.clone();
                                    let jail = ban.jail.clone();
                                    let ip2 = ip.clone();
                                    let ip3 = ip.clone();
                                    let ban_count = ban.ban_count;
                                    let is_permanent = ban.is_permanent;
                                    // 从 signal 读取最新 remaining_seconds，SSE 推送时自动刷新
                                    let remaining_seconds = Signal::derive(move || {
                                        bans_signal
                                            .get()
                                            .unwrap_or_default()
                                            .into_iter()
                                            .find(|b| b.ip == ip && b.jail == jail)
                                            .map(|b| b.remaining_seconds)
                                            .unwrap_or(0)
                                    });
                                    let remaining_display = move || {
                                        if is_permanent {
                                            return "永久".to_string();
                                        }
                                        let r = remaining_seconds.get();
                                        if r == -1 {
                                            "永久".to_string()
                                        } else if r <= 0 {
                                            "0s".to_string()
                                        } else {
                                            format_duration(r)
                                        }
                                    };
                                    // 复发次数颜色：1=正常, 2=橙色, 3+=红色
                                    let count_color = if ban_count >= 3 { "var(--color-red)" }
                                        else if ban_count >= 2 { "var(--color-orange)" }
                                        else { "var(--text-muted)" };
                                    // 威胁等级指示器：永久=红, ×3+=橙, ×2=黄, 其他=灰
                                    let threat_dot = if is_permanent { "var(--color-red)" }
                                        else if ban_count >= 3 { "var(--color-orange)" }
                                        else if ban_count >= 2 { "var(--color-yellow, #eab308)" }
                                        else { "transparent" };
                                    view! {
                                        <tr>
                                            <td class="mono" style="font-weight:600;color:var(--text-primary)">
                                                <span style=move || format!("display:inline-block;width:8px;height:8px;border-radius:50%;background:{};margin-right:6px;vertical-align:middle", threat_dot)></span>
                                                {&ban.ip}
                                            </td>
                                            <td><span class="badge badge-info">{&ban.jail}</span></td>
                                            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{&ban.reason}</td>
                                            <td class="mono" style=move || format!("font-weight:700;color:{}", count_color)>
                                                {move || format!("×{}", ban_count)}
                                            </td>
                                            <td class="mono" style="font-size:11px;color:var(--text-muted)">{format_datetime(ban.banned_at)}</td>
                                            <td class="mono" style=move || format!("font-size:11px;{}", if is_permanent { "color:var(--color-red);font-weight:700" } else { "" })>
                                                {remaining_display}
                                            </td>
                                            <td>
                                                <div style="display:flex;gap:4px">
                                                    <button class="btn btn-sm"
                                                        style="border-color:var(--border-strong)"
                                                        on:click=move |_| show_detail(ip3.clone())>
                                                        "详情"
                                                    </button>
                                                    <button class="btn btn-sm btn-danger"
                                                        on:click=move |_| do_unban(ip2.clone())>
                                                        "解封"
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    }
                                }/>
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

            // 封禁效果分析面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载封禁效果分析..."</div> }>
                {move || effectiveness_res.get().map(|eff| {
                    if eff.levels.is_empty() {
                        return view! { <div class="card" style="padding:16px;text-align:center;color:var(--text-muted)">"暂无封禁效果分析数据" </div> }.into_view();
                    }
                    let summary_color = if eff.overall_recidivism_rate > 50.0 {
                        "var(--color-red)"
                    } else if eff.overall_recidivism_rate > 30.0 {
                        "var(--color-orange)"
                    } else {
                        "var(--color-green)"
                    };
                    view! {
                        <div class="card effectiveness-card">
                            <div class="chart-header">
                                <h3>"封禁效果分析"</h3>
                                <span class="badge" style=move || format!("background:{};color:#fff", summary_color)>
                                    {move || format!("总复发率 {:.1}%", eff.overall_recidivism_rate)}
                                </span>
                            </div>
                            <div class="effectiveness-grid">
                                {eff.levels.iter().map(|level| {
                                    let level_color = match level.level {
                                        1 => "var(--color-green)",
                                        2 => "var(--color-yellow, #eab308)",
                                        3 => "var(--color-orange)",
                                        _ => "var(--color-red)",
                                    };
                                    let rate_color = if level.recidivism_rate > 50.0 {
                                        "var(--color-red)"
                                    } else if level.recidivism_rate > 30.0 {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-green)"
                                    };
                                    view! {
                                        <div class="effectiveness-level">
                                            <div class="level-header" style=move || format!("border-left:3px solid {}", level_color)>
                                                <span class="level-label">{level.label.clone()}</span>
                                                <span class="level-ips">{format!("{} IP", level.total_ips)}</span>
                                            </div>
                                            <div class="level-stats">
                                                <div class="stat-row">
                                                    <span class="stat-label">"复发率"</span>
                                                    <span class="stat-value" style=move || format!("color:{}", rate_color)>
                                                        {format!("{:.1}%", level.recidivism_rate)}
                                                    </span>
                                                </div>
                                                <div class="stat-row">
                                                    <span class="stat-label">"复发 IP"</span>
                                                    <span class="stat-value">{format!("{}/{}", level.recidivist_ips, level.total_ips)}</span>
                                                </div>
                                                <div class="stat-row">
                                                    <span class="stat-label">"永久封禁"</span>
                                                    <span class="stat-value" style="color:var(--color-red)">{level.permanent_bans}</span>
                                                </div>
                                            </div>
                                            <div class="level-verdict">{level.verdict.clone()}</div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                            <div class="effectiveness-summary">{eff.summary.clone()}</div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 封禁时长推荐面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载封禁时长推荐..."</div> }>
                {move || duration_recs_res.get().map(|recs| {
                    if recs.recommendations.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let needs_adj = recs.recommendations.iter().filter(|r| r.needs_adjustment).count();
                    let summary_color = if needs_adj > 0 { "var(--color-orange)" } else { "var(--color-green)" };
                    view! {
                        <div class="card">
                            <div class="chart-header">
                                <h3>"封禁时长推荐"</h3>
                                <span class="badge" style=move || format!("background:{};color:#fff", summary_color)>
                                    {if needs_adj > 0 {
                                        format!("{} 个 Jail 建议调整", needs_adj)
                                    } else {
                                        "全部达标".to_string()
                                    }}
                                </span>
                            </div>
                            <div style="display:grid;gap:8px;padding:12px 16px;">
                                {recs.recommendations.iter().map(|rec| {
                                    let status_color = if rec.needs_adjustment { "var(--color-orange)" } else { "var(--color-green)" };
                                    let current_str = if rec.current_ban_time == -1 {
                                        "永久".to_string()
                                    } else if rec.current_ban_time >= 86400 {
                                        format!("{}天", rec.current_ban_time / 86400)
                                    } else if rec.current_ban_time >= 3600 {
                                        format!("{}小时", rec.current_ban_time / 3600)
                                    } else {
                                        format!("{}分钟", rec.current_ban_time / 60)
                                    };
                                    let recommended_str = if rec.recommended_ban_time >= 86400 {
                                        format!("{}天", rec.recommended_ban_time / 86400)
                                    } else if rec.recommended_ban_time >= 3600 {
                                        format!("{}小时", rec.recommended_ban_time / 3600)
                                    } else {
                                        format!("{}分钟", rec.recommended_ban_time / 60)
                                    };
                                    let median_str = if rec.median_return_secs >= 86400 {
                                        format!("{:.1}天", rec.median_return_secs as f64 / 86400.0)
                                    } else if rec.median_return_secs >= 3600 {
                                        format!("{:.1}小时", rec.median_return_secs as f64 / 3600.0)
                                    } else {
                                        format!("{}分钟", rec.median_return_secs / 60)
                                    };
                                    view! {
                                        <div style="display:grid;grid-template-columns:100px 1fr 120px 80px;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-color);">
                                            <span class="mono" style="font-weight:600">{rec.jail_name.clone()}</span>
                                            <span style="font-size:12px;color:var(--text-secondary)">{rec.reason.clone()}</span>
                                            <span class="mono" style="font-size:12px;">
                                                {format!("{} → ", current_str)}
                                                <span style=move || format!("color:{};font-weight:600", status_color)>
                                                    {recommended_str.clone()}
                                                </span>
                                            </span>
                                            <span class="mono" style=move || format!("font-size:11px;color:{}", status_color)>
                                                {format!("中位{}{}", median_str, if rec.needs_adjustment { " ⚠" } else { " ✓" })}
                                            </span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                            <div style="padding:8px 16px;font-size:12px;color:var(--text-secondary)">{recs.summary.clone()}</div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // IP 信誉分面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载信誉分..."</div> }>
                {move || reputation_res.get().map(|entries| {
                    if entries.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let low_count = entries.iter().filter(|e| e.score < 80).count();
                    let critical_count = entries.iter().filter(|e| e.score < 50).count();
                    view! {
                        <div class="card">
                            <div class="chart-header">
                                <h3>"IP 信誉分"</h3>
                                <span class="badge" style=move || format!("background:{};color:#fff", if critical_count > 0 { "var(--color-red)" } else if low_count > 0 { "var(--color-orange)" } else { "var(--color-green)" })>
                                    {format!("{} 个低信誉", low_count)}
                                </span>
                            </div>
                            <div style="display:grid;gap:4px;padding:12px 16px;font-size:12px;">
                                <div style="display:grid;grid-template-columns:1fr 60px 70px 70px 60px;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-color);font-weight:600;color:var(--text-secondary);font-size:11px;">
                                    <span>"IP"</span>
                                    <span style="text-align:center">"分数"</span>
                                    <span style="text-align:center">"失败"</span>
                                    <span style="text-align:center">"封禁"</span>
                                    <span style="text-align:center">"乘数"</span>
                                </div>
                                {entries.iter().take(20).map(|entry| {
                                    let score_color = if entry.score >= 80 {
                                        "var(--color-green)"
                                    } else if entry.score >= 50 {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-red)"
                                    };
                                    let bar_width = entry.score;
                                    view! {
                                        <div style="display:grid;grid-template-columns:1fr 60px 70px 70px 60px;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid var(--border-color);">
                                            <span class="mono" style="font-size:12px">{entry.ip.clone()}</span>
                                            <div style="position:relative;height:18px;background:var(--bg-secondary);border-radius:3px;overflow:hidden;">
                                                <div style=move || format!("position:absolute;left:0;top:0;bottom:0;width:{}%;background:{};opacity:0.3;", bar_width, score_color)></div>
                                                <span class="mono" style=move || format!("position:relative;z-index:1;display:flex;align-items:center;justify-content:center;height:100%;font-size:11px;font-weight:600;color:{}", score_color)>
                                                    {entry.score}
                                                </span>
                                            </div>
                                            <span class="mono" style="text-align:center;color:var(--text-secondary)">{entry.total_failures}</span>
                                            <span class="mono" style="text-align:center;color:var(--text-secondary)">{entry.total_bans}</span>
                                            <span class="mono" style=move || format!("text-align:center;color:{};font-weight:600", score_color)>
                                                {format!("×{:.1}", entry.threshold_multiplier)}
                                            </span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                            <div style="padding:8px 16px;font-size:11px;color:var(--text-muted)">
                                "初始 100 分，每次失败 -10，每次封禁 -10。≥80 正常，50-79 略严（×0.8），<50 严格（×0.5）。每小时无失败 +1 恢复。"
                            </div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 攻击源网络分布面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载网络分布..."</div> }>
                {move || network_res.get().map(|blocks| {
                    if blocks.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let total_ips: u32 = blocks.iter().map(|b| b.unique_ips).sum();
                    let total_bans: u32 = blocks.iter().map(|b| b.total_bans).sum();
                    view! {
                        <div class="card">
                            <div class="chart-header">
                                <h3>"攻击源网络分布"</h3>
                                <span class="badge" style="background:var(--color-blue, #3b82f6);color:#fff">
                                    {format!("{} 子网 · {} IP · {} 封禁", blocks.len(), total_ips, total_bans)}
                                </span>
                            </div>
                            <div style="display:grid;gap:4px;padding:12px 16px;font-size:12px;">
                                <div style="display:grid;grid-template-columns:120px 60px 60px 1fr 80px;gap:8px;padding:4px 0;border-bottom:1px solid var(--border-color);font-weight:600;color:var(--text-secondary);font-size:11px;">
                                    <span>"子网"</span>
                                    <span style="text-align:center">"IP数"</span>
                                    <span style="text-align:center">"封禁"</span>
                                    <span>"占比"</span>
                                    <span style="text-align:right">"代表IP"</span>
                                </div>
                                {blocks.iter().take(20).map(|block| {
                                    let ratio = if total_bans > 0 {
                                        block.total_bans as f64 / total_bans as f64 * 100.0
                                    } else {
                                        0.0
                                    };
                                    let bar_color = if block.unique_ips >= 5 {
                                        "var(--color-red)"
                                    } else if block.unique_ips >= 3 {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-blue, #3b82f6)"
                                    };
                                    view! {
                                        <div style="display:grid;grid-template-columns:120px 60px 60px 1fr 80px;gap:8px;align-items:center;padding:4px 0;border-bottom:1px solid var(--border-color);">
                                            <span class="mono" style="font-size:12px;font-weight:500">{block.subnet.clone()}<span style="color:var(--text-muted);font-size:10px">"/24"</span></span>
                                            <span class="mono" style=move || format!("text-align:center;color:{}", bar_color)>{block.unique_ips}</span>
                                            <span class="mono" style="text-align:center">{block.total_bans}</span>
                                            <div style="position:relative;height:14px;background:var(--bg-secondary);border-radius:2px;overflow:hidden;">
                                                <div style=move || format!("height:100%;width:{:.1}%;background:{};opacity:0.6;", ratio, bar_color)></div>
                                                <span class="mono" style="position:absolute;left:4px;top:0;font-size:10px;line-height:14px;color:var(--text-primary)">{format!("{:.1}%", ratio)}</span>
                                            </div>
                                            <span class="mono" style="text-align:right;font-size:11px;color:var(--text-secondary)">{block.top_ip.clone()}</span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                            <div style="padding:8px 16px;font-size:11px;color:var(--text-muted)">
                                "按 /24 子网分组，颜色编码：红色（≥5 IP 集中攻击）/ 橙色（3-4 IP）/ 蓝色（1-2 IP）。数据窗口：近 7 天。"
                            </div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 周期性攻击者检测面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载周期性攻击检测..."</div> }>
                {move || periodic_res.get().map(|attackers| {
                    if attackers.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    view! {
                        <div class="card periodic-card">
                            <div class="chart-header">
                                <h3>"周期性攻击者"</h3>
                                <span class="badge badge-warning">{format!("{} 个", attackers.len())}</span>
                            </div>
                            <div class="periodic-list">
                                {attackers.iter().map(|attacker| {
                                    let score_color = if attacker.periodicity_score >= 70 {
                                        "var(--color-red)"
                                    } else if attacker.periodicity_score >= 50 {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-yellow, #eab308)"
                                    };
                                    let interval_str = if attacker.avg_interval_secs > 86400.0 {
                                        format!("{:.1} 天", attacker.avg_interval_secs / 86400.0)
                                    } else if attacker.avg_interval_secs > 3600.0 {
                                        format!("{:.1} 小时", attacker.avg_interval_secs / 3600.0)
                                    } else {
                                        format!("{:.0} 分钟", attacker.avg_interval_secs / 60.0)
                                    };
                                    let jitter = if attacker.avg_interval_secs > 0.0 {
                                        (attacker.interval_stddev / attacker.avg_interval_secs * 100.0) as u32
                                    } else { 0 };
                                    view! {
                                        <div class="periodic-item">
                                            <div class="periodic-main">
                                                <span class="periodic-ip mono">{&attacker.ip}</span>
                                                <span class="badge badge-info">{&attacker.jail_name}</span>
                                                <span class="periodic-badge" style=move || format!("background:{}", score_color)>
                                                    {format!("规律度 {}%", attacker.periodicity_score)}
                                                </span>
                                            </div>
                                            <div class="periodic-stats">
                                                <span class="periodic-stat">{format!("×{} 封禁", attacker.ban_count)}</span>
                                                <span class="periodic-sep">"·"</span>
                                                <span class="periodic-stat">{format!("间隔 {}", interval_str)}</span>
                                                <span class="periodic-sep">"·"</span>
                                                <span class="periodic-stat">{format!("抖动 {}%", jitter)}</span>
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 协同攻击检测面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载协同攻击检测..."</div> }>
                {move || collab_res.get().map(|attacks| {
                    if attacks.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    view! {
                        <div class="card collab-card">
                            <div class="chart-header">
                                <h3>"协同攻击检测"</h3>
                                <span class="badge badge-danger">{format!("{} 次", attacks.len())}</span>
                            </div>
                            <div class="collab-list">
                                {attacks.iter().map(|attack| {
                                    let score_color = if attack.correlation_score >= 70 {
                                        "var(--color-red)"
                                    } else if attack.correlation_score >= 40 {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-yellow, #eab308)"
                                    };
                                    let duration_mins = (attack.window_end - attack.window_start) / 60;
                                    view! {
                                        <div class="collab-item">
                                            <div class="collab-main">
                                                <span class="badge badge-info">{&attack.jail_name}</span>
                                                <span class="collab-badge" style=move || format!("background:{}", score_color)>
                                                    {format!("协同度 {}%", attack.correlation_score)}
                                                </span>
                                            </div>
                                            <div class="collab-stats">
                                                <span class="collab-stat">{format!("{} IP", attack.ip_count)}</span>
                                                <span class="collab-sep">"·"</span>
                                                <span class="collab-stat">{format!("{} 次封禁", attack.total_bans)}</span>
                                                <span class="collab-sep">"·"</span>
                                                <span class="collab-stat">{format!("持续 {} 分钟", duration_mins)}</span>
                                                <span class="collab-sep">"·"</span>
                                                <span class="collab-stat">{format_datetime(attack.window_start)}</span>
                                            </div>
                                            <div class="collab-ips">
                                                {attack.ips.iter().take(5).map(|ip| {
                                                    view! {
                                                        <span class="collab-ip mono">{ip}</span>
                                                    }
                                                }).collect_view()}
                                                {if attack.ips.len() > 5 {
                                                    view! { <span class="collab-ip-more">{format!("等 {} 个 IP", attack.ips.len())}</span> }.into_view()
                                                } else {
                                                    view! { <div/> }.into_view()
                                                }}
                                            </div>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 封禁时长分布直方图
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载封禁时长分布..."</div> }>
                {move || histogram_res.get().map(|hist| {
                    if hist.total == 0 {
                        return view! { <div/> }.into_view();
                    }
                    let max_count = hist.counts.iter().copied().max().unwrap_or(1);
                    view! {
                        <div class="card histogram-card">
                            <div class="chart-header">
                                <h3>"封禁时长分布"</h3>
                                <span class="badge badge-info">{format!("共 {} 次", hist.total)}</span>
                            </div>
                            <div class="histogram-bars">
                                {hist.labels.iter().zip(hist.counts.iter()).map(|(label, count)| {
                                    let count = *count;
                                    let pct = if max_count > 0 { (count as f64 / max_count as f64 * 100.0) as u32 } else { 0 };
                                    let bar_color = if label.contains("60s") {
                                        "var(--color-green)"
                                    } else if label.contains("5min") {
                                        "var(--color-yellow, #eab308)"
                                    } else if label.contains("1h") {
                                        "var(--color-orange)"
                                    } else {
                                        "var(--color-red)"
                                    };
                                    view! {
                                        <div class="histogram-bar-row">
                                            <span class="histogram-label">{label}</span>
                                            <div class="histogram-bar-bg">
                                                <div class="histogram-bar-fill" style=move || format!("width:{}%; background:{}", pct, bar_color)/>
                                            </div>
                                            <span class="histogram-count mono">{count}</span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                        </div>
                    }.into_view()
                })}
            </Suspense>

            // 封禁详情模态框
            <Show when=move || detail_ip.get().is_some()>
                <div class="modal-overlay" on:click=close_detail>
                    <div class="modal ban-detail-modal" on:click=move |e| e.stop_propagation()>
                        <div class="modal-header">
                            <h3>"封禁详情"</h3>
                            <button class="btn btn-icon" on:click=close_detail>"✕"</button>
                        </div>
                        <Show
                            when=move || !detail_loading.get()
                            fallback=|| view! { <div class="modal-body">"加载中..."</div> }
                        >
                            {move || {
                                detail_data.get().map(|detail| {
                                    let status_class = if detail.is_banned { "badge-danger" } else { "badge-success" };
                                    let status_text = if detail.is_banned { "封禁中" } else { "已解封" };
                                    view! {
                                        <div class="modal-body">
                                            <div class="detail-grid">
                                                <div class="detail-row">
                                                    <span class="detail-label">"IP 地址"</span>
                                                    <span class="detail-value mono">{detail.ip.clone()}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"状态"</span>
                                                    <span class=move || format!("badge {}", status_class)>{status_text}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"Jail"</span>
                                                    <span class="detail-value">{if detail.jail_name.is_empty() { "N/A".to_string() } else { detail.jail_name.clone() }}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"封禁原因"</span>
                                                    <span class="detail-value">{if detail.reason.is_empty() { "N/A".to_string() } else { detail.reason.clone() }}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"封禁时间"</span>
                                                    <span class="detail-value mono">{if detail.banned_at > 0 { format_datetime(detail.banned_at) } else { "N/A".to_string() }}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"过期时间"</span>
                                                    <span class="detail-value mono">{if detail.is_permanent { "永久".to_string() } else if detail.expires_at > 0 { format_datetime(detail.expires_at) } else { "N/A".to_string() }}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"失败次数"</span>
                                                    <span class="detail-value mono">{detail.fail_count}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"累计封禁"</span>
                                                    <span class="detail-value mono" style=move || format!("color:{}", if detail.ban_count >= 3 { "var(--color-red)" } else if detail.ban_count >= 2 { "var(--color-orange)" } else { "var(--text-primary)" })>
                                                        {format!("×{}", detail.ban_count)}
                                                    </span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"上次解封"</span>
                                                    <span class="detail-value mono">{if detail.last_unbanned_at > 0 { format_datetime(detail.last_unbanned_at) } else if detail.is_banned { "当前在封禁中".to_string() } else { "N/A".to_string() }}</span>
                                                </div>
                                            </div>
                                            <div class="detail-section">
                                                <h4>"渐进式封禁决策"</h4>
                                                <div class="detail-row">
                                                    <span class="detail-label">"封禁等级"</span>
                                                    <span class="detail-value">{detail.progressive_level.clone()}</span>
                                                </div>
                                                <div class="detail-row">
                                                    <span class="detail-label">"下次封禁时长"</span>
                                                    <span class="detail-value mono">{detail.next_ban_duration.clone()}</span>
                                                </div>
                                            </div>
                                            // IP 信誉分
                                            <div class="detail-section">
                                                <h4>"IP 信誉分"</h4>
                                                {
                                                    let score = detail.reputation_score;
                                                    let (score_color, score_label) = if score >= 80 {
                                                        ("var(--color-green, #22c55e)", "良好")
                                                    } else if score >= 50 {
                                                        ("var(--color-orange)", "可疑")
                                                    } else {
                                                        ("var(--color-red)", "高危")
                                                    };
                                                    view! {
                                                        <div class="detail-row">
                                                            <span class="detail-label">"信誉评分"</span>
                                                            <span class="detail-value mono" style=move || format!("color:{};font-weight:700;", score_color)>
                                                                {format!("{} / 100 ({})", score, score_label)}
                                                            </span>
                                                        </div>
                                                        <div class="detail-row">
                                                            <span class="detail-label">"阈值乘数"</span>
                                                            <span class="detail-value mono">{format!("×{}", detail.reputation_multiplier)}</span>
                                                        </div>
                                                    }
                                                }
                                            </div>
                                            // 封禁决策路径
                                            <div class="detail-section">
                                                <h4>"决策路径"</h4>
                                                <div style="display:flex;flex-direction:column;gap:0;margin-top:8px;">
                                                    {
                                                        let is_ddos = detail.reason.contains("flood") || detail.reason.contains("DDoS") || detail.reason.contains("rate") || detail.jail_name.is_empty();
                                                        let jail_display = if detail.jail_name.is_empty() { "内核自动封禁".to_string() } else { detail.jail_name.clone() };
                                                        let threshold_display = if is_ddos { "速率超阈值".to_string() } else { format!("失败 {} 次", detail.fail_count) };
                                                        let level_color = if detail.ban_count >= 4 { "var(--color-red)" } else if detail.ban_count >= 3 { "var(--color-orange)" } else { "var(--color-yellow, #eab308)" };
                                                        let decision_color = if detail.is_permanent { "var(--color-red)" } else { "var(--color-orange)" };
                                                        let decision_text = if detail.is_permanent { "永久封禁".to_string() } else { "临时封禁".to_string() };
                                                        let detect_text = if is_ddos { "DDoS 速率检测".to_string() } else { "日志正则匹配".to_string() };
                                                        let steps: Vec<(String, String, String, String)> = vec![
                                                            ("1".into(), "流量检测".into(), detect_text, "var(--color-cyan)".into()),
                                                            ("2".into(), "Jail 匹配".into(), jail_display, "var(--color-blue, #3b82f6)".into()),
                                                            ("3".into(), "阈值判定".into(), threshold_display, "var(--color-orange)".into()),
                                                            ("4".into(), "渐进等级".into(), detail.progressive_level.clone(), level_color.into()),
                                                            ("5".into(), "封禁决策".into(), decision_text, decision_color.into()),
                                                        ];
                                                        let total = steps.len();
                                                        steps.into_iter().enumerate().map(move |(i, (num, label, value, color))| {
                                                            let is_last = i == total - 1;
                                                            let circle_style = format!("width:24px;height:24px;border-radius:50%;background:{};color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;", color);
                                                            let value_style = format!("font-size:13px;color:{}", color);
                                                            let pad_bottom = if is_last { "0px" } else { "8px" };
                                                            let pad_style = format!("padding-bottom:{};", pad_bottom);
                                                            view! {
                                                                <div style="display:flex;align-items:flex-start;gap:10px;">
                                                                    <div style="display:flex;flex-direction:column;align-items:center;min-width:24px;">
                                                                        <div style=circle_style>
                                                                            {move || num.clone()}
                                                                        </div>
                                                                        {if !is_last {
                                                                            view! { <div style="width:2px;height:20px;background:var(--border-color);"/> }
                                                                        } else {
                                                                            view! { <div/> }
                                                                        }}
                                                                    </div>
                                                                    <div style=pad_style>
                                                                        <div style="font-size:11px;color:var(--text-secondary)">{move || label.clone()}</div>
                                                                        <div class="mono" style=value_style>{move || value.clone()}</div>
                                                                    </div>
                                                                </div>
                                                            }
                                                        }).collect_view()
                                                    }
                                                </div>
                                            </div>
                                        </div>
                                    }.into_view()
                                }).unwrap_or_else(|| view! { <div class="modal-body">"加载失败"</div> }.into_view())
                            }}
                        </Show>
                    </div>
                </div>
            </Show>
        </div>
    }
}
