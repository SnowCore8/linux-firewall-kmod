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

    // 阈值调优建议
    let threshold_recs = create_resource(
        || (),
        |_| async {
            api::get_threshold_recommendations().await.unwrap_or(
                api::ThresholdRecommendationResponse {
                    recommendations: vec![],
                    summary: String::new(),
                },
            )
        },
    );

    let stats_default = move || StatsResponse::default();
    let toggle_error = create_rw_signal(String::new());

    let do_toggle = move |name: String, current_enabled: bool| {
        let new_enabled = !current_enabled;
        let window = web_sys::window().expect("window not available");
        let action = if new_enabled { "启用" } else { "禁用" };
        if !window
            .confirm_with_message(&format!("确定要{} Jail '{}' 吗?", action, name))
            .unwrap_or(false)
        {
            return;
        }
        spawn_local(async move {
            match api::update_jail(&name, new_enabled).await {
                Ok(_) => {
                    if let Some(jails) = jails_signal.get() {
                        let updated: Vec<JailResponse> = jails
                            .into_iter()
                            .map(|j| {
                                if j.name == name {
                                    JailResponse {
                                        name: j.name,
                                        enabled: new_enabled,
                                        ban_count: j.ban_count,
                                        max_retries: j.max_retries,
                                        effective_max_retries: j.effective_max_retries,
                                        findtime: j.findtime,
                                        ban_time: j.ban_time,
                                        is_peak_hours: j.is_peak_hours,
                                        peak_hours_multiplier: j.peak_hours_multiplier,
                                        internal_ip_multiplier: j.internal_ip_multiplier,
                                        lines_parsed: j.lines_parsed,
                                        regex_matches: j.regex_matches,
                                        ips_extracted: j.ips_extracted,
                                        failed_attempts: j.failed_attempts,
                                        bans_triggered: j.bans_triggered,
                                    }
                                } else {
                                    j
                                }
                            })
                            .collect();
                        jails_signal.set(Some(updated));
                    }
                }
                Err(e) => {
                    toggle_error.set(format!("操作失败: {e}"));
                }
            }
        });
    };

    view! {
        <div class="jails-page">
            <div style="color:var(--color-red);font-size:12px;min-height:16px;text-align:center">{move || toggle_error.get()}</div>
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
                                    labels=Signal::derive(move || {
                                        let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                        let mut pairs: Vec<_> = s.jail_distribution.labels.into_iter()
                                            .zip(s.jail_distribution.values.into_iter())
                                            .collect();
                                        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                                        pairs.into_iter().map(|(l, _)| l).collect()
                                    })
                                    data=Signal::derive(move || {
                                        let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                        let mut pairs: Vec<_> = s.jail_distribution.labels.into_iter()
                                            .zip(s.jail_distribution.values.into_iter())
                                            .collect();
                                        pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                                        pairs.into_iter().map(|(_, v)| v).collect()
                                    })
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
                                    let name2 = name.clone();
                                    // 从 signal 读取最新数据，SSE 推送时自动刷新
                                    let jail_data = Signal::derive(move || {
                                        jails_signal
                                            .get()
                                            .unwrap_or_default()
                                            .into_iter()
                                            .find(|j| j.name == name)
                                            .unwrap_or_else(|| JailResponse {
                                                name: name.clone(),
                                                enabled: false,
                                                ban_count: 0,
                                                max_retries: 0,
                                                effective_max_retries: 0,
                                                findtime: 0,
                                                ban_time: 0,
                                                is_peak_hours: false,
                                                peak_hours_multiplier: 1.0,
                                                internal_ip_multiplier: 2.0,
                                                lines_parsed: 0,
                                                regex_matches: 0,
                                                ips_extracted: 0,
                                                failed_attempts: 0,
                                                bans_triggered: 0,
                                            })
                                    });
                                    view! {
                                        <div class="card jail-card">
                                            <div class="jail-header">
                                                <span class="jail-name">{&jail.name}</span>
                                                <div style="display:flex;gap:8px;align-items:center">
                                                    <span class=move || {
                                                        if jail_data.get().enabled { "badge badge-success badge-dot" } else { "badge badge-danger badge-dot" }
                                                    }>
                                                        {move || if jail_data.get().enabled { "ENABLED" } else { "DISABLED" }}
                                                    </span>
                                                    <button
                                                        class=move || {
                                                            if jail_data.get().enabled { "btn btn-sm btn-danger" } else { "btn btn-sm btn-success" }
                                                        }
                                                        style="padding:4px 8px;font-size:10px"
                                                        on:click=move |_| do_toggle(name2.clone(), jail_data.get().enabled)>
                                                        {move || if jail_data.get().enabled { "禁用" } else { "启用" }}
                                                    </button>
                                                </div>
                                            </div>
                                            <div class="jail-stats">
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"封禁数"</span>
                                                    <span class="jail-stat-value mono">{move || jail_data.get().ban_count}</span>
                                                </div>
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"失败阈值"</span>
                                                    <span class="jail-stat-value mono">
                                                        {move || {
                                                            let j = jail_data.get();
                                                            if j.effective_max_retries != j.max_retries {
                                                                format!("{}→{}", j.max_retries, j.effective_max_retries)
                                                            } else {
                                                                format!("{}", j.max_retries)
                                                            }
                                                        }}
                                                    </span>
                                                </div>
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"窗口"</span>
                                                    <span class="jail-stat-value mono">{move || format!("{}s", jail_data.get().findtime)}</span>
                                                </div>
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"封禁时长"</span>
                                                    <span class="jail-stat-value mono">
                                                        {move || {
                                                            let bt = jail_data.get().ban_time;
                                                            if bt < 0 { "永久".to_string() }
                                                            else if bt >= 3600 { format!("{}h", bt / 3600) }
                                                            else if bt >= 60 { format!("{}m", bt / 60) }
                                                            else { format!("{}s", bt) }
                                                        }}
                                                    </span>
                                                </div>
                                            </div>
                                            <div class="jail-threshold-info">
                                                {move || {
                                                    let j = jail_data.get();
                                                    let mut info_parts = Vec::new();

                                                    // 显示高峰期状态
                                                    if j.is_peak_hours {
                                                        info_parts.push(format!("高峰期 ×{:.1}", j.peak_hours_multiplier));
                                                    }

                                                    // 显示内网放宽策略
                                                    if j.internal_ip_multiplier > 1.0 {
                                                        info_parts.push(format!("内网 ×{:.1}", j.internal_ip_multiplier));
                                                    }

                                                    if info_parts.is_empty() {
                                                        view! { <span class="threshold-info">"标准阈值"</span> }.into_view()
                                                    } else {
                                                        view! {
                                                            <span class="threshold-info">
                                                                {info_parts.join(" · ")}
                                                            </span>
                                                        }.into_view()
                                                    }
                                                }}
                                            </div>
                                            // per-Jail 运行时统计
                                            <div class="jail-stats" style="margin-top:6px;padding-top:6px;border-top:1px solid var(--border-color);">
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"正则匹配率"</span>
                                                    <span class="jail-stat-value mono" style=move || {
                                                        let j = jail_data.get();
                                                        let rate = if j.lines_parsed > 0 {
                                                            j.regex_matches as f64 / j.lines_parsed as f64 * 100.0
                                                        } else { 0.0 };
                                                        let color = if j.lines_parsed == 0 {
                                                            "var(--text-muted)"
                                                        } else if rate < 0.1 {
                                                            "var(--color-red)"
                                                        } else if rate < 1.0 {
                                                            "var(--color-orange)"
                                                        } else {
                                                            "var(--color-green)"
                                                        };
                                                        format!("color:{}", color)
                                                    }>
                                                        {move || {
                                                            let j = jail_data.get();
                                                            if j.lines_parsed == 0 {
                                                                "N/A".to_string()
                                                            } else {
                                                                let rate = j.regex_matches as f64 / j.lines_parsed as f64 * 100.0;
                                                                format!("{:.2}%", rate)
                                                            }
                                                        }}
                                                    </span>
                                                </div>
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"解析行"</span>
                                                    <span class="jail-stat-value mono">{move || jail_data.get().lines_parsed}</span>
                                                </div>
                                                <div class="jail-stat">
                                                    <span class="jail-stat-label">"触发封禁"</span>
                                                    <span class="jail-stat-value mono">{move || jail_data.get().bans_triggered}</span>
                                                </div>
                                            </div>
                                        </div>
                                    }
                                }/>
                        }.into_view()
                    }}
                </Suspense>
            </div>

            // 阈值调优建议面板
            <Suspense fallback=|| view! { <div class="card" style="padding:16px;text-align:center;color:var(--text-muted)">"加载阈值分析..."</div> }>
                {move || threshold_recs.get().map(|recs| {
                    if recs.recommendations.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let needs_adj = recs.recommendations.iter().filter(|r| r.direction != "maintain").count();
                    view! {
                        <div class="card" style="margin-top:16px">
                            <div class="chart-header">
                                <h3>"阈值调优建议"</h3>
                                {if needs_adj > 0 {
                                    view! { <span class="badge" style="background:var(--color-orange);color:#fff">{format!("{} 个建议调整", needs_adj)}</span> }.into_view()
                                } else {
                                    view! { <span class="badge" style="background:var(--color-green);color:#fff">"全部合理"</span> }.into_view()
                                }}
                            </div>
                            <div style="display:grid;gap:8px;padding:12px 16px;">
                                {recs.recommendations.iter().map(|rec| {
                                    let (dir_label, dir_color) = match rec.direction.as_str() {
                                        "increase" => ("降低阈值 ⬆", "var(--color-red)"),
                                        "decrease" => ("放宽阈值 ⬇", "var(--color-green)"),
                                        _ => ("维持当前 ✓", "var(--color-text-secondary)"),
                                    };
                                    view! {
                                        <div style="display:grid;grid-template-columns:80px 1fr 100px 70px;gap:8px;align-items:center;padding:8px 0;border-bottom:1px solid var(--border-color);">
                                            <span class="mono" style="font-weight:600">{rec.jail_name.clone()}</span>
                                            <span style="font-size:12px;color:var(--text-secondary)">{rec.reason.clone()}</span>
                                            <span class="mono" style="font-size:12px;text-align:center">
                                                {if rec.direction == "maintain" {
                                                    format!("{}", rec.current_threshold)
                                                } else {
                                                    format!("{} → {}", rec.current_threshold, rec.recommended_threshold)
                                                }}
                                            </span>
                                            <span style=move || format!("font-size:11px;font-weight:600;color:{}", dir_color)>
                                                {dir_label}
                                            </span>
                                        </div>
                                    }
                                }).collect_view()}
                            </div>
                            <div style="padding:8px 16px;font-size:11px;color:var(--text-muted)">{recs.summary.clone()}</div>
                        </div>
                    }.into_view()
                })}
            </Suspense>
        </div>
    }
}
