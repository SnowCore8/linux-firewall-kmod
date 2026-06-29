//! 安全运营中心仪表盘 — 威胁态势 + 实时流量 + 攻击源 + 协议分布 + 24h 热力图 + 封禁效果

use leptos::*;

use crate::api::{self, StatsResponse};
use crate::charts::{LineChart, PieChart, RadarChart};
use crate::components::toast::ToastState;
use crate::sse::SseState;
use crate::types;

#[component]
pub fn Dashboard() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState context not found");
    let stats_signal = sse.stats;
    let rates_signal = sse.rates;
    let rate_history = sse.rate_history;

    // Toast 通知状态
    let toast_state = use_context::<ToastState>().expect("ToastState context not found");

    // 热力图数据（24 小时按小时聚合）
    let heatmap = create_resource(|| (), |_| async { api::get_heatmap().await.ok() });

    // 封禁效果追踪数据（复发率 + TOP 10）
    let recidivism = create_resource(|| (), |_| async { api::get_recidivism().await.ok() });

    // 迷你图数据
    let spark_active = create_rw_signal(Vec::<f64>::new());
    let spark_today = create_rw_signal(Vec::<f64>::new());
    let spark_ddos = create_rw_signal(Vec::<f64>::new());

    // 监听 stats 变化，更新迷你图
    create_effect(move |_| {
        if let Some(s) = stats_signal.get() {
            push_spark(spark_active, s.current_bans as f64);
            push_spark(spark_today, s.today_bans as f64);
            push_spark(spark_ddos, s.ddos_events as f64);
        }
    });

    // 计算威胁等级（优先使用后端综合评估，回退到前端速率判断）
    let threat_level = move || {
        if let Some(s) = stats_signal.get() {
            if let Some(tl) = s.threat_level {
                return match tl.score {
                    0 => types::ThreatLevel::Normal,
                    1..=2 => types::ThreatLevel::Warning,
                    _ => types::ThreatLevel::Critical,
                };
            }
        }
        let rates = rates_signal.get().unwrap_or_default();
        types::ThreatLevel::from_rates(&rates)
    };

    // 后端威胁评估详情
    let threat_factors = move || {
        stats_signal
            .get()
            .and_then(|s| s.threat_level)
            .map(|tl| tl.factors)
            .unwrap_or_default()
    };

    // 攻击源 TOP 10
    let top_attackers = move || {
        let rates = rates_signal.get().unwrap_or_default();
        let mut sorted = rates;
        sorted.sort_by(|a, b| b.packets_per_sec.cmp(&a.packets_per_sec));
        sorted.into_iter().take(10).collect::<Vec<_>>()
    };

    // 协议分布
    let protocol_distribution = move || {
        let rates = rates_signal.get().unwrap_or_default();
        let mut syn = 0_u64;
        let mut udp = 0_u64;
        let mut icmp = 0_u64;
        let mut ack = 0_u64;
        let mut total_all = 0_u64;
        for r in &rates {
            syn += r.syn_packets_per_sec;
            udp += r.udp_packets_per_sec;
            icmp += r.icmp_packets_per_sec;
            ack += r.ack_packets_per_sec;
            total_all += r.packets_per_sec;
        }
        let accounted = syn + udp + icmp + ack;
        let other = if total_all > accounted {
            total_all - accounted
        } else {
            0
        };
        (
            vec![
                "SYN".to_string(),
                "UDP".to_string(),
                "ICMP".to_string(),
                "ACK".to_string(),
                "OTHER".to_string(),
            ],
            vec![syn, udp, icmp, ack, other],
        )
    };

    // 6 协议雷达图数据（SYN/UDP/ICMP/ACK/RST/FIN）
    let protocol_radar = move || {
        let rates = rates_signal.get().unwrap_or_default();
        let mut syn = 0_u64;
        let mut udp = 0_u64;
        let mut icmp = 0_u64;
        let mut ack = 0_u64;
        let mut rst = 0_u64;
        let mut fin = 0_u64;
        for r in &rates {
            syn += r.syn_packets_per_sec;
            udp += r.udp_packets_per_sec;
            icmp += r.icmp_packets_per_sec;
            ack += r.ack_packets_per_sec;
            rst += r.rst_packets_per_sec;
            fin += r.fin_packets_per_sec;
        }
        (
            vec![
                "SYN".to_string(),
                "UDP".to_string(),
                "ICMP".to_string(),
                "ACK".to_string(),
                "RST".to_string(),
                "FIN".to_string(),
            ],
            vec![syn, udp, icmp, ack, rst, fin],
        )
    };

    let stats_default = move || StatsResponse::default();

    // 加载状态
    let is_loading = move || stats_signal.get().is_none() || rates_signal.get().is_none();

    view! {
        <div class="dashboard">
            <Show
                when=move || !is_loading()
                fallback=|| view! {
                    <div class="loading-skeleton">
                        <div class="skeleton-threat-bar"/>
                        <div class="skeleton-grid">
                            <div class="skeleton-card"/>
                            <div class="skeleton-card"/>
                        </div>
                        <div class="skeleton-grid">
                            <div class="skeleton-card"/>
                            <div class="skeleton-card"/>
                        </div>
                    </div>
                }
            >

            // 顶部威胁状态栏
            <div class="threat-bar">
                <div class="threat-level">
                    <span class="threat-dot" style=move || format!("background: {}", threat_level().color())/>
                    <span class="threat-label" style=move || format!("color: {}", threat_level().color())>
                        {move || threat_level().label()}
                    </span>
                </div>
                <div class="threat-stats">
                    <div class="threat-stat">
                        <span class="threat-stat-label">"吞吐量"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                let rates = rates_signal.get().unwrap_or_default();
                                let pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
                                let bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();
                                format!("{} / {}", types::format_rate(pps, "pps"), types::format_rate(bps, "bps"))
                            }}
                        </span>
                    </div>
                    <div class="threat-stat">
                        <span class="threat-stat-label">"活跃封禁"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                types::format_number(s.current_bans, false)
                            }}
                        </span>
                    </div>
                    <div class="threat-stat">
                        <span class="threat-stat-label">"DDoS 事件"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                let s = stats_signal.get().unwrap_or_else(|| stats_default());
                                types::format_number(s.ddos_events, false)
                            }}
                        </span>
                    </div>
                </div>
                // 威胁评估因素
                <Show when=move || {
                    let f = threat_factors();
                    !f.is_empty() && !(f.len() == 1 && f[0] == "一切正常")
                }>
                    <div class="threat-factors">
                        {move || {
                            threat_factors()
                                .into_iter()
                                .map(|factor| {
                                    view! { <span class="threat-factor">{factor}</span> }
                                })
                                .collect_view()
                        }}
                    </div>
                </Show>
            </div>

            // 快捷操作栏
            <div class="quick-actions">
                <button
                    class="btn btn-danger btn-sm"
                    on:click={
                        let toast_state = toast_state.clone();
                        move |_| {
                            let toast = toast_state.clone();
                            spawn_local(async move {
                                match api::unban_all_temporary().await {
                                    Ok(resp) => {
                                        toast.success(format!(
                                            "解封完成：{}/{} 成功", resp.succeeded, resp.total
                                        ));
                                    }
                                    Err(e) => {
                                        toast.error(format!("解封失败：{e}"));
                                    }
                                }
                            });
                        }
                    }
                >
                    "一键解封临时封禁"
                </button>
                <button
                    class="btn btn-primary btn-sm"
                    on:click={
                        let toast_state = toast_state.clone();
                        move |_| {
                            let rates = rates_signal.get().unwrap_or_default();
                            let mut sorted = rates;
                            sorted.sort_by(|a, b| b.packets_per_sec.cmp(&a.packets_per_sec));
                            let ips: Vec<String> = sorted.into_iter()
                                .take(5)
                                .map(|r| r.ip.clone())
                                .collect();
                            if ips.is_empty() {
                                return;
                            }
                            let toast = toast_state.clone();
                            spawn_local(async move {
                                match api::batch_ban(ips).await {
                                    Ok(resp) => {
                                        toast.success(format!(
                                            "封禁完成：{}/{} 成功", resp.succeeded, resp.total
                                        ));
                                    }
                                    Err(e) => {
                                        toast.error(format!("封禁失败：{e}"));
                                    }
                                }
                            });
                        }
                    }
                >
                    "一键封禁 TOP 5 攻击源"
                </button>
            </div>

            // 最近封禁事件流
            <div class="card" style="padding:14px">
                <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">
                    <h3 style="font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:0.08em;color:var(--text-secondary);margin:0">
                        "最近封禁"
                    </h3>
                    <span class="badge badge-dot" style=move || {
                        let bans = sse.bans.get().unwrap_or_default();
                        if bans.is_empty() {
                            "background:var(--color-green)".to_string()
                        } else {
                            "background:var(--color-red)".to_string()
                        }
                    }/>
                </div>
                <div class="ban-timeline">
                    {move || {
                        let mut bans = sse.bans.get().unwrap_or_default();
                        if bans.is_empty() {
                            return view! {
                                <div class="empty-state" style="padding:12px 0">
                                    <span style="color:var(--text-muted);font-size:12px">"当前无活跃封禁"</span>
                                </div>
                            }.into_view();
                        }
                        // 按封禁时间降序，取最近 8 条
                        bans.sort_by(|a, b| b.banned_at.cmp(&a.banned_at));
                        bans.truncate(8);
                        bans.into_iter().map(|ban| {
                            let ip = ban.ip.clone();
                            let jail = ban.jail.clone();
                            let is_permanent = ban.is_permanent;
                            let remaining = ban.remaining_seconds;
                            let ban_count = ban.ban_count;
                            let time_str = if is_permanent {
                                "永久".to_string()
                            } else if remaining > 3600 {
                                format!("{}h", remaining / 3600)
                            } else if remaining > 60 {
                                format!("{}m", remaining / 60)
                            } else {
                                format!("{}s", remaining.max(0))
                            };
                            view! {
                                <div class="ban-timeline-item">
                                    <span class="ban-tl-ip mono">{ip}</span>
                                    <span class="ban-tl-jail">{jail}</span>
                                    <Show when=move || { ban_count > 1 }>
                                        <span class="ban-tl-repeat">{format!("×{}", ban_count)}</span>
                                    </Show>
                                    <span class="ban-tl-time">{time_str}</span>
                                </div>
                            }
                        }).collect_view()
                    }}
                </div>
            </div>

            // 主内容区：流量图 + 攻击源
            <div class="dashboard-grid">
                <div class="card chart-card traffic-chart">
                    <div class="chart-header">
                        <h3>"实时流量趋势"</h3>
                    </div>
                    <div class="chart-body" style="height:200px">
                        <LineChart
                            labels=Signal::derive(move || rate_history.get().labels.clone())
                            data=Signal::derive(move || rate_history.get().pps.clone())
                            color="var(--color-cyan)"
                            height=200
                        />
                    </div>
                </div>

                <div class="card attackers-panel">
                    <div class="chart-header">
                        <h3>"攻击源 TOP 10"</h3>
                    </div>
                    <div class="attackers-list">
                        {move || {
                            let attackers = top_attackers();
                            if attackers.is_empty() {
                                return view! { <div class="empty-state"><span>"无活跃攻击"</span></div> }.into_view();
                            }
                            attackers.into_iter().enumerate().map(|(i, rate)| {
                                let level = types::attacker_threat_level(&rate);
                                let ip = rate.ip.clone();
                                let pps = types::format_rate(rate.packets_per_sec, "pps");
                                let protocol = types::dominant_protocol(&rate);
                                let threat_label = types::attacker_threat_label(&rate);
                                view! {
                                    <div class="attacker-row">
                                        <span class="attacker-rank mono">{i + 1}</span>
                                        <span class="attacker-ip mono">{ip}</span>
                                        <span class="attacker-pps mono">{pps}</span>
                                        <span class="attacker-protocol">
                                            {protocol}
                                        </span>
                                        <span class=move || format!("attacker-level {}", level)>
                                            {threat_label}
                                        </span>
                                    </div>
                                }
                            }).collect_view()
                        }}
                    </div>
                </div>
            </div>

            // 第二行：协议分布 + 协议雷达 + 封禁趋势
            <div class="dashboard-grid dashboard-grid-3">
                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"协议分布"</h3>
                    </div>
                    <div class="chart-body" style="height:180px">
                        {move || {
                            let (labels, data) = protocol_distribution();
                            let total: u64 = data.iter().sum();
                            if total == 0 {
                                return view! { <div class="empty-state"><span>"无流量数据"</span></div> }.into_view();
                            }
                            view! {
                                <PieChart
                                    labels=Signal::derive(move || labels.clone())
                                    data=Signal::derive(move || data.clone())
                                    size=180
                                />
                            }.into_view()
                        }}
                    </div>
                </div>

                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"协议雷达"</h3>
                    </div>
                    <div class="chart-body" style="height:180px">
                        {move || {
                            let (labels, data) = protocol_radar();
                            view! {
                                <RadarChart
                                    labels=Signal::derive(move || labels.clone())
                                    data=Signal::derive(move || data.clone())
                                    size=180
                                />
                            }.into_view()
                        }}
                    </div>
                </div>

                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"封禁趋势 (24h)"</h3>
                    </div>
                    <div class="chart-body" style="height:180px">
                        <LineChart
                            labels=Signal::derive(move || {
                                stats_signal.get().unwrap_or_else(|| stats_default()).ban_trend.labels
                            })
                            data=Signal::derive(move || {
                                stats_signal.get().unwrap_or_else(|| stats_default()).ban_trend.values
                            })
                            color="var(--color-red)"
                            height=180
                        />
                    </div>
                </div>
            </div>

            // 第三行：24 小时攻击热力图
            <div class="card heatmap-card">
                <div class="chart-header">
                    <h3>"24 小时攻击热力图"</h3>
                    <span class="heatmap-legend">
                        <span class="legend-item"><span class="legend-dot" style="background:#ef4444"/>"封禁"</span>
                        <span class="legend-item"><span class="legend-dot" style="background:#f59e0b"/>"失败"</span>
                        <span class="legend-item"><span class="legend-dot" style="background:#8b5cf6"/>"DDoS"</span>
                    </span>
                </div>
                <Suspense fallback=|| view! { <div class="heatmap-placeholder">"加载中..."</div> }>
                    {move || {
                        heatmap.get().map(|data| {
                            match data {
                                Some(hm) => view! { <HeatmapChart data=hm/> }.into_view(),
                                None => view! {
                                    <div class="heatmap-placeholder">"暂无数据"</div>
                                }.into_view(),
                            }
                        })
                    }}
                </Suspense>
            </div>

            // 第四行：封禁效果追踪
            <div class="card recidivism-card">
                <div class="chart-header">
                    <h3>"封禁效果追踪"</h3>
                </div>
                <Suspense fallback=|| view! { <div class="heatmap-placeholder">"加载中..."</div> }>
                    {move || {
                        recidivism.get().map(|data| {
                            match data {
                                Some(r) => view! { <RecidivismPanel data=r/> }.into_view(),
                                None => view! {
                                    <div class="heatmap-placeholder">"暂无数据"</div>
                                }.into_view(),
                            }
                        })
                    }}
                </Suspense>
            </div>

            // 底部内核统计
            <div class="kernel-stats-bar">
                <KernelStat label="丢包" value=move || {
                    let s = stats_signal.get().unwrap_or_else(|| stats_default());
                    types::format_number(s.packets_dropped, true)
                }/>
                <KernelStat label="通过" value=move || {
                    let s = stats_signal.get().unwrap_or_else(|| stats_default());
                    types::format_number(s.packets_accepted, true)
                }/>
                <KernelStat label="封禁表" value=move || {
                    let s = stats_signal.get().unwrap_or_else(|| stats_default());
                    types::format_number(s.current_bans, false)
                }/>
                <KernelStat label="白名单" value=move || {
                    let s = stats_signal.get().unwrap_or_else(|| stats_default());
                    types::format_number(s.whitelist_count, false)
                }/>
                <KernelStat label="运行时间" value=move || {
                    let s = stats_signal.get().unwrap_or_else(|| stats_default());
                    types::format_uptime(s.uptime_seconds)
                }/>
            </div>

            </Show>
        </div>
    }
}

fn push_spark(sig: RwSignal<Vec<f64>>, val: f64) {
    sig.update(|v| {
        v.push(val);
        if v.len() > 20 {
            v.remove(0);
        }
    });
}

#[component]
fn KernelStat(
    label: &'static str,
    value: impl Fn() -> String + Send + Sync + 'static,
) -> impl IntoView {
    view! {
        <div class="kernel-stat">
            <span class="kernel-stat-label">{label}</span>
            <span class="kernel-stat-value mono">{move || value()}</span>
        </div>
    }
}

/// 24 小时攻击热力图 — 纯 SVG 实现
///
/// 24 列（小时）× 3 行（封禁/失败/DDoS），颜色深浅表示强度
#[component]
fn HeatmapChart(data: api::HourlyHeatmap) -> impl IntoView {
    let cell_w = 28.0_f64;
    let cell_h = 28.0_f64;
    let gap = 2.0_f64;
    let label_w = 50.0_f64;
    let top_pad = 24.0_f64;
    let bottom_pad = 20.0_f64;
    let svg_w = label_w + 24.0 * (cell_w + gap);
    let svg_h = top_pad + 3.0 * (cell_h + gap) + bottom_pad;

    let row_labels = vec!["封禁", "失败", "DDoS"];
    let row_colors = vec!["#ef4444", "#f59e0b", "#8b5cf6"];

    // 计算每行最大值用于归一化
    let max_bans = data.hours.iter().map(|b| b.bans).max().unwrap_or(1).max(1);
    let max_failed = data
        .hours
        .iter()
        .map(|b| b.failed_attempts)
        .max()
        .unwrap_or(1)
        .max(1);
    let max_ddos = data
        .hours
        .iter()
        .map(|b| b.ddos_events)
        .max()
        .unwrap_or(1)
        .max(1);
    let row_maxes = vec![max_bans, max_failed, max_ddos];

    let row_values: Vec<Vec<u64>> = vec![
        data.hours.iter().map(|b| b.bans).collect(),
        data.hours.iter().map(|b| b.failed_attempts).collect(),
        data.hours.iter().map(|b| b.ddos_events).collect(),
    ];

    let hours_labels = (0..24).map(|i| format!("{i}")).collect::<Vec<_>>();

    view! {
        <div class="heatmap-container">
            <svg viewBox=format!("0 0 {svg_w} {svg_h}") class="heatmap-svg" xmlns="http://www.w3.org/2000/svg">
                // 小时标签（顶部）
                <g>
                    {hours_labels.into_iter().enumerate().map(|(i, label)| {
                        let x = label_w + i as f64 * (cell_w + gap) + cell_w / 2.0;
                        // 只显示偶数小时标签避免拥挤
                        if i % 2 == 0 {
                            view! {
                                <text x=x y=16 class="heatmap-hour-label" text-anchor="middle">{label}</text>
                            }.into_view()
                        } else {
                            view! { <text /> }.into_view()
                        }
                    }).collect_view()}
                </g>

                // 热力格子
                {(0..3).map(move |row| {
                    let y = top_pad + row as f64 * (cell_h + gap);
                    let max_val = row_maxes[row];
                    let color = row_colors[row];
                    let values = row_values[row].clone();
                    let row_label = row_labels[row].to_string();
                    let tooltip_label = row_label.clone();

                    view! {
                        <g>
                            // 行标签
                            <text x=label_w - 6.0 y=y + cell_h / 2.0 + 4.0 class="heatmap-row-label" text-anchor="end">
                                {row_label}
                            </text>
                            // 24 个格子
                            {values.into_iter().enumerate().map(move |(col, val)| {
                                let x = label_w + col as f64 * (cell_w + gap);
                                let intensity = if max_val > 0 {
                                    val as f64 / max_val as f64
                                } else {
                                    0.0
                                };
                                let opacity = if val > 0 {
                                    0.15 + 0.85 * intensity
                                } else {
                                    0.04
                                };
                                let tooltip = format!("{tooltip_label} {col}:00 — {val}");

                                view! {
                                    <g>
                                        <rect
                                            x=x
                                            y=y
                                            width=cell_w
                                            height=cell_h
                                            rx=3
                                            fill=color
                                            opacity=opacity
                                            class="heatmap-cell"
                                        >
                                            <title>{tooltip}</title>
                                        </rect>
                                        // 高值显示数字
                                        {if intensity > 0.5 {
                                            view! {
                                                <text
                                                    x=x + cell_w / 2.0
                                                    y=y + cell_h / 2.0 + 4.0
                                                    class="heatmap-cell-value"
                                                    text-anchor="middle"
                                                >
                                                    {format_number_compact(val)}
                                                </text>
                                            }.into_view()
                                        } else {
                                            view! { <text /> }.into_view()
                                        }}
                                    </g>
                                }
                            }).collect_view()}
                        </g>
                    }
                }).collect_view()}
            </svg>
        </div>
    }
}

/// 紧凑数字格式化：1200 → 1.2k, 1500000 → 1.5M
fn format_number_compact(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// 封禁效果追踪面板 — 复发率统计 + 复发 IP TOP 10
#[component]
fn RecidivismPanel(data: api::RecidivismResponse) -> impl IntoView {
    let rate_color = if data.recidivism_rate > 30.0 {
        "var(--color-red)"
    } else if data.recidivism_rate > 10.0 {
        "var(--color-orange)"
    } else {
        "var(--color-green)"
    };

    view! {
        <div class="recidivism-layout">
            // 左侧：统计摘要
            <div class="recidivism-summary">
                <div class="recidivism-stat">
                    <span class="recidivism-stat-label">"总封禁 IP"</span>
                    <span class="recidivism-stat-value mono">{data.total_ips}</span>
                </div>
                <div class="recidivism-stat">
                    <span class="recidivism-stat-label">"复发 IP"</span>
                    <span class="recidivism-stat-value mono">{data.recidivist_ips}</span>
                </div>
                <div class="recidivism-stat">
                    <span class="recidivism-stat-label">"复发率"</span>
                    <span class="recidivism-stat-value mono" style=format!("color: {rate_color}")>
                        {format!("{:.1}%", data.recidivism_rate)}
                    </span>
                </div>
                <div class="recidivism-stat">
                    <span class="recidivism-stat-label">"永久封禁"</span>
                    <span class="recidivism-stat-value mono">{data.permanent_bans}</span>
                </div>
            </div>

            // 右侧：复发 IP TOP 10
            <div class="recidivism-top">
                <div class="recidivism-top-header">"复发 IP TOP 10"</div>
                <div class="recidivism-list">
                    {move || {
                        if data.top_recidivists.is_empty() {
                            return view! {
                                <div class="recidivism-empty">"无复发 IP"</div>
                            }.into_view();
                        }
                        data.top_recidivists.iter().enumerate().map(|(i, entry)| {
                            let level_class = if entry.ban_count >= 4 {
                                "critical"
                            } else if entry.ban_count >= 3 {
                                "warning"
                            } else {
                                "normal"
                            };
                            let perm_badge = if entry.was_permanent {
                                view! { <span class="badge badge-danger">"永久"</span> }.into_view()
                            } else {
                                view! { <span /> }.into_view()
                            };
                            view! {
                                <div class="recidivism-row">
                                    <span class="recidivism-rank mono">{i + 1}</span>
                                    <span class="recidivism-ip mono">{entry.ip.clone()}</span>
                                    <span class="recidivism-count">
                                        <span class=format!("recidivism-badge {}", level_class)>
                                            {format!("×{}", entry.ban_count)}
                                        </span>
                                    </span>
                                    {perm_badge}
                                </div>
                            }
                        }).collect_view()
                    }}
                </div>
            </div>
        </div>
    }
}
