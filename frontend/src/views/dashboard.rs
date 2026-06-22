//! 安全运营中心仪表盘 — 威胁态势 + 实时流量 + 攻击源 + 协议分布

use leptos::*;

use crate::api::{self, StatsResponse};
use crate::charts::{LineChart, PieChart};
use crate::types;
use crate::sse;

#[component]
pub fn Dashboard() -> impl IntoView {
    let stats_signal = sse::use_sse_stats();
    let rates_signal = sse::use_sse_rates();

    // 迷你图数据
    let spark_active = create_rw_signal(Vec::<f64>::new());
    let spark_today = create_rw_signal(Vec::<f64>::new());
    let spark_ddos = create_rw_signal(Vec::<f64>::new());

    // 流量趋势数据（从 rates history 加载）
    let time_labels = create_rw_signal(Vec::<String>::new());
    let pps_data = create_rw_signal(Vec::<u64>::new());
    let bps_data = create_rw_signal(Vec::<u64>::new());

    // 加载历史流量数据
    let _history = create_resource(|| (), |_| async { api::get_rates_history().await.ok() });

    create_effect(move |_| {
        if let Some(Some(history)) = _history.get() {
            if time_labels.get().is_empty() && !history.is_empty() {
                let mut labels = Vec::new();
                let mut pps = Vec::new();
                let mut bps = Vec::new();
                for entry in &history {
                    let ts = entry.timestamp;
                    let h = (ts / 3600) % 24;
                    let m = (ts / 60) % 60;
                    labels.push(format!("{h:02}:{m:02}"));
                    pps.push(entry.total_pps);
                    bps.push(entry.total_bps);
                }
                // 只保留最后 60 个点
                let start = if pps.len() > 60 { pps.len() - 60 } else { 0 };
                time_labels.set(labels[start..].to_vec());
                pps_data.set(pps[start..].to_vec());
                bps_data.set(bps[start..].to_vec());
            }
        }
    });

    // 监听 stats 变化，更新迷你图
    create_effect(move |_| {
        if let Some(s) = stats_signal.try_get().flatten() {
            push_spark(spark_active, s.current_bans as f64);
            push_spark(spark_today, s.today_bans as f64);
            push_spark(spark_ddos, s.ddos_events as f64);
        }
    });

    // 计算威胁等级
    let threat_level = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        types::ThreatLevel::from_rates(&rates)
    };

    // 攻击源 TOP 10
    let top_attackers = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        let mut sorted = rates;
        sorted.sort_by(|a, b| b.packets_per_sec.cmp(&a.packets_per_sec));
        sorted.into_iter().take(10).collect::<Vec<_>>()
    };

    // 协议分布
    let protocol_distribution = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        let mut syn = 0_u64;
        let mut udp = 0_u64;
        let mut icmp = 0_u64;
        let mut ack = 0_u64;
        let mut other = 0_u64;
        for r in &rates {
            syn += r.syn_packets_per_sec;
            udp += r.udp_packets_per_sec;
            icmp += r.icmp_packets_per_sec;
            ack += r.ack_packets_per_sec;
            let total = r.packets_per_sec;
            let accounted = syn + udp + icmp + ack;
            if total > accounted {
                other += total - accounted;
            }
        }
        (
            vec!["SYN".to_string(), "UDP".to_string(), "ICMP".to_string(), "ACK".to_string(), "OTHER".to_string()],
            vec![syn, udp, icmp, ack, other],
        )
    };

    let stats_default = move || StatsResponse::default();

    // 加载状态
    let is_loading = move || {
        let stats = stats_signal.try_get().flatten();
        let rates = rates_signal.try_get().flatten();
        stats.is_none() || rates.is_none()
    };

    view! {
        <div class="dashboard">
            // 加载骨架屏
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
                                let rates = rates_signal.try_get().flatten().unwrap_or_default();
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
                                let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                                types::format_number(s.current_bans, false)
                            }}
                        </span>
                    </div>
                    <div class="threat-stat">
                        <span class="threat-stat-label">"DDoS 事件"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                                types::format_number(s.ddos_events, false)
                            }}
                        </span>
                    </div>
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
                            labels=Signal::derive(move || time_labels.get())
                            data=Signal::derive(move || pps_data.get())
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

            // 第二行：协议分布 + 封禁趋势
            <div class="dashboard-grid">
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

            // 底部内核统计
            <div class="kernel-stats-bar">
                <KernelStat label="丢包" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    types::format_number(s.packets_dropped, true)
                }/>
                <KernelStat label="通过" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    types::format_number(s.packets_accepted, true)
                }/>
                <KernelStat label="封禁表" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    types::format_number(s.current_bans, false)
                }/>
                <KernelStat label="白名单" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    types::format_number(s.whitelist_count, false)
                }/>
                <KernelStat label="运行时间" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
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
