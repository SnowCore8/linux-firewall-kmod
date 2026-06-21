//! DDoS 实时监控 — 速率卡片 + 协议分布时间线

use leptos::*;

use crate::api::RateResponse;
use crate::charts::LineChart;
use crate::format::format_rate;
use crate::sse;

#[component]
pub fn DdosMonitor() -> impl IntoView {
    let rates_signal = sse::use_sse_rates();

    // 时间线数据（累积到信号中）
    let time_labels = create_rw_signal(Vec::<String>::new());
    let total_data = create_rw_signal(Vec::<u64>::new());
    let syn_data = create_rw_signal(Vec::<u64>::new());
    let udp_data = create_rw_signal(Vec::<u64>::new());
    let icmp_data = create_rw_signal(Vec::<u64>::new());
    const MAX_POINTS: usize = 300;

    // 监听 rates 变化，更新时间线
    create_effect(move |_| {
        let rates = rates_signal.get().unwrap_or_default();
        if rates.is_empty() {
            return;
        }

        let mut total_pps = 0_u64;
        let mut total_syn = 0_u64;
        let mut total_udp = 0_u64;
        let mut total_icmp = 0_u64;
        for r in &rates {
            total_pps += r.packets_per_sec;
            total_syn += r.syn_packets_per_sec;
            total_udp += r.udp_packets_per_sec;
            total_icmp += r.icmp_packets_per_sec;
        }

        // 时间标签
        let now = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now() as u64)
            .unwrap_or(0);
        let label = format!(
            "{:02}:{:02}:{:02}",
            (now / 1000 / 3600) % 24,
            (now / 1000 / 60) % 60,
            (now / 1000) % 60
        );

        time_labels.update(|v| {
            v.push(label);
            if v.len() > MAX_POINTS {
                v.remove(0);
            }
        });
        total_data.update(|v| {
            v.push(total_pps);
            if v.len() > MAX_POINTS {
                v.remove(0);
            }
        });
        syn_data.update(|v| {
            v.push(total_syn);
            if v.len() > MAX_POINTS {
                v.remove(0);
            }
        });
        udp_data.update(|v| {
            v.push(total_udp);
            if v.len() > MAX_POINTS {
                v.remove(0);
            }
        });
        icmp_data.update(|v| {
            v.push(total_icmp);
            if v.len() > MAX_POINTS {
                v.remove(0);
            }
        });
    });

    view! {
        <div class="ddos-page">
            <div class="page-toolbar">
                <div class="toolbar-left">
                    <h2 class="section-title">"DDoS 速率监控"</h2>
                    <span class="badge badge-info">"实时"</span>
                </div>
            </div>

            // 速率卡片
            {move || {
                let rates = rates_signal.get().unwrap_or_default();
                if rates.is_empty() {
                    return view! {
                        <div class="card">
                            <div class="empty-state">
                                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
                                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                                </svg>
                                <span>"暂无活跃速率数据"</span>
                            </div>
                        </div>
                    }.into_view();
                }

                view! {
                    <div class="rates-grid">
                        <For
                            each=move || rates.clone()
                            key=|r| r.ip.clone()
                            children=move |rate: RateResponse| {
                                let level = get_rate_level(&rate);
                                let ip = rate.ip.clone();
                                let badge = get_rate_badge(&rate);
                                let label_text = get_rate_label(&rate);
                                let pps = rate.packets_per_sec;
                                let bps = rate.bytes_per_sec;
                                let syn = rate.syn_packets_per_sec;
                                let udp = rate.udp_packets_per_sec;
                                let icmp = rate.icmp_packets_per_sec;
                                view! {
                                    <div class=move || format!("card rate-card {level}")>
                                        <div class="rate-header">
                                            <span class="rate-ip mono">{ip.clone()}</span>
                                            <span class=move || format!("badge {}", badge)>
                                                {label_text}
                                            </span>
                                        </div>
                                        <div class="rate-stats">
                                            <RateStat label="总速率" value=format_rate(pps, "pps")/>
                                            <RateStat label="带宽" value=format_rate(bps, "bps")/>
                                            <RateStat label="SYN" value=format_rate(syn, "pps")/>
                                            <RateStat label="UDP" value=format_rate(udp, "pps")/>
                                            <RateStat label="ICMP" value=format_rate(icmp, "pps")/>
                                        </div>
                                    </div>
                                }
                            }
                        />
                    </div>
                }.into_view()
            }}

            // 时间线图表
            {move || {
                if total_data.get().len() < 2 {
                    return view! { <div/> }.into_view();
                }
                view! {
                    <div class="card chart-card">
                        <div class="chart-header">
                            <h3>"协议分布时间线"</h3>
                        </div>
                        <div class="chart-body" style="height:220px">
                            <LineChart
                                labels=Signal::derive(move || time_labels.get())
                                data=Signal::derive(move || total_data.get())
                                color="#3b82f6"
                                height=220
                            />
                        </div>
                    </div>
                }.into_view()
            }}
        </div>
    }
}

#[component]
fn RateStat(label: &'static str, value: String) -> impl IntoView {
    view! {
        <div class="rate-stat">
            <div class="rate-stat-label">{label}</div>
            <div class="rate-stat-value mono">{value}</div>
        </div>
    }
}

fn get_rate_level(rate: &RateResponse) -> &'static str {
    if rate.packets_per_sec > 10000 || rate.syn_packets_per_sec > 1000 {
        "critical"
    } else if rate.packets_per_sec > 1000 || rate.syn_packets_per_sec > 100 {
        "warning"
    } else {
        "normal"
    }
}

fn get_rate_badge(rate: &RateResponse) -> &'static str {
    match get_rate_level(rate) {
        "critical" => "badge-danger",
        "warning" => "badge-warning",
        _ => "badge-success",
    }
}

fn get_rate_label(rate: &RateResponse) -> &'static str {
    match get_rate_level(rate) {
        "critical" => "严重",
        "warning" => "警告",
        _ => "正常",
    }
}
