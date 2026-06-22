//! DDoS 攻击监控 — 协议分布 + 阈值对比 + 攻击源排行 + 时间线

use leptos::*;

use crate::api::{self};
use crate::charts::LineChart;
use crate::format::format_rate;
use crate::sse;

#[component]
pub fn DdosMonitor() -> impl IntoView {
    let rates_signal = sse::use_sse_rates();

    // 加载配置获取阈值
    let config = create_resource(|| (), |_| async { api::get_config().await.ok() });

    // 时间线数据
    let time_labels = create_rw_signal(Vec::<String>::new());
    let pps_data = create_rw_signal(Vec::<u64>::new());
    let bps_data = create_rw_signal(Vec::<u64>::new());
    let tracked_ips_data = create_rw_signal(Vec::<u32>::new());
    const MAX_POINTS: usize = 300;

    // 加载历史数据
    let _history = create_resource(|| (), |_| async { api::get_rates_history().await.ok() });

    create_effect(move |_| {
        if let Some(Some(history)) = _history.get() {
            if time_labels.get().is_empty() && !history.is_empty() {
                let mut labels = Vec::new();
                let mut pps = Vec::new();
                let mut bps = Vec::new();
                let mut tracked = Vec::new();
                for entry in &history {
                    let ts = entry.timestamp;
                    let h = (ts / 3600) % 24;
                    let m = (ts / 60) % 60;
                    labels.push(format!("{h:02}:{m:02}"));
                    pps.push(entry.total_pps);
                    bps.push(entry.total_bps);
                    tracked.push(entry.tracked_ips);
                }
                let start = if pps.len() > MAX_POINTS { pps.len() - MAX_POINTS } else { 0 };
                time_labels.set(labels[start..].to_vec());
                pps_data.set(pps[start..].to_vec());
                bps_data.set(bps[start..].to_vec());
                tracked_ips_data.set(tracked[start..].to_vec());
            }
        }
    });

    // 实时追加数据
    create_effect(move |_| {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        if rates.is_empty() { return; }

        let total_pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
        let total_bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();

        let now = web_sys::window()
            .and_then(|w| w.performance())
            .map(|p| p.now() as u64)
            .unwrap_or(0);
        let label = format!(
            "{:02}:{:02}",
            (now / 1000 / 60) % 60,
            (now / 1000) % 60
        );

        time_labels.update(|v| { v.push(label); if v.len() > MAX_POINTS { v.remove(0); } });
        pps_data.update(|v| { v.push(total_pps); if v.len() > MAX_POINTS { v.remove(0); } });
        bps_data.update(|v| { v.push(total_bps); if v.len() > MAX_POINTS { v.remove(0); } });
        tracked_ips_data.update(|v| { v.push(rates.len() as u32); if v.len() > MAX_POINTS { v.remove(0); } });
    });

    // 计算协议分布
    let protocol_stats = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
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
        let total = syn + udp + icmp + ack + rst + fin;
        (syn, udp, icmp, ack, rst, fin, total)
    };

    // 攻击源 TOP 10
    let top_attackers = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        let mut sorted = rates;
        sorted.sort_by(|a, b| b.packets_per_sec.cmp(&a.packets_per_sec));
        sorted.into_iter().take(10).collect::<Vec<_>>()
    };

    // 计算威胁等级
    let threat_level = move || {
        let rates = rates_signal.try_get().flatten().unwrap_or_default();
        if rates.is_empty() { return ("NORMAL", "var(--color-green)"); }
        let max_pps = rates.iter().map(|r| r.packets_per_sec).max().unwrap_or(0);
        let max_syn = rates.iter().map(|r| r.syn_packets_per_sec).max().unwrap_or(0);
        if max_pps > 10000 || max_syn > 1000 {
            ("CRITICAL", "var(--color-red)")
        } else if max_pps > 1000 || max_syn > 100 {
            ("WARNING", "var(--color-orange)")
        } else {
            ("NORMAL", "var(--color-green)")
        }
    };

    view! {
        <div class="ddos-page">
            // 顶部状态栏
            <div class="threat-bar">
                <div class="threat-level">
                    <span class="threat-dot" style=move || format!("background: {}", threat_level().1)/>
                    <span class="threat-label" style=move || format!("color: {}", threat_level().1)>
                        {move || threat_level().0}
                    </span>
                </div>
                <div class="threat-stats">
                    <div class="threat-stat">
                        <span class="threat-stat-label">"总吞吐量"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                let rates = rates_signal.try_get().flatten().unwrap_or_default();
                                let pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
                                let bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();
                                format!("{} / {}", format_rate(pps, "pps"), format_rate(bps, "bps"))
                            }}
                        </span>
                    </div>
                    <div class="threat-stat">
                        <span class="threat-stat-label">"跟踪 IP"</span>
                        <span class="threat-stat-value mono">
                            {move || {
                                rates_signal.try_get().flatten().map(|r| r.len()).unwrap_or(0).to_string()
                            }}
                        </span>
                    </div>
                </div>
            </div>

            // 协议分布 + 阈值对比
            <div class="dashboard-grid">
                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"协议分布"</h3>
                    </div>
                    <div class="protocol-grid">
                        {move || {
                            let (syn, udp, icmp, ack, rst, fin, total) = protocol_stats();
                            if total == 0 {
                                return view! { <div class="empty-state"><span>"无流量数据"</span></div> }.into_view();
                            }
                            view! {
                                <>
                                    <ProtocolBar label="SYN" value=syn total=total color="var(--color-red)"/>
                                    <ProtocolBar label="UDP" value=udp total=total color="var(--color-orange)"/>
                                    <ProtocolBar label="ICMP" value=icmp total=total color="var(--color-yellow)"/>
                                    <ProtocolBar label="ACK" value=ack total=total color="var(--color-cyan)"/>
                                    <ProtocolBar label="RST" value=rst total=total color="var(--color-purple)"/>
                                    <ProtocolBar label="FIN" value=fin total=total color="var(--color-blue)"/>
                                </>
                            }.into_view()
                        }}
                    </div>
                </div>

                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"阈值对比"</h3>
                    </div>
                    <div class="threshold-list">
                        <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                            {move || {
                                let cfg = config.get().flatten();
                                let rates = rates_signal.try_get().flatten().unwrap_or_default();
                                let max_pps = rates.iter().map(|r| r.packets_per_sec).max().unwrap_or(0);
                                let max_syn = rates.iter().map(|r| r.syn_packets_per_sec).max().unwrap_or(0);

                                if let Some(c) = cfg {
                                    view! {
                                        <>
                                            <ThresholdRow label="PPS 警告阈值" value=c.rate_warning_pps current=max_pps unit="pps"/>
                                            <ThresholdRow label="PPS 严重阈值" value=c.rate_critical_pps current=max_pps unit="pps"/>
                                            <ThresholdRow label="SYN 警告阈值" value=c.rate_warning_syn current=max_syn unit="pps"/>
                                            <ThresholdRow label="SYN 严重阈值" value=c.rate_critical_syn current=max_syn unit="pps"/>
                                        </>
                                    }.into_view()
                                } else {
                                    view! { <div>"配置加载中..."</div> }.into_view()
                                }
                            }}
                        </Suspense>
                    </div>
                </div>
            </div>

            // 流量时间线
            <div class="card chart-card">
                <div class="chart-header">
                    <h3>"流量趋势 (最近 5 分钟)"</h3>
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

            // 攻击源 TOP 10
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
                            let level = if rate.packets_per_sec > 10000 || rate.syn_packets_per_sec > 1000 {
                                "critical"
                            } else if rate.packets_per_sec > 1000 || rate.syn_packets_per_sec > 100 {
                                "warning"
                            } else {
                                "normal"
                            };
                            view! {
                                <div class="attacker-row">
                                    <span class="attacker-rank mono">{i + 1}</span>
                                    <span class="attacker-ip mono">{rate.ip}</span>
                                    <span class="attacker-pps mono">{format_rate(rate.packets_per_sec, "pps")}</span>
                                    <span class="attacker-protocol">
                                        {if rate.syn_packets_per_sec > rate.udp_packets_per_sec && rate.syn_packets_per_sec > rate.icmp_packets_per_sec {
                                            "SYN"
                                        } else if rate.udp_packets_per_sec > rate.icmp_packets_per_sec {
                                            "UDP"
                                        } else {
                                            "ICMP"
                                        }}
                                    </span>
                                    <span class=move || format!("attacker-level {}", level)>
                                        {if level == "critical" { "CRIT" } else if level == "warning" { "WARN" } else { "LOW" }}
                                    </span>
                                </div>
                            }
                        }).collect_view()
                    }}
                </div>
            </div>
        </div>
    }
}

#[component]
fn ProtocolBar(label: &'static str, value: u64, total: u64, color: &'static str) -> impl IntoView {
    let pct = if total > 0 { (value as f64 / total as f64 * 100.0) as u32 } else { 0 };
    view! {
        <div class="protocol-row">
            <span class="protocol-label">{label}</span>
            <div class="protocol-bar-bg">
                <div class="protocol-bar-fill" style=move || format!("width: {}%; background: {}", pct, color)/>
            </div>
            <span class="protocol-value mono">{format_rate(value, "pps")}</span>
            <span class="protocol-pct mono">{pct}%</span>
        </div>
    }
}

#[component]
fn ThresholdRow(label: &'static str, value: u64, current: u64, unit: &'static str) -> impl IntoView {
    let status = if current >= value { "var(--color-red)" } else { "var(--color-green)" };
    view! {
        <div class="threshold-row">
            <span class="threshold-label">{label}</span>
            <span class="threshold-value mono">{format_rate(value, unit)}</span>
            <span class="threshold-current mono" style=format!("color: {}", status)>
                {format_rate(current, unit)}
            </span>
        </div>
    }
}
