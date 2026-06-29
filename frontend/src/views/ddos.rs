//! DDoS 攻击监控 — 协议分布 + 阈值对比 + 攻击源排行 + 时间线 + 多窗口速率 + UDP 端口分布 + ICMP 类型分布

use leptos::*;

use crate::api;
use crate::charts::LineChart;
use crate::format::format_rate;
use crate::sse::SseState;

#[component]
pub fn DdosMonitor() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let rates_signal = sse.rates;
    let rate_history = sse.rate_history;

    let config = create_resource(|| (), |_| async { api::get_config().await.ok() });
    let windows = create_resource(|| (), |_| async { api::get_rate_windows().await.ok() });
    let udp_ports = create_resource(
        || (),
        |_| async { api::get_udp_port_distribution().await.ok() },
    );
    let icmp_types = create_resource(
        || (),
        |_| async { api::get_icmp_type_distribution().await.ok() },
    );
    let packet_sizes = create_resource(
        || (),
        |_| async { api::get_packet_size_distribution().await.ok() },
    );
    let ttl_dist = create_resource(|| (), |_| async { api::get_ttl_distribution().await.ok() });
    let ip_frags = create_resource(|| (), |_| async { api::get_ip_fragment_stats().await.ok() });
    let port_scans = create_resource(
        || (),
        |_| async { api::get_port_scan_detection().await.ok() },
    );
    let service_probes = create_resource(
        || (),
        |_| async { api::get_service_probe_detection().await.ok() },
    );

    let protocol_stats = move || {
        let rates = rates_signal.get().unwrap_or_default();
        let (mut syn, mut udp, mut icmp, mut ack, mut rst, mut fin) = (0, 0, 0, 0, 0, 0);
        for r in &rates {
            syn += r.syn_packets_per_sec;
            udp += r.udp_packets_per_sec;
            icmp += r.icmp_packets_per_sec;
            ack += r.ack_packets_per_sec;
            rst += r.rst_packets_per_sec;
            fin += r.fin_packets_per_sec;
        }
        (
            syn,
            udp,
            icmp,
            ack,
            rst,
            fin,
            syn + udp + icmp + ack + rst + fin,
        )
    };

    let top_attackers = move || {
        let mut sorted = rates_signal.get().unwrap_or_default();
        sorted.sort_by(|a, b| b.packets_per_sec.cmp(&a.packets_per_sec));
        sorted.into_iter().take(10).collect::<Vec<_>>()
    };

    let threat_level = move || {
        let rates = rates_signal.get().unwrap_or_default();
        if rates.is_empty() {
            return ("NORMAL", "var(--color-green)");
        }
        let max_pps = rates.iter().map(|r| r.packets_per_sec).max().unwrap_or(0);
        let max_syn = rates
            .iter()
            .map(|r| r.syn_packets_per_sec)
            .max()
            .unwrap_or(0);
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
                                let rates = rates_signal.get().unwrap_or_default();
                                let pps: u64 = rates.iter().map(|r| r.packets_per_sec).sum();
                                let bps: u64 = rates.iter().map(|r| r.bytes_per_sec).sum();
                                format!("{} / {}", format_rate(pps, "pps"), format_rate(bps, "bps"))
                            }}
                        </span>
                    </div>
                    <div class="threat-stat">
                        <span class="threat-stat-label">"跟踪 IP"</span>
                        <span class="threat-stat-value mono">
                            {move || rates_signal.get().map(|r| r.len()).unwrap_or(0).to_string()}
                        </span>
                    </div>
                </div>
            </div>

            <div class="dashboard-grid">
                <div class="card chart-card">
                    <div class="chart-header"><h3>"协议分布"</h3></div>
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
                    <div class="chart-header"><h3>"阈值对比"</h3></div>
                    <div class="threshold-list">
                        <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                            {move || {
                                let cfg = config.get().flatten();
                                let rates = rates_signal.get().unwrap_or_default();
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

            <div class="card chart-card">
                <div class="chart-header"><h3>"流量趋势 (最近 5 分钟)"</h3></div>
                <div class="chart-body" style="height:200px">
                    <LineChart
                        labels=Signal::derive(move || rate_history.get().labels.clone())
                        data=Signal::derive(move || rate_history.get().pps.clone())
                        color="var(--color-cyan)"
                        height=200
                    />
                </div>
            </div>

            <div class="card chart-card">
                <div class="chart-header"><h3>"多窗口速率检测"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let w = windows.get().flatten();
                        if let Some(w) = w {
                            view! {
                                <div class="window-grid">
                                    <div class="window-item">
                                        <div class="window-label">"短期 (~5s)"</div>
                                        <div class="window-value mono" style="color:var(--color-red)">
                                            {format_rate(w.pps_short, "pps")}
                                        </div>
                                        <div class="window-sub mono">{format_rate(w.bps_short, "bps")}</div>
                                        <div class="window-desc">"突发洪水检测"</div>
                                    </div>
                                    <div class="window-item">
                                        <div class="window-label">"中期 (~60s)"</div>
                                        <div class="window-value mono" style="color:var(--color-orange)">
                                            {format_rate(w.pps_mid, "pps")}
                                        </div>
                                        <div class="window-sub mono">{format_rate(w.bps_mid, "bps")}</div>
                                        <div class="window-desc">"持续攻击检测"</div>
                                    </div>
                                    <div class="window-item">
                                        <div class="window-label">"长期 (~5min)"</div>
                                        <div class="window-value mono" style="color:var(--color-cyan)">
                                            {format_rate(w.pps_long, "pps")}
                                        </div>
                                        <div class="window-sub mono">{format_rate(w.bps_long, "bps")}</div>
                                        <div class="window-desc">"慢速攻击检测"</div>
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card attackers-panel">
                <div class="chart-header"><h3>"攻击源 TOP 10"</h3></div>
                <div class="attackers-list">
                    {move || {
                        let attackers = top_attackers();
                        if attackers.is_empty() {
                            return view! { <div class="empty-state"><span>"无活跃攻击"</span></div> }.into_view();
                        }
                        attackers.into_iter().enumerate().map(|(i, rate)| {
                            let level = if rate.packets_per_sec > 10000 || rate.syn_packets_per_sec > 1000 { "critical" }
                                else if rate.packets_per_sec > 1000 || rate.syn_packets_per_sec > 100 { "warning" }
                                else { "normal" };
                            view! {
                                <div class="attacker-row">
                                    <span class="attacker-rank mono">{i + 1}</span>
                                    <span class="attacker-ip mono">{rate.ip}</span>
                                    <span class="attacker-pps mono">{format_rate(rate.packets_per_sec, "pps")}</span>
                                    <span class="attacker-protocol">
                                        {if rate.syn_packets_per_sec > rate.udp_packets_per_sec && rate.syn_packets_per_sec > rate.icmp_packets_per_sec { "SYN" }
                                         else if rate.udp_packets_per_sec > rate.icmp_packets_per_sec { "UDP" }
                                         else { "ICMP" }}
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

            <div class="card">
                <div class="chart-header"><h3>"UDP 端口分布"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let udp = udp_ports.get().flatten();
                        if let Some(udp) = udp {
                            if udp.ports.is_empty() {
                                return view! { <div class="empty-state"><span>"无 UDP 流量数据"</span></div> }.into_view();
                            }
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"跟踪端口数"</span>
                                        <span class="udp-summary-value mono">
                                            {udp.total_entries} " / " {udp.max_entries}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header">
                                            <span>"端口"</span>
                                            <span>"数据包"</span>
                                            <span>"字节"</span>
                                            <span>"最后出现"</span>
                                        </div>
                                        {udp.ports.iter().take(20).map(|port| {
                                            view! {
                                                <div class="udp-port-row">
                                                    <span class="udp-port-num mono">{port.port}</span>
                                                    <span class="udp-port-packets mono">{format_rate(port.packets, "")}</span>
                                                    <span class="udp-port-bytes mono">{format_rate(port.bytes, "B")}</span>
                                                    <span class="udp-port-age mono">{port.last_seen_secs}"s 前"</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"ICMP 类型分布"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let icmp = icmp_types.get().flatten();
                        if let Some(icmp) = icmp {
                            if icmp.types.is_empty() {
                                return view! { <div class="empty-state"><span>"无 ICMP 流量数据"</span></div> }.into_view();
                            }
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"跟踪类型数"</span>
                                        <span class="udp-summary-value mono">
                                            {icmp.total_entries} " / " {icmp.max_entries}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header">
                                            <span>"类型"</span>
                                            <span>"代码"</span>
                                            <span>"数据包"</span>
                                            <span>"字节"</span>
                                            <span>"最后出现"</span>
                                        </div>
                                        {icmp.types.iter().take(15).map(|entry| {
                                            let type_name = match entry.r#type {
                                                0 => "Echo Reply",
                                                3 => "Dest Unreachable",
                                                8 => "Echo Request",
                                                11 => "Time Exceeded",
                                                13 => "Timestamp",
                                                14 => "Timestamp Reply",
                                                _ => "Other",
                                            };
                                            view! {
                                                <div class="udp-port-row">
                                                    <span class="udp-port-num mono">{entry.r#type}" "{type_name}</span>
                                                    <span class="mono">{entry.code}</span>
                                                    <span class="udp-port-packets mono">{format_rate(entry.packets, "")}</span>
                                                    <span class="udp-port-bytes mono">{format_rate(entry.bytes, "B")}</span>
                                                    <span class="udp-port-age mono">{entry.last_seen_secs}"s 前"</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"包大小分布"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let sizes = packet_sizes.get().flatten();
                        if let Some(sizes) = sizes {
                            if sizes.total == 0 {
                                return view! { <div class="empty-state"><span>"无流量数据"</span></div> }.into_view();
                            }
                            let max_count = sizes.counts.iter().copied().max().unwrap_or(1);
                            // 颜色：小包(红-可疑) → 中包(黄) → 正常包(绿) → 大包(蓝)
                            let colors = ["var(--color-red)", "var(--color-orange)", "var(--color-yellow, #eab308)", "var(--color-green)", "var(--color-cyan)"];
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"总数据包"</span>
                                        <span class="udp-summary-value mono">
                                            {format_rate(sizes.total, "")}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header" style="grid-template-columns: 80px 1fr 80px 60px;">
                                            <span>"大小范围"</span>
                                            <span>"数据包"</span>
                                            <span>"占比"</span>
                                        </div>
                                        {sizes.labels.iter().zip(sizes.counts.iter()).zip(sizes.percentages.iter()).enumerate().map(|(i, ((label, count), pct))| {
                                            let bar_pct = if max_count > 0 { (*count as f64 / max_count as f64 * 100.0) as u32 } else { 0 };
                                            let color = colors.get(i).copied().unwrap_or("var(--text-muted)");
                                            view! {
                                                <div class="udp-port-row" style="grid-template-columns: 80px 1fr 80px 60px;">
                                                    <span class="udp-port-num mono" style=move || format!("color:{}", color)>{label}</span>
                                                    <div class="protocol-bar-bg" style="height:16px;">
                                                        <div class="protocol-bar-fill" style=move || format!("width:{}%; background:{}", bar_pct, color)/>
                                                    </div>
                                                    <span class="udp-port-packets mono">{format_rate(*count, "")}</span>
                                                    <span class="mono" style="font-size:11px;color:var(--text-secondary)">{format!("{:.1}%", pct)}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"TTL 分布"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let ttl = ttl_dist.get().flatten();
                        if let Some(ttl) = ttl {
                            if ttl.total == 0 {
                                return view! { <div class="empty-state"><span>"无流量数据"</span></div> }.into_view();
                            }
                            let max_count = ttl.counts.iter().copied().max().unwrap_or(1);
                            // 颜色：扫描(红-可疑) → 短TTL(橙) → 正常(绿) → 长TTL(蓝) → 最大(紫-可能伪造)
                            let colors = ["var(--color-red)", "var(--color-orange)", "var(--color-green)", "var(--color-cyan)", "var(--color-blue, #3b82f6)", "var(--color-purple, #a855f7)"];
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"总数据包"</span>
                                        <span class="udp-summary-value mono">
                                            {format_rate(ttl.total, "")}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header" style="grid-template-columns: 80px 1fr 80px 60px;">
                                            <span>"TTL 范围"</span>
                                            <span>"数据包"</span>
                                            <span>"占比"</span>
                                        </div>
                                        {ttl.labels.iter().zip(ttl.counts.iter()).zip(ttl.percentages.iter()).enumerate().map(|(i, ((label, count), pct))| {
                                            let bar_pct = if max_count > 0 { (*count as f64 / max_count as f64 * 100.0) as u32 } else { 0 };
                                            let color = colors.get(i).copied().unwrap_or("var(--text-muted)");
                                            view! {
                                                <div class="udp-port-row" style="grid-template-columns: 80px 1fr 80px 60px;">
                                                    <span class="udp-port-num mono" style=move || format!("color:{}", color)>{label}</span>
                                                    <div class="protocol-bar-bg" style="height:16px;">
                                                        <div class="protocol-bar-fill" style=move || format!("width:{}%; background:{}", bar_pct, color)/>
                                                    </div>
                                                    <span class="udp-port-packets mono">{format_rate(*count, "")}</span>
                                                    <span class="mono" style="font-size:11px;color:var(--text-secondary)">{format!("{:.1}%", pct)}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"IP 分片统计"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let frags = ip_frags.get().flatten();
                        if let Some(frags) = frags {
                            if frags.total_packets == 0 {
                                return view! { <div class="empty-state"><span>"无流量数据"</span></div> }.into_view();
                            }
                            // 分片比例颜色：< 1% 绿色（正常），1-5% 黄色（注意），> 5% 红色（异常）
                            let ratio_color = if frags.fragment_ratio > 5.0 {
                                "var(--color-red)"
                            } else if frags.fragment_ratio > 1.0 {
                                "var(--color-orange)"
                            } else {
                                "var(--color-green)"
                            };
                            let status_text = if frags.fragment_ratio > 5.0 {
                                "异常偏高"
                            } else if frags.fragment_ratio > 1.0 {
                                "略高"
                            } else {
                                "正常"
                            };
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"总 IP 包"</span>
                                        <span class="udp-summary-value mono">
                                            {format_rate(frags.total_packets, "")}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header" style="grid-template-columns: 120px 1fr 80px;">
                                            <span>"指标"</span>
                                            <span>"数值"</span>
                                        </div>
                                        <div class="udp-port-row" style="grid-template-columns: 120px 1fr 80px;">
                                            <span class="udp-port-num mono">"分片包数"</span>
                                            <div class="protocol-bar-bg" style="height:16px;">
                                                {let bar_pct = if frags.total_packets > 0 {
                                                    (frags.fragment_packets as f64 / frags.total_packets as f64 * 100.0).min(100.0) as u32
                                                } else { 0 };
                                                view! { <div class="protocol-bar-fill" style=move || format!("width:{}%; background:{}", bar_pct.max(1), ratio_color) /> }
                                                }
                                            </div>
                                            <span class="udp-port-packets mono">{format_rate(frags.fragment_packets, "")}</span>
                                        </div>
                                        <div class="udp-port-row" style="grid-template-columns: 120px 1fr 80px;">
                                            <span class="udp-port-num mono" style=move || format!("color:{}", ratio_color)>"分片比例"</span>
                                            <span class="mono" style="font-size:13px;">{status_text}</span>
                                            <span class="mono" style=move || format!("color:{}", ratio_color)>{format!("{:.2}%", frags.fragment_ratio)}</span>
                                        </div>
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"端口扫描检测"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let scans = port_scans.get().flatten();
                        if let Some(scans) = scans {
                            if scans.scanners.is_empty() {
                                return view! { <div class="empty-state"><span>"未检测到端口扫描"</span></div> }.into_view();
                            }
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"检测到的扫描者"</span>
                                        <span class="udp-summary-value mono" style="color:var(--color-red)">
                                            {scans.scanners.len().to_string()}
                                        </span>
                                        <span class="udp-summary-label" style="margin-left:16px">"阈值"</span>
                                        <span class="udp-summary-value mono">
                                            {format!("≥ {} 端口", scans.threshold)}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header" style="grid-template-columns: 140px 100px 100px;">
                                            <span>"IP 地址"</span>
                                            <span>"不同端口数"</span>
                                            <span>"数据包数"</span>
                                        </div>
                                        {scans.scanners.iter().map(|s| {
                                            let severity = if s.unique_ports > 50 {
                                                "var(--color-red)"
                                            } else if s.unique_ports > 20 {
                                                "var(--color-orange)"
                                            } else {
                                                "var(--color-yellow, #eab308)"
                                            };
                                            view! {
                                                <div class="udp-port-row" style="grid-template-columns: 140px 100px 100px;">
                                                    <span class="udp-port-num mono">{s.ip.clone()}</span>
                                                    <span class="mono" style=move || format!("color:{}", severity)>
                                                        {s.unique_ports.to_string()}
                                                    </span>
                                                    <span class="udp-port-packets mono">{format_rate(s.packets, "")}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>

            <div class="card">
                <div class="chart-header"><h3>"服务探测检测"</h3></div>
                <Suspense fallback=|| view! { <div>"加载中..."</div> }>
                    {move || {
                        let probes = service_probes.get().flatten();
                        if let Some(probes) = probes {
                            if probes.probes.is_empty() {
                                return view! { <div class="empty-state"><span>"未检测到服务探测"</span></div> }.into_view();
                            }
                            view! {
                                <div class="udp-ports-panel">
                                    <div class="udp-ports-summary">
                                        <span class="udp-summary-label">"检测到的探测者"</span>
                                        <span class="udp-summary-value mono" style="color:var(--color-orange)">
                                            {probes.probes.len().to_string()}
                                        </span>
                                        <span class="udp-summary-label" style="margin-left:16px">"阈值"</span>
                                        <span class="udp-summary-value mono">
                                            {format!("≥ {} 种协议", probes.threshold)}
                                        </span>
                                    </div>
                                    <div class="udp-ports-list">
                                        <div class="udp-port-header" style="grid-template-columns: 140px 100px 100px;">
                                            <span>"IP 地址"</span>
                                            <span>"协议类型数"</span>
                                            <span>"数据包数"</span>
                                        </div>
                                        {probes.probes.iter().map(|p| {
                                            let color = if p.protocol_count >= 3 {
                                                "var(--color-red)"
                                            } else {
                                                "var(--color-orange)"
                                            };
                                            view! {
                                                <div class="udp-port-row" style="grid-template-columns: 140px 100px 100px;">
                                                    <span class="udp-port-num mono">{p.ip.clone()}</span>
                                                    <span class="mono" style=move || format!("color:{}", color)>
                                                        {p.protocol_count.to_string()}
                                                    </span>
                                                    <span class="udp-port-packets mono">{format_rate(p.packets, "")}</span>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            }.into_view()
                        } else {
                            view! { <div>"暂无数据"</div> }.into_view()
                        }
                    }}
                </Suspense>
            </div>
        </div>
    }
}

#[component]
fn ProtocolBar(label: &'static str, value: u64, total: u64, color: &'static str) -> impl IntoView {
    let pct = if total > 0 {
        (value as f64 / total as f64 * 100.0) as u32
    } else {
        0
    };
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
fn ThresholdRow(
    label: &'static str,
    value: u64,
    current: u64,
    unit: &'static str,
) -> impl IntoView {
    let status = if current >= value {
        "var(--color-red)"
    } else {
        "var(--color-green)"
    };
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
