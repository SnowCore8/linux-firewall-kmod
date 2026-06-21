//! 仪表盘 — 统计卡片 + 图表 + 内核统计

use leptos::*;

use crate::api::StatsResponse;
use crate::charts::{LineChart, PieChart};
use crate::components::stat_card::StatCard;
use crate::format::{format_number, format_uptime};
use crate::sse;

#[component]
pub fn Dashboard() -> impl IntoView {
    let stats_signal = sse::use_sse_stats();

    // 迷你图数据
    let spark_active = create_rw_signal(Vec::<f64>::new());
    let spark_today = create_rw_signal(Vec::<f64>::new());
    let spark_failed = create_rw_signal(Vec::<f64>::new());
    let spark_ddos = create_rw_signal(Vec::<f64>::new());

    // 监听 stats 变化，更新迷你图
    create_effect(move |_| {
        if let Some(s) = stats_signal.try_get().flatten() {
            push_spark(spark_active, s.current_bans as f64);
            push_spark(spark_today, s.today_bans as f64);
            push_spark(spark_failed, s.failed_attempts as f64);
            push_spark(spark_ddos, s.ddos_events as f64);
        }
    });

    let stats_default = move || StatsResponse::default();

    view! {
        <div class="dashboard">
            // 统计卡片
            <div class="stats-grid">
                <StatCard
                    label="活跃封禁"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_number(s.current_bans, false)
                    })
                    accent="danger"
                    trend=Signal::derive(move || spark_active.get())
                />
                <StatCard
                    label="今日封禁"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_number(s.today_bans, false)
                    })
                    accent="primary"
                    trend=Signal::derive(move || spark_today.get())
                />
                <StatCard
                    label="失败尝试"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_number(s.failed_attempts, false)
                    })
                    accent="warning"
                    trend=Signal::derive(move || spark_failed.get())
                />
                <StatCard
                    label="DDoS 事件"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_number(s.ddos_events, false)
                    })
                    accent="purple"
                    trend=Signal::derive(move || spark_ddos.get())
                />
                <StatCard
                    label="运行时间"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_uptime(s.uptime_seconds)
                    })
                    accent="success"
                />
                <StatCard
                    label="白名单数"
                    value=Signal::derive(move || {
                        let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                        format_number(s.whitelist_count, false)
                    })
                    accent="info"
                />
            </div>

            // 图表行
            <div class="charts-grid">
                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"封禁趋势（24小时）"</h3>
                    </div>
                    <div class="chart-body">
                        <LineChart
                            labels=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).ban_trend.labels
                            })
                            data=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).ban_trend.values
                            })
                        />
                    </div>
                </div>
                <div class="card chart-card">
                    <div class="chart-header">
                        <h3>"Jail 分布"</h3>
                    </div>
                    <div class="chart-body">
                        <PieChart
                            labels=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).jail_distribution.labels
                            })
                            data=Signal::derive(move || {
                                stats_signal.try_get().flatten().unwrap_or_else(|| stats_default()).jail_distribution.values
                            })
                        />
                    </div>
                </div>
            </div>

            // 内核统计
            <div class="section-header">
                <h2>"内核模块统计"</h2>
            </div>
            <div class="kernel-grid">
                <KernelStat label="当前封禁" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.current_bans, false)
                }/>
                <KernelStat label="累计封禁" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.total_bans, false)
                }/>
                <KernelStat label="累计解封" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.total_unbans, false)
                }/>
                <KernelStat label="丢弃数据包" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.packets_dropped, true)
                }/>
                <KernelStat label="通过数据包" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.packets_accepted, true)
                }/>
                <KernelStat label="白名单条目" value=move || {
                    let s = stats_signal.try_get().flatten().unwrap_or_else(|| stats_default());
                    format_number(s.whitelist_count, false)
                }/>
            </div>
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
        <div class="kernel-card">
            <span class="kernel-label">{label}</span>
            <span class="kernel-value mono">{move || value()}</span>
        </div>
    }
}
