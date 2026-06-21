//! 系统设置

use leptos::*;

use crate::api::{self, WebuiConfig};
use crate::format::{format_number, format_uptime};
use crate::sse;

#[component]
pub fn Settings() -> impl IntoView {
    let stats_signal = sse::use_sse_stats();
    let config = create_resource(|| (), |_| async { api::get_config().await.ok() });

    let default_config = move || WebuiConfig {
        sse_push_interval: 1,
        rate_warning_pps: 1000,
        rate_critical_pps: 10000,
        rate_warning_syn: 100,
        rate_critical_syn: 1000,
    };

    view! {
        <div class="settings-page">
            <h2 class="section-title">"系统设置"</h2>

            <div class="settings-grid">
                // 守护进程信息
                <div class="card settings-card">
                    <h3>"守护进程"</h3>
                    <div class="settings-list">
                        <SettingItem label="版本" value=|| "v2.2.0".to_string()/>
                        <SettingItem label="运行时间" value=move || {
                            let s = stats_signal.get();
                            s.map(|s| format_uptime(s.uptime_seconds)).unwrap_or_else(|| "N/A".to_string())
                        }/>
                        <SettingItem label="今日封禁" value=move || {
                            stats_signal.get().map(|s| format_number(s.today_bans, false)).unwrap_or_else(|| "0".to_string())
                        }/>
                        <SettingItem label="失败尝试" value=move || {
                            stats_signal.get().map(|s| format_number(s.failed_attempts, false)).unwrap_or_else(|| "0".to_string())
                        }/>
                        <SettingItem label="DDoS 事件" value=move || {
                            stats_signal.get().map(|s| format_number(s.ddos_events, false)).unwrap_or_else(|| "0".to_string())
                        }/>
                    </div>
                </div>

                // 内核模块
                <div class="card settings-card">
                    <h3>"内核模块"</h3>
                    <div class="settings-list">
                        <SettingItem label="封禁表容量" value=|| "4096".to_string()/>
                        <SettingItem label="白名单容量" value=|| "64".to_string()/>
                        <SettingItem label="当前封禁" value=move || {
                            stats_signal.get().map(|s| format_number(s.current_bans, false)).unwrap_or_else(|| "0".to_string())
                        }/>
                        <SettingItem label="白名单条目" value=move || {
                            stats_signal.get().map(|s| format_number(s.whitelist_count, false)).unwrap_or_else(|| "0".to_string())
                        }/>
                        <SettingItem label="丢弃数据包" value=move || {
                            stats_signal.get().map(|s| format_number(s.packets_dropped, true)).unwrap_or_else(|| "0".to_string())
                        }/>
                    </div>
                </div>

                // Web UI 配置
                <div class="card settings-card">
                    <h3>"Web UI 配置"</h3>
                    <Suspense fallback=|| view! { <div style="padding:12px;color:var(--text-muted)">"加载中..."</div> }>
                        {move || {
                            let cfg = config.get().flatten().unwrap_or_else(|| default_config());
                            view! {
                                <div class="settings-list">
                                    <SettingItem label="SSE 推送间隔" value=move || format!("{}s", cfg.sse_push_interval)/>
                                    <SettingItem label="速率警告阈值" value=move || format!("{} pps", format_number(cfg.rate_warning_pps, false))/>
                                    <SettingItem label="速率严重阈值" value=move || format!("{} pps", format_number(cfg.rate_critical_pps, false))/>
                                    <SettingItem label="SYN 警告阈值" value=move || format!("{} pps", format_number(cfg.rate_warning_syn, false))/>
                                    <SettingItem label="SYN 严重阈值" value=move || format!("{} pps", format_number(cfg.rate_critical_syn, false))/>
                                </div>
                            }
                        }}
                    </Suspense>
                </div>

                // 关于
                <div class="card settings-card">
                    <h3>"关于"</h3>
                    <div class="settings-list">
                        <SettingItem label="项目" value=|| "Linux Firewall Kernel Module".to_string()/>
                        <SettingItem label="许可证" value=|| "MIT License".to_string()/>
                        <div class="setting-item">
                            <span class="setting-label">"仓库"</span>
                            <a class="setting-value" style="color:var(--accent-primary);text-decoration:none"
                                href="https://github.com/SnowCore8/linux-firewall-kmod" target="_blank">
                                "GitHub"
                            </a>
                        </div>
                        <SettingItem label="技术栈" value=|| "Rust + C Kernel Module + Leptos WASM".to_string()/>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn SettingItem(
    label: &'static str,
    value: impl Fn() -> String + Send + Sync + 'static,
) -> impl IntoView {
    view! {
        <div class="setting-item">
            <span class="setting-label">{label}</span>
            <span class="setting-value mono">{move || value()}</span>
        </div>
    }
}
