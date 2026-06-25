//! 系统设置

use leptos::*;

use crate::api::{self, WebuiConfig};
use crate::format::{format_number, format_uptime};
use crate::sse::SseState;

#[component]
pub fn Settings() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let stats_signal = sse.stats;
    let config = create_resource(|| (), |_| async { api::get_config().await.ok() });
    let saving = create_rw_signal(false);
    let save_msg = create_rw_signal(String::new());

    let edit_sse = create_rw_signal(String::new());
    let edit_warning_pps = create_rw_signal(String::new());
    let edit_critical_pps = create_rw_signal(String::new());
    let edit_warning_syn = create_rw_signal(String::new());
    let edit_critical_syn = create_rw_signal(String::new());
    // 协议专项阈值
    let edit_max_syn = create_rw_signal(String::new());
    let edit_max_udp = create_rw_signal(String::new());
    let edit_max_icmp = create_rw_signal(String::new());
    let edit_max_ack = create_rw_signal(String::new());
    let edit_max_rst = create_rw_signal(String::new());
    let edit_max_fin = create_rw_signal(String::new());
    // DDoS 检测开关
    let static_thresh = create_rw_signal(true);
    let dynamic_thresh = create_rw_signal(false);
    let ddos_enabled = create_rw_signal(true);
    // 容量配置
    let edit_max_ban_entries = create_rw_signal(String::new());
    let edit_max_whitelist_entries = create_rw_signal(String::new());
    let edit_max_rate_entries = create_rw_signal(String::new());
    let edit_max_local_ip_cache = create_rw_signal(String::new());

    create_effect(move |_| {
        if let Some(Some(cfg)) = config.get() {
            let _ = edit_sse.try_set(cfg.sse_push_interval.to_string());
            let _ = edit_warning_pps.try_set(cfg.rate_warning_pps.to_string());
            let _ = edit_critical_pps.try_set(cfg.rate_critical_pps.to_string());
            let _ = edit_warning_syn.try_set(cfg.rate_warning_syn.to_string());
            let _ = edit_critical_syn.try_set(cfg.rate_critical_syn.to_string());
            // 协议专项阈值
            let _ = edit_max_syn.try_set(cfg.max_syn_per_second.to_string());
            let _ = edit_max_udp.try_set(cfg.max_udp_per_second.to_string());
            let _ = edit_max_icmp.try_set(cfg.max_icmp_per_second.to_string());
            let _ = edit_max_ack.try_set(cfg.max_ack_per_second.to_string());
            let _ = edit_max_rst.try_set(cfg.max_rst_per_second.to_string());
            let _ = edit_max_fin.try_set(cfg.max_fin_per_second.to_string());
            // DDoS 检测开关
            let _ = static_thresh.try_set(cfg.static_threshold);
            let _ = dynamic_thresh.try_set(cfg.dynamic_threshold);
            let _ = ddos_enabled.try_set(cfg.ddos_detection);
            // 容量配置
            let _ = edit_max_ban_entries.try_set(cfg.max_ban_entries.to_string());
            let _ = edit_max_whitelist_entries.try_set(cfg.max_whitelist_entries.to_string());
            let _ = edit_max_rate_entries.try_set(cfg.max_rate_entries.to_string());
            let _ = edit_max_local_ip_cache.try_set(cfg.max_local_ip_cache.to_string());
        }
    });

    let do_save = move |_| {
        saving.set(true);
        save_msg.set(String::new());
        let sse_val = edit_sse.get().parse::<u32>().ok();
        let warning_pps = edit_warning_pps.get().parse::<u64>().ok();
        let critical_pps = edit_critical_pps.get().parse::<u64>().ok();
        let warning_syn = edit_warning_syn.get().parse::<u64>().ok();
        let critical_syn = edit_critical_syn.get().parse::<u64>().ok();
        // 协议专项阈值
        let max_syn = edit_max_syn.get().parse::<u32>().ok();
        let max_udp = edit_max_udp.get().parse::<u32>().ok();
        let max_icmp = edit_max_icmp.get().parse::<u32>().ok();
        let max_ack = edit_max_ack.get().parse::<u32>().ok();
        let max_rst = edit_max_rst.get().parse::<u32>().ok();
        let max_fin = edit_max_fin.get().parse::<u32>().ok();
        // DDoS 检测开关
        let static_thresh = static_thresh.get();
        let dynamic_thresh = dynamic_thresh.get();
        let ddos_enabled = ddos_enabled.get();
        // 容量配置
        let max_ban_entries = edit_max_ban_entries.get().parse::<u32>().ok();
        let max_whitelist_entries = edit_max_whitelist_entries.get().parse::<u32>().ok();
        let max_rate_entries = edit_max_rate_entries.get().parse::<u32>().ok();
        let max_local_ip_cache = edit_max_local_ip_cache.get().parse::<u32>().ok();
        spawn_local(async move {
            let req = api::UpdateConfigRequest {
                sse_push_interval: sse_val,
                rate_warning_pps: warning_pps,
                rate_critical_pps: critical_pps,
                rate_warning_syn: warning_syn,
                rate_critical_syn: critical_syn,
                max_syn_per_second: max_syn,
                max_udp_per_second: max_udp,
                max_icmp_per_second: max_icmp,
                max_ack_per_second: max_ack,
                max_rst_per_second: max_rst,
                max_fin_per_second: max_fin,
                static_threshold: Some(static_thresh),
                dynamic_threshold: Some(dynamic_thresh),
                ddos_detection: Some(ddos_enabled),
                max_ban_entries,
                max_whitelist_entries,
                max_rate_entries,
                max_local_ip_cache,
            };
            match api::update_config(req).await {
                Ok(_) => {
                    let _ = saving.try_set(false);
                    let _ = save_msg.try_set("保存成功".to_string());
                }
                Err(msg) => {
                    let _ = saving.try_set(false);
                    let _ = save_msg.try_set(format!("保存失败：{}", msg));
                }
            }
        });
    };

    let default_config = move || WebuiConfig {
        sse_push_interval: 1,
        rate_warning_pps: 1000,
        rate_critical_pps: 10000,
        rate_warning_syn: 100,
        rate_critical_syn: 1000,
        max_syn_per_second: 200,
        max_udp_per_second: 1000,
        max_icmp_per_second: 50,
        max_ack_per_second: 2000,
        max_rst_per_second: 200,
        max_fin_per_second: 200,
        static_threshold: true,
        dynamic_threshold: false,
        ddos_detection: true,
        max_ban_entries: 65535,
        max_whitelist_entries: 65535,
        max_rate_entries: 65535,
        max_local_ip_cache: 65535,
    };

    view! {
        <div class="settings-page">
            <h2 class="section-title">"系统设置"</h2>
            <div class="settings-grid">
                <div class="card settings-card">
                    <h3>"守护进程"</h3>
                    <div class="settings-list">
                        <SettingItem label="守护进程版本" value=move || stats_signal.get().map(|s| format!("v{}", s.daemon_version)).unwrap_or_else(|| "N/A".to_string())/>
                        <SettingItem label="内核模块版本" value=move || stats_signal.get().map(|s| format!("v{}", s.kernel_version)).unwrap_or_else(|| "N/A".to_string())/>
                        <SettingItem label="运行时间" value=move || stats_signal.get().map(|s| format_uptime(s.uptime_seconds)).unwrap_or_else(|| "N/A".to_string())/>
                        <SettingItem label="今日封禁" value=move || stats_signal.get().map(|s| format_number(s.today_bans, false)).unwrap_or_else(|| "0".to_string())/>
                        <SettingItem label="失败尝试" value=move || stats_signal.get().map(|s| format_number(s.failed_attempts, false)).unwrap_or_else(|| "0".to_string())/>
                        <SettingItem label="DDoS 事件" value=move || stats_signal.get().map(|s| format_number(s.ddos_events, false)).unwrap_or_else(|| "0".to_string())/>
                    </div>
                </div>
                <div class="card settings-card">
                    <h3>"内核模块"</h3>
                    <div class="settings-list">
                        <SettingItem label="封禁表容量" value=|| "4096".to_string()/>
                        <SettingItem label="白名单容量" value=|| "64".to_string()/>
                        <SettingItem label="当前封禁" value=move || stats_signal.get().map(|s| format_number(s.current_bans, false)).unwrap_or_else(|| "0".to_string())/>
                        <SettingItem label="白名单条目" value=move || stats_signal.get().map(|s| format_number(s.whitelist_count, false)).unwrap_or_else(|| "0".to_string())/>
                        <SettingItem label="丢弃数据包" value=move || stats_signal.get().map(|s| format_number(s.packets_dropped, true)).unwrap_or_else(|| "0".to_string())/>
                    </div>
                </div>
                <div class="card settings-card">
                    <h3>"Web UI 配置"</h3>
                    <Suspense fallback=|| view! { <div style="padding:12px;color:var(--text-muted)">"加载中..."</div> }>
                        {move || {
                            let _cfg = config.get().flatten().unwrap_or_else(|| default_config());
                            view! {
                                <div class="settings-list">
                                    <EditableItem label="SSE 推送间隔 (秒)" value=edit_sse/>
                                    <EditableItem label="速率警告阈值 (pps)" value=edit_warning_pps/>
                                    <EditableItem label="速率严重阈值 (pps)" value=edit_critical_pps/>
                                    <EditableItem label="SYN 警告阈值 (pps)" value=edit_warning_syn/>
                                    <EditableItem label="SYN 严重阈值 (pps)" value=edit_critical_syn/>
                                </div>
                            }
                        }}
                    </Suspense>
                </div>
                <div class="card settings-card">
                    <h3>"协议专项阈值 (每秒)"</h3>
                    <Suspense fallback=|| view! { <div style="padding:12px;color:var(--text-muted)">"加载中..."</div> }>
                        {move || {
                            let _cfg = config.get().flatten().unwrap_or_else(|| default_config());
                            view! {
                                <div class="settings-list">
                                    <EditableItem label="SYN Flood" value=edit_max_syn/>
                                    <EditableItem label="UDP Flood" value=edit_max_udp/>
                                    <EditableItem label="ICMP Flood" value=edit_max_icmp/>
                                    <EditableItem label="ACK Flood" value=edit_max_ack/>
                                    <EditableItem label="RST Flood" value=edit_max_rst/>
                                    <EditableItem label="FIN Flood" value=edit_max_fin/>
                                </div>
                            }
                        }}
                    </Suspense>
                </div>
                <div class="card settings-card">
                    <h3>"DDoS 检测算法"</h3>
                    <Suspense fallback=|| view! { <div style="padding:12px;color:var(--text-muted)">"加载中..."</div> }>
                        {move || {
                            let _cfg = config.get().flatten().unwrap_or_else(|| default_config());
                            view! {
                                <div class="settings-list">
                                    <ToggleItem label="DDoS 检测总开关" value=ddos_enabled/>
                                    <ToggleItem label="静态阈值算法" value=static_thresh/>
                                    <ToggleItem label="动态阈值算法 (基线×倍数)" value=dynamic_thresh/>
                                </div>
                            }
                        }}
                    </Suspense>
                </div>
                <div class="card settings-card">
                    <h3>"容量配置"</h3>
                    <Suspense fallback=|| view! { <div style="padding:12px;color:var(--text-muted)">"加载中..."</div> }>
                        {move || {
                            let _cfg = config.get().flatten().unwrap_or_else(|| default_config());
                            view! {
                                <div class="settings-list">
                                    <EditableItem label="封禁表最大条目数" value=edit_max_ban_entries/>
                                    <EditableItem label="白名单最大条目数" value=edit_max_whitelist_entries/>
                                    <EditableItem label="速率表最大条目数" value=edit_max_rate_entries/>
                                    <EditableItem label="本地 IP 缓存最大条目数" value=edit_max_local_ip_cache/>
                                </div>
                                <div style="margin-top:16px;display:flex;gap:12px;align-items:center;justify-content:center">
                                    <button class="btn btn-primary" on:click=do_save disabled=move || saving.get()>
                                        {move || if saving.get() { "保存中..." } else { "保存配置" }}
                                    </button>
                                    <span style="color:var(--text-muted);font-size:13px">{move || save_msg.get()}</span>
                                </div>
                            }
                        }}
                    </Suspense>
                </div>
                <div class="card settings-card">
                    <h3>"关于"</h3>
                    <div class="settings-list">
                        <SettingItem label="项目" value=|| "Linux Firewall Kernel Module".to_string()/>
                        <SettingItem label="许可证" value=|| "MIT License".to_string()/>
                        <div class="setting-item">
                            <span class="setting-label">"仓库"</span>
                            <a class="setting-value" style="color:var(--accent-primary);text-decoration:none;font-weight:500"
                                href="https://github.com/SnowCore8/linux-firewall-kmod" target="_blank">"GitHub ↗"</a>
                        </div>
                        <SettingItem label="技术栈" value=|| "Rust + C + Leptos WASM".to_string()/>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
fn SettingItem(label: &'static str, value: impl Fn() -> String + Send + Sync + 'static) -> impl IntoView {
    view! {
        <div class="setting-item">
            <span class="setting-label">{label}</span>
            <span class="setting-value">{move || value()}</span>
        </div>
    }
}

#[component]
fn ToggleItem(label: &'static str, value: RwSignal<bool>) -> impl IntoView {
    view! {
        <div class="setting-item">
            <span class="setting-label">{label}</span>
            <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                <input type="checkbox"
                    checked=move || value.get()
                    on:change=move |e: leptos::ev::Event| {
                        use wasm_bindgen::JsCast;
                        let target: web_sys::EventTarget = e.target().unwrap();
                        let input: web_sys::HtmlInputElement = target.unchecked_into();
                        value.set(input.checked());
                    }
                    style="width:16px;height:16px;accent-color:var(--accent-primary)"
                />
                <span style="font-size:14px;color:var(--text-muted)">{move || if value.get() { "开启" } else { "关闭" }}</span>
            </label>
        </div>
    }
}

#[component]
fn EditableItem(label: &'static str, value: RwSignal<String>) -> impl IntoView {
    view! {
        <div class="setting-item">
            <span class="setting-label">{label}</span>
            <input type="number" class="input mono" style="width:120px;padding:5px 8px;font-size:12px"
                prop:value=move || value.get()
                on:input=move |e| value.set(event_target_value(&e))/>
        </div>
    }
}
