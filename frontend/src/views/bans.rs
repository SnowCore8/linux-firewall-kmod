//! 封禁管理 — 封禁原因分布 + 封禁趋势 + 表格 + 搜索 + 手动封禁 + 封禁详情

use leptos::*;
use wasm_bindgen::JsCast;

use crate::api::{self, BanDetailResponse, BanEffectivenessResponse, BanResponse, StatsResponse};
use crate::charts::{LineChart, PieChart};
use crate::components::toast::ToastState;
use crate::format::{copy_to_clipboard, format_datetime, format_duration};
use crate::sse::SseState;
use crate::validation;

/// 搜索关键词高亮 — 将匹配文本包裹在 <mark> 标签中
fn highlight_text(text: &str, keyword: &str) -> impl IntoView {
    if keyword.is_empty() {
        return view! { <span>{text.to_string()}</span> }.into_view();
    }
    let lower_text = text.to_lowercase();
    let lower_kw = keyword.to_lowercase();
    let mut result: Vec<View> = Vec::new();
    let mut last = 0usize;
    for (start, _) in lower_text.match_indices(&lower_kw) {
        if start > last {
            result.push(view! { <span>{text[last..start].to_string()}</span> }.into_view());
        }
        let matched = text[start..start + lower_kw.len()].to_string();
        result.push(
            view! {
                <mark style="background:var(--color-yellow,#eab308);color:#000;padding:0 1px;border-radius:2px;font-style:normal">
                    {matched}
                </mark>
            }
            .into_view(),
        );
        last = start + lower_kw.len();
    }
    if last < text.len() {
        result.push(view! { <span>{text[last..].to_string()}</span> }.into_view());
    }
    if result.is_empty() {
        view! { <span>{text.to_string()}</span> }.into_view()
    } else {
        view! { <span>{result}</span> }.into_view()
    }
}

#[component]
pub fn Bans() -> impl IntoView {
    let sse = use_context::<SseState>().expect("SseState not found");
    let toast_state = use_context::<ToastState>().expect("ToastState not found");
    let bans_signal = sse.bans;
    let stats_signal = sse.stats;

    let page = create_rw_signal(1_u32);
    const PAGE_SIZE: u32 = 20;
    let sort_by = create_rw_signal("banned_at_desc".to_string());
    let search = create_rw_signal(String::new());

    // 批量选择状态
    let selected_ips = create_rw_signal(std::collections::HashSet::new());
    let batch_loading = create_rw_signal(false);
    let last_clicked_ip = create_rw_signal(None::<String>);

    // 实时倒计时 tick（每秒递增，驱动剩余时间刷新）
    let countdown_tick = create_rw_signal(0_u64);
    set_interval(
        move || countdown_tick.update(|t| *t = t.wrapping_add(1)),
        std::time::Duration::from_secs(1),
    );

    // 封禁详情模态框状态
    let detail_ip = create_rw_signal(None::<String>);
    let detail_data = create_rw_signal(None::<BanDetailResponse>);
    let detail_loading = create_rw_signal(false);

    // ESC 键关闭模态框 / 清除搜索，`/` 键聚焦搜索框
    let search_ref = create_node_ref::<html::Input>();
    if let Some(window) = web_sys::window() {
        let search_for_focus = search_ref;
        let search_for_clear = search;
        let handler =
            wasm_bindgen::closure::Closure::wrap(Box::new(move |e: web_sys::KeyboardEvent| {
                // 如果焦点在输入框内，不拦截 `/`
                let tag = web_sys::window()
                    .and_then(|w| w.document())
                    .and_then(|d| d.active_element())
                    .map(|el| el.tag_name().to_lowercase())
                    .unwrap_or_default();
                let is_input_focused = tag == "input" || tag == "textarea" || tag == "select";

                if e.key() == "Escape" {
                    // 先关闭模态框
                    detail_ip.set(None);
                    detail_data.set(None);
                    // 如果搜索框有内容，清除搜索
                    if !search_for_clear.get().is_empty() {
                        search_for_clear.set(String::new());
                        // 清除输入框焦点
                        if let Some(input) = search_for_focus.get() {
                            input.blur().ok();
                        }
                        e.prevent_default();
                    }
                } else if e.key() == "/" && !is_input_focused {
                    e.prevent_default();
                    if let Some(input) = search_for_focus.get() {
                        input.focus().ok();
                        input.select();
                    }
                }
            }) as Box<dyn FnMut(_)>);
        let _ =
            window.add_event_listener_with_callback("keydown", handler.as_ref().unchecked_ref());
        handler.forget();
    }

    // 打开详情模态框
    let show_detail = move |ip: String| {
        detail_ip.set(Some(ip.clone()));
        detail_loading.set(true);
        detail_data.set(None);
        let toast = toast_state;
        spawn_local(async move {
            match api::get_ban_detail(&ip).await {
                Ok(detail) => detail_data.set(Some(detail)),
                Err(e) => toast.error(format!("加载详情失败：{e}")),
            }
            detail_loading.set(false);
        });
    };

    // 关闭详情模态框
    let close_detail = move |_| {
        detail_ip.set(None);
        detail_data.set(None);
    };

    // 搜索变化时重置到第 1 页 + 清空选择
    create_effect(move |_| {
        let _ = search.get();
        page.set(1);
        selected_ips.set(std::collections::HashSet::new());
    });

    // 过滤 + 排序 + 分页（纯客户端，实时跟随 SSE）
    let displayed_bans = create_memo(move |_| {
        let kw = search.get().to_lowercase();
        let sort_key = sort_by.get();
        let current_page = page.get();
        let mut bans = bans_signal.get().unwrap_or_default();

        // 过滤
        if !kw.is_empty() {
            bans.retain(|b| {
                b.ip.to_lowercase().contains(&kw)
                    || b.jail.to_lowercase().contains(&kw)
                    || b.reason.to_lowercase().contains(&kw)
            });
        }

        // 排序
        match sort_key.as_str() {
            "ip_asc" => bans.sort_by(|a, b| a.ip.cmp(&b.ip)),
            "ip_desc" => bans.sort_by(|a, b| b.ip.cmp(&a.ip)),
            "banned_at_asc" => bans.sort_by_key(|a| a.banned_at),
            "remaining_asc" => bans.sort_by_key(|a| a.remaining_seconds),
            "remaining_desc" => bans.sort_by_key(|b| std::cmp::Reverse(b.remaining_seconds)),
            _ => bans.sort_by_key(|b| std::cmp::Reverse(b.banned_at)),
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
                    let t = toast_state;
                    t.success(format!("已封禁 {ip}"));
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
        let toast = toast_state;
        spawn_local(async move {
            if let Err(e) = api::delete_ban(&ip).await {
                toast.error(format!("解封失败：{e}"));
            }
        });
    };

    // 批量选择操作（支持 Shift+点击 范围选择）
    let toggle_select = move |ip: String, shift: bool| {
        if shift {
            // Shift+点击：选中从 last_clicked 到当前 ip 之间的所有行
            let page_ips: Vec<String> = filtered_bans().iter().map(|b| b.ip.clone()).collect();
            let last = last_clicked_ip.get();
            selected_ips.update(|set| {
                if let Some(last_ip) = &last {
                    let last_idx = page_ips.iter().position(|x| x == last_ip);
                    let cur_idx = page_ips.iter().position(|x| x == &ip);
                    if let (Some(li), Some(ci)) = (last_idx, cur_idx) {
                        let (start, end) = if li < ci { (li, ci) } else { (ci, li) };
                        for ip in &page_ips[start..=end] {
                            set.insert(ip.clone());
                        }
                        return;
                    }
                }
                // 无 last_clicked 或找不到索引，退化为普通切换
                if set.contains(&ip) {
                    set.remove(&ip);
                } else {
                    set.insert(ip.clone());
                }
            });
        } else {
            selected_ips.update(|set| {
                if set.contains(&ip) {
                    set.remove(&ip);
                } else {
                    set.insert(ip.clone());
                }
            });
        }
        last_clicked_ip.set(Some(ip));
    };

    let toggle_select_all_page = move |_| {
        let current_page_ips: Vec<String> = filtered_bans().iter().map(|b| b.ip.clone()).collect();
        selected_ips.update(|set| {
            let all_selected = current_page_ips.iter().all(|ip| set.contains(ip));
            if all_selected {
                for ip in &current_page_ips {
                    set.remove(ip);
                }
            } else {
                for ip in current_page_ips {
                    set.insert(ip);
                }
            }
        });
    };

    let is_all_page_selected = move || {
        let page_ips = filtered_bans();
        !page_ips.is_empty() && page_ips.iter().all(|b| selected_ips.get().contains(&b.ip))
    };

    let selected_count = move || -> usize { selected_ips.get().len() };

    let clear_selection = move |_| {
        selected_ips.set(std::collections::HashSet::new());
    };

    let do_batch_unban = move |_| {
        let ips: Vec<String> = selected_ips.get().into_iter().collect();
        if ips.is_empty() {
            return;
        }
        let window = web_sys::window().expect("window not available");
        if !window
            .confirm_with_message(&format!("确定要批量解封 {} 个 IP 吗?", ips.len()))
            .unwrap_or(false)
        {
            return;
        }
        batch_loading.set(true);
        let toast = toast_state;
        spawn_local(async move {
            let mut succeeded = 0u32;
            let mut failed = 0u32;
            for ip in &ips {
                match api::delete_ban(ip).await {
                    Ok(_) => succeeded += 1,
                    Err(_) => failed += 1,
                }
            }
            if failed == 0 {
                toast.success(format!("已批量解封 {} 个 IP", succeeded));
            } else {
                toast.error(format!("批量解封完成：成功 {}，失败 {}", succeeded, failed));
            }
            batch_loading.set(false);
            selected_ips.set(std::collections::HashSet::new());
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

    // 攻击预测
    let prediction_res = create_resource(
        || (),
        |_| async move {
            api::get_attack_predictions()
                .await
                .unwrap_or(api::AttackPredictionSummary {
                    predictions: Vec::new(),
                    jail_trends: Vec::new(),
                    imminent_count: 0,
                    within_24h_count: 0,
                })
        },
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
                                let s = stats_signal.get().unwrap_or_else(&stats_default);
                                let mut pairs: Vec<_> = s.failure_reasons.labels.into_iter()
                                    .zip(s.failure_reasons.values.into_iter())
                                    .collect();
                                pairs.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                                pairs.into_iter().map(|(l, _)| l).collect()
                            })
                            data=Signal::derive(move || {
                                let s = stats_signal.get().unwrap_or_else(&stats_default);
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
                            labels=Signal::derive(move || stats_signal.get().unwrap_or_else(&stats_default).ban_trend.labels)
                            data=Signal::derive(move || stats_signal.get().unwrap_or_else(&stats_default).ban_trend.values)
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
                    <div style="position:relative">
                        <input class="input mono" placeholder="搜索 IP / Jail / 原因..."
                            node_ref=search_ref
                            style="width:260px;padding-right:28px"
                            prop:value=move || search.get()
                            on:input=move |e| search.set(event_target_value(&e))/>
                        <span style="position:absolute;right:8px;top:50%;transform:translateY(-50%);font-size:10px;color:var(--text-muted);background:var(--bg-tertiary);padding:2px 6px;border-radius:3px;border:1px solid var(--border-color);font-family:monospace;pointer-events:none;opacity:0.6">"/"</span>
                    </div>
                </div>
            </div>

            // 批量操作栏（选中时显示）
            <Show when=move || !selected_ips.get().is_empty()>
                <div class="card" style="padding:10px 14px;display:flex;align-items:center;gap:12px;background:var(--bg-tertiary);border:1px solid var(--accent-primary);animation:slide-down 0.2s ease-out">
                    <span style="font-size:13px;font-weight:600;color:var(--accent-primary)">
                        {move || format!("已选择 {} 项", selected_count())}
                    </span>
                    <button class="btn btn-sm btn-danger" on:click=do_batch_unban
                        disabled=move || batch_loading.get()
                        style="font-size:12px">
                        {move || if batch_loading.get() { "解封中..." } else { "批量解封" }}
                    </button>
                    <button class="btn btn-sm" on:click=clear_selection
                        style="font-size:12px;border-color:var(--border-strong)">
                        "取消选择"
                    </button>
                </div>
            </Show>

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

            // 空态展示
            <Show when=move || {
                let bans = bans_signal.get().unwrap_or_default();
                bans.is_empty() && search.get().is_empty()
            }>
                <div class="card" style="padding:48px 24px;text-align:center">
                    <div style="font-size:48px;margin-bottom:16px;opacity:0.3">"🛡️"</div>
                    <h3 style="color:var(--text-secondary);font-weight:600;margin-bottom:8px">"当前无活跃封禁"</h3>
                    <p style="color:var(--text-muted);font-size:13px;max-width:360px;margin:0 auto">
                        "系统正在持续监控日志和流量。当检测到异常行为时，封禁记录将在此显示。"
                    </p>
                </div>
            </Show>

            <Show when=move || {
                let bans = bans_signal.get().unwrap_or_default();
                !bans.is_empty() || !search.get().is_empty()
            }>
            // 搜索结果空态
            <Show when=move || {
                let total = bans_signal.get().map(|b| b.len()).unwrap_or(0);
                let filtered = filtered_bans();
                total > 0 && filtered.is_empty() && !search.get().is_empty()
            }>
                <div class="card" style="padding:32px 16px;text-align:center">
                    <div style="font-size:32px;margin-bottom:8px;opacity:0.3">"🔍"</div>
                    <p style="color:var(--text-muted);font-size:13px">
                        {move || format!("未找到匹配 \"{}\" 的封禁记录", search.get())}
                    </p>
                </div>
            </Show>
            <Show when=move || !filtered_bans().is_empty()>
            <div class="card">
                <div class="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th style="width:32px">
                                    <input type="checkbox"
                                        checked=is_all_page_selected
                                        on:change=toggle_select_all_page
                                        style="width:15px;height:15px;accent-color:var(--accent-primary);cursor:pointer"
                                        title="选择当前页全部"/>
                                </th>
                                <th style="width:15%">"IP 地址"</th>
                                <th style="width:10%">"Jail"</th>
                                <th style="width:14%">"原因"</th>
                                <th style="width:5%">"次数"</th>
                                <th style="width:11%">"封禁时间"</th>
                                <th style="width:11%">"剩余时间"</th>
                                <th style="width:16%">"操作"</th>
                            </tr>
                        </thead>
                        <tbody>
                            <For each=filtered_bans key=|b| format!("{}:{}", b.ip, b.jail)
                                children=move |ban: BanResponse| {
                                    let ip = ban.ip.clone();
                                    let jail = ban.jail.clone();
                                    let ip2 = ip.clone();
                                    let ip3 = ip.clone();
                                    let ip4 = ip.clone();
                                    let ip5 = ip.clone();
                                    let ip6 = ip.clone();
                                    let ban_count = ban.ban_count;
                                    let is_permanent = ban.is_permanent;
                                    let banned_at_ts = ban.banned_at;
                                    // 实时倒计时：依赖 countdown_tick 每秒重新计算
                                    let remaining_display = move || {
                                        if is_permanent {
                                            return "永久".to_string();
                                        }
                                        // 触发响应式依赖——每秒刷新
                                        let _ = countdown_tick.get();
                                        // 从 SSE 数据推算到期时间戳
                                        let bans = bans_signal.get().unwrap_or_default();
                                        let remaining_at_push = bans
                                            .iter()
                                            .find(|b| b.ip == ip && b.jail == jail)
                                            .map(|b| b.remaining_seconds)
                                            .unwrap_or(0);
                                        if remaining_at_push <= 0 {
                                            return if remaining_at_push == -1 { "永久".to_string() } else { "已到期".to_string() };
                                        }
                                        let expires_at = banned_at_ts + remaining_at_push;
                                        let now = js_sys::Date::now() as i64 / 1000;
                                        let remaining = (expires_at - now).max(0);
                                        format_duration(remaining)
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
                                        <tr style=move || if selected_ips.get().contains(&ip4) { "background:color-mix(in srgb, var(--accent-primary) 8%, transparent)".to_string() } else { String::new() }>
                                            <td style="width:32px;text-align:center">
                                                <input type="checkbox"
                                                    checked=move || selected_ips.get().contains(&ip5)
                                                    on:click=move |e| {
                                                        let shift = e.shift_key();
                                                        toggle_select(ip6.clone(), shift);
                                                    }
                                                    style="width:15px;height:15px;accent-color:var(--accent-primary);cursor:pointer"/>
                                            </td>
                                            <td class="mono" style="font-weight:600;color:var(--text-primary)">
                                                <span style=move || format!("display:inline-block;width:8px;height:8px;border-radius:50%;background:{};margin-right:6px;vertical-align:middle", threat_dot)></span>
                                                <span style="cursor:pointer;border-bottom:1px dashed transparent;transition:border-color 0.15s"
                                                    title="点击复制 IP"
                                                    on:click={
                                                        let ip_copy = ban.ip.clone();
                                                        let toast = toast_state;
                                                        move |_| {
                                                            copy_to_clipboard(&ip_copy);
                                                            toast.success(format!("已复制 {ip_copy}"));
                                                        }
                                                    }>
                                                    {move || highlight_text(&ban.ip, &search.get())}
                                                </span>
                                            </td>
                                            <td>{move || {
                                                let kw = search.get();
                                                if kw.is_empty() {
                                                    view! { <span class="badge badge-info">{&ban.jail}</span> }.into_view()
                                                } else {
                                                    view! { <span class="badge badge-info">{highlight_text(&ban.jail, &kw)}</span> }.into_view()
                                                }
                                            }}</td>
                                            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{move || highlight_text(&ban.reason, &search.get())}</td>
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
                        let current = page.get();
                        let total_items = filtered_bans().len();
                        let start_item = if total_items > 0 { (current - 1) * PAGE_SIZE + 1 } else { 0 };
                        let end_item = ((current - 1) * PAGE_SIZE + total_items as u32).min(total_items as u32);
                        if tp <= 1 && total_items <= PAGE_SIZE as usize {
                            // 只有一页且不超过一页大小，不显示分页，但仍显示计数
                            return view! {
                                <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;font-size:12px;color:var(--text-muted)">
                                    <span>{format!("共 {} 条记录", total_items)}</span>
                                </div>
                            }.into_view();
                        }
                        // 生成页码按钮窗口（最多显示 7 个）
                        let page_window: Vec<u32> = if tp <= 7 {
                            (1..=tp).collect()
                        } else {
                            let start = if current <= 4 { 1 } else { (current - 3).min(tp - 6) };
                            let end = start + 6;
                            (start..=end.min(tp)).collect()
                        };
                        view! {
                            <div style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;flex-wrap:wrap;gap:8px">
                                <span style="font-size:12px;color:var(--text-muted)">
                                    {format!("显示 {}-{} / 共 {} 条", start_item, end_item, total_items)}
                                </span>
                                <div style="display:flex;gap:4px;align-items:center">
                                    <button class="btn btn-sm" style="padding:3px 8px;font-size:11px"
                                        disabled=move || page.get() <= 1
                                        on:click=move |_| page.set(1)>
                                        "«"
                                    </button>
                                    <button class="btn btn-sm" style="padding:3px 8px;font-size:11px"
                                        disabled=move || page.get() <= 1
                                        on:click=move |_| page.update(|p| *p = (*p).saturating_sub(1))>
                                        "‹"
                                    </button>
                                    {page_window.into_iter().map(|p| {
                                        let is_current = p == current;
                                        view! {
                                            <button class="btn btn-sm"
                                                style=move || {
                                                    if is_current {
                                                        "padding:3px 8px;font-size:11px;background:var(--accent-primary);color:#fff;border-color:var(--accent-primary);font-weight:700"
                                                    } else {
                                                        "padding:3px 8px;font-size:11px"
                                                    }
                                                }
                                                on:click=move |_| page.set(p)>
                                                {p}
                                            </button>
                                        }
                                    }).collect_view()}
                                    <button class="btn btn-sm" style="padding:3px 8px;font-size:11px"
                                        disabled=move || page.get() >= tp
                                        on:click=move |_| page.update(|p| *p += 1)>
                                        "›"
                                    </button>
                                    <button class="btn btn-sm" style="padding:3px 8px;font-size:11px"
                                        disabled=move || page.get() >= tp
                                        on:click=move |_| page.set(tp)>
                                        "»"
                                    </button>
                                </div>
                            </div>
                        }.into_view()
                    }}
                </Suspense>
            </div>
            </Show>
            </Show>

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

            // 攻击预测面板
            <Suspense fallback=|| view! { <div style="padding:12px;text-align:center;color:var(--text-muted)">"加载攻击预测..."</div> }>
                {move || prediction_res.get().map(|summary| {
                    if summary.predictions.is_empty() && summary.jail_trends.is_empty() {
                        return view! { <div/> }.into_view();
                    }
                    let pred_section = if !summary.predictions.is_empty() {
                        let imminent = summary.imminent_count;
                        let within_24h = summary.within_24h_count;
                        let preds = summary.predictions.clone();
                        view! {
                            <div class="card prediction-card">
                                <div class="chart-header">
                                    <h3>"攻击时间预测"</h3>
                                    <div style="display:flex;gap:6px">
                                        {if imminent > 0 {
                                            view! { <span class="badge badge-danger">{format!("紧急 {}", imminent)}</span> }.into_view()
                                        } else {
                                            view! { <div/> }.into_view()
                                        }}
                                        <span class="badge badge-warning">{format!("24h 内 {}", within_24h)}</span>
                                    </div>
                                </div>
                                <div class="prediction-list">
                                    {preds.iter().take(15).map(|pred| {
                                        let urgency_color = match pred.urgency.as_str() {
                                            "imminent" => "var(--color-red)",
                                            "soon" => "var(--color-orange)",
                                            "later" => "var(--color-yellow, #eab308)",
                                            _ => "var(--color-muted)",
                                        };
                                        let urgency_label = match pred.urgency.as_str() {
                                            "imminent" => "紧急",
                                            "soon" => "临近",
                                            "later" => "较远",
                                            _ => "远期",
                                        };
                                        let time_str = if pred.remaining_secs < 0 {
                                            format!("已超期 {}", format_duration(-pred.remaining_secs))
                                        } else {
                                            format!("{} 后", format_duration(pred.remaining_secs))
                                        };
                                        let interval_str = if pred.median_interval_secs > 86400.0 {
                                            format!("{:.1}天", pred.median_interval_secs / 86400.0)
                                        } else if pred.median_interval_secs > 3600.0 {
                                            format!("{:.1}h", pred.median_interval_secs / 3600.0)
                                        } else {
                                            format!("{:.0}min", pred.median_interval_secs / 60.0)
                                        };
                                        view! {
                                            <div class="prediction-item">
                                                <div class="prediction-main">
                                                    <span class="prediction-ip mono">{&pred.ip}</span>
                                                    <span class="badge badge-info">{&pred.jail_name}</span>
                                                    <span class="prediction-urgency" style=move || format!("background:{}", urgency_color)>
                                                        {urgency_label}
                                                    </span>
                                                </div>
                                                <div class="prediction-stats">
                                                    <span class="prediction-stat">{format!("×{} 封禁", pred.ban_count)}</span>
                                                    <span class="prediction-sep">"·"</span>
                                                    <span class="prediction-stat">{format!("周期 {}", interval_str)}</span>
                                                    <span class="prediction-sep">"·"</span>
                                                    <span class="prediction-stat" style=move || format!("color:{}", urgency_color)>{time_str}</span>
                                                    <span class="prediction-sep">"·"</span>
                                                    <span class="prediction-stat">{format!("置信度 {}%", pred.confidence)}</span>
                                                </div>
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_view()
                    } else {
                        view! { <div/> }.into_view()
                    };
                    let trend_section = if !summary.jail_trends.is_empty() {
                        let trends = summary.jail_trends.clone();
                        view! {
                            <div class="card trend-card">
                                <div class="chart-header">
                                    <h3>"Jail 攻击趋势"</h3>
                                </div>
                                <div class="trend-list">
                                    {trends.iter().map(|trend| {
                                        let trend_icon = match trend.trend.as_str() {
                                            "rising" => "↑",
                                            "falling" => "↓",
                                            _ => "→",
                                        };
                                        let trend_color = match trend.trend.as_str() {
                                            "rising" => "var(--color-red)",
                                            "falling" => "var(--color-green)",
                                            _ => "var(--color-muted)",
                                        };
                                        view! {
                                            <div class="trend-item">
                                                <span class="trend-jail">{&trend.jail_name}</span>
                                                <span class="trend-icon" style=move || format!("color:{}", trend_color)>
                                                    {trend_icon}
                                                </span>
                                                <span class="trend-counts mono">
                                                    {format!("24h: {} · 7d: {}", trend.bans_24h, trend.bans_7d)}
                                                </span>
                                                {if trend.predicted_attackers_24h > 0 {
                                                    view! { <span class="badge badge-warning">{format!("预测 {} IP", trend.predicted_attackers_24h)}</span> }.into_view()
                                                } else {
                                                    view! { <div/> }.into_view()
                                                }}
                                            </div>
                                        }
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_view()
                    } else {
                        view! { <div/> }.into_view()
                    };
                    view! {
                        <>
                            {pred_section}
                            {trend_section}
                        </>
                    }.into_view()
                })}
            </Suspense>

            // 封禁详情模态框
            <Show when=move || detail_ip.get().is_some()>
                <div class="modal-overlay" on:click=close_detail>
                    <div class="modal ban-detail-modal" role="dialog" aria-modal="true" aria-label="封禁详情"
                        on:click=move |e| e.stop_propagation()>
                        <div class="modal-header">
                            <h3>"封禁详情"</h3>
                            <button class="btn btn-icon" on:click=close_detail aria-label="关闭">"✕"</button>
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
