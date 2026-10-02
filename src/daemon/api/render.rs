//! 生产渲染器：把 [`Domain`] 的快照渲染成线上 JSON。
//!
//! # 与 REST 共用同一份视图
//!
//! 每个域的 JSON 都由 [`super::views`] 派生，与 `GET /api/v1/*` 走的是同一批
//! 函数。旧实现里 SSE 与 REST 各写一份构造代码，两者迟早不一致；这里从结构上
//! 排除了这种可能。
//!
//! # 只渲染被要求渲染的域
//!
//! [`DomainRenderer::render`] 每次只处理一个域——「只序列化变化的域」由调用方
//! （[`super::sse`]）决定，本层不做任何缓存与判重。

use std::sync::Arc;

use crate::state::hub::Domain;

use super::routes::ApiState;
use super::sse::DomainRenderer;
use super::views;

/// 基于 `state` 快照的渲染器。
pub struct StateRenderer {
    api: Arc<ApiState>,
}

impl StateRenderer {
    /// 由共享依赖构造。
    #[must_use]
    pub fn new(api: Arc<ApiState>) -> Self {
        Self { api }
    }

    fn stats_json(&self) -> Option<String> {
        let now = self.api.now_secs();
        let stats = self.api.state.stats().snapshot();
        let bans = self.api.state.bans().snapshot();
        let whitelist_count = self.api.state.whitelist().len() as u64;
        let trends = self.api.history.trends();
        let inputs = self.api.history.threat_inputs();
        let threshold = self.api.config.webui().rate_warning_pps;
        // DDoS 事件累计数与 `/api/v1/stats` 取同一权威来源（内核计数器），
        // 保证 SSE 与 REST 两条读路径不会给出不同的数。
        let ddos_events = crate::types::DDOS_STATS
            .events_detected
            .load(std::sync::atomic::Ordering::Relaxed);
        let threat = views::threat_level(
            bans.len() as u64,
            ddos_events,
            views::recent_bans(&bans, now),
            inputs.current_pps,
            threshold,
            inputs.baseline_frozen,
            inputs.peak_hours,
        );
        let payload = views::stats_view(
            &stats,
            &bans,
            whitelist_count,
            now.max(0) as u64,
            env!("CARGO_PKG_VERSION"),
            &self.api.kernel_version,
            ddos_events,
            &trends,
            threat,
            self.api.history.today_bans(),
        );
        serde_json::to_string(&payload).ok()
    }

    fn bans_json(&self) -> Option<String> {
        let now = self.api.now_secs();
        let snapshot = self.api.state.bans().snapshot();
        // SSE 推全量封禁列表（不分页、按默认排序）：前端本地做分页与排序，
        // 避免「推了第 1 页但用户在看第 3 页」这类不一致。
        let items = views::bans_sorted(&snapshot, views::BanSort::BannedAtDesc, now);
        serde_json::to_string(&items).ok()
    }

    fn jails_json(&self) -> Option<String> {
        let jails = self.api.config.jails();
        if jails.is_empty() {
            return None;
        }
        let bans = self.api.state.bans().snapshot();
        let items: Vec<super::payloads::JailResponse> = jails
            .into_iter()
            .map(|j| super::payloads::JailResponse {
                ban_count: bans.count_for_jail(&j.name),
                name: j.name,
                enabled: j.enabled,
                max_retries: j.max_retries,
                effective_max_retries: j.effective_max_retries,
                findtime: j.findtime,
                ban_time: j.ban_time,
                is_peak_hours: j.is_peak_hours,
                peak_hours_multiplier: j.peak_hours_multiplier,
                internal_ip_multiplier: j.internal_ip_multiplier,
                lines_parsed: 0,
                regex_matches: 0,
                ips_extracted: 0,
                failed_attempts: 0,
                bans_triggered: 0,
            })
            .collect();
        serde_json::to_string(&items).ok()
    }

    fn whitelist_json(&self) -> Option<String> {
        let snapshot = self.api.state.whitelist().snapshot();
        serde_json::to_string(&views::whitelist_view(&snapshot)).ok()
    }

    fn rates_json(&self) -> Option<String> {
        let snapshot = self.api.state.rates().snapshot();
        serde_json::to_string(&views::rates_view(&snapshot)).ok()
    }
}

impl DomainRenderer for StateRenderer {
    fn render(&self, domain: Domain) -> Option<String> {
        match domain {
            Domain::Stats => self.stats_json(),
            Domain::Bans => self.bans_json(),
            Domain::Jails => self.jails_json(),
            Domain::Whitelist => self.whitelist_json(),
            Domain::Rates => self.rates_json(),
        }
    }
}
