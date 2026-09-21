//! 端口的**临时**生产实现：桥到尚未重写的 owner。
//!
//! # 生命周期
//!
//! 本文件整体是过渡物。它让 `api::routes` 现在就能接上真实现（而不是返回假
//! 数据），同时把「哪些数据还来自旧模块」集中到一处、一眼可见。
//! `config` / `runtime_status` / `history_snapshot` / `ip_reputation` 各自重写时，
//! 对应实现换成新 owner，路由代码不动；本文件逐个方法缩小，最终删除。
//!
//! # 为什么不是「让路由直接调旧函数」
//!
//! 那样 `api` 会直接依赖 `web_ui` / `http_exporter`，2.E-4 退役旧模块时就得
//! 连带重写全部路由。经端口隔一层之后，退役只是「换一个 impl」。
//!
//! # 写后重读，不复制映射
//!
//! `apply` / `set_jail_enabled` 一律「调用旧实现 → 再从 `self` 读一遍」，
//! 而不是把 19 个字段的映射再手写一份：两份映射表必然会漂移，而重读是自证的。

use std::net::IpAddr;

use super::ports::{
    BanCommand, BanHistoryView, BanOutcome, ChartData, ConfigPort, ControlPort, HistoryPort,
    JailView, RuntimePort, RuntimeView, ThreatInputs, TrendsView, WebuiConfigPatch,
    WebuiConfigView,
};

// ============================================================================
// 配置面
// ============================================================================

/// 桥到 `config_reloader` / `http_exporter` 的临时配置端口。
#[derive(Debug, Default)]
pub struct LegacyConfigPort;

impl ConfigPort for LegacyConfigPort {
    fn webui(&self) -> WebuiConfigView {
        let config = crate::http_exporter::get_global_webui_config().unwrap_or_default();
        WebuiConfigView {
            sse_push_interval: config.sse_push_interval,
            rate_warning_pps: config.rate_warning_pps,
            rate_critical_pps: config.rate_critical_pps,
            rate_warning_syn: config.rate_warning_syn,
            rate_critical_syn: config.rate_critical_syn,
            max_syn_per_second: config.max_syn_per_second,
            max_udp_per_second: config.max_udp_per_second,
            max_icmp_per_second: config.max_icmp_per_second,
            max_ack_per_second: config.max_ack_per_second,
            max_rst_per_second: config.max_rst_per_second,
            max_fin_per_second: config.max_fin_per_second,
            static_threshold: config.static_threshold,
            dynamic_threshold: config.dynamic_threshold,
            ddos_detection: config.ddos_detection,
            max_ban_entries: config.max_ban_entries,
            max_whitelist_entries: config.max_whitelist_entries,
            max_rate_entries: config.max_rate_entries,
            max_local_ip_cache: config.max_local_ip_cache,
            clear_logs_at: config.clear_logs_at.clone(),
        }
    }

    fn apply(&self, patch: WebuiConfigPatch) -> Result<WebuiConfigView, String> {
        // 校验语义（warning < critical、容量非零……）属于配置 owner，沿用既有
        // 实现，避免在 `api` 里长出第二套校验规则。
        let req = crate::web_ui::api::UpdateConfigRequest {
            sse_push_interval: patch.sse_push_interval,
            rate_warning_pps: patch.rate_warning_pps,
            rate_critical_pps: patch.rate_critical_pps,
            rate_warning_syn: patch.rate_warning_syn,
            rate_critical_syn: patch.rate_critical_syn,
            max_syn_per_second: patch.max_syn_per_second,
            max_udp_per_second: patch.max_udp_per_second,
            max_icmp_per_second: patch.max_icmp_per_second,
            max_ack_per_second: patch.max_ack_per_second,
            max_rst_per_second: patch.max_rst_per_second,
            max_fin_per_second: patch.max_fin_per_second,
            static_threshold: patch.static_threshold,
            dynamic_threshold: patch.dynamic_threshold,
            ddos_detection: patch.ddos_detection,
            max_ban_entries: patch.max_ban_entries,
            max_whitelist_entries: patch.max_whitelist_entries,
            max_rate_entries: patch.max_rate_entries,
            max_local_ip_cache: patch.max_local_ip_cache,
            clear_logs_at: patch.clear_logs_at,
        };
        crate::web_ui::api::update_webui_config(req)?;
        // 重读而不是复用响应：写入路径的权威值就在全局里，重读不会与它不一致。
        Ok(self.webui())
    }

    fn jails(&self) -> Vec<JailView> {
        let peak = crate::decision::is_baseline_peak_hours();
        let peak_multiplier = if peak { 1.5 } else { 1.0 };
        crate::http_exporter::get_global_jails()
            .into_iter()
            .map(|j| JailView {
                name: j.name,
                enabled: j.enabled,
                max_retries: j.max_retries,
                effective_max_retries: (j.max_retries as f64 * peak_multiplier).ceil() as u32,
                findtime: j.findtime,
                ban_time: j.ban_time,
                is_peak_hours: peak,
                peak_hours_multiplier: peak_multiplier,
                internal_ip_multiplier: 2.0,
            })
            .collect()
    }

    fn set_jail_enabled(&self, name: &str, enabled: bool) -> Result<JailView, String> {
        crate::web_ui::api::update_jail_enabled(name, enabled)?;
        self.jails()
            .into_iter()
            .find(|j| j.name == name)
            .ok_or_else(|| format!("Jail '{name}' 更新后不可见"))
    }
}

// ============================================================================
// 运行时与指标
// ============================================================================

/// 桥到 `runtime_status` 与 `http_exporter` 指标渲染的临时运行时端口。
#[derive(Debug, Default)]
pub struct LegacyRuntimePort;

impl RuntimePort for LegacyRuntimePort {
    fn snapshot(&self) -> RuntimeView {
        let snap = crate::runtime_status::runtime_snapshot();
        RuntimeView {
            status: snap.status,
            netlink_ready: snap.netlink_ready,
            kmod_proc_present: snap.kmod_proc_present,
            ban_cache_initialized: snap.ban_cache_initialized,
            ban_history_initialized: snap.ban_history_initialized,
            active_bans: snap.active_bans,
            lease_state: snap.lease_state,
            lease_losses: snap.lease_losses,
        }
    }

    fn metrics_text(&self) -> String {
        crate::http_exporter::render_prometheus_metrics()
    }
}

// ============================================================================
// 历史与信誉
// ============================================================================

/// 桥到 `history_snapshot` 与 `ip_reputation` 的临时历史端口。
#[derive(Debug, Default)]
pub struct LegacyHistoryPort;

impl HistoryPort for LegacyHistoryPort {
    fn trends(&self) -> TrendsView {
        let (ban_trend, failed_attempts_trend) = crate::web_ui::stats::trends_snapshot();
        TrendsView {
            ban_trend: ChartData {
                labels: ban_trend.labels,
                values: ban_trend.values,
            },
            failed_attempts_trend: ChartData {
                labels: failed_attempts_trend.labels,
                values: failed_attempts_trend.values,
            },
        }
    }

    fn ban_history(&self, ip: IpAddr) -> Option<BanHistoryView> {
        let text = ip.to_string();
        let store = crate::ip_reputation::get_store();
        let reputation_score = store.get_score(&text);
        let reputation_multiplier = store.get_threshold_multiplier(&text);
        crate::types::BAN_HISTORY
            .get()
            .and_then(|history| history.get_entry(&text))
            .map(|entry| BanHistoryView {
                ban_count: entry.ban_count,
                last_unbanned_at: entry.last_unbanned_at,
                was_permanent: entry.was_permanent,
                reputation_score,
                reputation_multiplier,
            })
    }

    fn threat_inputs(&self) -> ThreatInputs {
        ThreatInputs {
            current_pps: crate::types::get_rate_windows().pps_short,
            baseline_frozen: crate::types::is_baseline_frozen(),
            peak_hours: crate::decision::is_baseline_peak_hours(),
        }
    }
}

// ============================================================================
// 控制面（封禁/解封）
// ============================================================================

/// 桥到 `web_ui::api` 封禁实现的临时控制端口。
#[derive(Debug, Default)]
pub struct LegacyControlPort;

impl ControlPort for LegacyControlPort {
    fn ban(&self, cmd: BanCommand) -> Result<BanOutcome, String> {
        let req = crate::web_ui::api::CreateBanRequest {
            ip: cmd.ip.to_string(),
            duration: cmd.duration,
            reason: cmd.reason,
        };
        let resp = crate::web_ui::api::create_ban(req)?;
        Ok(BanOutcome {
            permanent: resp.permanent,
            duration_seconds: resp.duration_seconds,
        })
    }

    fn unban(&self, ip: IpAddr) -> Result<(), String> {
        crate::web_ui::api::delete_ban(&ip.to_string()).map(|_| ())
    }

    fn add_whitelist(&self, cidr: &str) -> Result<String, String> {
        let req = crate::web_ui::api::CreateWhitelistRequest {
            cidr: cidr.to_string(),
        };
        crate::web_ui::api::create_whitelist(req).map(|resp| resp.cidr)
    }

    fn remove_whitelist(&self, cidr: &str) -> Result<String, String> {
        crate::web_ui::api::delete_whitelist(cidr).map(|resp| resp.cidr)
    }
}
