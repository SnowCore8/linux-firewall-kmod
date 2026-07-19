//! Web UI API - 提供 JSON 数据端点
//!
//! # RESTful 端点（v1）
//! - `GET /api/v1/stats` - 统计数据
//! - `GET /api/v1/bans` - 封禁列表
//! - `POST /api/v1/bans` - 封禁 IP
//! - `DELETE /api/v1/bans/:ip` - 解封 IP
//! - `GET /api/v1/jails` - Jail 列表
//! - `PUT /api/v1/jails/:name` - 更新 Jail 状态
//! - `GET /api/v1/config` - 配置
//! - `GET /api/v1/whitelist` - 白名单列表
//! - `POST /api/v1/whitelist` - 添加白名单
//! - `DELETE /api/v1/whitelist/:cidr` - 移除白名单
//! - `GET /api/v1/rates/current` - 当前速率
//! - `GET /api/v1/rates/history` - 速率历史
//! - `GET /api/v1/events` - SSE 实时推送

use crate::types::ACTIVE_BAN_CACHE;
use serde::{Deserialize, Serialize};

/// 统一 API 响应信封
#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub data: T,
    pub message: String,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            code: 0,
            data,
            message: String::new(),
        }
    }

    pub fn error(code: i32, message: String) -> ApiResponse<()> {
        ApiResponse {
            code,
            data: (),
            message,
        }
    }
}

/// 封禁信息响应（保留在此处，因为 get_jails 需要）
#[derive(Clone, Serialize)]
pub struct BanResponse {
    pub ip: String,
    pub jail: String,
    pub banned_at: i64,
    pub remaining_seconds: i64,
    pub reason: String,
    /// 该 IP 累计被封禁次数（渐进式封禁：第1次/第2次/第3次/第4次+）
    pub ban_count: u32,
    /// 是否永久封禁
    pub is_permanent: bool,
}

/// Jail 信息响应
#[derive(Serialize)]
pub struct JailResponse {
    pub name: String,
    pub enabled: bool,
    pub ban_count: usize,
    /// 配置的失败次数阈值
    pub max_retries: u32,
    /// 当前有效阈值（业务高峰期可能放宽）
    pub effective_max_retries: u32,
    /// 滑动窗口大小（秒）
    pub findtime: u32,
    /// 封禁时长（秒），-1 表示永久
    pub ban_time: i32,
    /// 是否处于业务高峰期（9-18 点 UTC）
    pub is_peak_hours: bool,
    /// 高峰期阈值放宽倍数
    pub peak_hours_multiplier: f64,
    /// 内网 IP 阈值放宽倍数
    pub internal_ip_multiplier: f64,
    /// per-Jail 统计：已解析日志行数
    pub lines_parsed: u64,
    /// per-Jail 统计：正则匹配次数
    pub regex_matches: u64,
    /// per-Jail 统计：提取的 IP 数
    pub ips_extracted: u64,
    /// per-Jail 统计：失败尝试次数
    pub failed_attempts: u64,
    /// per-Jail 统计：触发的封禁数
    pub bans_triggered: u64,
}

/// DDoS 速率信息响应
#[derive(Serialize)]
pub struct RateResponse {
    pub ip: String,
    pub packets_per_sec: u64,
    pub bytes_per_sec: u64,
    pub syn_packets_per_sec: u64,
    pub udp_packets_per_sec: u64,
    pub icmp_packets_per_sec: u64,
    pub ack_packets_per_sec: u64,
    pub rst_packets_per_sec: u64,
    pub fin_packets_per_sec: u64,
}

/// 速率历史趋势响应
#[derive(Serialize)]
pub struct RateHistoryResponse {
    pub timestamp: u64,
    pub total_pps: u64,
    pub total_bps: u64,
    pub tracked_ips: u32,
}

/// Web UI 配置响应
#[derive(Serialize)]
pub struct WebuiConfigResponse {
    pub sse_push_interval: u32,
    pub rate_warning_pps: u64,
    pub rate_critical_pps: u64,
    pub rate_warning_syn: u64,
    pub rate_critical_syn: u64,
    // 协议专项阈值
    pub max_syn_per_second: u32,
    pub max_udp_per_second: u32,
    pub max_icmp_per_second: u32,
    pub max_ack_per_second: u32,
    pub max_rst_per_second: u32,
    pub max_fin_per_second: u32,
    // DDoS 检测算法开关
    pub static_threshold: bool,
    pub dynamic_threshold: bool,
    pub ddos_detection: bool,
    // 容量配置
    pub max_ban_entries: u32,
    pub max_whitelist_entries: u32,
    pub max_rate_entries: u32,
    pub max_local_ip_cache: u32,
    /// 日志清空时间戳（过滤早于此时间的日志）
    pub clear_logs_at: Option<String>,
}

/// 获取 Web UI 配置
pub fn get_webui_config() -> WebuiConfigResponse {
    let config = crate::http_exporter::get_global_webui_config().unwrap_or_default();

    WebuiConfigResponse {
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

/// 更新 Web UI 配置请求
#[derive(Deserialize)]
pub struct UpdateConfigRequest {
    pub sse_push_interval: Option<u32>,
    pub rate_warning_pps: Option<u64>,
    pub rate_critical_pps: Option<u64>,
    pub rate_warning_syn: Option<u64>,
    pub rate_critical_syn: Option<u64>,
    // 协议专项阈值
    pub max_syn_per_second: Option<u32>,
    pub max_udp_per_second: Option<u32>,
    pub max_icmp_per_second: Option<u32>,
    pub max_ack_per_second: Option<u32>,
    pub max_rst_per_second: Option<u32>,
    pub max_fin_per_second: Option<u32>,
    // DDoS 检测算法开关
    pub static_threshold: Option<bool>,
    pub dynamic_threshold: Option<bool>,
    pub ddos_detection: Option<bool>,
    // 容量配置
    pub max_ban_entries: Option<u32>,
    pub max_whitelist_entries: Option<u32>,
    pub max_rate_entries: Option<u32>,
    pub max_local_ip_cache: Option<u32>,
    /// 日志清空时间戳（设置后过滤早于此时间的日志行，传空字符串=取消过滤）
    pub clear_logs_at: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateJailRequest {
    pub enabled: bool,
}

/// 更新 Jail 启用/禁用状态
pub fn update_jail_enabled(name: &str, enabled: bool) -> Result<JailResponse, String> {
    let lock = crate::http_exporter::GLOBAL_JAILS
        .get()
        .ok_or("Jail 存储未初始化".to_string())?;

    let mut jails = lock.write();
    let jail = jails
        .iter_mut()
        .find(|j| j.name == name)
        .ok_or_else(|| format!("Jail '{}' 不存在", name))?;

    jail.enabled = enabled;

    // 在释放锁之前读取所有需要的字段
    let max_retries = jail.max_retries;
    let findtime = jail.findtime;
    let ban_time = jail.ban_time;
    let is_peak_hours = crate::file_monitor::monitor_loop::is_baseline_peak_hours();
    let peak_hours_multiplier = if is_peak_hours { 1.5 } else { 1.0 };
    let internal_ip_multiplier = 2.0; // 内网 IP 阈值放宽倍数
    let effective_max_retries = (max_retries as f64 * peak_hours_multiplier).ceil() as u32;

    drop(jails);

    // 返回更新后的 Jail 信息
    let ban_count = ACTIVE_BAN_CACHE
        .get()
        .map(|cache| cache.get_by_jail(name).len())
        .unwrap_or(0);

    let (lines_parsed, regex_matches, ips_extracted, failed_attempts, bans_triggered) =
        crate::types::JAIL_STATS
            .get()
            .and_then(|lock| {
                let map = lock.read();
                map.get(name).map(|s| {
                    let snap = s.snapshot();
                    (
                        snap.lines_parsed,
                        snap.regex_matches,
                        snap.ips_extracted,
                        snap.failed_attempts,
                        snap.bans_triggered,
                    )
                })
            })
            .unwrap_or((0, 0, 0, 0, 0));

    let response = JailResponse {
        name: name.to_string(),
        enabled,
        ban_count,
        max_retries,
        effective_max_retries,
        findtime,
        ban_time,
        is_peak_hours,
        peak_hours_multiplier,
        internal_ip_multiplier,
        lines_parsed,
        regex_matches,
        ips_extracted,
        failed_attempts,
        bans_triggered,
    };

    // 同步到全局缓存并持久化
    sync_jail_enabled_to_persist(name, enabled)?;

    Ok(response)
}

/// 更新 Jail 启用状态后，同步到全局缓存并持久化
///
/// # 返回
/// - `Ok(())` — 持久化成功
/// - `Err(String)` — 持久化失败（缓存更新成功但写入文件失败）
fn sync_jail_enabled_to_persist(name: &str, enabled: bool) -> Result<(), String> {
    // 同步到 GLOBAL_JAILS_ENABLED 缓存
    let mut jails = crate::http_exporter::GLOBAL_JAILS
        .get()
        .map(|lock| lock.read().clone())
        .unwrap_or_default();
    // 更新对应条目（保持其他条目不变）
    if let Some(idx) = jails.iter().position(|j| j.name == name) {
        jails[idx].enabled = enabled;
    }
    let enabled_list: Vec<(String, bool)> =
        jails.into_iter().map(|j| (j.name, j.enabled)).collect();
    crate::config_reloader::set_global_jails_enabled(&enabled_list);
    // 持久化到运行时配置文件
    crate::config_reloader::persist_runtime_config().map_err(|e| {
        crate::logger::error!(
            crate::logger::get(),
            "Jail 启用状态持久化失败";
            "jail" => name,
            "error" => %e
        );
        format!("配置持久化失败: {e}")
    })
}

/// 更新 Web UI 配置
pub fn update_webui_config(req: UpdateConfigRequest) -> Result<WebuiConfigResponse, String> {
    let mut config = crate::http_exporter::get_global_webui_config().unwrap_or_default();

    // 验证阈值逻辑：warning < critical
    let new_warning_pps = req.rate_warning_pps.unwrap_or(config.rate_warning_pps);
    let new_critical_pps = req.rate_critical_pps.unwrap_or(config.rate_critical_pps);
    let new_warning_syn = req.rate_warning_syn.unwrap_or(config.rate_warning_syn);
    let new_critical_syn = req.rate_critical_syn.unwrap_or(config.rate_critical_syn);

    if new_warning_pps >= new_critical_pps {
        return Err("速率警告阈值必须小于严重阈值".to_string());
    }
    if new_warning_syn >= new_critical_syn {
        return Err("SYN 警告阈值必须小于严重阈值".to_string());
    }

    // 应用更新
    if let Some(v) = req.sse_push_interval {
        if v == 0 || v > 60 {
            return Err("SSE 推送间隔必须在 1-60 秒之间".to_string());
        }
        config.sse_push_interval = v;
    }
    config.rate_warning_pps = new_warning_pps;
    config.rate_critical_pps = new_critical_pps;
    config.rate_warning_syn = new_warning_syn;
    config.rate_critical_syn = new_critical_syn;

    // 协议专项阈值（验证并应用）
    if let Some(v) = req.max_syn_per_second {
        if v == 0 {
            return Err("SYN 阈值不能为 0".to_string());
        }
        config.max_syn_per_second = v;
    }
    if let Some(v) = req.max_udp_per_second {
        if v == 0 {
            return Err("UDP 阈值不能为 0".to_string());
        }
        config.max_udp_per_second = v;
    }
    if let Some(v) = req.max_icmp_per_second {
        if v == 0 {
            return Err("ICMP 阈值不能为 0".to_string());
        }
        config.max_icmp_per_second = v;
    }
    if let Some(v) = req.max_ack_per_second {
        if v == 0 {
            return Err("ACK 阈值不能为 0".to_string());
        }
        config.max_ack_per_second = v;
    }
    if let Some(v) = req.max_rst_per_second {
        if v == 0 {
            return Err("RST 阈值不能为 0".to_string());
        }
        config.max_rst_per_second = v;
    }
    if let Some(v) = req.max_fin_per_second {
        if v == 0 {
            return Err("FIN 阈值不能为 0".to_string());
        }
        config.max_fin_per_second = v;
    }
    // DDoS 检测算法开关
    if let Some(v) = req.static_threshold {
        config.static_threshold = v;
    }
    if let Some(v) = req.dynamic_threshold {
        config.dynamic_threshold = v;
    }
    if let Some(v) = req.ddos_detection {
        config.ddos_detection = v;
    }

    // 容量配置（验证并应用）
    if let Some(v) = req.max_ban_entries {
        if v == 0 {
            return Err("封禁表容量不能为 0".to_string());
        }
        config.max_ban_entries = v;
    }
    if let Some(v) = req.max_whitelist_entries {
        if v == 0 {
            return Err("白名单容量不能为 0".to_string());
        }
        config.max_whitelist_entries = v;
    }
    if let Some(v) = req.max_rate_entries {
        if v == 0 {
            return Err("速率表容量不能为 0".to_string());
        }
        config.max_rate_entries = v;
    }
    if let Some(v) = req.max_local_ip_cache {
        if v == 0 {
            return Err("本地 IP 缓存容量不能为 0".to_string());
        }
        config.max_local_ip_cache = v;
    }

    // 日志清空时间戳（None = 无过滤，Some("") = 取消过滤，Some(ts) = 过滤早于 ts 的行）
    if let Some(v) = req.clear_logs_at {
        config.clear_logs_at = if v.is_empty() { None } else { Some(v) };
    }

    // 写入全局配置
    crate::http_exporter::set_global_webui_config(config.clone());

    // 同步协议阈值到内核（失败时记录 error 日志，不阻断配置保存）
    if let Err(e) = sync_protocol_thresholds_to_kernel(&config) {
        crate::logger::error!(
            crate::logger::get(),
            "协议阈值内核同步失败，配置已保存但内核未更新";
            "error" => e
        );
    }

    // 同步 DDoS 检测开关到内核
    sync_ddos_detection_to_kernel(&config);

    // 同步 WebUI 中的 DDoS 相关字段到 DdosConfig，确保 SIGHUP 重载不覆盖 API 变更
    sync_webui_to_ddos_config(&config);

    // 持久化到运行时配置文件，确保守护进程重启后恢复 API 修改
    if let Err(ref e) = crate::config_reloader::persist_runtime_config() {
        crate::logger::error!(
            crate::logger::get(),
            "API 配置变更后持久化失败，配置已保存但未写入磁盘";
            "error" => %e
        );
    }

    Ok(WebuiConfigResponse {
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
    })
}

/// 同步 DDoS 检测开关到内核模块参数
fn sync_ddos_detection_to_kernel(config: &crate::types::WebuiConfig) {
    crate::ban::write_sysfs_bool_param("fw_static_threshold", config.static_threshold);
    crate::ban::write_sysfs_bool_param("fw_dynamic_threshold", config.dynamic_threshold);
    crate::ban::write_sysfs_bool_param("fw_ddos_detection", config.ddos_detection);
}

/// 同步协议专项阈值到内核模块
///
/// # 返回
/// - `Ok(())` — 同步成功或 netlink 未初始化（静默跳过）
/// - `Err(String)` — netlink 存在但发送失败
fn sync_protocol_thresholds_to_kernel(config: &crate::types::WebuiConfig) -> Result<(), String> {
    use crate::netlink::{config_flags, ConfigUpdate};

    match crate::netlink::get_global_netlink_ctx() {
        Some(netlink) => {
            let config_update = ConfigUpdate::new(
                config_flags::MAX_SYN
                    | config_flags::MAX_UDP
                    | config_flags::MAX_ICMP
                    | config_flags::MAX_ACK
                    | config_flags::MAX_RST
                    | config_flags::MAX_FIN,
            )
            .with_max_syn(config.max_syn_per_second as u64)
            .with_max_udp(config.max_udp_per_second as u64)
            .with_max_icmp(config.max_icmp_per_second as u64);

            // ACK/RST/FIN 需要手动设置字段
            let config_update = {
                let mut cu = config_update;
                cu.max_ack_per_second = (config.max_ack_per_second as u64).to_be();
                cu.max_rst_per_second = (config.max_rst_per_second as u64).to_be();
                cu.max_fin_per_second = (config.max_fin_per_second as u64).to_be();
                cu
            };

            netlink.send_config_update(&config_update).map_err(|e| {
                crate::logger::error!(
                    crate::logger::get(),
                    "同步协议阈值到内核失败";
                    "error" => %e
                );
                format!("内核同步失败: {e}")
            })?;

            crate::logger::info!(
                crate::logger::get(),
                "协议阈值已同步到内核";
                "SYN" => config.max_syn_per_second,
                "UDP" => config.max_udp_per_second,
                "ICMP" => config.max_icmp_per_second,
                "ACK" => config.max_ack_per_second,
                "RST" => config.max_rst_per_second,
                "FIN" => config.max_fin_per_second
            );

            Ok(())
        }
        None => {
            // netlink 未初始化时静默跳过（守护进程启动初期常见）
            Ok(())
        }
    }
}

/// 同步 WebUI 配置中的 DDoS 相关字段到 DdosConfig
///
/// WebUI 和 DdosConfig 共享协议阈值/检测开关字段。API 修改 WebUI 后必须
/// 同步到 DdosConfig，否则 SIGHUP 热重载会从 YAML 重新加载旧值覆盖 API 变更。
fn sync_webui_to_ddos_config(webui: &crate::types::WebuiConfig) {
    match crate::http_exporter::get_global_decision_engine() {
        Some(engine) => {
            let mut ddos = engine.current_config();
            ddos.max_syn_per_second = webui.max_syn_per_second;
            ddos.max_udp_per_second = webui.max_udp_per_second;
            ddos.max_icmp_per_second = webui.max_icmp_per_second;
            ddos.max_ack_per_second = webui.max_ack_per_second;
            ddos.max_rst_per_second = webui.max_rst_per_second;
            ddos.max_fin_per_second = webui.max_fin_per_second;
            ddos.static_threshold = webui.static_threshold;
            ddos.dynamic_threshold = webui.dynamic_threshold;
            ddos.ddos_detection = webui.ddos_detection;
            engine.update_config(ddos);
        }
        None => {
            crate::logger::warn!(
                crate::logger::get(),
                "DDoS 决策引擎未初始化，WebUI DDoS 字段未同步到 DdosConfig";
                "note" => "SIGHUP 热重载时会重新同步"
            );
        }
    }
}

/// 获取 DDoS 速率数据
///
/// 从全局 `RATE_CACHE` 读取，该缓存由 netlink 接收线程定期更新。
/// 程序内部走内存（`/proc/firewall/*` 是用户操作接口）。
pub fn get_ddos_rates() -> Vec<RateResponse> {
    crate::types::RATE_CACHE
        .read()
        .iter()
        .map(|entry| RateResponse {
            ip: entry.ip.clone(),
            packets_per_sec: entry.packets_per_sec,
            bytes_per_sec: entry.bytes_per_sec,
            syn_packets_per_sec: entry.syn_packets_per_sec,
            udp_packets_per_sec: entry.udp_packets_per_sec,
            icmp_packets_per_sec: entry.icmp_packets_per_sec,
            ack_packets_per_sec: entry.ack_packets_per_sec,
            rst_packets_per_sec: entry.rst_packets_per_sec,
            fin_packets_per_sec: entry.fin_packets_per_sec,
        })
        .collect()
}

/// 获取速率历史趋势数据
///
/// 从全局 `RATE_HISTORY` 读取，保留最近 1 小时的速率快照（每 2 秒一条）。
/// Web UI 可读取此数据绘制速率趋势图。
pub fn get_rate_history() -> Vec<RateHistoryResponse> {
    crate::types::RATE_HISTORY
        .read()
        .iter()
        .map(|entry| RateHistoryResponse {
            timestamp: entry.timestamp,
            total_pps: entry.total_pps,
            total_bps: entry.total_bps,
            tracked_ips: entry.tracked_ips,
        })
        .collect()
}

/// 获取多窗口速率数据（短期/中期/长期 EWMA）
///
/// 三个时间尺度的流量特征：
/// - 短期（~5s）：捕捉突发洪水（SYN Flood 等）
/// - 中期（~60s）：识别持续攻击（持续 1 分钟以上的高速）
/// - 长期（~300s）：检测慢速攻击（低频但持续 5 分钟以上的异常）
pub fn get_rate_windows() -> crate::types::RateWindowSnapshot {
    crate::types::get_rate_windows()
}

/// 获取 24 小时攻击热力图数据
///
/// 按小时聚合封禁/失败/DDoS 三个指标，用于热力图可视化
pub fn get_heatmap() -> crate::history_snapshot::HourlyHeatmap {
    crate::history_snapshot::get_hourly_heatmap().unwrap_or_else(|_| {
        let mut buckets = [crate::history_snapshot::HourlyBucket::default(); 24];
        for (i, bucket) in buckets.iter_mut().enumerate() {
            bucket.hour = i as u32;
        }
        crate::history_snapshot::HourlyHeatmap { hours: buckets }
    })
}

/// 获取 Jail 列表
pub fn get_jails(jail_infos: &[crate::http_exporter::JailInfo]) -> Vec<JailResponse> {
    let is_peak_hours = crate::file_monitor::monitor_loop::is_baseline_peak_hours();
    let peak_hours_multiplier = if is_peak_hours { 1.5 } else { 1.0 };
    let internal_ip_multiplier = 2.0; // 内网 IP 阈值放宽倍数

    jail_infos
        .iter()
        .map(|jail_info| {
            let ban_count = ACTIVE_BAN_CACHE
                .get()
                .map(|cache| cache.get_by_jail(&jail_info.name).len())
                .unwrap_or(0);

            // 业务高峰期（9-18 点 UTC）放宽阈值 × 1.5
            let effective_max_retries =
                (jail_info.max_retries as f64 * peak_hours_multiplier).ceil() as u32;

            // per-Jail 运行时统计（从 JAIL_STATS 读取）
            let jail_stats = crate::types::JAIL_STATS.get().and_then(|lock| {
                let map = lock.read();
                map.get(&jail_info.name).map(|s| s.snapshot())
            });
            let (lines_parsed, regex_matches, ips_extracted, failed_attempts, bans_triggered) =
                jail_stats
                    .map(|s| {
                        (
                            s.lines_parsed,
                            s.regex_matches,
                            s.ips_extracted,
                            s.failed_attempts,
                            s.bans_triggered,
                        )
                    })
                    .unwrap_or((0, 0, 0, 0, 0));

            JailResponse {
                name: jail_info.name.clone(),
                enabled: jail_info.enabled,
                ban_count,
                max_retries: jail_info.max_retries,
                effective_max_retries,
                findtime: jail_info.findtime,
                ban_time: jail_info.ban_time,
                is_peak_hours,
                peak_hours_multiplier,
                internal_ip_multiplier,
                lines_parsed,
                regex_matches,
                ips_extracted,
                failed_attempts,
                bans_triggered,
            }
        })
        .collect()
}

// ============================================================================
// 子模块重导出 — handler.rs 通过 crate::web_ui::api::* 统一访问
// ============================================================================

pub use super::stats::*;

pub use super::ban_ops::{
    batch_ban, create_ban, create_whitelist, delete_ban, delete_whitelist, get_active_bans,
    get_active_bans_paginated, get_ban_detail, get_whitelist, unban_all_temporary,
    BanDetailResponse, BanOperationResponse, BatchOperationResponse, CreateBanRequest,
    CreateWhitelistRequest, PaginatedResponse, PaginationParams, WhitelistEntryResponse,
    WhitelistOperationResponse,
};

pub use super::analysis::{
    get_attack_predictions, get_ban_effectiveness, get_collaborative_attacks,
    get_periodic_attackers, get_whitelist_recommendations, BanEffectivenessResponse,
    BanLevelEffectiveness, WhitelistRecommendation,
};

pub use super::ddos_stats::{
    get_ban_duration_histogram, get_icmp_type_distribution, get_udp_port_distribution,
    BanDurationHistogramResponse, IcmpTypeDistributionResponse, IcmpTypeEntry,
    UdpPortDistributionResponse, UdpPortEntry,
};

pub use super::packet_analysis::{
    get_ip_fragment_stats, get_packet_size_distribution, get_port_scan_detection,
    get_service_probe_detection, get_ttl_distribution, IpFragmentStatsResponse,
    PacketSizeDistributionResponse, PortScanResponse, PortScannerEntry, ServiceProbeEntry,
    ServiceProbeResponse, TtlDistributionResponse,
};

pub use super::recommendations::{
    get_ban_duration_recommendations, BanDurationRecommendation, BanDurationRecommendationResponse,
    ReputationEntryResponse, ThresholdRecommendationResponse,
};
