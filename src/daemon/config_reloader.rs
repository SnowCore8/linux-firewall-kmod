//! 配置热重载模块
//!
//! # 核心职责
//!
//! - SIGHUP 触发的双缓冲热重载
//! - 配置解析 + 验证 + 默认值应用
//! - `failed_hash` 迁移（保留历史失败计数）
//! - partial 行缓冲周期清理
//! - 同步配置到 DDoS 决策引擎、内核模块、WebUI
//! - 配置持久化（保存到文件，重启后恢复）
//! - 配置版本历史（支持回滚）
//!
//! # 关键不变量
//!
//! - 任何步骤失败旧配置不受影响（双缓冲）
//! - `config_file` / `config_dir` 保留供后续 reload 复用

use std::sync::atomic::Ordering;

use anyhow::Result;

use crate::file_monitor::setup_inotify;
use crate::jail;
use crate::types::{Config, DAEMON_STATS};

// ============================================================================
// 配置版本历史（支持回滚）
// ============================================================================

/// 配置版本历史（最多保留 5 个版本）
const MAX_CONFIG_VERSIONS: usize = 5;

/// 全局配置版本历史（使用 OnceLock<RwLock> 兼容 Rust 1.75 MSRV）
static CONFIG_HISTORY: std::sync::OnceLock<parking_lot::RwLock<Vec<ConfigSnapshot>>> =
    std::sync::OnceLock::new();

/// 全局 trusted_ips 缓存（供 persist_runtime_config 使用，避免写入默认空列表）
static GLOBAL_TRUSTED_IPS: std::sync::OnceLock<parking_lot::RwLock<Vec<String>>> =
    std::sync::OnceLock::new();

/// 全局 capacity 缓存（供 persist_runtime_config 使用，避免写入默认值）
static GLOBAL_CAPACITY: std::sync::OnceLock<parking_lot::RwLock<crate::types::CapacityConfig>> =
    std::sync::OnceLock::new();

/// Jail enabled 状态缓存（供 persist_runtime_config 使用）。
/// 存储 jail 名称 → enabled 布尔值的映射，仅持久化运行时修改的 enabled 状态。
static GLOBAL_JAILS_ENABLED: std::sync::OnceLock<parking_lot::RwLock<Vec<(String, bool)>>> =
    std::sync::OnceLock::new();

/// 更新全局 trusted_ips 缓存（配置加载/热重载时调用）
pub fn set_global_trusted_ips(ips: &[String]) {
    let lock = GLOBAL_TRUSTED_IPS.get_or_init(|| parking_lot::RwLock::new(Vec::new()));
    *lock.write() = ips.to_vec();
}

/// 更新全局 capacity 缓存（配置加载/热重载时调用）
pub fn set_global_capacity(capacity: &crate::types::CapacityConfig) {
    let lock = GLOBAL_CAPACITY
        .get_or_init(|| parking_lot::RwLock::new(crate::types::CapacityConfig::default()));
    *lock.write() = capacity.clone();
}

/// 更新全局 jail enabled 状态缓存（update_jail_enabled / SIGHUP / 启动恢复时调用）
pub fn set_global_jails_enabled(jails: &[(String, bool)]) {
    let lock = GLOBAL_JAILS_ENABLED.get_or_init(|| parking_lot::RwLock::new(Vec::new()));
    *lock.write() = jails.to_vec();
}

/// 获取全局 jail enabled 状态缓存（供 persist_runtime_config 使用）
pub fn get_global_jails_enabled() -> Vec<(String, bool)> {
    GLOBAL_JAILS_ENABLED
        .get()
        .map(|lock| lock.read().clone())
        .unwrap_or_default()
}

/// 获取配置历史锁
fn config_history_lock() -> &'static parking_lot::RwLock<Vec<ConfigSnapshot>> {
    CONFIG_HISTORY.get_or_init(|| parking_lot::RwLock::new(Vec::new()))
}

/// Jail 可回滚字段的轻量快照（避免 Clone 整个 Jail 含 RwLock）
#[derive(Clone)]
struct JailSnapshot {
    name: String,
    enabled: bool,
    max_retries: u32,
    findtime: u32,
    ban_time: i32,
}

/// 配置快照（用于版本历史和回滚）
#[derive(Clone)]
struct ConfigSnapshot {
    /// 版本时间戳
    timestamp: i64,
    /// DDoS 配置
    ddos: crate::types::DdosConfig,
    /// Web UI 配置
    webui: crate::types::WebuiConfig,
    /// 容量配置
    capacity: crate::types::CapacityConfig,
    /// 可信 IP 列表
    trusted_ips: Vec<String>,
    /// HTTP Metrics 绑定/鉴权（变更需重启才真正生效，快照仍保存以便回滚内存态）
    metrics_port: u16,
    metrics_bind_address: String,
    metrics_username: Option<String>,
    metrics_password: Option<String>,
    /// Jail 可回滚字段（max_retries/findtime/ban_time/enabled）
    jails: Vec<JailSnapshot>,
}

/// 保存配置快照到版本历史
fn save_config_snapshot(cfg: &Config) {
    let jails: Vec<JailSnapshot> = cfg
        .jails
        .iter()
        .map(|j| JailSnapshot {
            name: j.name.clone(),
            enabled: j.enabled,
            max_retries: j.max_retries,
            findtime: j.findtime,
            ban_time: j.ban_time,
        })
        .collect();

    let snapshot = ConfigSnapshot {
        timestamp: crate::types::now_secs(),
        ddos: cfg.ddos.clone(),
        webui: cfg.webui.clone(),
        capacity: cfg.capacity.clone(),
        trusted_ips: cfg.trusted_ips.clone(),
        metrics_port: cfg.metrics_port,
        metrics_bind_address: cfg.metrics_bind_address.clone(),
        metrics_username: cfg.metrics_username.clone(),
        metrics_password: cfg.metrics_password.clone(),
        jails,
    };

    let mut history = config_history_lock().write();
    history.push(snapshot);
    // 保留最近的 MAX_CONFIG_VERSIONS 个版本
    while history.len() > MAX_CONFIG_VERSIONS {
        history.remove(0);
    }
}

/// 回滚到上一个配置版本
pub fn rollback_config(cfg: &mut Config) -> Result<()> {
    let mut history = config_history_lock().write();
    // history 仅保存「重载前」快照，不含当前运行配置；弹出最近一条即回滚目标
    let snapshot = history
        .pop()
        .ok_or_else(|| anyhow::anyhow!("没有可回滚的历史版本"))?;

    // 应用快照配置
    cfg.ddos = snapshot.ddos;
    cfg.webui = snapshot.webui;
    cfg.capacity = snapshot.capacity;
    cfg.trusted_ips = snapshot.trusted_ips;
    cfg.metrics_port = snapshot.metrics_port;
    cfg.metrics_bind_address = snapshot.metrics_bind_address;
    cfg.metrics_username = snapshot.metrics_username;
    cfg.metrics_password = snapshot.metrics_password;

    // 恢复 Jail 可回滚字段
    for jail_snap in &snapshot.jails {
        if let Some(jail) = cfg.jails.iter_mut().find(|j| j.name == jail_snap.name) {
            jail.enabled = jail_snap.enabled;
            jail.max_retries = jail_snap.max_retries;
            jail.findtime = jail_snap.findtime;
            jail.ban_time = jail_snap.ban_time;
        }
    }

    // 同步到各组件
    sync_config_to_components(cfg)?;

    // 持久化回滚后的配置，防止重启后丢失回滚状态
    if let Err(e) = persist_config(cfg, &[]) {
        crate::logger::warn!(
            crate::logger::get(),
            "回滚后持久化配置失败";
            "error" => %e
        );
    }

    crate::logger::info!(
        crate::logger::get(),
        "配置已回滚";
        "timestamp" => snapshot.timestamp
    );

    Ok(())
}

// ============================================================================
// 配置持久化
// ============================================================================

/// 配置持久化目标路径（原始 YAML 配置文件）。
///
/// Web UI API 修改配置后直接回写到原始 YAML，消除双文件覆盖问题。
static CONFIG_TARGET_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// 设置配置持久化目标路径（启动时调用）
pub fn set_config_target_path(path: &str) {
    CONFIG_TARGET_PATH.set(path.to_string()).ok(); // 首次设置成功，后续调用忽略
}

/// 获取配置持久化目标路径
fn get_config_target_path() -> Result<&'static str> {
    CONFIG_TARGET_PATH
        .get()
        .map(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("配置目标路径未设置，启动时未调用 set_config_target_path"))
}

/// 从全局状态构建 Config 并回写到原始 YAML 配置文件。
///
/// Web UI API 修改配置后调用此函数，将当前内存状态直接写入原始 YAML，
/// 重启后从同一文件加载，无需二级覆盖层。
/// trusted_ips 和 capacity 从全局缓存读取，避免写入默认值。
pub fn persist_runtime_config() -> Result<()> {
    let trusted_ips = GLOBAL_TRUSTED_IPS
        .get()
        .map(|lock| lock.read().clone())
        .unwrap_or_default();
    let capacity = GLOBAL_CAPACITY
        .get()
        .map(|lock| lock.read().clone())
        .unwrap_or_default();
    let jails_enabled = get_global_jails_enabled();

    let cfg = Config {
        webui: crate::http_exporter::get_global_webui_config().unwrap_or_default(),
        ddos: crate::http_exporter::get_global_decision_engine()
            .map(|e| e.current_config())
            .unwrap_or_default(),
        trusted_ips,
        capacity,
        ..Config::default()
    };
    persist_config(&cfg, &jails_enabled)
}

/// 运行时覆盖段的起止标记（YAML 注释，不影响解析）
const RUNTIME_BLOCK_START: &str = "# === BEGIN RUNTIME OVERRIDES (auto-managed, do not edit) ===";
const RUNTIME_BLOCK_END: &str = "# === END RUNTIME OVERRIDES ===";

/// 保存配置到原始 YAML 文件（原地替换值，保留文件结构、注释和 jail 定义）。
///
/// 逐行扫描 YAML，替换 ddos/webui/capacity/trusted_ips 段内的已知 key 值。
/// 不在原始文件中的 section 追加到末尾。
fn persist_config(cfg: &Config, jails_enabled: &[(String, bool)]) -> Result<()> {
    let target = get_config_target_path()?;
    let target_path = std::path::Path::new(target);
    let write_path = if target_path.is_dir() {
        target_path.join("_overrides.yaml")
    } else {
        target_path.to_path_buf()
    };

    // 构建需要替换的 key-value 映射（section → key → value）
    let ddos_kvs = vec![
        ("enabled", fmt_bool(cfg.ddos.enabled)),
        ("per_ip_conn_rate", fmt_u32(cfg.ddos.per_ip_conn_rate)),
        ("per_ip_fail_rate", fmt_u32(cfg.ddos.per_ip_fail_rate)),
        ("global_conn_rate", fmt_u32(cfg.ddos.global_conn_rate)),
        ("auto_ban_duration", fmt_u32(cfg.ddos.auto_ban_duration)),
        ("auto_ban_threshold", fmt_u32(cfg.ddos.auto_ban_threshold)),
        ("check_interval", fmt_u32(cfg.ddos.check_interval)),
        (
            "baseline_warmup_samples",
            fmt_u32(cfg.ddos.baseline_warmup_samples),
        ),
        ("max_syn_per_second", fmt_u32(cfg.ddos.max_syn_per_second)),
        ("max_udp_per_second", fmt_u32(cfg.ddos.max_udp_per_second)),
        ("max_icmp_per_second", fmt_u32(cfg.ddos.max_icmp_per_second)),
        ("max_ack_per_second", fmt_u32(cfg.ddos.max_ack_per_second)),
        ("max_rst_per_second", fmt_u32(cfg.ddos.max_rst_per_second)),
        ("max_fin_per_second", fmt_u32(cfg.ddos.max_fin_per_second)),
        ("static_threshold", fmt_bool(cfg.ddos.static_threshold)),
        ("dynamic_threshold", fmt_bool(cfg.ddos.dynamic_threshold)),
        ("ddos_detection", fmt_bool(cfg.ddos.ddos_detection)),
        ("max_bans_per_second", fmt_u32(cfg.ddos.max_bans_per_second)),
        ("max_rate_entries", fmt_u32(cfg.ddos.max_rate_entries)),
    ];
    let webui_kvs = vec![
        ("sse_push_interval", fmt_u32(cfg.webui.sse_push_interval)),
        ("rate_warning_pps", fmt_u64(cfg.webui.rate_warning_pps)),
        ("rate_critical_pps", fmt_u64(cfg.webui.rate_critical_pps)),
        ("rate_warning_syn", fmt_u64(cfg.webui.rate_warning_syn)),
        ("rate_critical_syn", fmt_u64(cfg.webui.rate_critical_syn)),
        ("max_syn_per_second", fmt_u32(cfg.webui.max_syn_per_second)),
        ("max_udp_per_second", fmt_u32(cfg.webui.max_udp_per_second)),
        (
            "max_icmp_per_second",
            fmt_u32(cfg.webui.max_icmp_per_second),
        ),
        ("max_ack_per_second", fmt_u32(cfg.webui.max_ack_per_second)),
        ("max_rst_per_second", fmt_u32(cfg.webui.max_rst_per_second)),
        ("max_fin_per_second", fmt_u32(cfg.webui.max_fin_per_second)),
        ("static_threshold", fmt_bool(cfg.webui.static_threshold)),
        ("dynamic_threshold", fmt_bool(cfg.webui.dynamic_threshold)),
        ("ddos_detection", fmt_bool(cfg.webui.ddos_detection)),
        ("max_ban_entries", fmt_u32(cfg.webui.max_ban_entries)),
        (
            "max_whitelist_entries",
            fmt_u32(cfg.webui.max_whitelist_entries),
        ),
        ("max_rate_entries", fmt_u32(cfg.webui.max_rate_entries)),
        ("max_local_ip_cache", fmt_u32(cfg.webui.max_local_ip_cache)),
    ];
    let capacity_kvs = vec![
        ("max_ban_entries", fmt_u32(cfg.capacity.max_ban_entries)),
        (
            "max_whitelist_entries",
            fmt_u32(cfg.capacity.max_whitelist_entries),
        ),
        ("max_rate_entries", fmt_u32(cfg.capacity.max_rate_entries)),
        (
            "max_local_ip_cache",
            fmt_u32(cfg.capacity.max_local_ip_cache),
        ),
    ];

    // 读取原始文件（不存在则用空内容）
    let original = if write_path.exists() {
        std::fs::read_to_string(&write_path)?
    } else {
        String::new()
    };

    // 先移除旧的 runtime 段（如果有）
    let cleaned = strip_runtime_block(&original);

    // 文件为空时（目录模式首次持久化），从零生成完整 YAML
    let result = if cleaned.trim().is_empty() {
        generate_fresh_config_yaml(cfg, &ddos_kvs, &webui_kvs, &capacity_kvs, jails_enabled)
    } else {
        // 原地替换已知 section 内的 key 值
        let mut r = replace_section_values(&cleaned, "ddos:", &ddos_kvs);
        r = replace_section_values(&r, "webui:", &webui_kvs);
        r = replace_section_values(&r, "capacity:", &capacity_kvs);

        // trusted_ips: 整段替换（列表型，无法逐 key 替换）
        r = replace_list_section(&r, "trusted_ips:", &cfg.trusted_ips);

        // jails enabled 状态：逐 jail 替换 enabled 行
        r = replace_jails_enabled(&r, jails_enabled);
        r
    };

    // 写回文件
    let mut file = std::fs::File::create(&write_path)?;
    use std::io::Write;
    file.write_all(result.as_bytes())?;

    crate::logger::info!(
        crate::logger::get(),
        "配置已回写到原始配置文件";
        "path" => %write_path.display()
    );

    Ok(())
}

fn fmt_u32(v: u32) -> String {
    v.to_string()
}
fn fmt_u64(v: u64) -> String {
    v.to_string()
}
fn fmt_bool(v: bool) -> String {
    v.to_string()
}

/// 从零生成完整的运行时覆盖 YAML（目录模式首次持久化时使用）
fn generate_fresh_config_yaml(
    cfg: &Config,
    ddos_kvs: &[(&str, String)],
    webui_kvs: &[(&str, String)],
    capacity_kvs: &[(&str, String)],
    jails_enabled: &[(String, bool)],
) -> String {
    let mut out = String::new();

    // ddos section
    out.push_str("ddos:\n");
    for (key, val) in ddos_kvs {
        out.push_str(&format!("  {}: {}\n", key, val));
    }
    out.push('\n');

    // webui section
    out.push_str("webui:\n");
    for (key, val) in webui_kvs {
        out.push_str(&format!("  {}: {}\n", key, val));
    }
    out.push('\n');

    // capacity section
    out.push_str("capacity:\n");
    for (key, val) in capacity_kvs {
        out.push_str(&format!("  {}: {}\n", key, val));
    }
    out.push('\n');

    // trusted_ips section
    out.push_str("trusted_ips:\n");
    for ip in &cfg.trusted_ips {
        out.push_str(&format!("  - \"{}\"\n", ip));
    }
    out.push('\n');

    // jails enabled section
    if !jails_enabled.is_empty() {
        out.push_str("jails:\n");
        for (name, enabled) in jails_enabled {
            out.push_str(&format!("  {}:\n", name));
            out.push_str(&format!("    enabled: {}\n", enabled));
        }
    }

    out
}

/// 在指定 section 内替换 key 的值（保留注释），返回修改后的全文。
///
/// 扫描每一行：进入 target_section 后，如果行的 key 匹配替换列表中的项，
/// 则保留缩进和前缀注释，替换值部分。离开 section（遇到下一个顶级 key）时停止。
fn replace_section_values(content: &str, section: &str, kvs: &[(&str, String)]) -> String {
    let mut result = String::new();
    let mut in_section = false;

    for line in content.lines() {
        let trimmed = line.trim();

        // 检测 section 开始
        if trimmed == section || trimmed.starts_with(&format!("{} ", section)) {
            in_section = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }

        // 检测 section 结束（遇到新的顶级 key）
        if in_section
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && trimmed.ends_with(':')
        {
            in_section = false;
        }

        if in_section {
            // 尝试匹配 key: value 模式
            let mut replaced = false;
            for (key, new_val) in kvs {
                // 匹配 "  key: old_value  # comment" 或 "  key: old_value"
                let prefix = format!("{}:", key);
                if let Some(pos) = trimmed.find(&prefix) {
                    // 确保是行首缩进后的 key（不是子串匹配）
                    let before_key = &trimmed[..pos];
                    if before_key.chars().all(|c| c == ' ' || c == '\t') {
                        // 保留缩进
                        let indent = &line[..line.len() - trimmed.len()];
                        // 保留尾部注释
                        let after_value = trimmed[pos + prefix.len()..].trim();
                        let comment = if let Some(hash_pos) = after_value.find('#') {
                            // 找到值后面的 # 注释（跳过值本身中的 #）
                            let val_part = after_value[..hash_pos].trim();
                            if !val_part.is_empty() {
                                format!("  #{}", &after_value[hash_pos + 1..])
                            } else {
                                format!("#{}", &after_value[hash_pos + 1..])
                            }
                        } else {
                            String::new()
                        };
                        let comment_suffix = if comment.is_empty() {
                            String::new()
                        } else {
                            // 重新构建注释（保留原始注释格式）
                            if let Some(hash_pos) = after_value.find(" #") {
                                after_value[hash_pos..].to_string()
                            } else {
                                String::new()
                            }
                        };
                        result.push_str(&format!(
                            "{}{}: {}{}\n",
                            indent, key, new_val, comment_suffix
                        ));
                        replaced = true;
                        break;
                    }
                }
            }
            if !replaced {
                result.push_str(line);
                result.push('\n');
            }
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// 替换列表型 section（如 trusted_ips）
fn replace_list_section(content: &str, section: &str, items: &[String]) -> String {
    let mut result = String::new();
    let mut in_section = false;
    let mut section_written = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed == section || trimmed.starts_with(&format!("{} ", section)) {
            in_section = true;
            if !section_written {
                // 写入新段
                result.push_str(line);
                result.push('\n');
                for item in items {
                    result.push_str(&format!("  - \"{}\"\n", item));
                }
                section_written = true;
            }
            continue;
        }

        if in_section {
            // 跳过旧的列表项
            if trimmed.starts_with("- ") || trimmed.starts_with("-\"") {
                continue;
            }
            // 遇到空行或新 section → 结束列表段
            let is_new_section = (!trimmed.is_empty()
                && !trimmed.starts_with('#')
                && !line.starts_with(' ')
                && !line.starts_with('\t'))
                || trimmed.is_empty();
            if is_new_section {
                in_section = false;
            }
            if !in_section {
                result.push_str(line);
                result.push('\n');
            }
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// 替换 jails section 中各 jail 的 enabled 值
fn replace_jails_enabled(content: &str, jails: &[(String, bool)]) -> String {
    if jails.is_empty() {
        return content.to_string();
    }
    let mut result = String::new();
    let mut in_jails = false;
    let mut current_jail: Option<&str> = None;
    let mut indent_level = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        // 检测 jails: section
        if trimmed == "jails:" || trimmed.starts_with("jails: ") {
            in_jails = true;
            result.push_str(line);
            result.push('\n');
            continue;
        }

        // 检测 jails section 结束
        if in_jails
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && !line.starts_with(' ')
            && !line.starts_with('\t')
            && trimmed.ends_with(':')
        {
            in_jails = false;
            current_jail = None;
        }

        if in_jails {
            // 检测 jail name（缩进 2 格的 key:）
            let line_indent = line.len() - line.trim_start().len();
            if line_indent <= 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
                let jail_name = trimmed.trim_end_matches(':');
                current_jail = Some(jail_name);
                indent_level = line_indent;
            }

            // 检测 enabled: 行（缩进比 jail name 深）
            if let Some(jail_name) = current_jail {
                if trimmed.starts_with("enabled:") && line_indent > indent_level {
                    // 查找这个 jail 的 enabled 值
                    if let Some((_, enabled)) = jails.iter().find(|(n, _)| n == jail_name) {
                        let indent = &line[..line.len() - trimmed.len()];
                        result.push_str(&format!("{}enabled: {}\n", indent, enabled));
                        continue;
                    }
                }
            }
        }

        result.push_str(line);
        result.push('\n');
    }
    result
}

/// 从文件内容中移除旧的运行时覆盖段（兼容旧格式清理）
fn strip_runtime_block(content: &str) -> String {
    let mut result = String::new();
    let mut in_block = false;
    for line in content.lines() {
        if line.trim() == RUNTIME_BLOCK_START {
            in_block = true;
            continue;
        }
        if line.trim() == RUNTIME_BLOCK_END {
            in_block = false;
            continue;
        }
        if !in_block {
            result.push_str(line);
            result.push('\n');
        }
    }
    let trimmed = result.trim_end().to_string();
    if trimmed.is_empty() {
        trimmed
    } else {
        trimmed + "\n"
    }
}

// ============================================================================
// 配置同步到各组件
// ============================================================================

/// 同步配置到 DDoS 决策引擎、内核模块、WebUI
fn sync_config_to_components(cfg: &Config) -> Result<()> {
    // 1. 同步到 DDoS 决策引擎
    if let Some(engine) = crate::http_exporter::get_global_decision_engine() {
        engine.update_config(cfg.ddos.clone());
        crate::logger::info!(
            crate::logger::get(),
            "配置已同步到 DDoS 决策引擎";
            "auto_ban_threshold" => cfg.ddos.auto_ban_threshold,
            "auto_ban_duration" => cfg.ddos.auto_ban_duration
        );
    }

    // 2. 同步到内核模块（通过 netlink）
    if let Some(netlink) = crate::http_exporter::get_global_netlink_ctx() {
        use crate::netlink::{config_flags, ConfigUpdate};

        // 构建配置更新消息
        let config_update = ConfigUpdate::new(
            config_flags::BAN_TIME
                | config_flags::RATE_WINDOW
                | config_flags::MAX_PPS
                | config_flags::DDOS_BAN_DURATION
                | config_flags::MAX_SYN
                | config_flags::MAX_UDP
                | config_flags::MAX_ICMP
                | config_flags::MAX_ACK
                | config_flags::MAX_RST
                | config_flags::MAX_FIN,
        )
        .with_ban_time(cfg.ddos.auto_ban_duration)
        .with_rate_window(cfg.ddos.check_interval)
        .with_max_pps(cfg.ddos.global_conn_rate as u64)
        .with_ddos_ban_duration(cfg.ddos.auto_ban_duration)
        .with_max_syn(cfg.ddos.max_syn_per_second as u64)
        .with_max_udp(cfg.ddos.max_udp_per_second as u64)
        .with_max_icmp(cfg.ddos.max_icmp_per_second as u64);

        // ACK/RST/FIN 需要手动设置字段（没有 with_max_* 方法）
        let config_update = {
            let mut cu = config_update;
            cu.max_ack_per_second = (cfg.ddos.max_ack_per_second as u64).to_be();
            cu.max_rst_per_second = (cfg.ddos.max_rst_per_second as u64).to_be();
            cu.max_fin_per_second = (cfg.ddos.max_fin_per_second as u64).to_be();
            cu
        };

        if let Err(e) = netlink.send_config_update(&config_update) {
            crate::logger::warn!(
                crate::logger::get(),
                "同步配置到内核模块失败";
                "error" => %e
            );
        } else {
            crate::logger::info!(
                crate::logger::get(),
                "配置已同步到内核模块";
                "ban_time" => cfg.ddos.auto_ban_duration,
                "max_pps" => cfg.ddos.global_conn_rate,
                "ddos_ban_duration" => cfg.ddos.auto_ban_duration
            );
        }

        // 同步 DDoS 检测开关到内核模块参数
        sync_ddos_detection_to_kernel(cfg);
    }

    // 3. 更新全局 Web UI 配置
    crate::http_exporter::set_global_webui_config(cfg.webui.clone());
    crate::logger::info!(
        crate::logger::get(),
        "配置已同步到 Web UI";
        "sse_push_interval" => cfg.webui.sse_push_interval
    );

    // 4. 更新全局 Jail 信息
    let jail_infos: Vec<crate::http_exporter::JailInfo> = cfg
        .jails
        .iter()
        .map(|j| crate::http_exporter::JailInfo {
            name: j.name.clone(),
            enabled: j.enabled,
            max_retries: j.max_retries,
            findtime: j.findtime,
            ban_time: j.ban_time,
        })
        .collect();
    let jail_count = jail_infos.len();
    crate::http_exporter::set_global_jails(jail_infos);
    crate::logger::info!(
        crate::logger::get(),
        "Jail 信息已更新";
        "count" => jail_count
    );

    Ok(())
}

// ============================================================================
// 配置热重载
// ============================================================================

/// SIGHUP 热重载（事务）：提交前失败不影响运行态；提交后关键步骤失败则回退内存配置。
///
/// 步骤：clone 旧 → 解析到新 → 应用默认 → 验证 → 迁移 `failed_hash` →
/// 编译正则 → 保存快照 → 原子替换 → 重建 inotify → 可信 IP / 组件同步 → 持久化。
///
/// HTTP 绑定地址与 metrics 凭据无法在不重启监听器的情况下热更新；若文件中变更则告警。
pub fn reload_configuration(cfg: &mut Config) -> Result<()> {
    use crate::config;

    let config_path = if let Some(ref f) = cfg.config_file {
        f.clone()
    } else if let Some(ref d) = cfg.config_dir {
        d.clone()
    } else {
        return Err(anyhow::anyhow!(
            "No config file or directory specified for reload"
        ));
    };

    let old_cfg = jail::config_clone(cfg);

    // 从当前配置初始化（保留运行时修改），解析文件后覆盖文件中的字段
    let mut new_cfg = jail::config_clone(cfg);
    // 清空 jails：parse_config 会 push 所有 jail，不清空会导致每次重载 jail 翻倍
    new_cfg.jails.clear();

    let path = std::path::Path::new(&config_path);
    if path.is_file() {
        config::parse_config_file(&config_path, &mut new_cfg, cfg.strict_mode)?;
    } else if path.is_dir() {
        config::load_config_directory(&config_path, &mut new_cfg, cfg.strict_mode)?;
    } else {
        return Err(anyhow::anyhow!("Config path does not exist: {config_path}"));
    }

    jail::apply_smart_defaults_to_all(&mut new_cfg);
    jail::config_validate(&new_cfg).map_err(|e| anyhow::anyhow!("{e}"))?;

    // 迁移 failed_hash（保留历史失败计数）
    for old_jail in &old_cfg.jails {
        for new_jail in &mut new_cfg.jails {
            if old_jail.name == new_jail.name {
                let mut old_hash = old_jail.failed_hash.write();
                let mut new_hash = new_jail.failed_hash.write();
                for (ip, entry) in old_hash.drain() {
                    new_hash.insert(ip, entry);
                }
                break;
            }
        }
    }

    // 正则编译失败则中止，不改运行态
    jail::init_log_patterns(&mut new_cfg)
        .map_err(|e| anyhow::anyhow!("重载时初始化日志模式失败，已保持旧配置: {e}"))?;

    // 保留 Web UI API 修改的 Jail 启用状态（GLOBAL_JAILS 是运行时权威源）
    if let Some(lock) = crate::http_exporter::GLOBAL_JAILS.get() {
        let runtime_jails = lock.read();
        for runtime_jail in runtime_jails.iter() {
            if let Some(cfg_jail) = new_cfg
                .jails
                .iter_mut()
                .find(|j| j.name == runtime_jail.name)
            {
                cfg_jail.enabled = runtime_jail.enabled;
            }
        }
    }

    let http_listener_changed = old_cfg.metrics_port != new_cfg.metrics_port
        || old_cfg.metrics_bind_address != new_cfg.metrics_bind_address
        || old_cfg.metrics_username != new_cfg.metrics_username
        || old_cfg.metrics_password != new_cfg.metrics_password;

    // 提交前先入历史，供 --rollback / 失败回退使用
    save_config_snapshot(&old_cfg);

    *cfg = new_cfg;

    if let Err(e) = setup_inotify(cfg) {
        crate::logger::error!(
            crate::logger::get(),
            "重载后重建 inotify 失败，回退到旧配置";
            "error" => %e
        );
        *cfg = old_cfg;
        let _ = setup_inotify(cfg);
        // 弹出刚才写入的快照（已回到该版本运行）
        let _ = config_history_lock().write().pop();
        return Err(e);
    }

    update_trusted_ips(&old_cfg.trusted_ips, &cfg.trusted_ips);

    DAEMON_STATS.config_reloads.fetch_add(1, Ordering::Relaxed);

    set_global_trusted_ips(&cfg.trusted_ips);
    set_global_capacity(&cfg.capacity);
    crate::types::set_baseline_warmup_samples(cfg.ddos.baseline_warmup_samples);

    if let Err(e) = sync_config_to_components(cfg) {
        crate::logger::error!(
            crate::logger::get(),
            "同步配置到组件失败，回退到旧配置";
            "error" => %e
        );
        update_trusted_ips(&cfg.trusted_ips, &old_cfg.trusted_ips);
        *cfg = old_cfg;
        let _ = setup_inotify(cfg);
        let _ = sync_config_to_components(cfg);
        let _ = config_history_lock().write().pop();
        return Err(e);
    }

    if http_listener_changed {
        crate::logger::warn!(
            crate::logger::get(),
            "metrics 绑定地址或 Basic Auth 凭据已变更，需重启守护进程后监听器才会切换";
            "bind" => &cfg.metrics_bind_address,
            "port" => cfg.metrics_port
        );
    }

    if let Err(e) = persist_config(cfg, &get_global_jails_enabled()) {
        crate::logger::warn!(
            crate::logger::get(),
            "持久化配置失败";
            "error" => %e
        );
    }

    Ok(())
}

// ============================================================================
// 周期维护
// ============================================================================

/// 周期维护：flush 所有 jail 的 partial 行缓冲。`monitor_loop` 超时 60s 触发。
///
/// 防止 partial 缓冲无限增长（异常日志最后一行无 `\n`）。
///
/// # Arguments
/// - `cfg`：全局配置
pub fn cleanup_partial_line_buffer(cfg: &Config) {
    for jail in &cfg.jails {
        let mut buf = jail.partial_line_buffer.write();
        if !buf.is_empty() {
            crate::logger::debug!(
                crate::logger::get(),
                "清理 partial 行缓冲";
                "jail" => &jail.name,
                "size" => buf.len()
            );
            buf.clear();
        }
    }
}

// ============================================================================
// 可信 IP 白名单更新
// ============================================================================

/// 热重载时更新可信 IP 白名单。
///
/// 对比新旧列表，添加新增的 IP，移除不再需要的 IP。
///
/// # Arguments
/// - `old_ips`: 旧的可信 IP 列表
/// - `new_ips`: 新的可信 IP 列表
fn update_trusted_ips(old_ips: &[String], new_ips: &[String]) {
    use crate::ban;
    use std::collections::HashSet;

    let old_set: HashSet<&str> = old_ips.iter().map(|s| s.as_str()).collect();
    let new_set: HashSet<&str> = new_ips.iter().map(|s| s.as_str()).collect();

    // 新增的 IP（在 new 中但不在 old 中）
    let added: Vec<String> = new_set
        .difference(&old_set)
        .map(|s| s.to_string())
        .collect();

    // 移除的 IP（在 old 中但不在 new 中）
    let removed: Vec<String> = old_set
        .difference(&new_set)
        .map(|s| s.to_string())
        .collect();

    if !added.is_empty() {
        crate::logger::info!(
            crate::logger::get(),
            "热重载：添加新的可信 IP";
            "count" => added.len(),
            "ips" => ?added
        );
        let failed = ban::init_trusted_ips(&added);
        if !failed.is_empty() {
            crate::logger::warn!(
                crate::logger::get(),
                "热重载：部分可信 IP 添加失败";
                "failed" => ?failed
            );
        }
    }

    if !removed.is_empty() {
        crate::logger::info!(
            crate::logger::get(),
            "热重载：移除不再信任的 IP";
            "count" => removed.len(),
            "ips" => ?removed
        );
        let failed = ban::remove_trusted_ips(&removed);
        if !failed.is_empty() {
            crate::logger::warn!(
                crate::logger::get(),
                "热重载：部分可信 IP 移除失败";
                "failed" => ?failed
            );
        }
    }
}

/// 同步 DDoS 检测开关到内核模块参数
fn sync_ddos_detection_to_kernel(cfg: &crate::types::Config) {
    crate::ban::write_sysfs_bool_param("fw_static_threshold", cfg.ddos.static_threshold);
    crate::ban::write_sysfs_bool_param("fw_dynamic_threshold", cfg.ddos.dynamic_threshold);
    crate::ban::write_sysfs_bool_param("fw_ddos_detection", cfg.ddos.ddos_detection);

    crate::logger::info!(
        crate::logger::get(),
        "DDoS 检测开关已同步到内核";
        "static" => cfg.ddos.static_threshold,
        "dynamic" => cfg.ddos.dynamic_threshold,
        "enabled" => cfg.ddos.ddos_detection
    );
}
