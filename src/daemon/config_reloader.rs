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

/// 全局配置版本历史
static CONFIG_HISTORY: std::sync::LazyLock<parking_lot::RwLock<Vec<ConfigSnapshot>>> =
    std::sync::LazyLock::new(|| parking_lot::RwLock::new(Vec::new()));

/// 配置快照（用于版本历史和回滚）
#[derive(Clone)]
struct ConfigSnapshot {
    /// 版本时间戳
    timestamp: i64,
    /// DDoS 配置
    ddos: crate::types::DdosConfig,
    /// Web UI 配置
    webui: crate::types::WebuiConfig,
    /// 可信 IP 列表
    trusted_ips: Vec<String>,
}

/// 保存配置快照到版本历史
fn save_config_snapshot(cfg: &Config) {
    let snapshot = ConfigSnapshot {
        timestamp: crate::types::now_secs(),
        ddos: cfg.ddos.clone(),
        webui: cfg.webui.clone(),
        trusted_ips: cfg.trusted_ips.clone(),
    };

    let mut history = CONFIG_HISTORY.write();
    history.push(snapshot);
    // 保留最近的 MAX_CONFIG_VERSIONS 个版本
    while history.len() > MAX_CONFIG_VERSIONS {
        history.remove(0);
    }
}

/// 回滚到上一个配置版本
pub fn rollback_config(cfg: &mut Config) -> Result<()> {
    let mut history = CONFIG_HISTORY.write();
    if history.len() < 2 {
        return Err(anyhow::anyhow!("没有可回滚的历史版本"));
    }

    // 移除当前版本
    history.pop();
    // 获取上一个版本
    let snapshot = history.last().unwrap().clone();

    // 应用快照配置
    cfg.ddos = snapshot.ddos;
    cfg.webui = snapshot.webui;
    cfg.trusted_ips = snapshot.trusted_ips;

    // 同步到各组件
    sync_config_to_components(cfg)?;

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

/// 运行时配置文件路径
const RUNTIME_CONFIG_PATH: &str = "/var/lib/firewall/runtime_config.yaml";

/// 保存配置到持久化文件
fn persist_config(cfg: &Config) -> Result<()> {
    use std::io::Write;

    let mut yaml = String::new();

    // 写入 DDoS 配置
    yaml.push_str("ddos:\n");
    yaml.push_str(&format!("  enabled: {}\n", cfg.ddos.enabled));
    yaml.push_str(&format!(
        "  per_ip_conn_rate: {}\n",
        cfg.ddos.per_ip_conn_rate
    ));
    yaml.push_str(&format!(
        "  per_ip_fail_rate: {}\n",
        cfg.ddos.per_ip_fail_rate
    ));
    yaml.push_str(&format!(
        "  global_conn_rate: {}\n",
        cfg.ddos.global_conn_rate
    ));
    yaml.push_str(&format!(
        "  auto_ban_duration: {}\n",
        cfg.ddos.auto_ban_duration
    ));
    yaml.push_str(&format!(
        "  auto_ban_threshold: {}\n",
        cfg.ddos.auto_ban_threshold
    ));
    yaml.push_str(&format!("  check_interval: {}\n", cfg.ddos.check_interval));

    // 写入 Web UI 配置
    yaml.push_str("\nwebui:\n");
    yaml.push_str(&format!(
        "  sse_push_interval: {}\n",
        cfg.webui.sse_push_interval
    ));
    yaml.push_str(&format!(
        "  rate_warning_pps: {}\n",
        cfg.webui.rate_warning_pps
    ));
    yaml.push_str(&format!(
        "  rate_critical_pps: {}\n",
        cfg.webui.rate_critical_pps
    ));
    yaml.push_str(&format!(
        "  rate_warning_syn: {}\n",
        cfg.webui.rate_warning_syn
    ));
    yaml.push_str(&format!(
        "  rate_critical_syn: {}\n",
        cfg.webui.rate_critical_syn
    ));

    // 写入可信 IP
    if !cfg.trusted_ips.is_empty() {
        yaml.push_str("\ntrusted_ips:\n");
        for ip in &cfg.trusted_ips {
            yaml.push_str(&format!("  - \"{}\"\n", ip));
        }
    }

    // 写入文件
    let path = std::path::Path::new(RUNTIME_CONFIG_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(path)?;
    file.write_all(yaml.as_bytes())?;

    crate::logger::info!(
        crate::logger::get(),
        "配置已持久化";
        "path" => RUNTIME_CONFIG_PATH
    );

    Ok(())
}

/// 加载持久化的配置（启动时调用）
pub fn load_persisted_config() -> Option<String> {
    let path = std::path::Path::new(RUNTIME_CONFIG_PATH);
    if path.exists() {
        std::fs::read_to_string(path).ok()
    } else {
        None
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
        let config_update = ConfigUpdate::new(config_flags::BAN_TIME | config_flags::MAX_PPS)
            .with_ban_time(cfg.ddos.auto_ban_duration)
            .with_max_pps(cfg.ddos.global_conn_rate as u64);

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
                "max_pps" => cfg.ddos.global_conn_rate
            );
        }
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

/// SIGHUP 热重载（双缓冲）：任何步骤失败旧配置不受影响。
///
/// 步骤：clone 旧 → 解析到新 → 应用默认 → 验证 → 迁移 `failed_hash` →
/// 编译正则 → 原子替换 → 重建 inotify → 同步到各组件 → 持久化。
///
/// # Arguments
/// - `cfg`：旧配置（会被新配置原子替换）
///
/// # Returns
/// 成功时 `Ok(())`，`DAEMON_STATS.config_reloads` +1
///
/// # Errors
/// 配置源缺失 / 解析失败 / 验证失败 / inotify 重建失败
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

    // 保留 config_file / config_dir 保留供 SIGHUP 后继 reload 复用
    let mut new_cfg = Config {
        config_file: old_cfg.config_file.clone(),
        config_dir: old_cfg.config_dir.clone(),
        ..Config::default()
    };

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

    if let Err(e) = jail::init_log_patterns(&mut new_cfg) {
        crate::logger::warn!(
            crate::logger::get(),
            "重载时初始化日志模式失败";
            "error" => %e
        );
    }

    // 更新可信 IP 白名单
    update_trusted_ips(&old_cfg.trusted_ips, &new_cfg.trusted_ips);

    // 保存旧配置快照（用于回滚）
    save_config_snapshot(&old_cfg);

    *cfg = new_cfg;
    DAEMON_STATS.config_reloads.fetch_add(1, Ordering::Relaxed);
    setup_inotify(cfg)?;

    // 同步配置到各组件
    if let Err(e) = sync_config_to_components(cfg) {
        crate::logger::warn!(
            crate::logger::get(),
            "同步配置到组件失败";
            "error" => %e
        );
    }

    // 持久化配置
    if let Err(e) = persist_config(cfg) {
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
