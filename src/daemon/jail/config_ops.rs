//! 配置克隆 + 验证 + 失败条目迁移

use super::regex::free_jail_regex_full;
use crate::types::{Config, Jail, MAX_JAILS};

use super::operations::clone_jail;

pub fn config_clone(src: &Config) -> Config {
    // 显式列出所有 Config 字段（不使用 `..Config::default()`），
    // 确保未来新增字段时编译器强制报错，防止热重载静默丢失字段值
    let mut dst = Config {
        default_max_retries: src.default_max_retries,
        default_findtime: src.default_findtime,
        default_ban_time: src.default_ban_time,
        daemon: src.daemon,
        interval: src.interval,
        metrics_port: src.metrics_port,
        metrics_bind_address: src.metrics_bind_address.clone(),
        metrics_username: src.metrics_username.clone(),
        metrics_password: src.metrics_password.clone(),
        config_file: src.config_file.clone(),
        config_dir: src.config_dir.clone(),
        log_file: src.log_file.clone(),
        log_level: src.log_level,
        log_destination: src.log_destination,
        log_format: src.log_format,
        strict_mode: src.strict_mode,
        jails: Vec::with_capacity(src.jails.len()),
        storage: src.storage.clone(),
        ddos: src.ddos.clone(),
        webui: src.webui.clone(),
        trusted_ips: src.trusted_ips.clone(),
        capacity: src.capacity.clone(),
    };

    for src_jail in &src.jails {
        let mut dst_jail = Jail::new(src_jail.name.clone());
        if clone_jail(&mut dst_jail, src_jail).is_ok() {
            dst.jails.push(dst_jail);
        }
    }

    dst
}

/// 校验 `Config` 的完整性。`main()` 在 `apply_smart_defaults_to_all` 之后、
/// 启动 inotify 之前调用。
///
/// 检查项:
/// - `jails` 数量 ∈ `[1, MAX_JAILS]`
/// - `interval` ∈ `[1, 60]`
/// - `default_max_retries` / `default_findtime` > 0
/// - 各 enabled jail 必须有 `log_files` / `max_retries` / `findtime`
///
/// # Arguments
/// - `cfg`: 待校验的配置
///
/// # Errors
/// 任一规则不满足即返回 `Err(String)`,失败信息包含具体字段名
pub fn config_validate(cfg: &Config) -> Result<(), String> {
    if cfg.jails.is_empty() || cfg.jails.len() > MAX_JAILS {
        return Err(format!(
            "invalid jail_count={} (must be 1..{})",
            cfg.jails.len(),
            MAX_JAILS
        ));
    }
    if cfg.interval == 0 || cfg.interval > 60 {
        return Err(format!("invalid interval={} (must be 1..60)", cfg.interval));
    }
    // metrics_port 是 u16, 范围检查在类型系统天然保证; 0 = 禁用, 1..=65535 = 监听
    if cfg.default_max_retries == 0 {
        return Err("default_max_retries is 0".to_string());
    }
    if cfg.default_findtime == 0 {
        return Err("default_findtime is 0".to_string());
    }

    for jail in &cfg.jails {
        if !jail.enabled {
            continue;
        }
        if jail.log_files.is_empty() {
            return Err(format!("Jail '{}' has no log files", jail.name));
        }
        if jail.max_retries == 0 {
            return Err(format!("Jail '{}' has max_retries=0", jail.name));
        }
        if jail.findtime == 0 {
            return Err(format!("Jail '{}' has findtime=0", jail.name));
        }
        if jail.ban_time == 0 || jail.ban_time < -1 {
            return Err(format!(
                "Jail '{}' has invalid ban_time={} (use -1 for permanent or >0 for timed)",
                jail.name, jail.ban_time
            ));
        }
    }

    Ok(())
}

/// SIGHUP 热重载:把旧 jail 的 `failed_hash` 迁移到同名新 jail,保留运行时
/// 失败计数状态,避免新配置生效后攻击者失败计数清零。
///
/// # Arguments
/// - `old`: 旧配置 (可变,`failed_hash` 被 drain)
/// - `new`: 新配置 (可变,`failed_hash` 被填充)
pub fn migrate_failed_entries(old: &mut Config, new: &mut Config) {
    for old_jail in &mut old.jails {
        if old_jail.failed_hash.read().is_empty() {
            continue;
        }

        for new_jail in &mut new.jails {
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
}

/// 部分释放 `Config`:清空所有 jail + 配置来源追踪 + 敏感字段。
///
/// 与 `cleanup_all_jails` 的区别:还清空 `config_file` / `config_dir` /
/// `metrics_*` 字段,适用于"完全卸载配置"的场景。
///
/// # Arguments
/// - `cfg`: 目标配置 (可变引用)
pub fn free_config_partial(cfg: &mut Config) {
    for jail in &mut cfg.jails {
        jail.log_files.clear();
        free_jail_regex_full(jail);
        jail.failed_hash.write().clear();
    }
    cfg.jails.clear();
    cfg.config_file = None;
    cfg.config_dir = None;
    cfg.metrics_bind_address.clear();
    cfg.metrics_username = None;
    cfg.metrics_password = None;
}
