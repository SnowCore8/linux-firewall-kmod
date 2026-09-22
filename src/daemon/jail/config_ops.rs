//! 配置克隆 + 验证 + 失败条目迁移

use super::regex::free_jail_regex_full;
use crate::types::{Config, Jail, MAX_JAILS};

use super::operations::clone_jail;

/// 集群检测允许的最短 IPv4 聚合前缀。
///
/// 命中后封的是整个聚合网段，前缀过短会一次封掉远超预期的地址范围
/// （`/1` 即半个 IPv4 空间）。`/16` 是"至少一个机构级网段"的保守下限，
/// 实际用途（`/24`、`/16`）都在其上。
const MIN_PREFIX_V4: u8 = 16;

/// 集群检测允许的最短 IPv6 聚合前缀（与 IPv4 同理，`/32` 对应一个站点级网段）。
const MIN_PREFIX_V6: u8 = 32;

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
        log_max_size_mb: src.log_max_size_mb,
        log_max_files: src.log_max_files,
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
    // log_max_files 含当前文件，0 意味着「一片都不留」；log_max_size_mb=0 表示关闭轮转
    if cfg.log_max_files == 0 {
        return Err("log_max_files is 0 (must be >= 1)".to_string());
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
        // 集群扫描检测：仅在启用时校验。`window` / `min_ips` 为 0 会让 `detect` 直接
        // 返回空（退化分支），用户以为开着而实际永不触发，故按硬错误拒绝。
        if jail.cluster.enabled {
            if jail.cluster.window == 0 {
                return Err(format!(
                    "Jail '{}' has cluster.window=0 (must be >0 when cluster.enabled)",
                    jail.name
                ));
            }
            if jail.cluster.min_ips == 0 {
                return Err(format!(
                    "Jail '{}' has cluster.min_ips=0 (must be >0 when cluster.enabled)",
                    jail.name
                ));
            }
            if jail.cluster.prefix_v4 > 32 {
                return Err(format!(
                    "Jail '{}' has cluster.prefix_v4={} (must be <=32)",
                    jail.name, jail.cluster.prefix_v4
                ));
            }
            if jail.cluster.prefix_v6 > 128 {
                return Err(format!(
                    "Jail '{}' has cluster.prefix_v6={} (must be <=128)",
                    jail.name, jail.cluster.prefix_v6
                ));
            }
            // 下界必须挡住：命中后封的是**整个聚合网段**，前缀过短等于封掉半个
            // 互联网——`prefix_v4=1` 会把 `203.0.113.7` 归一到 `128.0.0.0/1`。
            // 取 16/32 是"至少一个机构级网段"的保守下限；合法用途（/24、/16）
            // 都在其上。
            if jail.cluster.prefix_v4 < MIN_PREFIX_V4 {
                return Err(format!(
                    "Jail '{}' has cluster.prefix_v4={} (must be >={MIN_PREFIX_V4}): \
                     封禁按整个聚合网段下发，前缀过短会波及远超预期的地址范围",
                    jail.name, jail.cluster.prefix_v4
                ));
            }
            if jail.cluster.prefix_v6 < MIN_PREFIX_V6 {
                return Err(format!(
                    "Jail '{}' has cluster.prefix_v6={} (must be >={MIN_PREFIX_V6}): \
                     封禁按整个聚合网段下发，前缀过短会波及远超预期的地址范围",
                    jail.name, jail.cluster.prefix_v6
                ));
            }
            // `max_per_ip` 超过 `min_ips` 时不拒绝（仍是合法配置），但第二条判据
            // 「每 IP 失败数 ≤ max_per_ip」会失去区分度：每 IP 允许的失败数一旦
            // 赶上命中门槛，高频出口（CGNAT、单出口多用户）也会被算作低频而误封。
            if jail.cluster.max_per_ip > jail.cluster.min_ips {
                crate::logger::warn!(
                    crate::logger::get(),
                    "cluster.max_per_ip 大于 min_ips，判定会误纳高频出口（建议 max_per_ip <= min_ips）";
                    "jail" => &jail.name,
                    "min_ips" => jail.cluster.min_ips,
                    "max_per_ip" => jail.cluster.max_per_ip
                );
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::ClusterConfig;

    /// 启用集群检测、前缀取 `prefix` 的单个 jail 配置。
    ///
    /// 需带日志文件与一条正则，否则校验会先在前置检查（`no log files`）处返回，
    /// 走不到 cluster 段。
    fn cfg_with_prefix_v4(prefix: u8) -> Config {
        let mut jail = Jail::new("sshd".to_string());
        jail.log_files = vec!["/var/log/auth.log".to_string()];
        jail.regexes = vec![crate::types::RegexInfo::new(
            "default".to_string(),
            r"Failed password from (\d+\.\d+\.\d+\.\d+)".to_string(),
        )];
        // 阈值三项也必须合法，否则校验会先在那里返回、走不到 cluster 段。
        jail.max_retries = 5;
        jail.findtime = 600;
        jail.ban_time = 600;
        jail.cluster = ClusterConfig {
            enabled: true,
            prefix_v4: prefix,
            ..ClusterConfig::default()
        };
        Config {
            jails: vec![jail],
            ..Config::default()
        }
    }

    /// 下界是**安全**约束而非风格约束：命中后封的是整个聚合网段，前缀过短会
    /// 一次封掉远超预期的地址范围（`/1` 即半个 IPv4 空间），故必须拒绝。
    #[test]
    fn cluster_prefix_below_the_floor_is_rejected() {
        let err = config_validate(&cfg_with_prefix_v4(MIN_PREFIX_V4 - 1))
            .expect_err("低于下限的 prefix_v4 应拒绝");
        assert!(err.contains("prefix_v4"), "错误信息应点出违规字段: {err}");

        assert!(
            config_validate(&cfg_with_prefix_v4(MIN_PREFIX_V4)).is_ok(),
            "恰好等于下限应通过"
        );
        assert!(
            config_validate(&cfg_with_prefix_v4(24)).is_ok(),
            "默认量级（/24）应通过"
        );
    }

    /// 上界（IPv4 /32、IPv6 /128）仍被拒绝——与下界是两条独立断言。
    #[test]
    fn cluster_prefix_above_the_width_is_rejected() {
        let err =
            config_validate(&cfg_with_prefix_v4(33)).expect_err("超过 32 的 prefix_v4 应拒绝");
        assert!(err.contains("prefix_v4"), "错误信息应点出违规字段: {err}");
    }
}
