//! 配置文件/目录加载: 单文件 + 目录多文件

use crate::types::Config;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

use super::parser::{parse_config, validate_and_normalize_path};

// ============================================================================
// 单文件解析
// ============================================================================

/// 解析单个 YAML 配置文件。
///
/// 失败时不修改 `cfg` (原子性保证)。
///
/// # Arguments
/// - `path`: 配置文件路径 (需通过 [`validate_and_normalize_path`] 检查)
/// - `cfg`: 目标 Config
/// - `strict`: 是否开启严格模式 (未知 key 报错)
///
/// # Errors
/// - 路径安全检查失败
/// - 文件读取失败
/// - YAML 解析失败
/// - 严格模式下出现未知 key
pub fn parse_config_file(path: &str, cfg: &mut Config, strict: bool) -> Result<()> {
    validate_and_normalize_path(path)?;

    if !Path::new(path).is_file() {
        bail!("Config file does not exist: {}", path);
    }

    let content = fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path))?;

    // 快照当前配置, 解析失败时回滚
    let old_strict = cfg.strict_mode;
    let saved_config_file = cfg.config_file.clone();
    let saved_config_dir = cfg.config_dir.clone();
    let saved_permanent_db_path = cfg.permanent_db_path.clone();
    let saved_permanent_ban_enabled = cfg.permanent_ban_enabled;
    let saved_log_file = cfg.log_file.clone();
    let saved_metrics_bind_address = cfg.metrics_bind_address.clone();
    let saved_metrics_username = cfg.metrics_username.clone();
    let saved_metrics_password = cfg.metrics_password.clone();
    let saved_jails_len = cfg.jails.len();
    // 补充缺失的字段快照
    let saved_default_max_retries = cfg.default_max_retries;
    let saved_default_findtime = cfg.default_findtime;
    let saved_default_ban_time = cfg.default_ban_time;
    let saved_interval = cfg.interval;
    let saved_metrics_port = cfg.metrics_port;
    let saved_log_level = cfg.log_level;
    let saved_log_destination = cfg.log_destination;
    let saved_log_format = cfg.log_format;

    cfg.strict_mode = strict;

    match parse_config(&content, cfg) {
        Ok(_) => {
            cfg.config_file = Some(path.to_string());
            Ok(())
        }
        Err(e) => {
            // 回滚所有可回滚字段
            cfg.strict_mode = old_strict;
            cfg.config_file = saved_config_file;
            cfg.config_dir = saved_config_dir;
            cfg.permanent_db_path = saved_permanent_db_path;
            cfg.permanent_ban_enabled = saved_permanent_ban_enabled;
            cfg.log_file = saved_log_file;
            cfg.metrics_bind_address = saved_metrics_bind_address;
            cfg.metrics_username = saved_metrics_username;
            cfg.metrics_password = saved_metrics_password;
            cfg.jails.truncate(saved_jails_len);
            // 补充缺失的字段回滚
            cfg.default_max_retries = saved_default_max_retries;
            cfg.default_findtime = saved_default_findtime;
            cfg.default_ban_time = saved_default_ban_time;
            cfg.interval = saved_interval;
            cfg.metrics_port = saved_metrics_port;
            cfg.log_level = saved_log_level;
            cfg.log_destination = saved_log_destination;
            cfg.log_format = saved_log_format;
            Err(e)
        }
    }
}

// ============================================================================
// 目录加载
// ============================================================================

/// 加载目录下所有 `.yml` / `.yaml` 配置文件, 按文件名字母序合并。
///
/// 设计要点:
/// - **字母序合并**: `01-base.yml` 先于 `02-override.yml`, 后者可覆盖前者
/// - **原子性**: 任一文件失败时, 已加载的条目全部回滚
/// - **跳过隐藏文件 / 非 YAML**: 符合 fail2ban 的 `jail.d/` 惯例
///
/// # Arguments
/// - `dir`: 目录路径 (需通过 [`validate_and_normalize_path`] 检查)
/// - `cfg`: 目标 Config
/// - `strict`: 是否开启严格模式
///
/// # Errors
/// - 路径安全检查失败
/// - 目录不存在 / 不可读
/// - 任一 YAML 文件解析失败 (已加载条目回滚)
pub fn load_config_directory(dir: &str, cfg: &mut Config, strict: bool) -> Result<()> {
    validate_and_normalize_path(dir)?;

    let dir_path = Path::new(dir);
    if !dir_path.is_dir() {
        bail!("Config directory does not exist: {}", dir);
    }

    // 收集 YAML 文件并按名称字母序排序
    let mut files: Vec<_> = fs::read_dir(dir_path)
        .with_context(|| format!("Failed to read config directory: {}", dir))?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?;
            if name.starts_with('.') {
                return None; // 跳过隐藏文件
            }
            match path.extension().and_then(|e| e.to_str()) {
                Some("yml") | Some("yaml") => Some(path),
                _ => None,
            }
        })
        .collect();

    files.sort();

    if files.is_empty() {
        bail!("No YAML files found in directory: {}", dir);
    }

    // 快照: 目录加载模式下, 任一文件失败则整体回滚
    let old_strict = cfg.strict_mode;
    let saved_config_file = cfg.config_file.clone();
    let saved_config_dir = cfg.config_dir.clone();
    let saved_permanent_db_path = cfg.permanent_db_path.clone();
    let saved_permanent_ban_enabled = cfg.permanent_ban_enabled;
    let saved_log_file = cfg.log_file.clone();
    let saved_metrics_bind_address = cfg.metrics_bind_address.clone();
    let saved_metrics_username = cfg.metrics_username.clone();
    let saved_metrics_password = cfg.metrics_password.clone();
    let saved_jails_len = cfg.jails.len();

    cfg.strict_mode = strict;

    for file in &files {
        let file_str = file.to_string_lossy();
        if let Err(e) = parse_config_file(&file_str, cfg, strict) {
            // 失败回滚, 恢复快照
            cfg.strict_mode = old_strict;
            cfg.config_file = saved_config_file;
            cfg.config_dir = saved_config_dir;
            cfg.permanent_db_path = saved_permanent_db_path;
            cfg.permanent_ban_enabled = saved_permanent_ban_enabled;
            cfg.log_file = saved_log_file;
            cfg.metrics_bind_address = saved_metrics_bind_address;
            cfg.metrics_username = saved_metrics_username;
            cfg.metrics_password = saved_metrics_password;
            cfg.jails.truncate(saved_jails_len);
            return Err(e).with_context(|| {
                format!("Failed to parse config file in directory: {}", file_str)
            });
        }
    }

    cfg.config_dir = Some(dir.to_string());
    Ok(())
}
