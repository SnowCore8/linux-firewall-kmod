//! 配置热重载模块
//!
//! # 核心职责
//!
//! - SIGHUP 触发的双缓冲热重载
//! - 配置解析 + 验证 + 默认值应用
//! - failed_hash 迁移 (保留历史失败计数)
//! - partial 行缓冲周期清理
//!
//! # 关键不变量
//!
//! - 任何步骤失败旧配置不受影响 (双缓冲)
//! - `config_file` / `config_dir` 保留供后续 reload 复用

use std::sync::atomic::Ordering;

use anyhow::Result;

use crate::file_monitor::setup_inotify;
use crate::jail;
use crate::types::{Config, DAEMON_STATS};

// ============================================================================
// 配置热重载
// ============================================================================

/// SIGHUP 热重载 (双缓冲):任何步骤失败旧配置不受影响。
///
/// 步骤: clone 旧 → 解析到新 → 应用默认 → 验证 → 迁移 `failed_hash` →
/// 编译正则 → 原子替换 → 重建 inotify。
///
/// # Arguments
/// - `cfg`: 旧配置 (会被新配置原子替换)
///
/// # Returns
/// 成功时 `Ok(())`,`DAEMON_STATS.config_reloads` +1
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

    // 保留 config_file / config_dir 供 SIGHUP 后继 reload 复用
    let mut new_cfg = crate::types::Config {
        config_file: old_cfg.config_file.clone(),
        config_dir: old_cfg.config_dir.clone(),
        ..crate::types::Config::default()
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

    // 迁移 failed_hash (保留历史失败计数)
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

    if let Err(_e) = jail::init_log_patterns(&mut new_cfg) {
        // 正则编译失败,继续使用旧正则
    }

    *cfg = new_cfg;
    DAEMON_STATS.config_reloads.fetch_add(1, Ordering::Relaxed);
    setup_inotify(cfg)?;

    Ok(())
}

// ============================================================================
// 周期维护
// ============================================================================

/// 周期维护: flush 所有 jail 的 partial 行缓冲。`monitor_loop` 超时 60s 触发。
///
/// 防止 partial 缓冲无限增长(异常日志最后一行无 `\n`)。
///
/// # Arguments
/// - `cfg`: 全局配置
pub fn cleanup_partial_line_buffer(cfg: &Config) {
    for jail in &cfg.jails {
        let mut buf = jail.partial_line_buffer.write();
        if !buf.is_empty() {
            // 清理过期缓冲
            buf.clear();
        }
    }
}
