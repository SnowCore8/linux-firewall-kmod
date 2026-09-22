//! 配置文件/目录加载: 单文件 + 目录多文件

use crate::types::Config;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

use super::parser::{parse_config_from, validate_and_normalize_path};

/// daemon 自动管理的运行期覆盖文件名前缀（当前唯一使用者是 `_overrides.yaml`）。
///
/// 这类文件由 `config_reloader` 写回，只承载运行期状态（jail 的 `enabled` 等），
/// 因此目录加载时**最后合并**——它对预置文件里的定义拥有最终发言权。
pub const RUNTIME_OVERRIDE_PREFIX: char = '_';

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

    // 运行期覆盖文件（`_` 前缀）只带运行期状态，jail 处理规则不同（见 parser::parse_config_from）
    let runtime_override = Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.starts_with(RUNTIME_OVERRIDE_PREFIX))
        .unwrap_or(false);

    match parse_config_from(&content, cfg, runtime_override) {
        Ok(_) => {
            cfg.config_file = Some(path.to_string());
            Ok(())
        }
        Err(e) => {
            // 回滚所有可回滚字段
            cfg.strict_mode = old_strict;
            cfg.config_file = saved_config_file;
            cfg.config_dir = saved_config_dir;
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
/// - **运行期覆盖最后**: `_` 前缀的自动管理文件（如 `_overrides.yaml`）排在最后合并
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

    files.sort_by(|a, b| {
        // 先按文件名（字母序契约），再把运行期覆盖文件排到最后：纯字节序下
        // `_`（0x5F）排在小写字母之前，会让自动写回的运行期状态反过来被预置定义覆盖。
        let key = |p: &std::path::PathBuf| {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .to_string();
            (name.starts_with(RUNTIME_OVERRIDE_PREFIX), name)
        };
        key(a).cmp(&key(b))
    });

    if files.is_empty() {
        bail!("No YAML files found in directory: {}", dir);
    }

    // 快照: 目录加载模式下, 任一文件失败则整体回滚
    let old_strict = cfg.strict_mode;
    let saved_config_file = cfg.config_file.clone();
    let saved_config_dir = cfg.config_dir.clone();
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

    // 目录加载模式：设置 config_dir，清除 config_file（避免 reload 时只加载单个文件）
    cfg.config_dir = Some(dir.to_string());
    cfg.config_file = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// 系统临时目录下的唯一子目录，避免污染仓库。
    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "fw-config-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("建临时目录失败");
        dir
    }

    fn write(dir: &std::path::Path, name: &str, body: &str) {
        std::fs::write(dir.join(name), body).expect("写配置失败");
    }

    /// 运行期覆盖文件只带 `enabled` 时，不能抹掉预置文件里的 `log_files`。
    ///
    /// 这是「同名 jail 后到优先」对自动写回文件的关键约束：一旦覆盖成整条替换，
    /// 守护进程下次启动就会因 `Jail 'x' has no log files` 拒绝加载（实测过一次）。
    #[test]
    fn runtime_override_keeps_definition_from_preset_file() {
        let dir = tempdir("merge");
        write(
            &dir,
            "frp.yaml",
            "jails:\n  frp:\n    enabled: true\n    log_files:\n      - /var/log/frp.log\n",
        );
        write(
            &dir,
            "_overrides.yaml",
            "jails:\n  frp:\n    enabled: false\n",
        );

        let mut cfg = Config::default();
        load_config_directory(dir.to_str().unwrap(), &mut cfg, false).expect("目录加载失败");

        let frp: Vec<_> = cfg.jails.iter().filter(|j| j.name == "frp").collect();
        assert_eq!(
            frp.len(),
            1,
            "同名 jail 应合并成一条，实际 {} 条",
            frp.len()
        );
        assert_eq!(frp[0].log_files, vec!["/var/log/frp.log".to_string()]);
        assert!(!frp[0].enabled, "运行期覆盖的 enabled 应最后生效");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 运行期覆盖引用了别处未定义的 jail：忽略，而不是造出一个缺 log_files 的条目。
    #[test]
    fn runtime_override_ignores_unknown_jail() {
        let dir = tempdir("unknown");
        write(
            &dir,
            "sshd.yaml",
            "jails:\n  sshd:\n    log_files:\n      - /var/log/auth.log\n",
        );
        write(
            &dir,
            "_overrides.yaml",
            "jails:\n  ghost:\n    enabled: true\n",
        );

        let mut cfg = Config::default();
        load_config_directory(dir.to_str().unwrap(), &mut cfg, false).expect("目录加载失败");

        assert_eq!(cfg.jails.len(), 1, "未定义的 jail 不应被造出来");
        assert_eq!(cfg.jails[0].name, "sshd");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 普通文件之间的同名 jail 同样后到优先，且未声明的字段保留。
    #[test]
    fn later_file_wins_for_same_jail_name() {
        let dir = tempdir("order");
        write(
            &dir,
            "a-sshd.yaml",
            "jails:\n  sshd:\n    log_files:\n      - /var/log/a.log\n    max_retries: 2\n",
        );
        write(&dir, "b-sshd.yaml", "jails:\n  sshd:\n    max_retries: 5\n");

        let mut cfg = Config::default();
        load_config_directory(dir.to_str().unwrap(), &mut cfg, false).expect("目录加载失败");

        let sshd: Vec<_> = cfg.jails.iter().filter(|j| j.name == "sshd").collect();
        assert_eq!(sshd.len(), 1);
        assert_eq!(sshd[0].max_retries, 5, "后加载的文件应覆盖 max_retries");
        assert_eq!(
            sshd[0].log_files,
            vec!["/var/log/a.log".to_string()],
            "未声明的字段应保留"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
