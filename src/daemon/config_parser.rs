//! YAML 配置解析 + 路径安全 3 重检查 + 严格模式 key 白名单 + 失败回滚 + CLI 参数
//!
//! # 核心特性
//!
//! - **路径安全 3 重检查**:
//!   1. `..` 路径遍历
//!   2. `%2e` / `%2f` / `%5c` URL 编码绕过
//!   3. shell 元字符命令注入
//!
//!   故意不做白名单检查,与 C 版 `validate_and_normalize_path` 行为等价
//! - **严格模式 key 白名单**:`--strict` (默认) 时任何未知 key 直接 bail
//! - **失败回滚**:先快照所有可回滚字段,中途失败时整体恢复
//! - **CLI 双形式支持**:`-c FILE` / `--config=FILE` 两种参数风格都接受
//!
//! # 失败模式
//!
//! - YAML 语法错误 → 立即 bail,旧 `cfg` 不变
//! - 严格模式命中未知 key → 立即 bail,旧 `cfg` 不变
//! - 路径不安全 → 跳过该日志文件,继续解析其他字段
//! - `log_destination` / `log_format` 非法值 → 整体回滚 + bail
//!
//! # CLI 标志
//!
//! | 短 | 长 | 说明 |
//! |----|-----|------|
//! | `-c` | `--config` | 指定配置文件 |
//! | `-C` | `--config-dir` | 加载目录下所有 .yaml/.yml |
//! | `-d` | `--daemon` | 后台守护进程模式 |
//! | `-s` | `--strict` | 启用严格模式 (默认) |
//! | `-p` | `--no-strict` / `--permissive` | 禁用严格模式 |
//! | `-h` | `--help` | 打印帮助后退出 |

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use crate::jail;
use crate::types::{Config, Jail, RegexInfo, MAX_JAILS};

// ============================================================================
// YAML 反序列化结构
// ============================================================================

/// 顶层 YAML 结构:`defaults` (全局默认) + `jails` (命名 jail 映射)
#[derive(Debug, Deserialize)]
struct YamlConfig {
    #[serde(default)]
    defaults: Option<YamlDefaults>,
    #[serde(default)]
    jails: Option<HashMap<String, YamlJail>>,
}

/// 全局默认字段集合。所有 `Option` 都是"未设置 = 使用 `Config::default()`"
#[derive(Debug, Deserialize)]
struct YamlDefaults {
    max_retries: Option<u32>,
    findtime: Option<u32>,
    ban_time: Option<u32>,
    interval: Option<u32>,
    metrics_port: Option<u16>,
    metrics_bind_address: Option<String>,
    metrics_username: Option<String>,
    metrics_password: Option<String>,
    permanent_db_path: Option<String>,
    permanent_ban_enabled: Option<bool>,
    log_file: Option<String>,
    log_level: Option<u8>,
    log_destination: Option<String>,
    log_format: Option<String>,
}

/// 单个 jail 的 YAML 表示。支持 `regex` 单条 + `regexes` 嵌套映射两种写法
#[derive(Debug, Deserialize)]
struct YamlJail {
    enabled: Option<bool>,
    log_files: Option<Vec<String>>,
    max_retries: Option<u32>,
    findtime: Option<u32>,
    ban_time: Option<u32>,
    regex: Option<String>,
    regex_name: Option<String>,
    /// 嵌套 regexes 映射: `{ name: { pattern: "..." }, ... }`
    #[serde(default)]
    regexes: HashMap<String, YamlRegexEntry>,
}

/// 嵌套 `regexes` 映射的 value 结构
#[derive(Debug, Deserialize)]
struct YamlRegexEntry {
    pattern: String,
}

// ============================================================================
// 路径验证
// ============================================================================

/// 校验并归一化日志文件路径。三重安全检查 + `canonicalize` 解析软链。
///
/// # Arguments
/// - `input_path`: 用户在 YAML 中写的路径
///
/// # Returns
/// - `Ok(String)`: 归一化后的绝对路径 (canonical 形式)
///
/// # Errors
/// - 包含 `..` 路径遍历
/// - 包含 URL 编码绕过 (`%2e` / `%2f` / `%5c` 大小写不敏感)
/// - 包含 shell 元字符(详见源码 `shell_chars` 常量)
/// - **包含嵌入 NUL 字节**(`'\0'`/`U+0000`): Rust 的 `Path` 在 Unix 上静默接受 NUL,
///   但 `OpenOptions::open` 内部转 C 字符串时 NUL 截断,导致 daemon 打开与用户预期
///   不同的文件(`/var/log/foo\0/etc/shadow` 实际打开 `/var/log/foo`)。这是静默
///   错误而非安全漏洞,但仍应在校验阶段拒绝以避免混淆。
pub fn validate_and_normalize_path(input_path: &str) -> Result<String> {
    if input_path.contains("..") {
        bail!("Log file path contains '..' (path traversal): {input_path}");
    }

    if input_path.contains('\0') {
        bail!("Log file path contains embedded NUL byte (U+0000): {input_path:?}");
    }

    let lower = input_path.to_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") {
        bail!("Log file path contains URL-encoded traversal: {input_path}");
    }

    let shell_chars = "|;&`$(){}<>!~*?[]";
    if input_path.chars().any(|c| shell_chars.contains(c)) {
        bail!("Log file path contains shell metacharacters: {input_path}");
    }

    let path = Path::new(input_path);
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    Ok(canonical.to_string_lossy().to_string())
}

// ============================================================================
// 严格模式: YAML key 白名单
// ============================================================================

/// `defaults:` 段允许的 key 列表
const VALID_DEFAULTS_KEYS: &[&str] = &[
    "max_retries",
    "findtime",
    "ban_time",
    "interval",
    "metrics_port",
    "metrics_bind_address",
    "metrics_username",
    "metrics_password",
    "permanent_db_path",
    "permanent_ban_enabled",
    "log_file",
    "log_level",
    "log_destination",
    "log_format",
];

/// `jails[name]:` 段允许的 key 列表
const VALID_JAIL_KEYS: &[&str] = &[
    "enabled",
    "log_files",
    "max_retries",
    "findtime",
    "ban_time",
    "regex",
    "regex_name",
    "regexes",
];

/// 顶层允许的 key 列表 (与 `defaults:` / `jails:` 同级)
const VALID_TOP_LEVEL_KEYS: &[&str] = &["defaults", "jails"];

/// 在 strict 模式下预先校验 YAML 中所有 key 都在白名单内。
///
/// 解析两次 YAML (一次为 `serde_yaml::Value` 检查 keys,一次为 `YamlConfig`
/// 反序列化) 故意保留:严格模式是"早失败"防御,普通解析错误晚于 key 检查。
///
/// v2.2.1 bug 修复:先前**只校验 defaults:/jails:[*] 内部 key**,不校验顶层 key,
/// 导致 `permanent_db_path` 误放顶层时被静默忽略(整个 `defaults:` 块之外的字段
/// 都被 parser 跳过)。修复:同时拒绝顶层未知 key。
///
/// # Errors
/// 任何未知 key 在顶层 / `defaults` / `jails[*]` 段命中,返回 `Err` 包含 key 名和
/// 合法 key 列表
fn validate_yaml_keys(content: &str) -> Result<()> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(content).context("Failed to parse YAML for key validation")?;

    // 顶层 key 校验:仅 `defaults` 和 `jails` 是合法顶层 key
    if let Some(map) = value.as_mapping() {
        for (key, _) in map {
            if let Some(key_str) = key.as_str() {
                if !VALID_TOP_LEVEL_KEYS.contains(&key_str) {
                    bail!(
                        "Unknown top-level key '{key_str}' (strict mode). Valid top-level keys: {VALID_TOP_LEVEL_KEYS:?}"
                    );
                }
            }
        }
    }

    if let Some(defaults) = value.get("defaults") {
        if let Some(map) = defaults.as_mapping() {
            for (key, _) in map {
                if let Some(key_str) = key.as_str() {
                    if !VALID_DEFAULTS_KEYS.contains(&key_str) {
                        bail!(
                            "Unknown key '{key_str}' in defaults section (strict mode). Valid keys: {VALID_DEFAULTS_KEYS:?}"
                        );
                    }
                }
            }
        }
    }

    if let Some(jails) = value.get("jails") {
        if let Some(map) = jails.as_mapping() {
            for (jail_name, jail_value) in map {
                if let Some(jail_map) = jail_value.as_mapping() {
                    for (key, _) in jail_map {
                        if let Some(key_str) = key.as_str() {
                            if !VALID_JAIL_KEYS.contains(&key_str) {
                                bail!(
                                    "Unknown key '{}' in jail '{}' section (strict mode). Valid keys: {:?}",
                                    key_str, jail_name.as_str().unwrap_or("?"), VALID_JAIL_KEYS
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// YAML 配置解析 (双缓冲: 失败时 cfg 保持不变)
// ============================================================================

/// 解析单个 YAML 配置文件到 `cfg`。
///
/// 失败模式:
/// - 读取 / 解析失败 → `Err`,`cfg` 不变
/// - 严格模式命中未知 key → `Err`,`cfg` 不变
/// - 路径不安全 → 跳过该文件,继续
/// - `log_destination` / `log_format` 非法值 → 整体回滚后 `Err`
///
/// # Arguments
/// - `config_path`: YAML 路径
/// - `cfg`: 目标配置 (可变,失败时回滚)
/// - `strict_mode`: 是否启用严格模式 key 校验
///
/// # Errors
/// - 文件读取失败
/// - 严格模式命中未知 key
/// - YAML 反序列化失败
/// - `log_destination` / `log_format` 非法值 (整体回滚后)
pub fn parse_config_file(config_path: &str, cfg: &mut Config, strict_mode: bool) -> Result<()> {
    let content = fs::read_to_string(config_path)
        .with_context(|| format!("Failed to read config file: {config_path}"))?;

    if strict_mode {
        validate_yaml_keys(&content)?;
    }

    let yaml_config: YamlConfig = serde_yaml::from_str(&content)
        .with_context(|| format!("Failed to parse YAML config: {config_path}"))?;

    // 先快照所有可回滚字段, 失败时一并恢复
    let saved_config_file = cfg.config_file.clone();
    let saved_config_dir = cfg.config_dir.clone();
    let saved_permanent_db_path = cfg.permanent_db_path.clone();
    let saved_permanent_ban_enabled = cfg.permanent_ban_enabled;
    let saved_log_file = cfg.log_file.clone();
    let saved_metrics_bind_address = cfg.metrics_bind_address.clone();
    let saved_metrics_username = cfg.metrics_username.clone();
    let saved_metrics_password = cfg.metrics_password.clone();

    if let Some(defaults) = &yaml_config.defaults {
        if let Some(v) = defaults.max_retries {
            cfg.default_max_retries = v;
        }
        if let Some(v) = defaults.findtime {
            cfg.default_findtime = v;
        }
        if let Some(v) = defaults.ban_time {
            cfg.default_ban_time = v;
        }
        if let Some(v) = defaults.interval {
            cfg.interval = v;
        }
        if let Some(v) = defaults.metrics_port {
            cfg.metrics_port = v;
        }
        if let Some(ref v) = defaults.metrics_bind_address {
            cfg.metrics_bind_address.clone_from(v);
        }
        if let Some(ref v) = defaults.metrics_username {
            cfg.metrics_username = Some(v.clone());
        }
        if let Some(ref v) = defaults.metrics_password {
            cfg.metrics_password = Some(v.clone());
        }
        if let Some(ref v) = defaults.permanent_db_path {
            cfg.permanent_db_path = Some(v.clone());
        }
        if let Some(v) = defaults.permanent_ban_enabled {
            cfg.permanent_ban_enabled = v;
        }
        if let Some(ref v) = defaults.log_file {
            cfg.log_file = Some(v.clone());
        }
        if let Some(v) = defaults.log_level {
            cfg.log_level = v;
        }
        if let Some(ref v) = defaults.log_destination {
            cfg.log_destination = match v.as_str() {
                "syslog" => 0,
                "file" => 1,
                "both" => 2,
                "journal" => 3,
                _ => {
                    // 非法值: 回滚所有已修改字段
                    cfg.config_file = saved_config_file;
                    cfg.config_dir = saved_config_dir;
                    cfg.permanent_db_path = saved_permanent_db_path;
                    cfg.permanent_ban_enabled = saved_permanent_ban_enabled;
                    cfg.log_file = saved_log_file;
                    cfg.metrics_bind_address = saved_metrics_bind_address;
                    cfg.metrics_username = saved_metrics_username;
                    cfg.metrics_password = saved_metrics_password;
                    bail!("Invalid log_destination value: {v}");
                }
            };
        }
        if let Some(ref v) = defaults.log_format {
            cfg.log_format = match v.as_str() {
                "plain" => 0,
                "json" => 1,
                _ => {
                    cfg.config_file = saved_config_file;
                    cfg.config_dir = saved_config_dir;
                    cfg.permanent_db_path = saved_permanent_db_path;
                    cfg.permanent_ban_enabled = saved_permanent_ban_enabled;
                    cfg.log_file = saved_log_file;
                    cfg.metrics_bind_address = saved_metrics_bind_address;
                    cfg.metrics_username = saved_metrics_username;
                    cfg.metrics_password = saved_metrics_password;
                    bail!("Invalid log_format value: {v}");
                }
            };
        }
    }

    if let Some(jails) = &yaml_config.jails {
        for (name, yaml_jail) in jails {
            if cfg.jails.len() >= MAX_JAILS {
                continue;
            }

            let mut jail = Jail::new(name.clone());
            jail.enabled = yaml_jail.enabled.unwrap_or(true);

            if let Some(ref log_files) = yaml_jail.log_files {
                for lf in log_files {
                    match validate_and_normalize_path(lf) {
                        Ok(normalized) => jail.log_files.push(normalized),
                        Err(_) => {},
                    }
                }
            }

            if let Some(v) = yaml_jail.max_retries {
                jail.max_retries = v;
                jail.max_retries_set = true;
            }
            if let Some(v) = yaml_jail.findtime {
                jail.findtime = v;
                jail.findtime_set = true;
            }
            if let Some(v) = yaml_jail.ban_time {
                jail.ban_time = v;
                jail.ban_time_set = true;
            }

            if let Some(ref pattern) = yaml_jail.regex {
                let name = yaml_jail.regex_name.as_deref().unwrap_or("custom");
                jail.regexes.push(RegexInfo {
                    name: name.to_string(),
                    pattern: pattern.clone(),
                    compiled: None,
                });
            }

            for (regex_name, yaml_regex_entry) in &yaml_jail.regexes {
                jail.regexes.push(RegexInfo {
                    name: regex_name.clone(),
                    pattern: yaml_regex_entry.pattern.clone(),
                    compiled: None,
                });
            }

            cfg.jails.push(jail);
        }
    }

    Ok(())
}

/// 从目录加载所有 `.yaml` / `.yml` 文件。按文件名升序,逐个调 [`parse_config_file`],
/// 失败的文件记 WARN 后继续,不影响其他文件。
///
/// # Arguments
/// - `config_dir`: 目录绝对路径
/// - `cfg`: 目标配置 (可变,逐个文件叠加修改)
/// - `strict_mode`: 是否启用严格模式
///
/// # Errors
/// - 目录不存在
/// - `fs::read_dir` 失败
pub fn load_config_directory(config_dir: &str, cfg: &mut Config, strict_mode: bool) -> Result<()> {
    let dir = Path::new(config_dir);
    if !dir.is_dir() {
        bail!("Config directory does not exist: {config_dir}");
    }

    let mut yaml_files: Vec<_> = fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .filter_map(|e| {
            let path = e.path();
            let ext = path.extension().and_then(|s| s.to_str());
            if ext == Some("yaml") || ext == Some("yml") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    yaml_files.sort();

    for path in &yaml_files {
        if let Some(path_str) = path.to_str() {
            let _ = parse_config_file(path_str, cfg, strict_mode);
        }
    }

    Ok(())
}

// ============================================================================
// 命令行参数解析
// ============================================================================

/// 解析 `argv` 得到 `(config_path, daemon_mode, strict_mode)`。
///
/// 支持的参数:
/// - `-c` / `--config` 后接路径
/// - `-C` / `--config-dir` 后接路径
/// - `-d` / `--daemon` 守护进程模式
/// - `-s` / `--strict` 严格模式 (默认)
/// - `-p` / `--no-strict` / `--permissive` 关闭严格
/// - `-h` / `--help` 打印帮助后返回 `Ok(None)`
/// - `--config=VALUE` / `--config-dir=VALUE` 等价于空格分隔
///
/// # Arguments
/// - `args`: 完整 `argv` (含程序名作为 `args[0]`)
///
/// # Returns
/// - `Ok(Some((path, daemon, strict)))`: 正常解析,默认 path = `/etc/firewall`
/// - `Ok(None)`: 用户请求 `--help`
/// - `Err`: 未知参数 / 缺少参数值
///
/// # Errors
/// - 未知参数
/// - `-c` / `-C` 后缺少路径
/// - `--config=` / `--config-dir=` 空值
pub fn parse_config_args(args: &[String]) -> Result<Option<(String, bool, bool)>> {
    let mut config_file: Option<String> = None;
    let mut config_dir: Option<String> = None;
    let mut daemon = false;
    let mut show_help = false;
    let mut strict_mode = true;

    let mut i = 1;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-c" | "--config" => {
                i += 1;
                if i >= args.len() {
                    bail!("Missing argument for -c/--config");
                }
                config_file = Some(args[i].clone());
            }
            "-C" | "--config-dir" => {
                i += 1;
                if i >= args.len() {
                    bail!("Missing argument for -C/--config-dir");
                }
                config_dir = Some(args[i].clone());
            }
            "-d" | "--daemon" => {
                daemon = true;
            }
            "--strict" | "-s" => {
                strict_mode = true;
            }
            "--no-strict" | "--permissive" | "-p" => {
                strict_mode = false;
            }
            "-h" | "--help" => {
                show_help = true;
            }
            _ => {
                // 支持 --config=VALUE / --config-dir=VALUE 形式
                if let Some(value) = arg.strip_prefix("--config=") {
                    if value.is_empty() {
                        bail!("Missing argument for --config=");
                    }
                    config_file = Some(value.to_string());
                } else if let Some(value) = arg.strip_prefix("--config-dir=") {
                    if value.is_empty() {
                        bail!("Missing argument for --config-dir=");
                    }
                    config_dir = Some(value.to_string());
                } else {
                    bail!("Unknown argument: {arg}");
                }
            }
        }
        i += 1;
    }

    if show_help {
        print_help();
        return Ok(None);
    }

    Ok(Some((
        config_file
            .or(config_dir)
            .unwrap_or_else(|| "/etc/firewall".to_string()),
        daemon,
        strict_mode,
    )))
}

/// 打印 CLI 帮助到 stdout。`--help` 时调。
fn print_help() {
    println!("Usage: firewall-daemon [OPTIONS]");
    println!();
    println!("Options:");
    println!("  -c, --config <FILE>       Use specific config file");
    println!("  -C, --config-dir <DIR>    Load all .yaml/.yml from directory");
    println!("  -d, --daemon              Run as daemon (background process)");
    println!("      --strict              Enable strict config validation (default)");
    println!("      --no-strict, -p       Disable strict config validation");
    println!("  -h, --help                Show this help message");
}

// ============================================================================
// 主配置解析入口
// ============================================================================

/// 一步完成:解析 argv → 加载 YAML → 套用智能默认 → 校验 → 返回 `Config`。
///
/// `parse_config_file` + `apply_smart_defaults_to_all` + `config_validate`
/// 的串联包装。`--help` 时返回 `Err` (实际是 `bail!("Help requested")`)。
///
/// # Arguments
/// - `args`: 完整 `argv`
///
/// # Returns
/// 完整 `Config`,已通过 [`jail::config_validate`] 校验
///
/// # Errors
/// - `--help` (不应再继续启动)
/// - YAML 解析失败
/// - 校验失败
pub fn parse_config(args: &[String]) -> Result<Config> {
    let mut cfg = Config::default();

    let parsed = parse_config_args(args)?;
    let Some((config_path, daemon, _strict)) = parsed else {
        bail!("Help requested, exiting");
    };

    cfg.daemon = daemon;

    let path = Path::new(&config_path);
    if path.is_file() {
        parse_config_file(&config_path, &mut cfg, true)?;
        cfg.config_file = Some(config_path);
    } else if path.is_dir() {
        load_config_directory(&config_path, &mut cfg, true)?;
        cfg.config_dir = Some(config_path);
    } else {
        bail!("Config path does not exist: {config_path}");
    }

    jail::apply_smart_defaults_to_all(&mut cfg);
    jail::config_validate(&cfg).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(cfg)
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn write_temp_yaml(content: &str) -> std::path::PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let tmpdir =
            std::env::temp_dir().join(format!("fw_config_test_{}_{}", std::process::id(), n));
        std::fs::create_dir_all(&tmpdir).unwrap();
        let path = tmpdir.join("test.yaml");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path
    }

    #[test]
    fn parse_minimal_config() {
        let yaml = r#"
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        parse_config_file(path.to_str().unwrap(), &mut cfg, true).unwrap();

        assert_eq!(cfg.default_max_retries, 5);
        assert_eq!(cfg.default_findtime, 600);
        assert_eq!(cfg.default_ban_time, 900);
        assert_eq!(cfg.jails.len(), 1);
        assert_eq!(cfg.jails[0].name, "sshd");
        assert!(cfg.jails[0].enabled);
        assert_eq!(cfg.jails[0].log_files.len(), 1);
        assert!(cfg.jails[0].log_files[0].contains("auth.log"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn parse_config_with_log_settings() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
  log_file: /var/log/firewall.log
  log_level: 3
  log_destination: both
  log_format: plain
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        parse_config_file(path.to_str().unwrap(), &mut cfg, true).unwrap();

        assert_eq!(cfg.log_file, Some("/var/log/firewall.log".to_string()));
        assert_eq!(cfg.log_level, 3);
        assert_eq!(cfg.log_destination, 2);
        assert_eq!(cfg.log_format, 0);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn parse_invalid_log_destination() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
  log_destination: invalid_value
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        let result = parse_config_file(path.to_str().unwrap(), &mut cfg, true);
        assert!(result.is_err());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn validate_path_rejects_path_traversal() {
        assert!(validate_and_normalize_path("/var/log/../../../etc/passwd").is_err());
        assert!(validate_and_normalize_path("/tmp/../../etc/shadow").is_err());
    }

    #[test]
    fn validate_path_rejects_url_encoding() {
        assert!(validate_and_normalize_path("/var/log/%2e%2e/etc/passwd").is_err());
        assert!(validate_and_normalize_path("/tmp/%2f..%2fetc/shadow").is_err());
    }

    #[test]
    fn validate_path_rejects_shell_metacharacters() {
        assert!(validate_and_normalize_path("/var/log/$(whoami).log").is_err());
        assert!(validate_and_normalize_path("/tmp/test;rm -rf.log").is_err());
    }

    #[test]
    fn validate_path_allows_normal_paths() {
        assert!(validate_and_normalize_path("/var/log/auth.log").is_ok());
        assert!(validate_and_normalize_path("/home/user/app.log").is_ok());
    }

    #[test]
    fn validate_path_rejects_embedded_nul() {
        // 嵌入 NUL 字节: Rust 的 Path 静默接受,但 OpenOptions::open 内部转 C 字符串
        // 时会 NUL 截断,导致打开与用户预期不同的文件。静默错误非漏洞,仍应拒绝。
        assert!(validate_and_normalize_path("/var/log/firewall.log\0").is_err());
        assert!(validate_and_normalize_path("/tmp/foo\0/etc/shadow").is_err());
    }

    #[test]
    fn strict_mode_rejects_unknown_defaults_key() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
  max_retrise: 5
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        let result = parse_config_file(path.to_str().unwrap(), &mut cfg, true);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("max_retrise"));
        assert!(err_msg.contains("strict mode"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn strict_mode_rejects_unknown_jail_key() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retrise: 5
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        let result = parse_config_file(path.to_str().unwrap(), &mut cfg, true);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("max_retrise"));
        assert!(err_msg.contains("strict mode"));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn parse_args_config_file() {
        let args = vec![
            "firewall-daemon".to_string(),
            "-c".to_string(),
            "/etc/firewall/sshd.yaml".to_string(),
        ];
        let result = parse_config_args(&args).unwrap();
        let (path, daemon, strict) = result.unwrap();
        assert_eq!(path, "/etc/firewall/sshd.yaml");
        assert!(!daemon);
        assert!(strict);
    }

    #[test]
    fn parse_args_daemon_flag() {
        let args = vec![
            "firewall-daemon".to_string(),
            "-c".to_string(),
            "/etc/firewall/sshd.yaml".to_string(),
            "--daemon".to_string(),
        ];
        let result = parse_config_args(&args).unwrap();
        let (_, daemon, _) = result.unwrap();
        assert!(daemon);
    }

    #[test]
    fn parse_args_daemon_short_flag() {
        let args = vec![
            "firewall-daemon".to_string(),
            "-c".to_string(),
            "/etc/firewall/sshd.yaml".to_string(),
            "-d".to_string(),
        ];
        let result = parse_config_args(&args).unwrap();
        let (_, daemon, _) = result.unwrap();
        assert!(daemon);
    }

    #[test]
    fn parse_args_no_strict_flag() {
        let args = vec![
            "firewall-daemon".to_string(),
            "-c".to_string(),
            "/etc/firewall/sshd.yaml".to_string(),
            "--no-strict".to_string(),
        ];
        let result = parse_config_args(&args).unwrap();
        let (_, _, strict) = result.unwrap();
        assert!(!strict);
    }

    #[test]
    fn parse_args_permissive_short_flag() {
        let args = vec![
            "firewall-daemon".to_string(),
            "-c".to_string(),
            "/etc/firewall/sshd.yaml".to_string(),
            "-p".to_string(),
        ];
        let result = parse_config_args(&args).unwrap();
        let (_, _, strict) = result.unwrap();
        assert!(!strict);
    }

    #[test]
    fn parse_args_help() {
        let args = vec!["firewall-daemon".to_string(), "--help".to_string()];
        let result = parse_config_args(&args).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn parse_args_unknown_flag() {
        let args = vec!["firewall-daemon".to_string(), "--unknown".to_string()];
        let result = parse_config_args(&args);
        assert!(result.is_err());
    }

    #[test]
    fn parse_config_with_nested_regexes() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    regexes:
      invalid_user:
        pattern: "Failed password for invalid user .* from <HOST>"
      root_login:
        pattern: "Failed password for root from <HOST>"
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        parse_config_file(path.to_str().unwrap(), &mut cfg, true).unwrap();

        assert_eq!(cfg.jails.len(), 1);
        assert_eq!(cfg.jails[0].regexes.len(), 2);
        let names: Vec<&str> = cfg.jails[0]
            .regexes
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert!(names.contains(&"invalid_user"));
        assert!(names.contains(&"root_login"));
        for regex in &cfg.jails[0].regexes {
            if regex.name == "invalid_user" {
                assert!(regex.pattern.contains("invalid user"));
            } else if regex.name == "root_login" {
                assert!(regex.pattern.contains("root from"));
            }
        }

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }

    #[test]
    fn parse_config_with_combined_regex_and_regexes() {
        let yaml = r#"
defaults:
  max_retries: 3
  findtime: 300
  ban_time: 600
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    regex: "Failed password for .* from <HOST>"
    regex_name: "default"
    regexes:
      ssh_failed:
        pattern: "Failed password for .* from <HOST>"
"#;
        let path = write_temp_yaml(yaml);
        let mut cfg = Config::default();
        parse_config_file(path.to_str().unwrap(), &mut cfg, true).unwrap();

        assert_eq!(cfg.jails.len(), 1);
        assert_eq!(cfg.jails[0].regexes.len(), 2);
        assert_eq!(cfg.jails[0].regexes[0].name, "default");
        assert_eq!(cfg.jails[0].regexes[1].name, "ssh_failed");

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(path.parent().unwrap());
    }
}
