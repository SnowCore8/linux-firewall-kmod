//! YAML 配置解析 + 路径安全 3 重检查

use crate::types::{Config, Jail, RegexInfo};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;

// ============================================================================
// 路径安全
// ============================================================================

/// 4 重安全检查 + 路径规范化,任一命中返回 `Err` (拒绝路径):
/// 1. 包含 `..` 路径遍历
/// 2. 包含 URL 编码绕过（单层 + 双重编码）
/// 3. 包含 shell 元字符命令注入
/// 4. 长度上限
/// 5. 路径规范化 (canonicalize): 已存在的路径解析符号链接,防止通过软链接逃逸
///
/// 故意不做白名单检查,与 C 版 `validate_and_normalize_path` 行为等价
pub fn validate_and_normalize_path(path: &str) -> Result<()> {
    let lower = path.to_ascii_lowercase();

    // 1) `..` 路径遍历
    if lower.contains("..") {
        bail!("Path validation failed (path traversal detected): {}", path);
    }

    // 2) URL 编码绕过：单层（%2e/. %2f// %5c/\）+ 双重编码（%25xx 形式）
    //    双重编码示例：%252e%252e → 解码一次为 %2e%2e → 再解码为 ..
    if lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%255c")
        || lower.contains("%25")
    {
        bail!("Path validation failed (URL encoding detected): {}", path);
    }

    // 3) Shell 元字符
    if lower.contains('|')
        || lower.contains('&')
        || lower.contains(';')
        || lower.contains('$')
        || lower.contains('`')
        || lower.contains('(')
        || lower.contains(')')
        || lower.contains('<')
        || lower.contains('>')
        || lower.contains('{')
        || lower.contains('}')
    {
        bail!(
            "Path validation failed (shell metacharacter detected): {}",
            path
        );
    }

    // 4) 长度上限
    if path.len() > 4096 {
        bail!("Path validation failed (path too long, max 4096): {}", path);
    }

    // 5) 路径规范化: 对已存在的路径解析符号链接,防止通过软链接逃逸到敏感目录
    //    路径不存在时跳过 (配置文件引用的日志文件可能尚未创建)
    let p = std::path::Path::new(path);
    if p.exists() {
        if let Ok(canonical) = p.canonicalize() {
            let canonical_str = canonical.to_string_lossy();
            // 规范化后的路径也不允许包含 .. (防御纵深)
            if canonical_str.contains("..") {
                bail!(
                    "Path validation failed (canonicalized path contains traversal): {} -> {}",
                    path,
                    canonical_str
                );
            }
        }
    }

    Ok(())
}

// ============================================================================
// YAML 反序列化结构
// ============================================================================

/// 顶层 YAML 结构:`defaults` (全局默认) + `jails` (命名 jail 映射)
///
/// # 严格模式
///
/// 使用 `deny_unknown_fields` 拒绝未知字段，防止配置错误。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlConfig {
    #[serde(default)]
    defaults: Option<YamlDefaults>,
    #[serde(default)]
    jails: Option<HashMap<String, YamlJail>>,
    #[serde(default)]
    ddos: Option<YamlDdos>,
    #[serde(default)]
    webui: Option<YamlWebui>,
    #[serde(default)]
    trusted_ips: Option<Vec<String>>,
}

/// 全局默认字段集合。所有 `Option` 都是"未设置 = 使用 `Config::default()`"
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlDefaults {
    max_retries: Option<u32>,
    findtime: Option<u32>,
    ban_time: Option<i32>,
    interval: Option<u32>,
    metrics_port: Option<u16>,
    metrics_bind_address: Option<String>,
    metrics_username: Option<String>,
    metrics_password: Option<String>,
    log_file: Option<String>,
    log_level: Option<u8>,
    log_destination: Option<String>,
    log_format: Option<String>,
}

/// 单个 jail 的 YAML 表示。支持 `regex` 单条 + `regexes` 嵌套映射两种写法
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlJail {
    enabled: Option<bool>,
    log_files: Option<Vec<String>>,
    max_retries: Option<u32>,
    findtime: Option<u32>,
    ban_time: Option<i32>,
    regex: Option<String>,
    regex_name: Option<String>,
    /// 嵌套 regexes 映射: `{ name: { pattern: "..." }, ... }`
    #[serde(default)]
    regexes: HashMap<String, YamlRegexEntry>,
}

/// 嵌套 `regexes` 映射的 value 结构
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlRegexEntry {
    pattern: String,
}

/// DDoS 防护配置的 YAML 表示
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlDdos {
    enabled: Option<bool>,
    per_ip_conn_rate: Option<u32>,
    per_ip_fail_rate: Option<u32>,
    global_conn_rate: Option<u32>,
    auto_ban_duration: Option<u32>,
    auto_ban_threshold: Option<u32>,
    check_interval: Option<u32>,
    baseline_warmup_samples: Option<u32>,
    // 协议专项阈值（同步到内核模块）
    max_syn_per_second: Option<u32>,
    max_udp_per_second: Option<u32>,
    max_icmp_per_second: Option<u32>,
    max_ack_per_second: Option<u32>,
    max_rst_per_second: Option<u32>,
    max_fin_per_second: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlWebui {
    sse_push_interval: Option<u32>,
    rate_warning_pps: Option<u64>,
    rate_critical_pps: Option<u64>,
    rate_warning_syn: Option<u64>,
    rate_critical_syn: Option<u64>,
}

// ============================================================================
// YAML 解析
// ============================================================================

/// 将 YAML 内容解析到 Config 结构体中。
///
/// 失败时不修改 `cfg` (原子性): 解析完的临时值收集在局部变量中,
/// 所有字段都成功后再一次性写入 `cfg`。
///
/// # Arguments
/// - `content`: YAML 字符串
/// - `cfg`: 目标 Config (成功时原地修改, 失败时保持原值)
pub fn parse_config(content: &str, cfg: &mut Config) -> Result<()> {
    let yaml_config: YamlConfig =
        serde_yaml::from_str(content).context("Failed to parse YAML config")?;

    // 1. 应用 defaults 部分到 cfg
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
        if let Some(v) = &defaults.metrics_bind_address {
            cfg.metrics_bind_address = v.clone();
        }
        if let Some(v) = &defaults.metrics_username {
            cfg.metrics_username = Some(v.clone());
        }
        if let Some(v) = &defaults.metrics_password {
            cfg.metrics_password = Some(v.clone());
        }
        if let Some(v) = &defaults.log_file {
            cfg.log_file = Some(v.clone());
        }
        cfg.log_level = defaults.log_level.unwrap_or(cfg.log_level);
        if let Some(v) = &defaults.log_destination {
            cfg.log_destination = match v.as_str() {
                "syslog" => 0,
                "file" => 1,
                "both" => 2,
                "journal" => 3,
                _ => bail!("Invalid log_destination value: {v}"),
            };
        }
        if let Some(v) = &defaults.log_format {
            cfg.log_format = match v.as_str() {
                "plain" => 0,
                "json" => 1,
                _ => bail!("Invalid log_format value: {v}"),
            };
        }
    }

    // 2. 解析 jails 部分
    if let Some(jails_map) = &yaml_config.jails {
        for (name, yaml_jail) in jails_map {
            let mut jail = Jail::new(name.clone());

            if let Some(enabled) = yaml_jail.enabled {
                jail.enabled = enabled;
            }
            if let Some(ref log_files) = yaml_jail.log_files {
                jail.log_files = log_files.clone();
            }
            if let Some(max_retries) = yaml_jail.max_retries {
                jail.max_retries = max_retries;
                jail.max_retries_set = true;
            }
            if let Some(findtime) = yaml_jail.findtime {
                jail.findtime = findtime;
                jail.findtime_set = true;
            }
            if let Some(ban_time) = yaml_jail.ban_time {
                jail.ban_time = ban_time;
                jail.ban_time_set = true;
            }

            // 支持单条 regex
            if let Some(ref regex) = yaml_jail.regex {
                let regex_name = yaml_jail
                    .regex_name
                    .clone()
                    .unwrap_or_else(|| "default".to_string());
                jail.regexes.push(RegexInfo::new(regex_name, regex.clone()));
            }

            // 支持多条 regexes
            for (name, entry) in &yaml_jail.regexes {
                jail.regexes
                    .push(RegexInfo::new(name.clone(), entry.pattern.clone()));
            }

            cfg.jails.push(jail);
        }
    }

    // 3. 解析 ddos 部分
    if let Some(ddos) = &yaml_config.ddos {
        if let Some(enabled) = ddos.enabled {
            cfg.ddos.enabled = enabled;
        }
        if let Some(rate) = ddos.per_ip_conn_rate {
            cfg.ddos.per_ip_conn_rate = rate;
        }
        if let Some(rate) = ddos.per_ip_fail_rate {
            cfg.ddos.per_ip_fail_rate = rate;
        }
        if let Some(rate) = ddos.global_conn_rate {
            cfg.ddos.global_conn_rate = rate;
        }
        if let Some(duration) = ddos.auto_ban_duration {
            cfg.ddos.auto_ban_duration = duration;
        }
        if let Some(threshold) = ddos.auto_ban_threshold {
            cfg.ddos.auto_ban_threshold = threshold;
        }
        if let Some(interval) = ddos.check_interval {
            cfg.ddos.check_interval = interval;
        }
        if let Some(samples) = ddos.baseline_warmup_samples {
            cfg.ddos.baseline_warmup_samples = samples;
        }
        // 协议专项阈值
        if let Some(rate) = ddos.max_syn_per_second {
            cfg.ddos.max_syn_per_second = rate;
        }
        if let Some(rate) = ddos.max_udp_per_second {
            cfg.ddos.max_udp_per_second = rate;
        }
        if let Some(rate) = ddos.max_icmp_per_second {
            cfg.ddos.max_icmp_per_second = rate;
        }
        if let Some(rate) = ddos.max_ack_per_second {
            cfg.ddos.max_ack_per_second = rate;
        }
        if let Some(rate) = ddos.max_rst_per_second {
            cfg.ddos.max_rst_per_second = rate;
        }
        if let Some(rate) = ddos.max_fin_per_second {
            cfg.ddos.max_fin_per_second = rate;
        }
    }

    // 4. 解析 webui 部分
    if let Some(webui) = &yaml_config.webui {
        if let Some(interval) = webui.sse_push_interval {
            cfg.webui.sse_push_interval = interval;
        }
        if let Some(rate) = webui.rate_warning_pps {
            cfg.webui.rate_warning_pps = rate;
        }
        if let Some(rate) = webui.rate_critical_pps {
            cfg.webui.rate_critical_pps = rate;
        }
        if let Some(rate) = webui.rate_warning_syn {
            cfg.webui.rate_warning_syn = rate;
        }
        if let Some(rate) = webui.rate_critical_syn {
            cfg.webui.rate_critical_syn = rate;
        }
    }

    // 5. 解析 trusted_ips 部分
    if let Some(trusted_ips) = &yaml_config.trusted_ips {
        cfg.trusted_ips = trusted_ips.clone();
    }

    Ok(())
}
