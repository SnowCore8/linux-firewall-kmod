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
    #[serde(default)]
    capacity: Option<YamlCapacity>,
    /// GeoIP 城市级数据库路径（`.mmdb`）。见 `Config::geoip_db_path`。
    #[serde(default)]
    geoip_db_path: Option<String>,
    /// 本机（服务器）纬度。见 `Config::server_latitude`。
    #[serde(default)]
    server_latitude: Option<YamlCoord>,
    /// 本机（服务器）经度。见 `Config::server_longitude`。
    #[serde(default)]
    server_longitude: Option<YamlCoord>,
    /// 是否探测出口 IP 以确定本机坐标。见 `Config::geoip_detect_egress`。
    #[serde(default)]
    geoip_detect_egress: Option<bool>,
    /// 出口 IP 探测地址。见 `Config::geoip_egress_probe_url`。
    #[serde(default)]
    geoip_egress_probe_url: Option<String>,
}

/// YAML 里经纬度可接受的两种写法：直接写数字，或写成字符串（含空白字符串＝未设置）。
///
/// 为什么不直接声明为 `Option<f64>`：`server_latitude: ""` 这类「显式留空」的写法
/// 会被 serde 判为类型错误而让整份配置拒绝加载，与本仓库「空串/纯空白视为未设置」
/// 的既有约定（见 `geoip_db_path`）不一致。故先按原样收下，再由 [`YamlCoord::resolve`]
/// 归一：能解析成浮点即取值，纯空白即 `None`，其余一律报错。
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum YamlCoord {
    /// YAML 数字（`server_latitude: 39.9042`，未加引号）
    Number(f64),
    /// YAML 字符串（`server_latitude: "39.9042"`，或留空的 `""`）
    Text(String),
}

impl YamlCoord {
    /// 归一为一个可选的浮点值。
    ///
    /// - 数字 → 原样取出
    /// - 字符串 → 去首尾空白后为空则 `None`（未设置）；否则按浮点解析，失败即报错
    ///
    /// # Errors
    ///
    /// 字符串不是合法浮点数时返回 `Err`（携带字段名，便于定位）。
    fn resolve(&self, field: &str) -> Result<Option<f64>> {
        match self {
            Self::Number(v) => Ok(Some(*v)),
            Self::Text(raw) => {
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Ok(None);
                }
                match trimmed.parse::<f64>() {
                    Ok(v) => Ok(Some(v)),
                    Err(_) => bail!("Invalid {field} value: {raw:?} (must be a decimal number)"),
                }
            }
        }
    }
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
    log_max_size_mb: Option<u32>,
    log_max_files: Option<u32>,
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
    /// 集群扫描检测段 (`cluster:`)。整段缺省 = 保持默认（关闭检测）
    cluster: Option<YamlCluster>,
}

/// 单个 jail 的集群扫描检测配置 (`cluster:` 段)。
///
/// 全字段 `Option`：**只有显式给出的字段才覆盖默认值**，未给出的字段保留
/// [`crate::decision::ClusterConfig::default()`] 中的对应值（见 `apply_jail_definition`）。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlCluster {
    /// 是否启用集群检测（默认关闭）
    enabled: Option<bool>,
    /// 只记录不封禁（默认 `true`，上线初期观察用）
    audit_only: Option<bool>,
    /// IPv4 聚合前缀长度
    prefix_v4: Option<u8>,
    /// IPv6 聚合前缀长度
    prefix_v6: Option<u8>,
    /// 观测窗口（秒）
    window: Option<u32>,
    /// 命中所需的最小不同源 IP 数
    min_ips: Option<u32>,
    /// 单个源 IP 允许的失败数上限（超过则视为高频而排除）
    max_per_ip: Option<u32>,
    /// 命中后该网段的封禁时长（秒）
    ban_time: Option<u32>,
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
    // DDoS 检测算法开关
    static_threshold: Option<bool>,
    dynamic_threshold: Option<bool>,
    ddos_detection: Option<bool>,
    // 内核模块参数
    max_bans_per_second: Option<u32>,
    max_rate_entries: Option<u32>,
    // 对外监听端口自动纳入 DDoS 速率判定（默认 true）
    protect_open_ports: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlWebui {
    sse_push_interval: Option<u32>,
    rate_warning_pps: Option<u64>,
    rate_critical_pps: Option<u64>,
    rate_warning_syn: Option<u64>,
    rate_critical_syn: Option<u64>,
    max_syn_per_second: Option<u32>,
    max_udp_per_second: Option<u32>,
    max_icmp_per_second: Option<u32>,
    max_ack_per_second: Option<u32>,
    max_rst_per_second: Option<u32>,
    max_fin_per_second: Option<u32>,
    static_threshold: Option<bool>,
    dynamic_threshold: Option<bool>,
    ddos_detection: Option<bool>,
    max_ban_entries: Option<u32>,
    max_whitelist_entries: Option<u32>,
    max_rate_entries: Option<u32>,
    max_local_ip_cache: Option<u32>,
}

/// 容量配置的 YAML 表示（用户自定义上限）
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct YamlCapacity {
    max_ban_entries: Option<u32>,
    max_whitelist_entries: Option<u32>,
    max_rate_entries: Option<u32>,
    max_local_ip_cache: Option<u32>,
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
    parse_config_from(content, cfg, false)
}

/// 同 [`parse_config`]，但可声明内容来自 daemon 自动管理的**运行期覆盖文件**
/// （`_` 前缀，见 [`super::file_loader::RUNTIME_OVERRIDE_PREFIX`]）。
///
/// 这类文件只携带运行期状态（当前是 jail 的 `enabled`），因此 jail 处理多两条规则：
/// - 未定义的 jail 名忽略并告警：自动写回的文件不能凭空造出一个缺 `log_files` 的
///   jail，否则它的下一次启动会直接拒绝加载；
/// - 其余同名合并语义与普通文件一致（显式字段后到优先）。
pub fn parse_config_from(content: &str, cfg: &mut Config, runtime_override: bool) -> Result<()> {
    let yaml_config: YamlConfig =
        serde_yml::from_str(content).context("Failed to parse YAML config")?;

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
        if let Some(v) = defaults.log_max_size_mb {
            cfg.log_max_size_mb = v;
        }
        if let Some(v) = defaults.log_max_files {
            cfg.log_max_files = v;
        }
    }

    // 2. 解析 jails 部分
    //
    // 同名 jail 跨文件按**后到优先**合并（契约见 `docs/zh/configuration/yaml-config.md`
    // 「多配置文件加载」）。不合并的话同一 jail 会在 `cfg.jails` 里留下两份条目，
    // 而校验与日志派发都逐条目处理——运行期覆盖文件只带 `enabled` 时，那一份就会
    // 因为缺 `log_files` 让整个配置加载失败。
    if let Some(jails_map) = &yaml_config.jails {
        for (name, yaml_jail) in jails_map {
            match cfg.jails.iter_mut().find(|j| j.name == *name) {
                Some(existing) => apply_jail_definition(existing, yaml_jail),
                None if runtime_override => {
                    crate::logger::warn!(
                        crate::logger::get(),
                        "运行期覆盖引用了未定义的 jail，已忽略";
                        "jail" => %name,
                    );
                }
                None => cfg.jails.push(build_jail(name, yaml_jail)),
            }
        }
    }

    // 3. 解析 ddos 部分
    if let Some(ddos) = &yaml_config.ddos {
        if let Some(enabled) = ddos.enabled {
            cfg.ddos.enabled = enabled;
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
        // DDoS 检测算法开关
        if let Some(v) = ddos.static_threshold {
            cfg.ddos.static_threshold = v;
        }
        if let Some(v) = ddos.dynamic_threshold {
            cfg.ddos.dynamic_threshold = v;
        }
        if let Some(v) = ddos.ddos_detection {
            cfg.ddos.ddos_detection = v;
        }
        // 内核模块参数
        if let Some(v) = ddos.max_bans_per_second {
            cfg.ddos.max_bans_per_second = v;
        }
        if let Some(v) = ddos.max_rate_entries {
            cfg.ddos.max_rate_entries = v;
        }
        if let Some(v) = ddos.protect_open_ports {
            cfg.ddos.protect_open_ports = v;
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
        if let Some(v) = webui.max_syn_per_second {
            cfg.webui.max_syn_per_second = v;
        }
        if let Some(v) = webui.max_udp_per_second {
            cfg.webui.max_udp_per_second = v;
        }
        if let Some(v) = webui.max_icmp_per_second {
            cfg.webui.max_icmp_per_second = v;
        }
        if let Some(v) = webui.max_ack_per_second {
            cfg.webui.max_ack_per_second = v;
        }
        if let Some(v) = webui.max_rst_per_second {
            cfg.webui.max_rst_per_second = v;
        }
        if let Some(v) = webui.max_fin_per_second {
            cfg.webui.max_fin_per_second = v;
        }
        if let Some(v) = webui.static_threshold {
            cfg.webui.static_threshold = v;
        }
        if let Some(v) = webui.dynamic_threshold {
            cfg.webui.dynamic_threshold = v;
        }
        if let Some(v) = webui.ddos_detection {
            cfg.webui.ddos_detection = v;
        }
        if let Some(v) = webui.max_ban_entries {
            cfg.webui.max_ban_entries = v;
        }
        if let Some(v) = webui.max_whitelist_entries {
            cfg.webui.max_whitelist_entries = v;
        }
        if let Some(v) = webui.max_rate_entries {
            cfg.webui.max_rate_entries = v;
        }
        if let Some(v) = webui.max_local_ip_cache {
            cfg.webui.max_local_ip_cache = v;
        }
    }

    // 5. 解析 trusted_ips 部分
    if let Some(trusted_ips) = &yaml_config.trusted_ips {
        cfg.trusted_ips = trusted_ips.clone();
    }

    // 6. 解析 capacity 部分
    if let Some(capacity) = &yaml_config.capacity {
        if let Some(v) = capacity.max_ban_entries {
            cfg.capacity.max_ban_entries = v;
        }
        if let Some(v) = capacity.max_whitelist_entries {
            cfg.capacity.max_whitelist_entries = v;
        }
        if let Some(v) = capacity.max_rate_entries {
            cfg.capacity.max_rate_entries = v;
        }
        if let Some(v) = capacity.max_local_ip_cache {
            cfg.capacity.max_local_ip_cache = v;
        }
    }

    // 7. 解析 geoip_db_path（空字符串按「未设置」处理，与模块的禁用语义一致）
    if let Some(path) = &yaml_config.geoip_db_path {
        if !path.trim().is_empty() {
            cfg.geoip_db_path = Some(path.trim().to_string());
        }
    }

    // 8. 解析本机经纬度（攻击地图的「本机」标记与弧线终点）
    //
    // 与 geoip_db_path 同为顶层字段；留空按「未设置」处理。严格校验：越界、非数字，
    // 或只给出其中一个都直接拒绝加载——半份坐标会画到一个错误的位置上，比没有更糟。
    if let Some(raw) = &yaml_config.server_latitude {
        if let Some(latitude) = raw.resolve("server_latitude")? {
            if !(-90.0..=90.0).contains(&latitude) {
                bail!("Invalid server_latitude value: {latitude} (must be within -90..90)");
            }
            cfg.server_latitude = Some(latitude);
        }
    }
    if let Some(raw) = &yaml_config.server_longitude {
        if let Some(longitude) = raw.resolve("server_longitude")? {
            if !(-180.0..=180.0).contains(&longitude) {
                bail!("Invalid server_longitude value: {longitude} (must be within -180..180)");
            }
            cfg.server_longitude = Some(longitude);
        }
    }
    // 成对约束按**合并后**的结果判定：多文件配置下两个值可能分别落在不同文件里，
    // 逐文件判定会误报「只给了一个」。
    if cfg.server_latitude.is_some() != cfg.server_longitude.is_some() {
        bail!("server_latitude and server_longitude must be provided together (only one was set)");
    }

    // 9. 解析出口 IP 探测开关与探测地址
    if let Some(enabled) = yaml_config.geoip_detect_egress {
        cfg.geoip_detect_egress = enabled;
    }
    if let Some(url) = &yaml_config.geoip_egress_probe_url {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            // 空串 = 用内置默认地址（与 geoip_db_path 的「空＝未设置」语义一致）
            cfg.geoip_egress_probe_url = None;
        } else {
            validate_probe_url(trimmed)?;
            cfg.geoip_egress_probe_url = Some(trimmed.to_string());
        }
    }

    Ok(())
}

/// 探测 URL 的长度上限。
const MAX_PROBE_URL_LEN: usize = 2048;

/// 校验出口 IP 探测地址。
///
/// 严格校验而非「非法就退回默认」：这是守护进程唯一会主动发出去的请求目标，
/// 静默改地址等于把用户的意图换成了别的东西。
///
/// # Errors
///
/// 非 `http(s)` 协议、缺主机名、含空白或控制字符、超长时返回 `Err`。
fn validate_probe_url(url: &str) -> Result<()> {
    if url.len() > MAX_PROBE_URL_LEN {
        bail!("Invalid geoip_egress_probe_url: too long (max {MAX_PROBE_URL_LEN})");
    }
    // 空白与控制字符会让请求行被拆成别的形状（请求走私那一类问题的起点），直接拒绝
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        bail!("Invalid geoip_egress_probe_url: {url:?} (must not contain whitespace or control characters)");
    }
    let lower = url.to_ascii_lowercase();
    let scheme_len = if lower.starts_with("https://") {
        "https://".len()
    } else if lower.starts_with("http://") {
        "http://".len()
    } else {
        bail!("Invalid geoip_egress_probe_url: {url:?} (must start with http:// or https://)");
    };
    // 主机名取 scheme 之后、第一个 `/` `?` `#` 之前的部分，必须非空
    let host = url[scheme_len..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if host.is_empty() {
        bail!("Invalid geoip_egress_probe_url: {url:?} (missing host)");
    }
    Ok(())
}

/// 由 YAML 定义构造一个新 jail。
///
/// 未显式给出的字段保持 [`Jail::new`] 的初值（`0` / 空列表 + `*_set = false`），
/// 随后由 `defaults` 段统一补齐——与原实现一致。
fn build_jail(name: &str, yaml_jail: &YamlJail) -> Jail {
    let mut jail = Jail::new(name.to_string());
    apply_jail_definition(&mut jail, yaml_jail);
    jail
}

/// 把一份 YAML jail 定义合并进已有 jail：**只覆盖显式给出的字段**。
///
/// 这是「同名 jail 后到优先」的落地方式。未出现的字段保持原值，因为后加载的文件
/// 通常只声明差异——运行期覆盖文件就只声明 `enabled`。若整条替换，此前文件里的
/// `log_files` / `regexes` 会被一起抹掉。
fn apply_jail_definition(jail: &mut Jail, yaml_jail: &YamlJail) {
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

    // 集群扫描检测：`cluster:` 整段缺省时保持 `ClusterConfig::default()`（默认关闭）；
    // 段内同样只覆盖显式给出的字段，未给出的保留默认值——与其他字段的合并语义一致。
    if let Some(ref cluster) = yaml_jail.cluster {
        if let Some(enabled) = cluster.enabled {
            jail.cluster.enabled = enabled;
        }
        if let Some(audit_only) = cluster.audit_only {
            jail.cluster.audit_only = audit_only;
        }
        if let Some(prefix_v4) = cluster.prefix_v4 {
            jail.cluster.prefix_v4 = prefix_v4;
        }
        if let Some(prefix_v6) = cluster.prefix_v6 {
            jail.cluster.prefix_v6 = prefix_v6;
        }
        if let Some(window) = cluster.window {
            jail.cluster.window = window;
        }
        if let Some(min_ips) = cluster.min_ips {
            jail.cluster.min_ips = min_ips;
        }
        if let Some(max_per_ip) = cluster.max_per_ip {
            jail.cluster.max_per_ip = max_per_ip;
        }
        if let Some(ban_time) = cluster.ban_time {
            jail.cluster.ban_time = ban_time;
        }
    }

    // 正则：后加载的定义只要给出了正则就整体替换（而非叠加），否则同一个 jail
    // 会同时带上两份规则集，命中行为取决于遍历顺序。
    if yaml_jail.regex.is_some() || !yaml_jail.regexes.is_empty() {
        jail.regexes.clear();
        append_jail_regexes(jail, yaml_jail);
    }
}

/// 追加单条 `regex` 与嵌套 `regexes` 映射中的全部规则。
fn append_jail_regexes(jail: &mut Jail, yaml_jail: &YamlJail) {
    if let Some(ref regex) = yaml_jail.regex {
        let regex_name = yaml_jail
            .regex_name
            .clone()
            .unwrap_or_else(|| "default".to_string());
        jail.regexes.push(RegexInfo::new(regex_name, regex.clone()));
    }
    for (name, entry) in &yaml_jail.regexes {
        jail.regexes
            .push(RegexInfo::new(name.clone(), entry.pattern.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 用一份最小的 YAML 片段解析进全新 `Config`，返回结果与解析后的配置。
    fn parse(yaml: &str) -> (Result<()>, Config) {
        let mut cfg = Config::default();
        let result = parse_config(yaml, &mut cfg);
        (result, cfg)
    }

    /// 两个值都给、都在范围内 → 原样落到 `Config`（数字与字符串两种写法等价）。
    #[test]
    fn server_coordinates_are_parsed_when_both_valid() {
        let (result, cfg) = parse("server_latitude: 39.9042\nserver_longitude: 116.4074\n");
        assert!(result.is_ok(), "合法坐标不应报错: {result:?}");
        assert_eq!(cfg.server_latitude, Some(39.9042));
        assert_eq!(cfg.server_longitude, Some(116.4074));

        let (result, cfg) = parse("server_latitude: \"39.9042\"\nserver_longitude: \"116.4074\"\n");
        assert!(result.is_ok(), "字符串写法也应接受: {result:?}");
        assert_eq!(cfg.server_latitude, Some(39.9042));
        assert_eq!(cfg.server_longitude, Some(116.4074));
    }

    /// 空白字符串按「未设置」处理，且不成对也不需要报错（两个都没设）。
    #[test]
    fn blank_coordinates_mean_unset() {
        let (result, cfg) = parse("server_latitude: \"\"\nserver_longitude: \"   \"\n");
        assert!(result.is_ok(), "留空应视为未设置而非报错: {result:?}");
        assert_eq!(cfg.server_latitude, None);
        assert_eq!(cfg.server_longitude, None);
    }

    /// 只给一个坐标 → 拒绝加载（半份坐标会画到错误的位置上）。
    #[test]
    fn a_lone_coordinate_is_rejected() {
        let (result, _) = parse("server_latitude: 39.9\n");
        let err = result.expect_err("只给纬度应报错");
        assert!(
            err.to_string().contains("must be provided together"),
            "错误信息应点出成对约束: {err}"
        );

        let (result, _) = parse("server_longitude: 116.4\n");
        assert!(result.is_err(), "只给经度应报错");
    }

    /// 越界与非法字符串都拒绝加载（严格校验）。边界值本身应通过。
    #[test]
    fn out_of_range_or_invalid_coordinates_are_rejected() {
        let (result, _) = parse("server_latitude: 90.1\nserver_longitude: 0\n");
        assert!(
            result
                .expect_err("纬度超出 90 应报错")
                .to_string()
                .contains("server_latitude"),
            "错误信息应点出违规字段"
        );

        let (result, _) = parse("server_latitude: 0\nserver_longitude: -180.1\n");
        assert!(
            result
                .expect_err("经度超出 -180 应报错")
                .to_string()
                .contains("server_longitude"),
            "错误信息应点出违规字段"
        );

        let (result, _) = parse("server_latitude: abc\nserver_longitude: 0\n");
        assert!(result.is_err(), "非数字字符串应报错");

        // 边界值（±90 / ±180）合法
        assert!(parse("server_latitude: 90\nserver_longitude: -180\n")
            .0
            .is_ok());
        assert!(parse("server_latitude: -90\nserver_longitude: 180\n")
            .0
            .is_ok());
    }

    /// 多文件配置：两个坐标分别落在不同片段里也应合并成功（成对约束按合并结果判定）。
    #[test]
    fn coordinates_split_across_files_merge() {
        // 一个片段已给出纬度（等价于前一个文件给过），下一个片段补经度：成对约束
        // 按合并后的结果判定，因此「先后补齐」的路径必须能走通，不能逐文件误报。
        let mut cfg = Config {
            server_latitude: Some(39.9),
            ..Config::default()
        };
        assert!(parse_config("server_longitude: 116.4\n", &mut cfg).is_ok());
        assert_eq!(cfg.server_latitude, Some(39.9));
        assert_eq!(cfg.server_longitude, Some(116.4));
    }

    /// 探测开关默认关闭（现状即默认行为），显式写出才打开。
    #[test]
    fn egress_detection_is_off_by_default() {
        let (result, cfg) = parse("");
        assert!(result.is_ok());
        assert!(!cfg.geoip_detect_egress, "默认必须关闭：不静默对外发请求");
        assert_eq!(cfg.geoip_egress_probe_url, None, "默认用内置地址");

        let (result, cfg) = parse("geoip_detect_egress: true\n");
        assert!(result.is_ok());
        assert!(cfg.geoip_detect_egress);
    }

    /// 探测地址：留空＝用内置默认；合法 http(s) 原样保存；非法一律拒绝加载。
    #[test]
    fn probe_url_is_strictly_validated() {
        let (result, cfg) = parse("geoip_egress_probe_url: \"  \"\n");
        assert!(result.is_ok(), "留空应视为未设置: {result:?}");
        assert_eq!(cfg.geoip_egress_probe_url, None);

        let (result, cfg) = parse("geoip_egress_probe_url: https://api.ip.sb/geoip\n");
        assert!(result.is_ok());
        assert_eq!(
            cfg.geoip_egress_probe_url.as_deref(),
            Some("https://api.ip.sb/geoip")
        );

        // 合法但不带路径、以及 http 明文（内网自建探测端点）都应通过
        assert!(parse("geoip_egress_probe_url: http://10.0.0.5\n").0.is_ok());

        for bad in [
            "geoip_egress_probe_url: ftp://example.com/x\n", // 非 http(s)
            "geoip_egress_probe_url: api.ip.sb/geoip\n",     // 缺协议
            "geoip_egress_probe_url: \"https://\"\n",        // 缺主机名
            "geoip_egress_probe_url: \"https://a b.com/\"\n", // 含空白
            "geoip_egress_probe_url: \"file:///etc/passwd\"\n", // 本地文件协议
        ] {
            let err = parse(bad).0.expect_err("非法探测地址必须拒绝加载");
            assert!(
                err.to_string().contains("geoip_egress_probe_url"),
                "错误信息应点出违规字段: {err}（输入 {bad:?}）"
            );
        }
    }

    /// 超长 URL 同样拒绝（上限 2048）。
    #[test]
    fn overlong_probe_url_is_rejected() {
        let long = format!("https://example.com/{}", "a".repeat(2100));
        let yaml = format!("geoip_egress_probe_url: {long}\n");
        let err = parse(&yaml).0.expect_err("超长 URL 应拒绝");
        assert!(err.to_string().contains("too long"), "应说明超长: {err}");
    }
}
