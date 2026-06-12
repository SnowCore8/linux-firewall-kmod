//! Jail 管理: 服务名智能匹配 + 智能默认参数推断 + `ReDoS` 防护正则编译 + 配置克隆
//!
//! # 核心职责
//!
//! - **服务名智能匹配**:根据 jail 名称自动识别 SSH / WEB / FTP / MAIL / FRP / DB
//!   服务类型,并套用该类型的合理默认参数
//! - **智能默认参数推断**:仅当用户未显式配置时才覆盖,避免误覆盖
//! - **`ReDoS` 防护**:编译前校验正则模式,拒绝嵌套量词 / 占有量词 / 量化交替组
//!   等易触发指数回溯的写法
//! - **配置克隆**:SIGHUP 热重载时的双缓冲支持(失败时旧配置不受影响)
//!
//! # 默认参数表
//!
//! | 服务 | max_retries | findtime | ban_time |
//! |------|-------------|----------|----------|
//! | SSH  | 5           | 600      | 900      |
//! | WEB  | 10          | 300      | 1800     |
//! | FTP  | 5           | 600      | 1800     |
//! | MAIL | 5           | 300      | 1800     |
//! | FRP  | 10          | 300      | 1800     |
//! | DB   | 3           | 300      | 3600     |
//! | 未知 | `default_*` | 同左     | 同左     |

use crate::types::{Config, Jail, RegexInfo, MAX_JAILS};
use crate::{log_debug, log_err, log_info, log_warn};

// ============================================================================
// 服务名称模式
// ============================================================================

/// 匹配 `ssh` / `sshd` 及以 `ssh-` / `-ssh` 连接的变体
const SSH_PATTERNS: &[&str] = &["ssh", "sshd"];
/// 匹配 `nginx` / `apache` / `http` 及变体
const WEB_PATTERNS: &[&str] = &["nginx", "apache", "http"];
/// 匹配 `ftp` / `vsftpd` / `proftpd` 及变体
const FTP_PATTERNS: &[&str] = &["ftp", "vsftpd", "proftpd"];
/// 匹配 `postfix` / `dovecot` / `mail` 及变体
const MAIL_PATTERNS: &[&str] = &["postfix", "dovecot", "mail"];
/// 匹配 `frp` (Fast Reverse Proxy) 及变体
const FRP_PATTERNS: &[&str] = &["frp"];
/// 匹配 `mysql` / `mariadb` / `postgres` 及变体
const DB_PATTERNS: &[&str] = &["mysql", "mariadb", "postgres"];

// ============================================================================
// 服务名称匹配
// ============================================================================

/// 判断 `name` 是否命中 `patterns` 中的任一服务类型。
///
/// 匹配规则(按顺序尝试):
/// 1. 精确匹配 (`sshd == sshd`)
/// 2. 前缀 + 连接符 (`sshd-custom` 以 `sshd-` 开头)
/// 3. 后缀 + 连接符 (`custom-sshd` 以 `-sshd` 结尾)
/// 4. 包含 + 两端连接符 (`my-sshd-service` 中 `-sshd-` 是独立词)
///
/// 故意避免匹配 `sshdlike` (无连接符),减少误命中。
///
/// # Arguments
/// - `name`: jail 名称
/// - `patterns`: 服务关键字模式列表
///
/// # Returns
/// 任意一个 pattern 命中即返回 `true`
fn is_service_name_match(name: &str, patterns: &[&str]) -> bool {
    for &pattern in patterns {
        let name_len = name.len();
        let pattern_len = pattern.len();

        if name == pattern {
            return true;
        }

        if name_len > pattern_len
            && name.starts_with(pattern)
            && name.as_bytes()[pattern_len] == b'-'
        {
            return true;
        }

        if name_len > pattern_len
            && name.ends_with(pattern)
            && name.as_bytes()[name_len - pattern_len - 1] == b'-'
        {
            return true;
        }

        if let Some(pos) = name.find(pattern) {
            let at_start = pos == 0;
            let at_end = pos + pattern_len == name_len;
            let char_before_ok = at_start || name.as_bytes()[pos - 1] == b'-';
            let char_after_ok = at_end || name.as_bytes()[pos + pattern_len] == b'-';

            if char_before_ok && char_after_ok {
                return true;
            }
        }
    }
    false
}

// ============================================================================
// 智能默认参数
// ============================================================================

/// 套用 `service_type` 的默认参数。仅当对应 `*_set == false` 时覆盖,
/// 用户显式配置始终优先。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
/// - `name`: jail 名称 (日志用)
/// - `service_type`: 服务类型字符串,日志用
/// - `retries` / `findtime` / `ban_time`: 智能默认值
fn apply_service_defaults(
    jail: &mut Jail,
    name: &str,
    service_type: &str,
    retries: u32,
    findtime: u32,
    ban_time: u32,
) {
    if !jail.max_retries_set {
        jail.max_retries = retries;
    }
    if !jail.findtime_set {
        jail.findtime = findtime;
    }
    if !jail.ban_time_set {
        jail.ban_time = ban_time;
    }

    log_info!(
        "Jail '{}': applying {} smart defaults (retries={}, findtime={}, ban={})",
        name,
        service_type,
        jail.max_retries,
        jail.findtime,
        jail.ban_time
    );
}

/// 对单个 jail 套用智能默认。匹配优先级: SSH > WEB > FTP > MAIL > FRP > DB > 全局默认。
///
/// 默认值表见模块级文档。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
/// - `default_max_retries` / `default_findtime` / `default_ban_time`: 全局默认
///   (用户未匹配任何服务类型时使用)
fn apply_smart_defaults_single(
    jail: &mut Jail,
    default_max_retries: u32,
    default_findtime: u32,
    default_ban_time: u32,
) {
    let name = jail.name.clone();

    if is_service_name_match(&name, SSH_PATTERNS) {
        apply_service_defaults(jail, &name, "SSH", 5, 600, 900);
    } else if is_service_name_match(&name, WEB_PATTERNS) {
        apply_service_defaults(jail, &name, "WEB", 10, 300, 1800);
    } else if is_service_name_match(&name, FTP_PATTERNS) {
        apply_service_defaults(jail, &name, "FTP", 5, 600, 1800);
    } else if is_service_name_match(&name, MAIL_PATTERNS) {
        apply_service_defaults(jail, &name, "MAIL", 5, 300, 1800);
    } else if is_service_name_match(&name, FRP_PATTERNS) {
        apply_service_defaults(jail, &name, "FRP", 10, 300, 1800);
    } else if is_service_name_match(&name, DB_PATTERNS) {
        apply_service_defaults(jail, &name, "DB", 3, 300, 3600);
    } else {
        if !jail.max_retries_set {
            jail.max_retries = default_max_retries;
        }
        if !jail.findtime_set {
            jail.findtime = default_findtime;
        }
        if !jail.ban_time_set {
            jail.ban_time = default_ban_time;
        }
        log_info!(
            "Jail '{}': using global defaults (retries={}, findtime={}, ban={})",
            name,
            jail.max_retries,
            jail.findtime,
            jail.ban_time
        );
    }
}

/// 对整个 `Config` 的所有 jail 套用智能默认。`main()` 在 `parse_config_file`
/// 之后、`config_validate` 之前调用。
///
/// # Arguments
/// - `target_cfg`: 待处理的配置 (可变引用)
pub fn apply_smart_defaults_to_all(target_cfg: &mut Config) {
    let default_max_retries = target_cfg.default_max_retries;
    let default_findtime = target_cfg.default_findtime;
    let default_ban_time = target_cfg.default_ban_time;
    for jail in &mut target_cfg.jails {
        apply_smart_defaults_single(
            jail,
            default_max_retries,
            default_findtime,
            default_ban_time,
        );
    }
}

// ============================================================================
// Jail 初始化
// ============================================================================

/// 把 jail 字段全部重置为初始状态 (清空 `failed_hash` / `partial_line_buffer`
/// / `regexes` / `log_files`,数值字段归零,`enabled = true`)。
///
/// SIGHUP 热重载复用某个 jail 名称时调用此函数先清旧状态。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
/// - `_target_cfg`: 保留参数,与 C 版 API 对齐
pub fn init_jail_defaults(jail: &mut Jail, _target_cfg: &Config) {
    jail.enabled = true;
    jail.log_files.clear();
    jail.regexes.clear();
    jail.max_retries = 0;
    jail.findtime = 0;
    jail.ban_time = 0;
    jail.max_retries_set = false;
    jail.findtime_set = false;
    jail.ban_time_set = false;
    jail.failed_hash.write().clear();
    jail.partial_line_buffer.write().clear();
}

// ============================================================================
// 正则表达式管理
// ============================================================================

/// 释放 jail 内所有正则的编译对象 (保留模式串)。`destroy_jail` / 配置重载前调。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
pub fn free_jail_regex(jail: &mut Jail) {
    for regex_info in &mut jail.regexes {
        regex_info.compiled = None;
    }
}

/// 完全清空 jail 的正则列表 (模式串 + 编译对象)。`destroy_jail` 时调。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
pub fn free_jail_regex_full(jail: &mut Jail) {
    jail.regexes.clear();
}

/// `ReDoS` 防护: 拒绝易触发指数/多项式级回溯的模式。
///
/// 检查项:
/// 1. 嵌套量词 `(a+)+` / `(a*)*`
/// 2. 占有量词 `a++` / `a*+` (Rust regex 实际不支持, 仍校验防御性)
/// 3. 量化的交替组 `(a|aa)+`
/// 4. 模式 > 1024 字节 / 分支数 > 50
///
/// # Arguments
/// - `jail`: 目标 jail (用于错误信息)
/// - `pattern`: 待校验的正则模式串
///
/// # Returns
/// - `Ok(())`: 安全
/// - `Err(String)`: 拒绝原因
fn validate_regex_safety(jail: &Jail, pattern: &str) -> Result<(), String> {
    let pattern_len = pattern.len();

    if pattern_len > 1024 {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': pattern too long ({} bytes, max 1024)",
            jail.name, pattern_len
        ));
    }

    for (i, c) in pattern.chars().enumerate() {
        if c == ')' {
            let next = pattern.chars().nth(i + 1);
            if next == Some('+') || next == Some('*') {
                return Err(format!(
                    "Rejected unsafe regex for jail '{}': nested quantifiers detected at offset {}",
                    jail.name, i
                ));
            }
        }
    }

    if pattern.contains("++") || pattern.contains("*+") {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': possessive quantifiers detected",
            jail.name
        ));
    }

    for (i, c) in pattern.chars().enumerate() {
        if c == '(' {
            let next = pattern.chars().nth(i + 1);
            if next == Some('+') || next == Some('*') || next == Some('{') || next == Some('?') {
                return Err(format!(
                    "Rejected unsafe regex for jail '{}': invalid quantifier after '(?' at offset {}",
                    jail.name, i
                ));
            }
        }
    }

    let pipe_count = pattern.chars().filter(|&c| c == '|').count();
    if pipe_count > 50 {
        return Err(format!(
            "Rejected unsafe regex for jail '{}': too many alternations ({} , max 50)",
            jail.name, pipe_count
        ));
    }

    let mut paren_depth: usize = 0;
    let mut has_alternation_in_group = false;
    for (i, c) in pattern.chars().enumerate() {
        match c {
            '(' => {
                let next = pattern.chars().nth(i + 1);
                if next != Some('?') {
                    paren_depth += 1;
                    has_alternation_in_group = false;
                }
            }
            ')' => {
                if has_alternation_in_group {
                    let next = pattern.chars().nth(i + 1);
                    if next == Some('+')
                        || next == Some('*')
                        || next == Some('{')
                        || next == Some('?')
                    {
                        return Err(format!(
                            "Rejected unsafe regex for jail '{}': alternation inside quantified group at offset {}",
                            jail.name, i
                        ));
                    }
                }
                paren_depth = paren_depth.saturating_sub(1);
            }
            '|' if paren_depth > 0 => {
                has_alternation_in_group = true;
            }
            _ => {}
        }
    }

    Ok(())
}

/// 编译 jail 内所有正则。空时自动套用内置默认 sshd 失败模式。
///
/// 失败模式 (`ReDoS 拒绝` / `regex 编译错误`) 不中断其他正则的尝试,
/// 全部失败时返回 `Err`,至少 1 条成功时返回 `Ok`。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
///
/// # Returns
/// - `Ok(())`: 至少 1 条编译成功
/// - `Err(String)`: 所有正则都失败
///
/// # Errors
/// `validate_regex_safety` 拒绝(嵌套量词等)或 `regex::Regex::new` 解析失败的模式
/// 累积到最后,只有当全部正则都失败时才返回
pub fn compile_jail_regex(jail: &mut Jail) -> Result<(), String> {
    free_jail_regex(jail);

    if jail.regexes.is_empty() {
        let default_pattern = r"Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})";
        jail.regexes.push(RegexInfo {
            name: "default".to_string(),
            pattern: default_pattern.to_string(),
            compiled: None,
        });
    }

    let mut compiled_count = 0;
    for i in 0..jail.regexes.len() {
        let pattern = jail.regexes[i].pattern.clone();
        if pattern.is_empty() {
            continue;
        }

        if let Err(e) = validate_regex_safety(jail, &pattern) {
            log_err!("{}", e);
            continue;
        }

        match regex::Regex::new(&pattern) {
            Ok(re) => {
                jail.regexes[i].compiled = Some(re);
                compiled_count += 1;
                log_info!(
                    "Compiled regex '{}' for jail '{}': {}",
                    jail.regexes[i].name,
                    jail.name,
                    pattern
                );
            }
            Err(e) => {
                log_err!("Failed to compile regex for jail '{}': {}", jail.name, e);
            }
        }
    }

    log_info!(
        "Compiled {} regex pattern(s) for jail '{}'",
        compiled_count,
        jail.name
    );

    if compiled_count > 0 {
        Ok(())
    } else {
        Err(format!(
            "No regex patterns compiled for jail '{}'",
            jail.name
        ))
    }
}

// ============================================================================
// Jail 创建/销毁
// ============================================================================

/// 查找现有 jail,或创建新 jail。达到 [`MAX_JAILS`] 上限时不创建。
///
/// # Arguments
/// - `cfg`: 全局配置 (可变引用)
/// - `name`: 目标 jail 名称
///
/// # Returns
/// 找到或新建的 `&mut Jail`;达到上限时返回 `None`。
///
/// # Panics
/// `cfg.jails.last_mut().unwrap()` 仅在 `push` 后立即调用时 panic,
/// 而本函数 push 之后立刻 unwrap,实际不可能
pub fn find_or_create_jail<'a>(cfg: &'a mut Config, name: &str) -> Option<&'a mut Jail> {
    let existing_idx = cfg.jails.iter().position(|j| j.name == name);
    if let Some(idx) = existing_idx {
        return Some(&mut cfg.jails[idx]);
    }

    if cfg.jails.len() >= MAX_JAILS {
        log_warn!(
            "Max jails reached ({}), cannot create jail '{}'",
            MAX_JAILS,
            name
        );
        return None;
    }

    let jail = Jail::new(name.to_string());
    cfg.jails.push(jail);
    let jail = cfg.jails.last_mut().unwrap();

    log_info!("Created new jail: {}", name);
    Some(jail)
}

/// 销毁单个 jail:清空所有字段,释放正则编译对象。
///
/// # Arguments
/// - `jail`: 目标 jail (可变引用)
pub fn destroy_jail(jail: &mut Jail) {
    jail.log_files.clear();
    free_jail_regex_full(jail);
    jail.failed_hash.write().clear();
    jail.partial_line_buffer.write().clear();

    log_info!("Destroyed jail: {}", jail.name);
}

/// 销毁 `Config` 中所有 jail 并清空列表。`cleanup` 阶段使用。
///
/// # Arguments
/// - `cfg`: 全局配置 (可变引用)
pub fn cleanup_all_jails(cfg: &mut Config) {
    for jail in &mut cfg.jails {
        destroy_jail(jail);
    }
    cfg.jails.clear();
    log_info!("All jails resources cleaned up");
}

// ============================================================================
// 配置克隆 (双缓冲热重载)
// ============================================================================

/// 克隆单 jail (深拷贝,不含运行时状态,正则编译对象丢弃需重新编译)。
///
/// 不会复制 `failed_hash` / `partial_line_buffer` (运行时态);
/// 不会复制 `compiled` (克隆后需重新编译)。
///
/// # Arguments
/// - `dst`: 目标 jail (可变引用)
/// - `src`: 源 jail
///
/// # Returns
/// 当前总是 `Ok(())`,保留 `Result` 是为未来扩展(校验/部分克隆策略)。
///
/// # Errors
/// 当前实现不会 `Err`,保留签名以备未来加入字段校验
pub fn clone_jail(dst: &mut Jail, src: &Jail) -> Result<(), String> {
    dst.name.clone_from(&src.name);
    dst.enabled = src.enabled;
    dst.max_retries = src.max_retries;
    dst.findtime = src.findtime;
    dst.ban_time = src.ban_time;
    dst.max_retries_set = src.max_retries_set;
    dst.findtime_set = src.findtime_set;
    dst.ban_time_set = src.ban_time_set;

    dst.log_files.clone_from(&src.log_files);

    dst.regexes = src
        .regexes
        .iter()
        .map(|r| RegexInfo {
            name: r.name.clone(),
            pattern: r.pattern.clone(),
            compiled: None,
        })
        .collect();

    dst.failed_hash.write().clear();
    dst.partial_line_buffer.write().clear();

    Ok(())
}

/// 深克隆整个 `Config`。SIGHUP 热重载第一阶段使用,失败时旧配置不受影响。
///
/// 不克隆 `jails[*].failed_hash` / `partial_line_buffer` (运行时态),
/// 调用方需在应用新配置前调 [`migrate_failed_entries`] 把旧条目迁移过来。
///
/// # Arguments
/// - `src`: 源配置
///
/// # Returns
/// 与 `src` 等值的全新 `Config`(无运行时态)
#[must_use]
pub fn config_clone(src: &Config) -> Config {
    // 一次性初始化,避免 `Config::default()` + 17 次字段赋值的低效模式
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
        permanent_db_path: src.permanent_db_path.clone(),
        permanent_ban_enabled: src.permanent_ban_enabled,
        log_file: src.log_file.clone(),
        log_level: src.log_level,
        log_destination: src.log_destination,
        log_format: src.log_format,
        ..Config::default()
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
            "Config validation failed: invalid jail_count={} (must be 1..{})",
            cfg.jails.len(),
            MAX_JAILS
        ));
    }
    if cfg.interval == 0 || cfg.interval > 60 {
        return Err(format!(
            "Config validation failed: invalid interval={} (must be 1..60)",
            cfg.interval
        ));
    }
    // metrics_port 是 u16, 范围检查在类型系统天然保证; 0 = 禁用, 1..=65535 = 监听
    if cfg.default_max_retries == 0 {
        return Err("Config validation failed: default_max_retries is 0".to_string());
    }
    if cfg.default_findtime == 0 {
        return Err("Config validation failed: default_findtime is 0".to_string());
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
        if jail.ban_time == 0 {
            log_debug!("Jail '{}' ban_time=0 (permanent ban)", jail.name);
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
                log_debug!("Migrated failed entries for jail '{}'", new_jail.name);
                break;
            }
        }
    }
}

/// 部分释放 `Config`:清空所有 jail + 配置来源追踪 + 敏感字段。
///
/// 与 `cleanup_all_jails` 的区别:还清空 `config_file` / `config_dir` /
/// `permanent_db_path` / `metrics_*` 字段,适用于"完全卸载配置"的场景。
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
    cfg.permanent_db_path = None;
    cfg.metrics_bind_address.clear();
    cfg.metrics_username = None;
    cfg.metrics_password = None;
}

// ============================================================================
// 预编译正则表达式
// ============================================================================

/// 为所有 enabled jail 编译正则。空正则列表视为使用内置默认,
/// 不调 [`compile_jail_regex`] 而是记 INFO 说明。
///
/// 部分 jail 失败不中断其他 jail 的编译,最后至少 1 个 jail 成功即返回 `Ok`。
///
/// # Arguments
/// - `cfg`: 待处理的配置 (可变引用)
///
/// # Returns
/// - `Ok(())`: 至少 1 个 jail 编译成功
/// - `Err(String)`: 没有任何 jail 编译成功 (累积最后 1 个错误信息)
///
/// # Errors
/// 部分 [`compile_jail_regex`] 失败的错误信息会被累积,只有当全部 jail
/// 都失败时才返回最后 1 个错误
pub fn init_log_patterns(cfg: &mut Config) -> Result<(), String> {
    let mut ret = Ok(());

    for jail in &mut cfg.jails {
        if !jail.enabled {
            log_debug!(
                "Skipping disabled jail '{}' for regex compilation",
                jail.name
            );
            continue;
        }

        if jail.regexes.is_empty() {
            log_info!(
                "Jail '{}' will use built-in default regex pattern",
                jail.name
            );
        } else if let Err(e) = compile_jail_regex(jail) {
            log_warn!("Failed to compile regex for jail '{}': {}", jail.name, e);
            ret = Err(e);
            // 继续为其他 jail 编译
        } else {
            log_info!(
                "Compiled {} regex pattern(s) for jail '{}'",
                jail.regexes.iter().filter(|r| r.compiled.is_some()).count(),
                jail.name
            );
        }
    }

    ret
}

/// 释放所有全局正则模式。保留函数以与 C 版 API 对齐;当前实现
/// (正则按 jail 管理) 是 no-op。
pub fn free_log_patterns(_cfg: &mut Config) {
    // 正则表达式现在按 jail 管理, 没有全局模式需要释放
}

// ============================================================================
// 单元测试
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_service_name_match_exact() {
        assert!(is_service_name_match("sshd", SSH_PATTERNS));
        assert!(is_service_name_match("nginx", WEB_PATTERNS));
        assert!(is_service_name_match("mysql", DB_PATTERNS));
    }

    #[test]
    fn is_service_name_match_prefix() {
        assert!(is_service_name_match("sshd-custom", SSH_PATTERNS));
        assert!(is_service_name_match("nginx-proxy", WEB_PATTERNS));
    }

    #[test]
    fn is_service_name_match_suffix() {
        assert!(is_service_name_match("custom-sshd", SSH_PATTERNS));
        assert!(is_service_name_match("my-nginx", WEB_PATTERNS));
    }

    #[test]
    fn is_service_name_match_contains() {
        assert!(is_service_name_match("my-sshd-service", SSH_PATTERNS));
        assert!(is_service_name_match("custom-nginx-config", WEB_PATTERNS));
    }

    #[test]
    fn is_service_name_match_no_match() {
        assert!(!is_service_name_match("unknown", SSH_PATTERNS));
        assert!(!is_service_name_match("redis", DB_PATTERNS));
    }

    #[test]
    fn apply_smart_defaults_ssh() {
        let mut cfg = Config::default();
        let (mr, ft, bt) = (
            cfg.default_max_retries,
            cfg.default_findtime,
            cfg.default_ban_time,
        );
        let jail = find_or_create_jail(&mut cfg, "sshd").unwrap();
        apply_smart_defaults_single(jail, mr, ft, bt);
        assert_eq!(jail.max_retries, 5);
        assert_eq!(jail.findtime, 600);
        assert_eq!(jail.ban_time, 900);
    }

    #[test]
    fn apply_smart_defaults_web() {
        let mut cfg = Config::default();
        let (mr, ft, bt) = (
            cfg.default_max_retries,
            cfg.default_findtime,
            cfg.default_ban_time,
        );
        let jail = find_or_create_jail(&mut cfg, "nginx").unwrap();
        apply_smart_defaults_single(jail, mr, ft, bt);
        assert_eq!(jail.max_retries, 10);
        assert_eq!(jail.findtime, 300);
        assert_eq!(jail.ban_time, 1800);
    }

    #[test]
    fn apply_smart_defaults_unknown() {
        let mut cfg = Config::default();
        cfg.default_max_retries = 7;
        cfg.default_findtime = 120;
        cfg.default_ban_time = 300;
        let (mr, ft, bt) = (
            cfg.default_max_retries,
            cfg.default_findtime,
            cfg.default_ban_time,
        );
        let jail = find_or_create_jail(&mut cfg, "unknown-service").unwrap();
        apply_smart_defaults_single(jail, mr, ft, bt);
        assert_eq!(jail.max_retries, 7);
        assert_eq!(jail.findtime, 120);
        assert_eq!(jail.ban_time, 300);
    }

    #[test]
    fn config_validate_empty_jails() {
        let cfg = Config::default();
        assert!(config_validate(&cfg).is_err());
    }

    #[test]
    fn config_validate_invalid_interval() {
        let mut cfg = Config::default();
        cfg.jails.push(Jail::new("test".to_string()));
        cfg.jails[0].log_files.push("/var/log/test.log".to_string());
        cfg.jails[0].max_retries = 3;
        cfg.jails[0].findtime = 600;
        cfg.jails[0].ban_time = 600;

        cfg.interval = 0;
        assert!(config_validate(&cfg).is_err());

        cfg.interval = 61;
        assert!(config_validate(&cfg).is_err());

        cfg.interval = 1;
        assert!(config_validate(&cfg).is_ok());
    }

    #[test]
    fn config_clone_preserves_values() {
        let mut src = Config::default();
        src.default_max_retries = 10;
        src.default_findtime = 1200;
        src.default_ban_time = 1800;
        src.metrics_port = 8080;
        src.metrics_bind_address = "0.0.0.0".to_string();

        let dst = config_clone(&src);
        assert_eq!(dst.default_max_retries, 10);
        assert_eq!(dst.default_findtime, 1200);
        assert_eq!(dst.default_ban_time, 1800);
        assert_eq!(dst.metrics_port, 8080);
        assert_eq!(dst.metrics_bind_address, "0.0.0.0");
    }

    #[test]
    fn validate_regex_safety_rejects_nested_quantifiers() {
        let jail = Jail::new("test".to_string());
        assert!(validate_regex_safety(&jail, "(a+)+").is_err());
        assert!(validate_regex_safety(&jail, "(a*)*").is_err());
    }

    #[test]
    fn validate_regex_safety_rejects_possessive() {
        let jail = Jail::new("test".to_string());
        assert!(validate_regex_safety(&jail, "a++").is_err());
        assert!(validate_regex_safety(&jail, "a*+").is_err());
    }

    #[test]
    fn validate_regex_safety_rejects_too_long() {
        let jail = Jail::new("test".to_string());
        let long_pattern = "a".repeat(1025);
        assert!(validate_regex_safety(&jail, &long_pattern).is_err());
    }

    #[test]
    fn validate_regex_safety_accepts_valid() {
        let jail = Jail::new("test".to_string());
        assert!(
            validate_regex_safety(&jail, r"Failed password for .* from \d+\.\d+\.\d+\.\d+").is_ok()
        );
    }
}
