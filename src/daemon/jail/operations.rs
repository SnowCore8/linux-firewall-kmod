//! Jail CRUD 操作 + 日志模式初始化/释放

use super::regex::free_jail_regex_full;
use crate::types::{Config, Jail, RegexInfo, MAX_JAILS};

use super::regex::compile_jail_regex;

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
        return None;
    }

    let jail = Jail::new(name.to_string());
    cfg.jails.push(jail);
    let jail = cfg.jails.last_mut().unwrap();

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
pub fn init_log_patterns(cfg: &mut Config) -> Result<(), String> {
    let mut ret = Ok(());

    for jail in &mut cfg.jails {
        if !jail.enabled {
            continue;
        }

        if jail.regexes.is_empty() {
            // 无正则表达式，跳过
        } else if let Err(e) = compile_jail_regex(jail) {
            ret = Err(e);
            // 继续为其他 jail 编译
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
