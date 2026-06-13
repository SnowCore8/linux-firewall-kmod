//! 失败条目管理: 查找、创建、移除

use anyhow::Result;

use crate::types::{FailedEntry, Jail};

/// 在 `failed_hash` 中查找已有条目。调用方需持有 `jail.failed_hash` 读锁。
///
/// # Arguments
/// - `hash`: 已加读锁的失败条目 map
/// - `ip`: 待查询的 IP 字符串
///
/// # Returns
/// 找到的 `&FailedEntry`,无则 `None`。
#[must_use]
pub fn find_entry<'a>(
    hash: &'a std::collections::HashMap<String, FailedEntry>,
    ip: &str,
) -> Option<&'a FailedEntry> {
    hash.get(ip)
}

/// 在指定 jail 中为某 IP 创建失败条目 (若不存在)。已存在则 no-op。
///
/// # Arguments
/// - `jail`: 目标 jail
/// - `ip`: 待添加的 IP
///
/// # Errors
/// 当前实现不会 `Err`,保留签名以备未来加入持久化错误传播
pub fn create_entry_for_jail(jail: &Jail, ip: &str) -> Result<()> {
    let mut hash = jail.failed_hash.write();

    if hash.contains_key(ip) {
        return Ok(());
    }

    let entry = FailedEntry::new(ip.to_string());
    hash.insert(ip.to_string(), entry);

    Ok(())
}

/// 从指定 jail 中移除某 IP 的失败条目。封禁成功后清理用。
///
/// # Arguments
/// - `jail`: 目标 jail
/// - `ip`: 待移除的 IP
pub fn remove_entry_for_jail(jail: &Jail, ip: &str) {
    let mut hash = jail.failed_hash.write();
    hash.remove(ip);
}
