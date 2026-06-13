//! 失败尝试跟踪: 滑动窗口计数 (R9-7 优化) + 阈值检查 + 触发封禁

#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use std::time::{SystemTime, UNIX_EPOCH};

use crate::ban;
use crate::types::{FailedEntry, Jail, DAEMON_STATS, MAX_FAILED_TIMESTAMPS};

/// 当前 Unix 秒 (内部时间源)。所有时间戳统一基于此函数。
#[inline]
pub(super) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ============================================================================
// 统计时间窗口内近期失败次数
// ============================================================================

/// 统计 `entry.timestamps` 中 `now - ts <= window` 的元素数。
///
/// R9-7 优化:用 `recent_head` 跳过已确认过期的前缀,平均 O(1)(最坏仍 O(n))。
/// `count > max_retries` 提前 break 进一步限制上界。
///
/// # Arguments
/// - `entry`: 失败条目
/// - `window`: 滑动窗口大小 (秒),`<= 0` 直接返回 0
/// - `max_retries`: 阈值,达到后停止扫描 (上界保护)
///
/// # Returns
/// 窗口内失败次数,0..=`max_retries`。
pub fn count_recent(entry: &FailedEntry, window: i64, max_retries: u32) -> u32 {
    let now = now_secs();

    if window <= 0 {
        return 0;
    }

    let mut start = entry.recent_head.load(std::sync::atomic::Ordering::Relaxed);
    if start >= entry.timestamps.len() {
        start = 0;
    }

    while start < entry.timestamps.len()
        && now >= entry.timestamps[start]
        && (now - entry.timestamps[start]) > window
    {
        start += 1;
    }
    entry
        .recent_head
        .store(start, std::sync::atomic::Ordering::Relaxed);

    let mut count: u32 = 0;
    for i in start..entry.timestamps.len() {
        if now >= entry.timestamps[i] {
            let diff = now - entry.timestamps[i];
            if diff <= window {
                count += 1;
            }
        }
        if count > max_retries {
            break;
        }
    }

    count
}

// ============================================================================
// 环形缓冲式时间戳管理
// ============================================================================

/// 向 `entry.timestamps` 追加新时间戳。满 [`MAX_FAILED_TIMESTAMPS`] 时 FIFO
/// 移出最旧的,并同步维护 `recent_head` 索引。
///
/// 索引维护规则:移出 1 个时间戳后,`recent_head > 0` 时减 1;之后立即做一次
/// 过期过滤(基于 `findtime`),`recent_head` 重置为 0,避免下次 `count_recent`
/// 重复扫描已知过期前缀。
///
/// # Arguments
/// - `entry`: 失败条目 (可变引用)
/// - `now`: 当前 Unix 秒
/// - `findtime`: 滑动窗口大小 (秒),用于过期过滤
pub fn process_failed_timestamps(entry: &mut FailedEntry, now: i64, findtime: i64) {
    if entry.timestamps.len() < MAX_FAILED_TIMESTAMPS {
        entry.timestamps.push(now);
    } else {
        // 满后移出最旧时间戳腾出空间, 同时维护 recent_head 索引
        entry.timestamps.remove(0);
        entry.timestamps.push(now);

        if entry.recent_head.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            entry
                .recent_head
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }

        // 移动后立即过滤一次过期, 避免下次 count_recent 重做
        let oldest_valid = now - findtime;
        entry.timestamps.retain(|&ts| ts >= oldest_valid);

        entry
            .recent_head
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }
}

/// 处理单次失败尝试的完整流程:累加计数 → 阈值检查 → 触发封禁 → 清理条目。
///
/// # Arguments
/// - `jail`: 目标 jail
/// - `ip`: 触发失败的 IP (已通过 [`crate::ban::validate_ip`])
/// - `max_retries`: 该 jail 的失败阈值
/// - `findtime`: 该 jail 的滑动窗口 (秒)
///
/// 副作用:
/// - `DAEMON_STATS.failed_attempts` +1
/// - 达到阈值时调 `ban::ban_ip` 写 procfs
/// - 封禁成功后清理 `failed_hash` 中对应条目
pub fn handle_failed_attempt_for_jail(jail: &Jail, ip: &str, max_retries: u32, findtime: u32) {
    if ip.is_empty() {
        return;
    }

    DAEMON_STATS
        .failed_attempts
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    let findtime_i64 = i64::from(findtime);
    let now = now_secs();

    let mut hash = jail.failed_hash.write();
    let entry = hash
        .entry(ip.to_string())
        .or_insert_with(|| FailedEntry::new(ip.to_string()));

    process_failed_timestamps(entry, now, findtime_i64);

    let recent_fails = count_recent(entry, findtime_i64, max_retries);
    if recent_fails >= max_retries {
        // 必须先释放写锁再调 ban_ip, 否则 ban 内部可能触发的日志写会与本锁死锁
        drop(hash);

        if ban::ban_ip(ip).is_ok() {
            // 成功封禁后移除条目, 避免重复封禁计数
            let mut hash2 = jail.failed_hash.write();
            hash2.remove(ip);
        }
    }
}
