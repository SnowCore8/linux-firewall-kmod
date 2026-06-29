//! 失败尝试跟踪: 滑动窗口计数 (R9-7 优化) + 阈值检查 + 触发封禁

#![allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]

use crate::ban;
use crate::types::{FailedEntry, Jail, DAEMON_STATS, MAX_FAILED_TIMESTAMPS};

/// 当前 Unix 秒 (内部时间源)。委托 [`crate::types::now_secs`] 避免重复 unwrap。
#[inline]
pub(super) fn now_secs() -> i64 {
    crate::types::now_secs()
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
        entry.timestamps.push_back(now);
    } else {
        // 性能优化：使用 VecDeque::pop_front() 替代 Vec::remove(0)
        // FIFO 移出操作从 O(n) 降低到 O(1)，避免在持有写锁期间阻塞其他 IP 处理
        entry.timestamps.pop_front();
        entry.timestamps.push_back(now);

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

/// 清理 `failed_hash` 中所有时间戳均已过期的条目。
///
/// 目的:防止长期未触发封禁的 IP 条目无限累积导致内存泄漏。
/// 清理条件:`entry.timestamps` 为空,或最后一个时间戳 < `now - findtime`。
///
/// # Arguments
/// - `jail`: 目标 jail
/// - `now`: 当前 Unix 秒
/// - `findtime`: 滑动窗口大小 (秒)
///
/// # Returns
/// 被清理的条目数
pub fn cleanup_expired_entries(jail: &Jail, now: i64, findtime: i64) -> usize {
    let mut hash = jail.failed_hash.write();
    let before = hash.len();

    hash.retain(|_ip, entry| {
        // 空条目直接移除
        if entry.timestamps.is_empty() {
            return false;
        }

        // 检查最后一个时间戳是否已过期
        // timestamps 是单调追加的,所以最后一个就是最新的
        if let Some(&last_ts) = entry.timestamps.back() {
            let expired = now - last_ts > findtime;
            !expired // 返回 true 表示保留
        } else {
            false
        }
    });

    before - hash.len()
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
/// - 达到阈值时调 `ban::ban_ip` 通过 netlink 封禁
/// - 封禁成功后清理 `failed_hash` 中对应条目
pub fn handle_failed_attempt_for_jail(jail: &Jail, ip: &str, max_retries: u32, findtime: u32) {
    if ip.is_empty() {
        return;
    }

    DAEMON_STATS
        .failed_attempts
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // 记录失败到 IP 信誉分系统（-10 分）
    let reputation = crate::ip_reputation::get_store();
    reputation.record_failure(ip);

    let findtime_i64 = i64::from(findtime);
    let now = now_secs();

    // 按时间段放宽阈值：业务高峰期（9-18 点 UTC）× 1.5
    let is_peak_hours = crate::file_monitor::monitor_loop::is_baseline_peak_hours();
    let peak_hours_multiplier = if is_peak_hours { 1.5 } else { 1.0 };

    // 按来源放宽阈值：内网 IP × 2.0，外网 IP × 1.0
    let is_internal = crate::ban::is_internal_ip(ip);
    let source_multiplier = if is_internal { 2.0 } else { 1.0 };

    // 按信誉分调整阈值：信誉 < 50 → × 0.5（严格），50-79 → × 0.8，≥ 80 → × 1.0
    let reputation_multiplier = reputation.get_threshold_multiplier(ip);

    // 综合计算有效阈值（三种策略叠加）
    let effective_max_retries =
        (max_retries as f64 * peak_hours_multiplier * source_multiplier * reputation_multiplier)
            .ceil()
            .max(1.0) as u32;

    let mut hash = jail.failed_hash.write();
    let entry = hash
        .entry(ip.to_string())
        .or_insert_with(|| FailedEntry::new(ip.to_string()));

    process_failed_timestamps(entry, now, findtime_i64);

    let recent_fails = count_recent(entry, findtime_i64, effective_max_retries);
    if recent_fails >= effective_max_retries {
        // 记录触发封禁的失败统计
        let fail_count = recent_fails;

        // 复用 validate_ip 统一处理 IPv4/IPv6，验证失败时跳过而非静默使用 0
        let ip_num = match crate::ban::validate_ip(ip) {
            Ok(v) => v.ip_num,
            Err(e) => {
                crate::logger::error!(
                    crate::logger::get(),
                    "IP 验证失败，跳过封禁";
                    "ip" => ip,
                    "error" => %e
                );
                return;
            }
        };

        // === 渐进式封禁：根据历史封禁次数递增封禁时长 ===
        let ban_history = crate::types::BAN_HISTORY.get_or_init(crate::types::BanHistory::new);
        let ban_count = ban_history.get_ban_count(ip);
        let base_duration = if jail.ban_time < 0 {
            0u32
        } else {
            jail.ban_time as u32
        };
        let progressive_duration = ban_history.calculate_progressive_duration(ip, base_duration);
        // jail.ban_time < 0 → 配置级永久封禁（如 sshd ban_time=-1）
        // progressive_duration == 0 && ban_count >= 3 → 渐进式升级永久封禁
        let is_permanent = jail.ban_time < 0 || (progressive_duration == 0 && ban_count >= 3);

        // 记录渐进式封禁日志
        if ban_count > 0 {
            crate::logger::info!(
                crate::logger::get(),
                "渐进式封禁：复发 IP 封禁时长递增";
                "ip" => ip,
                "ban_count" => ban_count + 1,
                "base_duration" => base_duration,
                "progressive_duration" => progressive_duration,
                "is_permanent" => is_permanent,
                "jail" => &jail.name
            );
        }

        let ban_info = crate::types::BanInfo {
            ip: ip.to_string(),
            ip_num,
            jail_name: jail.name.clone(),
            reason: jail.name.clone(),
            banned_at: now,
            expires_at: if is_permanent {
                0 // 永久封禁
            } else if progressive_duration > 0 {
                now + progressive_duration as i64
            } else {
                // progressive_duration == 0 但非永久：ban_time=0 的退化情况
                // 使用 jail 默认 ban_time 兜底，避免 0 秒即过期
                now + base_duration.max(1) as i64
            },
            is_permanent,
            fail_count,
            ban_count: ban_count + 1,
        };

        // 必须先释放写锁再调 ban_ip, 否则 ban 内部可能触发的日志写会与本锁死锁
        drop(hash);

        // 原子性检查并插入缓存：消除 check-then-act 竞态条件
        // 多线程同时触发同一 IP 封禁时，只有一个线程的 try_insert 返回 true
        let cache = crate::types::ACTIVE_BAN_CACHE.get_or_init(crate::types::ActiveBanCache::new);
        if !cache.try_insert(ban_info) {
            // 已被其他线程先行封禁，跳过本次操作
            return;
        }

        let ban_duration = if is_permanent {
            0u64
        } else {
            progressive_duration as u64
        };
        if let Err(e) = ban::ban_ip(ip, ban_duration, &jail.name) {
            // 封禁失败，回滚缓存标记（允许下次重试）
            // record_ban / record_ban_event / record_ban(ip_reputation) 尚未调用，无需回滚
            cache.remove(ip);
            crate::logger::warn!(
                crate::logger::get(),
                "内核封禁失败，已回滚缓存标记";
                "ip" => ip,
                "jail" => &jail.name,
                "error" => %e
            );
            return;
        }

        // netlink 成功后才记录副作用（避免封禁失败时 ban_count/信誉分/事件表被污染）
        // handle_ban_state_change 检测到 cache.contains → 跳过重复 record_ban
        ban_history.record_ban(ip, is_permanent);
        crate::history_snapshot::record_ban_event(ip, &jail.name, ban_count + 1);
        crate::ip_reputation::get_store().record_ban(ip);

        // per-Jail 统计：封禁触发
        crate::types::with_jail_stats(&jail.name, |s| {
            s.bans_triggered
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
        {
            // 成功封禁后移除条目, 避免重复封禁计数
            let mut hash2 = jail.failed_hash.write();
            hash2.remove(ip);
        }
    }
}
