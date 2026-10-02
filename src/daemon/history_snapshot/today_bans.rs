//! 「今日」封禁数——本地时区自然日窗口内的封禁事件计数。
//!
//! 数据源是 `ban_events` 表（每次封禁记一行，7 天保留），按各行的 `banned_at`
//! 落在窗口内计数。相比读 `DAEMON_STATS.ips_banned` 原子计数器，它有两个好处：
//!
//! - **窗口真实存在**：计数器是进程启动以来的累计值，重启即归零；本函数给的是
//!   「今天 00:00 起」的窗口值，与 `total_bans` 是两个不同的量。
//! - **跨重启一致**：事件在库里，守护进程重启后今日数不会凭空回零。
//!
//! # 窗口定义（契约 `StatsResponse.today_bans` 同口径）
//!
//! 窗口起点是**本地时区**的当日 00:00，时区取守护进程进程的本地时区（`TZ`
//! 环境变量或系统时区，经 `chrono::Local` 解析）。刻意不用 UTC：看板上的「今日」
//! 是给本机运维看的，跟运维的日历走。
//!
//! # 缓存
//!
//! 读路径（REST `/api/v1/stats` 与 SSE 推送）会反复取这个值，故带 30 秒 TTL
//! 缓存——与 [`crate::web_ui::stats::trends_snapshot`] 同一节奏。缓存的副作用是
//! 窗口切换（午夜）最多晚 30 秒反映到看板上，对「今日封禁」这个量级无影响。

use super::history_db;

/// 缓存有效期（秒）。与趋势数据同节奏：都是「看板上的统计数字」。
const CACHE_TTL_SECS: i64 = 30;

/// 缓存内容：上次取数时刻与当时的计数。
struct TodayBansCache {
    count: u64,
    last_update: i64,
}

static TODAY_BANS_CACHE: std::sync::OnceLock<parking_lot::Mutex<TodayBansCache>> =
    std::sync::OnceLock::new();

fn cache() -> &'static parking_lot::Mutex<TodayBansCache> {
    TODAY_BANS_CACHE.get_or_init(|| {
        parking_lot::Mutex::new(TodayBansCache {
            count: 0,
            last_update: 0,
        })
    })
}

/// 本地时区「今日 00:00」的 Unix 时间戳。
///
/// 用 `Local.from_local_datetime(...).earliest()` 而不是「当前时间减去本地墙钟秒数」：
/// 后者在夏令时切换日会偏一小时（偏移量在午夜与当前时刻之间变过）。夏令时把整点
/// 00:00 跳过（少数时区在午夜切换）时 `earliest()` 返回 `None`，此时才退回墙钟反推。
fn local_midnight_ts() -> i64 {
    use chrono::{Local, TimeZone, Timelike};

    let now = Local::now();
    now.date_naive()
        .and_hms_opt(0, 0, 0)
        .and_then(|naive| Local.from_local_datetime(&naive).earliest())
        .map_or_else(
            || now.timestamp() - i64::from(now.num_seconds_from_midnight()),
            |dt| dt.timestamp(),
        )
}

/// 统计 `banned_at >= since` 的封禁事件数。
///
/// 历史库不可用时返回 0（库不在则事件本就写不进去，0 是「已记录数」的真实值），
/// 不返回错误——调用方在 SSE 渲染线程上，没有处理错误的余地。
fn count_bans_since(since: i64) -> u64 {
    let db = history_db();
    let Some(conn) = db.as_ref() else {
        return 0;
    };
    conn.query_row(
        "SELECT COUNT(*) FROM ban_events WHERE banned_at >= ?1",
        rusqlite::params![since],
        |row| row.get::<_, i64>(0),
    )
    .map(|n| n.max(0) as u64)
    .unwrap_or(0)
}

/// 今日（本地时区自然日）封禁数，带 30 秒缓存。
///
/// 由 `HistoryPort::today_bans` 调用（REST 与 SSE 两条读路径同源）。
#[must_use]
pub fn today_ban_count() -> u64 {
    let now = crate::types::now_secs();
    let mut cached = cache().lock();
    if now - cached.last_update < CACHE_TTL_SECS {
        return cached.count;
    }
    let count = count_bans_since(local_midnight_ts());
    cached.count = count;
    cached.last_update = now;
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_midnight_is_start_of_today_and_not_in_the_future() {
        use chrono::TimeZone;

        let midnight = local_midnight_ts();
        let now = chrono::Local::now();
        assert!(
            midnight <= now.timestamp(),
            "窗口起点不得晚于当前时刻（{midnight} > {}）",
            now.timestamp()
        );
        // 起点必须落在今天的本地日期上。判据刻意不用「与当前时刻相差不超过
        // 24 小时」：夏令时回拨日的本地日有 25 小时，那个判据在当天会误报。
        let start = chrono::Local
            .timestamp_opt(midnight, 0)
            .single()
            .expect("起点应是合法本地时刻");
        assert_eq!(
            start.date_naive(),
            now.date_naive(),
            "窗口起点应落在今天的本地日期（实际 {start}）"
        );
    }

    #[test]
    fn midnight_is_stable_within_the_same_call_second() {
        // 同一秒内两次取值必须一致（幂等），否则缓存会给出跳变的窗口起点。
        let a = local_midnight_ts();
        let b = local_midnight_ts();
        assert_eq!(a, b);
    }

    #[test]
    fn count_bans_since_future_returns_zero() {
        // 未来时刻之后没有任何事件 → 0。这条同时覆盖「库未装配」的返回路径
        // （测试进程里历史库通常未初始化，两条路径都返回 0）。
        let far_future = chrono::Utc::now().timestamp() + 86_400;
        assert_eq!(count_bans_since(far_future), 0);
    }
}
