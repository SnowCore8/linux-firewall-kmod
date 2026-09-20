//! 每 (jail, ip) 的失败时间戳窗口：**单所有者**，无跨模块锁。
//!
//! 旧实现把窗口放在 `Jail.failed_hash`（`RwLock<HashMap<String, FailedEntry>>`），于是
//! 同一 jail 的所有源、所有 IP 共用一把写锁——10 Gbps 级别的失败事件涌入时，写锁争用
//! 直接落在热路径上（这也是旧代码要给 `recent_head` 做 O(1) 前缀跳过、给 `VecDeque`
//! 做 O(1) FIFO 的原因：锁内必须尽量短）。
//!
//! 这里窗口归**一个 jail 的判定执行体**独占：`FailureWindow` 只被该执行体 `&mut` 使用，
//! 因此内部用普通 `HashMap` / `VecDeque`，无需原子、无需锁。跨执行体传递的是判定结果
//! （是否触发封禁、触发时的失败计数），不是窗口本身。
//!
//! 计数语义与旧 `count_recent` + `process_failed_timestamps` 对齐：只统计
//! `now - findtime <= ts <= now` 的时间戳；条目时间戳数上限 [`MAX_TIMESTAMPS_PER_IP`]
//! （FIFO 淘汰最旧）。

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// 单个 IP 保留的时间戳上限（与旧 `MAX_FAILED_TIMESTAMPS` 一致）。
pub const MAX_TIMESTAMPS_PER_IP: usize = 100;

/// 一次观测的结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// 窗口内（`findtime` 秒）的失败次数，已按 `cap` 截断。
    pub recent: u32,
    /// 本次观测后该 IP 的窗口内计数是否已达到 `cap`（触发封禁）。
    pub reached_cap: bool,
}

/// 单个 jail 的失败窗口表，由该 jail 的判定执行体独占。
#[derive(Debug, Default)]
pub struct FailureWindow {
    /// IP → 失败时间戳（Unix 秒），按追加顺序排列。
    entries: HashMap<IpAddr, VecDeque<i64>>,
}

impl FailureWindow {
    /// 新建空窗口。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前被跟踪的 IP 数。
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 是否没有任何被跟踪的 IP。
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// 记录一次失败并返回窗口内计数。
    ///
    /// `findtime == 0` 时旧实现直接返回 0（不计数、不触发）；这里保持同一语义，
    /// 但仍会落一次时间戳，使「窗口为 0」的配置不会静默丢弃观测。
    ///
    /// # Arguments
    /// - `ip`: 来源 IP（已通过提取与保留段校验）
    /// - `now`: 当前 Unix 秒（由调用方注入，函数本身纯粹于时钟）
    /// - `findtime`: 滑动窗口（秒）
    /// - `cap`: 计数上界，达到即停止累加（避免无谓地扫满 100 个时间戳）
    pub fn observe(&mut self, ip: IpAddr, now: i64, findtime: u32, cap: u32) -> Verdict {
        let window = i64::from(findtime);
        let timestamps = self.entries.entry(ip).or_default();

        // 与旧 `process_failed_timestamps` 逐条对齐：未满则直接追加；**仅在满员时**
        // 才 FIFO 淘汰并顺手过滤过期前缀。不在每轮都过滤，是因为过滤用的「现在」
        // 是本次事件的时间——若事件时间乱序（时钟回拨），按每轮过滤会以某个更靠后
        // 的事件时间为准提前丢弃仍在窗口内的旧时间戳，与旧实现产生分歧。
        // 过期与否由后面的计数阶段按调用方给的 `now` 判定，不依赖此处的物理删除。
        if timestamps.len() >= MAX_TIMESTAMPS_PER_IP {
            timestamps.pop_front();
            timestamps.push_back(now);
            if window > 0 {
                let oldest_valid = now - window;
                timestamps.retain(|&ts| ts >= oldest_valid);
            }
        } else {
            timestamps.push_back(now);
        }

        if window <= 0 {
            return Verdict {
                recent: 0,
                reached_cap: false,
            };
        }

        let mut recent: u32 = 0;
        for &ts in timestamps.iter() {
            // 只统计不晚于 `now` 的时间戳（时钟回拨时可能出现未来时间戳）。
            if now >= ts && now - ts <= window {
                recent += 1;
                if recent >= cap {
                    break;
                }
            }
        }

        Verdict {
            recent,
            reached_cap: recent >= cap,
        }
    }

    /// 只读查询窗口内计数（不改动窗口），供 API / 诊断使用。
    ///
    /// 「读路径零副作用」的体现：旧实现在读路径上更新 `recent_head`、甚至清理条目，
    /// 一次查询会改变后续判定的行为；这里查询是纯读。
    #[must_use]
    pub fn peek(&self, ip: IpAddr, now: i64, findtime: u32, cap: u32) -> u32 {
        let Some(timestamps) = self.entries.get(&ip) else {
            return 0;
        };
        let window = i64::from(findtime);
        if window <= 0 {
            return 0;
        }
        let mut recent = 0;
        for &ts in timestamps {
            if now >= ts && now - ts <= window {
                recent += 1;
                if recent >= cap {
                    break;
                }
            }
        }
        recent
    }

    /// 封禁成功后丢弃该 IP 的窗口，避免重复封禁计数。
    pub fn forget(&mut self, ip: IpAddr) {
        self.entries.remove(&ip);
    }

    /// 清理所有时间戳均已过期的条目，返回清理条数。
    ///
    /// 判据与旧 `cleanup_expired_entries` 一致：窗口内无任何时间戳即删除（含空条目）。
    pub fn cleanup_expired(&mut self, now: i64, findtime: u32) -> usize {
        let window = i64::from(findtime);
        let before = self.entries.len();
        self.entries.retain(|_, timestamps| {
            if timestamps.is_empty() {
                return false;
            }
            // 时间戳单调追加，故队尾即最新；最新都过期则整条过期。
            timestamps.back().is_some_and(|&last| now - last <= window)
        });
        before - self.entries.len()
    }

    /// 遍历全部被跟踪的 IP 及其最新时间戳（顺序不保证），供快照导出。
    pub fn iter(&self) -> impl Iterator<Item = (IpAddr, Option<i64>)> + '_ {
        self.entries
            .iter()
            .map(|(&ip, ts)| (ip, ts.back().copied()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试用 IP 必须合法")
    }

    #[test]
    fn counts_only_within_window() {
        let mut w = FailureWindow::new();
        let t0 = 10_000_i64;
        // 记录与计数用的是同一个时钟读数（与旧实现一致），故每次 observe 传入的
        // `now` 既是新时间戳，也是本轮的计数基准。
        assert_eq!(w.observe(ip("1.1.1.1"), t0, 300, 100).recent, 1);
        assert_eq!(w.observe(ip("1.1.1.1"), t0 + 100, 300, 100).recent, 2);
        // 到 t0+400 时：t0 那次相隔 400 秒已滑出 300 秒窗口，t0+100 那次恰好
        // 相隔 300 秒仍在窗口边界内（`<=`）。
        let v = w.observe(ip("1.1.1.1"), t0 + 400, 300, 100);
        assert_eq!(v.recent, 2, "应只保留 t0+100 与 t0+400 两次");
        assert!(!v.reached_cap);
    }

    #[test]
    fn reached_cap_flags_when_threshold_hit() {
        let mut w = FailureWindow::new();
        let mut last = None;
        for _ in 0..5 {
            last = Some(w.observe(ip("2.2.2.2"), 42, 600, 5));
        }
        let v = last.expect("应有观测");
        assert_eq!(v.recent, 5);
        assert!(v.reached_cap, "达到 cap 必须被标出");
    }

    #[test]
    fn zero_window_never_counts() {
        let mut w = FailureWindow::new();
        let v = w.observe(ip("3.3.3.3"), 100, 0, 5);
        assert_eq!(v.recent, 0);
        assert!(!v.reached_cap);
        assert_eq!(w.peek(ip("3.3.3.3"), 100, 0, 5), 0);
    }

    #[test]
    fn ring_drops_oldest_beyond_capacity() {
        let mut w = FailureWindow::new();
        let ip = ip("4.4.4.4");
        // 塞满 100 个时间戳（同一时刻，全部在窗口内）。
        for _ in 0..(MAX_TIMESTAMPS_PER_IP as u32 + 10) {
            w.observe(ip, 1_000, 10_000, u32::MAX);
        }
        assert_eq!(
            w.peek(ip, 1_000, 10_000, u32::MAX),
            MAX_TIMESTAMPS_PER_IP as u32,
            "每 IP 时间戳不应超过上限"
        );
    }

    #[test]
    fn peek_does_not_mutate_and_forget_clears() {
        let mut w = FailureWindow::new();
        let ip = ip("5.5.5.5");
        w.observe(ip, 100, 600, 10);
        assert_eq!(w.peek(ip, 100, 600, 10), 1);
        // 连续 peek 结果必须稳定（读路径无副作用）。
        assert_eq!(w.peek(ip, 100, 600, 10), 1);
        w.forget(ip);
        assert_eq!(w.peek(ip, 100, 600, 10), 0);
        assert!(w.is_empty());
    }

    #[test]
    fn cleanup_removes_only_fully_expired_entries() {
        let mut w = FailureWindow::new();
        w.observe(ip("6.6.6.6"), 100, 600, 10); // 过期
        w.observe(ip("7.7.7.7"), 900, 600, 10); // 未过期
        assert_eq!(w.cleanup_expired(1_000, 600), 1);
        assert_eq!(w.len(), 1);
        assert_eq!(w.peek(ip("7.7.7.7"), 1_000, 600, 10), 1);
    }

    #[test]
    fn future_timestamps_are_ignored_in_count() {
        // 时钟回拨产生的「未来」时间戳不应计入窗口计数。
        let mut w = FailureWindow::new();
        let ip = ip("8.8.8.8");
        w.observe(ip, 2_000, 600, 10); // now=1000 时这是未来
        assert_eq!(w.peek(ip, 1_000, 600, 10), 0);
        assert_eq!(w.peek(ip, 2_000, 600, 10), 1);
    }

    /// 运行期对照：与旧 `FailedEntry` 的 `process_failed_timestamps` + `count_recent`
    /// 在同一批相对时间戳上必须给出相同计数。旧模块在 2.C 收尾时删除，本测试同时退役。
    #[test]
    fn parity_with_legacy_count_recent() {
        use crate::failed_tracker::{count_recent, process_failed_timestamps};
        use crate::types::{FailedEntry, MAX_FAILED_TIMESTAMPS};

        // 旧实现的 `count_recent` 内部读真实时钟，故用真实 `now` 构造相对时间戳。
        let now = crate::types::now_secs();
        let findtime: i64 = 600;
        let offsets = [0_i64, -10, -100, -599, -600, -601, -5_000, 30];

        let mut legacy = FailedEntry::new("9.9.9.9".to_string());
        let mut window = FailureWindow::new();
        let ip = ip("9.9.9.9");

        for off in offsets {
            process_failed_timestamps(&mut legacy, now + off, findtime);
            // 新实现的 observe 用注入的 `now`；把时间戳按同样的偏移写入。
            window.observe(ip, now + off, u32::try_from(findtime).unwrap(), 1_000);

            let legacy_count = count_recent(&legacy, findtime, u32::MAX);
            let new_count = window.peek(ip, now, u32::try_from(findtime).unwrap(), u32::MAX);
            assert_eq!(
                new_count, legacy_count,
                "窗口计数不一致（off={off}）: 新 {new_count} vs 旧 {legacy_count}"
            );
        }

        // 上限一致性：两者都不得超过 MAX_FAILED_TIMESTAMPS。
        assert!(legacy.timestamps.len() <= MAX_FAILED_TIMESTAMPS);
    }
}
