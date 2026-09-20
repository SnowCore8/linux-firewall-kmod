//! 封禁判定的**纯函数**部分：有效阈值、渐进式时长、封禁计划。
//!
//! 这里没有任何状态，也没有锁——旧实现里这些算式与 `BAN_HISTORY`、信誉分 store、
//! `ACTIVE_BAN_CACHE` 等全局状态纠缠在一起（`failed_tracker::handle_failed_attempt_for_jail`），
//! 换个时钟或换个 IP 都要先把全局态摆好。拆成纯函数后，同一份算式可以用假定的
//! `now` / 分数直接跑对照测试，不受真实时钟与真实缓存影响。
//!
//! 判据必须与旧实现逐条一致（设计文档「冻结面 · 判定语义」）：
//!
//! - 有效阈值 = `max_retries × 高峰(1.5) × 内网(2.0) × 信誉`，再 `.ceil().max(1.0)`
//! - 信誉系数：`≥80 → 1.0`，`≥50 → 0.8`，否则 `0.5`
//! - 渐进式时长：第 1 次 `base`，第 2 次 `1800`，第 3 次 `86400`，第 4 次起 `0`（永久）
//! - `ban_time < 0` 即配置级永久；`progressive == 0 && 已封禁 ≥3 次` 亦为永久

use std::net::IpAddr;

/// 高峰期时长系数（业务高峰 9–18 点 UTC）。
const PEAK_HOURS_MULTIPLIER: f64 = 1.5;
/// 内网来源时长系数。
const INTERNAL_SOURCE_MULTIPLIER: f64 = 2.0;

/// 是否处于判定用的「业务高峰期」。
///
/// 只接受小时数（UTC，`0..=23`），时间源由调用方提供——这样本判据可被固定小时数的
/// 测试完全覆盖，不依赖跑测试时的真实时钟（旧实现直接读 `chrono::Utc::now()`）。
#[must_use]
pub fn is_peak_hours(hour_utc: u32) -> bool {
    (9..18).contains(&hour_utc)
}

/// 信誉分 → 阈值系数：分越高越宽松。
#[must_use]
pub fn reputation_multiplier(score: u32) -> f64 {
    if score >= 80 {
        1.0
    } else if score >= 50 {
        0.8
    } else {
        0.5
    }
}

/// 是否为内网（私有）地址，即「来源可信度较高、阈值可放宽」的来源。
///
/// 与旧 `ban::is_internal_ip` 判据一致：v4 的 `10/8`、`172.16/12`、`192.168/16`；
/// v6 的 `fc00::/7`（ULA）。
#[must_use]
pub fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xFE00) == 0xFC00,
    }
}

/// 计算有效失败阈值（达到即触发封禁）。
///
/// 三项系数**相乘**后 `ceil`，并至少为 1——保证任何配置下都存在触发点，
/// 不会出现「阈值 0 导致永不封禁」或「阈值 0 导致每次失败都封禁」的歧义。
#[must_use]
pub fn effective_threshold(
    max_retries: u32,
    peak_hours: bool,
    internal: bool,
    reputation_score: u32,
) -> u32 {
    let peak = if peak_hours {
        PEAK_HOURS_MULTIPLIER
    } else {
        1.0
    };
    let source = if internal {
        INTERNAL_SOURCE_MULTIPLIER
    } else {
        1.0
    };
    let reputation = reputation_multiplier(reputation_score);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    // `max_retries` 最大 u32::MAX，乘 3 后远小于 2^53（f64 精确整数范围），
    // 且非负；`as u32` 在超界时按 Rust 语义饱和，与旧实现同款转换。
    let value = (f64::from(max_retries) * peak * source * reputation)
        .ceil()
        .max(1.0) as u32;
    value
}

/// 渐进式封禁时长：按**此前**已封禁次数决定本次时长。
///
/// - `prior_ban_count == 0`（首次）→ `base_duration`
/// - `== 1` → 1800 秒
/// - `== 2` → 86400 秒
/// - `>= 3` → 0（永久）
#[must_use]
pub fn progressive_duration(base_duration: u32, prior_ban_count: u32) -> u32 {
    match prior_ban_count {
        0 => base_duration,
        1 => 1800,
        2 => 86400,
        _ => 0,
    }
}

/// 一次封禁的完整计划（不涉及任何 IO，便于对照与快照）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanPlan {
    /// 下发给内核的封禁时长（秒）；`0` 表示永久。
    pub duration: u64,
    /// 是否永久封禁。
    pub is_permanent: bool,
    /// 过期时刻（Unix 秒）；永久封禁为 `0`。
    pub expires_at: i64,
    /// 本次封禁后的累计封禁次数（即旧 `BanInfo.ban_count`）。
    pub ban_count: u32,
    /// 触发本次封禁的失败次数。
    pub fail_count: u32,
    /// 渐进式时长（`0` 表示永久或退化情形）。
    pub progressive_duration: u32,
}

/// 依据配置与历史，算出本次封禁的参数。
///
/// # Arguments
/// - `ban_time`: jail 配置的封禁时长；**负值**表示配置级永久封禁
/// - `prior_ban_count`: 此前该 IP 已封禁次数（来自封禁历史）
/// - `now`: 当前 Unix 秒（由调用方提供，保证本函数纯粹）
/// - `fail_count`: 触发本次封禁的窗口内失败次数
#[must_use]
pub fn plan_ban(ban_time: i32, prior_ban_count: u32, now: i64, fail_count: u32) -> BanPlan {
    let base_duration = if ban_time < 0 {
        0
    } else {
        #[allow(clippy::cast_sign_loss)]
        // `ban_time >= 0` 已由上游分支排除负值。
        let d = ban_time as u32;
        d
    };

    let progressive = progressive_duration(base_duration, prior_ban_count);
    // 配置级永久（ban_time < 0），或渐进式升级到永久（第 4 次起）。
    let is_permanent = ban_time < 0 || (progressive == 0 && prior_ban_count >= 3);

    let expires_at = if is_permanent {
        0
    } else if progressive > 0 {
        now + i64::from(progressive)
    } else {
        // progressive == 0 但非永久：`ban_time == 0` 的退化情形。
        // 用 base 兜底并至少 1 秒，避免「0 秒即过期」导致封禁形同虚设。
        now + i64::from(base_duration.max(1))
    };

    BanPlan {
        duration: if is_permanent {
            0
        } else {
            u64::from(progressive)
        },
        is_permanent,
        expires_at,
        ban_count: prior_ban_count + 1,
        fail_count,
        progressive_duration: progressive,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("测试用 IP 必须合法")
    }

    #[test]
    fn peak_hours_window_is_9_to_17_inclusive() {
        assert!(!is_peak_hours(8));
        assert!(is_peak_hours(9));
        assert!(is_peak_hours(17));
        assert!(!is_peak_hours(18));
    }

    #[test]
    fn reputation_multiplier_thresholds() {
        assert!((reputation_multiplier(100) - 1.0).abs() < f64::EPSILON);
        assert!((reputation_multiplier(80) - 1.0).abs() < f64::EPSILON);
        assert!((reputation_multiplier(79) - 0.8).abs() < f64::EPSILON);
        assert!((reputation_multiplier(50) - 0.8).abs() < f64::EPSILON);
        assert!((reputation_multiplier(49) - 0.5).abs() < f64::EPSILON);
        assert!((reputation_multiplier(0) - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn internal_detection_matches_legacy_ranges() {
        for private in [
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "fd00::1",
        ] {
            assert!(is_internal(ip(private)), "{private} 应判为内网");
        }
        for public in [
            "11.0.0.1",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.1.1",
            "2001:db8::1",
        ] {
            assert!(!is_internal(ip(public)), "{public} 不应判为内网");
        }
    }

    #[test]
    fn effective_threshold_combines_three_factors() {
        // 基准：无高峰、外网、信誉满 → 就是 max_retries 本身。
        assert_eq!(effective_threshold(3, false, false, 100), 3);
        // 高峰 ×1.5：3 → 4.5 → ceil → 5
        assert_eq!(effective_threshold(3, true, false, 100), 5);
        // 内网 ×2.0：3 → 6
        assert_eq!(effective_threshold(3, false, true, 100), 6);
        // 三项叠加：3 × 1.5 × 2.0 × 0.5 = 4.5 → 5
        assert_eq!(effective_threshold(3, true, true, 0), 5);
        // 下限恒为 1：max_retries = 0 也不能变成「永不触发」以外的语义。
        assert_eq!(effective_threshold(0, false, false, 0), 1);
    }

    #[test]
    fn progressive_ladder_is_exact() {
        assert_eq!(progressive_duration(600, 0), 600);
        assert_eq!(progressive_duration(600, 1), 1800);
        assert_eq!(progressive_duration(600, 2), 86400);
        assert_eq!(progressive_duration(600, 3), 0);
        assert_eq!(progressive_duration(600, 99), 0);
    }

    #[test]
    fn plan_ban_first_offense_uses_base_duration() {
        let plan = plan_ban(600, 0, 1_000_000, 5);
        assert_eq!(plan.duration, 600);
        assert!(!plan.is_permanent);
        assert_eq!(plan.expires_at, 1_000_600);
        assert_eq!(plan.ban_count, 1);
        assert_eq!(plan.fail_count, 5);
    }

    #[test]
    fn plan_ban_escalates_then_goes_permanent() {
        let second = plan_ban(600, 1, 0, 5);
        assert_eq!(second.duration, 1800);
        assert!(!second.is_permanent);

        let third = plan_ban(600, 2, 0, 5);
        assert_eq!(third.duration, 86400);
        assert!(!third.is_permanent);

        let fourth = plan_ban(600, 3, 0, 5);
        assert_eq!(fourth.duration, 0);
        assert!(fourth.is_permanent, "第 4 次必须升级为永久");
        assert_eq!(fourth.expires_at, 0);
        assert_eq!(fourth.ban_count, 4);
    }

    #[test]
    fn negative_ban_time_is_config_level_permanent() {
        let plan = plan_ban(-1, 0, 123, 5);
        assert!(plan.is_permanent);
        assert_eq!(plan.duration, 0);
        assert_eq!(plan.expires_at, 0);
        assert_eq!(plan.ban_count, 1, "永久封禁同样计入历史次数");
    }

    #[test]
    fn zero_ban_time_degrades_to_one_second_not_zero() {
        // ban_time == 0 且首次：progressive == base == 0，非永久，
        // 必须兜底到 1 秒，否则封禁会「立刻过期」。
        let plan = plan_ban(0, 0, 500, 5);
        assert!(!plan.is_permanent);
        assert_eq!(plan.expires_at, 501);
        assert_eq!(plan.progressive_duration, 0);
    }

    /// 运行期对照：与旧 `BanHistory::calculate_progressive_duration` 及
    /// `handle_failed_attempt_for_jail` 里内联的「永久判据 / 过期时刻」算式，在同一批
    /// 输入上必须逐一相等。旧模块在 2.C 收尾时删除，本测试同时退役。
    #[test]
    fn parity_with_legacy_ban_arithmetic() {
        use crate::types::BanHistory;

        // 旧实现按「已封禁次数」取渐进时长；新实现把它拆成纯函数，两侧喂同一计数。
        for prior in 0..5u32 {
            let h = BanHistory::new();
            for _ in 0..prior {
                h.record_ban("9.9.9.9", false);
            }
            let legacy_count = h.get_ban_count("9.9.9.9");
            assert_eq!(legacy_count, prior, "构造的历史次数应与预期一致");

            for base in [0u32, 600, 3600] {
                let legacy_progressive = h.calculate_progressive_duration("9.9.9.9", base);
                assert_eq!(
                    progressive_duration(base, prior),
                    legacy_progressive,
                    "渐进时长不一致: prior={prior} base={base}"
                );
            }
        }

        // 旧 `handle_failed_attempt_for_jail` 中永久判据与过期时刻的原文算式：
        //   is_permanent = jail.ban_time < 0 || (progressive == 0 && ban_count >= 3)
        //   expires_at   = 0 若永久；progressive > 0 则 now + progressive；
        //                  否则 now + base_duration.max(1)
        // 逐条搬来对比 `plan_ban`，确保重构没有改变任一分支。
        let now = 1_700_000_000_i64;
        for ban_time in [-1_i32, 0, 600, 3600] {
            for prior in 0..5u32 {
                let base_duration = if ban_time < 0 { 0u32 } else { ban_time as u32 };
                let progressive = progressive_duration(base_duration, prior);
                let legacy_permanent = ban_time < 0 || (progressive == 0 && prior >= 3);
                let legacy_expires = if legacy_permanent {
                    0
                } else if progressive > 0 {
                    now + i64::from(progressive)
                } else {
                    now + i64::from(base_duration.max(1))
                };
                let legacy_duration = if legacy_permanent {
                    0u64
                } else {
                    u64::from(progressive)
                };

                let plan = plan_ban(ban_time, prior, now, 7);
                assert_eq!(
                    plan.is_permanent, legacy_permanent,
                    "永久判据: bt={ban_time} prior={prior}"
                );
                assert_eq!(
                    plan.expires_at, legacy_expires,
                    "过期时刻: bt={ban_time} prior={prior}"
                );
                assert_eq!(
                    plan.duration, legacy_duration,
                    "时长: bt={ban_time} prior={prior}"
                );
                assert_eq!(plan.ban_count, prior + 1);
            }
        }
    }
}
