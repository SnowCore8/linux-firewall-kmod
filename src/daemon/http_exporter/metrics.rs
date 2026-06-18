//! 内核统计读取 + Prometheus 指标生成

use std::sync::atomic::Ordering;

use crate::types::{now_secs, DAEMON_STATS, DDOS_STATS};

// ============================================================================
// 内核统计信息读取
// ============================================================================

/// 从 `/proc/firewall/stats` 解析 4 个内核态指标:当前封禁数 / 总封禁 /
/// 总解封 / 当前白名单数。文件不存在时全部为 0。
///
/// 提前退出:4 个 key 都找到后立即 break,避免读完整文件。
///
/// # Returns
/// `(banned, total_bans, total_unbans, whitelist_count)` 元组
fn read_kernel_stats() -> (u64, u64, u64, u64) {
    let mut banned: u64 = 0;
    let mut total_bans: u64 = 0;
    let mut total_unbans: u64 = 0;
    let mut whitelist_count: u64 = 0;
    let mut has_banned = false;
    let mut has_total_bans = false;
    let mut has_total_unbans = false;
    let mut has_whitelist_count = false;

    if let Ok(content) = std::fs::read_to_string("/proc/firewall/stats") {
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() == 2 {
                if let Ok(val) = parts[1].parse::<u64>() {
                    match parts[0] {
                        "current_bans" => {
                            banned = val;
                            has_banned = true;
                        }
                        "total_bans" => {
                            total_bans = val;
                            has_total_bans = true;
                        }
                        "total_unbans" => {
                            total_unbans = val;
                            has_total_unbans = true;
                        }
                        "current_whitelist" => {
                            whitelist_count = val;
                            has_whitelist_count = true;
                        }
                        _ => {}
                    }
                    // 4 个 key 都找到后提前退出
                    if has_banned && has_total_bans && has_total_unbans && has_whitelist_count {
                        break;
                    }
                }
            }
        }
    }

    (banned, total_bans, total_unbans, whitelist_count)
}

// ============================================================================
// 指标生成
// ============================================================================

/// 生成 Prometheus 文本格式 (`text/plain; version=0.0.4`) 的全部指标。
///
/// 包含 4 个内核态 + 10 个用户态 + 1 个 `uptime` gauge。
///
/// # Returns
/// Prometheus exposition 格式字符串
///
/// # Panics
/// `SystemTime::now().duration_since(UNIX_EPOCH)` 仅在系统时钟早于
/// 1970-01-01 时 panic,实际不可能
pub(super) fn generate_metrics() -> String {
    let (banned, total_bans, total_unbans, whitelist_count) = read_kernel_stats();

    let lines_parsed = DAEMON_STATS.lines_parsed.load(Ordering::Relaxed);
    let ips_extracted = DAEMON_STATS.ips_extracted.load(Ordering::Relaxed);
    let ips_banned = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
    let failed_attempts = DAEMON_STATS.failed_attempts.load(Ordering::Relaxed);
    let config_reloads = DAEMON_STATS.config_reloads.load(Ordering::Relaxed);
    let inotify_events = DAEMON_STATS.inotify_events.load(Ordering::Relaxed);
    let log_rotations = DAEMON_STATS.log_rotations.load(Ordering::Relaxed);
    let lines_skipped = DAEMON_STATS.lines_skipped.load(Ordering::Relaxed);
    let regex_matches = DAEMON_STATS.regex_matches.load(Ordering::Relaxed);

    // DDoS 检测指标
    let ddos_events_detected = DDOS_STATS.events_detected.load(Ordering::Relaxed);
    let ddos_auto_bans = DDOS_STATS.auto_bans_triggered.load(Ordering::Relaxed);
    let ddos_tracked_ips = DDOS_STATS.tracked_ips.load(Ordering::Relaxed);

    let start_time = DAEMON_STATS.start_time.load(Ordering::Relaxed);
    let uptime = if start_time > 0 {
        now_secs() as u64 - start_time
    } else {
        0
    };

    format!(
        "# HELP firewall_kernel_banned_ips_current Current number of banned IPs in kernel\n\
         # TYPE firewall_kernel_banned_ips_current gauge\n\
         firewall_kernel_banned_ips_current {banned}\n\
         \n\
         # HELP firewall_kernel_bans_total Total number of ban operations in kernel\n\
         # TYPE firewall_kernel_bans_total counter\n\
         firewall_kernel_bans_total {total_bans}\n\
         \n\
         # HELP firewall_kernel_unbans_total Total number of unban operations in kernel\n\
         # TYPE firewall_kernel_unbans_total counter\n\
         firewall_kernel_unbans_total {total_unbans}\n\
         \n\
         # HELP firewall_kernel_whitelist_count Current number of whitelisted IPs\n\
         # TYPE firewall_kernel_whitelist_count gauge\n\
         firewall_kernel_whitelist_count {whitelist_count}\n\
         \n\
         # HELP firewall_daemon_lines_parsed_total Total log lines parsed by daemon\n\
         # TYPE firewall_daemon_lines_parsed_total counter\n\
         firewall_daemon_lines_parsed_total {lines_parsed}\n\
         \n\
         # HELP firewall_daemon_ips_extracted_total Total IP addresses extracted from logs\n\
         # TYPE firewall_daemon_ips_extracted_total counter\n\
         firewall_daemon_ips_extracted_total {ips_extracted}\n\
         \n\
         # HELP firewall_daemon_ips_banned_total Total IP addresses banned by daemon\n\
         # TYPE firewall_daemon_ips_banned_total counter\n\
         firewall_daemon_ips_banned_total {ips_banned}\n\
         \n\
         # HELP firewall_daemon_failed_attempts_total Total failed login attempts detected\n\
         # TYPE firewall_daemon_failed_attempts_total counter\n\
         firewall_daemon_failed_attempts_total {failed_attempts}\n\
         \n\
         # HELP firewall_daemon_config_reloads_total Total configuration reloads\n\
         # TYPE firewall_daemon_config_reloads_total counter\n\
         firewall_daemon_config_reloads_total {config_reloads}\n\
         \n\
         # HELP firewall_daemon_inotify_events_total Total inotify events received\n\
         # TYPE firewall_daemon_inotify_events_total counter\n\
         firewall_daemon_inotify_events_total {inotify_events}\n\
         \n\
         # HELP firewall_daemon_log_rotations_total Total log rotation events detected\n\
         # TYPE firewall_daemon_log_rotations_total counter\n\
         firewall_daemon_log_rotations_total {log_rotations}\n\
         \n\
         # HELP firewall_daemon_lines_skipped_total Total log lines skipped (too long or invalid)\n\
         # TYPE firewall_daemon_lines_skipped_total counter\n\
         firewall_daemon_lines_skipped_total {lines_skipped}\n\
         \n\
         # HELP firewall_daemon_regex_matches_total Total regex pattern matches across all jails\n\
         # TYPE firewall_daemon_regex_matches_total counter\n\
         firewall_daemon_regex_matches_total {regex_matches}\n\
         \n\
         # HELP firewall_ddos_events_detected_total Total DDoS events detected\n\
         # TYPE firewall_ddos_events_detected_total counter\n\
         firewall_ddos_events_detected_total {ddos_events_detected}\n\
         \n\
         # HELP firewall_ddos_auto_bans_total Total ban decisions made by DDoS decision engine via netlink\n\
         # TYPE firewall_ddos_auto_bans_total counter\n\
         firewall_ddos_auto_bans_total {ddos_auto_bans}\n\
         \n\
         # HELP firewall_ddos_tracked_ips_current Current number of IPs tracked for DDoS detection\n\
         # TYPE firewall_ddos_tracked_ips_current gauge\n\
         firewall_ddos_tracked_ips_current {ddos_tracked_ips}\n\
         \n\
         # HELP firewall_daemon_uptime_seconds Daemon uptime in seconds\n\
         # TYPE firewall_daemon_uptime_seconds gauge\n\
         firewall_daemon_uptime_seconds {uptime}\n\
         "
    )
}
