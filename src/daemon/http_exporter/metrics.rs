//! 内核统计读取 + Prometheus 指标生成

use std::sync::atomic::Ordering;

use crate::types::{now_secs, ACTIVE_BAN_CACHE, DAEMON_STATS, DDOS_STATS};

// ============================================================================
// 内核统计信息读取
// ============================================================================

/// 从内存缓存读取 4 个内核态指标：当前封禁数 / 总封禁 / 总解封 / 当前白名单数。
///
/// 程序内部走内存（`/proc/firewall/*` 是用户操作接口）。
fn read_kernel_stats() -> (u64, u64, u64, u64) {
    let banned = ACTIVE_BAN_CACHE
        .get()
        .map(|cache| cache.len() as u64)
        .unwrap_or(0);
    let total_bans = DAEMON_STATS.ips_banned.load(Ordering::Relaxed);
    let total_unbans = DAEMON_STATS.total_unbans.load(Ordering::Relaxed);
    let whitelist_count = DAEMON_STATS.whitelist_count.load(Ordering::Relaxed);
    (banned, total_bans, total_unbans, whitelist_count)
}

// ============================================================================
// 指标生成
// ============================================================================

/// 生成 Prometheus 文本格式 (`text/plain; version=0.0.4`) 的全部指标。
///
/// 包含 4 个内核态 + 13 个用户态 + 4 个 netlink 健康 + 1 个 uptime + 3 个信誉分（共 25 个）。
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

    // Netlink 健康指标
    let netlink_sent = DAEMON_STATS.netlink_messages_sent.load(Ordering::Relaxed);
    let netlink_recv = DAEMON_STATS
        .netlink_messages_received
        .load(Ordering::Relaxed);
    let netlink_send_err = DAEMON_STATS.netlink_send_errors.load(Ordering::Relaxed);
    let netlink_recv_err = DAEMON_STATS.netlink_recv_errors.load(Ordering::Relaxed);

    let start_time = DAEMON_STATS.start_time.load(Ordering::Relaxed);
    let uptime = if start_time > 0 {
        (now_secs() as u64).saturating_sub(start_time)
    } else {
        0
    };

    // IP 信誉分指标（单次 snapshot 避免双重读锁+克隆）
    let reputation_store = crate::ip_reputation::get_store();
    let reputation_snapshot = reputation_store.snapshot();
    let reputation_tracked = reputation_snapshot.len() as u64;
    let mut reputation_low = 0u64;
    let mut reputation_critical = 0u64;
    for entry in &reputation_snapshot {
        if entry.score < 50 {
            reputation_critical += 1;
            reputation_low += 1; // < 50 也是 < 80
        } else if entry.score < 80 {
            reputation_low += 1;
        }
    }

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
         # HELP firewall_netlink_messages_sent_total Total netlink messages sent to kernel\n\
         # TYPE firewall_netlink_messages_sent_total counter\n\
         firewall_netlink_messages_sent_total {netlink_sent}\n\
         \n\
         # HELP firewall_netlink_messages_received_total Total netlink messages received from kernel\n\
         # TYPE firewall_netlink_messages_received_total counter\n\
         firewall_netlink_messages_received_total {netlink_recv}\n\
         \n\
         # HELP firewall_netlink_send_errors_total Total netlink send failures\n\
         # TYPE firewall_netlink_send_errors_total counter\n\
         firewall_netlink_send_errors_total {netlink_send_err}\n\
         \n\
         # HELP firewall_netlink_recv_errors_total Total netlink receive/parse failures\n\
         # TYPE firewall_netlink_recv_errors_total counter\n\
         firewall_netlink_recv_errors_total {netlink_recv_err}\n\
         \n\
         # HELP firewall_daemon_uptime_seconds Daemon uptime in seconds\n\
         # TYPE firewall_daemon_uptime_seconds gauge\n\
         firewall_daemon_uptime_seconds {uptime}\n\
         \n\
         # HELP firewall_reputation_tracked_ips Current number of IPs tracked by reputation system\n\
         # TYPE firewall_reputation_tracked_ips gauge\n\
         firewall_reputation_tracked_ips {reputation_tracked}\n\
         \n\
         # HELP firewall_reputation_low_count IPs with reputation score below 80 (suspicious)\n\
         # TYPE firewall_reputation_low_count gauge\n\
         firewall_reputation_low_count {reputation_low}\n\
         \n\
         # HELP firewall_reputation_critical_count IPs with reputation score below 50 (high risk, stricter thresholds)\n\
         # TYPE firewall_reputation_critical_count gauge\n\
         firewall_reputation_critical_count {reputation_critical}\n\
         "
    )
}
