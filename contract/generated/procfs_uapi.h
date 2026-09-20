/* 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。 */
/* 单一真相源: procfs.fwidl（文本协议契约，非二进制线格式） */

#ifndef FW_CONTRACT_PROCFS_UAPI_H
#define FW_CONTRACT_PROCFS_UAPI_H

/* procfs 根目录 */
#define FW_PROCFS_ROOT "/proc/firewall"

/* 条目路径与权限位（权限位即 proc_create 的 mode 实参） */
#define FW_PROCFS_BANS_PATH "/proc/firewall/bans"
#define FW_PROCFS_BANS_MODE 0600
#define FW_PROCFS_WHITELIST_PATH "/proc/firewall/whitelist"
#define FW_PROCFS_WHITELIST_MODE 0600
#define FW_PROCFS_CONFIG_PATH "/proc/firewall/config"
#define FW_PROCFS_CONFIG_MODE 0600
#define FW_PROCFS_STATS_PATH "/proc/firewall/stats"
#define FW_PROCFS_STATS_MODE 0400
#define FW_PROCFS_RATES_PATH "/proc/firewall/rates"
#define FW_PROCFS_RATES_MODE 0400
#define FW_PROCFS_UDP_PORTS_PATH "/proc/firewall/udp_ports"
#define FW_PROCFS_UDP_PORTS_MODE 0400
#define FW_PROCFS_ICMP_TYPES_PATH "/proc/firewall/icmp_types"
#define FW_PROCFS_ICMP_TYPES_MODE 0400
#define FW_PROCFS_PKT_SIZES_PATH "/proc/firewall/pkt_sizes"
#define FW_PROCFS_PKT_SIZES_MODE 0400
#define FW_PROCFS_TTL_DIST_PATH "/proc/firewall/ttl_dist"
#define FW_PROCFS_TTL_DIST_MODE 0400
#define FW_PROCFS_IP_FRAGS_PATH "/proc/firewall/ip_frags"
#define FW_PROCFS_IP_FRAGS_MODE 0400
#define FW_PROCFS_PORT_SCANNERS_PATH "/proc/firewall/port_scanners"
#define FW_PROCFS_PORT_SCANNERS_MODE 0400
#define FW_PROCFS_SERVICE_PROBES_PATH "/proc/firewall/service_probes"
#define FW_PROCFS_SERVICE_PROBES_MODE 0400

#define FW_PROCFS_BAN_OP_BAN_DEFAULT 0
#define FW_PROCFS_BAN_OP_BAN_TIMED 1
#define FW_PROCFS_BAN_OP_BAN_PERMANENT 2
#define FW_PROCFS_BAN_OP_UNBAN 3

#define FW_PROCFS_WHITELIST_OP_ADD 0
#define FW_PROCFS_WHITELIST_OP_ADD_IMPLICIT 1
#define FW_PROCFS_WHITELIST_OP_REMOVE 2

#define FW_PROCFS_CONFIG_PARAM_BAN_TIME 0

#define FW_PROCFS_BANS_FORM_BAN_DEFAULT "<ip>"
#define FW_PROCFS_BANS_FORM_BAN_TIMED "<ip> <seconds>"
#define FW_PROCFS_BANS_FORM_BAN_PERMANENT "<ip> 0"
#define FW_PROCFS_BANS_FORM_UNBAN "unban <ip>"

#define FW_PROCFS_WHITELIST_FORM_ADD "add <subnet>"
#define FW_PROCFS_WHITELIST_FORM_ADD_IMPLICIT "<subnet>"
#define FW_PROCFS_WHITELIST_FORM_REMOVE "remove <subnet>"

#define FW_PROCFS_CONFIG_FORM_BAN_TIME "ban_time <seconds>"

#define FW_PROCFS_KEY_TOTAL_BANS "total_bans"
#define FW_PROCFS_KEY_TOTAL_UNBANS "total_unbans"
#define FW_PROCFS_KEY_WHITELIST_REJECTS "whitelist_rejects"
#define FW_PROCFS_KEY_BAN_TABLE_FULL_REJECTS "ban_table_full_rejects"
#define FW_PROCFS_KEY_ALLOC_FAILURES "alloc_failures"
#define FW_PROCFS_KEY_PACKETS_DROPPED "packets_dropped"
#define FW_PROCFS_KEY_PACKETS_ACCEPTED "packets_accepted"
#define FW_PROCFS_KEY_TCP_ANOMALY_DROPPED "tcp_anomaly_dropped"
#define FW_PROCFS_KEY_CLEANUP_CYCLES "cleanup_cycles"
#define FW_PROCFS_KEY_CLEANUP_EXPIRED_TOTAL "cleanup_expired_total"
#define FW_PROCFS_KEY_CURRENT_BANS "current_bans"
#define FW_PROCFS_KEY_CURRENT_WHITELIST "current_whitelist"
#define FW_PROCFS_KEY_RECENT_ADDITIONS "recent_additions"

/* 容量上限；未列出的表表示实现中无条目上限 */
#define FW_PROCFS_LIMIT_BANS 65535
#define FW_PROCFS_LIMIT_WHITELIST 65535
#define FW_PROCFS_LIMIT_RATES 65536
#define FW_PROCFS_LIMIT_UDP_PORTS 512
#define FW_PROCFS_LIMIT_ICMP_TYPES 128
#define FW_PROCFS_LIMIT_PORT_SCANNERS 20
#define FW_PROCFS_LIMIT_SERVICE_PROBES 20

#endif /* FW_CONTRACT_PROCFS_UAPI_H */
