/* 本文件由 contract/gen.py 从 .fwidl 生成，请勿手改。 */
/* 单一真相源: netlink.fwidl */

#ifndef FW_CONTRACT_NETLINK_UAPI_H
#define FW_CONTRACT_NETLINK_UAPI_H

#include <linux/types.h>

#define FW_NL_MAGIC 0x46574C4EU

typedef __u8 addr16[16];

enum fw_addr_family {
    FW_ADDR_FAMILY_INET = 2,
    FW_ADDR_FAMILY_INET6 = 10,
};
/* 枚举底层宽度 u8 -> __u8 */

enum fw_ban_action {
    FW_BAN_ACTION_BAN = 1,
    FW_BAN_ACTION_UNBAN = 2,
};
/* 枚举底层宽度 u8 -> __u8 */

enum fw_whitelist_action {
    FW_WHITELIST_ACTION_ADD = 1,
    FW_WHITELIST_ACTION_REMOVE = 2,
};
/* 枚举底层宽度 u8 -> __u8 */

enum fw_msg_type {
    FW_MSG_TYPE_DDOS_EVENT = 1,
    FW_MSG_TYPE_BAN_IP = 2,
    FW_MSG_TYPE_UNBAN_IP = 3,
    FW_MSG_TYPE_SET_CONFIG = 4,
    FW_MSG_TYPE_BAN_STATE_CHANGE = 5,
    FW_MSG_TYPE_LIST_BANS_QUERY = 6,
    FW_MSG_TYPE_LIST_BANS_RESPONSE = 7,
    FW_MSG_TYPE_STATS_QUERY = 8,
    FW_MSG_TYPE_STATS_RESPONSE = 9,
    FW_MSG_TYPE_LIST_WHITELIST_QUERY = 10,
    FW_MSG_TYPE_LIST_WHITELIST_RESPONSE = 11,
    FW_MSG_TYPE_ADD_WHITELIST = 12,
    FW_MSG_TYPE_REMOVE_WHITELIST = 13,
    FW_MSG_TYPE_CONFIG_ACK = 14,
    FW_MSG_TYPE_LIST_RATES_QUERY = 15,
    FW_MSG_TYPE_LIST_RATES_RESPONSE = 16,
    FW_MSG_TYPE_WHITELIST_STATE_CHANGE = 17,
    FW_MSG_TYPE_CMD_RESULT = 18,
    FW_MSG_TYPE_CONFIG_CHANGE = 19,
    FW_MSG_TYPE_ANALYSIS_QUERY = 20,
    FW_MSG_TYPE_ANALYSIS_RESPONSE = 21,
    FW_MSG_TYPE_DAEMON_REGISTER = 22,
    FW_MSG_TYPE_DAEMON_REGISTER_ACK = 23,
    FW_MSG_TYPE_SET_PROTECTED_PORTS = 24,
};
/* 枚举底层宽度 u16 -> __u16 */

#define FW_CONFIG_FLAGS_BAN_TIME (1U << 0)
#define FW_CONFIG_FLAGS_RATE_WINDOW (1U << 1)
#define FW_CONFIG_FLAGS_MAX_PPS (1U << 2)
#define FW_CONFIG_FLAGS_MAX_BPS (1U << 3)
#define FW_CONFIG_FLAGS_MAX_SYN (1U << 4)
#define FW_CONFIG_FLAGS_MAX_UDP (1U << 5)
#define FW_CONFIG_FLAGS_MAX_ICMP (1U << 6)
#define FW_CONFIG_FLAGS_MAX_ACK (1U << 7)
#define FW_CONFIG_FLAGS_MAX_RST (1U << 8)
#define FW_CONFIG_FLAGS_MAX_FIN (1U << 9)
#define FW_CONFIG_FLAGS_DYNAMIC_THRESHOLD (1U << 10)
#define FW_CONFIG_FLAGS_BASELINE_UPDATE (1U << 11)
#define FW_CONFIG_FLAGS_DDOS_BAN_DURATION (1U << 12)

#define FW_DYN_THRESHOLD_FLAGS_ENABLED (1U << 0)

struct fw_msg_hdr {
    __u32 magic;
    __u16 msg_type;
    __u16 msg_len;
    __u32 seq;
} __packed;
_Static_assert(sizeof(struct fw_msg_hdr) == 12, "msg_hdr 布局必须为 12 字节");

struct fw_ddos_event {
    struct fw_msg_hdr hdr;
    __u8 af;
    __u8 reason[32];
    __u32 rate_pps;
    addr16 addr;
} __packed;
_Static_assert(sizeof(struct fw_ddos_event) == 65, "ddos_event 布局必须为 65 字节");

struct fw_ban_state_change {
    struct fw_msg_hdr hdr;
    __u8 action;
    __u8 af;
    __u32 duration_secs;
    addr16 addr;
    __u8 reason[32];
    __u8 jail_name[32];
    __u64 packets_dropped;
    __u64 packets_accepted;
    __u32 current_bans;
    __u32 whitelist_count;
} __packed;
_Static_assert(sizeof(struct fw_ban_state_change) == 122, "ban_state_change 布局必须为 122 字节");

struct fw_whitelist_state_change {
    struct fw_msg_hdr hdr;
    __u8 action;
    __u8 af;
    __u8 prefix_len;
    addr16 addr;
    __u8 device[16];
    __u32 whitelist_count;
} __packed;
_Static_assert(sizeof(struct fw_whitelist_state_change) == 51, "whitelist_state_change 布局必须为 51 字节");

struct fw_cmd_result {
    struct fw_msg_hdr hdr;
    __u16 original_cmd;
    __s16 pad;
    __s32 error_code;
    __u8 af;
    addr16 addr;
} __packed;
_Static_assert(sizeof(struct fw_cmd_result) == 37, "cmd_result 布局必须为 37 字节");

struct fw_config_ack {
    struct fw_msg_hdr hdr;
    __u32 applied_flags;
    __u32 rejected_flags;
} __packed;
_Static_assert(sizeof(struct fw_config_ack) == 20, "config_ack 布局必须为 20 字节");

struct fw_config_change {
    struct fw_msg_hdr hdr;
    __u32 flags;
    __u32 ban_time;
    __u32 rate_window_seconds;
    __u64 max_packets_per_second;
    __u64 max_bytes_per_second;
    __u64 max_syn_per_second;
    __u64 max_udp_per_second;
    __u64 max_icmp_per_second;
    __u64 max_ack_per_second;
    __u64 max_rst_per_second;
    __u64 max_fin_per_second;
    __u32 dynamic_threshold_flags;
    __u32 dynamic_threshold_ratio_x100;
    __u64 baseline_pps;
    __u64 baseline_bps;
    __u32 ddos_ban_duration;
} __packed;
_Static_assert(sizeof(struct fw_config_change) == 116, "config_change 布局必须为 116 字节");

struct fw_ban_entry {
    __u8 af;
    __u8 is_permanent;
    __u32 duration_secs;
    __u64 banned_at;
    addr16 addr;
    __u8 jail_name[32];
    __u8 reason[32];
} __packed;
_Static_assert(sizeof(struct fw_ban_entry) == 94, "ban_entry 布局必须为 94 字节");

struct fw_list_bans_response {
    struct fw_msg_hdr hdr;
    __u32 count;
    __u32 total;
    __u32 offset;
} __packed;
_Static_assert(sizeof(struct fw_list_bans_response) == 24, "list_bans_response 布局必须为 24 字节");
/* 其后紧跟 count 个 struct fw_ban_entry；u16 长度上限内最多 696 条 */

struct fw_stats_response {
    struct fw_msg_hdr hdr;
    __u64 current_bans;
    __u64 total_bans;
    __u64 total_unbans;
    __u64 whitelist_count;
    __u64 packets_dropped;
    __u64 packets_accepted;
} __packed;
_Static_assert(sizeof(struct fw_stats_response) == 60, "stats_response 布局必须为 60 字节");

struct fw_whitelist_entry {
    __u8 af;
    __u8 prefix_len;
    addr16 addr;
    __u8 device[16];
} __packed;
_Static_assert(sizeof(struct fw_whitelist_entry) == 34, "whitelist_entry 布局必须为 34 字节");

struct fw_list_whitelist_response {
    struct fw_msg_hdr hdr;
    __u32 count;
    __u32 total;
    __u32 offset;
} __packed;
_Static_assert(sizeof(struct fw_list_whitelist_response) == 24, "list_whitelist_response 布局必须为 24 字节");
/* 其后紧跟 count 个 struct fw_whitelist_entry；u16 长度上限内最多 1926 条 */

struct fw_rate_entry {
    __u8 af;
    __u8 pad[3];
    __u64 packets;
    __u64 bytes;
    __u64 syn_packets;
    __u64 udp_packets;
    __u64 icmp_packets;
    __u64 ack_packets;
    __u64 rst_packets;
    __u64 fin_packets;
    addr16 addr;
} __packed;
_Static_assert(sizeof(struct fw_rate_entry) == 84, "rate_entry 布局必须为 84 字节");

struct fw_list_rates_response {
    struct fw_msg_hdr hdr;
    __u32 count;
    __u32 total;
    __u32 offset;
    __u64 global_pps;
    __u64 global_bps;
} __packed;
_Static_assert(sizeof(struct fw_list_rates_response) == 40, "list_rates_response 布局必须为 40 字节");
/* 其后紧跟 count 个 struct fw_rate_entry；u16 长度上限内最多 779 条 */

struct fw_udp_port_item {
    __u16 port;
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_secs;
} __packed;
_Static_assert(sizeof(struct fw_udp_port_item) == 26, "udp_port_item 布局必须为 26 字节");

struct fw_icmp_type_item {
    __u8 type;
    __u8 code;
    __u64 packets;
    __u64 bytes;
    __u64 last_seen_secs;
} __packed;
_Static_assert(sizeof(struct fw_icmp_type_item) == 26, "icmp_type_item 布局必须为 26 字节");

struct fw_scanner_item {
    __u8 af;
    __u8 pad[3];
    addr16 addr;
    __u32 metric;
    __u64 packets;
} __packed;
_Static_assert(sizeof(struct fw_scanner_item) == 32, "scanner_item 布局必须为 32 字节");

struct fw_analysis_response {
    struct fw_msg_hdr hdr;
    __u64 pkt_sizes[5];
    __u64 ttl_dist[6];
    __u64 ip_frag_total;
    __u64 ip_frag_count;
    __u32 udp_port_count;
    __u32 udp_port_capacity;
    struct fw_udp_port_item udp_ports[64];
    __u32 icmp_type_count;
    __u32 icmp_type_capacity;
    struct fw_icmp_type_item icmp_types[64];
    __u32 port_scan_count;
    __u32 port_scan_threshold;
    struct fw_scanner_item port_scanners[20];
    __u32 service_probe_count;
    __u32 service_probe_threshold;
    struct fw_scanner_item service_probes[20];
} __packed;
_Static_assert(sizeof(struct fw_analysis_response) == 4756, "analysis_response 布局必须为 4756 字节");

struct fw_daemon_register_ack {
    struct fw_msg_hdr hdr;
    __u8 accepted;
} __packed;
_Static_assert(sizeof(struct fw_daemon_register_ack) == 13, "daemon_register_ack 布局必须为 13 字节");

struct fw_ban_ip {
    struct fw_msg_hdr hdr;
    __u8 af;
    __u32 duration_secs;
    addr16 addr;
    __u8 reason[32];
} __packed;
_Static_assert(sizeof(struct fw_ban_ip) == 65, "ban_ip 布局必须为 65 字节");

struct fw_unban_ip {
    struct fw_msg_hdr hdr;
    __u8 af;
    __u32 duration_secs;
    addr16 addr;
    __u8 reason[32];
} __packed;
_Static_assert(sizeof(struct fw_unban_ip) == 65, "unban_ip 布局必须为 65 字节");

struct fw_set_config {
    struct fw_msg_hdr hdr;
    __u32 flags;
    __u32 ban_time;
    __u32 rate_window_seconds;
    __u64 max_packets_per_second;
    __u64 max_bytes_per_second;
    __u64 max_syn_per_second;
    __u64 max_udp_per_second;
    __u64 max_icmp_per_second;
    __u64 max_ack_per_second;
    __u64 max_rst_per_second;
    __u64 max_fin_per_second;
    __u32 dynamic_threshold_flags;
    __u32 dynamic_threshold_ratio_x100;
    __u64 baseline_pps;
    __u64 baseline_bps;
    __u32 ddos_ban_duration;
} __packed;
_Static_assert(sizeof(struct fw_set_config) == 116, "set_config 布局必须为 116 字节");

struct fw_set_protected_ports {
    struct fw_msg_hdr hdr;
    __u32 count;
    __u8 bitmap[8192];
} __packed;
_Static_assert(sizeof(struct fw_set_protected_ports) == 8208, "set_protected_ports 布局必须为 8208 字节");

struct fw_list_bans_query {
    struct fw_msg_hdr hdr;
    __u32 offset;
    __u32 limit;
} __packed;
_Static_assert(sizeof(struct fw_list_bans_query) == 20, "list_bans_query 布局必须为 20 字节");

struct fw_list_whitelist_query {
    struct fw_msg_hdr hdr;
    __u32 offset;
    __u32 limit;
} __packed;
_Static_assert(sizeof(struct fw_list_whitelist_query) == 20, "list_whitelist_query 布局必须为 20 字节");

struct fw_list_rates_query {
    struct fw_msg_hdr hdr;
    __u32 offset;
    __u32 limit;
} __packed;
_Static_assert(sizeof(struct fw_list_rates_query) == 20, "list_rates_query 布局必须为 20 字节");

struct fw_add_whitelist {
    struct fw_msg_hdr hdr;
    __u8 af;
    __u8 prefix_len;
    addr16 addr;
    __u8 device[16];
} __packed;
_Static_assert(sizeof(struct fw_add_whitelist) == 46, "add_whitelist 布局必须为 46 字节");

struct fw_remove_whitelist {
    struct fw_msg_hdr hdr;
    __u8 af;
    __u8 prefix_len;
    addr16 addr;
    __u8 device[16];
} __packed;
_Static_assert(sizeof(struct fw_remove_whitelist) == 46, "remove_whitelist 布局必须为 46 字节");

struct fw_stats_query {
    struct fw_msg_hdr hdr;
} __packed;
_Static_assert(sizeof(struct fw_stats_query) == 12, "stats_query 布局必须为 12 字节");

struct fw_analysis_query {
    struct fw_msg_hdr hdr;
} __packed;
_Static_assert(sizeof(struct fw_analysis_query) == 12, "analysis_query 布局必须为 12 字节");

struct fw_daemon_register {
    struct fw_msg_hdr hdr;
} __packed;
_Static_assert(sizeof(struct fw_daemon_register) == 12, "daemon_register 布局必须为 12 字节");

#endif /* FW_CONTRACT_NETLINK_UAPI_H */
