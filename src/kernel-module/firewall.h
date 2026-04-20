#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/hash.h>
#include <linux/timer.h>
#include <linux/rcupdate.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <uapi/linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/if_addr.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

/* ============================================================================
 * Unified Logging System
 * ============================================================================
 * Log levels:
 *   FW_LOG_LEVEL_NONE  (0) - No logging
 *   FW_LOG_LEVEL_ERR   (1) - Error logging - always output
 *   FW_LOG_LEVEL_WARN  (2) - Warning logging - important warnings
 *   FW_LOG_LEVEL_INFO  (3) - Info logging - normal operations
 *   FW_LOG_LEVEL_DEBUG (4) - Debug logging - development debugging
 *
 * Usage:
 *   fw_pr_err(fmt, ...)    - Error level (always output)
 *   fw_pr_warn(fmt, ...)   - Warning level
 *   fw_pr_info(fmt, ...)   - Info level
 *   fw_pr_debug(fmt, ...)  - Debug level (controlled by DEBUG_LEVEL)
 *   fw_log(level, fmt, ...) - Dynamic level logging
 *
 * Backward compatibility:
 *   FW_DEBUG(level, fmt, args...) - Legacy macro, mapped to new system
 * ========================================================================== */

/* Log level definitions */
#define FW_LOG_LEVEL_NONE   0  /* No logging */
#define FW_LOG_LEVEL_ERR    1  /* Error logging - always output */
#define FW_LOG_LEVEL_WARN   2  /* Warning logging - important warnings */
#define FW_LOG_LEVEL_INFO   3  /* Info logging - normal operations */
#define FW_LOG_LEVEL_DEBUG  4  /* Debug logging - development debugging */

/* Unified logging macros - use pr_* series (recommended) */
#define fw_pr_err(fmt, ...) \
    pr_err("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn(fmt, ...) \
    pr_warn("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_info(fmt, ...) \
    pr_info("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug(fmt, ...) \
    pr_debug("firewall: " fmt, ##__VA_ARGS__)

/* Rate-limited variants for high-frequency logging */
#define fw_pr_info_ratelimited(fmt, ...) \
    pr_info_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn_ratelimited(fmt, ...) \
    pr_warn_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_err_ratelimited(fmt, ...) \
    pr_err_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug_ratelimited(fmt, ...) \
    pr_debug_ratelimited("firewall: " fmt, ##__VA_ARGS__)

/* Dynamic level logging macro - controlled by DEBUG_LEVEL at compile time */
#define fw_log(level, fmt, ...) \
    do { \
        if (level <= DEBUG_LEVEL) { \
            switch (level) { \
            case FW_LOG_LEVEL_ERR: \
                fw_pr_err(fmt, ##__VA_ARGS__); break; \
            case FW_LOG_LEVEL_WARN: \
                fw_pr_warn(fmt, ##__VA_ARGS__); break; \
            case FW_LOG_LEVEL_INFO: \
                fw_pr_info(fmt, ##__VA_ARGS__); break; \
            case FW_LOG_LEVEL_DEBUG: \
                fw_pr_debug(fmt, ##__VA_ARGS__); break; \
            } \
        } \
    } while (0)

/* Legacy FW_DEBUG macro compatibility - maps old level 1-3 to new system */
#ifdef DEBUG_LEVEL
#define FW_DEBUG(level, fmt, args...) \
    fw_log(FW_LOG_LEVEL_DEBUG - (level) + 1, fmt, ##args)
#else
#define FW_DEBUG(level, fmt, args...) \
    do { } while (0)
#endif

#define BAN_HASH_BITS 10
#define MAX_BAN_ENTRIES (1 << BAN_HASH_BITS)  /* 1024 entries */
#define DEFAULT_BAN_TIME 600  /* 10 minutes in seconds */
#define DEFAULT_MAX_RETRIES 3
#define DEFAULT_FINDTIME 600  /* 10 minutes */

/* Whitelist hash table structure */
#define WHITELIST_HASH_BITS 6
#define MAX_WHITELIST_ENTRIES (1 << WHITELIST_HASH_BITS)  /* 64 entries */

/* Whitelist entry structure - IPv4 only */
struct whitelist_entry {
    __be32 ip;                 /* IPv4 address in network byte order */
    __be32 mask;               /* Network mask for subnets */
    char device_name[16];      /* Network device name (e.g., eth0) */
    struct hlist_node hash;    /* Hash table node */
    struct rcu_head rcu_head;  /* For RCU-based freeing */
};

/* Ban entry structure - IPv4 only */
struct ban_entry {
    __be32 ip;                 /* IPv4 address in network byte order */
    unsigned long ban_time;    /* when the IP was banned */
    unsigned long unban_time;  /* when to unban */
    atomic_t retry_count;
    struct hlist_node hash;
    struct rcu_head rcu_head;  /* For RCU-based freeing */
};

/* Global firewall structure */
struct firewall_info {
    DECLARE_HASHTABLE(ban_table, BAN_HASH_BITS);
    spinlock_t lock;
    atomic_t ban_count;
    atomic_t shutting_down;  /* Flag to prevent timer during shutdown */
    unsigned int ban_time;
    unsigned int max_retries;
    unsigned int findtime;
    struct timer_list cleanup_timer;
    bool timer_initialized;  /* Track if timer has been initialized */
    int cleanup_last_bucket; /* Track last processed bucket for incremental cleanup */

    /* Flood protection */
    spinlock_t flood_lock;
    unsigned long last_flood_check;
    unsigned int recent_additions;

    /* Whitelist hash table */
    DECLARE_HASHTABLE(whitelist_table, WHITELIST_HASH_BITS);
    spinlock_t whitelist_lock;
    atomic_t whitelist_count;

    /* Procfs entries */
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_ban_list;
    struct proc_dir_entry *proc_add_ban;
    struct proc_dir_entry *proc_remove_ban;
    struct proc_dir_entry *proc_whitelist;
    struct proc_dir_entry *proc_whitelist_add;
    struct proc_dir_entry *proc_whitelist_remove;
    struct proc_dir_entry *proc_config;
    struct proc_dir_entry *proc_settings;
};

/* Function declarations */
int ban_ip(struct firewall_info *fw, __be32 ip);
int unban_ip(struct firewall_info *fw, __be32 ip);
int is_banned(struct firewall_info *fw, __be32 ip);
void cleanup_expired_bans(struct firewall_info *fw);

/* Whitelist functions */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name);
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip);
bool is_in_whitelist(struct firewall_info *fw, __be32 ip);
void auto_discover_system_ips(struct firewall_info *fw);

int create_procfs_entries(struct firewall_info *fw);
void destroy_procfs_entries(struct firewall_info *fw);

#endif /* FIREWALL_H */
