#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
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
#include <linux/ipv6.h>
#include <linux/inetdevice.h>
#include <linux/if_addr.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>

/* Debug level control - define DEBUG_LEVEL to enable various debug messages */
#ifdef DEBUG_LEVEL
#define FW_DEBUG(level, fmt, args...) \
    do { \
        if (DEBUG_LEVEL >= level) \
            printk(KERN_DEBUG "firewall: [%s:%d] " fmt "\n", __func__, __LINE__, ##args); \
    } while (0)
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

/* IP address union to support both IPv4 and IPv6 */
union ip_address {
    __be32 ipv4;              /* IPv4 address in network byte order */
    struct in6_addr ipv6;      /* IPv6 address structure */
};

/* IP type enum */
enum ip_type {
    IPV4_ADDR = 0,
    IPV6_ADDR = 1
};

/* Whitelist entry structure */
struct whitelist_entry {
    union ip_address ip;
    enum ip_type type;         /* IP address type: IPv4 or IPv6 */
    union ip_address mask;     /* Network mask for subnets */
    char device_name[16];  /* Network device name (e.g., eth0) */
    struct hlist_node hash;  /* Hash table node */
    struct rcu_head rcu_head;  /* For RCU-based freeing */
};

/* Ban entry structure */
struct ban_entry {
    union ip_address ip;
    enum ip_type type;         /* IP address type: IPv4 or IPv6 */
    unsigned long ban_time;    /* when the IP was banned */
    unsigned long unban_time;  /* when to unban */
    atomic_t retry_count;
    struct hlist_node hash;
    struct rcu_head rcu_head;  /* For RCU-based freeing */
    bool being_freed;          /* 防止双重释放标记 - 在 cleanup_expired_bans 中标记正在释放的条目 */
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
    unsigned long last_flood_check;
    int recent_additions;
    spinlock_t flood_lock;

    /* Whitelist hash table */
    DECLARE_HASHTABLE(whitelist_table, WHITELIST_HASH_BITS);
    spinlock_t whitelist_lock;
    atomic_t whitelist_count;

    /* Procfs entries */
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_ban_list;
    struct proc_dir_entry *proc_add_ban;
    struct proc_dir_entry *proc_remove_ban;
    struct proc_dir_entry *proc_settings;
    struct proc_dir_entry *proc_whitelist;
    struct proc_dir_entry *proc_whitelist_add;
    struct proc_dir_entry *proc_whitelist_remove;
    struct proc_dir_entry *proc_config;
};

/* Function declarations */
int ban_ip_v4(struct firewall_info *fw, __be32 ip);
int ban_ip_v6(struct firewall_info *fw, const struct in6_addr *ip);
int unban_ip_v4(struct firewall_info *fw, __be32 ip);
int unban_ip_v6(struct firewall_info *fw, const struct in6_addr *ip);
int is_banned_v4(struct firewall_info *fw, __be32 ip);
int is_banned_v6(struct firewall_info *fw, const struct in6_addr *ip);
void cleanup_expired_bans(struct firewall_info *fw);

/* Whitelist functions */
int add_whitelist_entry_v4(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name);
int add_whitelist_entry_v6(struct firewall_info *fw, const struct in6_addr *ip, const struct in6_addr *mask, const char *dev_name);
int remove_whitelist_entry_v4(struct firewall_info *fw, __be32 ip);
int remove_whitelist_entry_v6(struct firewall_info *fw, const struct in6_addr *ip);
bool is_in_whitelist_v4(struct firewall_info *fw, __be32 ip);
bool is_in_whitelist_v6(struct firewall_info *fw, const struct in6_addr *ip);
void auto_discover_system_ips(struct firewall_info *fw);

int create_procfs_entries(struct firewall_info *fw);
void destroy_procfs_entries(struct firewall_info *fw);

#endif /* FIREWALL_H */
