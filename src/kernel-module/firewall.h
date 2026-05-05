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
#include <linux/overflow.h>
#include <linux/workqueue.h>

/* ============================================================================
 * 统一日志系统
 * ============================================================================
 * 日志级别:
 *   FW_LOG_LEVEL_NONE  (0) - 无日志
 *   FW_LOG_LEVEL_ERR   (1) - 错误日志 - 始终输出
 *   FW_LOG_LEVEL_WARN  (2) - 警告日志 - 重要警告
 *   FW_LOG_LEVEL_INFO  (3) - 信息日志 - 正常操作
 *   FW_LOG_LEVEL_DEBUG (4) - 调试日志 - 开发调试
 *
 * 用法:
 *   fw_pr_err(fmt, ...)    - 错误级别 (始终输出)
 *   fw_pr_warn(fmt, ...)   - 警告级别
 *   fw_pr_info(fmt, ...)   - 信息级别
 *   fw_pr_debug(fmt, ...)  - 调试级别 (由 DEBUG_LEVEL 控制)
 *   fw_log(level, fmt, ...) - 动态级别日志
 *
 * 向后兼容:
 *   FW_DEBUG(level, fmt, args...) - 遗留宏，映射到新系统
 * ========================================================================== */

/* 日志级别定义 */
#define FW_LOG_LEVEL_NONE   0  /* 无日志 */
#define FW_LOG_LEVEL_ERR    1  /* 错误日志 - 始终输出 */
#define FW_LOG_LEVEL_WARN   2  /* 警告日志 - 重要警告 */
#define FW_LOG_LEVEL_INFO   3  /* 信息日志 - 正常操作 */
#define FW_LOG_LEVEL_DEBUG  4  /* 调试日志 - 开发调试 */

/* 统一日志宏 - 使用 pr_* 系列 (推荐) */
#define fw_pr_err(fmt, ...) \
    pr_err("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn(fmt, ...) \
    pr_warn("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_info(fmt, ...) \
    pr_info("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug(fmt, ...) \
    pr_debug("firewall: " fmt, ##__VA_ARGS__)

/* 限流变体，用于高频日志 */
#define fw_pr_info_ratelimited(fmt, ...) \
    pr_info_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn_ratelimited(fmt, ...) \
    pr_warn_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_err_ratelimited(fmt, ...) \
    pr_err_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug_ratelimited(fmt, ...) \
    pr_debug_ratelimited("firewall: " fmt, ##__VA_ARGS__)

/* 动态级别日志宏 - 由编译时 DEBUG_LEVEL 控制 */
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

/* 遗留 FW_DEBUG 宏兼容性 - 将旧级别 1-3 映射到新系统 */
#ifdef DEBUG_LEVEL
#define FW_DEBUG(level, fmt, args...) \
    fw_log(FW_LOG_LEVEL_DEBUG - (level) + 1, fmt, ##args)
#else
#define FW_DEBUG(level, fmt, args...) \
    do { } while (0)
#endif

#define BAN_HASH_BITS 10
#define MAX_BAN_ENTRIES (1 << BAN_HASH_BITS)  /* 1024 个条目 */
#define DEFAULT_BAN_TIME 600  /* 10 分钟（秒） */
#define MAX_BAN_TIME (365 * 24 * 60 * 60)  /* 最大 1 年，防止溢出 */
#define MIN_BAN_TIME 30  /* 最小 30 秒，避免过多的定时器开销 */

/* 白名单哈希表结构 */
#define WHITELIST_HASH_BITS 6
#define MAX_WHITELIST_ENTRIES (1 << WHITELIST_HASH_BITS)  /* 64 个条目 */

/* 自动发现 IP 的最大数量（与白名单容量一致） */
#define MAX_DISCOVERED_IPS MAX_WHITELIST_ENTRIES

/* 白名单条目结构 - 仅 IPv4 */
struct whitelist_entry {
    __be32 ip;                 /* IPv4 地址，网络字节序 */
    __be32 mask;               /* 子网掩码 */
    char device_name[16];      /* 网络设备名称（如 eth0） */
    struct hlist_node hash;    /* 哈希表节点 */
    struct rcu_head rcu_head;  /* 用于 RCU 释放 */
};

/* 封禁条目结构 - 仅 IPv4 */
struct ban_entry {
    __be32 ip;                 /* IPv4 地址，网络字节序 */
    unsigned long ban_time;    /* IP 被封禁的时间 */
    unsigned long unban_time;  /* 解除封禁的时间（0 = 永久） */
    atomic_t retry_count;       /* 保留供将来使用 */
    bool is_permanent;         /* 永久封禁标志 */
    struct hlist_node hash;
    struct rcu_head rcu_head;  /* 用于 RCU 释放 */
};

/* 全局防火墙结构 */
struct firewall_info {
    DECLARE_HASHTABLE(ban_table, BAN_HASH_BITS);
    spinlock_t lock;
    atomic_t ban_count;
    atomic_t shutting_down;  /* 防止关闭期间定时器触发的标志 */
    unsigned int ban_time;
    struct timer_list cleanup_timer;
    bool timer_initialized;  /* 跟踪定时器是否已初始化 */
    int cleanup_last_bucket; /* 修复 4.1：跟踪上次处理的桶，用于增量清理
                              * 注意：仅由定时器回调（单线程上下文）访问，无需原子操作 */

    /* 泛洪保护 */
    spinlock_t flood_lock;
    unsigned long last_flood_check;
    unsigned int recent_additions;

    /* 统计计数器 */
    atomic_t total_ban_count;          /* 累计封禁操作次数 */
    atomic_t total_unban_count;        /* 累计解封操作次数 */
    atomic_t whitelist_reject_count;   /* 被白名单拒绝的封禁 */
    atomic_t ban_table_full_count;     /* 封禁表已满的拒绝次数 */
    atomic_t alloc_failure_count;      /* 内存分配失败次数 */
    atomic_t packets_dropped;          /* 被 netfilter 丢弃的数据包 */
    atomic_t packets_accepted;         /* 被 netfilter 接受的数据包 */
    atomic_t cleanup_cycles;           /* 清理定时器周期数 */
    atomic_t cleanup_expired_total;    /* 已清理的过期条目总数 */

    /* 白名单哈希表 */
    DECLARE_HASHTABLE(whitelist_table, WHITELIST_HASH_BITS);
    spinlock_t whitelist_lock;
    atomic_t whitelist_count;

    /* procfs 条目 */
    struct proc_dir_entry *proc_dir;
    struct proc_dir_entry *proc_bans;        /* 统一封禁接口（读/写） */
    struct proc_dir_entry *proc_whitelist;   /* 统一白名单接口（读/写） */
    struct proc_dir_entry *proc_config;      /* 配置（读/写） */
    struct proc_dir_entry *proc_settings;
    struct proc_dir_entry *proc_stats;       /* 统计端点（只读） */

    /* 网络事件监听器 */
    struct notifier_block netdev_notifier;
    struct delayed_work sync_work;           /* 防抖同步工作队列 */
    bool netdev_notifier_registered;         /* 跟踪通知器是否成功注册 */
};

/* 函数声明 */
int ban_ip(struct firewall_info *fw, __be32 ip);
int ban_ip_permanent(struct firewall_info *fw, __be32 ip);
int unban_ip(struct firewall_info *fw, __be32 ip);
int unban_permanent_ip(struct firewall_info *fw, __be32 ip);
int is_banned(struct firewall_info *fw, __be32 ip);
int is_permanently_banned(struct firewall_info *fw, __be32 ip);
void cleanup_expired_bans(struct firewall_info *fw);

/* 白名单函数 */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name);
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip);
bool is_in_whitelist(struct firewall_info *fw, __be32 ip);
void auto_discover_system_ips(struct firewall_info *fw);
void sync_system_ips(struct firewall_info *fw);

/* 网络事件监听 */
int register_netdev_notifier(struct firewall_info *fw);
void unregister_netdev_notifier(struct firewall_info *fw);

int create_procfs_entries(struct firewall_info *fw);
void destroy_procfs_entries(struct firewall_info *fw);

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void);

#endif /* FIREWALL_H */
