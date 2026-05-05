#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/errno.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/if_addr.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/overflow.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <uapi/linux/ip.h>

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
#define FW_LOG_LEVEL_NONE 0  /* 无日志 */
#define FW_LOG_LEVEL_ERR 1   /* 错误日志 - 始终输出 */
#define FW_LOG_LEVEL_WARN 2  /* 警告日志 - 重要警告 */
#define FW_LOG_LEVEL_INFO 3  /* 信息日志 - 正常操作 */
#define FW_LOG_LEVEL_DEBUG 4 /* 调试日志 - 开发调试 */

/* 统一日志宏 - 使用 pr_* 系列 (推荐) */
#define fw_pr_err(fmt, ...) pr_err("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn(fmt, ...) pr_warn("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_info(fmt, ...) pr_info("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug(fmt, ...) pr_debug("firewall: " fmt, ##__VA_ARGS__)

/* 限流变体，用于高频日志 */
#define fw_pr_info_ratelimited(fmt, ...)                                       \
  pr_info_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_warn_ratelimited(fmt, ...)                                       \
  pr_warn_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_err_ratelimited(fmt, ...)                                        \
  pr_err_ratelimited("firewall: " fmt, ##__VA_ARGS__)
#define fw_pr_debug_ratelimited(fmt, ...)                                      \
  pr_debug_ratelimited("firewall: " fmt, ##__VA_ARGS__)

/* 动态级别日志宏 - 由编译时 DEBUG_LEVEL 控制 */
#define fw_log(level, fmt, ...)                                                \
  do {                                                                         \
    if (level <= DEBUG_LEVEL) {                                                \
      switch (level) {                                                         \
      case FW_LOG_LEVEL_ERR:                                                   \
        fw_pr_err(fmt, ##__VA_ARGS__);                                         \
        break;                                                                 \
      case FW_LOG_LEVEL_WARN:                                                  \
        fw_pr_warn(fmt, ##__VA_ARGS__);                                        \
        break;                                                                 \
      case FW_LOG_LEVEL_INFO:                                                  \
        fw_pr_info(fmt, ##__VA_ARGS__);                                        \
        break;                                                                 \
      case FW_LOG_LEVEL_DEBUG:                                                 \
        fw_pr_debug(fmt, ##__VA_ARGS__);                                       \
        break;                                                                 \
      }                                                                        \
    }                                                                          \
  } while (0)

/* 遗留 FW_DEBUG 宏兼容性 - 将旧级别 1-3 映射到新系统 */
#ifdef DEBUG_LEVEL
#define FW_DEBUG(level, fmt, args...)                                          \
  fw_log(FW_LOG_LEVEL_DEBUG - (level) + 1, fmt, ##args)
#else
#define FW_DEBUG(level, fmt, args...)                                          \
  do {                                                                         \
  } while (0)
#endif

#define BAN_HASH_BITS 12
#define MAX_BAN_ENTRIES (1 << BAN_HASH_BITS) /* 4096 个条目 */
#define DEFAULT_BAN_TIME 600                 /* 10 分钟（秒） */
#define MAX_BAN_TIME (365 * 24 * 60 * 60)    /* 最大 1 年，防止溢出 */
#define MIN_BAN_TIME 30 /* 最小 30 秒，避免过多的定时器开销 */

/* 白名单哈希表结构 */
#define WHITELIST_HASH_BITS 6
#define MAX_WHITELIST_ENTRIES (1 << WHITELIST_HASH_BITS) /* 64 个条目 */

/* 自动发现 IP 的最大数量（与白名单容量一致） */
#define MAX_DISCOVERED_IPS MAX_WHITELIST_ENTRIES

/* 白名单条目结构 - 仅 IPv4 */
struct whitelist_entry {
  __be32 ip;                /* IPv4 地址，网络字节序 */
  __be32 mask;              /* 子网掩码 */
  char device_name[16];     /* 网络设备名称（如 eth0） */
  struct hlist_node hash;   /* 哈希表节点 */
  struct rcu_head rcu_head; /* 用于 RCU 释放 */
};

/* 封禁条目结构 - 仅 IPv4 */
struct ban_entry {
  __be32 ip;                /* IPv4 地址，网络字节序 */
  unsigned long ban_time;   /* IP 被封禁的时间 */
  unsigned long unban_time; /* 解除封禁的时间（0 = 永久） */
  atomic_t retry_count;     /* 保留供将来使用 */
  bool is_permanent;        /* 永久封禁标志 */
  struct hlist_node hash;
  struct rcu_head rcu_head; /* 用于 RCU 释放 */
};

/* 全局防火墙结构 */
struct firewall_info {
  DECLARE_HASHTABLE(ban_table, BAN_HASH_BITS);
  spinlock_t lock;
  atomic_t ban_count;
  atomic_t shutting_down; /* 防止关闭期间定时器触发的标志 */
  unsigned int ban_time;
  struct timer_list cleanup_timer;
  bool timer_initialized; /* 跟踪定时器是否已初始化 */
  int cleanup_last_bucket; /* 修复 4.1：跟踪上次处理的桶，用于增量清理
                            * 注意：仅由定时器回调（单线程上下文）访问，无需原子操作
                            */

  /* 泛洪保护 */
  spinlock_t flood_lock;
  unsigned long last_flood_check;
  unsigned int recent_additions;

  /* 统计计数器 */
  atomic_t total_ban_count;        /* 累计封禁操作次数 */
  atomic_t total_unban_count;      /* 累计解封操作次数 */
  atomic_t whitelist_reject_count; /* 被白名单拒绝的封禁 */
  atomic_t ban_table_full_count;   /* 封禁表已满的拒绝次数 */
  atomic_t alloc_failure_count;    /* 内存分配失败次数 */
  atomic_t packets_dropped;        /* 被 netfilter 丢弃的数据包 */
  atomic_t packets_accepted;       /* 被 netfilter 接受的数据包 */
  atomic_t cleanup_cycles;         /* 清理定时器周期数 */
  atomic_t cleanup_expired_total;  /* 已清理的过期条目总数 */

  /* 白名单哈希表 */
  DECLARE_HASHTABLE(whitelist_table, WHITELIST_HASH_BITS);
  spinlock_t whitelist_lock;
  atomic_t whitelist_count;

  /* procfs 条目 */
  struct proc_dir_entry *proc_dir;
  struct proc_dir_entry *proc_bans;      /* 统一封禁接口（读/写） */
  struct proc_dir_entry *proc_whitelist; /* 统一白名单接口（读/写） */
  struct proc_dir_entry *proc_config;    /* 配置（读/写） */
  struct proc_dir_entry *proc_settings;
  struct proc_dir_entry *proc_stats; /* 统计端点（只读） */

  /* 网络事件监听器 */
  struct notifier_block netdev_notifier;
  struct delayed_work sync_work;   /* 防抖同步工作队列 */
  bool netdev_notifier_registered; /* 跟踪通知器是否成功注册 */
};

/* 函数声明 */

/* ban-manager.c */
int ban_ip(struct firewall_info *fw, __be32 ip);
int ban_ip_permanent(struct firewall_info *fw, __be32 ip);
int ban_ip_with_duration(struct firewall_info *fw, __be32 ip,
                         unsigned long seconds);
int unban_ip(struct firewall_info *fw, __be32 ip);
int unban_permanent_ip(struct firewall_info *fw, __be32 ip);
int is_banned(struct firewall_info *fw, __be32 ip);
int is_permanently_banned(struct firewall_info *fw, __be32 ip);
int check_flood_protection(void);

/* whitelist.c */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask,
                        const char *dev_name);
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip);
bool is_in_whitelist(struct firewall_info *fw, __be32 ip);

/* netdev.c */
void auto_discover_system_ips(struct firewall_info *fw);
void sync_system_ips(struct firewall_info *fw);
void sync_work_handler(struct work_struct *work);
int register_netdev_notifier(struct firewall_info *fw);
void unregister_netdev_notifier(struct firewall_info *fw);

/* procfs.c */
int create_procfs_entries(struct firewall_info *fw);
void destroy_procfs_entries(struct firewall_info *fw);

/* state-persist.c */
int save_state_to_file(const char *filename);
int restore_state_from_file(const char *filename);

/* RCU 回调函数（cleanup.c 中定义，其他模块需要使用） */
void free_ban_entry_rcu(struct rcu_head *head);
void free_whitelist_entry_rcu(struct rcu_head *head);

/* 清理定时器回调（cleanup.c 中定义） */
void cleanup_timer_callback(struct timer_list *t);

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void);

/* Netfilter 钩子操作结构（在 netfilter.c 中定义） */
extern struct nf_hook_ops nf_ops_ipv4;

/* ============================================================================
 * 公共内联辅助函数
 * ============================================================================
 */

/**
 * ipv4_to_str - 将 IPv4 地址转换为点分十进制字符串
 * @ip: IPv4 地址（网络字节序）
 * @buf: 输出缓冲区
 * @len: 缓冲区长度
 */
static inline void ipv4_to_str(__be32 ip, char *buf, int len) {
  unsigned int a = ntohl(ip) >> 24;
  unsigned int b = (ntohl(ip) >> 16) & 0xFF;
  unsigned int c = (ntohl(ip) >> 8) & 0xFF;
  unsigned int d = ntohl(ip) & 0xFF;

  if (len < 16) {
    if (len > 0) {
      buf[0] = '\0';
    }
    return;
  }

  snprintf(buf, len, "%u.%u.%u.%u", a, b, c, d);
}

/**
 * compare_ips - 比较两个 IPv4 地址是否相等
 * @ip1: 第一个 IPv4 地址
 * @ip2: 第二个 IPv4 地址
 * 返回: true 如果相等，否则 false
 */
static inline bool compare_ips(__be32 ip1, __be32 ip2) { return ip1 == ip2; }

/**
 * validate_ipv4_address - 验证 IPv4 地址是否合法
 * @ip: IPv4 地址（网络字节序）
 * @ip_str: IP 字符串（用于日志，可为 NULL）
 * @context: 上下文描述（如 "ban"、"whitelist"）
 * 返回: 0 表示合法，-EINVAL 表示非法
 */
static inline int validate_ipv4_address(__be32 ip, const char *ip_str,
                                        const char *context) {
  unsigned int ip_num = ntohl(ip);

  if (ip == 0 || ip == 0xFFFFFFFF) {
    fw_pr_warn("Attempt to %s invalid IPv4: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  if ((ip_num & 0xFF000000) == 0x7F000000) {
    fw_pr_warn("Attempt to %s loopback IPv4: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  if ((ip_num & 0xF0000000) == 0xE0000000) {
    fw_pr_warn("Attempt to %s reserved IPv4 (multicast/Class E): %s", context,
               ip_str ?: "(null)");
    return -EINVAL;
  }
  if ((ip_num & 0xFF000000) == 0x00000000) {
    fw_pr_warn("Attempt to %s invalid IPv4 (0.0.0.0/8): %s", context,
               ip_str ?: "(null)");
    return -EINVAL;
  }
  if ((ip_num & 0xFF000000) == 0xFF000000) {
    fw_pr_warn("Attempt to %s invalid IPv4 (255.0.0.0/8): %s", context,
               ip_str ?: "(null)");
    return -EINVAL;
  }

  return 0;
}

#endif /* FIREWALL_H */
