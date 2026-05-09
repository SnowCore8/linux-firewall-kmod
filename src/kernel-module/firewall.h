#ifndef FIREWALL_H
#define FIREWALL_H

#include <linux/errno.h>
#include <linux/hash.h>
#include <linux/hashtable.h>
#include <linux/if_addr.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
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

/* Per-CPU packet stats for hot-path optimization (R9-1).
 * Instead of atomic_inc on every packet (cache coherency overhead),
 * each CPU maintains local counters and flushes to global atomics
 * in batches. */
#define FW_PER_CPU_BATCH_SIZE 1024

struct fw_per_cpu_stats {
  u64 packets_accepted;
  u64 packets_dropped;
};

/* R9-1: Per-CPU counter flush function (called from cleanup timer) */
void fw_flush_cpu_stats(void);

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

/* IPv6 地址字符串最大长度 (e.g., "2001:db8::ffff:ffff:ffff:ffff") */
#define INET6_STR_LEN 48

/* IP 地址族标识 */
#define FW_AF_INET 2   /* AF_INET */
#define FW_AF_INET6 10 /* AF_INET6 */

/* 白名单条目结构 - 支持 IPv4/IPv6 */
struct whitelist_entry {
  u8 af; /* 地址族: FW_AF_INET 或 FW_AF_INET6 */
  union {
    __be32 ipv4;          /* IPv4 地址，网络字节序 */
    struct in6_addr ipv6; /* IPv6 地址 */
  } addr;
  union {
    __be32 ipv4_mask; /* IPv4 子网掩码 */
    u8 prefix_len;    /* IPv6 前缀长度 */
  } mask;
  char device_name[16];     /* 网络设备名称（如 eth0） */
  struct hlist_node hash;   /* 哈希表节点 */
  struct rcu_head rcu_head; /* 用于 RCU 释放 */
  struct list_head subnet_node; /* R9-3: 子网链表节点（仅非精确匹配条目使用） */
};

/* 封禁条目结构 - 支持 IPv4/IPv6 */
struct ban_entry {
  u8 af; /* 地址族: FW_AF_INET 或 FW_AF_INET6 */
  union {
    __be32 ipv4;          /* IPv4 地址，网络字节序 */
    struct in6_addr ipv6; /* IPv6 地址 */
  } addr;
  unsigned long ban_time;   /* IP 被封禁的时间 */
  unsigned long unban_time; /* 解除封禁的时间（0 = 永久） */
  atomic_t retry_count;     /* 保留供将来使用 */
  bool is_permanent;        /* 永久封禁标志 */
  struct hlist_node hash;
  struct rcu_head rcu_head; /* 用于 RCU 释放 */
};

/* 全局防火墙结构 */
struct firewall_info {
  /* IPv4 封禁哈希表 */
  DECLARE_HASHTABLE(ban_table_ipv4, BAN_HASH_BITS);
  /* IPv6 封禁哈希表 */
  DECLARE_HASHTABLE(ban_table_ipv6, BAN_HASH_BITS);
  spinlock_t lock;
  /* R9-4 修复：每桶自旋锁，减少高并发封禁场景下的锁竞争。
   * 不同桶的封禁/解封操作可并行执行。 */
  spinlock_t ban_locks_ipv4[1 << BAN_HASH_BITS];
  spinlock_t ban_locks_ipv6[1 << BAN_HASH_BITS];
  atomic_t ban_count;
  atomic_t shutting_down; /* 防止关闭期间定时器触发的标志 */
  unsigned int ban_time;
  struct timer_list cleanup_timer;
  bool timer_initialized; /* 跟踪定时器是否已初始化 */
  int cleanup_last_bucket_ipv4; /* 修复：IPv4 独立的清理进度索引 */
  int cleanup_last_bucket_ipv6; /* 修复：IPv6 独立的清理进度索引，防止 IPv4/IPv6 互相干扰 */

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
  atomic64_t packets_dropped;        /* 被 netfilter 丢弃的数据包 */
  atomic64_t packets_accepted;       /* 被 netfilter 接受的数据包 */
  atomic_t cleanup_cycles;         /* 清理定时器周期数 */
  atomic_t cleanup_expired_total;  /* 已清理的过期条目总数 */

  /* IPv4 白名单哈希表 */
  DECLARE_HASHTABLE(whitelist_table_ipv4, WHITELIST_HASH_BITS);
  /* IPv6 白名单哈希表 */
  DECLARE_HASHTABLE(whitelist_table_ipv6, WHITELIST_HASH_BITS);
  spinlock_t whitelist_lock;
  atomic_t whitelist_count;

  /* R9-3 修复：子网白名单 RCU 链表，用于 O(1) 平均查找。
   * 哈希表用于精确匹配 O(1)，子网链表用于前缀匹配（避免遍历所有 64 个桶）。 */
  struct list_head ipv4_subnet_wl;
  struct list_head ipv6_subnet_wl;

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
int ban_ip(struct firewall_info *fw, u8 af, const void *ip);
int ban_ip_permanent(struct firewall_info *fw, u8 af, const void *ip);
int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds);
int unban_ip(struct firewall_info *fw, u8 af, const void *ip);
int unban_permanent_ip(struct firewall_info *fw, u8 af, const void *ip);
int is_banned(struct firewall_info *fw, u8 af, const void *ip);
int is_permanently_banned(struct firewall_info *fw, u8 af, const void *ip);
int check_flood_protection(void);

/* whitelist.c */
int add_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                        const void *mask, int prefix_len, const char *dev_name);
int remove_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                           int prefix_len);
bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip);

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
extern struct nf_hook_ops nf_ops_ipv6;

/* 全局哈希种子（在 firewall-main.c 中初始化） */
extern u32 fw_hash_seed;

/* ============================================================================
 * 公共内联辅助函数
 * ============================================================================
 */

/**
 * ip_to_str - 将 IP 地址转换为字符串
 * @af: 地址族 (FW_AF_INET 或 FW_AF_INET6)
 * @ip: IP 地址指针
 * @buf: 输出缓冲区 (至少 INET6_STR_LEN 字节)
 * @len: 缓冲区长度
 */
static inline void ip_to_str(u8 af, const void *ip, char *buf, size_t len) {
  if (af == FW_AF_INET6) {
    const struct in6_addr *addr = ip;
    if (len < INET6_STR_LEN) {
      if (len > 0)
        buf[0] = '\0';
      return;
    }
    snprintf(buf, len, "%pI6", addr);
  } else {
    __be32 addr = *(__be32 *)ip;
    unsigned int a = ntohl(addr) >> 24;
    unsigned int b = (ntohl(addr) >> 16) & 0xFF;
    unsigned int c = (ntohl(addr) >> 8) & 0xFF;
    unsigned int d = ntohl(addr) & 0xFF;
    if (len < 16) {
      if (len > 0)
        buf[0] = '\0';
      return;
    }
    snprintf(buf, len, "%u.%u.%u.%u", a, b, c, d);
  }
}

/**
 * compare_ips - 比较两个 IP 地址是否相等
 * @af: 地址族
 * @ip1: 第一个 IP 地址
 * @ip2: 第二个 IP 地址
 * 返回: true 如果相等，否则 false
 */
static inline bool compare_ips(u8 af, const void *ip1, const void *ip2) {
  if (af == FW_AF_INET6)
    return ipv6_addr_equal((const struct in6_addr *)ip1,
                           (const struct in6_addr *)ip2);
  return *(__be32 *)ip1 == *(__be32 *)ip2;
}

/**
 * hash_ip - 计算 IP 地址的哈希值
 * @af: 地址族
 * @ip: IP 地址
 * @bits: 哈希表位数
 * 返回: 哈希值
 */
static inline u32 hash_ip(u8 af, const void *ip, int bits) {
  if (af == FW_AF_INET6) {
    const struct in6_addr *addr = ip;
    return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) &
           ((1 << bits) - 1);
  }
  return hash_min(*(__be32 *)ip, bits);
}

/**
 * hash_ip_for_ban - 计算用于 ban_table 的哈希值
 * 使用 jhash2 确保 IPv4 和 IPv6 分布均匀
 */
static inline u32 hash_ip_for_ban(u8 af, const void *ip, int bits) {
  return hash_ip(af, ip, bits);
}

/**
 * hash_ip_for_whitelist - 计算用于 whitelist_table 的哈希值
 */
static inline u32 hash_ip_for_whitelist(u8 af, const void *ip, int bits) {
  return hash_ip(af, ip, bits);
}

/**
 * get_ban_table - 获取对应地址族的 ban 哈希表
 */
static inline struct hlist_head *get_ban_table(struct firewall_info *fw,
                                               u8 af) {
  if (af == FW_AF_INET6)
    return fw->ban_table_ipv6;
  return fw->ban_table_ipv4;
}

/**
 * get_whitelist_table - 获取对应地址族的 whitelist 哈希表
 */
static inline struct hlist_head *get_whitelist_table(struct firewall_info *fw,
                                                     u8 af) {
  if (af == FW_AF_INET6)
    return fw->whitelist_table_ipv6;
  return fw->whitelist_table_ipv4;
}

/**
 * validate_ipv4_address - 验证 IPv4 地址是否合法
 * @ip: IPv4 地址（网络字节序）
 * @ip_str: IP 字符串（用于日志，可为 NULL）
 * @context: 上下文描述（如 "ban"、"whitelist"）
 * @allow_loopback: 是否允许回环地址
 * 返回: 0 表示合法，-EINVAL 表示非法
 */
static inline int validate_ipv4_address(__be32 ip, const char *ip_str,
                                        const char *context,
                                        bool allow_loopback) {
  unsigned int ip_num = ntohl(ip);

  if (ip == 0 || ip == 0xFFFFFFFF) {
    fw_pr_warn("Attempt to %s invalid IPv4: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  if (!allow_loopback && (ip_num & 0xFF000000) == 0x7F000000) {
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

/**
 * validate_ipv6_address - 验证 IPv6 地址是否合法
 * @addr: IPv6 地址
 * @ip_str: IP 字符串（用于日志，可为 NULL）
 * @context: 上下文描述
 * @allow_loopback: 是否允许回环地址
 * 返回: 0 表示合法，-EINVAL 表示非法
 */
static inline int validate_ipv6_address(const struct in6_addr *addr,
                                        const char *ip_str, const char *context,
                                        bool allow_loopback) {
  if (ipv6_addr_any(addr)) {
    fw_pr_warn("Attempt to %s invalid IPv6: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  if (!allow_loopback && ipv6_addr_loopback(addr)) {
    fw_pr_warn("Attempt to %s loopback IPv6: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  /* 拒绝 multicast 和 link-local */
  if (ipv6_addr_is_multicast(addr)) {
    fw_pr_warn("Attempt to %s multicast IPv6: %s", context, ip_str ?: "(null)");
    return -EINVAL;
  }
  return 0;
}

/**
 * validate_ip_address - 统一 IP 地址验证入口
 * @af: 地址族
 * @ip: IP 地址
 * @ip_str: IP 字符串（用于日志）
 * @context: 上下文描述
 * @allow_loopback: 是否允许回环地址
 */
static inline int validate_ip_address(u8 af, const void *ip, const char *ip_str,
                                      const char *context,
                                      bool allow_loopback) {
  if (af == FW_AF_INET6)
    return validate_ipv6_address((const struct in6_addr *)ip, ip_str, context,
                                 allow_loopback);
  return validate_ipv4_address(*(__be32 *)ip, ip_str, context, allow_loopback);
}

#endif /* FIREWALL_H */
