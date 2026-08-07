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
  u64 global_packets; /* 全局流量计数（per-CPU 本地，flush 时写入全局 atomic） */
  u64 global_bytes; /* 全局字节计数（per-CPU 本地，flush 时写入全局 atomic） */
};

/* R9-1: Per-CPU counter flush function (called from cleanup timer) */
void fw_flush_cpu_stats(void);

/* 跨 CPU 刷新所有 per-CPU 计数器（速率查询前调用，确保数据完整） */
void fw_flush_all_cpu_stats(void);

#define BAN_HASH_BITS 12
/* 封禁表哈希桶数（4096 桶），条目数量无上限（按需扩展） */
#define MAX_BAN_ENTRIES (1 << BAN_HASH_BITS) /* 保留：用于临时数组大小 */
#define DEFAULT_BAN_TIME 600                 /* 10 分钟（秒） */
#define MAX_BAN_TIME (365 * 24 * 60 * 60) /* 最大 1 年，防止溢出 */
#define MIN_BAN_TIME 30 /* 最小 30 秒，避免过多的定时器开销 */

/* 白名单哈希表结构 */
#define WHITELIST_HASH_BITS 6
/* 白名单哈希桶数（64 桶），条目数量无上限（按需扩展） */

/* 速率检测哈希表结构 */
#define RATE_HASH_BITS 16
/* 速率表哈希桶数（65536 桶）；条目数受 fw_max_rate_entries 硬限制 */

/* UDP 端口分布统计 */
#define UDP_PORT_HASH_BITS 8
#define UDP_PORT_HASH_SIZE (1 << UDP_PORT_HASH_BITS) /* 256 桶 */
#define MAX_UDP_PORT_ENTRIES 512 /* 最多跟踪 512 个不同端口 */

struct udp_port_entry {
  u16 port;                 /* UDP 目标端口（主机字节序） */
  atomic64_t packet_count;  /* 数据包计数 */
  atomic64_t byte_count;    /* 字节计数 */
  unsigned long last_seen;  /* 最后活动时间（jiffies） */
  struct hlist_node hash;   /* 哈希表节点 */
  struct rcu_head rcu_head; /* RCU 释放回调 */
};

/* ICMP 类型分布统计 */
#define ICMP_TYPE_HASH_BITS 6
#define ICMP_TYPE_HASH_SIZE (1 << ICMP_TYPE_HASH_BITS) /* 64 桶 */
#define MAX_ICMP_TYPE_ENTRIES 128 /* 最多跟踪 128 种类型/代码组合 */

struct icmp_type_entry {
  u8 type;                  /* ICMP 类型（0-255） */
  u8 code;                  /* ICMP 代码（0-255） */
  atomic64_t packet_count;  /* 数据包计数 */
  atomic64_t byte_count;    /* 字节计数 */
  unsigned long last_seen;  /* 最后活动时间（jiffies） */
  struct hlist_node hash;   /* 哈希表节点 */
  struct rcu_head rcu_head; /* RCU 释放回调 */
};

/* 速率检测默认配置 */
#define DEFAULT_RATE_WINDOW_SECONDS 1         /* 默认 1 秒窗口 */
#define DEFAULT_MAX_PACKETS_PER_SECOND 100000 /* 默认 100K PPS */
#define DEFAULT_MAX_BYTES_PER_SECOND (100 * 1024 * 1024) /* 默认 100 MB/s */

/* 协议专项检测默认配置 */
#define DEFAULT_MAX_SYN_PER_SECOND 2000 /* 正常 Web 服务器 SYN 500-1500/s */
#define DEFAULT_MAX_UDP_PER_SECOND 10000 /* DNS/NTP 等正常 UDP 可达数千 */
#define DEFAULT_MAX_ICMP_PER_SECOND 500  /* 正常 ping/路径 MTU 发现 */
#define DEFAULT_MAX_ACK_PER_SECOND 20000 /* 正常 TCP 连接 ACK 速率高 */
#define DEFAULT_MAX_RST_PER_SECOND 2000  /* 大量短连接场景 RST 较高 */
#define DEFAULT_MAX_FIN_PER_SECOND 2000  /* FIN 同理 */

/* 动态阈值默认配置 */
#define DEFAULT_DYNAMIC_THRESHOLD_ENABLED 0      /* 默认关闭 */
#define DEFAULT_DYNAMIC_THRESHOLD_RATIO_X100 300 /* 默认 3.0 倍（× 100） */

/* 自动发现 IP 的临时数组大小（按需扩展，无上限） */
#define MAX_DISCOVERED_IPS 4096 /* 初始大小，实际可动态扩展 */

/* IPv6 地址字符串最大长度 (e.g., "2001:db8::ffff:ffff:ffff:ffff") */
#define INET6_STR_LEN 48

/* IP 地址族标识 */
#define FW_AF_INET 2   /* AF_INET */
#define FW_AF_INET6 10 /* AF_INET6 */

/* TCP 标志位（用于协议子分类检测） */
#define TCP_FLAGS_FIN 0x01
#define TCP_FLAGS_SYN 0x02
#define TCP_FLAGS_RST 0x04
#define TCP_FLAGS_ACK 0x10

/* TCP 异常标志位组合检测（扫描/畸形包识别）
 *
 * 检测以下无效组合：
 * 1. SYN+FIN — 协议不允许，扫描特征
 * 2. SYN+RST — 协议不允许，扫描特征
 * 3. NULL — 全零标志位（NULL scan）
 *
 * 返回 true 表示检测到异常，应丢弃该包 */
static inline bool is_tcp_flag_anomaly(u8 tcp_flags) {
  u8 masked = tcp_flags & (TCP_FLAGS_SYN | TCP_FLAGS_FIN | TCP_FLAGS_RST | TCP_FLAGS_ACK);

  /* SYN+FIN 或 SYN+RST：无效组合 */
  if ((masked & TCP_FLAGS_SYN) && (masked & (TCP_FLAGS_FIN | TCP_FLAGS_RST)))
    return true;

  /* NULL scan：四个主要标志位全为 0 */
  if (masked == 0)
    return true;

  return false;
}

/* 本地 IP 缓存条目（热路径优化：避免每次包都走白名单哈希表查找）
 * 由 netdev_notifier 事件触发刷新（USB 插拔/手动改 IP/DHCP 等） */
struct local_ip_cache_entry {
  u8 af;
  union {
    __be32 ipv4;
    struct in6_addr ipv6;
  } addr;
  union {
    __be32 ipv4_mask;
    u8 prefix_len;
  } mask;
};

/* 本地 IP 缓存整体（count 与 entries 同对象发布，避免指针/计数拆分 TOCTOU） */
struct local_ip_cache {
  unsigned int count;
  struct local_ip_cache_entry entries[];
};

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
  char jail_name[32]; /* Jail 名称（如 "sshd"、"nginx"、"api" 等） */
  char reason[32]; /* 封禁原因（如 "DDoS SYN flood"、"failed attempts" 等） */
  struct hlist_node hash;
  struct list_head ban_node; /* 全局活跃封禁链表节点 */
  struct rcu_head rcu_head;  /* 用于 RCU 释放 */
  struct timer_list expire_timer; /* per-entry 过期定时器（非永久封禁时使用） */
};

/* IP 速率统计条目 - 用于 DDoS 检测
 *
 * 设计原理：
 * 1. 滑动窗口算法：在 window_start 到 last_activity 的时间窗口内统计速率
 * 2. 原子计数器：使用 atomic64_t 避免锁竞争（热路径优化）
 * 3. RCU 保护：读操作无锁，写操作使用 per-bucket spinlock
 * 4. 内存布局：IP 地址在前（缓存友好），时间戳在后
 * 5. EWMA 平滑：窗口重置时更新平滑速率，过滤突发流量误判
 *
 * 性能目标：10Gbps（~1500 万 PPS）场景下，每个数据包的处理开销 < 100ns
 */
struct ip_rate_entry {
  u8 af; /* 地址族: FW_AF_INET 或 FW_AF_INET6 */
  union {
    __be32 ipv4;          /* IPv4 地址，网络字节序 */
    struct in6_addr ipv6; /* IPv6 地址 */
  } addr;

  /* 速率统计（原子计数器，无锁更新） */
  atomic64_t packet_count; /* 当前窗口内的数据包数 */
  atomic64_t byte_count;   /* 当前窗口内的字节数 */

  /* 协议专项统计（用于 SYN/UDP/ICMP Flood 检测） */
  atomic64_t syn_count;  /* TCP SYN 包数（SYN Flood 检测） */
  atomic64_t udp_count;  /* UDP 包数（UDP Flood 检测） */
  atomic64_t icmp_count; /* ICMP Echo Request 数（ICMP Flood 检测） */

  /* TCP 子分类统计（ACK/RST/FIN Flood 检测） */
  atomic64_t ack_count; /* TCP ACK 包数 */
  atomic64_t rst_count; /* TCP RST 包数 */
  atomic64_t fin_count; /* TCP FIN 包数 */

  /* EWMA 平滑速率（窗口重置时更新，检测时使用）
   * 公式：smoothed = (3 * current + 7 * smoothed) / 10（α=0.3 定点运算）
   * 作用：过滤突发流量误判，只有持续高速才触发封禁 */
  atomic64_t smoothed_pps;  /* 平滑后的包速率（packets/sec） */
  atomic64_t smoothed_bps;  /* 平滑后的字节速率（bytes/sec） */
  atomic64_t smoothed_syn;  /* 平滑后的 SYN 速率 */
  atomic64_t smoothed_udp;  /* 平滑后的 UDP 速率 */
  atomic64_t smoothed_icmp; /* 平滑后的 ICMP 速率 */
  atomic64_t smoothed_ack;  /* 平滑后的 ACK 速率 */
  atomic64_t smoothed_rst;  /* 平滑后的 RST 速率 */
  atomic64_t smoothed_fin;  /* 平滑后的 FIN 速率 */

  /* 时间戳（jiffies） */
  unsigned long window_start; /* 当前窗口的起始时间 */
  unsigned long last_activity; /* 最后活动时间（用于过期清理和 LRU 替换） */

  /* LRU 保护标志：白名单 IP 的条目不被踢出 */
  u8 pinned;

  /* 端口扫描检测：跟踪目标端口变化
   * 轻量级近似：每次 dst_port 与 last_dst_port 不同时递增 unique_ports
   * 对于顺序扫描（端口 1,2,3,...N）精确计数；对于重复访问会高估，但不影响检测 */
  atomic_t unique_ports; /* 不同目标端口数（近似） */
  u16 last_dst_port;     /* 上一次看到的目标端口 */

  /* 哈希表和 RCU */
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
  struct list_head active_bans_list; /* 全局活跃封禁链表，O(n) 遍历实际条目 */
  /* 保护 active_bans_list 的写端；读端用 list_for_each_entry_rcu */
  spinlock_t active_bans_lock;
  atomic_t shutting_down; /* 防止关闭期间定时器触发的标志 */
  unsigned int ban_time;

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
  atomic64_t packets_dropped;      /* 被 netfilter 丢弃的数据包 */
  atomic64_t packets_accepted;     /* 被 netfilter 接受的数据包 */
  atomic64_t tcp_anomaly_dropped;  /* TCP 异常标志位丢弃的数据包 */
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

  /* 本地 IP 缓存（热路径优化：避免每次包都走白名单哈希表查找）
   * 由 netdev_notifier 事件触发刷新（USB 插拔/手动改 IP/DHCP 等）
   * 结构：简单数组 + 计数，RCU 保护读，写时重建整个数组
   * 容量：与白名单一致（64 条），通常只有几个到十几个本地 IP */
  struct local_ip_cache __rcu *local_ip_cache;

  /* 速率检测（DDoS 防护） */
  DECLARE_HASHTABLE(rate_table_ipv4, RATE_HASH_BITS); /* IPv4 速率统计表 */
  DECLARE_HASHTABLE(rate_table_ipv6, RATE_HASH_BITS); /* IPv6 速率统计表 */
  spinlock_t rate_locks_ipv4[1 << RATE_HASH_BITS];    /* per-bucket 自旋锁 */
  spinlock_t rate_locks_ipv6[1 << RATE_HASH_BITS];
  atomic_t rate_count; /* 当前速率条目总数 */

  /* 速率检测配置 */
  unsigned int rate_window_seconds;  /* 滑动窗口大小（秒） */
  unsigned long rate_window_jiffies; /* 窗口大小（jiffies，缓存值） */
  unsigned long max_packets_per_second; /* 每秒最大数据包数 */
  unsigned long max_bytes_per_second;   /* 每秒最大字节数 */

  /* 协议专项检测配置（Flood 攻击） */
  unsigned long max_syn_per_second; /* 每秒最大 TCP SYN 包数（SYN Flood） */
  unsigned long max_udp_per_second; /* 每秒最大 UDP 包数（UDP Flood） */
  unsigned long max_icmp_per_second; /* 每秒最大 ICMP Echo Request 数（ICMP Flood） */
  unsigned long max_ack_per_second; /* 每秒最大 TCP ACK 包数（ACK Flood） */
  unsigned long max_rst_per_second; /* 每秒最大 TCP RST 包数（RST Flood） */
  unsigned long max_fin_per_second; /* 每秒最大 TCP FIN 包数（FIN Flood） */

  /* 动态阈值（方案 C 混合模式）
   * 当 dynamic_threshold_enabled 时，实际阈值 = max(静态阈值, 基线 × 倍数)
   * 基线使用全局 EWMA（α=0.01，极慢衰减），跟踪长期流量趋势 */
  bool dynamic_threshold_enabled; /* 是否启用动态阈值 */
  bool static_threshold_enabled; /* 是否启用静态阈值（与模块参数同步到运行态） */
  u32 dynamic_threshold_ratio_x100; /* 倍数 × 100（如 300 = 3.0 倍） */
  atomic64_t global_baseline_pps;   /* 全局 PPS 基线（EWMA α=0.01） */
  atomic64_t global_baseline_bps;   /* 全局 BPS 基线（EWMA α=0.01） */

  /* DDoS 封禁配置 */
  u32 ddos_ban_duration; /* DDoS 封禁时长（秒），0 表示使用默认值 3600 */

  /* 全局流量计数器（netfilter 热路径递增，守护进程每 2 秒读取）
   * 使用 atomic64_xchg 读取并重置，守护进程计算 PPS/BPS 后下发基线 */
  atomic64_t global_traffic_packets; /* 自上次查询以来的数据包总数 */
  atomic64_t global_traffic_bytes;   /* 自上次查询以来的字节总数 */

  /* UDP 端口分布统计（用于分析 UDP 流量模式） */
  DECLARE_HASHTABLE(udp_port_table, UDP_PORT_HASH_BITS);
  spinlock_t udp_port_lock; /* 保护 udp_port_table 的写操作 */
  atomic_t udp_port_count;  /* 当前跟踪的端口数 */

  /* ICMP 类型分布统计（用于分析 ICMP 流量模式） */
  DECLARE_HASHTABLE(icmp_type_table, ICMP_TYPE_HASH_BITS);
  spinlock_t icmp_type_lock; /* 保护 icmp_type_table 的写操作 */
  atomic_t icmp_type_count;  /* 当前跟踪的类型/代码组合数 */

  /* 包大小分布直方图（用于检测小包洪水攻击）
   * 5 个桶：Tiny(<64B) Small(64-256B) Medium(256-1024B) Large(1024-1500B) Jumbo(>1500B)
   * 使用 atomic64 计数器，热路径无锁递增 */
  atomic64_t pkt_size_tiny;   /* < 64 bytes */
  atomic64_t pkt_size_small;  /* 64-256 bytes */
  atomic64_t pkt_size_medium; /* 256-1024 bytes */
  atomic64_t pkt_size_large;  /* 1024-1500 bytes */
  atomic64_t pkt_size_jumbo;  /* > 1500 bytes */

  /* TTL 分布直方图（用于检测异常 TTL 值，如扫描/伪造包）
   * 6 个桶：Scan(=1) VeryShort(2-32) Short(33-64) Normal(65-128) Long(129-192) Max(193-255)
   * 使用 atomic64 计数器，热路径无锁递增 */
  atomic64_t ttl_scan;       /* TTL = 1（traceroute/扫描） */
  atomic64_t ttl_very_short; /* TTL 2-32（异常短 TTL） */
  atomic64_t ttl_short;      /* TTL 33-64（短 TTL，近距离主机） */
  atomic64_t ttl_normal;     /* TTL 65-128（正常范围） */
  atomic64_t ttl_long;       /* TTL 129-192（长 TTL） */
  atomic64_t ttl_max;        /* TTL 193-255（最大 TTL，可能伪造） */

  /* IP 分片统计（用于检测分片洪水攻击）
   * 使用 atomic64 计数器，热路径无锁递增 */
  atomic64_t ip_frag_count; /* IP 分片包数（MF=1 或 frag_offset != 0） */
  atomic64_t ip_total_count; /* 总 IP 数据包数 */

  /* 端口扫描检测统计 */
  atomic_t port_scan_detected; /* 检测到的端口扫描次数 */

  /* procfs 条目 */
  struct proc_dir_entry *proc_dir;
  struct proc_dir_entry *proc_bans;      /* 统一封禁接口（读/写） */
  struct proc_dir_entry *proc_whitelist; /* 统一白名单接口（读/写） */
  struct proc_dir_entry *proc_config;    /* 配置（读/写） */
  struct proc_dir_entry *proc_settings;
  struct proc_dir_entry *proc_stats;         /* 统计端点（只读） */
  struct proc_dir_entry *proc_rates;         /* 速率统计（只读） */
  struct proc_dir_entry *proc_udp_ports;     /* UDP 端口分布（只读） */
  struct proc_dir_entry *proc_icmp_types;    /* ICMP 类型分布（只读） */
  struct proc_dir_entry *proc_pkt_sizes;     /* 包大小分布（只读） */
  struct proc_dir_entry *proc_ttl_dist;      /* TTL 分布（只读） */
  struct proc_dir_entry *proc_ip_frags;      /* IP 分片统计（只读） */
  struct proc_dir_entry *proc_port_scanners; /* 端口扫描检测（只读） */
  struct proc_dir_entry *proc_service_probes; /* 服务探测检测（只读） */

  /* 网络事件监听器 */
  struct notifier_block netdev_notifier;
  struct delayed_work sync_work;   /* 防抖同步工作队列 */
  bool netdev_notifier_registered; /* 跟踪通知器是否成功注册 */
};

/*
 * active_bans_list 写锁助手
 * 锁顺序（必须遵守，防死锁）：
 *   ban_locks_ipv4/ipv6[bkt]  →  active_bans_lock
 * 禁止：先持 active_bans_lock 再取桶锁。
 * CIDR 遍历应 RCU 只读收集 IP，再走桶锁解封路径。
 *
 * 白名单与封禁互斥协议：
 * - 封禁：桶锁内插入前/后各做一次白名单 RCU 检查；后检失败则同锁回滚。
 * - 白名单：先 RCU 发布条目，再按桶解封匹配 IP（与上形成闭环）。
 * - 不交叉持有 whitelist_lock 与 ban 桶锁（避免与 softirq 封禁路径死锁）。
 */
static inline void active_bans_add(struct firewall_info *fw, struct ban_entry *entry) {
  spin_lock(&fw->active_bans_lock);
  list_add_tail_rcu(&entry->ban_node, &fw->active_bans_list);
  spin_unlock(&fw->active_bans_lock);
}

static inline void active_bans_del(struct firewall_info *fw, struct ban_entry *entry) {
  spin_lock(&fw->active_bans_lock);
  list_del_rcu(&entry->ban_node);
  spin_unlock(&fw->active_bans_lock);
}

/* 函数声明 */

/* ban-manager.c */
int ban_ip(struct firewall_info *fw, u8 af, const void *ip, const char *reason);
int ban_ip_permanent(struct firewall_info *fw, u8 af, const void *ip, const char *reason);
int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds, const char *reason);
int unban_ip(struct firewall_info *fw, u8 af, const void *ip);
int unban_permanent_ip(struct firewall_info *fw, u8 af, const void *ip);
int is_banned(struct firewall_info *fw, u8 af, const void *ip);
int is_permanently_banned(struct firewall_info *fw, u8 af, const void *ip);
int check_flood_protection(void);
u32 hash_ipv6(const struct in6_addr *addr);

/* whitelist.c */
int add_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                        const void *mask, int prefix_len, const char *dev_name);
int remove_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip, int prefix_len);
bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip);

/* rate-detector.c - 速率检测（DDoS 防护） */
int update_rate_stats(struct firewall_info *fw, u8 af, const void *ip,
                      u32 packet_len, u8 protocol, u8 tcp_flags, u16 dst_port);
bool check_rate_violation(struct firewall_info *fw, u8 af, const void *ip);
bool check_protocol_violation(struct firewall_info *fw, u8 af, const void *ip, u8 protocol);
const char *check_tcp_flood_violation(struct firewall_info *fw, u8 af,
                                      const void *ip, u8 tcp_flags);
void clear_all_rate_entries(struct firewall_info *fw);
void free_rate_entry_rcu(struct rcu_head *head);
void update_global_baseline(struct firewall_info *fw, u64 total_pps, u64 total_bps);

/* UDP 端口分布统计 */
void record_udp_port(struct firewall_info *fw, u16 dst_port, u32 packet_len);
void free_udp_port_entry_rcu(struct rcu_head *head);

/* ICMP 类型分布统计 */
void record_icmp_type(struct firewall_info *fw, u8 type, u8 code, u32 packet_len);
void free_icmp_type_entry_rcu(struct rcu_head *head);

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

/* per-entry 过期定时器回调（ban-manager.c 中定义） */
void ban_entry_expire_callback(struct timer_list *t);

/* netlink.c - Netlink 通信层 */
int fw_netlink_init(void);
void fw_netlink_exit(void);
int fw_netlink_send_event(u8 af, const void *ip, const char *reason, u32 rate_pps);
int fw_netlink_send_ban_state_change(u8 af, const void *ip, u8 action, u32 duration_secs,
                                     const char *reason, const char *jail_name);
int fw_netlink_send_whitelist_state_change(u8 af, const void *ip, u8 prefix_len,
                                           u8 action, const char *dev_name);
int fw_netlink_send_list_bans_response(u32 seq, u32 portid);
int fw_netlink_send_stats_response(u32 seq, u32 portid);
int fw_netlink_send_analysis_response(u32 seq, u32 portid);
int fw_netlink_send_config_ack(u32 seq, u32 applied_flags, u32 rejected_flags, u32 portid);
int fw_netlink_send_list_whitelist_response(u32 seq, u32 portid);
int fw_netlink_send_list_rates_response(u32 seq, u32 portid);
void fw_netlink_send_config_change(u32 flag, u32 value);

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void);

/* Netfilter 钩子操作结构（在 netfilter.c 中定义） */
extern struct nf_hook_ops nf_ops_ipv4;
extern struct nf_hook_ops nf_ops_ipv6;

/* 全局哈希种子（在 firewall-main.c 中初始化） */
extern u32 fw_hash_seed;

/* 速率表最大条目数（模块参数，可在加载时配置） */
extern unsigned int fw_max_rate_entries;

/* 静态阈值检测开关（模块参数） */
extern unsigned int fw_static_threshold;

/* 动态阈值检测开关（模块参数） */
extern unsigned int fw_dynamic_threshold;

/* DDoS 检测总开关（模块参数） */
extern unsigned int fw_ddos_detection;

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
    return ipv6_addr_equal((const struct in6_addr *)ip1, (const struct in6_addr *)ip2);
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
    return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) & ((1 << bits) - 1);
  }
  return hash_min(*(__be32 *)ip, bits);
}

/**
 * hash_ip_for_rate - 计算用于 rate_table 的哈希值
 */
static inline u32 hash_ip_for_rate(u8 af, const void *ip, int bits) {
  return hash_ip(af, ip, bits);
}

/**
 * get_rate_table - 获取对应地址族的 rate 哈希表
 */
static inline struct hlist_head *get_rate_table(struct firewall_info *fw, u8 af) {
  if (af == FW_AF_INET6)
    return fw->rate_table_ipv6;
  return fw->rate_table_ipv4;
}

/**
 * record_packet_size - 记录数据包大小到直方图
 * @fw: 防火墙信息
 * @size: 数据包大小（字节）
 *
 * 热路径调用，使用 atomic64 无锁递增
 * 5 个桶：Tiny(<64B) Small(64-256B) Medium(256-1024B) Large(1024-1500B) Jumbo(>1500B)
 */
static inline void record_packet_size(struct firewall_info *fw, u32 size) {
  if (unlikely(!fw))
    return;

  if (size < 64) {
    atomic64_inc(&fw->pkt_size_tiny);
  } else if (size < 256) {
    atomic64_inc(&fw->pkt_size_small);
  } else if (size < 1024) {
    atomic64_inc(&fw->pkt_size_medium);
  } else if (size <= 1500) {
    atomic64_inc(&fw->pkt_size_large);
  } else {
    atomic64_inc(&fw->pkt_size_jumbo);
  }
}

/**
 * record_ttl - 记录数据包 TTL 值到直方图
 * @fw: 防火墙信息
 * @ttl: 数据包 TTL 值（0-255）
 *
 * 热路径调用，使用 atomic64 无锁递增
 * 6 个桶：Scan(=1) VeryShort(2-32) Short(33-64) Normal(65-128) Long(129-192) Max(193-255)
 */
static inline void record_ttl(struct firewall_info *fw, u8 ttl) {
  if (unlikely(!fw))
    return;

  if (ttl == 1) {
    atomic64_inc(&fw->ttl_scan);
  } else if (ttl <= 32) {
    atomic64_inc(&fw->ttl_very_short);
  } else if (ttl <= 64) {
    atomic64_inc(&fw->ttl_short);
  } else if (ttl <= 128) {
    atomic64_inc(&fw->ttl_normal);
  } else if (ttl <= 192) {
    atomic64_inc(&fw->ttl_long);
  } else {
    atomic64_inc(&fw->ttl_max);
  }
}

/**
 * record_ip_frag - 记录 IP 分片统计
 * @fw: 防火墙信息
 * @is_fragment: 是否为分片包（MF=1 或 frag_offset != 0）
 *
 * 热路径调用，使用 atomic64 无锁递增
 * 跟踪总分片数和总 IP 包数，用于计算分片比例
 */
static inline void record_ip_frag(struct firewall_info *fw, bool is_fragment) {
  if (unlikely(!fw))
    return;

  atomic64_inc(&fw->ip_total_count);
  if (is_fragment)
    atomic64_inc(&fw->ip_frag_count);
}

/**
 * get_rate_lock - 获取对应地址族的 per-bucket 自旋锁
 * @fw: 防火墙信息
 * @af: 地址族
 * @bucket: 桶索引
 */
static inline spinlock_t *get_rate_lock(struct firewall_info *fw, u8 af, u32 bucket) {
  if (af == FW_AF_INET6)
    return &fw->rate_locks_ipv6[bucket];
  return &fw->rate_locks_ipv4[bucket];
}

/**
 * validate_ipv4_address - 验证 IPv4 地址是否合法
 * @ip: IPv4 地址（网络字节序）
 * @ip_str: IP 字符串（保留参数，未来用于日志）
 * @context: 上下文描述（保留参数，未来用于日志）
 * @allow_loopback: 是否允许回环地址
 * 返回: 0 表示合法，-EINVAL 表示非法
 */
static inline int validate_ipv4_address(__be32 ip, const char *ip_str __maybe_unused,
                                        const char *context __maybe_unused,
                                        bool allow_loopback) {
  unsigned int ip_num = ntohl(ip);

  if (ip == 0 || ip == 0xFFFFFFFF) {
    return -EINVAL;
  }
  if (!allow_loopback && (ip_num & 0xFF000000) == 0x7F000000) {
    return -EINVAL;
  }
  if ((ip_num & 0xF0000000) == 0xE0000000) {
    return -EINVAL;
  }
  if ((ip_num & 0xFF000000) == 0x00000000) {
    return -EINVAL;
  }
  if ((ip_num & 0xFF000000) == 0xFF000000) {
    return -EINVAL;
  }

  return 0;
}

/**
 * validate_ipv6_address - 验证 IPv6 地址是否合法
 * @addr: IPv6 地址
 * @ip_str: IP 字符串（保留参数，未来用于日志）
 * @context: 上下文描述（保留参数，未来用于日志）
 * @allow_loopback: 是否允许回环地址
 * 返回: 0 表示合法，-EINVAL 表示非法
 */
static inline int validate_ipv6_address(const struct in6_addr *addr,
                                        const char *ip_str __maybe_unused,
                                        const char *context __maybe_unused,
                                        bool allow_loopback) {
  if (ipv6_addr_any(addr)) {
    return -EINVAL;
  }
  if (!allow_loopback && ipv6_addr_loopback(addr)) {
    return -EINVAL;
  }
  /* 拒绝 multicast 和 link-local */
  if (ipv6_addr_is_multicast(addr)) {
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
                                      const char *context, bool allow_loopback) {
  if (af == FW_AF_INET6)
    return validate_ipv6_address((const struct in6_addr *)ip, ip_str, context, allow_loopback);
  return validate_ipv4_address(*(__be32 *)ip, ip_str, context, allow_loopback);
}

/**
 * is_local_ip - 检查是否为本机接口精确地址（热路径缓存）
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 * 返回：true 如果是本机接口地址（/32 或 /128）
 *
 * 缓存由 netdev_notifier 刷新；仅存精确主机地址，同网段其他主机不豁免。
 */
static inline bool is_local_ip(struct firewall_info *fw, u8 af, const void *ip) {
  struct local_ip_cache *cache;
  unsigned int count, i;

  /* RCU 读侧：一次解引用同时获得 count 与 entries，杜绝拆分发布 TOCTOU */
  rcu_read_lock();
  cache = rcu_dereference(fw->local_ip_cache);
  if (!cache || cache->count == 0) {
    rcu_read_unlock();
    return false;
  }
  count = cache->count;

  if (af == FW_AF_INET6) {
    const struct in6_addr *ip6 = ip;
    for (i = 0; i < count; i++) {
      if (cache->entries[i].af == FW_AF_INET6) {
        u8 prefix = READ_ONCE(cache->entries[i].mask.prefix_len);
        if (ipv6_prefix_equal(ip6, &cache->entries[i].addr.ipv6, prefix)) {
          rcu_read_unlock();
          return true;
        }
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    for (i = 0; i < count; i++) {
      if (cache->entries[i].af == FW_AF_INET) {
        __be32 mask = READ_ONCE(cache->entries[i].mask.ipv4_mask);
        __be32 cached_ip = READ_ONCE(cache->entries[i].addr.ipv4);
        if ((ipv4 & mask) == (cached_ip & mask)) {
          rcu_read_unlock();
          return true;
        }
      }
    }
  }
  rcu_read_unlock();
  return false;
}

#endif /* FIREWALL_H */
