/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_types.h - 内核防火墙模块的内部类型与常量（无数据所有权）
 *
 * 本文件不含任何可变数据，只放三类东西：
 *   1. 契约生成头（两份 *_uapi.h）的引入与对外常量的再导出
 *   2. 内部结构体定义（每个结构体归属一个模块，见各模块头文件）
 *   3. 热路径 static inline 原语（哈希、地址比较、校验、协议异常判定）
 *
 * 设计来源：docs/zh/development/kernel-rewrite-design.md
 *
 * 锁顺序协议（必须遵守，违反即死锁）
 * ----------------------------------
 *   ban 层桶锁      (spin_lock_bh，每层每桶一把，见 struct fw_ban_layer)
 *   ban_layer_lock  (spin_lock_bh，封禁表「已用前缀长度」位图与层计数)
 *     └─ 与桶锁**不嵌套**：层内增删在桶锁内完成，位图维护在桶锁释放之后
 *   wl_lock         (spin_lock_bh)
 *   rate_locks[bkt] (spin_lock_bh)
 *     └─ rate_slot_lock 唯一允许的嵌套：建速率条目时「探测空槽 + 发布」必须原子
 *   flood_lock      (spin_lock_bh)
 *   stats 表锁      (spin_lock_bh，仅 flush/惰性建条目)
 *
 * 规则：
 *   - 除 rate_locks[bkt] → rate_slot_lock 这一对之外，任意两把锁**不得嵌套持有**；
 *     需要跨表操作时先释放再取。
 *   - 热路径（软中断）不持有其中任何一把（速率桶锁仅在建条目的冷路径取）。
 *   - 删除路径一律 hlist_del_rcu + call_rcu，锁只保护链表的增删与遍历边界。
 */

#ifndef FW_TYPES_H
#define FW_TYPES_H

#include <linux/atomic.h>
#include <linux/bitmap.h>
#include <linux/errno.h>
#include <linux/hash.h>
#include <linux/if_addr.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/jhash.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/workqueue.h>

/* 契约生成头：线格式与文本协议的单一真相源，禁止在本目录手改 */
#include "../../contract/generated/netlink_uapi.h"
#include "../../contract/generated/procfs_uapi.h"

/* ============================================================================
 * 地址族：直接复用契约枚举，保证三端同值
 * ==========================================================================*/
#define FW_AF_INET FW_ADDR_FAMILY_INET   /* 2  */
#define FW_AF_INET6 FW_ADDR_FAMILY_INET6 /* 10 */

/* ============================================================================
 * 表规模常量
 * ==========================================================================*/

/* 封禁表：按 prefix_len 分层，每层一组桶头；条目上限由 fw_max_ban_entries 控制。
 *
 * 全长层（IPv4 /32、IPv6 /128）承载「精确单机」封禁——既有全部调用点都是它，
 * 桶数与旧实现一致（BAN_HASH_SIZE），热路径常数项不变。更短的前缀层（/24 这类
 * 网段封禁）条目稀少，每层用小桶数组即可，避免 129 组大桶数组把段撑大。 */
#define BAN_HASH_BITS 12
#define BAN_HASH_SIZE (1 << BAN_HASH_BITS)
/* 层下标即 prefix_len：IPv6 最长 128，故 129 层（IPv4 只用前 33 层） */
#define BAN_MAX_LAYERS 129
#define BAN_SHORT_LAYER_BITS 6 /* 短前缀层每层 64 桶 */
#define BAN_SHORT_LAYER_SIZE (1 << BAN_SHORT_LAYER_BITS)

/* 白名单：64 精确桶 + 子网链；条目上限由 fw_max_whitelist_entries 控制 */
#define WHITELIST_HASH_BITS 6
#define WHITELIST_HASH_SIZE (1 << WHITELIST_HASH_BITS)

/* 速率表：65536 桶；条目上限由 fw_max_rate_entries 控制（既有模块参数） */
#define RATE_HASH_BITS 16
#define RATE_HASH_SIZE (1 << RATE_HASH_BITS)

/* 每 CPU 直接映射槽位（速率窗口计数、UDP 端口分布、ICMP 类型分布） */
#define FW_RATE_CPU_SLOTS 128
#define FW_UDP_CPU_SLOTS 64
#define FW_ICMP_CPU_SLOTS 32

/* 端口扫描：窗口内去重端口上限与触发阈值 */
#define PORT_SCAN_SEEN_MAX 32
#define PORT_SCAN_THRESHOLD 5
#define PORT_SCAN_MAX_RESULTS 20

/* 服务探测：协议种类阈值与展示上限 */
#define SERVICE_PROBE_THRESHOLD 3
#define SERVICE_PROBE_MAX_RESULTS 20

/* 分析表条目上限（读侧全量遍历，无二次截断） */
#define MAX_UDP_PORT_ENTRIES 512
#define MAX_ICMP_TYPE_ENTRIES 128

/* 分析数据在 netlink AnalysisResponse 中打包的子项数上限（契约固定 64） */
#define FW_ANALYSIS_UDP_PACK_MAX 64
#define FW_ANALYSIS_ICMP_PACK_MAX 64

/* 包大小 / TTL 直方图桶数（与契约 AnalysisResponse 固定长度一致） */
#define FW_PKT_SIZE_BUCKETS 5
#define FW_TTL_BUCKETS 6

/* 地址字符串缓冲区（"2001:db8::ffff:ffff:ffff:ffff" 最长） */
#define FW_INET6_STR_LEN 48

/* 封禁时长边界（秒）：procfs 与模块参数共用 */
#define FW_BAN_TIME_MIN 1
#define FW_BAN_TIME_MAX 31536000 /* 365 天 */

/* 默认配置（模块参数与运行态默认值） */
#define DEFAULT_BAN_TIME 600
#define DEFAULT_RATE_WINDOW_SECONDS 1
#define DEFAULT_MAX_PACKETS_PER_SECOND 100000
#define DEFAULT_MAX_BYTES_PER_SECOND (100ULL * 1024 * 1024)
#define DEFAULT_MAX_SYN_PER_SECOND 2000
#define DEFAULT_MAX_UDP_PER_SECOND 10000
#define DEFAULT_MAX_ICMP_PER_SECOND 500
#define DEFAULT_MAX_ACK_PER_SECOND 20000
#define DEFAULT_MAX_RST_PER_SECOND 2000
#define DEFAULT_MAX_FIN_PER_SECOND 2000
#define DEFAULT_DYNAMIC_THRESHOLD_ENABLED 0
#define DEFAULT_DYNAMIC_THRESHOLD_RATIO_X100 300

/* DDoS 自决封禁默认时长（秒）；0 表示走 fw_ban_time */
#define DEFAULT_DDOS_BAN_DURATION 3600

/* EWMA 定点系数：smoothed = (3 * current + 7 * smoothed) / 10（α = 0.3） */
#define FW_EWMA_NUM 3
#define FW_EWMA_DEN 10

/* 全局基线 EWMA：α = 0.01（1/100），跟踪长期趋势 */
#define FW_BASELINE_EWMA_DEN 100

/* TCP 标志位 */
#define FW_TCP_FIN 0x01
#define FW_TCP_SYN 0x02
#define FW_TCP_RST 0x04
#define FW_TCP_ACK 0x10

/* ============================================================================
 * 直方图分桶（热路径判定与读侧共用同一套边界）
 * ==========================================================================*/

/* 包大小 5 桶：Tiny(<64) Small(64-255) Medium(256-1023) Large(1024-1500) Jumbo(>1500) */
static inline int fw_pkt_size_bucket(u32 size) {
  if (size < 64)
    return 0;
  if (size < 256)
    return 1;
  if (size < 1024)
    return 2;
  if (size <= 1500)
    return 3;
  return 4;
}

/* TTL 6 桶：Scan(=1) VeryShort(2-32) Short(33-64) Normal(65-128) Long(129-192) Max(>192) */
static inline int fw_ttl_bucket(u8 ttl) {
  if (ttl == 1)
    return 0;
  if (ttl <= 32)
    return 1;
  if (ttl <= 64)
    return 2;
  if (ttl <= 128)
    return 3;
  if (ttl <= 192)
    return 4;
  return 5;
}

/* ============================================================================
 * 内部结构体
 * ==========================================================================*/

/* 报文字段用契约生成头里的 fw_* 类型；运行期数据结构另用 fw_*_node。
 * 这是刻意的名字区分：契约头里的 struct fw_ban_entry / fw_rate_entry 是**线
 * 格式**（packed、大端、只在 fw_netlink.c 序列化时使用），运行期条目允许有
 * 定时器、链表节点、指针等无法上线的东西。 */
union fw_addr {
  __be32 ipv4;
  struct in6_addr ipv6;
  u8 raw[16];
};

/* 白名单条目：精确匹配条目只入桶；子网条目同时挂子网链 */
struct fw_wl_entry {
  u8 af;
  u8 prefix_len;
  union fw_addr addr;
  char device_name[16];
  struct hlist_node hash;       /* 精确桶节点 */
  struct list_head subnet_node; /* 子网链节点（仅前缀 < 全长时使用） */
  struct rcu_head rcu;
};

/* 封禁条目：per-entry 定时器负责到期摘链，无全局清理线程 */
struct fw_ban_node {
  u8 af;
  u8 prefix_len; /* 32/128 = 精确单机；更短 = 网段封禁（条目身份的一部分） */
  u8 is_permanent;
  u32 duration_secs; /* 本次封禁时长（秒），永久为 0；续期时更新 */
  unsigned long banned_at;     /* jiffies */
  unsigned long unban_jiffies; /* 到期 jiffies；永久条目无意义 */
  union fw_addr addr;
  char jail_name[32];
  char reason[32];
  struct hlist_node hash;
  struct rcu_head rcu;
  struct timer_list expire_timer;
};

/*
 * 封禁表的一层（一个前缀长度）：
 *
 *   - buckets/locks 指向该层的桶头与同宽锁数组。全长层复用表内的 full_buckets /
 *     full_locks（与旧实现同规模），短前缀层用本层内嵌的小数组——两者访问方式
 *     统一，因此增删查代码不必为全长层写特例。
 *   - bucket_bits 是该层的桶索引位宽（桶数 = 1 << bucket_bits）。
 *   - count 记录层内条目数：它是「该层是否还非空」的判据，位图清位必须有它，
 *     否则无法在 O(1) 内判断层已空（逐桶扫描是 O(层桶数)）。
 */
struct fw_ban_layer {
  struct hlist_head *buckets;
  spinlock_t *locks;
  u8 bucket_bits;
  u8 pad[3];
  atomic_t count;
  struct hlist_head short_buckets[BAN_SHORT_LAYER_SIZE];
  spinlock_t short_locks[BAN_SHORT_LAYER_SIZE];
};

/*
 * 封禁表（按前缀长度分层，见 docs/zh/development/cluster-detection-design.md §4.2）
 *
 * 前缀封禁无法用「按完整地址哈希」直接命中：同一 /24 内不同源 IP 会散落到不同桶；
 * 而逐层探测（每个候选前缀长度各算一次哈希）在 IPv4 要 32 次、IPv6 要 129 次，
 * 热路径不可接受。分层后查询只遍历 used 位图中置位的层（常态 1–3 层），每层一次
 * 哈希；层内桶索引按**该层前缀归一化后的地址**计算，所以同一网段内任意源 IP 必然
 * 落到同一桶。
 *
 * used 位图（bit i = 层 i 非空）由 fw_ban_layer_mark/unmark 在增删时维护，
 * 清位判据见那两个函数的注释。
 */
struct fw_ban_table {
  u8 max_prefix; /* IPv4 32 / IPv6 128：最长前缀即「精确单机」层 */
  u8 pad[3];
  struct hlist_head full_buckets[BAN_HASH_SIZE]; /* 全长层的桶头 */
  spinlock_t full_locks[BAN_HASH_SIZE];          /* 全长层的桶锁 */
  struct fw_ban_layer layers[BAN_MAX_LAYERS];    /* 下标即 prefix_len */
  DECLARE_BITMAP(used, BAN_MAX_LAYERS); /* 已用前缀长度位图（热路径只读） */
};

/*
 * 速率条目：保存窗口起点与 EWMA 平滑值。
 *
 *   - smoothed_* 是判定路径要读的值，热路径无锁读取，故用 atomic64_t。
 *   - 窗口内原始计数在 per-CPU 槽（fw_rate_cpu_slot），窗口滚动时由抢到
 *     选举的那个 CPU 汇总各 CPU 槽并清零（见 fw_rate.c）。这也是「热路径只写
 *     本 CPU 内存」得以成立的原因：每包只碰自己的槽，跨 CPU 汇总仅发生在滚动。
 *   - rolling 是窗口滚动的选举开关：只有 cmpxchg 成功的那个 CPU 结算本窗口，
 *     这样滚动路径无需自旋锁，热路径全程无锁。
 *   - seen_ports/seen_port_n/unique_ports/port_scan_counted 只由滚动者改写。
 */
struct fw_rate_node {
  u8 af;
  union fw_addr addr;

  /* EWMA 平滑值（窗口滚动时更新，热路径原子读） */
  atomic64_t smoothed_pps;
  atomic64_t smoothed_bps;
  atomic64_t smoothed_syn;
  atomic64_t smoothed_udp;
  atomic64_t smoothed_icmp;
  atomic64_t smoothed_ack;
  atomic64_t smoothed_rst;
  atomic64_t smoothed_fin;

  atomic_t rolling;           /* 窗口滚动选举：0 空闲，1 结算中 */
  u8 slot_idx;                /* 本条目在每 CPU 槽表中的固定下标 */
  unsigned long window_start; /* 当前窗口起点（jiffies），仅滚动者写 */
  unsigned long last_activity;

  u16 seen_ports[PORT_SCAN_SEEN_MAX]; /* 窗口内去重端口并集 */
  u8 seen_port_n;
  u8 port_scan_counted;
  u32 unique_ports;

  struct hlist_node hash;
  struct rcu_head rcu;
};

/*
 * 每 CPU 速率槽：直接映射表的一项，按 fw_hash_addr() % FW_RATE_CPU_SLOTS 定位。
 *
 * 只有本 CPU 的热路径写这里；窗口滚动时由本 CPU 的槽把这些计数折回所属条目
 * （atomic），因此计数是 atomic64_t。
 *
 * entry 指回该槽归属的条目，使槽位被顶替时**无需二次查表**即可把旧计数折回
 * 对应条目。指针安全性：删除条目时先在所有 CPU 上把引用它的槽清零（entry 置
 * NULL），再 synchronize_rcu() 释放，因此 RCU 读者要么读到空槽，要么读到的
 * 条目必然存活。
 */
struct fw_rate_cpu_slot {
  u8 af;
  u8 seen_port_n;
  u8 port_scan_counted;
  union fw_addr addr;
  struct fw_rate_node __rcu *entry;
  atomic64_t packets;
  atomic64_t bytes;
  atomic64_t syn;
  atomic64_t udp;
  atomic64_t icmp;
  atomic64_t ack;
  atomic64_t rst;
  atomic64_t fin;
  u16 seen_ports[PORT_SCAN_SEEN_MAX];
  unsigned long last_activity;
};

/* 每 CPU 速率槽表 */
struct fw_rate_pcpu {
  struct fw_rate_cpu_slot slots[FW_RATE_CPU_SLOTS];
} ____cacheline_aligned_in_smp;

/*
 * 速率表清空（fw_rate_clear_all）的跨 CPU 上下文。
 *
 * 摘链必须与「热路径重绑槽位」互斥，否则可能把一个即将被释放的条目重新挂进
 * 某个槽（其 entry 指针随后悬空）。做法：先置 clearing 让热路径的槽位重绑
 * 走慢路径（本函数已完成清槽后，重绑会重新查表），再用 on_each_cpu 在**各
 * CPU 本地**清掉指向待删条目的槽（本地写，避免跨 CPU 写槽）。CFS 上
 * on_each_cpu 的每个回调都能抢占软中断，故清槽与任意在跑的热路径必然串行。
 */
struct fw_rate_clear_ctx {
  bool clearing;
  u8 af;
  struct {
    DECLARE_HASHTABLE(buckets, RATE_HASH_BITS);
  } pre;
};

/* 每 CPU 统计分析槽（UDP 端口分布） */
struct fw_udp_cpu_slot {
  u16 port;
  u64 packets;
  u64 bytes;
  unsigned long last_seen;
};

/* 每 CPU 统计分析槽（ICMP 类型分布） */
struct fw_icmp_cpu_slot {
  u8 type;
  u8 code;
  u64 packets;
  u64 bytes;
  unsigned long last_seen;
};

/*
 * 每 CPU 统计块：热路径只写本 CPU 的这一份，读侧先跨 CPU 冲刷再取全局值。
 * 与旧实现的区别：不再用「全局 atomic + 每 1024 包 flush」的批次方案，
 * 每包只触碰本 CPU 内存，因此每包共享 cache line 写为 0。
 */
struct fw_stats_pcpu {
  u64 packets_accepted;
  u64 packets_dropped;
  u64 tcp_anomaly_dropped;
  u64 global_packets; /* 全局流量计数（供 daemon 计算 PPS 基线） */
  u64 global_bytes;
  u64 pkt_sizes[FW_PKT_SIZE_BUCKETS];
  u64 ttl_dist[FW_TTL_BUCKETS];
  u64 ip_frag_total;
  u64 ip_frag_count;
  struct fw_udp_cpu_slot udp[FW_UDP_CPU_SLOTS];
  struct fw_icmp_cpu_slot icmp[FW_ICMP_CPU_SLOTS];
} ____cacheline_aligned_in_smp;

/* UDP 端口分布全局表条目（读侧汇总用） */
struct fw_udp_port_entry {
  u16 port;
  atomic64_t packets;
  atomic64_t bytes;
  unsigned long last_seen;
  struct hlist_node hash;
  struct rcu_head rcu;
};

/* ICMP 类型分布全局表条目（读侧汇总用） */
struct fw_icmp_type_entry {
  u8 type;
  u8 code;
  atomic64_t packets;
  atomic64_t bytes;
  unsigned long last_seen;
  struct hlist_node hash;
  struct rcu_head rcu;
};

/* 端口扫描者 / 服务探测者展示条目 */
struct fw_scanner_row {
  u8 af;
  union fw_addr addr;
  u32 metric;
  u64 packets;
};

/* 读侧遍历行：与契约线格式同形，供 fw_netlink 直接序列化、供 procfs 直接打印 */
struct fw_ban_row {
  u8 af;
  u8 is_permanent;
  u8 prefix_len;
  u32 duration_secs;
  u64 banned_at; /* Unix 秒 */
  union fw_addr addr;
  char jail_name[32];
  char reason[32];
};

struct fw_wl_row {
  u8 af;
  u8 prefix_len;
  union fw_addr addr;
  char device_name[16];
};

struct fw_rate_row {
  u8 af;
  union fw_addr addr;
  u64 packets;
  u64 bytes;
  u64 syn_packets;
  u64 udp_packets;
  u64 icmp_packets;
  u64 ack_packets;
  u64 rst_packets;
  u64 fin_packets;
};

struct fw_udp_port_row {
  u16 port;
  u64 packets;
  u64 bytes;
  u64 last_seen_secs;
};

struct fw_icmp_type_row {
  u8 type;
  u8 code;
  u64 packets;
  u64 bytes;
  u64 last_seen_secs;
};

/* 分析数据快照：一次取齐，供 procfs 的 5 个分析条目与 netlink ANALYSIS_RESPONSE 共用 */
struct fw_analysis_snapshot {
  u64 pkt_sizes[FW_PKT_SIZE_BUCKETS];
  u64 ttl_dist[FW_TTL_BUCKETS];
  u64 ip_frag_total;
  u64 ip_frag_count;

  u32 udp_count;
  u32 udp_capacity;
  struct fw_udp_port_row udp[FW_ANALYSIS_UDP_PACK_MAX];

  u32 icmp_count;
  u32 icmp_capacity;
  struct fw_icmp_type_row icmp[FW_ANALYSIS_ICMP_PACK_MAX];

  u32 port_scan_count;
  u32 port_scan_threshold;
  struct fw_scanner_row port_scanners[PORT_SCAN_MAX_RESULTS];

  u32 service_probe_count;
  u32 service_probe_threshold;
  struct fw_scanner_row service_probes[SERVICE_PROBE_MAX_RESULTS];
};

/* 本机地址集合：开放寻址哈希集，只存精确主机地址（不含子网豁免） */
struct fw_local_slot {
  u8 af;
  u8 used;
  u16 pad;
  union fw_addr addr;
};

struct fw_local_set {
  u32 capacity; /* 2 的幂 */
  u32 count;
  struct rcu_head rcu; /* 换表时旧表由 kfree_rcu 释放 */
  struct fw_local_slot slots[];
};

/*
 * 受保护端口位图：固定 65536 位（8KB），位 i 置位表示端口 i 受保护
 * ——即该端口的入站流量参与 DDoS 速率判定。
 *
 * 由 daemon 扫描本机对外监听端口后经 netlink 下发（见 contract/netlink.fwidl
 * 的 SetProtectedPorts）。整体 rcu_assign_pointer 换指针、旧表 kfree_rcu 释放，
 * 因此热路径只需一次位测试、无锁无分配。
 *
 * bitmap 用 unsigned long 而非 u8：内核的 test_bit / bitmap_weight 要求
 * `unsigned long *`，按字节数组声明会在 -Werror 下报指针类型不兼容。线格式
 * 仍是 8192 字节（netlink 侧按字节拷贝，两者大小一致）。
 *
 * 空指针语义：**未下发位图时视为全端口受保护**——daemon 不在位不等于关掉
 * 检测；详见 fw_ports_is_protected()。
 */
#define FW_PROTECTED_PORTS_BYTES 8192
#define FW_PROTECTED_PORTS_MAX 65536

/*
 * /proc/firewall/protected_ports 的展示行数上限：位图容量是 65536 位，
 * 逐位全列会给 seq_file 造出数万行文本（且人读无意义）。超出即截断并打印
 * 已截断提示与受保护总数，保证「有多少端口受保护」始终可读。
 */
#define FW_PROCFS_PROTECTED_PORTS_MAX_LINES 256

struct fw_protected_ports {
  u32 count; /* 置位端口数（观测用） */
  u32 pad;
  struct rcu_head rcu; /* 换表时旧表由 kfree_rcu 释放 */
  unsigned long bitmap[DIV_ROUND_UP(FW_PROTECTED_PORTS_MAX, BITS_PER_LONG)];
};

/* 统计快照（读侧一次性取齐，避免多次遍历） */
struct fw_stats_snapshot {
  u64 total_bans;
  u64 total_unbans;
  u64 whitelist_rejects;
  u64 ban_table_full_rejects;
  u64 alloc_failures;
  u64 packets_dropped;
  u64 packets_accepted;
  u64 tcp_anomaly_dropped;
  u64 cleanup_cycles;
  u64 cleanup_expired_total;
  u64 current_bans;
  u64 current_whitelist;
  u64 recent_additions;
  u64 global_packets;
  u64 global_bytes;
};

/*
 * 全局单例。字段按模块分组，每个模块只触碰自己那一组。
 * 「全局计数器」一律为 atomic，且**只**由冷路径（flush、事件回调）写入。
 */
struct fw_info {
  /* ---- 封禁表（fw_ban.c） ---- */
  struct fw_ban_table ban_v4;
  struct fw_ban_table ban_v6;
  spinlock_t ban_layer_lock; /* 保护两张表的 used 位图与层计数（见 fw_ban.c mark/unmark） */
  atomic_t ban_count;
  unsigned int max_ban_entries;

  /* ---- 白名单（fw_wl.c） ---- */
  DECLARE_HASHTABLE(wl_ipv4, WHITELIST_HASH_BITS);
  DECLARE_HASHTABLE(wl_ipv6, WHITELIST_HASH_BITS);
  struct list_head wl_subnet_ipv4;
  struct list_head wl_subnet_ipv6;
  spinlock_t wl_lock;
  atomic_t wl_count;
  atomic_t wl_reject_count;
  unsigned int max_wl_entries;

  /* ---- 本机地址集合（fw_local.c） ---- */
  struct fw_local_set __rcu *local_set;
  unsigned int max_local_ips;

  /* ---- 受保护端口位图（fw_ports.c） ---- */
  struct fw_protected_ports __rcu *protected_ports;

  /* ---- 速率表（fw_rate.c） ---- */
  DECLARE_HASHTABLE(rate_ipv4, RATE_HASH_BITS);
  DECLARE_HASHTABLE(rate_ipv6, RATE_HASH_BITS);
  spinlock_t rate_locks[RATE_HASH_SIZE];
  atomic_t rate_count;
  spinlock_t rate_slot_lock; /* 保护槽位「探测空槽 + 发布」这一对操作 */
  struct fw_rate_pcpu __percpu *rate_pcpu;
  struct fw_rate_clear_ctx rate_clear_ctx;

  /* 速率配置（运行态，由 SET_CONFIG / procfs 修改） */
  unsigned int rate_window_seconds;
  unsigned long rate_window_jiffies;
  u64 max_packets_per_second;
  u64 max_bytes_per_second;
  u64 max_syn_per_second;
  u64 max_udp_per_second;
  u64 max_icmp_per_second;
  u64 max_ack_per_second;
  u64 max_rst_per_second;
  u64 max_fin_per_second;
  bool dynamic_threshold_enabled;
  bool static_threshold_enabled;
  u32 dynamic_threshold_ratio_x100;
  u64 baseline_pps; /* EWMA α=0.01，由 daemon 或内核更新 */
  u64 baseline_bps;
  u32 ddos_ban_duration;

  /* ---- 泛洪保护（fw_ban.c） ---- */
  spinlock_t flood_lock;
  unsigned long flood_window_start;
  unsigned int recent_additions;
  unsigned int max_bans_per_second;

  /* ---- 统计（fw_stats.c） ---- */
  atomic64_t total_bans;
  atomic64_t total_unbans;
  atomic64_t ban_table_full_rejects;
  atomic64_t alloc_failures;
  atomic64_t packets_dropped;
  atomic64_t packets_accepted;
  atomic64_t tcp_anomaly_dropped;
  atomic64_t cleanup_cycles; /* 有意保留：恒为 0，仅为不破坏外部解析 */
  atomic64_t cleanup_expired_total;
  atomic64_t rate_slot_spill; /* per-CPU 速率槽被顶替且找不到条目时的计数 */
  atomic64_t global_traffic_packets;
  atomic64_t global_traffic_bytes;

  /* ---- 分析表（fw_stats.c） ---- */
  DECLARE_HASHTABLE(udp_port_table, 8);
  spinlock_t udp_port_lock;
  atomic_t udp_port_count;
  DECLARE_HASHTABLE(icmp_type_table, 6);
  spinlock_t icmp_type_lock;
  atomic_t icmp_type_count;
  atomic_t port_scan_detected;

  /* ---- netfilter 钩子（fw_hook.c） ---- */
  atomic_t shutting_down;

  /* ---- procfs（fw_procfs.c） ---- */
  struct proc_dir_entry *proc_dir;
  struct proc_dir_entry *proc_bans;
  struct proc_dir_entry *proc_whitelist;
  struct proc_dir_entry *proc_config;
  struct proc_dir_entry *proc_stats;
  struct proc_dir_entry *proc_rates;
  struct proc_dir_entry *proc_udp_ports;
  struct proc_dir_entry *proc_icmp_types;
  struct proc_dir_entry *proc_pkt_sizes;
  struct proc_dir_entry *proc_ttl_dist;
  struct proc_dir_entry *proc_ip_frags;
  struct proc_dir_entry *proc_port_scanners;
  struct proc_dir_entry *proc_service_probes;
  struct proc_dir_entry *proc_protected_ports;

  /* ---- netdev（fw_netdev.c） ---- */
  struct notifier_block netdev_notifier;
  struct delayed_work sync_work;
  bool netdev_notifier_registered;
};

/* 全局单例与哈希种子（fw_main.c 定义） */
extern struct fw_info fw_info;
extern u32 fw_hash_seed;

/* netfilter 钩子注册表（fw_hook.c 定义；fw_main.c 在 init/exit 中注册与注销） */
extern struct nf_hook_ops nf_ops_ipv4;
extern struct nf_hook_ops nf_ops_ipv6;

/* 模块参数（fw_main.c 定义） */
extern unsigned int fw_ban_time;
extern char *fw_state_file;
extern unsigned int fw_max_bans_per_second;
extern unsigned int fw_max_rate_entries;
extern unsigned int fw_max_ban_entries;
extern unsigned int fw_max_whitelist_entries;
extern unsigned int fw_max_local_ips;
extern unsigned int fw_static_threshold;
extern unsigned int fw_dynamic_threshold;
extern unsigned int fw_ddos_detection;

/* ============================================================================
 * 热路径 static inline 原语
 * ==========================================================================*/

/* 地址比较：整体比较即可，白名单/封禁条目发布后不再修改 */
static inline bool fw_addr_equal(u8 af, const void *a, const void *b) {
  if (af == FW_AF_INET6)
    return ipv6_addr_equal((const struct in6_addr *)a, (const struct in6_addr *)b);
  return *(__be32 *)a == *(__be32 *)b;
}

/* 桶索引：v4/v6 统一走 jhash + 每引导随机种子，防哈希碰撞攻击 */
static inline u32 fw_hash_addr(u8 af, const void *ip, int bits) {
  if (af == FW_AF_INET6)
    return jhash(ip, sizeof(struct in6_addr), fw_hash_seed) & ((1 << bits) - 1);
  return jhash_1word((__force u32) * (__be32 *)ip, fw_hash_seed) & ((1 << bits) - 1);
}

/*
 * 地址族的最长前缀：即「精确单机」的前缀长度（IPv4 /32、IPv6 /128）。
 * 封禁表按它区分全长层与短前缀层；调用点用它补齐旧接口缺省的前缀长度。
 */
static inline u8 fw_max_prefix_len(u8 af) {
  return af == FW_AF_INET6 ? 128 : 32;
}

/*
 * 前缀匹配：地址是否落在 network/prefix_len 内。
 * 白名单子网链、封禁表热路径与「白名单变更 → 解封联动」共用本原语，
 * 避免多处各写一套前缀比较（两套必然漂移）。前缀长度合法性由调用方保证。
 */
static inline bool fw_prefix_match(u8 af, const void *ip, const void *network, u8 prefix_len) {
  if (af == FW_AF_INET) {
    __be32 a = *(__be32 *)ip, n = *(__be32 *)network;
    __be32 mask = prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len));

    return (a & mask) == (n & mask);
  } else {
    const u8 *a = ip, *n = network;
    u32 full = prefix_len / 8;
    u8 rem = prefix_len % 8;

    if (full && memcmp(a, n, full) != 0)
      return false;
    if (rem) {
      u8 m = (u8)(0xFF << (8 - rem));

      if ((a[full] & m) != (n[full] & m))
        return false;
    }
    return true;
  }
}

/* 地址转字符串（日志与 procfs 用，热路径不调用） */
static inline void fw_addr_to_str(u8 af, const void *ip, char *buf, size_t len) {
  if (af == FW_AF_INET6) {
    if (len < FW_INET6_STR_LEN) {
      if (len)
        buf[0] = '\0';
      return;
    }
    snprintf(buf, len, "%pI6", (const struct in6_addr *)ip);
  } else {
    snprintf(buf, len, "%pI4", (const __be32 *)ip);
  }
}

/*
 * 把地址按 prefix_len 归一化为 network 地址（清掉掩码之外的位）。
 *
 * 白名单表存的是 **network 地址**（fw_wl_add / fw_wl_remove / fw_wl_find_locked
 * 都只做整体比较，不做掩码），因此所有非热路径调用者——procfs 写侧、状态恢复、
 * netdev 对账——必须先过本函数。否则同一子网会因主机位不同而写入多条表项，
 * 且按归一化地址 remove 时查不到。
 *
 * 热路径不使用本原语：入站报文的源地址不做归一化，子网命中由 fw_prefix_match
 * 现场比较（见 fw_wl_lookup 的子网链）。
 */
static inline void fw_addr_normalize(u8 af, void *addr, u8 prefix_len) {
  if (af == FW_AF_INET) {
    __be32 *a = addr;

    *a &= prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len));
  } else {
    u8 *b = addr;
    u32 full = prefix_len / 8;
    u8 rem = prefix_len % 8;
    u32 i, start = full;

    if (rem) {
      b[full] &= (u8)(0xFF << (8 - rem));
      start++;
    }
    for (i = start; i < 16; i++)
      b[i] = 0;
  }
}

/*
 * 源地址合法性：热路径判定「非法即放行」。非法地址不进入任何表查询，
 * 也不计入丢弃统计（它们本就不该被防火墙处理）。
 */
static inline bool fw_src_is_invalid_ipv4(__be32 ip) {
  u32 h = ntohl(ip);

  if (ip == 0 || ip == 0xFFFFFFFFU)
    return true; /* 0.0.0.0 / 广播 */
  if ((h & 0xFF000000U) == 0x7F000000U)
    return true; /* 回环 */
  if ((h & 0xF0000000U) == 0xE0000000U)
    return true; /* 组播 */
  if ((h & 0xFF000000U) == 0x00000000U)
    return true; /* 0.0.0.0/8 */
  if ((h & 0xFF000000U) == 0xFF000000U)
    return true; /* 255.0.0.0/8 */
  return false;
}

static inline bool fw_src_is_invalid_ipv6(const struct in6_addr *a) {
  if (ipv6_addr_any(a))
    return true;
  if (ipv6_addr_loopback(a))
    return true;
  if (ipv6_addr_is_multicast(a))
    return true;
  if (ipv6_addr_type(a) & IPV6_ADDR_LINKLOCAL)
    return true;
  return false;
}

/* 地址是否可作为封禁目标（procfs/netlink 写侧校验，允许回环关闭） */
static inline bool fw_addr_is_valid(u8 af, const void *ip) {
  if (af == FW_AF_INET6)
    return !fw_src_is_invalid_ipv6((const struct in6_addr *)ip);
  return !fw_src_is_invalid_ipv4(*(__be32 *)ip);
}

/*
 * TCP 标志异常判定：SYN+FIN / SYN+RST 为协议不允许的组合；
 * 四个主要标志位全零为 NULL 扫描。
 */
static inline bool fw_tcp_flag_anomaly(u8 flags) {
  u8 masked = flags & (FW_TCP_SYN | FW_TCP_FIN | FW_TCP_RST | FW_TCP_ACK);

  if ((masked & FW_TCP_SYN) && (masked & (FW_TCP_FIN | FW_TCP_RST)))
    return true;
  if (masked == 0)
    return true;
  return false;
}

/* 是否处于关闭中：热路径第一道判断，置位后一律放行 */
static inline bool fw_is_shutting_down(void) {
  return unlikely(atomic_read(&fw_info.shutting_down) != 0);
}

#endif /* FW_TYPES_H */
