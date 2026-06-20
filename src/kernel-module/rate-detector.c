// SPDX-License-Identifier: GPL-2.0
/*
 * rate-detector.c - IP 速率检测（DDoS 防护）
 *
 * 设计目标：10Gbps（~1500 万 PPS）场景下，每个数据包的处理开销 < 100ns
 *
 * 核心算法：滑动窗口速率统计
 * - 时间窗口：默认 1 秒（可配置）
 * - 统计维度：packet_count（数据包数）、byte_count（字节数）
 * - 检测逻辑：超过 max_packets_per_second 或 max_bytes_per_second 触发封禁
 *
 * 并发控制：
 * - RCU（Read-Copy-Update）：读操作无锁，写操作使用 per-bucket spinlock
 * - 原子计数器：packet_count/byte_count 使用 atomic64_t，避免锁竞争
 * - per-bucket 锁：4096 个桶，每个桶独立锁，减少高并发场景下的锁竞争
 *
 * 性能优化：
 * 1. 缓存友好的内存布局：IP 地址在前，时间戳在后
 * 2. 哈希表快速查找：O(1) 平均时间复杂度
 * 3. 批量更新：减少原子操作的开销
 * 4. 过期清理：定时清理不活跃的条目，避免内存泄漏
 */

#include "firewall.h"
#include <linux/jiffies.h>
#include <linux/slab.h>

/* 速率条目过期时间（秒）- 超过此时间未活动的条目将被清理 */
#define RATE_ENTRY_EXPIRE_SECONDS 10

/**
 * free_rate_entry_rcu - RCU 回调函数，释放速率条目
 * @head: RCU 头
 *
 * 在 RCU 宽限期结束后调用，安全释放内存
 */
void free_rate_entry_rcu(struct rcu_head *head) {
  struct ip_rate_entry *entry = container_of(head, struct ip_rate_entry, rcu_head);
  kfree(entry);
}

/**
 * find_rate_entry - 查找速率条目（RCU 保护）
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 *
 * 返回: 速率条目指针（需要 rcu_read_unlock），未找到返回 NULL
 *
 * 注意：调用方必须持有 rcu_read_lock()
 */
static struct ip_rate_entry *find_rate_entry_rcu(struct firewall_info *fw,
                                                 u8 af, const void *ip) {
  struct hlist_head *table = get_rate_table(fw, af);
  u32 hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);
  struct ip_rate_entry *entry;

  hlist_for_each_entry_rcu(entry, &table[hash], hash) {
    if (entry->af != af)
      continue;
    /* 热路径优化：根据 af 直接比较，避免 compare_ips 的分支开销 */
    if (af == FW_AF_INET) {
      if (entry->addr.ipv4 == *(__be32 *)ip)
        return entry;
    } else {
      if (ipv6_addr_equal(&entry->addr.ipv6, (const struct in6_addr *)ip))
        return entry;
    }
  }

  return NULL;
}

/**
 * evict_lru_rate_entry - 踢出最不活跃的速率条目（LRU 替换）
 * @fw: 防火墙信息
 * @af: 地址族
 *
 * 遍历速率表，找到 last_activity 最旧的条目并删除。
 * 调用方必须持有全局 rate_lock（或遍历期间保证安全）。
 *
 * 返回: 0 成功，-ENOENT 无条目可踢
 */
static int evict_lru_rate_entry(struct firewall_info *fw, u8 af) {
  struct ip_rate_entry *entry, *oldest = NULL;
  struct hlist_node *tmp;
  unsigned long oldest_time = ULONG_MAX;
  struct hlist_head *table = get_rate_table(fw, af);
  int i;

  for (i = 0; i < (1 << RATE_HASH_BITS); i++) {
    spinlock_t *lock = get_rate_lock(fw, af, i);
    spin_lock_bh(lock);

    hlist_for_each_entry_safe(entry, tmp, &table[i], hash) {
      /* 跳过 pinned 条目（白名单 IP 不被 LRU 踢出） */
      if (entry->pinned)
        continue;
      if (time_before(entry->last_activity, oldest_time)) {
        oldest_time = entry->last_activity;
        oldest = entry;
      }
    }

    spin_unlock_bh(lock);
  }

  if (!oldest) {
    return -ENOENT;
  }

  /* 删除最旧条目 */
  i = hash_ip_for_rate(af, &oldest->addr, RATE_HASH_BITS);
  spin_lock_bh(get_rate_lock(fw, af, i));
  hlist_del_rcu(&oldest->hash);
  spin_unlock_bh(get_rate_lock(fw, af, i));
  call_rcu(&oldest->rcu_head, free_rate_entry_rcu);
  atomic_dec(&fw->rate_count);

  return 0;
}

/**
 * create_rate_entry - 创建新的速率条目
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 *
 * 返回: 新创建的条目，失败返回 ERR_PTR
 *
 * 注意：调用方必须持有对应桶的 spinlock
 *
 * 改进：表满时 LRU 替换（踢出 last_activity 最旧的条目），而非拒绝新条目。
 * 支持 10Gbps+ 大规模 DDoS 场景（>65536 源 IP 时自动淘汰不活跃条目）。
 */
static struct ip_rate_entry *create_rate_entry(struct firewall_info *fw, u8 af,
                                               const void *ip) {
  struct ip_rate_entry *entry;
  struct hlist_head *table = get_rate_table(fw, af);
  u32 hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);

  /* 表满时 LRU 替换：踢出最不活跃的条目 */
  if (atomic_read(&fw->rate_count) >= fw_max_rate_entries) {
    if (evict_lru_rate_entry(fw, af) < 0) {
      atomic_inc(&fw->ban_table_full_count);
      return ERR_PTR(-ENOSPC);
    }
  }

  /* 分配内存 */
  entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
  if (!entry) {
    atomic_inc(&fw->alloc_failure_count);
    return ERR_PTR(-ENOMEM);
  }

  /* 初始化字段 */
  entry->af = af;
  if (af == FW_AF_INET) {
    entry->addr.ipv4 = *(__be32 *)ip;
  } else {
    entry->addr.ipv6 = *(struct in6_addr *)ip;
  }

  /* 检查 IP 是否在白名单中，如果是则设置 pinned 标志（LRU 不踢出） */
  entry->pinned = is_in_whitelist(fw, af, ip) ? 1 : 0;

  atomic64_set(&entry->packet_count, 0);
  atomic64_set(&entry->byte_count, 0);
  atomic64_set(&entry->syn_count, 0);
  atomic64_set(&entry->udp_count, 0);
  atomic64_set(&entry->icmp_count, 0);
  atomic64_set(&entry->ack_count, 0);
  atomic64_set(&entry->rst_count, 0);
  atomic64_set(&entry->fin_count, 0);
  atomic64_set(&entry->smoothed_pps, 0);
  atomic64_set(&entry->smoothed_bps, 0);
  atomic64_set(&entry->smoothed_syn, 0);
  atomic64_set(&entry->smoothed_udp, 0);
  atomic64_set(&entry->smoothed_icmp, 0);
  atomic64_set(&entry->smoothed_ack, 0);
  atomic64_set(&entry->smoothed_rst, 0);
  atomic64_set(&entry->smoothed_fin, 0);
  entry->window_start = jiffies;
  entry->last_activity = jiffies;

  /* 插入哈希表 */
  hlist_add_head_rcu(&entry->hash, &table[hash]);
  atomic_inc(&fw->rate_count);

  return entry;
}

/**
 * update_rate_stats - 更新 IP 速率统计
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 * @packet_len: 数据包长度（字节）
 * @protocol: 协议类型（IPPROTO_TCP/IPPROTO_UDP/IPPROTO_ICMP/0）
 *
 * 返回: 0 成功，负数失败
 *
 * 算法：
 * 1. RCU 查找现有条目
 * 2. 如果存在，原子更新计数器
 * 3. 如果不存在，获取 per-bucket 锁，创建新条目
 * 4. 检查窗口是否过期，过期则重置计数器
 *
 * 性能优化：
 * - 热路径（已存在条目）：无锁，只有原子操作
 * - 冷路径（新条目）：per-bucket 锁，减少竞争
 */
int update_rate_stats(struct firewall_info *fw, u8 af, const void *ip,
                      u32 packet_len, u8 protocol, u8 tcp_flags) {
  struct ip_rate_entry *entry;
  unsigned long now = jiffies;
  unsigned long elapsed;
  u32 hash;
  spinlock_t *lock;

  /* 参数验证 */
  if (!fw || !ip) {
    return -EINVAL;
  }

  /* RCU 快速路径：查找现有条目 */
  rcu_read_lock();
  entry = find_rate_entry_rcu(fw, af, ip);

  if (entry) {
    /* 检查窗口是否过期 */
    elapsed = now - entry->window_start;
    if (time_after(now, entry->window_start + fw->rate_window_jiffies)) {
      /* 窗口过期，重置计数器（需要获取锁） */
      rcu_read_unlock();

      hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);
      lock = get_rate_lock(fw, af, hash);
      spin_lock_bh(lock);

      /* 双重检查：可能其他 CPU 已经重置 */
      if (time_after(now, entry->window_start + fw->rate_window_jiffies)) {
        /* 窗口过期，先更新 EWMA 平滑速率，再重置计数器
         * EWMA 公式：smoothed = (3 * current + 7 * smoothed) / 10
         * 作用：过滤突发流量，只有持续高速才触发封禁 */
        {
          unsigned long win_elapsed = now - entry->window_start;
          u64 old_packets, old_bytes, old_syn, old_udp, old_icmp, old_ack, old_rst, old_fin;
          u64 cur_pps, cur_bps, cur_syn, cur_udp, cur_icmp, cur_ack, cur_rst, cur_fin;
          u64 s_pps, s_bps, s_syn, s_udp, s_icmp, s_ack, s_rst, s_fin;

          if (win_elapsed == 0)
            win_elapsed = 1;

          /* 计算当前窗口的实际速率 */
          old_packets = atomic64_read(&entry->packet_count);
          old_bytes = atomic64_read(&entry->byte_count);
          old_syn = atomic64_read(&entry->syn_count);
          old_udp = atomic64_read(&entry->udp_count);
          old_icmp = atomic64_read(&entry->icmp_count);
          old_ack = atomic64_read(&entry->ack_count);
          old_rst = atomic64_read(&entry->rst_count);
          old_fin = atomic64_read(&entry->fin_count);

          cur_pps = (old_packets * HZ) / win_elapsed;
          cur_bps = (old_bytes * HZ) / win_elapsed;
          cur_syn = (old_syn * HZ) / win_elapsed;
          cur_udp = (old_udp * HZ) / win_elapsed;
          cur_icmp = (old_icmp * HZ) / win_elapsed;
          cur_ack = (old_ack * HZ) / win_elapsed;
          cur_rst = (old_rst * HZ) / win_elapsed;
          cur_fin = (old_fin * HZ) / win_elapsed;

          /* 读取旧的平滑值 */
          s_pps = atomic64_read(&entry->smoothed_pps);
          s_bps = atomic64_read(&entry->smoothed_bps);
          s_syn = atomic64_read(&entry->smoothed_syn);
          s_udp = atomic64_read(&entry->smoothed_udp);
          s_icmp = atomic64_read(&entry->smoothed_icmp);
          s_ack = atomic64_read(&entry->smoothed_ack);
          s_rst = atomic64_read(&entry->smoothed_rst);
          s_fin = atomic64_read(&entry->smoothed_fin);

          /* EWMA 更新：smoothed = (3 * current + 7 * smoothed) / 10 */
          atomic64_set(&entry->smoothed_pps, (3 * cur_pps + 7 * s_pps) / 10);
          atomic64_set(&entry->smoothed_bps, (3 * cur_bps + 7 * s_bps) / 10);
          atomic64_set(&entry->smoothed_syn, (3 * cur_syn + 7 * s_syn) / 10);
          atomic64_set(&entry->smoothed_udp, (3 * cur_udp + 7 * s_udp) / 10);
          atomic64_set(&entry->smoothed_icmp, (3 * cur_icmp + 7 * s_icmp) / 10);
          atomic64_set(&entry->smoothed_ack, (3 * cur_ack + 7 * s_ack) / 10);
          atomic64_set(&entry->smoothed_rst, (3 * cur_rst + 7 * s_rst) / 10);
          atomic64_set(&entry->smoothed_fin, (3 * cur_fin + 7 * s_fin) / 10);
        }

        /* 重置计数器 */
        atomic64_set(&entry->packet_count, 1);
        atomic64_set(&entry->byte_count, packet_len);
        atomic64_set(&entry->syn_count, 0);
        atomic64_set(&entry->udp_count, 0);
        atomic64_set(&entry->icmp_count, 0);
        atomic64_set(&entry->ack_count, 0);
        atomic64_set(&entry->rst_count, 0);
        atomic64_set(&entry->fin_count, 0);
        entry->window_start = now;

        /* 根据协议类型更新计数器 */
        if (protocol == IPPROTO_TCP) {
          if (tcp_flags & TCP_FLAGS_SYN)
            atomic64_set(&entry->syn_count, 1);
          if (tcp_flags & TCP_FLAGS_ACK)
            atomic64_set(&entry->ack_count, 1);
          if (tcp_flags & TCP_FLAGS_RST)
            atomic64_set(&entry->rst_count, 1);
          if (tcp_flags & TCP_FLAGS_FIN)
            atomic64_set(&entry->fin_count, 1);
        } else if (protocol == IPPROTO_UDP) {
          atomic64_set(&entry->udp_count, 1);
        } else if (protocol == IPPROTO_ICMP) {
          atomic64_set(&entry->icmp_count, 1);
        }
      } else {
        /* 其他 CPU 已经重置，只更新计数器 */
        atomic64_inc(&entry->packet_count);
        atomic64_add(packet_len, &entry->byte_count);

        /* 根据协议类型更新计数器 */
        if (protocol == IPPROTO_TCP) {
          if (tcp_flags & TCP_FLAGS_SYN)
            atomic64_inc(&entry->syn_count);
          if (tcp_flags & TCP_FLAGS_ACK)
            atomic64_inc(&entry->ack_count);
          if (tcp_flags & TCP_FLAGS_RST)
            atomic64_inc(&entry->rst_count);
          if (tcp_flags & TCP_FLAGS_FIN)
            atomic64_inc(&entry->fin_count);
        } else if (protocol == IPPROTO_UDP) {
          atomic64_inc(&entry->udp_count);
        } else if (protocol == IPPROTO_ICMP) {
          atomic64_inc(&entry->icmp_count);
        }
      }

      entry->last_activity = now;
      spin_unlock_bh(lock);
      return 0;
    }

    /* 窗口未过期，原子更新计数器（无锁） */
    atomic64_inc(&entry->packet_count);
    atomic64_add(packet_len, &entry->byte_count);

    /* 根据协议类型更新计数器 */
    if (protocol == IPPROTO_TCP) {
      if (tcp_flags & TCP_FLAGS_SYN)
        atomic64_inc(&entry->syn_count);
      if (tcp_flags & TCP_FLAGS_ACK)
        atomic64_inc(&entry->ack_count);
      if (tcp_flags & TCP_FLAGS_RST)
        atomic64_inc(&entry->rst_count);
      if (tcp_flags & TCP_FLAGS_FIN)
        atomic64_inc(&entry->fin_count);
    } else if (protocol == IPPROTO_UDP) {
      atomic64_inc(&entry->udp_count);
    } else if (protocol == IPPROTO_ICMP) {
      atomic64_inc(&entry->icmp_count);
    }

    entry->last_activity = now;

    rcu_read_unlock();
    return 0;
  }

  rcu_read_unlock();

  /* 慢速路径：创建新条目 */
  hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);
  lock = get_rate_lock(fw, af, hash);
  spin_lock_bh(lock);

  /* 双重检查：可能其他 CPU 已经创建 */
  rcu_read_lock();
  entry = find_rate_entry_rcu(fw, af, ip);
  rcu_read_unlock();

  if (entry) {
    /* 其他 CPU 已经创建，更新计数器 */
    atomic64_inc(&entry->packet_count);
    atomic64_add(packet_len, &entry->byte_count);

    /* 根据协议类型更新计数器 */
    if (protocol == IPPROTO_TCP) {
      if (tcp_flags & TCP_FLAGS_SYN)
        atomic64_inc(&entry->syn_count);
      if (tcp_flags & TCP_FLAGS_ACK)
        atomic64_inc(&entry->ack_count);
      if (tcp_flags & TCP_FLAGS_RST)
        atomic64_inc(&entry->rst_count);
      if (tcp_flags & TCP_FLAGS_FIN)
        atomic64_inc(&entry->fin_count);
    } else if (protocol == IPPROTO_UDP) {
      atomic64_inc(&entry->udp_count);
    } else if (protocol == IPPROTO_ICMP) {
      atomic64_inc(&entry->icmp_count);
    }

    entry->last_activity = now;
    spin_unlock_bh(lock);
    return 0;
  }

  /* 创建新条目 */
  entry = create_rate_entry(fw, af, ip);
  if (IS_ERR(entry)) {
    spin_unlock_bh(lock);
    return PTR_ERR(entry);
  }

  /* 初始化计数器 */
  atomic64_set(&entry->packet_count, 1);
  atomic64_set(&entry->byte_count, packet_len);
  atomic64_set(&entry->syn_count, 0);
  atomic64_set(&entry->udp_count, 0);
  atomic64_set(&entry->icmp_count, 0);
  atomic64_set(&entry->ack_count, 0);
  atomic64_set(&entry->rst_count, 0);
  atomic64_set(&entry->fin_count, 0);

  /* 根据协议类型设置初始值 */
  if (protocol == IPPROTO_TCP) {
    if (tcp_flags & TCP_FLAGS_SYN)
      atomic64_set(&entry->syn_count, 1);
    if (tcp_flags & TCP_FLAGS_ACK)
      atomic64_set(&entry->ack_count, 1);
    if (tcp_flags & TCP_FLAGS_RST)
      atomic64_set(&entry->rst_count, 1);
    if (tcp_flags & TCP_FLAGS_FIN)
      atomic64_set(&entry->fin_count, 1);
  } else if (protocol == IPPROTO_UDP) {
    atomic64_set(&entry->udp_count, 1);
  } else if (protocol == IPPROTO_ICMP) {
    atomic64_set(&entry->icmp_count, 1);
  }

  entry->window_start = now;
  entry->last_activity = now;

  spin_unlock_bh(lock);
  return 0;
}

/**
 * check_rate_violation - 检查 IP 是否超过速率阈值
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 *
 * 返回: true 超过阈值，false 未超过或未找到
 *
 * 注意：调用方必须持有 rcu_read_lock()
 *
 * 使用 EWMA 平滑速率进行检测，过滤突发流量误判。
 * 只有持续高速（多个窗口）才会触发封禁。
 *
 * 动态阈值（方案 C 混合模式）：
 * 当 dynamic_threshold_enabled 时，实际阈值 = max(静态阈值, 基线 × 倍数)。
 * 基线由守护进程通过 netlink 定期下发（EWMA α=0.01 跟踪全局流量趋势）。
 */
bool check_rate_violation(struct firewall_info *fw, u8 af, const void *ip) {
  struct ip_rate_entry *entry;
  u64 pps, bps;
  u64 pps_threshold, bps_threshold;

  if (!fw || !ip) {
    return false;
  }

  entry = find_rate_entry_rcu(fw, af, ip);
  if (!entry) {
    return false;
  }

  /* 读取 EWMA 平滑速率（原子操作） */
  pps = atomic64_read(&entry->smoothed_pps);
  bps = atomic64_read(&entry->smoothed_bps);

  /* 计算实际阈值：动态阈值 = max(静态阈值, 基线 × 倍数) */
  pps_threshold = fw->max_packets_per_second;
  bps_threshold = fw->max_bytes_per_second;

  if (READ_ONCE(fw->dynamic_threshold_enabled)) {
    u64 baseline_pps = atomic64_read(&fw->global_baseline_pps);
    u64 baseline_bps = atomic64_read(&fw->global_baseline_bps);
    u32 ratio = READ_ONCE(fw->dynamic_threshold_ratio_x100);

    if (ratio > 0) {
      u64 dynamic_pps, dynamic_bps;
      u64 ratio64 = (u64)ratio;

      /* 溢出防护：baseline × ratio 可能超过 U64_MAX */
      if (check_mul_overflow(baseline_pps, ratio64, &dynamic_pps))
        dynamic_pps = U64_MAX;
      else
        dynamic_pps /= 100;

      if (check_mul_overflow(baseline_bps, ratio64, &dynamic_bps))
        dynamic_bps = U64_MAX;
      else
        dynamic_bps /= 100;

      if (dynamic_pps > pps_threshold)
        pps_threshold = dynamic_pps;
      if (dynamic_bps > bps_threshold)
        bps_threshold = dynamic_bps;
    }
  }

  /* 检查是否超过阈值 */
  if (pps > pps_threshold) {
    return true;
  }

  if (bps > bps_threshold) {
    return true;
  }

  return false;
}

/**
 * check_protocol_violation - 检查 IP 是否超过协议专项速率阈值
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 * @protocol: 协议类型（IPPROTO_TCP/IPPROTO_UDP/IPPROTO_ICMP）
 *
 * 返回: true 超过阈值，false 未超过或未找到
 *
 * 用途：SYN Flood、UDP Flood、ICMP Flood 专项检测
 *
 * 注意：调用方必须持有 rcu_read_lock()
 *
 * 使用 EWMA 平滑速率进行检测，过滤突发流量误判。
 */
bool check_protocol_violation(struct firewall_info *fw, u8 af, const void *ip, u8 protocol) {
  struct ip_rate_entry *entry;
  u64 count;

  if (!fw || !ip) {
    return false;
  }

  entry = find_rate_entry_rcu(fw, af, ip);
  if (!entry) {
    return false;
  }

  /* 读取 EWMA 平滑速率（原子操作） */
  switch (protocol) {
  case IPPROTO_TCP:
    count = atomic64_read(&entry->smoothed_syn);
    break;
  case IPPROTO_UDP:
    count = atomic64_read(&entry->smoothed_udp);
    break;
  case IPPROTO_ICMP:
    count = atomic64_read(&entry->smoothed_icmp);
    break;
  default:
    return false;
  }

  /* 根据协议类型检查阈值 */
  switch (protocol) {
  case IPPROTO_TCP:
    if (count > fw->max_syn_per_second) {
      return true;
    }
    break;
  case IPPROTO_UDP:
    if (count > fw->max_udp_per_second) {
      return true;
    }
    break;
  case IPPROTO_ICMP:
    if (count > fw->max_icmp_per_second) {
      return true;
    }
    break;
  default:
    break;
  }

  return false;
}

/**
 * check_tcp_flood_violation - 检查 TCP 子类型 Flood 违规
 * @fw: 防火墙信息
 * @af: 地址族
 * @ip: IP 地址
 * @tcp_flags: TCP 标志位
 *
 * 返回: 违规类型字符串（"ACK flood"/"RST flood"/"FIN flood"），无违规返回 NULL
 *
 * 用途：ACK/RST/FIN Flood 专项检测
 *
 * 注意：调用方必须持有 rcu_read_lock()
 */
const char *check_tcp_flood_violation(struct firewall_info *fw, u8 af,
                                      const void *ip, u8 tcp_flags) {
  struct ip_rate_entry *entry;
  u64 count;

  if (!fw || !ip) {
    return NULL;
  }

  entry = find_rate_entry_rcu(fw, af, ip);
  if (!entry) {
    return NULL;
  }

  /* 检查 ACK flood */
  if (tcp_flags & TCP_FLAGS_ACK) {
    count = atomic64_read(&entry->smoothed_ack);
    if (count > fw->max_ack_per_second) {
      return "ACK flood";
    }
  }

  /* 检查 RST flood */
  if (tcp_flags & TCP_FLAGS_RST) {
    count = atomic64_read(&entry->smoothed_rst);
    if (count > fw->max_rst_per_second) {
      return "RST flood";
    }
  }

  /* 检查 FIN flood */
  if (tcp_flags & TCP_FLAGS_FIN) {
    count = atomic64_read(&entry->smoothed_fin);
    if (count > fw->max_fin_per_second) {
      return "FIN flood";
    }
  }

  return NULL;
}

/**
 * update_global_baseline - 更新全局流量基线（动态阈值）
 * @fw: 防火墙信息
 * @total_pps: 当前总 PPS
 * @total_bps: 当前总 BPS
 *
 * 使用 EWMA（α=0.01）跟踪长期流量趋势。
 * 每 2 秒由守护进程调用一次。
 */
void update_global_baseline(struct firewall_info *fw, u64 total_pps, u64 total_bps) {
  u64 old_pps, old_bps;

  if (!fw) {
    return;
  }

  old_pps = atomic64_read(&fw->global_baseline_pps);
  old_bps = atomic64_read(&fw->global_baseline_bps);

  /* EWMA 更新：baseline = (1 * current + 99 * baseline) / 100（α=0.01） */
  atomic64_set(&fw->global_baseline_pps, (total_pps + 99 * old_pps) / 100);
  atomic64_set(&fw->global_baseline_bps, (total_bps + 99 * old_bps) / 100);
}

/**
 * cleanup_rate_entries - 清理过期的速率条目
 * @fw: 防火墙信息
 *
 * 定期调用（由 cleanup_timer 触发），清理超过 RATE_ENTRY_EXPIRE_SECONDS
 * 未活动的条目，避免内存泄漏
 *
 * 实现：遍历所有桶，删除过期条目
 */
void cleanup_rate_entries(struct firewall_info *fw) {
  struct ip_rate_entry *entry;
  struct hlist_node *tmp;
  unsigned long now = jiffies;
  unsigned long expire_time = msecs_to_jiffies(RATE_ENTRY_EXPIRE_SECONDS * 1000);
  int i;
  int cleaned = 0;

  if (!fw) {
    return;
  }

  /* 清理 IPv4 表 */
  for (i = 0; i < (1 << RATE_HASH_BITS); i++) {
    spinlock_t *lock = &fw->rate_locks_ipv4[i];
    struct hlist_head *head = &fw->rate_table_ipv4[i];

    spin_lock_bh(lock);
    hlist_for_each_entry_safe(entry, tmp, head, hash) {
      if (time_after(now, entry->last_activity + expire_time)) {
        hlist_del_rcu(&entry->hash);
        call_rcu(&entry->rcu_head, free_rate_entry_rcu);
        atomic_dec(&fw->rate_count);
        cleaned++;
      }
    }
    spin_unlock_bh(lock);
  }

  /* 清理 IPv6 表 */
  for (i = 0; i < (1 << RATE_HASH_BITS); i++) {
    spinlock_t *lock = &fw->rate_locks_ipv6[i];
    struct hlist_head *head = &fw->rate_table_ipv6[i];

    spin_lock_bh(lock);
    hlist_for_each_entry_safe(entry, tmp, head, hash) {
      if (time_after(now, entry->last_activity + expire_time)) {
        hlist_del_rcu(&entry->hash);
        call_rcu(&entry->rcu_head, free_rate_entry_rcu);
        atomic_dec(&fw->rate_count);
        cleaned++;
      }
    }
    spin_unlock_bh(lock);
  }

  if (cleaned > 0) {
    pr_debug("firewall: cleaned up %d rate entries\n", cleaned);
  }
}

/**
 * clear_all_rate_entries - 清除所有速率统计条目
 * @fw: 防火墙信息结构
 *
 * 在速率窗口配置更新时调用，确保所有条目使用新窗口。
 */
void clear_all_rate_entries(struct firewall_info *fw) {
  struct ip_rate_entry *entry;
  struct hlist_node *tmp;
  int i;
  int cleared = 0;

  if (!fw) {
    return;
  }

  /* 清除 IPv4 表 */
  for (i = 0; i < (1 << RATE_HASH_BITS); i++) {
    spinlock_t *lock = &fw->rate_locks_ipv4[i];
    struct hlist_head *head = &fw->rate_table_ipv4[i];

    spin_lock_bh(lock);
    hlist_for_each_entry_safe(entry, tmp, head, hash) {
      hlist_del_rcu(&entry->hash);
      call_rcu(&entry->rcu_head, free_rate_entry_rcu);
      atomic_dec(&fw->rate_count);
      cleared++;
    }
    spin_unlock_bh(lock);
  }

  /* 清除 IPv6 表 */
  for (i = 0; i < (1 << RATE_HASH_BITS); i++) {
    spinlock_t *lock = &fw->rate_locks_ipv6[i];
    struct hlist_head *head = &fw->rate_table_ipv6[i];

    spin_lock_bh(lock);
    hlist_for_each_entry_safe(entry, tmp, head, hash) {
      hlist_del_rcu(&entry->hash);
      call_rcu(&entry->rcu_head, free_rate_entry_rcu);
      atomic_dec(&fw->rate_count);
      cleared++;
    }
    spin_unlock_bh(lock);
  }

  if (cleared > 0) {
    pr_info("firewall: cleared %d rate entries (config update)\n", cleared);
  }
}
