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
static struct ip_rate_entry *find_rate_entry_rcu(struct firewall_info *fw, u8 af,
                                                  const void *ip) {
  struct hlist_head *table = get_rate_table(fw, af);
  u32 hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);
  struct ip_rate_entry *entry;

  hlist_for_each_entry_rcu(entry, &table[hash], hash) {
    if (entry->af == af && compare_ips(af, &entry->addr, ip)) {
      return entry;
    }
  }

  return NULL;
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
 */
static struct ip_rate_entry *create_rate_entry(struct firewall_info *fw, u8 af,
                                                const void *ip) {
  struct ip_rate_entry *entry;
  struct hlist_head *table = get_rate_table(fw, af);
  u32 hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);

  /* 检查是否超过最大条目数 */
  if (atomic_read(&fw->rate_count) >= MAX_RATE_ENTRIES) {
    atomic_inc(&fw->ban_table_full_count);
    return ERR_PTR(-ENOSPC);
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

  atomic64_set(&entry->packet_count, 0);
  atomic64_set(&entry->byte_count, 0);
  atomic64_set(&entry->syn_count, 0);
  atomic64_set(&entry->udp_count, 0);
  atomic64_set(&entry->icmp_count, 0);
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
int update_rate_stats(struct firewall_info *fw, u8 af, const void *ip, u32 packet_len,
                      u8 protocol) {
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
    if (time_after(elapsed, fw->rate_window_jiffies)) {
      /* 窗口过期，重置计数器（需要获取锁） */
      rcu_read_unlock();

      hash = hash_ip_for_rate(af, ip, RATE_HASH_BITS);
      lock = get_rate_lock(fw, af, hash);
      spin_lock_bh(lock);

      /* 双重检查：可能其他 CPU 已经重置 */
      if (time_after(now - entry->window_start, fw->rate_window_jiffies)) {
        atomic64_set(&entry->packet_count, 1);
        atomic64_set(&entry->byte_count, packet_len);
        atomic64_set(&entry->syn_count, 0);
        atomic64_set(&entry->udp_count, 0);
        atomic64_set(&entry->icmp_count, 0);
        entry->window_start = now;

        /* 根据协议类型更新计数器 */
        if (protocol == IPPROTO_TCP) {
          atomic64_set(&entry->syn_count, 1);
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
          atomic64_inc(&entry->syn_count);
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
      atomic64_inc(&entry->syn_count);
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
      atomic64_inc(&entry->syn_count);
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

  /* 根据协议类型设置初始值 */
  if (protocol == IPPROTO_TCP) {
    atomic64_set(&entry->syn_count, 1);
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
 */
bool check_rate_violation(struct firewall_info *fw, u8 af, const void *ip) {
  struct ip_rate_entry *entry;
  u64 packets, bytes;

  if (!fw || !ip) {
    return false;
  }

  entry = find_rate_entry_rcu(fw, af, ip);
  if (!entry) {
    return false;
  }

  /* 读取计数器（原子操作） */
  packets = atomic64_read(&entry->packet_count);
  bytes = atomic64_read(&entry->byte_count);

  /* 检查是否超过阈值 */
  if (packets > fw->max_packets_per_second) {
    return true;
  }

  if (bytes > fw->max_bytes_per_second) {
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

  /* 根据协议类型检查对应的计数器 */
  switch (protocol) {
    case IPPROTO_TCP:
      count = atomic64_read(&entry->syn_count);
      if (count > fw->max_syn_per_second) {
        return true;
      }
      break;

    case IPPROTO_UDP:
      count = atomic64_read(&entry->udp_count);
      if (count > fw->max_udp_per_second) {
        return true;
      }
      break;

    case IPPROTO_ICMP:
      count = atomic64_read(&entry->icmp_count);
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
      if (time_after(now - entry->last_activity, expire_time)) {
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
      if (time_after(now - entry->last_activity, expire_time)) {
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
