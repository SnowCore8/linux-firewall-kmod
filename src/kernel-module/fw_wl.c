// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_wl.c - 白名单（64 精确桶 + 子网链表）
 *
 * 与旧实现的差别（见 docs/zh/development/kernel-rewrite-design.md「白名单」）：
 *
 *   - **容量上限**：新增模块参数 fw_max_whitelist_entries（默认 65535），插入前在
 *     wl_lock 内原子检查，修复 PROC_WHITELIST_CAPACITY_UNENFORCED。
 *   - **IPv6 比较去冗余**：旧实现在「桶内候选」与「子网链候选」两处都做
 *     4 × READ_ONCE(u32) 拼装再比较。条目在发布后不再修改，RCU 读者只会看到
 *     完整旧值或完整新值，整体比较即可（fw_addr_equal）。
 *   - **remove 改精确匹配**：旧实现用子网比较判定「本机接口 IP」，接口配 /24 时
 *     整个网段的显式条目都删不掉（PROC_WHITELIST_REMOVE_SUBNET_OVERREACH）。
 *     新实现只比较「接口精确主机地址」，且用 fw_local_lookup()（O(1) 哈希）。
 *
 * 数据结构：精确条目（prefix_len == 全长）只入精确桶；子网条目同时入桶与子网链。
 * 命中判定 = 精确桶匹配地址，或子网链上存在覆盖该地址的前缀条目。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/slab.h>

#include "fw_wl.h"
#include "fw_ban.h"
#include "fw_local.h"
#include "fw_stats.h"

/* 入口参数归一：prefix_len 是否等于该地址族全长（即精确主机条目） */
static inline bool fw_wl_is_full_prefix(u8 af, u8 prefix_len) {
  return af == FW_AF_INET6 ? prefix_len == 128 : prefix_len == 32;
}

static inline u8 fw_wl_max_prefix(u8 af) {
  return af == FW_AF_INET6 ? 128 : 32;
}

/* 桶索引：与封禁表同源（jhash + 随机种子），避免结构碰撞攻击 */
static inline u32 fw_wl_bucket(u8 af, const void *addr) {
  return fw_hash_addr(af, addr, WHITELIST_HASH_BITS);
}

static inline struct hlist_head *fw_wl_bucket_head(u8 af, const void *addr) {
  u32 bkt = fw_wl_bucket(af, addr);

  return af == FW_AF_INET6 ? &fw_info.wl_ipv6[bkt] : &fw_info.wl_ipv4[bkt];
}

static inline struct list_head *fw_wl_subnet_list(u8 af) {
  return af == FW_AF_INET6 ? &fw_info.wl_subnet_ipv6 : &fw_info.wl_subnet_ipv4;
}

/* 桶内查找同一 (af, addr, prefix_len) —— 用于去重与 remove */
static struct fw_wl_entry *fw_wl_find_locked(u8 af, const void *addr, u8 prefix_len) {
  struct fw_wl_entry *e;

  hlist_for_each_entry(e, fw_wl_bucket_head(af, addr), hash) {
    if (e->af == af && e->prefix_len == prefix_len && fw_addr_equal(af, &e->addr, addr))
      return e;
  }
  return NULL;
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

int fw_wl_init(void) {
  hash_init(fw_info.wl_ipv4);
  hash_init(fw_info.wl_ipv6);
  INIT_LIST_HEAD(&fw_info.wl_subnet_ipv4);
  INIT_LIST_HEAD(&fw_info.wl_subnet_ipv6);
  spin_lock_init(&fw_info.wl_lock);
  atomic_set(&fw_info.wl_count, 0);
  atomic_set(&fw_info.wl_reject_count, 0);
  return 0;
}

static void fw_wl_free_rcu(struct rcu_head *head) {
  kfree(container_of(head, struct fw_wl_entry, rcu));
}

void fw_wl_exit(void) {
  struct fw_wl_entry *e;
  struct hlist_node *tmp;
  u32 bkt;

  spin_lock_bh(&fw_info.wl_lock);

  hash_for_each_safe(fw_info.wl_ipv4, bkt, tmp, e, hash) {
    hash_del_rcu(&e->hash);
    if (!fw_wl_is_full_prefix(e->af, e->prefix_len))
      list_del_rcu(&e->subnet_node);
    call_rcu(&e->rcu, fw_wl_free_rcu);
  }
  hash_for_each_safe(fw_info.wl_ipv6, bkt, tmp, e, hash) {
    hash_del_rcu(&e->hash);
    if (!fw_wl_is_full_prefix(e->af, e->prefix_len))
      list_del_rcu(&e->subnet_node);
    call_rcu(&e->rcu, fw_wl_free_rcu);
  }

  atomic_set(&fw_info.wl_count, 0);
  spin_unlock_bh(&fw_info.wl_lock);

  synchronize_rcu();
  rcu_barrier();
}

/* ============================================================================
 * 热路径（RCU 只读）
 * ==========================================================================*/

bool fw_wl_lookup(u8 af, const void *ip) {
  struct fw_wl_entry *e;

  /* 1) 精确桶：地址与前缀全长的条目 */
  hlist_for_each_entry_rcu(e, fw_wl_bucket_head(af, ip), hash) {
    if (e->af != af || !fw_wl_is_full_prefix(af, e->prefix_len))
      continue;
    if (fw_addr_equal(af, &e->addr, ip))
      return true;
  }

  /* 2) 子网链：存在覆盖该地址的前缀条目 */
  list_for_each_entry_rcu(e, fw_wl_subnet_list(af), subnet_node) {
    if (fw_prefix_match(af, ip, &e->addr, e->prefix_len))
      return true;
  }

  return false;
}

bool fw_wl_has_exact(u8 af, const void *ip) {
  struct fw_wl_entry *e;

  hlist_for_each_entry_rcu(e, fw_wl_bucket_head(af, ip), hash) {
    if (e->af == af && fw_wl_is_full_prefix(af, e->prefix_len) &&
        fw_addr_equal(af, &e->addr, ip))
      return true;
  }
  return false;
}

u32 fw_wl_count(void) {
  return (u32)atomic_read(&fw_info.wl_count);
}

/* ============================================================================
 * 添加 / 移除（冷路径）
 * ==========================================================================*/

int fw_wl_add(u8 af, const void *ip, u8 prefix_len, const char *device_name) {
  struct fw_wl_entry *e;
  bool subnet;

  if (!ip || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;
  if (prefix_len > fw_wl_max_prefix(af))
    return -EINVAL;

  subnet = !fw_wl_is_full_prefix(af, prefix_len);

  spin_lock_bh(&fw_info.wl_lock);

  /* 去重：同一 (af, 归一化地址, prefix_len) 只保留一条 */
  e = fw_wl_find_locked(af, ip, prefix_len);
  if (e) {
    if (device_name && device_name[0] && !e->device_name[0]) {
      strscpy(e->device_name, device_name, sizeof(e->device_name));
    }
    spin_unlock_bh(&fw_info.wl_lock);
    return 0;
  }

  if (atomic_read(&fw_info.wl_count) >= (int)fw_info.max_wl_entries) {
    atomic_inc(&fw_info.wl_reject_count);
    spin_unlock_bh(&fw_info.wl_lock);
    return -ENOSPC;
  }

  e = kzalloc(sizeof(*e), GFP_ATOMIC);
  if (!e) {
    fw_stat_bump_alloc_fail();
    spin_unlock_bh(&fw_info.wl_lock);
    return -ENOMEM;
  }

  e->af = af;
  e->prefix_len = prefix_len;
  if (af == FW_AF_INET6)
    memcpy(&e->addr, ip, sizeof(struct in6_addr));
  else
    e->addr.ipv4 = *(__be32 *)ip;
  if (device_name)
    strscpy(e->device_name, device_name, sizeof(e->device_name));

  hlist_add_head_rcu(&e->hash, fw_wl_bucket_head(af, &e->addr));
  if (subnet)
    list_add_tail_rcu(&e->subnet_node, fw_wl_subnet_list(af));
  atomic_inc(&fw_info.wl_count);

  spin_unlock_bh(&fw_info.wl_lock);

  return 0;
}

int fw_wl_remove(u8 af, const void *ip, u8 prefix_len) {
  struct fw_wl_entry *e;

  if (!ip || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;

  /*
	 * 本机接口地址不允许从白名单直接移除：它由 fw_netdev.c 依据接口状态维护。
	 * 精确匹配（fw_local_lookup 是 /32 与 /128 的哈希集合），不再用子网比较。
	 */
  if (fw_local_lookup(af, ip))
    return -EPERM;

  spin_lock_bh(&fw_info.wl_lock);

  e = fw_wl_find_locked(af, ip, prefix_len);
  if (!e) {
    spin_unlock_bh(&fw_info.wl_lock);
    return -ENOENT;
  }

  hash_del_rcu(&e->hash);
  if (!fw_wl_is_full_prefix(af, prefix_len))
    list_del_rcu(&e->subnet_node);
  atomic_dec(&fw_info.wl_count);
  call_rcu(&e->rcu, fw_wl_free_rcu);

  spin_unlock_bh(&fw_info.wl_lock);

  /* 白名单变更后，落在其覆盖范围内的封禁一并解除 */
  fw_ban_del_matching(af, ip, prefix_len);

  return 0;
}

/* 供 netdev 变更路径按 (af, 地址, 前缀) 静默移除（不触发封禁联动） */
int fw_wl_remove_quiet(u8 af, const void *ip, u8 prefix_len) {
  struct fw_wl_entry *e;

  if (!ip || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;

  spin_lock_bh(&fw_info.wl_lock);
  e = fw_wl_find_locked(af, ip, prefix_len);
  if (!e) {
    spin_unlock_bh(&fw_info.wl_lock);
    return -ENOENT;
  }
  hash_del_rcu(&e->hash);
  if (!fw_wl_is_full_prefix(af, prefix_len))
    list_del_rcu(&e->subnet_node);
  atomic_dec(&fw_info.wl_count);
  call_rcu(&e->rcu, fw_wl_free_rcu);
  spin_unlock_bh(&fw_info.wl_lock);

  return 0;
}

/* ============================================================================
 * 读侧遍历（netlink LIST_WHITELIST_RESPONSE 与 procfs whitelist 共用）
 * ==========================================================================*/

u32 fw_wl_fill_entries(u32 offset, u32 limit, struct fw_wl_row *rows) {
  struct fw_wl_entry *e;
  u32 idx = 0, count = 0, bkt;

  if (!rows || !limit)
    return 0;

  rcu_read_lock();

  for (bkt = 0; bkt < WHITELIST_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(e, &fw_info.wl_ipv4[bkt], hash) {
      if (idx++ < offset)
        continue;
      rows[count].af = e->af;
      rows[count].prefix_len = e->prefix_len;
      rows[count].addr = e->addr;
      memcpy(rows[count].device_name, e->device_name, sizeof(rows[count].device_name));
      if (++count >= limit)
        break;
    }
  }
  for (bkt = 0; bkt < WHITELIST_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(e, &fw_info.wl_ipv6[bkt], hash) {
      if (idx++ < offset)
        continue;
      rows[count].af = e->af;
      rows[count].prefix_len = e->prefix_len;
      rows[count].addr = e->addr;
      memcpy(rows[count].device_name, e->device_name, sizeof(rows[count].device_name));
      if (++count >= limit)
        break;
    }
  }

  rcu_read_unlock();
  return count;
}
