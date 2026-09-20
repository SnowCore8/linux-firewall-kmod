// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_local.c - 本机接口精确地址集合（开放寻址线性探测哈希集）
 *
 * 与旧实现的差别（见 docs/zh/development/kernel-rewrite-design.md「本机地址集合」）：
 *
 *   - 旧实现是「数组 + 每包 O(N) 线性扫描 + 掩码比较」，且 count == 0 时直接
 *     返回「非本机」——一个空表窗口即失败开放。新实现是 O(1) 哈希集。
 *   - 空表窗口在结构上消除：集合由 fw_netdev.c 在钩子注册**之前**发布，
 *     运行期必然存在一张已发布的表。lookup 仍保留 NULL 判断，但那只是防御。
 *   - 只存精确主机地址（IPv4 /32、IPv6 /128），**不扩成子网豁免**：旧实现在
 *     白名单 remove 路径上用子网比较判定「本机接口 IP」，导致接口配 /24 时
 *     整个网段的显式白名单条目都删不掉（PROC_WHITELIST_REMOVE_SUBNET_OVERREACH）。
 *
 * 并发模型：整张表由 fw_netdev.c 重新构建后整体 rcu_assign_pointer 发布，
 * 旧表 kfree_rcu 释放；发布后表内容不再修改，读者只需 RCU。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/slab.h>

#include "fw_local.h"
#include "fw_stats.h"

/* 表容量上限：哈希取低 16 位，故容量不得超过 2^16 */
#define FW_LOCAL_HASH_BITS 16
#define FW_LOCAL_CAP_MAX (1u << FW_LOCAL_HASH_BITS)
#define FW_LOCAL_CAP_MIN 16

/*
 * 按模块参数 fw_max_local_ips 取 2 的幂容量。
 * 取不到合法值（0 或过大）时退到最小/最大，绝不返回 0——0 会让掩码运算失效。
 */
static u32 fw_local_capacity(void) {
  u32 want = fw_info.max_local_ips;
  u32 cap = FW_LOCAL_CAP_MIN;

  if (want)
    while (cap < want && cap < FW_LOCAL_CAP_MAX)
      cap <<= 1;

  return cap;
}

static inline u32 fw_local_slot_index(const struct fw_local_set *set, u8 af,
                                      const void *addr) {
  return fw_hash_addr(af, addr, FW_LOCAL_HASH_BITS) & (set->capacity - 1);
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

void fw_local_init(void) {
  RCU_INIT_POINTER(fw_info.local_set, NULL);
}

void fw_local_exit(void) {
  struct fw_local_set *set = rcu_dereference_protected(fw_info.local_set, 1);

  RCU_INIT_POINTER(fw_info.local_set, NULL);
  fw_local_free_rcu(set);
}

/* ============================================================================
 * 热路径
 * ==========================================================================*/

bool fw_local_lookup(u8 af, const void *ip) {
  struct fw_local_set *set = rcu_dereference(fw_info.local_set);
  u32 mask, start, i;

  if (unlikely(!set || !set->capacity))
    return false;

  mask = set->capacity - 1;
  start = fw_local_slot_index(set, af, ip);

  for (i = 0; i < set->capacity; i++) {
    const struct fw_local_slot *s = &set->slots[(start + i) & mask];

    if (!READ_ONCE(s->used))
      return false; /* 探测到空槽 ⇒ 之后不存在 */
    if (s->af == af && fw_addr_equal(af, &s->addr, ip))
      return true;
  }
  return false;
}

/* ============================================================================
 * 集合构建（fw_netdev.c 调用，非热路径）
 * ==========================================================================*/

struct fw_local_set *fw_local_set_alloc(u32 capacity) {
  struct fw_local_set *set;

  /* capacity == 0 表示按模块参数 fw_max_local_ips 取默认容量 */
  if (!capacity)
    capacity = fw_local_capacity();

  if (capacity & (capacity - 1))
    return NULL; /* 必须是 2 的幂 */
  if (capacity > FW_LOCAL_CAP_MAX)
    capacity = FW_LOCAL_CAP_MAX;

  set = kzalloc(struct_size(set, slots, capacity), GFP_KERNEL);
  if (!set) {
    fw_stat_bump_alloc_fail();
    return NULL;
  }
  set->capacity = capacity;
  set->count = 0;
  return set;
}

/* 插入一个精确主机地址；重复返回 false（未插入，不算错误） */
bool fw_local_set_insert(struct fw_local_set *set, u8 af, const void *addr) {
  u32 mask, start, i;

  if (!set || !set->capacity || !addr)
    return false;

  mask = set->capacity - 1;
  start = fw_local_slot_index(set, af, addr);

  for (i = 0; i < set->capacity; i++) {
    struct fw_local_slot *s = &set->slots[(start + i) & mask];

    if (s->used) {
      if (s->af == af && fw_addr_equal(af, &s->addr, addr))
        return false; /* 已在集合中 */
      continue;
    }
    s->af = af;
    if (af == FW_AF_INET6)
      memcpy(&s->addr, addr, sizeof(struct in6_addr));
    else
      s->addr.ipv4 = *(__be32 *)addr;
    s->used = 1;
    set->count++;
    return true;
  }
  return false; /* 表满 */
}

void fw_local_publish(struct fw_local_set *set) {
  struct fw_local_set *old = rcu_dereference_protected(fw_info.local_set, 1);

  rcu_assign_pointer(fw_info.local_set, set);
  if (old)
    fw_local_free_rcu(old);
}

void fw_local_free_rcu(struct fw_local_set *set) {
  if (set)
    kfree_rcu(set, rcu);
}

u32 fw_local_count(void) {
  struct fw_local_set *set = rcu_dereference_protected(fw_info.local_set, 1);

  return set ? set->count : 0;
}
