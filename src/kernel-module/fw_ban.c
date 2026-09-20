// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_ban.c - 封禁表（4096 桶 hlist + RCU + per-bucket 锁，per-entry 定时器）
 *
 * 与旧实现的差别（见 docs/zh/development/kernel-rewrite-design.md）：
 *
 *   - **容量上限**：新增 fw_max_ban_entries（默认 65535），在桶锁内原子检查；
 *     到限拒绝并递增 ban_table_full_rejects —— 这给了该计数器唯一递增点，
 *     修复 PROC_BAN_TABLE_FULL_NEVER_INC（旧实现该计数恒为 0）。
 *   - **删除 retry_count**：旧实现只有置零、无读取点。
 *   - **泛洪闸门统一**：fw_ban_flood_allow() 由三条封禁路径（procfs / netlink /
 *     DDoS 自决）统一调用；旧实现只有 procfs 一条路径检查 fw_max_bans_per_second
 *     （设计文档「本次新查出的稳定性问题 1」）。
 *
 * 锁顺序：本文件只取 ban_locks[bkt]（spin_lock_bh），不嵌套任何其它锁。
 *
 * 定时器与释放的安全性（关键）：
 *   到期回调整体包在 rcu_read_lock() 里。删除路径（手动解封 / 白名单联动 /
 *   退出清理）用 timer_delete()（非等待）+ hlist_del_rcu() + call_rcu() 释放。
 *   由于 call_rcu 的释放回调必须等一个宽限期结束，而正在执行的到期回调持有
 *   RCU 读侧临界区，宽限期不会在它结束前完成 —— 因此回调不可能访问到已释放
 *   的节点。这样既不需要在持桶锁时调用 timer_delete_sync()（会自锁死），
 *   也不存在使用后释放。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/ktime.h>
#include <linux/slab.h>

#include "fw_ban.h"
#include "fw_wl.h"
#include "fw_stats.h"
#include "fw_netlink.h"

/*
 * banned_at 的内部单位是 jiffies（单调，便于算已封禁时长）；对外一律是
 * Unix 秒（契约 netlink.fwidl:207 与 fw_types.h 的 struct fw_ban_row 都这么定）。
 * 两者之间的换算只在读侧序列化时做，避免热路径调用 ktime_get_real_seconds()。
 */
static u64 fw_ban_start_unix(const struct fw_ban_node *n) {
  u64 now = ktime_get_real_seconds();
  unsigned long elapsed = jiffies - n->banned_at;

  return now - (u64)(elapsed / HZ);
}

static inline u32 fw_ban_bucket(u8 af, const void *addr) {
  return fw_hash_addr(af, addr, BAN_HASH_BITS);
}

static inline struct hlist_head *fw_ban_bucket_head(u8 af, u32 bkt) {
  return af == FW_AF_INET6 ? &fw_info.ban_ipv6[bkt] : &fw_info.ban_ipv4[bkt];
}

/* 桶内按 (af, addr) 查条目；调用者已持桶锁 */
static struct fw_ban_node *fw_ban_find_locked(u8 af, const void *addr, u32 bkt) {
  struct fw_ban_node *n;

  hlist_for_each_entry(n, fw_ban_bucket_head(af, bkt), hash) {
    if (n->af == af && fw_addr_equal(af, &n->addr, addr))
      return n;
  }
  return NULL;
}

static inline bool fw_ban_node_expired(const struct fw_ban_node *n) {
  return !n->is_permanent && time_after_eq(jiffies, n->unban_jiffies);
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

int fw_ban_init(void) {
  u32 i;

  hash_init(fw_info.ban_ipv4);
  hash_init(fw_info.ban_ipv6);
  for (i = 0; i < BAN_HASH_SIZE; i++)
    spin_lock_init(&fw_info.ban_locks[i]);
  atomic_set(&fw_info.ban_count, 0);

  spin_lock_init(&fw_info.flood_lock);
  fw_info.flood_window_start = 0;
  fw_info.recent_additions = 0;

  return 0;
}

static void fw_ban_free_rcu(struct rcu_head *head) {
  kfree(container_of(head, struct fw_ban_node, rcu));
}

static void fw_ban_expire_cb(struct timer_list *t);

static struct fw_ban_node *fw_ban_alloc(u8 af, const void *addr,
                                        u32 duration_secs, const char *reason,
                                        const char *jail, u64 start_unix) {
  struct fw_ban_node *n = kzalloc(sizeof(*n), GFP_ATOMIC);

  if (!n) {
    fw_stat_bump_alloc_fail();
    return NULL;
  }
  n->af = af;
  n->duration_secs = duration_secs;
  n->is_permanent = duration_secs == 0;
  if (start_unix) {
    /* 状态恢复：外部时点换算回 jiffies 偏移，保住原始封禁起点 */
    u64 now = ktime_get_real_seconds();
    unsigned long elapsed = start_unix >= now ? 0 : (unsigned long)((now - start_unix) * HZ);

    n->banned_at = jiffies - elapsed;
  } else {
    n->banned_at = jiffies;
  }
  if (duration_secs)
    n->unban_jiffies = jiffies + (unsigned long)duration_secs * HZ;
  if (af == FW_AF_INET6)
    memcpy(&n->addr, addr, sizeof(struct in6_addr));
  else
    n->addr.ipv4 = *(__be32 *)addr;
  strscpy(n->reason, reason ? reason : "", sizeof(n->reason));
  strscpy(n->jail_name, jail ? jail : "", sizeof(n->jail_name));
  INIT_HLIST_NODE(&n->hash);
  timer_setup(&n->expire_timer, fw_ban_expire_cb, 0);

  return n;
}

/*
 * 到期回调：持桶锁摘链 + call_rcu 释放 + 推送 BAN_STATE_CHANGE。
 * 整体持 RCU 读侧临界区，保证与删除路径的 call_rcu 释放互斥（见文件头说明）。
 */
static void fw_ban_expire_cb(struct timer_list *t) {
  struct fw_ban_node *n = timer_container_of(n, t, expire_timer);
  union fw_addr addr;
  u32 bkt;
  u8 af;

  rcu_read_lock();

  af = READ_ONCE(n->af);
  bkt = fw_ban_bucket(af, &n->addr);
  if (af == FW_AF_INET6)
    memcpy(&addr, &n->addr, sizeof(struct in6_addr));
  else
    addr.ipv4 = n->addr.ipv4;

  spin_lock_bh(&fw_info.ban_locks[bkt]);

  if (hlist_unhashed(&n->hash)) {
    /* 已被手动解封 / 白名单联动 / 退出清理摘链，本回调无需再动 */
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    rcu_read_unlock();
    return;
  }
  /* 续期竞态：到期前被延长，则重武装本次定时器 */
  if (!READ_ONCE(n->is_permanent) && time_before(jiffies, READ_ONCE(n->unban_jiffies))) {
    mod_timer(&n->expire_timer, n->unban_jiffies);
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    rcu_read_unlock();
    return;
  }

  hlist_del_rcu(&n->hash);
  atomic_dec(&fw_info.ban_count);
  spin_unlock_bh(&fw_info.ban_locks[bkt]);

  rcu_read_unlock();

  fw_stat_add_expired(1);
  call_rcu(&n->rcu, fw_ban_free_rcu);
  fw_nl_send_ban_state_change(FW_BAN_ACTION_UNBAN, af, &addr, 0, "expired", NULL);
}

void fw_ban_exit(void) {
  struct fw_ban_node *n;
  struct hlist_node *tmp;
  u32 bkt;

  for (bkt = 0; bkt < BAN_HASH_SIZE; bkt++) {
    spin_lock_bh(&fw_info.ban_locks[bkt]);

    hlist_for_each_entry_safe(n, tmp, &fw_info.ban_ipv4[bkt], hash) {
      timer_delete(&n->expire_timer);
      hlist_del_rcu(&n->hash);
      call_rcu(&n->rcu, fw_ban_free_rcu);
    }
    hlist_for_each_entry_safe(n, tmp, &fw_info.ban_ipv6[bkt], hash) {
      timer_delete(&n->expire_timer);
      hlist_del_rcu(&n->hash);
      call_rcu(&n->rcu, fw_ban_free_rcu);
    }
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
  }
  atomic_set(&fw_info.ban_count, 0);

  synchronize_rcu();
  rcu_barrier();
}

/* ============================================================================
 * 热路径（RCU 只读）
 * ==========================================================================*/

bool fw_ban_lookup(u8 af, const void *ip) {
  struct fw_ban_node *n;
  u32 bkt = fw_ban_bucket(af, ip);

  hlist_for_each_entry_rcu(n, fw_ban_bucket_head(af, bkt), hash) {
    if (n->af == af && fw_addr_equal(af, &n->addr, ip))
      return true;
  }
  return false;
}

u32 fw_ban_count(void) {
  return (u32)atomic_read(&fw_info.ban_count);
}

/* ============================================================================
 * 泛洪闸门（procfs / netlink / DDoS 三路统一）
 * ==========================================================================*/

bool fw_ban_flood_allow(void) {
  unsigned long now = jiffies;
  unsigned int max = READ_ONCE(fw_info.max_bans_per_second);
  bool allow = true;

  spin_lock_bh(&fw_info.flood_lock);
  if (now - fw_info.flood_window_start >= HZ) {
    fw_info.flood_window_start = now;
    fw_info.recent_additions = 1;
  } else {
    fw_info.recent_additions++;
    if (fw_info.recent_additions > max)
      allow = false;
  }
  spin_unlock_bh(&fw_info.flood_lock);
  return allow;
}

static unsigned int fw_ban_recent_additions(void) {
  unsigned int v;

  spin_lock_bh(&fw_info.flood_lock);
  v = fw_info.recent_additions;
  spin_unlock_bh(&fw_info.flood_lock);
  return v;
}

/* 供 procfs 的 stats 暴露 recent_additions（契约 stats 的最后一个键） */
unsigned int fw_ban_recent_additions_stat(void) {
  return fw_ban_recent_additions();
}

/* ============================================================================
 * 添加 / 移除
 * ==========================================================================*/

/*
 * 单临界区插入：查重 → 续期 或 容量检查 → 插入。
 * 分配在取锁之前完成（GFP_ATOMIC 不持锁），若最终未用则 kfree。
 */
static int fw_ban_insert(u8 af, const void *addr, u32 duration_secs, const char *reason,
                         const char *jail, bool notify, bool *is_new, u64 start_unix) {
  struct fw_ban_node *n, *existing;
  u32 bkt = fw_ban_bucket(af, addr);

  n = fw_ban_alloc(af, addr, duration_secs, reason, jail, start_unix);
  if (!n)
    return -ENOMEM;

  spin_lock_bh(&fw_info.ban_locks[bkt]);

  existing = fw_ban_find_locked(af, addr, bkt);
  if (existing && !fw_ban_node_expired(existing)) {
    /* 已在封禁中：不重复插入、不推送事件 */
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    kfree(n);
    return 0;
  }

  if (existing) {
    /* 过期未摘链：按本次请求续期，重武装定时器 */
    existing->duration_secs = duration_secs;
    existing->is_permanent = duration_secs == 0;
    existing->banned_at = n->banned_at;
    existing->unban_jiffies = duration_secs ? jiffies + (unsigned long)duration_secs * HZ : 0;
    if (duration_secs)
      mod_timer(&existing->expire_timer, existing->unban_jiffies);
    else
      timer_delete(&existing->expire_timer);
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    kfree(n);
    return 0;
  }

  if (atomic_read(&fw_info.ban_count) >= (int)fw_info.max_ban_entries) {
    fw_stat_bump_ban_full();
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    kfree(n);
    return -ENOSPC;
  }

  hlist_add_head_rcu(&n->hash, fw_ban_bucket_head(af, bkt));
  atomic_inc(&fw_info.ban_count);
  spin_unlock_bh(&fw_info.ban_locks[bkt]);

  if (duration_secs)
    mod_timer(&n->expire_timer, n->unban_jiffies);

  if (is_new)
    *is_new = true;
  fw_stat_inc_bans();

  if (notify)
    fw_nl_send_ban_state_change(
      FW_BAN_ACTION_BAN, af, &n->addr, duration_secs, n->reason, n->jail_name);
  return 0;
}

int fw_ban_add(u8 af, const void *addr, u32 duration_secs, const char *reason,
               const char *jail, bool notify) {
  bool dummy = false;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;

  return fw_ban_insert(af, addr, duration_secs, reason, jail, notify, &dummy, 0);
}

int fw_ban_try_add(u8 af, const void *addr, u32 duration_secs,
                   const char *reason, const char *jail, bool notify) {
  bool is_new = false;
  int ret;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;
  if (!fw_addr_is_valid(af, addr))
    return -EINVAL;

  /* 白名单前检：命中即拒绝（白名单优先于封禁） */
  if (fw_wl_lookup(af, addr)) {
    fw_stat_bump_wl_rejects();
    return -EPERM;
  }

  /* 泛洪闸门：三条封禁路径共用同一道闸 */
  if (!fw_ban_flood_allow())
    return -EBUSY;

  ret = fw_ban_insert(af, addr, duration_secs, reason, jail, notify, &is_new, 0);
  return ret;
}

int fw_ban_del(u8 af, const void *addr, bool notify) {
  struct fw_ban_node *n;
  union fw_addr a;
  u32 bkt;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;

  bkt = fw_ban_bucket(af, addr);
  if (af == FW_AF_INET6)
    memcpy(&a, addr, sizeof(struct in6_addr));
  else
    a.ipv4 = *(__be32 *)addr;

  spin_lock_bh(&fw_info.ban_locks[bkt]);
  n = fw_ban_find_locked(af, addr, bkt);
  if (!n) {
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
    return -ENOENT;
  }
  timer_delete(&n->expire_timer);
  hlist_del_rcu(&n->hash);
  atomic_dec(&fw_info.ban_count);
  spin_unlock_bh(&fw_info.ban_locks[bkt]);

  call_rcu(&n->rcu, fw_ban_free_rcu);
  fw_stat_inc_unbans();

  if (notify)
    fw_nl_send_ban_state_change(FW_BAN_ACTION_UNBAN, af, &a, 0, "unban", NULL);
  return 0;
}

/*
 * 白名单变更联动：解封落在 (network / prefix_len) 覆盖范围内的条目。
 * 调用者不得持有白名单锁（本函数取各封禁桶锁）。精确前缀等价于「该地址本身」。
 */
void fw_ban_del_matching(u8 af, const void *network, u8 prefix_len) {
  struct fw_ban_node *n;
  struct hlist_node *tmp;
  u32 bkt;

  for (bkt = 0; bkt < BAN_HASH_SIZE; bkt++) {
    spin_lock_bh(&fw_info.ban_locks[bkt]);

    hlist_for_each_entry_safe(n, tmp, &fw_info.ban_ipv4[bkt], hash) {
      if (n->af != af)
        continue;
      if (!fw_prefix_match(af, &n->addr, network, prefix_len))
        continue;
      timer_delete(&n->expire_timer);
      hlist_del_rcu(&n->hash);
      atomic_dec(&fw_info.ban_count);
      call_rcu(&n->rcu, fw_ban_free_rcu);
      fw_stat_inc_unbans();
    }
    hlist_for_each_entry_safe(n, tmp, &fw_info.ban_ipv6[bkt], hash) {
      if (n->af != af)
        continue;
      if (!fw_prefix_match(af, &n->addr, network, prefix_len))
        continue;
      timer_delete(&n->expire_timer);
      hlist_del_rcu(&n->hash);
      atomic_dec(&fw_info.ban_count);
      call_rcu(&n->rcu, fw_ban_free_rcu);
      fw_stat_inc_unbans();
    }
    spin_unlock_bh(&fw_info.ban_locks[bkt]);
  }
}

/* ============================================================================
 * 状态恢复（跳过泛洪闸门；白名单前检由 fw_state.c 负责）
 * ==========================================================================*/

int fw_ban_restore(u8 af, const void *addr, u32 duration_secs, u64 banned_at,
                   const char *reason, const char *jail) {
  bool is_new = false;

  return fw_ban_insert(af, addr, duration_secs, reason, jail, true, &is_new, banned_at);
}

/* ============================================================================
 * 读侧分页遍历
 * ==========================================================================*/

u32 fw_ban_fill_entries(u32 offset, u32 limit, struct fw_ban_row *rows) {
  struct fw_ban_node *n;
  u32 idx = 0, count = 0, bkt;

  if (!rows || !limit)
    return 0;

  rcu_read_lock();

  for (bkt = 0; bkt < BAN_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(n, &fw_info.ban_ipv4[bkt], hash) {
      if (idx++ < offset)
        continue;
      rows[count].af = n->af;
      rows[count].is_permanent = n->is_permanent;
      rows[count].duration_secs = n->duration_secs;
      rows[count].banned_at = fw_ban_start_unix(n);
      rows[count].addr = n->addr;
      memcpy(rows[count].jail_name, n->jail_name, sizeof(rows[count].jail_name));
      memcpy(rows[count].reason, n->reason, sizeof(rows[count].reason));
      if (++count >= limit)
        break;
    }
  }
  for (bkt = 0; bkt < BAN_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(n, &fw_info.ban_ipv6[bkt], hash) {
      if (idx++ < offset)
        continue;
      rows[count].af = n->af;
      rows[count].is_permanent = n->is_permanent;
      rows[count].duration_secs = n->duration_secs;
      rows[count].banned_at = fw_ban_start_unix(n);
      rows[count].addr = n->addr;
      memcpy(rows[count].jail_name, n->jail_name, sizeof(rows[count].jail_name));
      memcpy(rows[count].reason, n->reason, sizeof(rows[count].reason));
      if (++count >= limit)
        break;
    }
  }

  rcu_read_unlock();
  return count;
}
