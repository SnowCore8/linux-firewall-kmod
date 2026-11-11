// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_ban.c - 封禁表（按 prefix_len 分层的桶表 + RCU + 层内桶锁，per-entry 定时器）
 *
 * 与旧实现的差别（见 docs/zh/development/kernel-module-design.md）：
 *
 *   - **容量上限**：新增 fw_max_ban_entries（默认 65535），在桶锁内原子检查；
 *     到限拒绝并递增 ban_table_full_rejects —— 这给了该计数器唯一递增点，
 *     修复 PROC_BAN_TABLE_FULL_NEVER_INC（旧实现该计数恒为 0）。
 *   - **删除 retry_count**：旧实现只有置零、无读取点。
 *   - **泛洪闸门统一**：fw_ban_flood_allow() 由三条封禁路径（procfs / netlink /
 *     DDoS 自决）统一调用；旧实现只有 procfs 一条路径检查 fw_max_bans_per_second
 *     （设计文档「本次新查出的稳定性问题 1」）。
 *   - **前缀（CIDR）封禁**：条目带 prefix_len，32/128 表示精确单机。命中条件由
 *     「地址相等」改为「ip 落在条目前缀内」，复用白名单的 fw_prefix_match()——
 *     两处必须是同一个函数，否则前缀语义会漂移。条目身份是 (af, addr, prefix_len)
 *     三元组：全长与前缀条目分处不同层，`x.x.x.0/24` 与 `x.x.x.0/32` 互不覆盖。
 *     层内桶索引按**本层前缀归一化后的地址**计算，故同一网段内任意源 IP 必落同一
 *     桶；全长层的归一化是恒等变换，/32 的查找路径与加该字段之前逐桶一致。
 *
 * 锁顺序：本文件只取（i）某层某桶的层内桶锁，或（ii）ban_layer_lock（位图与层
 * 计数），两者**不嵌套**——层内增删在桶锁内完成后，才在锁外维护位图。
 *
 * 位图维护的正确性（关键）：
 *   used 位图的 bit L 表示「层 L 可能有条目」，热路径只探测置位的层。清位必须
 *   保证层内确实没有活着的条目，否则条目会永久不可见（等于漏封）。做法是每层一个
 *   count，并严格遵守两处顺序：
 *     - 插入：先把节点挂进桶（add_head_rcu），**再** count++ 并在 0→1 时置位；
 *     - 删除：先把节点摘链，**再** count-- 并在归零时清位。
 *   于是「已 mark 的活条目」必然使 count > 0，而清位只在 count 归零时发生，故清位
 *   不可能落在活条目上。插入在「已挂链、未 mark」的窗口内可能被并发读者漏看一次
 *   （与 RCU 发布的固有语义一致：并发插入本就不保证被同一次查询看到）。
 *
 * 定时器与释放的安全性（关键）：
 *   到期回调整体包在 rcu_read_lock() 里。删除路径（手动解封 / 白名单联动 /
 *   退出清理）用 timer_delete()（非等待）+ hlist_del_init_rcu() + call_rcu() 释放。
 *   摘链一律 hlist_del_init_rcu()（pprev 置 NULL）：到期回调与删除路径竞态时，
 *   hlist_unhashed() 必须仍能判出「已摘链」，否则会二次摘链并写毒化指针。
 *   由于 call_rcu 的释放回调必须等一个宽限期结束，而正在执行的到期回调持有
 *   RCU 读侧临界区，宽限期不会在它结束前完成 —— 因此回调不可能访问到已释放
 *   的节点。这样既不需要在持桶锁时调用 timer_delete_sync()（会自锁死），
 *   也不存在使用后释放。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include "fw_ban.h"
#include "fw_wl.h"
#include "fw_stats.h"
#include "fw_netlink.h"

/*
 * 内核 API 兼容层：`timer_container_of()` 是 6.16 才引入的名字，此前的内核里同一
 * 件事叫 `from_timer()`，而 7.0 起旧名已经删除，两个名字不共存。Ubuntu 24.04 的 GA
 * 内核 6.8 只有 `from_timer`，缺这段就直接卡在 -Werror=implicit-function-declaration。
 *
 * 这里按**宏是否存在**来适配，而不是比 `LINUX_VERSION_CODE`：发行版会把新宏
 * backport 进旧版本号的内核（也反过来砍掉旧宏），照版本号判断在这类内核上正好判反。
 */
#ifndef timer_container_of
#  define timer_container_of(var, callback_timer, timer_fieldname) \
    from_timer(var, callback_timer, timer_fieldname)
#endif

/*
 * 编译期自检（分层桶表的尺寸不变量）。
 * 本机内核未开 CONFIG_KUNIT，也没有宿主侧单元测试环境，故凡是能编译期证明的
 * 语义不足都放这里，不留到运行时：
 *   - 层号即 prefix_len，层数组与 used 位图都必须能索引到 IPv6 的 128；
 *   - 遍历桶的三处（fw_ban_exit / fw_ban_del_matching / fw_ban_fill_entries）
 *     都按 `1U << layer->bucket_bits` 走，位移量必须 < 32（u32 位移溢出即 UB）；
 *   - 短前缀层必须真的小于全长层，否则「分层省内存」这条取舍不成立。
 * 断言消息用 ASCII：GCC 在本机把非 ASCII 的 _Static_assert 消息打成八进制转义
 * （`\377...`），日志里不可读；中文说明留在本注释里。
 */
_Static_assert(BAN_MAX_LAYERS == 129, "ban layers/bitmap must cover prefix_len 0..128");
_Static_assert(BAN_SHORT_LAYER_BITS < BAN_HASH_BITS,
               "short-prefix layers must be smaller than the full-length layer");
_Static_assert(BAN_SHORT_LAYER_BITS < 32 && BAN_HASH_BITS < 32,
               "bucket_bits is used as 1U << bits, must stay below 32");

/*
 * banned_at 是封禁起点的 Unix 秒；unban_jiffies 是绝对到期时刻，**同样以 Unix
 * 秒计**（0 表示永久）。二者对外契约本来就是 Unix 秒，存 Unix 秒可省掉读侧换算。
 * 不用 jiffies 存到期时刻的原因在 32 位内核上很硬：unsigned long 只有 32 位，
 * 365 天（契约允许的上限）乘以 HZ 后回绕成过去值，mod_timer 会立即到期。Unix
 * 秒在 32 位 unsigned long 上可表示到 2106 年，远超契约上限。定时器因此只武装
 * 到可表示的一跳，未到绝对时刻就再武装剩余段（见 fw_ban_timer_deadline）。
 */
static u64 fw_ban_start_unix(const struct fw_ban_node *n) {
  return (u64)READ_ONCE(n->banned_at);
}

/*
 * 定时器的一次武装截止点：jiffies 最多安全推进 MAX_JIFFY_OFFSET，更长的间隔
 * 必须分段。返回 jiffies + min(距到期秒数 * HZ, MAX_JIFFY_OFFSET)。
 */
static unsigned long fw_ban_timer_deadline(u64 expire_unix) {
  u64 now = ktime_get_real_seconds();
  u64 secs = expire_unix > now ? expire_unix - now : 0;
  u64 jif = secs * (u64)HZ;

  if (jif > (u64)MAX_JIFFY_OFFSET)
    jif = (u64)MAX_JIFFY_OFFSET;
  return jiffies + (unsigned long)jif;
}

/* 地址族对应的封禁表（v4/v6 各一张，层内结构相同，只是层数不同） */
static inline struct fw_ban_table *fw_ban_table(u8 af) {
  return af == FW_AF_INET6 ? &fw_info.ban_v6 : &fw_info.ban_v4;
}

/* 前缀长度合法性：越界会索引到 layers[] 之外，故写侧一律先过这一关 */
static inline bool fw_ban_prefix_valid(u8 af, u8 prefix_len) {
  return af == FW_AF_INET6 ? prefix_len <= 128 : prefix_len <= 32;
}

/*
 * 层内桶下标。地址必须先按本层前缀归一化：同一 /24 内不同源 IP 只有清掉主机位才
 * 落到同一桶（否则每个 IP 各占一桶，前缀封禁等于失效）。全长层掩码全 1，归一化
 * 是恒等变换，故直接哈希原地址 —— 与旧实现的桶映射完全一致。
 */
static inline u32 fw_ban_bucket(const struct fw_ban_layer *layer, u8 af,
                                const void *addr, u8 prefix_len) {
  union fw_addr key;

  if (prefix_len == fw_max_prefix_len(af))
    return fw_hash_addr(af, addr, layer->bucket_bits);

  memcpy(key.raw, addr, af == FW_AF_INET6 ? sizeof(struct in6_addr) : sizeof(__be32));
  fw_addr_normalize(af, key.raw, prefix_len);
  return fw_hash_addr(af, key.raw, layer->bucket_bits);
}

/*
 * 桶内查找同一 (af, addr) 的条目；调用者已持该桶锁。
 * 层号即 prefix_len（每层一套桶数组），故同一层内比较地址即可，三元组的第三元由
 * 「在哪个层里找」保证。
 */
static struct fw_ban_node *fw_ban_find_locked(const struct fw_ban_layer *layer,
                                              u8 af, const void *addr, u32 bkt) {
  struct fw_ban_node *n;

  hlist_for_each_entry(n, &layer->buckets[bkt], hash) {
    if (n->af == af && fw_addr_equal(af, &n->addr, addr))
      return n;
  }
  return NULL;
}

/*
 * 层计数 + 位图的维护：入账（插入后）与出账（删除后）。
 * 只由这两个函数改写位图；顺序要求（挂链在前、位图在后）见文件头。
 */
static void fw_ban_layer_mark(struct fw_ban_table *t, u8 prefix_len) {
  spin_lock_bh(&fw_info.ban_layer_lock);
  if (atomic_inc_return(&t->layers[prefix_len].count) == 1)
    set_bit(prefix_len, t->used);
  spin_unlock_bh(&fw_info.ban_layer_lock);
}

static void fw_ban_layer_release(struct fw_ban_table *t, u8 prefix_len, u32 n) {
  spin_lock_bh(&fw_info.ban_layer_lock);
  if (atomic_sub_return((int)n, &t->layers[prefix_len].count) <= 0)
    clear_bit(prefix_len, t->used);
  spin_unlock_bh(&fw_info.ban_layer_lock);
}

static inline bool fw_ban_node_expired(const struct fw_ban_node *n) {
  if (READ_ONCE(n->is_permanent))
    return false;
  return ktime_get_real_seconds() >= (u64)READ_ONCE(n->unban_jiffies);
}

/* 单层探测：层内桶里是否存在覆盖 ip 的条目（调用者持 RCU 读侧临界区） */
static bool fw_ban_probe_layer(struct fw_ban_table *t, u8 af, u8 prefix_len, const void *ip) {
  const struct fw_ban_layer *layer = &t->layers[prefix_len];
  const struct fw_ban_node *n;
  u32 bkt = fw_ban_bucket(layer, af, ip, prefix_len);

  hlist_for_each_entry_rcu(n, &layer->buckets[bkt], hash) {
    /* 同层条目的 prefix_len 必然等于本层层号，故只需验地址是否落在前缀内 */
    if (fw_prefix_match(af, ip, &n->addr, prefix_len))
      return true;
  }
  return false;
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

static void fw_ban_table_setup(struct fw_ban_table *t, u8 max_prefix) {
  u8 L;
  u32 i;

  t->max_prefix = max_prefix;
  bitmap_zero(t->used, BAN_MAX_LAYERS);

  for (i = 0; i < BAN_HASH_SIZE; i++) {
    INIT_HLIST_HEAD(&t->full_buckets[i]);
    spin_lock_init(&t->full_locks[i]);
  }

  for (L = 0; L <= max_prefix; L++) {
    struct fw_ban_layer *layer = &t->layers[L];

    if (L == max_prefix) {
      /* 全长层（精确单机）：复用表内的 4096 桶，与旧实现同规模 */
      layer->buckets = t->full_buckets;
      layer->locks = t->full_locks;
      layer->bucket_bits = BAN_HASH_BITS;
    } else {
      /* 短前缀层（网段）：条目稀少，用本层内嵌的小桶数组 */
      layer->buckets = layer->short_buckets;
      layer->locks = layer->short_locks;
      layer->bucket_bits = BAN_SHORT_LAYER_BITS;
      for (i = 0; i < BAN_SHORT_LAYER_SIZE; i++) {
        INIT_HLIST_HEAD(&layer->short_buckets[i]);
        spin_lock_init(&layer->short_locks[i]);
      }
    }
    atomic_set(&layer->count, 0);
  }
}

int fw_ban_init(void) {
  fw_ban_table_setup(&fw_info.ban_v4, 32);
  fw_ban_table_setup(&fw_info.ban_v6, 128);

  spin_lock_init(&fw_info.ban_layer_lock);
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

static struct fw_ban_node *fw_ban_alloc(u8 af, const void *addr, u8 prefix_len,
                                        u32 duration_secs, const char *reason,
                                        const char *jail, u64 start_unix) {
  struct fw_ban_node *n = kzalloc(sizeof(*n), GFP_ATOMIC);

  if (!n) {
    fw_stat_bump_alloc_fail();
    return NULL;
  }
  n->af = af;
  n->prefix_len = prefix_len;
  n->duration_secs = duration_secs;
  n->is_permanent = duration_secs == 0;
  /* 起点：状态恢复传回原始起点，运行路径取当前时刻；到期时刻 = 起点 + 时长 */
  n->banned_at = (unsigned long)(start_unix ? start_unix : (u64)ktime_get_real_seconds());
  if (duration_secs)
    n->unban_jiffies = (unsigned long)((u64)n->banned_at + duration_secs);
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
  struct fw_ban_table *tbl;
  struct fw_ban_layer *layer;
  union fw_addr addr;
  u32 bkt;
  u8 af, prefix_len;
  u64 expire;

  rcu_read_lock();

  af = READ_ONCE(n->af);
  prefix_len = READ_ONCE(n->prefix_len);
  tbl = fw_ban_table(af);
  layer = &tbl->layers[prefix_len];
  bkt = fw_ban_bucket(layer, af, &n->addr, prefix_len);
  if (af == FW_AF_INET6)
    memcpy(&addr, &n->addr, sizeof(struct in6_addr));
  else
    addr.ipv4 = n->addr.ipv4;

  spin_lock_bh(&layer->locks[bkt]);

  if (hlist_unhashed(&n->hash)) {
    /* 已被手动解封 / 白名单联动 / 退出清理摘链，本回调无需再动 */
    spin_unlock_bh(&layer->locks[bkt]);
    rcu_read_unlock();
    return;
  }
  /*
   * 续期为永久：续期路径写 is_permanent=1 后只做 timer_delete()（不同步），
   * 本回调可能已在运行。此时条目按永久保留，绝不能按到期摘链删除。
   */
  if (READ_ONCE(n->is_permanent)) {
    spin_unlock_bh(&layer->locks[bkt]);
    rcu_read_unlock();
    return;
  }
  /*
   * 定时器只武装到可表示的一跳（32 位内核上 365 天远超 jiffies 范围），故这里
   * 按绝对到期时刻判断：续期竞态（到期前被延长）与分段未走完都表现为「未到绝对
   * 时刻」，此时重新武装剩余段即可，不能按 jiffies 比较（那会被截断骗过）。
   */
  expire = (u64)READ_ONCE(n->unban_jiffies);
  if (!READ_ONCE(n->is_permanent) && ktime_get_real_seconds() < expire) {
    mod_timer(&n->expire_timer, fw_ban_timer_deadline(expire));
    spin_unlock_bh(&layer->locks[bkt]);
    rcu_read_unlock();
    return;
  }

  hlist_del_init_rcu(&n->hash);
  atomic_dec(&fw_info.ban_count);
  spin_unlock_bh(&layer->locks[bkt]);

  rcu_read_unlock();

  fw_ban_layer_release(tbl, prefix_len, 1); /* 摘链之后才清位图（文件头顺序要求） */
  fw_stat_add_expired(1);
  call_rcu(&n->rcu, fw_ban_free_rcu);

  /*
   * 发送前尝试获取读锁，防止 fw_netlink_exit() 在此期间释放 socket。
   * 使用 trylock 避免在 softirq 上下文中休眠（非 PREEMPT_RT 内核的定时器回调
   * 在 softirq 中执行，down_read 是可休眠的 rwsem，会导致 might_sleep 警告）。
   * 获取失败时跳过通知，不影响封禁解除的正确性。
   */
  if (fw_nl_send_trylock()) {
    if (fw_nl_sock_available())
      fw_nl_send_ban_state_change(
        FW_BAN_ACTION_UNBAN, af, prefix_len, &addr, 0, "expired", NULL);
    fw_nl_send_unlock();
  }
}

void fw_ban_exit(void) {
  struct fw_ban_table *tables[] = { &fw_info.ban_v4, &fw_info.ban_v6 };
  struct fw_ban_node *n;
  struct hlist_node *tmp;
  u32 ti;
  u8 L;

  for (ti = 0; ti < ARRAY_SIZE(tables); ti++) {
    struct fw_ban_table *t = tables[ti];

    for (L = 0; L <= t->max_prefix; L++) {
      struct fw_ban_layer *layer = &t->layers[L];
      u32 bkt, nbuckets = 1U << layer->bucket_bits;

      for (bkt = 0; bkt < nbuckets; bkt++) {
        spin_lock_bh(&layer->locks[bkt]);

        hlist_for_each_entry_safe(n, tmp, &layer->buckets[bkt], hash) {
          timer_delete(&n->expire_timer);
          hlist_del_init_rcu(&n->hash);
          call_rcu(&n->rcu, fw_ban_free_rcu);
        }
        spin_unlock_bh(&layer->locks[bkt]);
      }
      atomic_set(&layer->count, 0);
    }
    bitmap_zero(t->used, BAN_MAX_LAYERS);
  }
  atomic_set(&fw_info.ban_count, 0);

  synchronize_rcu();
  rcu_barrier();
}

/* ============================================================================
 * 热路径（RCU 只读）
 * ==========================================================================*/

bool fw_ban_lookup(u8 af, const void *ip) {
  struct fw_ban_table *t = fw_ban_table(af);
  unsigned long L;

  /* 先查精确层（/32 或 /128）：现状全部条目都在这一层，一次哈希即命中 */
  if (test_bit(t->max_prefix, t->used) && fw_ban_probe_layer(t, af, t->max_prefix, ip))
    return true;

  /* 再按位图遍历更短前缀层（常态 1–3 层），每层一次哈希 */
  for_each_set_bit(L, t->used, t->max_prefix) {
    if (fw_ban_probe_layer(t, af, (u8)L, ip))
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
 * 查重与删除定位都按 (af, addr, prefix_len) 三元组：前缀决定层，层决定桶数组。
 */
static int fw_ban_insert(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
                         const char *reason, const char *jail, bool notify,
                         bool *is_new, u64 start_unix, bool flood_gate) {
  struct fw_ban_table *t = fw_ban_table(af);
  struct fw_ban_layer *layer = &t->layers[prefix_len];
  struct fw_ban_node *n, *existing;
  union fw_addr addr_copy;
  char reason_copy[32];
  char jail_copy[32];
  u32 bkt = fw_ban_bucket(layer, af, addr, prefix_len);

  n = fw_ban_alloc(af, addr, prefix_len, duration_secs, reason, jail, start_unix);
  if (!n)
    return -ENOMEM;

  spin_lock_bh(&layer->locks[bkt]);

  existing = fw_ban_find_locked(layer, af, addr, bkt);
  if (existing && !fw_ban_node_expired(existing)) {
    /* 已在封禁中：不重复插入、不推送事件 */
    spin_unlock_bh(&layer->locks[bkt]);
    kfree(n);
    return 0;
  }

  if (existing) {
    /*
     * 过期未摘链：若直接走新插入路径而不删除旧节点，同一 (af, addr, prefix_len)
     * 在哈希桶中会有两个节点，ban_count 被多加 1，导致计数膨胀。必须先完整
     * 删除旧节点（停定时器、摘链、减计数、RCU 释放），再插入新节点。
     */
    timer_delete(&existing->expire_timer);
    hlist_del_init_rcu(&existing->hash);
    atomic_dec(&fw_info.ban_count);
    call_rcu(&existing->rcu, fw_ban_free_rcu);
    /* 旧节点已摘链，继续走下方的新插入路径 */
  }

  /*
   * 容量检查用 atomic_inc_return 保证原子性，避免多桶并发插入导致超限。
   * 先增后判：超限时回滚递减。
   */
  if (atomic_inc_return(&fw_info.ban_count) > (int)fw_info.max_ban_entries) {
    atomic_dec(&fw_info.ban_count);
    fw_stat_bump_ban_full();
    spin_unlock_bh(&layer->locks[bkt]);
    kfree(n);
    return -ENOSPC;
  }

  /*
   * 泛洪闸门只对「确实要插入新条目」扣预算：有效条目在上面已直接返回，续期
   * 走另一个分支，都不会到这里。闸门放在容量检查之后，被 -ENOSPC 拒绝的请求
   * 也不占预算——只扣真正落地为插入的那一次，重复下发同一地址不会把 200/s
   * 的名额耗尽后让新封禁报 -EBUSY。
   */
  if (flood_gate && !fw_ban_flood_allow()) {
    atomic_dec(&fw_info.ban_count);
    spin_unlock_bh(&layer->locks[bkt]);
    kfree(n);
    return -EBUSY;
  }

  /*
   * 定时器在发布前武装：避免 PREEMPT_RT 下节点发布后、mod_timer 前被其他 CPU
   * 删除并释放，导致操作已释放的 timer_list（use-after-free）。
   */
  if (duration_secs)
    mod_timer(&n->expire_timer, fw_ban_timer_deadline((u64)n->unban_jiffies));

  /*
   * 事件字段必须在解锁前拷到栈上：节点一旦挂链就发布给读者，并发的
   * fw_ban_del / fw_ban_del_matching 会摘链并 call_rcu 释放，解锁后再读
   * n->addr / n->reason / n->jail_name 就是访问已释放内存。
   */
  addr_copy = n->addr;
  strscpy(reason_copy, n->reason, sizeof(reason_copy));
  strscpy(jail_copy, n->jail_name, sizeof(jail_copy));

  hlist_add_head_rcu(&n->hash, &layer->buckets[bkt]);
  spin_unlock_bh(&layer->locks[bkt]);

  /* 位图维护在桶锁之外，且必须在挂链之后（顺序理由见文件头） */
  fw_ban_layer_mark(t, prefix_len);

  if (is_new)
    *is_new = true;
  fw_stat_inc_bans();

  /*
   * 通知发送：字段已在上面的临界区内拷贝，解锁后发送不会碰到已释放节点。
   * 同时持有 netlink 发送锁，防止 socket 被并发释放。
   */
  if (notify) {
    fw_nl_send_lock();
    if (fw_nl_sock_available())
      fw_nl_send_ban_state_change(FW_BAN_ACTION_BAN, af, prefix_len, &addr_copy,
                                  duration_secs, reason_copy, jail_copy);
    fw_nl_send_unlock();
  }
  return 0;
}

int fw_ban_try_add(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
                   const char *reason, const char *jail, bool notify) {
  bool is_new = false;
  int ret;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;
  if (!fw_ban_prefix_valid(af, prefix_len))
    return -EINVAL;
  if (!fw_addr_is_valid(af, addr))
    return -EINVAL;

  /* 白名单前检：命中即拒绝（白名单优先于封禁）。前缀条目按「网段地址本身是否落在
   * 白名单覆盖范围内」判断；网段内部的个别白名单主机由热路径的白名单短路保护。 */
  if (fw_wl_lookup(af, addr)) {
    fw_stat_bump_wl_rejects();
    return -EPERM;
  }

  /* 泛洪闸门：三条封禁路径共用同一道闸。闸门在 fw_ban_insert 内、确认要插入
   * 新条目之后才扣预算，重复下发已封禁地址不再消耗名额。 */
  ret = fw_ban_insert(
    af, addr, prefix_len, duration_secs, reason, jail, notify, &is_new, 0, true);
  return ret;
}

int fw_ban_del(u8 af, const void *addr, u8 prefix_len, bool notify) {
  struct fw_ban_table *t = fw_ban_table(af);
  struct fw_ban_layer *layer;
  struct fw_ban_node *n;
  union fw_addr a;
  u32 bkt;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;
  if (!fw_ban_prefix_valid(af, prefix_len))
    return -EINVAL;

  layer = &t->layers[prefix_len];
  bkt = fw_ban_bucket(layer, af, addr, prefix_len);
  if (af == FW_AF_INET6)
    memcpy(&a, addr, sizeof(struct in6_addr));
  else
    a.ipv4 = *(__be32 *)addr;

  spin_lock_bh(&layer->locks[bkt]);
  n = fw_ban_find_locked(layer, af, addr, bkt);
  if (!n) {
    spin_unlock_bh(&layer->locks[bkt]);
    return -ENOENT;
  }
  timer_delete(&n->expire_timer);
  hlist_del_init_rcu(&n->hash);
  atomic_dec(&fw_info.ban_count);
  spin_unlock_bh(&layer->locks[bkt]);

  fw_ban_layer_release(t, prefix_len, 1); /* 摘链之后才清位图（文件头顺序要求） */
  call_rcu(&n->rcu, fw_ban_free_rcu);
  fw_stat_inc_unbans();

  /*
   * 发送保护：持有 netlink 发送读锁，防止与 fw_netlink_exit() 的 socket 释放并发。
   * 与 fw_ban_insert() 保持一致的锁模式。
   */
  if (notify) {
    fw_nl_send_lock();
    if (fw_nl_sock_available())
      fw_nl_send_ban_state_change(FW_BAN_ACTION_UNBAN, af, prefix_len, &a, 0, "unban", NULL);
    fw_nl_send_unlock();
  }
  return 0;
}

/*
 * 白名单变更联动：解封落在 (network / prefix_len) 覆盖范围内的条目。
 * 调用者不得持有白名单锁（本函数取各封禁层桶锁）。
 * 精确前缀等价于「该地址本身」；判定沿用同一个 fw_prefix_match()。
 */
void fw_ban_del_matching(u8 af, const void *network, u8 prefix_len) {
  struct fw_ban_table *t = fw_ban_table(af);
  struct fw_ban_node *n;
  struct hlist_node *tmp;
  u8 L;

  if (af != FW_AF_INET && af != FW_AF_INET6)
    return;

  for (L = 0; L <= t->max_prefix; L++) {
    struct fw_ban_layer *layer = &t->layers[L];
    u32 bkt, nbuckets = 1U << layer->bucket_bits;

    for (bkt = 0; bkt < nbuckets; bkt++) {
      u32 removed = 0;

      spin_lock_bh(&layer->locks[bkt]);
      hlist_for_each_entry_safe(n, tmp, &layer->buckets[bkt], hash) {
        if (!fw_prefix_match(af, &n->addr, network, prefix_len))
          continue;
        timer_delete(&n->expire_timer);
        hlist_del_init_rcu(&n->hash);
        atomic_dec(&fw_info.ban_count);
        call_rcu(&n->rcu, fw_ban_free_rcu);
        fw_stat_inc_unbans();
        removed++;
      }
      spin_unlock_bh(&layer->locks[bkt]);

      /* 位图维护在桶锁之外（本文件不允许两把 ban 锁嵌套持有） */
      if (removed)
        fw_ban_layer_release(t, L, removed);
    }
  }
}

/* ============================================================================
 * 状态恢复（跳过泛洪闸门；白名单前检由 fw_state.c 负责）
 * ==========================================================================*/

int fw_ban_restore(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
                   u64 banned_at, const char *reason, const char *jail) {
  bool is_new = false;

  if (!addr || (af != FW_AF_INET && af != FW_AF_INET6))
    return -EINVAL;
  if (!fw_ban_prefix_valid(af, prefix_len))
    return -EINVAL;

  return fw_ban_insert(af, addr, prefix_len, duration_secs, reason, jail, true,
                       &is_new, banned_at, false);
}

/* ============================================================================
 * 读侧分页遍历
 * ==========================================================================*/

u32 fw_ban_fill_entries(u32 offset, u32 limit, struct fw_ban_row *rows) {
  struct fw_ban_table *tables[] = { &fw_info.ban_v4, &fw_info.ban_v6 };
  struct fw_ban_node *n;
  u32 idx = 0, count = 0, ti;
  u8 L;

  if (!rows || !limit)
    return 0;

  rcu_read_lock();

  for (ti = 0; ti < ARRAY_SIZE(tables) && count < limit; ti++) {
    struct fw_ban_table *t = tables[ti];

    for (L = 0; L <= t->max_prefix && count < limit; L++) {
      struct fw_ban_layer *layer = &t->layers[L];
      u32 bkt, nbuckets = 1U << layer->bucket_bits;

      for (bkt = 0; bkt < nbuckets && count < limit; bkt++) {
        spin_lock_bh(&layer->locks[bkt]);
        hlist_for_each_entry_rcu(n, &layer->buckets[bkt], hash) {
          if (idx++ < offset)
            continue;
          rows[count].af = n->af;
          rows[count].is_permanent = READ_ONCE(n->is_permanent);
          rows[count].prefix_len = n->prefix_len;
          rows[count].duration_secs = READ_ONCE(n->duration_secs);
          rows[count].banned_at = fw_ban_start_unix(n);
          rows[count].addr = n->addr;
          memcpy(rows[count].jail_name, n->jail_name, sizeof(rows[count].jail_name));
          memcpy(rows[count].reason, n->reason, sizeof(rows[count].reason));
          if (++count >= limit)
            break;
        }
        spin_unlock_bh(&layer->locks[bkt]);
      }
    }
  }

  rcu_read_unlock();
  return count;
}
