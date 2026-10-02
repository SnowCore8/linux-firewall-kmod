// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_rate.c - 速率表（65536 桶 hlist + RCU）、窗口滚动、EWMA、违规判定
 *
 * 与旧实现的关键差别（见 docs/zh/development/kernel-rewrite-design.md）：
 *
 *   1. **一次查表**。旧实现的 update_rate_stats / check_rate_violation /
 *      check_protocol_violation / check_tcp_flood_violation 各自调用
 *      find_rate_entry_rcu，合计 2.81 次/包。本文件由 fw_rate_observe() 一次
 *      查表取到条目指针，同一指针完成窗口滚动与四类违规判定。
 *
 *   2. **窗口原始计数落 per-CPU 槽**。热路径只写本 CPU 内存（无共享 cache line
 *      写）；窗口滚动时由抢到选举的那个 CPU 汇总各 CPU 槽并清零 —— 与设计文档
 *      「窗口滚动时（持桶锁的那个 CPU）汇总各 CPU 槽位并清零」一致。跨 CPU 写
 *      只发生在每次窗口滚动一次，不在每包路径上。
 *
 *   3. **热路径无自旋锁**。旧实现在「窗口未过期」的快速路径上只要 dst_port > 0
 *      就取速率桶锁去更新 seen_ports（最多 32 项线性扫描）。这里端口去重集合在
 *      per-CPU 槽，条目上的并集只由滚动者合并。桶锁只在**建条目**时取一次。
 *
 * 无锁热路径的正确性要点：
 *   - 条目自带固定槽下标 slot_idx，热路径只写 slots[slot_idx]。同一条目的所有包
 *     永远落在同一组槽位上，因此不存在「条目在槽间漂移」或需要重绑的情形。
 *   - 条目建立时在每 CPU 的 slots[slot_idx] 写入 entry 指针（此后不再改变），
 *     故热路径取到槽位后无需再查表。
 *   - 滚动用 atomic_cmpxchg(&n->rolling, 0, 1) 选出唯一的结算者，其余 CPU 直接
 *     返回；滚动者用 xchg 把各 CPU 计数取走并清零（计数是 atomic64）。
 *   - 删除条目时先在所有 CPU 上把引用它的槽置空，再 synchronize_rcu 释放，故
 *     RCU 读者要么读到空槽，要么读到的条目必然存活。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/overflow.h>
#include <linux/slab.h>

#include "fw_rate.h"
#include "fw_stats.h"

/* 读侧保留最近活跃扫描者的时长（秒） */
#define FW_RATE_PIN_SECONDS 60

/* ============================================================================
 * 小工具
 * ==========================================================================*/

static inline u32 fw_rate_bucket(u8 af, const void *addr) {
  return fw_hash_addr(af, addr, RATE_HASH_BITS);
}

static inline struct hlist_head *fw_rate_bucket_head(u8 af, u32 bkt) {
  return af == FW_AF_INET6 ? &fw_info.rate_ipv6[bkt] : &fw_info.rate_ipv4[bkt];
}

/* 桶内查找同一 (af, addr)。热路径与建条目路径都用；调用者决定是否持锁 */
static struct fw_rate_node *fw_rate_find_locked(u8 af, const void *addr, u32 bkt) {
  struct fw_rate_node *n;

  hlist_for_each_entry(n, fw_rate_bucket_head(af, bkt), hash) {
    if (n->af == af && fw_addr_equal(af, &n->addr, addr))
      return n;
  }
  return NULL;
}

/* EWMA 定点更新：smoothed = (3 * cur + 7 * old) / 10 */
static inline u64 fw_ewma(u64 cur, u64 old) {
  return (FW_EWMA_NUM * cur + (FW_EWMA_DEN - FW_EWMA_NUM) * old) / FW_EWMA_DEN;
}

/* 计数折算为「每秒」。溢出时退化为先除再乘，避免中间值回绕 */
static inline u64 fw_pps(u64 count, unsigned long elapsed) {
  unsigned long e = elapsed ? elapsed : 1;

  if (count > U64_MAX / HZ)
    return (count / e) * HZ;
  return count * HZ / e;
}

/* 槽位下标：与本机 CPU 数无关，只取决于地址（各 CPU 上同地址同下标） */
static inline u8 fw_rate_slot_idx(u8 af, const void *addr) {
  return (u8)(fw_hash_addr(af, addr, 16) & (FW_RATE_CPU_SLOTS - 1));
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

static void fw_rate_free_rcu(struct rcu_head *head) {
  kfree(container_of(head, struct fw_rate_node, rcu));
}

/*
 * 在所有 CPU 上清掉 entry 指向 victim 的槽位。
 * 通过 on_each_cpu(..., wait=1) 在**各 CPU 本地**执行：每个回调在工作队列上下文
 * 运行，可抢占软中断，因此与任意在跑的热路径（软中断或进程上下文）串行。
 * info == NULL 表示清空全部槽位（初始化用）。
 */
static void fw_rate_clear_slots_this_cpu(void *info) {
  struct fw_rate_node *victim = info;
  struct fw_rate_pcpu *r = this_cpu_ptr(fw_info.rate_pcpu);
  int i;

  for (i = 0; i < FW_RATE_CPU_SLOTS; i++) {
    struct fw_rate_cpu_slot *s = &r->slots[i];

    if (victim && rcu_access_pointer(s->entry) != victim)
      continue;

    atomic64_set(&s->packets, 0);
    atomic64_set(&s->bytes, 0);
    atomic64_set(&s->syn, 0);
    atomic64_set(&s->udp, 0);
    atomic64_set(&s->icmp, 0);
    atomic64_set(&s->ack, 0);
    atomic64_set(&s->rst, 0);
    atomic64_set(&s->fin, 0);
    smp_store_release(&s->entry, NULL);
    s->seen_port_n = 0;
    s->port_scan_counted = 0;
  }
}

/*
 * 把 tables 中的全部条目摘链到 ctx->pre，再逐条清槽 + 释放。
 * 冷路径专用（清表 / 退出）。摘链后统一走二次遍历，避免在桶锁内做 on_each_cpu。
 * 关键：清槽依赖 on_each_cpu 的各 CPU 回调能抢占软中断，因此不与热路径交错。
 */
static void fw_rate_drain_tables(void) {
  struct fw_rate_node *n;
  struct hlist_node *tmp;
  u32 bkt;

  for (bkt = 0; bkt < RATE_HASH_SIZE; bkt++) {
    spin_lock_bh(&fw_info.rate_locks[bkt]);
    hlist_for_each_entry_safe(n, tmp, &fw_info.rate_ipv4[bkt], hash) {
      hlist_del_rcu(&n->hash);
      hlist_add_head(&n->hash, &fw_info.rate_clear_ctx.pre.buckets[bkt]);
    }
    hlist_for_each_entry_safe(n, tmp, &fw_info.rate_ipv6[bkt], hash) {
      hlist_del_rcu(&n->hash);
      hlist_add_head(&n->hash, &fw_info.rate_clear_ctx.pre.buckets[bkt]);
    }
    spin_unlock_bh(&fw_info.rate_locks[bkt]);
  }

  for (bkt = 0; bkt < RATE_HASH_SIZE; bkt++) {
    hlist_for_each_entry_safe(n, tmp, &fw_info.rate_clear_ctx.pre.buckets[bkt], hash) {
      hlist_del(&n->hash);
      on_each_cpu(fw_rate_clear_slots_this_cpu, n, 1);
      call_rcu(&n->rcu, fw_rate_free_rcu);
    }
    INIT_HLIST_HEAD(&fw_info.rate_clear_ctx.pre.buckets[bkt]);
  }
}

int fw_rate_init(void) {
  u32 i;

  hash_init(fw_info.rate_ipv4);
  hash_init(fw_info.rate_ipv6);
  for (i = 0; i < RATE_HASH_SIZE; i++)
    spin_lock_init(&fw_info.rate_locks[i]);
  for (i = 0; i < RATE_HASH_SIZE; i++)
    INIT_HLIST_HEAD(&fw_info.rate_clear_ctx.pre.buckets[i]);
  spin_lock_init(&fw_info.rate_slot_lock);
  atomic_set(&fw_info.rate_count, 0);
  fw_info.rate_clear_ctx.clearing = false;

  fw_info.rate_pcpu = alloc_percpu(struct fw_rate_pcpu);
  if (!fw_info.rate_pcpu)
    return -ENOMEM;

  /* 新分配的 per-CPU 块已清零；显式清一遍以防复用残留 */
  on_each_cpu(fw_rate_clear_slots_this_cpu, NULL, 1);
  return 0;
}

void fw_rate_exit(void) {
  if (!fw_info.rate_pcpu)
    return;

  fw_info.rate_clear_ctx.clearing = true;
  smp_mb__after_atomic();

  fw_rate_drain_tables();

  synchronize_rcu();
  rcu_barrier();
  free_percpu(fw_info.rate_pcpu);
  fw_info.rate_pcpu = NULL;
  atomic_set(&fw_info.rate_count, 0);
  fw_info.rate_clear_ctx.clearing = false;
}

void fw_rate_clear_all(void) {
  if (!fw_info.rate_pcpu)
    return;

  fw_info.rate_clear_ctx.clearing = true;
  smp_mb__after_atomic();

  fw_rate_drain_tables();

  synchronize_rcu();
  atomic_set(&fw_info.rate_count, 0);
  fw_info.rate_clear_ctx.clearing = false;
}

/* ============================================================================
 * 条目创建（冷路径，持桶锁）
 * ==========================================================================*/

/* 把新条目的 entry 写进每个 CPU 的 slots[slot_idx]（发布槽位） */
static void fw_rate_publish_slots(struct fw_rate_node *n) {
  int cpu;

  for_each_possible_cpu(cpu) {
    struct fw_rate_cpu_slot *s = &per_cpu_ptr(fw_info.rate_pcpu, cpu)->slots[n->slot_idx];

    atomic64_set(&s->packets, 0);
    atomic64_set(&s->bytes, 0);
    atomic64_set(&s->syn, 0);
    atomic64_set(&s->udp, 0);
    atomic64_set(&s->icmp, 0);
    atomic64_set(&s->ack, 0);
    atomic64_set(&s->rst, 0);
    atomic64_set(&s->fin, 0);
    s->af = n->af;
    s->addr = n->addr;
    s->seen_port_n = 0;
    s->port_scan_counted = 0;
    s->last_activity = jiffies;
    rcu_assign_pointer(s->entry, n);
  }
}

/*
 * 建立条目。调用者已持对应桶锁；本函数内部再取 rate_slot_lock（桶锁 → 槽锁，
 * 唯一允许的嵌套，见 fw_types.h 锁顺序协议）。
 *
 * 槽位是「一条目固定一槽」：从 slot_idx 起线性探测一个未被任何条目占用的槽位，
 * 保证同一下标的各 CPU 槽位归属同一条目。表满（fw_max_rate_entries）或槽位耗尽
 * 或分配失败时返回 NULL。
 */
static struct fw_rate_node *fw_rate_create(u8 af, const void *addr, u32 bkt) {
  struct fw_rate_node *n;
  u8 slot_idx;
  u32 probe;

  if (atomic_read(&fw_info.rate_count) >= (int)fw_max_rate_entries) {
    fw_stat_bump_rate_spill();
    return NULL;
  }
  /* 清表/退出进行中：不建新条目（否则可能与 on_each_cpu 清槽交错） */
  if (unlikely(fw_info.rate_clear_ctx.clearing))
    return NULL;

  n = kzalloc(sizeof(*n), GFP_ATOMIC);
  if (!n) {
    fw_stat_bump_alloc_fail();
    return NULL;
  }

  spin_lock_bh(&fw_info.rate_slot_lock);

  slot_idx = fw_rate_slot_idx(af, addr);
  for (probe = 0; probe < FW_RATE_CPU_SLOTS; probe++) {
    struct fw_rate_cpu_slot *s = &per_cpu_ptr(fw_info.rate_pcpu, 0)->slots[slot_idx];

    if (!rcu_access_pointer(s->entry))
      break;
    slot_idx = (u8)((slot_idx + 1) & (FW_RATE_CPU_SLOTS - 1));
  }
  if (probe == FW_RATE_CPU_SLOTS) {
    spin_unlock_bh(&fw_info.rate_slot_lock);
    kfree(n);
    fw_stat_bump_rate_spill();
    return NULL;
  }

  n->af = af;
  if (af == FW_AF_INET6)
    memcpy(&n->addr, addr, sizeof(struct in6_addr));
  else
    n->addr.ipv4 = *(__be32 *)addr;
  n->slot_idx = slot_idx;
  n->window_start = jiffies;
  n->last_activity = jiffies;
  atomic_set(&n->rolling, 0);
  INIT_HLIST_NODE(&n->hash);

  hlist_add_head_rcu(&n->hash, fw_rate_bucket_head(af, bkt));
  atomic_inc(&fw_info.rate_count);
  fw_rate_publish_slots(n);

  spin_unlock_bh(&fw_info.rate_slot_lock);

  return n;
}

/* ============================================================================
 * 窗口滚动（由抢到选举的 CPU 执行）
 * ==========================================================================*/

/*
 * 结算上一窗口：汇总各 CPU 槽位并清零，计算新 EWMA，更新端口并集。
 *
 * elapsed 用实际经过的 jiffies（可能略大于一个窗口），因此算法对窗口抖动不敏感。
 */
static void fw_rate_roll(struct fw_rate_node *n, unsigned long now) {
  unsigned long elapsed = now - n->window_start;
  u64 cur_packets = 0, cur_bytes = 0, cur_syn = 0, cur_udp = 0, cur_icmp = 0,
      cur_ack = 0, cur_rst = 0, cur_fin = 0;
  int cpu;

  if (elapsed == 0)
    elapsed = 1;

  for_each_possible_cpu(cpu) {
    struct fw_rate_cpu_slot *s = &per_cpu_ptr(fw_info.rate_pcpu, cpu)->slots[n->slot_idx];
    u8 i;

    if (rcu_access_pointer(s->entry) != n)
      continue;

    cur_packets += (u64)atomic64_xchg(&s->packets, 0);
    cur_bytes += (u64)atomic64_xchg(&s->bytes, 0);
    cur_syn += (u64)atomic64_xchg(&s->syn, 0);
    cur_udp += (u64)atomic64_xchg(&s->udp, 0);
    cur_icmp += (u64)atomic64_xchg(&s->icmp, 0);
    cur_ack += (u64)atomic64_xchg(&s->ack, 0);
    cur_rst += (u64)atomic64_xchg(&s->rst, 0);
    cur_fin += (u64)atomic64_xchg(&s->fin, 0);

    for (i = 0; i < s->seen_port_n && i < PORT_SCAN_SEEN_MAX; i++) {
      u16 p = s->seen_ports[i];
      u8 j;
      bool dup = false;

      for (j = 0; j < n->seen_port_n; j++) {
        if (n->seen_ports[j] == p) {
          dup = true;
          break;
        }
      }
      if (!dup && n->seen_port_n < PORT_SCAN_SEEN_MAX)
        n->seen_ports[n->seen_port_n++] = p;
    }
    s->seen_port_n = 0;
    s->port_scan_counted = 0;
  }

  atomic64_set(&n->smoothed_pps, fw_ewma(fw_pps(cur_packets, elapsed),
                                         atomic64_read(&n->smoothed_pps)));
  atomic64_set(&n->smoothed_bps,
               fw_ewma(fw_pps(cur_bytes, elapsed), atomic64_read(&n->smoothed_bps)));
  atomic64_set(&n->smoothed_syn,
               fw_ewma(fw_pps(cur_syn, elapsed), atomic64_read(&n->smoothed_syn)));
  atomic64_set(&n->smoothed_udp,
               fw_ewma(fw_pps(cur_udp, elapsed), atomic64_read(&n->smoothed_udp)));
  atomic64_set(&n->smoothed_icmp,
               fw_ewma(fw_pps(cur_icmp, elapsed), atomic64_read(&n->smoothed_icmp)));
  atomic64_set(&n->smoothed_ack,
               fw_ewma(fw_pps(cur_ack, elapsed), atomic64_read(&n->smoothed_ack)));
  atomic64_set(&n->smoothed_rst,
               fw_ewma(fw_pps(cur_rst, elapsed), atomic64_read(&n->smoothed_rst)));
  atomic64_set(&n->smoothed_fin,
               fw_ewma(fw_pps(cur_fin, elapsed), atomic64_read(&n->smoothed_fin)));

  n->unique_ports = n->seen_port_n;
  if (!n->port_scan_counted && n->seen_port_n >= PORT_SCAN_THRESHOLD) {
    n->port_scan_counted = 1;
    atomic_inc(&fw_info.port_scan_detected);
  }

  n->window_start = now;
  n->last_activity = now;

  /* 释放选举：atomic RMW 自带全屏障，保证 window_start 的写入先行可见 */
  atomic_xchg(&n->rolling, 0);
}

/* ============================================================================
 * 违规判定
 * ==========================================================================*/

/* 协议专项阈值：命中返回理由字符串，否则 NULL */
static const char *fw_rate_protocol_check(const struct fw_rate_node *n,
                                          u8 protocol, u8 tcp_flags) {
  if (protocol == IPPROTO_TCP) {
    if (atomic64_read(&n->smoothed_syn) > READ_ONCE(fw_info.max_syn_per_second))
      return "SYN flood";
    if (tcp_flags & FW_TCP_ACK) {
      if (atomic64_read(&n->smoothed_ack) > READ_ONCE(fw_info.max_ack_per_second))
        return "ACK flood";
    }
    if (tcp_flags & FW_TCP_RST) {
      if (atomic64_read(&n->smoothed_rst) > READ_ONCE(fw_info.max_rst_per_second))
        return "RST flood";
    }
    if (tcp_flags & FW_TCP_FIN) {
      if (atomic64_read(&n->smoothed_fin) > READ_ONCE(fw_info.max_fin_per_second))
        return "FIN flood";
    }
    return NULL;
  }

  if (protocol == IPPROTO_UDP) {
    if (atomic64_read(&n->smoothed_udp) > READ_ONCE(fw_info.max_udp_per_second))
      return "UDP flood";
  } else if (protocol == IPPROTO_ICMP) {
    if (atomic64_read(&n->smoothed_icmp) > READ_ONCE(fw_info.max_icmp_per_second))
      return "ICMP flood";
  }
  return NULL;
}

/* 总速率阈值：静态与动态取较大者；两者都关时不判定 */
static const char *fw_rate_total_check(const struct fw_rate_node *n) {
  u64 pps_threshold = 0, bps_threshold = 0;
  bool use_static = fw_info.static_threshold_enabled;
  bool use_dynamic = fw_info.dynamic_threshold_enabled;

  if (!use_static && !use_dynamic)
    return NULL;

  if (use_static) {
    pps_threshold = READ_ONCE(fw_info.max_packets_per_second);
    bps_threshold = READ_ONCE(fw_info.max_bytes_per_second);
  }
  if (use_dynamic) {
    u64 ratio = READ_ONCE(fw_info.dynamic_threshold_ratio_x100);
    u64 base_pps = READ_ONCE(fw_info.baseline_pps);
    u64 base_bps = READ_ONCE(fw_info.baseline_bps);

    if (ratio) {
      u64 d_pps, d_bps;

      if (check_mul_overflow(base_pps, ratio, &d_pps))
        d_pps = 0;
      else
        d_pps /= 100;
      if (check_mul_overflow(base_bps, ratio, &d_bps))
        d_bps = 0;
      else
        d_bps /= 100;
      if (d_pps > pps_threshold)
        pps_threshold = d_pps;
      if (d_bps > bps_threshold)
        bps_threshold = d_bps;
    }
  }

  if (atomic64_read(&n->smoothed_pps) > pps_threshold)
    return "total rate";
  if (atomic64_read(&n->smoothed_bps) > bps_threshold)
    return "total rate";
  return NULL;
}

/* ============================================================================
 * 热路径入口（已持 RCU 读锁，由 fw_hook.c 调用）
 * ==========================================================================*/

const char *fw_rate_observe(u8 af, const void *addr, u32 packet_len, u8 protocol,
                            u8 tcp_flags, u16 dst_port, u64 *out_pps) {
  struct fw_rate_node *n;
  struct fw_rate_cpu_slot *s;
  const char *reason;
  unsigned long now = jiffies;
  u32 bkt = fw_rate_bucket(af, addr);
  u8 slot_idx;

  /* 清表/退出进行中：本包不参与速率判定（放行） */
  if (unlikely(fw_info.rate_clear_ctx.clearing))
    return NULL;

  n = fw_rate_find_locked(af, addr, bkt);
  if (unlikely(!n)) {
    /* 冷路径建条目：rate_locks[bkt] → rate_slot_lock（唯一允许的嵌套） */
    spin_lock_bh(&fw_info.rate_locks[bkt]);
    n = fw_rate_find_locked(af, addr, bkt);
    if (!n)
      n = fw_rate_create(af, addr, bkt);
    spin_unlock_bh(&fw_info.rate_locks[bkt]);
    if (unlikely(!n)) {
      /* 速率表满或分配失败：有意放行（见 fw_rate.h），由 rate_slot_spill 观测 */
      return NULL;
    }
  }

  slot_idx = n->slot_idx;
  if (unlikely(slot_idx >= FW_RATE_CPU_SLOTS))
    return NULL;

  s = &this_cpu_ptr(fw_info.rate_pcpu)->slots[slot_idx];
  /* 清表/退出窗口内槽位已被置空：本包不计、不判定 */
  if (unlikely(rcu_access_pointer(s->entry) != n))
    return NULL;

  atomic64_inc(&s->packets);
  atomic64_add(packet_len, &s->bytes);
  s->last_activity = now;

  switch (protocol) {
  case IPPROTO_TCP:
    if (tcp_flags & FW_TCP_SYN)
      atomic64_inc(&s->syn);
    if (tcp_flags & FW_TCP_ACK)
      atomic64_inc(&s->ack);
    if (tcp_flags & FW_TCP_RST)
      atomic64_inc(&s->rst);
    if (tcp_flags & FW_TCP_FIN)
      atomic64_inc(&s->fin);
    break;
  case IPPROTO_UDP:
    atomic64_inc(&s->udp);
    break;
  case IPPROTO_ICMP:
    atomic64_inc(&s->icmp);
    break;
  default:
    break;
  }

  /* 端口去重：只写本 CPU 槽（旧实现在此处取桶锁） */
  if (dst_port) {
    u8 i;
    bool dup = false;

    for (i = 0; i < s->seen_port_n && i < PORT_SCAN_SEEN_MAX; i++) {
      if (s->seen_ports[i] == dst_port) {
        dup = true;
        break;
      }
    }
    if (!dup && s->seen_port_n < PORT_SCAN_SEEN_MAX)
      s->seen_ports[s->seen_port_n++] = dst_port;
  }

  /* 窗口滚动：cmpxchg 选举唯一结算者，热路径不取锁 */
  if (unlikely(time_after(now, n->window_start + fw_info.rate_window_jiffies))) {
    if (atomic_cmpxchg(&n->rolling, 0, 1) == 0)
      fw_rate_roll(n, now);
  }

  if (out_pps)
    *out_pps = (u64)atomic64_read(&n->smoothed_pps);

  reason = fw_rate_total_check(n);
  if (!reason)
    reason = fw_rate_protocol_check(n, protocol, tcp_flags);
  return reason;
}

/* ============================================================================
 * 读侧
 * ==========================================================================*/

u32 fw_rate_count(void) {
  return (u32)atomic_read(&fw_info.rate_count);
}

void fw_rate_update_baseline(u64 total_pps, u64 total_bps) {
  u64 num = FW_BASELINE_EWMA_DEN - 1;

  WRITE_ONCE(fw_info.baseline_pps,
             (total_pps + num * READ_ONCE(fw_info.baseline_pps)) / FW_BASELINE_EWMA_DEN);
  WRITE_ONCE(fw_info.baseline_bps,
             (total_bps + num * READ_ONCE(fw_info.baseline_bps)) / FW_BASELINE_EWMA_DEN);
}

static void fw_rate_fill_row(struct fw_rate_row *row, struct fw_rate_node *n) {
  row->af = n->af;
  row->addr = n->addr;
  /* 速率条目对外语义是「速率」：用 EWMA 平滑值，读侧稳定可比 */
  row->packets = (u64)atomic64_read(&n->smoothed_pps);
  row->bytes = (u64)atomic64_read(&n->smoothed_bps);
  row->syn_packets = (u64)atomic64_read(&n->smoothed_syn);
  row->udp_packets = (u64)atomic64_read(&n->smoothed_udp);
  row->icmp_packets = (u64)atomic64_read(&n->smoothed_icmp);
  row->ack_packets = (u64)atomic64_read(&n->smoothed_ack);
  row->rst_packets = (u64)atomic64_read(&n->smoothed_rst);
  row->fin_packets = (u64)atomic64_read(&n->smoothed_fin);
  /* 端口并集不是 EWMA：它是条目生命周期内的累计并集（只增不减，上限
   * PORT_SCAN_SEEN_MAX），由滚动者在窗口边界把各 CPU 槽的集合并入。
   * READ_ONCE 与滚动者的写入配对，避免读到撕裂值。 */
  row->unique_ports = READ_ONCE(n->unique_ports);
}

u32 fw_rate_fill_entries(u32 offset, u32 limit, struct fw_rate_row *rows) {
  struct fw_rate_node *n;
  u32 idx = 0, count = 0, bkt;

  if (!rows || !limit)
    return 0;

  rcu_read_lock();
  for (bkt = 0; bkt < RATE_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(n, &fw_info.rate_ipv4[bkt], hash) {
      if (idx++ < offset)
        continue;
      fw_rate_fill_row(&rows[count], n);
      if (++count >= limit)
        break;
    }
  }
  for (bkt = 0; bkt < RATE_HASH_SIZE && count < limit; bkt++) {
    hlist_for_each_entry_rcu(n, &fw_info.rate_ipv6[bkt], hash) {
      if (idx++ < offset)
        continue;
      fw_rate_fill_row(&rows[count], n);
      if (++count >= limit)
        break;
    }
  }
  rcu_read_unlock();
  return count;
}

/* 服务探测：窗口内出现过 >= SERVICE_PROBE_THRESHOLD 种协议（TCP/UDP/ICMP 各算一种） */
static inline u32 fw_rate_proto_count(struct fw_rate_node *n) {
  u32 proto = 0;

  if (atomic64_read(&n->smoothed_syn) || atomic64_read(&n->smoothed_ack) ||
      atomic64_read(&n->smoothed_rst) || atomic64_read(&n->smoothed_fin))
    proto++;
  if (atomic64_read(&n->smoothed_udp))
    proto++;
  if (atomic64_read(&n->smoothed_icmp))
    proto++;
  return proto;
}

/* 单表扫描：端口扫描者；表由 caller 指定（v4/v6） */
static void fw_rate_scan_table(struct hlist_head *table, u32 *cnt, u32 max,
                               struct fw_scanner_row *out, unsigned long now,
                               unsigned long pin) {
  struct fw_rate_node *n;
  u32 bkt;

  for (bkt = 0; bkt < RATE_HASH_SIZE && *cnt < max; bkt++) {
    hlist_for_each_entry_rcu(n, &table[bkt], hash) {
      u32 metric;

      if (now - READ_ONCE(n->last_activity) > pin)
        continue;
      metric = READ_ONCE(n->unique_ports);
      if (metric < PORT_SCAN_THRESHOLD)
        continue;
      out[*cnt].af = n->af;
      out[*cnt].addr = n->addr;
      out[*cnt].metric = metric;
      out[*cnt].packets = (u64)atomic64_read(&n->smoothed_pps);
      (*cnt)++;
      if (*cnt >= max)
        break;
    }
  }
}

static void fw_rate_probe_table(struct hlist_head *table, u32 *cnt, u32 max,
                                struct fw_scanner_row *out, unsigned long now,
                                unsigned long pin) {
  struct fw_rate_node *n;
  u32 bkt;

  for (bkt = 0; bkt < RATE_HASH_SIZE && *cnt < max; bkt++) {
    hlist_for_each_entry_rcu(n, &table[bkt], hash) {
      u32 proto;

      if (now - READ_ONCE(n->last_activity) > pin)
        continue;
      proto = fw_rate_proto_count(n);
      if (proto < SERVICE_PROBE_THRESHOLD)
        continue;
      out[*cnt].af = n->af;
      out[*cnt].addr = n->addr;
      out[*cnt].metric = proto;
      out[*cnt].packets = (u64)atomic64_read(&n->smoothed_pps);
      (*cnt)++;
      if (*cnt >= max)
        break;
    }
  }
}

void fw_rate_read_scanners(struct fw_scanner_row *port_scanners, u32 port_max,
                           struct fw_scanner_row *service_probes, u32 probe_max,
                           u32 *probe_count) {
  unsigned long now = jiffies;
  unsigned long pin = (unsigned long)FW_RATE_PIN_SECONDS * HZ;
  u32 n_scan = 0, n_probe = 0;

  if (!port_scanners || !service_probes || !probe_count)
    return;
  *probe_count = 0;

  rcu_read_lock();
  /* 只取最近活跃的条目，避免哈希顺序把真正的扫描者挤出结果集 */
  fw_rate_scan_table(fw_info.rate_ipv4, &n_scan, port_max, port_scanners, now, pin);
  fw_rate_scan_table(fw_info.rate_ipv6, &n_scan, port_max, port_scanners, now, pin);
  fw_rate_probe_table(fw_info.rate_ipv4, &n_probe, probe_max, service_probes, now, pin);
  fw_rate_probe_table(fw_info.rate_ipv6, &n_probe, probe_max, service_probes, now, pin);
  rcu_read_unlock();

  *probe_count = n_probe;
}
