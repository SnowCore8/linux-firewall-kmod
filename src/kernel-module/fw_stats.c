// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_stats.c - per-CPU 统计与分析分布
 *
 * 设计要点（见 docs/zh/development/kernel-rewrite-design.md）：
 *   - 热路径 `fw_stat_account()` 只写本 CPU 的 fw_stats_pcpu，无锁、无共享
 *     cache line 写。旧实现用全局 atomic64 递增直方图与分布，是多通路并发下
 *     每包 6/10 次共享写的来源。
 *   - 读侧（procfs 的 stats 与 5 个分析条目、netlink 的 STATS_QUERY /
 *     ANALYSIS_QUERY）一律先 `fw_stats_flush_all()`，消除旧实现
 *     `stats_show` 不刷新导致的陈旧读数（契约 defect PROC_STATS_STALE_NO_FLUSH）。
 *   - UDP 端口 / ICMP 类型分布需要「窗口内累计」语义，故 per-CPU 槽在 flush
 *     时并入全局哈希表（读侧才能给出全量分布），槽位随之清零。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/sort.h>

#include "fw_stats.h"
#include "fw_rate.h"

static struct fw_stats_pcpu __percpu *stats_pcpu;

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

int fw_stats_init(void) {
  stats_pcpu = alloc_percpu(struct fw_stats_pcpu);
  if (!stats_pcpu)
    return -ENOMEM;

  hash_init(fw_info.udp_port_table);
  spin_lock_init(&fw_info.udp_port_lock);
  atomic_set(&fw_info.udp_port_count, 0);

  hash_init(fw_info.icmp_type_table);
  spin_lock_init(&fw_info.icmp_type_lock);
  atomic_set(&fw_info.icmp_type_count, 0);

  atomic_set(&fw_info.port_scan_detected, 0);

  return 0;
}

static void fw_stats_free_udp_entry_rcu(struct rcu_head *head) {
  kfree(container_of(head, struct fw_udp_port_entry, rcu));
}

static void fw_stats_free_icmp_entry_rcu(struct rcu_head *head) {
  kfree(container_of(head, struct fw_icmp_type_entry, rcu));
}

void fw_stats_exit(void) {
  struct fw_udp_port_entry *ue;
  struct fw_icmp_type_entry *ie;
  struct hlist_node *tmp;
  u32 bkt;

  if (stats_pcpu) {
    free_percpu(stats_pcpu);
    stats_pcpu = NULL;
  }

  spin_lock_bh(&fw_info.udp_port_lock);
  hash_for_each_safe(fw_info.udp_port_table, bkt, tmp, ue, hash) {
    hash_del_rcu(&ue->hash);
    call_rcu(&ue->rcu, fw_stats_free_udp_entry_rcu);
  }
  spin_unlock_bh(&fw_info.udp_port_lock);

  spin_lock_bh(&fw_info.icmp_type_lock);
  hash_for_each_safe(fw_info.icmp_type_table, bkt, tmp, ie, hash) {
    hash_del_rcu(&ie->hash);
    call_rcu(&ie->rcu, fw_stats_free_icmp_entry_rcu);
  }
  spin_unlock_bh(&fw_info.icmp_type_lock);

  hash_init(fw_info.udp_port_table);
  atomic_set(&fw_info.udp_port_count, 0);
  hash_init(fw_info.icmp_type_table);
  atomic_set(&fw_info.icmp_type_count, 0);

  synchronize_rcu();
  rcu_barrier();
}

/* ============================================================================
 * 热路径
 * ==========================================================================*/

struct fw_stats_pcpu *fw_stats_this_cpu(void) {
  return this_cpu_ptr(stats_pcpu);
}

/*
 * UDP 端口 / ICMP 类型用「per-CPU 直接映射槽 + 命中即累加」：
 * 槽按 (端口 / (类型,代码)) 直接索引，冲突时顶替。分析类计数**允许丢**（与速率
 * 计数不同，见 fw_rate.c），槽位被顶替时旧分布不再保留，只记一次
 * rate_slot_spill 观测；因此热路径无锁、无全局去重表查找。
 */
static inline void fw_stat_udp_account(struct fw_stats_pcpu *s, u16 port, u32 bytes) {
  struct fw_udp_cpu_slot *slot = &s->udp[port % FW_UDP_CPU_SLOTS];

  if (READ_ONCE(slot->port) != port || slot->packets == 0) {
    /* 槽位顶替：旧槽位的分布计数丢弃（分析计数允许丢），
		 * 仅递增观测计数。 */
    if (slot->packets)
      fw_stat_bump_rate_spill();
    slot->port = port;
    slot->packets = 1;
    slot->bytes = bytes;
  } else {
    slot->packets++;
    slot->bytes += bytes;
  }
  slot->last_seen = jiffies;
}

static inline void fw_stat_icmp_account(struct fw_stats_pcpu *s, u8 type, u8 code, u32 bytes) {
  struct fw_icmp_cpu_slot *slot = &s->icmp[(type * 31u + code) % FW_ICMP_CPU_SLOTS];

  if (slot->type != type || slot->code != code || slot->packets == 0) {
    if (slot->packets)
      fw_stat_bump_rate_spill();
    slot->type = type;
    slot->code = code;
    slot->packets = 1;
    slot->bytes = bytes;
  } else {
    slot->packets++;
    slot->bytes += bytes;
  }
  slot->last_seen = jiffies;
}

void fw_stat_account(u32 pkt_len, u8 ttl, bool is_fragment, u16 dst_port,
                     bool is_udp, bool is_icmp, u8 icmp_type, u8 icmp_code) {
  struct fw_stats_pcpu *s = this_cpu_ptr(stats_pcpu);

  s->pkt_sizes[fw_pkt_size_bucket(pkt_len)]++;
  s->ttl_dist[fw_ttl_bucket(ttl)]++;
  s->ip_frag_total++;
  if (is_fragment)
    s->ip_frag_count++;

  if (is_udp && dst_port)
    fw_stat_udp_account(s, dst_port, pkt_len);
  else if (is_icmp)
    fw_stat_icmp_account(s, icmp_type, icmp_code, pkt_len);
}

void fw_stat_global_traffic(u32 pkt_len) {
  struct fw_stats_pcpu *s = this_cpu_ptr(stats_pcpu);

  s->global_packets++;
  s->global_bytes += pkt_len;
}

/* ============================================================================
 * 冷路径增量
 * ==========================================================================*/

void fw_stat_inc_bans(void) {
  atomic64_inc(&fw_info.total_bans);
}
void fw_stat_inc_unbans(void) {
  atomic64_inc(&fw_info.total_unbans);
}
void fw_stat_bump_wl_rejects(void) {
  atomic_inc(&fw_info.wl_reject_count);
}
void fw_stat_bump_ban_full(void) {
  atomic64_inc(&fw_info.ban_table_full_rejects);
}
void fw_stat_bump_alloc_fail(void) {
  atomic64_inc(&fw_info.alloc_failures);
}
void fw_stat_add_expired(u32 n) {
  atomic64_add(n, &fw_info.cleanup_expired_total);
}
void fw_stat_bump_rate_spill(void) {
  atomic64_inc(&fw_info.rate_slot_spill);
}

/* ============================================================================
 * flush：把本 CPU 计数并入全局
 * ==========================================================================*/

static void fw_udp_merge(struct fw_udp_cpu_slot *slot) {
  struct fw_udp_port_entry *e;
  u32 bkt;
  bool found = false;
  u16 port = slot->port;

  if (!port || !slot->packets)
    return;

  bkt = hash_min(port, HASH_BITS(fw_info.udp_port_table));
  spin_lock_bh(&fw_info.udp_port_lock);
  hash_for_each_possible(fw_info.udp_port_table, e, hash, port) {
    if (e->port == port) {
      found = true;
      break;
    }
  }
  if (found) {
    atomic64_add(slot->packets, &e->packets);
    atomic64_add(slot->bytes, &e->bytes);
    e->last_seen = slot->last_seen;
    spin_unlock_bh(&fw_info.udp_port_lock);
    return;
  }

  if (atomic_read(&fw_info.udp_port_count) >= MAX_UDP_PORT_ENTRIES) {
    spin_unlock_bh(&fw_info.udp_port_lock);
    fw_stat_bump_rate_spill();
    return;
  }
  e = kzalloc(sizeof(*e), GFP_ATOMIC);
  if (!e) {
    spin_unlock_bh(&fw_info.udp_port_lock);
    fw_stat_bump_alloc_fail();
    return;
  }
  e->port = port;
  atomic64_set(&e->packets, slot->packets);
  atomic64_set(&e->bytes, slot->bytes);
  e->last_seen = slot->last_seen;
  hash_add_rcu(fw_info.udp_port_table, &e->hash, port);
  atomic_inc(&fw_info.udp_port_count);
  spin_unlock_bh(&fw_info.udp_port_lock);
}

static void fw_icmp_merge(struct fw_icmp_cpu_slot *slot) {
  struct fw_icmp_type_entry *e;
  u32 key;
  bool found = false;

  if (!slot->packets)
    return;

  key = (u32)slot->type * 256u + slot->code;
  spin_lock_bh(&fw_info.icmp_type_lock);
  hash_for_each_possible(fw_info.icmp_type_table, e, hash, key) {
    if (e->type == slot->type && e->code == slot->code) {
      found = true;
      break;
    }
  }
  if (found) {
    atomic64_add(slot->packets, &e->packets);
    atomic64_add(slot->bytes, &e->bytes);
    e->last_seen = slot->last_seen;
    spin_unlock_bh(&fw_info.icmp_type_lock);
    return;
  }

  if (atomic_read(&fw_info.icmp_type_count) >= MAX_ICMP_TYPE_ENTRIES) {
    spin_unlock_bh(&fw_info.icmp_type_lock);
    fw_stat_bump_rate_spill();
    return;
  }
  e = kzalloc(sizeof(*e), GFP_ATOMIC);
  if (!e) {
    spin_unlock_bh(&fw_info.icmp_type_lock);
    fw_stat_bump_alloc_fail();
    return;
  }
  e->type = slot->type;
  e->code = slot->code;
  atomic64_set(&e->packets, slot->packets);
  atomic64_set(&e->bytes, slot->bytes);
  e->last_seen = slot->last_seen;
  hash_add_rcu(fw_info.icmp_type_table, &e->hash, key);
  atomic_inc(&fw_info.icmp_type_count);
  spin_unlock_bh(&fw_info.icmp_type_lock);
}

static void fw_stats_flush_local(void *info) {
  struct fw_stats_pcpu *s = this_cpu_ptr(stats_pcpu);
  u32 i;

  (void)info;

  if (s->packets_accepted) {
    atomic64_add(s->packets_accepted, &fw_info.packets_accepted);
    s->packets_accepted = 0;
  }
  if (s->packets_dropped) {
    atomic64_add(s->packets_dropped, &fw_info.packets_dropped);
    s->packets_dropped = 0;
  }
  if (s->tcp_anomaly_dropped) {
    atomic64_add(s->tcp_anomaly_dropped, &fw_info.tcp_anomaly_dropped);
    s->tcp_anomaly_dropped = 0;
  }
  if (s->global_packets) {
    atomic64_add(s->global_packets, &fw_info.global_traffic_packets);
    s->global_packets = 0;
  }
  if (s->global_bytes) {
    atomic64_add(s->global_bytes, &fw_info.global_traffic_bytes);
    s->global_bytes = 0;
  }

  for (i = 0; i < FW_UDP_CPU_SLOTS; i++) {
    if (s->udp[i].packets) {
      fw_udp_merge(&s->udp[i]);
      memset(&s->udp[i], 0, sizeof(s->udp[i]));
    }
  }
  for (i = 0; i < FW_ICMP_CPU_SLOTS; i++) {
    if (s->icmp[i].packets) {
      fw_icmp_merge(&s->icmp[i]);
      memset(&s->icmp[i], 0, sizeof(s->icmp[i]));
    }
  }
}

void fw_stats_flush_all(void) {
  if (!stats_pcpu)
    return;
  /* 同步等待每个 CPU 完成，调用返回后全局计数已包含全部 per-CPU 值 */
  on_each_cpu(fw_stats_flush_local, NULL, 1);
}

/* ============================================================================
 * 读侧：直方图求和
 * ==========================================================================*/

static void fw_stats_sum_histograms(u64 *pkt_sizes, u64 *ttl_dist,
                                    u64 *ip_frag_total, u64 *ip_frag_count) {
  int cpu, i;

  memset(pkt_sizes, 0, sizeof(u64) * FW_PKT_SIZE_BUCKETS);
  memset(ttl_dist, 0, sizeof(u64) * FW_TTL_BUCKETS);
  *ip_frag_total = 0;
  *ip_frag_count = 0;

  for_each_possible_cpu(cpu) {
    struct fw_stats_pcpu *s = per_cpu_ptr(stats_pcpu, cpu);

    for (i = 0; i < FW_PKT_SIZE_BUCKETS; i++)
      pkt_sizes[i] += READ_ONCE(s->pkt_sizes[i]);
    for (i = 0; i < FW_TTL_BUCKETS; i++)
      ttl_dist[i] += READ_ONCE(s->ttl_dist[i]);
    *ip_frag_total += READ_ONCE(s->ip_frag_total);
    *ip_frag_count += READ_ONCE(s->ip_frag_count);
  }
}

static int fw_udp_cmp(const void *a, const void *b) {
  const struct fw_udp_port_row *x = a, *y = b;

  return x->port < y->port ? -1 : (x->port > y->port ? 1 : 0);
}

void fw_stats_snapshot(struct fw_stats_snapshot *out) {
  fw_stats_flush_all();

  memset(out, 0, sizeof(*out));
  out->total_bans = atomic64_read(&fw_info.total_bans);
  out->total_unbans = atomic64_read(&fw_info.total_unbans);
  out->whitelist_rejects = atomic_read(&fw_info.wl_reject_count);
  out->ban_table_full_rejects = atomic64_read(&fw_info.ban_table_full_rejects);
  out->alloc_failures = atomic64_read(&fw_info.alloc_failures);
  out->packets_dropped = atomic64_read(&fw_info.packets_dropped);
  out->packets_accepted = atomic64_read(&fw_info.packets_accepted);
  out->tcp_anomaly_dropped = atomic64_read(&fw_info.tcp_anomaly_dropped);
  out->cleanup_cycles = atomic64_read(&fw_info.cleanup_cycles);
  out->cleanup_expired_total = atomic64_read(&fw_info.cleanup_expired_total);
  out->global_packets = atomic64_read(&fw_info.global_traffic_packets);
  out->global_bytes = atomic64_read(&fw_info.global_traffic_bytes);
}

u64 fw_stats_take_traffic(u64 *bytes) {
  u64 pkts;

  fw_stats_flush_all();
  pkts = atomic64_xchg(&fw_info.global_traffic_packets, 0);
  *bytes = atomic64_xchg(&fw_info.global_traffic_bytes, 0);
  return pkts;
}

void fw_stats_read_analysis(struct fw_analysis_snapshot *out) {
  struct fw_udp_port_entry *ue;
  struct fw_icmp_type_entry *ie;
  u32 bkt, n;
  unsigned long now = jiffies;

  fw_stats_flush_all();

  memset(out, 0, sizeof(*out));
  fw_stats_sum_histograms(
    out->pkt_sizes, out->ttl_dist, &out->ip_frag_total, &out->ip_frag_count);

  /* UDP 端口分布：全量收集后按端口排序，保证输出稳定可比 */
  n = 0;
  rcu_read_lock();
  hash_for_each_rcu(fw_info.udp_port_table, bkt, ue, hash) {
    if (n >= FW_ANALYSIS_UDP_PACK_MAX)
      break;
    out->udp[n].port = ue->port;
    out->udp[n].packets = atomic64_read(&ue->packets);
    out->udp[n].bytes = atomic64_read(&ue->bytes);
    out->udp[n].last_seen_secs = now >= ue->last_seen ? (now - ue->last_seen) / HZ : 0;
    n++;
  }
  rcu_read_unlock();
  sort(out->udp, n, sizeof(out->udp[0]), fw_udp_cmp, NULL);
  out->udp_count = n;
  out->udp_capacity = MAX_UDP_PORT_ENTRIES;

  n = 0;
  rcu_read_lock();
  hash_for_each_rcu(fw_info.icmp_type_table, bkt, ie, hash) {
    if (n >= FW_ANALYSIS_ICMP_PACK_MAX)
      break;
    out->icmp[n].type = ie->type;
    out->icmp[n].code = ie->code;
    out->icmp[n].packets = atomic64_read(&ie->packets);
    out->icmp[n].bytes = atomic64_read(&ie->bytes);
    out->icmp[n].last_seen_secs = now >= ie->last_seen ? (now - ie->last_seen) / HZ : 0;
    n++;
  }
  rcu_read_unlock();
  out->icmp_count = n;
  out->icmp_capacity = MAX_ICMP_TYPE_ENTRIES;

  /* 扫描者 / 探测者来自速率表（fw_rate.c），此处只做组合 */
  out->port_scan_count = atomic_read(&fw_info.port_scan_detected);
  out->port_scan_threshold = PORT_SCAN_THRESHOLD;
  out->service_probe_threshold = SERVICE_PROBE_THRESHOLD;
  fw_rate_read_scanners(out->port_scanners, PORT_SCAN_MAX_RESULTS, out->service_probes,
                        SERVICE_PROBE_MAX_RESULTS, &out->service_probe_count);
}
