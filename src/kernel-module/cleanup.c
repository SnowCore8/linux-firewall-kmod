/*
 * cleanup.c - 过期封禁条目清理 (支持 IPv4/IPv6)
 *
 * 包含清理过期封禁条目和定时器回调相关的函数实现。
 */

#include "firewall.h"

extern unsigned int fw_ban_time;

/* R9-1: 声明 netfilter.c 中的 per-CPU 计数器刷新函数 */
extern void fw_flush_cpu_stats(void);

void free_ban_entry_rcu(struct rcu_head *head) {
  struct ban_entry *entry = container_of(head, struct ban_entry, rcu_head);
  kfree(entry);
}

void free_whitelist_entry_rcu(struct rcu_head *head) {
  struct whitelist_entry *entry = container_of(head, struct whitelist_entry, rcu_head);
  kfree(entry);
}

static int cleanup_table_ipv4(struct firewall_info *fw) {
  struct ban_entry *entry;
  struct hlist_node *tmp;
  unsigned long now = jiffies;
  int removed = 0;
  int processed = 0;
  int max_processed_per_call = 50;
  /* 修复：使用 IPv4 独立的清理进度索引 */
  int start_bucket = READ_ONCE(fw->cleanup_last_bucket_ipv4);
  unsigned int table_size = 1 << BAN_HASH_BITS;

  for (int i = 0; i < (1 << 3) && processed < max_processed_per_call; i++) {
    int current_bucket = (start_bucket + i) % table_size;
    /* R9-4: 使用每桶锁替代全局锁
     * 使用 spin_lock_bh：此函数在定时器回调（softirq 上下文）中执行
     * 禁用 softirq 避免与 netfilter hook 的死锁风险 */
    spin_lock_bh(&fw->ban_locks_ipv4[current_bucket]);
    hlist_for_each_entry_safe(entry, tmp, &fw->ban_table_ipv4[current_bucket], hash) {
      if (processed >= max_processed_per_call)
        break;
      if (READ_ONCE(entry->is_permanent)) {
        processed++;
        continue;
      }
      if (time_after(now, READ_ONCE(entry->unban_time))) {
        /* 先保存 IP 再删除（call_rcu 后另一 CPU 可能立即释放） */
        __be32 expired_ip = entry->addr.ipv4;
        list_del_rcu(&entry->ban_node);
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->ban_count);
        removed++;
        call_rcu(&entry->rcu_head, free_ban_entry_rcu);
        /* 事件推送：通知守护进程移除过期封禁 */
        fw_netlink_send_ban_state_change(FW_AF_INET, &expired_ip, 2, 0, "expired", NULL);
      }
      processed++;
    }
    spin_unlock_bh(&fw->ban_locks_ipv4[current_bucket]);
  }
  return removed;
}

static int cleanup_table_ipv6(struct firewall_info *fw) {
  struct ban_entry *entry;
  struct hlist_node *tmp;
  unsigned long now = jiffies;
  int removed = 0;
  int processed = 0;
  int max_processed_per_call = 50;
  /* 修复：使用 IPv6 独立的清理进度索引 */
  int start_bucket = READ_ONCE(fw->cleanup_last_bucket_ipv6);
  unsigned int table_size = 1 << BAN_HASH_BITS;

  for (int i = 0; i < (1 << 3) && processed < max_processed_per_call; i++) {
    int current_bucket = (start_bucket + i) % table_size;
    /* R9-4: 使用每桶锁替代全局锁
     * 使用 spin_lock_bh：此函数在定时器回调（softirq 上下文）中执行
     * 禁用 softirq 避免与 netfilter hook 的死锁风险 */
    spin_lock_bh(&fw->ban_locks_ipv6[current_bucket]);
    hlist_for_each_entry_safe(entry, tmp, &fw->ban_table_ipv6[current_bucket], hash) {
      if (processed >= max_processed_per_call)
        break;
      if (READ_ONCE(entry->is_permanent)) {
        processed++;
        continue;
      }
      if (time_after(now, READ_ONCE(entry->unban_time))) {
        /* 先保存 IP 再删除（call_rcu 后另一 CPU 可能立即释放） */
        struct in6_addr expired_ip6 = entry->addr.ipv6;
        list_del_rcu(&entry->ban_node);
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->ban_count);
        removed++;
        call_rcu(&entry->rcu_head, free_ban_entry_rcu);
        /* 事件推送：通知守护进程移除过期封禁 */
        fw_netlink_send_ban_state_change(FW_AF_INET6, &expired_ip6, 2, 0, "expired", NULL);
      }
      processed++;
    }
    spin_unlock_bh(&fw->ban_locks_ipv6[current_bucket]);
  }
  return removed;
}

static bool cleanup_expired_bans(struct firewall_info *fw) {
  int removed = 0;

  atomic_inc(&fw->cleanup_cycles);

  /* 注意：fw_flush_cpu_stats() 由调用方 cleanup_timer_callback 负责调用，
   * 此处不再重复刷新，避免在同一个 tick 内对 per-CPU 计数器做两次加锁读取。 */

  if (atomic_read(&fw->ban_count) == 0) {
    /* 修复：分别重置 IPv4 和 IPv6 独立的清理进度索引 */
    WRITE_ONCE(fw->cleanup_last_bucket_ipv4, 0);
    WRITE_ONCE(fw->cleanup_last_bucket_ipv6, 0);
    return false;
  }

  /* R9-4: 清理操作使用每桶锁，无需全局锁 */
  removed += cleanup_table_ipv4(fw);
  removed += cleanup_table_ipv6(fw);

  /* 修复：分别更新 IPv4 和 IPv6 独立的清理进度索引 */
  WRITE_ONCE(fw->cleanup_last_bucket_ipv4,
             (READ_ONCE(fw->cleanup_last_bucket_ipv4) + (1 << 3)) % (1 << BAN_HASH_BITS));
  WRITE_ONCE(fw->cleanup_last_bucket_ipv6,
             (READ_ONCE(fw->cleanup_last_bucket_ipv6) + (1 << 3)) % (1 << BAN_HASH_BITS));

  if (removed > 0) {
    atomic_add(removed, &fw->cleanup_expired_total);
  }

  /* 守护统计不变量(每秒一次,WARN_ON_ONCE 仅警告一次):
   *   total_bans == current_bans + total_unbans + cleanup_expired_total
   *
   * 注意:在多 CPU 高并发场景下,atomic_inc 顺序不同时可能被短暂违反
   * (例如 new insert 路径中,atomic_inc(&ban_count) 与 atomic_inc(&total_ban_count)
   *  是两条独立指令,中断可能落在其间)。为避免误报,采用 ±MAX_IN_FLIGHT 容差,
   * 其中 MAX_IN_FLIGHT 设为 ban_table 容量(4096),远超实际并发窗口。
   * 若 delta 超过该容差,几乎可以确定存在真正的计数漂移 Bug。 */
  {
    int tb = atomic_read(&fw->total_ban_count);
    int cb = atomic_read(&fw->ban_count);
    int tu = atomic_read(&fw->total_unban_count);
    int ce = atomic_read(&fw->cleanup_expired_total);
    int delta = tb - (cb + tu + ce);
    WARN_ON_ONCE(delta > MAX_BAN_ENTRIES || delta < -MAX_BAN_ENTRIES);
  }

  bool has_more = (removed > 0 && atomic_read(&fw->ban_count) > 0);
  return has_more;
}

void cleanup_timer_callback(struct timer_list *t) {
  struct firewall_info *fw = container_of(t, struct firewall_info, cleanup_timer);

  if (unlikely(atomic_read(&fw->shutting_down))) {
    return;
  }

  /* R9-1: 定期刷新 per-CPU 计数器到全局计数器 */
  fw_flush_cpu_stats();

  /* 守护统计不变量(每次定时器触发都检查,无论 ban_count 是否为 0):
   *   total_bans == current_bans + total_unbans + cleanup_expired_total
   * 在 ban_count == 0 的情况下退化为 total_bans == total_unbans + cleanup_expired_total。
   * 同样采用 ±MAX_BAN_ENTRIES 容差避免高并发误报。 */
  {
    int tb = atomic_read(&fw->total_ban_count);
    int cb = atomic_read(&fw->ban_count);
    int tu = atomic_read(&fw->total_unban_count);
    int ce = atomic_read(&fw->cleanup_expired_total);
    int delta = tb - (cb + tu + ce);
    WARN_ON_ONCE(delta > MAX_BAN_ENTRIES || delta < -MAX_BAN_ENTRIES);
  }

  bool has_more_entries = cleanup_expired_bans(fw);

  /* 清理过期的速率条目（DDoS 防护） */
  cleanup_rate_entries(fw);

  if (unlikely(atomic_read(&fw->shutting_down))) {
    return;
  }

  unsigned long cleanup_interval;
  if (has_more_entries) {
    cleanup_interval = HZ;
  } else {
    cleanup_interval = max(HZ * 30UL, ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 4);
  }

  mod_timer(&fw->cleanup_timer, jiffies + cleanup_interval);
}
