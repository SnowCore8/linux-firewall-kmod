/*
 * cleanup.c - 过期封禁条目清理
 *
 * 包含清理过期封禁条目和定时器回调相关的函数实现。
 */

#include "firewall.h"

/* 外部变量声明 */
extern unsigned int fw_ban_time;

/*
 * free_ban_entry_rcu - RCU 回调释放封禁条目
 */
void free_ban_entry_rcu(struct rcu_head *head) {
  struct ban_entry *entry = container_of(head, struct ban_entry, rcu_head);
  FW_DEBUG(3, "Freeing ban entry via RCU callback");
  kfree(entry);
}

/*
 * free_whitelist_entry_rcu - RCU 回调释放白名单条目
 */
void free_whitelist_entry_rcu(struct rcu_head *head) {
  struct whitelist_entry *entry =
      container_of(head, struct whitelist_entry, rcu_head);
  FW_DEBUG(3, "Freeing whitelist entry via RCU callback");
  kfree(entry);
}

/*
 * cleanup_expired_bans - 移除过期的封禁条目
 */
static bool cleanup_expired_bans(struct firewall_info *fw) {
  struct ban_entry *entry;
  struct hlist_node *tmp;
  unsigned long now = jiffies;
  int removed = 0;
  int processed = 0;
  int max_processed_per_call = 50;
  int start_bucket = fw->cleanup_last_bucket;

  FW_DEBUG(2, "ENTRY: cleanup_expired_bans(current_count=%d, start_bucket=%d)",
           atomic_read(&fw->ban_count), start_bucket);

  atomic_inc(&fw->cleanup_cycles);

  if (atomic_read(&fw->ban_count) == 0) {
    fw->cleanup_last_bucket = 0;
    FW_DEBUG(3, "No entries to clean, exiting early");
    FW_DEBUG(2, "EXIT: cleanup_expired_bans -> false (no entries)");
    return false;
  }

  spin_lock(&fw->lock);

  if (atomic_read(&fw->ban_count) == 0) {
    spin_unlock(&fw->lock);
    fw->cleanup_last_bucket = 0;
    FW_DEBUG(3, "No entries to clean after lock acquired, exiting early");
    FW_DEBUG(2, "EXIT: cleanup_expired_bans -> false (no entries after lock)");
    return false;
  }

  unsigned int ban_table_size = 1 << BAN_HASH_BITS;

  for (int i = 0; i < (1 << 3) && processed < max_processed_per_call; i++) {
    int current_bucket = (start_bucket + i) % ban_table_size;

    hlist_for_each_entry_safe(entry, tmp, &fw->ban_table[current_bucket],
                              hash) {
      if (processed >= max_processed_per_call) {
        break;
      }

      if (READ_ONCE(entry->is_permanent)) {
        processed++;
        continue;
      }

      if (time_after(now, READ_ONCE(entry->unban_time))) {
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->ban_count);
        removed++;
        call_rcu(&entry->rcu_head, free_ban_entry_rcu);
        FW_DEBUG(2, "Removed expired ban entry");
      }
      processed++;
    }
  }

  fw->cleanup_last_bucket = (start_bucket + (1 << 3)) % ban_table_size;

  spin_unlock(&fw->lock);

  if (removed > 0) {
    atomic_add(removed, &fw->cleanup_expired_total);
    FW_DEBUG(1, "Cleaned up %d expired ban entries", removed);
    fw_pr_info_ratelimited("Cleaned up %d expired ban entries", removed);
  } else {
    FW_DEBUG(3, "No expired entries found during cleanup");
  }

  bool has_more_entries = (removed > 0 && atomic_read(&fw->ban_count) > 0);
  if (has_more_entries) {
    FW_DEBUG(2, "Entries remain after cleanup, timer callback will use shorter "
                "interval");
  } else {
    FW_DEBUG(3, "No more entries to clean, using standard timer interval");
  }

  FW_DEBUG(2, "EXIT: cleanup_expired_bans -> %s (removed=%d, processed=%d)",
           has_more_entries ? "true" : "false", removed, processed);
  return has_more_entries;
}

/*
 * cleanup_timer_callback - 定期清理的定时器回调
 */
void cleanup_timer_callback(struct timer_list *t) {
  struct firewall_info *fw =
      container_of(t, struct firewall_info, cleanup_timer);

  FW_DEBUG(3, "ENTRY: cleanup_timer_callback");

  if (unlikely(atomic_read(&fw->shutting_down))) {
    FW_DEBUG(2, "EXIT: cleanup_timer_callback -> void (shutting down)");
    return;
  }

  bool has_more_entries = cleanup_expired_bans(fw);

  if (unlikely(atomic_read(&fw->shutting_down))) {
    FW_DEBUG(
        2,
        "EXIT: cleanup_timer_callback -> void (shutting down after cleanup)");
    return;
  }

  unsigned long cleanup_interval;
  if (has_more_entries) {
    cleanup_interval = HZ;
    FW_DEBUG(3, "More entries to clean, using short interval (1s)");
  } else {
    cleanup_interval =
        max(HZ * 30UL, ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 4);
    FW_DEBUG(3, "No more entries, using standard interval (%lu jiffies)",
             cleanup_interval);
  }

  mod_timer(&fw->cleanup_timer, jiffies + cleanup_interval);

  FW_DEBUG(3, "EXIT: cleanup_timer_callback -> void (timer re-armed)");
}
