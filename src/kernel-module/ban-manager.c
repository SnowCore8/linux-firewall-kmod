/*
 * ban-manager.c - IP 封禁/解封管理 (支持 IPv4/IPv6)
 */

#include "firewall.h"

extern unsigned int fw_ban_time;
extern unsigned int fw_max_bans_per_second;
extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

extern void free_ban_entry_rcu(struct rcu_head *head);

static int __do_ban_ip(struct firewall_info *fw, u8 af, const void *ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg);
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw, u8 af,
                                              const void *ip);
static int __do_unban_ip(struct firewall_info *fw, u8 af, const void *ip,
                         bool permanent_only);

int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds);
int check_flood_protection(void);

/* 辅助：IPv6 哈希值计算 */
static u32 hash_ipv6(const struct in6_addr *addr) {
  return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) &
         ((1 << BAN_HASH_BITS) - 1);
}

static int __do_ban_ip(struct firewall_info *fw, u8 af, const void *ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg) {
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  int bkt;
  char ip_str[INET6_STR_LEN];
  ip_to_str(af, ip, ip_str, sizeof(ip_str));

  if (!ip) {
    fw_pr_err("Invalid IP address for banning: %s", ip_str);
    return -EINVAL;
  }

  entry = kmalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {
    atomic_inc(&fw->alloc_failure_count);
    fw_pr_err("Failed to allocate memory for ban entry for IP %s", ip_str);
    return -ENOMEM;
  }

  /* 白名单检查（在锁外执行，避免持 spinlock 遍历整个 whitelist 表） */
  rcu_read_lock();
  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    hash_for_each_rcu(fw->whitelist_table_ipv6, bkt, wl_entry, hash) {
      u8 prefix = READ_ONCE(wl_entry->mask.prefix_len);
      const struct in6_addr *wl_ip = &wl_entry->addr.ipv6;
      if (ipv6_prefix_equal(ip6, wl_ip, prefix)) {
        rcu_read_unlock();
        kfree(entry);
        atomic_inc(&fw->whitelist_reject_count);
        fw_pr_warn("REFUSED to ban whitelisted IP %s", ip_str);
        return -EPERM;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    hash_for_each_rcu(fw->whitelist_table_ipv4, bkt, wl_entry, hash) {
      __be32 wl_mask = READ_ONCE(wl_entry->mask.ipv4_mask);
      __be32 wl_ip = READ_ONCE(wl_entry->addr.ipv4);
      if ((ipv4 & wl_mask) == (wl_ip & wl_mask)) {
        rcu_read_unlock();
        kfree(entry);
        atomic_inc(&fw->whitelist_reject_count);
        fw_pr_warn("REFUSED to ban whitelisted IP %s", ip_str);
        return -EPERM;
      }
    }
  }
  rcu_read_unlock();

  spin_lock(&fw->lock);

  /* 修复 W2-3：已在 spinlock 保护下，使用 hlist_for_each_entry 替代 RCU 版本，
   * 消除 RCU 嵌套（spinlock + rcu_read_lock）导致的 lockdep 警告。 */
  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    u32 bkt6 = hash_ipv6(ip6);
    struct ban_entry *existing;
    hlist_for_each_entry(existing, &fw->ban_table_ipv6[bkt6], hash) {
      if (existing->af == af && ipv6_addr_equal(&existing->addr.ipv6, ip6)) {
        bool is_perm = READ_ONCE(existing->is_permanent);
        unsigned long ubt = READ_ONCE(existing->unban_time);
        if (is_perm || time_before(jiffies, ubt)) {
          spin_unlock(&fw->lock);
          kfree(entry);
          return 0;
        }
        WRITE_ONCE(existing->ban_time, jiffies);
        WRITE_ONCE(existing->unban_time, unban_time);
        atomic_set(&existing->retry_count, 0);
        spin_unlock(&fw->lock);
        kfree(entry);
        return 0;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    u32 bkt4 = hash_min(ipv4, BAN_HASH_BITS);
    struct ban_entry *existing;
    hlist_for_each_entry(existing, &fw->ban_table_ipv4[bkt4], hash) {
      if (existing->af == af && existing->addr.ipv4 == ipv4) {
        bool is_perm = READ_ONCE(existing->is_permanent);
        unsigned long ubt = READ_ONCE(existing->unban_time);
        if (is_perm || time_before(jiffies, ubt)) {
          spin_unlock(&fw->lock);
          kfree(entry);
          return 0;
        }
        WRITE_ONCE(existing->ban_time, jiffies);
        WRITE_ONCE(existing->unban_time, unban_time);
        atomic_set(&existing->retry_count, 0);
        spin_unlock(&fw->lock);
        kfree(entry);
        return 0;
      }
    }
  }

  if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
    spin_unlock(&fw->lock);
    kfree(entry);
    atomic_inc(&fw->ban_table_full_count);
    fw_pr_warn("Ban table full, cannot ban %s", ip_str);
    return -ENOSPC;
  }

  entry->af = af;
  if (af == FW_AF_INET6)
    entry->addr.ipv6 = *(const struct in6_addr *)ip;
  else
    entry->addr.ipv4 = *(__be32 *)ip;
  entry->ban_time = jiffies;
  entry->unban_time = unban_time;
  entry->is_permanent = is_permanent;
  atomic_set(&entry->retry_count, 0);

  if (af == FW_AF_INET6) {
    u32 bkt6 = hash_ipv6((struct in6_addr *)ip);
    hash_add_rcu(fw->ban_table_ipv6, &entry->hash, bkt6);
  } else {
    hash_add_rcu(fw->ban_table_ipv4, &entry->hash, *(__be32 *)ip);
  }
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);

  spin_unlock(&fw->lock);

  if (log_msg && log_arg)
    fw_pr_info_ratelimited("%s %s %lu", log_msg, ip_str, log_arg);
  else if (log_msg)
    fw_pr_info_ratelimited("%s %s", log_msg, ip_str);

  return 0;
}

static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw, u8 af,
                                              const void *ip) {
  struct ban_entry *entry;

  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    u32 bkt = hash_ipv6(ip6);
    hlist_for_each_entry_rcu(entry, &fw->ban_table_ipv6[bkt], hash) {
      if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, ip6))
        return entry;
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    u32 bkt = hash_min(ipv4, BAN_HASH_BITS);
    hlist_for_each_entry_rcu(entry, &fw->ban_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->addr.ipv4 == ipv4)
        return entry;
    }
  }
  return NULL;
}

static int __do_unban_ip(struct firewall_info *fw, u8 af, const void *ip,
                         bool permanent_only) {
  struct ban_entry *entry;
  int found = 0;
  char ip_str[INET6_STR_LEN];
  ip_to_str(af, ip, ip_str, sizeof(ip_str));

  spin_lock(&fw->lock);
  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    u32 bkt = hash_ipv6(ip6);
    hlist_for_each_entry(entry, &fw->ban_table_ipv6[bkt], hash) {
      if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, ip6)) {
        if (!permanent_only || READ_ONCE(entry->is_permanent)) {
          hlist_del_rcu(&entry->hash);
          atomic_dec(&fw->ban_count);
          found = 1;
          call_rcu(&entry->rcu_head, free_ban_entry_rcu);
        }
        break;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    u32 bkt = hash_min(ipv4, BAN_HASH_BITS);
    hlist_for_each_entry(entry, &fw->ban_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->addr.ipv4 == ipv4) {
        if (!permanent_only || READ_ONCE(entry->is_permanent)) {
          hlist_del_rcu(&entry->hash);
          atomic_dec(&fw->ban_count);
          found = 1;
          call_rcu(&entry->rcu_head, free_ban_entry_rcu);
        }
        break;
      }
    }
  }
  spin_unlock(&fw->lock);

  if (found) {
    atomic_inc(&fw->total_unban_count);
    if (permanent_only)
      fw_pr_info("IP %s permanently unbanned", ip_str);
    else
      fw_pr_info_ratelimited("IP %s unbanned", ip_str);
    return 0;
  }
  return -ENOENT;
}

int unban_ip(struct firewall_info *fw, u8 af, const void *ip) {
  FW_DEBUG(1, "ENTRY: unban_ip(af=%d)", af);
  int ret = __do_unban_ip(fw, af, ip, false);
  FW_DEBUG(1, "EXIT: unban_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(unban_ip);

int unban_permanent_ip(struct firewall_info *fw, u8 af, const void *ip) {
  FW_DEBUG(1, "ENTRY: unban_permanent_ip(af=%d)", af);
  int ret = __do_unban_ip(fw, af, ip, true);
  if (ret == -ENOENT)
    fw_pr_warn("IP not found in permanent ban list");
  FW_DEBUG(1, "EXIT: unban_permanent_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(unban_permanent_ip);

int is_banned(struct firewall_info *fw, u8 af, const void *ip) {
  struct ban_entry *entry;
  unsigned long now = jiffies;
  int found = 0;

  FW_DEBUG(3, "Checking if IP (af=%d) is banned", af);
  rcu_read_lock();
  entry = __find_ban_entry_rcu(fw, af, ip);
  if (entry) {
    if (READ_ONCE(entry->is_permanent)) {
      found = 1;
    } else if (time_after(now, READ_ONCE(entry->unban_time))) {
      found = 0;
    } else {
      found = 1;
    }
  }
  rcu_read_unlock();
  FW_DEBUG(3, "Result for IP (af=%d) ban check: %s", af,
           found ? "BANNED" : "NOT BANNED");
  return found;
}
EXPORT_SYMBOL_GPL(is_banned);

int ban_ip(struct firewall_info *fw, u8 af, const void *ip) {
  unsigned long ban_secs = READ_ONCE(fw_ban_time);
  unsigned long ban_duration;
  FW_DEBUG(1, "ENTRY: ban_ip(af=%d)", af);
  if (check_mul_overflow(ban_secs, (unsigned long)HZ, &ban_duration)) {
    fw_pr_err("ban_time overflow detected");
    return -EINVAL;
  }
  FW_DEBUG(2, "Attempting to ban IP (af=%d)", af);
  int ret = __do_ban_ip(fw, af, ip, jiffies + ban_duration, false,
                        "banned for %u seconds", ban_secs);
  FW_DEBUG(1, "EXIT: ban_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip);

int ban_ip_permanent(struct firewall_info *fw, u8 af, const void *ip) {
  FW_DEBUG(1, "ENTRY: ban_ip_permanent(af=%d)", af);
  FW_DEBUG(2, "Attempting to permanently ban IP (af=%d)", af);
  int ret = __do_ban_ip(fw, af, ip, 0, true, "permanently banned", 0);
  FW_DEBUG(1, "EXIT: ban_ip_permanent -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip_permanent);

int is_permanently_banned(struct firewall_info *fw, u8 af, const void *ip) {
  struct ban_entry *entry;
  int found = 0;
  FW_DEBUG(3, "Checking if IP (af=%d) is permanently banned", af);
  rcu_read_lock();
  entry = __find_ban_entry_rcu(fw, af, ip);
  if (entry && READ_ONCE(entry->is_permanent))
    found = 1;
  rcu_read_unlock();
  FW_DEBUG(3, "Result for IP (af=%d) permanent ban check: %s", af,
           found ? "PERMANENTLY BANNED" : "NOT PERMANENTLY BANNED");
  return found;
}
EXPORT_SYMBOL_GPL(is_permanently_banned);

int check_flood_protection(void) {
  unsigned long now = jiffies;
  unsigned long one_second = HZ;
  unsigned int max_bans;
  spin_lock(&fw_info.flood_lock);
  if (time_after(now, fw_info.last_flood_check + one_second)) {
    fw_info.recent_additions = 1;
    fw_info.last_flood_check = now;
  } else {
    fw_info.recent_additions++;
    max_bans = READ_ONCE(fw_max_bans_per_second);
    if (fw_info.recent_additions > max_bans) {
      spin_unlock(&fw_info.flood_lock);
      return -EBUSY;
    }
  }
  spin_unlock(&fw_info.flood_lock);
  return 0;
}

int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds) {
  unsigned long ban_duration;
  FW_DEBUG(1, "ENTRY: ban_ip_with_duration(af=%d, seconds=%lu)", af, seconds);
  if (!ip) {
    fw_pr_err("Invalid IP address for banning");
    return -EINVAL;
  }
  if (seconds == 0) {
    fw_pr_err("Invalid ban duration: 0 seconds");
    return -EINVAL;
  }
  if (check_mul_overflow(seconds, (unsigned long)HZ, &ban_duration)) {
    fw_pr_err("ban duration overflow");
    return -EINVAL;
  }
  FW_DEBUG(2, "Attempting to ban IP (af=%d) for %lu seconds", af, seconds);
  int ret = __do_ban_ip(fw, af, ip, jiffies + ban_duration, false,
                        "banned for %lu seconds", seconds);
  FW_DEBUG(1, "EXIT: ban_ip_with_duration -> %d", ret);
  return ret;
}
