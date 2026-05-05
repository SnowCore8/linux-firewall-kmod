/*
 * ban-manager.c - IP 封禁/解封管理
 *
 * 包含所有封禁、解封、查询封禁状态相关的函数实现。
 */

#include "firewall.h"

/* 外部变量声明 */
extern unsigned int fw_ban_time;
extern unsigned int fw_max_bans_per_second;
extern struct firewall_info fw_info;

/* 来自 cleanup.c 的 RCU 回调函数 */
extern void free_ban_entry_rcu(struct rcu_head *head);

/* 内部辅助函数前向声明 */
static int __do_ban_ip(struct firewall_info *fw, __be32 ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg);
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw,
                                              __be32 ip);
static int __do_unban_ip(struct firewall_info *fw, __be32 ip,
                         bool permanent_only);

/* 导出函数声明 */
int ban_ip_with_duration(struct firewall_info *fw, __be32 ip,
                         unsigned long seconds);
int check_flood_protection(void);

/*
 * __do_ban_ip - 内部统一封禁函数
 */
static int __do_ban_ip(struct firewall_info *fw, __be32 ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg) {
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  u32 hash;
  int bkt;

  if (!ip) {
    fw_pr_err("Invalid IP address for banning: %pI4", &ip);
    return -EINVAL;
  }

  /* 在锁外预分配内存，避免在持锁时分配 */
  entry = kmalloc(sizeof(*entry), GFP_KERNEL);
  if (!entry) {
    atomic_inc(&fw->alloc_failure_count);
    fw_pr_err("Failed to allocate memory for ban entry for IP %pI4", &ip);
    return -ENOMEM;
  }

  spin_lock(&fw->lock);

  /* 白名单检查必须在锁内执行，防止 UAF 竞态条件：
   * 在 RCU 读锁外检查白名单后，条目可能被其他 CPU 释放，
   * 导致后续操作基于已释放的数据做出错误决策。
   * 使用 RCU 读锁保护白名单遍历，确保数据一致性。 */
  rcu_read_lock();
  hash_for_each_rcu(fw->whitelist_table, bkt, wl_entry, hash) {
    /* 使用 READ_ONCE() 防止 RCU 读端与写端并发时的撕裂读 */
    __be32 wl_mask = READ_ONCE(wl_entry->mask);
    __be32 wl_ip = READ_ONCE(wl_entry->ip);
    if ((ip & wl_mask) == (wl_ip & wl_mask)) {
      rcu_read_unlock();
      spin_unlock(&fw->lock);
      kfree(entry);
      atomic_inc(&fw->whitelist_reject_count);
      fw_pr_warn("REFUSED to ban whitelisted IP %pI4", &ip);
      return -EPERM;
    }
  }
  rcu_read_unlock();

  /* 检查是否已被封禁 */
  hash = hash_min(ip, BAN_HASH_BITS);
  struct ban_entry *existing;
  hash_for_each_possible(fw->ban_table, existing, hash, ip) {
    if (compare_ips(existing->ip, ip)) {
      /* 使用 READ_ONCE() 与写入端的 WRITE_ONCE() 配对，防止撕裂读 */
      bool is_permanent = READ_ONCE(existing->is_permanent);
      unsigned long unban_time_val = READ_ONCE(existing->unban_time);
      if (is_permanent || time_before(jiffies, unban_time_val)) {
        spin_unlock(&fw->lock);
        kfree(entry);
        return 0;
      } else {
        WRITE_ONCE(existing->ban_time, jiffies);
        WRITE_ONCE(existing->unban_time, unban_time);
        WRITE_ONCE(existing->is_permanent, is_permanent);
        atomic_set(&existing->retry_count, 0);
        spin_unlock(&fw->lock);
        kfree(entry);
        return 0;
      }
    }
  }

  /* 检查封禁表容量 */
  if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
    spin_unlock(&fw->lock);
    kfree(entry);
    atomic_inc(&fw->ban_table_full_count);
    fw_pr_warn("Ban table full, cannot ban %pI4", &ip);
    return -ENOSPC;
  }

  /* 初始化并插入新条目 */
  entry->ip = ip;
  entry->ban_time = jiffies;
  entry->unban_time = unban_time;
  entry->is_permanent = is_permanent;
  atomic_set(&entry->retry_count, 0);

  hash_add_rcu(fw->ban_table, &entry->hash, ip);
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);

  spin_unlock(&fw->lock);

  if (log_msg && log_arg)
    fw_pr_info_ratelimited("%pI4 %s %lu", &ip, log_msg, log_arg);
  else if (log_msg)
    fw_pr_info_ratelimited("%pI4 %s", &ip, log_msg);

  return 0;
}

/*
 * __find_ban_entry_rcu - 使用 RCU 查找封禁条目
 */
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw,
                                              __be32 ip) {
  struct ban_entry *entry;
  u32 hash __maybe_unused = hash_min(ip, BAN_HASH_BITS);

  hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip) {
    if (compare_ips(entry->ip, ip))
      return entry;
  }
  return NULL;
}

/*
 * __do_unban_ip - 内部统一解封函数
 */
static int __do_unban_ip(struct firewall_info *fw, __be32 ip,
                         bool permanent_only) {
  struct ban_entry *entry;
  int found = 0;
  char ip_str[INET_ADDRSTRLEN];
  u32 hash;

  ipv4_to_str(ip, ip_str, sizeof(ip_str));

  spin_lock(&fw->lock);
  hash = hash_min(ip, BAN_HASH_BITS);
  hash_for_each_possible(fw->ban_table, entry, hash, ip) {
    if (compare_ips(entry->ip, ip)) {
      /* 使用 READ_ONCE() 与写入端的 WRITE_ONCE() 配对 */
      if (!permanent_only || READ_ONCE(entry->is_permanent)) {
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->ban_count);
        found = 1;
        call_rcu(&entry->rcu_head, free_ban_entry_rcu);
      }
      break;
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

/*
 * unban_ip - 从封禁列表中移除 IPv4
 */
int unban_ip(struct firewall_info *fw, __be32 ip) {
  FW_DEBUG(1, "ENTRY: unban_ip(ip=%pI4)", &ip);
  int ret = __do_unban_ip(fw, ip, false);
  FW_DEBUG(1, "EXIT: unban_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(unban_ip);

/*
 * unban_permanent_ip - 移除永久封禁条目
 */
int unban_permanent_ip(struct firewall_info *fw, __be32 ip) {
  FW_DEBUG(1, "ENTRY: unban_permanent_ip(ip=%pI4)", &ip);
  int ret = __do_unban_ip(fw, ip, true);
  if (ret == -ENOENT)
    fw_pr_warn("IP 未在永久封禁列表中找到");
  FW_DEBUG(1, "EXIT: unban_permanent_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(unban_permanent_ip);

/*
 * is_banned - 检查 IPv4 是否被封禁
 */
int is_banned(struct firewall_info *fw, __be32 ip) {
  struct ban_entry *entry;
  unsigned long now = jiffies;
  int found = 0;

  FW_DEBUG(3, "Checking if IPv4 %pI4 is banned", &ip);

  rcu_read_lock();
  entry = __find_ban_entry_rcu(fw, ip);
  if (entry) {
    if (READ_ONCE(entry->is_permanent)) {
      FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
      found = 1;
    } else if (time_after(now, READ_ONCE(entry->unban_time))) {
      FW_DEBUG(2, "Found expired ban entry for IPv4 %pI4", &ip);
      found = 0;
    } else {
      FW_DEBUG(2, "Found active ban entry for IPv4 %pI4", &ip);
      found = 1;
    }
  }
  rcu_read_unlock();

  FW_DEBUG(3, "Result for IPv4 %pI4 ban check: %s", &ip,
           found ? "BANNED" : "NOT BANNED");
  return found;
}
EXPORT_SYMBOL_GPL(is_banned);

/*
 * ban_ip - 将 IPv4 添加到封禁列表，使用默认持续时间
 */
int ban_ip(struct firewall_info *fw, __be32 ip) {
  unsigned long ban_secs = READ_ONCE(fw_ban_time);
  unsigned long ban_duration;

  FW_DEBUG(1, "ENTRY: ban_ip(ip=%pI4)", &ip);

  if (check_mul_overflow(ban_secs, (unsigned long)HZ, &ban_duration)) {
    fw_pr_err("ban_time overflow detected");
    return -EINVAL;
  }

  FW_DEBUG(2, "Attempting to ban IPv4: %pI4", &ip);
  int ret = __do_ban_ip(fw, ip, jiffies + ban_duration, false,
                        "banned for %u seconds", ban_secs);
  FW_DEBUG(1, "EXIT: ban_ip -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip);

/*
 * ban_ip_permanent - 将 IPv4 添加到永久封禁列表
 */
int ban_ip_permanent(struct firewall_info *fw, __be32 ip) {
  FW_DEBUG(1, "ENTRY: ban_ip_permanent(ip=%pI4)", &ip);
  FW_DEBUG(2, "Attempting to permanently ban IPv4: %pI4", &ip);

  int ret = __do_ban_ip(fw, ip, 0, true, "permanently banned", 0);
  FW_DEBUG(1, "EXIT: ban_ip_permanent -> %d", ret);
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip_permanent);

/*
 * is_permanently_banned - 检查 IPv4 是否被永久封禁
 */
int is_permanently_banned(struct firewall_info *fw, __be32 ip) {
  struct ban_entry *entry;
  int found = 0;

  FW_DEBUG(3, "Checking if IPv4 %pI4 is permanently banned", &ip);

  rcu_read_lock();
  entry = __find_ban_entry_rcu(fw, ip);
  if (entry && READ_ONCE(entry->is_permanent)) {
    FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
    found = 1;
  }
  rcu_read_unlock();

  FW_DEBUG(3, "Result for IPv4 %pI4 permanent ban check: %s", &ip,
           found ? "PERMANENTLY BANNED" : "NOT PERMANENTLY BANNED");
  return found;
}
EXPORT_SYMBOL_GPL(is_permanently_banned);

/*
 * check_flood_protection - 检查添加此条目是否会超过泛洪限制
 */
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

/*
 * ban_ip_with_duration - 使用自定义持续时间封禁 IP
 */
int ban_ip_with_duration(struct firewall_info *fw, __be32 ip,
                         unsigned long seconds) {
  unsigned long ban_duration;

  FW_DEBUG(1, "ENTRY: ban_ip_with_duration(ip=%pI4, seconds=%lu)", &ip,
           seconds);

  if (!ip) {
    fw_pr_err("Invalid IP address for banning: %pI4", &ip);
    FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (invalid IP)");
    return -EINVAL;
  }

  if (seconds == 0) {
    fw_pr_err("Invalid ban duration: 0 seconds");
    FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (zero duration)");
    return -EINVAL;
  }

  if (check_mul_overflow(seconds, (unsigned long)HZ, &ban_duration)) {
    fw_pr_err("ban duration overflow for IP %pI4", &ip);
    FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (overflow)");
    return -EINVAL;
  }

  FW_DEBUG(2, "Attempting to ban IPv4 %pI4 for %lu seconds", &ip, seconds);

  int ret = __do_ban_ip(fw, ip, jiffies + ban_duration, false,
                        "banned for %lu seconds", seconds);
  FW_DEBUG(1, "EXIT: ban_ip_with_duration -> %d", ret);
  return ret;
}
