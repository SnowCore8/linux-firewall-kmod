/*
 * ban-manager.c - IP 封禁/解封管理 (支持 IPv4/IPv6)
 *
 * M1 修复：锁顺序文档
 * - 全局锁 (fw->lock): 用于保护白名单检查和容量检查
 * - 每桶锁 (fw->ban_locks_ipv4/ipv6[bkt]): 用于保护封禁表操作
 * 锁顺序规则：
 * 1. 全局锁和每桶锁不能嵌套持有（必须先释放全局锁再获取每桶锁）
 * 2. 不同桶的锁可以并发获取（无顺序要求）
 * 3. RCU 读锁 (rcu_read_lock) 可以与任何锁嵌套（不会阻塞）
 */

#include "firewall.h"

extern unsigned int fw_ban_time;
extern unsigned int fw_max_bans_per_second;
extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

extern void free_ban_entry_rcu(struct rcu_head *head);

/* 白名单二次检查：在每桶锁保护下验证 IP 是否被加入白名单
 *
 * 为什么需要二次检查：
 * 全局锁下的白名单检查与封禁表插入之间存在时间窗口，
 * 在此期间 IP 可能被加入白名单。二次检查确保不会封禁白名单 IP。
 */
static inline int __recheck_whitelist_ipv6(struct firewall_info *fw,
                                           const struct in6_addr *ip6);
static inline int __recheck_whitelist_ipv4(struct firewall_info *fw, __be32 ipv4);

static inline int __recheck_whitelist_ipv6(struct firewall_info *fw,
                                           const struct in6_addr *ip6) {
  int bkt;
  struct whitelist_entry *wl_entry;

  hash_for_each_rcu(fw->whitelist_table_ipv6, bkt, wl_entry, hash) {
    u8 prefix = READ_ONCE(wl_entry->mask.prefix_len);
    const struct in6_addr *wl_ip = &wl_entry->addr.ipv6;
    if (ipv6_prefix_equal(ip6, wl_ip, prefix))
      return -EPERM;
  }
  return 0;
}

static inline int __recheck_whitelist_ipv4(struct firewall_info *fw, __be32 ipv4) {
  int bkt;
  struct whitelist_entry *wl_entry;

  hash_for_each_rcu(fw->whitelist_table_ipv4, bkt, wl_entry, hash) {
    __be32 wl_mask = READ_ONCE(wl_entry->mask.ipv4_mask);
    __be32 wl_ip = READ_ONCE(wl_entry->addr.ipv4);
    if ((ipv4 & wl_mask) == (wl_ip & wl_mask))
      return -EPERM;
  }
  return 0;
}

/* __do_ban_ip - 封禁 IP 的核心实现
 *
 * 采用两阶段锁策略：
 *   阶段 1（全局锁）：白名单检查 + 容量检查
 *     - 快速失败：如果 IP 在白名单或表已满，立即返回
 *   阶段 2（每桶锁）：封禁表插入
 *     - 细粒度锁：不同桶的插入操作可并行
 *     - 二次白名单检查：防止阶段 1 到阶段 2 之间白名单状态变化
 *
 * 为什么不在全局锁下直接插入：
 * 全局锁是所有封禁/解封操作的瓶颈，将其限制在检查阶段，
 * 让插入阶段使用每桶锁，可大幅提升并发性能。
 */
static int __do_ban_ip(struct firewall_info *fw, u8 af, const void *ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg);
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw, u8 af,
                                              const void *ip);
static int __do_unban_ip(struct firewall_info *fw, u8 af, const void *ip, bool permanent_only);

int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds);
int check_flood_protection(void);

/* 计算 IPv6 地址在封禁表中的哈希桶索引
 *
 * 使用 jhash 确保地址分布均匀，减少哈希冲突。
 * fw_hash_seed 在模块初始化时随机生成，防止攻击者构造哈希碰撞。
 */
static u32 hash_ipv6(const struct in6_addr *addr) {
  return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) & ((1 << BAN_HASH_BITS) - 1);
}

/* __do_ban_ip_ipv6 - 将 IPv6 地址插入封禁表
 *
 * 在每桶锁保护下执行，不同桶的插入操作可并行。
 * 执行流程：
 *   1. 二次白名单检查（防 TOCTTOU）
 *   2. 查找是否已有封禁条目：
 *      - 永久封禁或未过期：返回 -EEXIST（无变化，不计入任何统计）
 *      - 已过期：刷新时间戳（仅续期，不计入任何统计）
 *   3. 新条目：初始化、插入哈希表，同时计入 ban_count 和 total_ban_count
 *
 * 返回值约定：
 *   0      - 成功执行了实际变更（新插入）
 *   -EEXIST - 条目已存在（永久/未过期或刷新过期条目），无变化、无统计影响
 *   -EPERM  - 白名单 recheck 拒绝（已计入 whitelist_reject_count）
 *
 * 统计不变量（任一时刻都应成立）:
 *   total_bans == current_bans + total_unbans + cleanup_expired_total
 */
static int __do_ban_ip_ipv6(struct firewall_info *fw,
                            const struct in6_addr *ip6, struct ban_entry *entry,
                            unsigned long unban_time, bool is_permanent) {
  u32 bkt6 = hash_ipv6(ip6);
  struct ban_entry *existing;

  spin_lock(&fw->ban_locks_ipv6[bkt6]);

  rcu_read_lock();
  int ret = __recheck_whitelist_ipv6(fw, ip6);
  rcu_read_unlock();
  if (ret == -EPERM) {
    spin_unlock(&fw->ban_locks_ipv6[bkt6]);
    kfree(entry);
    atomic_inc(&fw->whitelist_reject_count);
    return ret;
  }

  hlist_for_each_entry(existing, &fw->ban_table_ipv6[bkt6], hash) {
    if (existing->af == FW_AF_INET6 && ipv6_addr_equal(&existing->addr.ipv6, ip6)) {
      bool is_perm = READ_ONCE(existing->is_permanent);
      unsigned long ubt = READ_ONCE(existing->unban_time);
      if (is_perm || time_before(jiffies, ubt)) {
        spin_unlock(&fw->ban_locks_ipv6[bkt6]);
        kfree(entry);
        return -EEXIST;
      }
      WRITE_ONCE(existing->ban_time, jiffies);
      WRITE_ONCE(existing->unban_time, unban_time);
      atomic_set(&existing->retry_count, 0);
      spin_unlock(&fw->ban_locks_ipv6[bkt6]);
      kfree(entry);
      /* 刷新已过期条目：条目仍在表中，仅续期，不计入任何统计计数器。
       * 这样保证不变量: total_bans == current_bans + total_unbans + cleanup_expired_total */
      return 0;
    }
  }

  entry->af = FW_AF_INET6;
  entry->addr.ipv6 = *ip6;
  entry->ban_time = jiffies;
  entry->unban_time = unban_time;
  entry->is_permanent = is_permanent;
  atomic_set(&entry->retry_count, 0);
  /* 修复：直接用桶索引 hlist_add_head_rcu，避免 hash_add_rcu 以 bkt6 为 key
   * 重新 hash_min 落到错误桶(会导致重复检查失效、产生重复条目)。
   * IPv4 路径不受影响(其 key=ipv4,hash_min(ipv4,...) 与 bkt4 巧合一致)。*/
  hlist_add_head_rcu(&entry->hash, &fw->ban_table_ipv6[bkt6]);
  spin_unlock(&fw->ban_locks_ipv6[bkt6]);
  /* 新插入：同时增加表内计数与累计操作次数 */
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);
  return 0;
}

/* __do_ban_ip_ipv4 - 将 IPv4 地址插入封禁表
 *
 * 逻辑与 __do_ban_ip_ipv6 相同，仅地址族和哈希计算不同。
 * 使用 hash_min 替代 jhash，因为 IPv4 地址本身就是 32 位哈希值。
 *
 * 返回值约定：
 *   0      - 成功执行了实际变更（新插入）
 *   -EEXIST - 条目已存在（永久/未过期或刷新过期条目），无变化、无统计影响
 *   -EPERM  - 白名单 recheck 拒绝（已计入 whitelist_reject_count）
 *
 * 统计不变量（任一时刻都应成立）:
 *   total_bans == current_bans + total_unbans + cleanup_expired_total
 */
static int __do_ban_ip_ipv4(struct firewall_info *fw, __be32 ipv4, struct ban_entry *entry,
                            unsigned long unban_time, bool is_permanent) {
  u32 bkt4 = hash_min(ipv4, BAN_HASH_BITS);
  struct ban_entry *existing;

  spin_lock(&fw->ban_locks_ipv4[bkt4]);

  rcu_read_lock();
  int ret = __recheck_whitelist_ipv4(fw, ipv4);
  rcu_read_unlock();
  if (ret == -EPERM) {
    spin_unlock(&fw->ban_locks_ipv4[bkt4]);
    kfree(entry);
    atomic_inc(&fw->whitelist_reject_count);
    return ret;
  }

  hlist_for_each_entry(existing, &fw->ban_table_ipv4[bkt4], hash) {
    if (existing->af == FW_AF_INET && existing->addr.ipv4 == ipv4) {
      bool is_perm = READ_ONCE(existing->is_permanent);
      unsigned long ubt = READ_ONCE(existing->unban_time);
      if (is_perm || time_before(jiffies, ubt)) {
        spin_unlock(&fw->ban_locks_ipv4[bkt4]);
        kfree(entry);
        return -EEXIST;
      }
      WRITE_ONCE(existing->ban_time, jiffies);
      WRITE_ONCE(existing->unban_time, unban_time);
      atomic_set(&existing->retry_count, 0);
      spin_unlock(&fw->ban_locks_ipv4[bkt4]);
      kfree(entry);
      /* 刷新已过期条目：条目仍在表中，仅续期，不计入任何统计计数器。
       * 这样保证不变量: total_bans == current_bans + total_unbans + cleanup_expired_total */
      return 0;
    }
  }

  entry->af = FW_AF_INET;
  entry->addr.ipv4 = ipv4;
  entry->ban_time = jiffies;
  entry->unban_time = unban_time;
  entry->is_permanent = is_permanent;
  atomic_set(&entry->retry_count, 0);
  /* 与 IPv6 路径保持一致:直接用桶索引 hlist_add_head_rcu,
   * 杜绝 hash_add_rcu(key) API 误用导致桶错位。*/
  hlist_add_head_rcu(&entry->hash, &fw->ban_table_ipv4[bkt4]);
  spin_unlock(&fw->ban_locks_ipv4[bkt4]);
  /* 新插入：同时增加表内计数与累计操作次数 */
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);
  return 0;
}

static int __do_ban_ip(struct firewall_info *fw, u8 af, const void *ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg) {
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  int bkt;
  int ret;
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

  /* 阶段 1：全局锁保护下的白名单检查（快速失败） */
  spin_lock(&fw->lock);
  rcu_read_lock();
  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    hash_for_each_rcu(fw->whitelist_table_ipv6, bkt, wl_entry, hash) {
      u8 prefix = READ_ONCE(wl_entry->mask.prefix_len);
      const struct in6_addr *wl_ip = &wl_entry->addr.ipv6;
      if (ipv6_prefix_equal(ip6, wl_ip, prefix)) {
        rcu_read_unlock();
        spin_unlock(&fw->lock);
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
        spin_unlock(&fw->lock);
        kfree(entry);
        atomic_inc(&fw->whitelist_reject_count);
        fw_pr_warn("REFUSED to ban whitelisted IP %s", ip_str);
        return -EPERM;
      }
    }
  }
  rcu_read_unlock();

  /* 阶段 2：检查封禁表容量（仍在全局锁下） */
  if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
    spin_unlock(&fw->lock);
    kfree(entry);
    atomic_inc(&fw->ban_table_full_count);
    fw_pr_warn("Ban table full, cannot ban %s", ip_str);
    return -ENOSPC;
  }
  spin_unlock(&fw->lock);

  /* 阶段 3：使用每桶锁操作封禁表（不同桶可并行） */
  if (af == FW_AF_INET6) {
    ret = __do_ban_ip_ipv6(fw, (struct in6_addr *)ip, entry, unban_time, is_permanent);
  } else {
    ret = __do_ban_ip_ipv4(fw, *(__be32 *)ip, entry, unban_time, is_permanent);
  }

  if (ret == -EPERM) {
    fw_pr_warn("REFUSED to ban whitelisted IP %s (recheck)", ip_str);
    return ret;
  }
  if (ret == -EEXIST) {
    /* 条目已存在且仍有效：no-op，不计入任何统计、不打日志以避免刷屏 */
    return 0;
  }
  if (ret < 0)
    return ret;

  /* ret == 0：实际变更（新插入或刷新过期条目），
   * ban_count / total_ban_count 已在 __do_ban_ip_ipv4/ipv6 中按语义更新。 */

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

/* __do_unban_ip - 解封 IP 的核心实现
 *
 * 使用每桶锁而非全局锁，不同桶的解封操作可并行执行。
 * permanent_only 参数用于区分普通解封和永久封禁移除。
 */
static int __do_unban_ip(struct firewall_info *fw, u8 af, const void *ip, bool permanent_only) {
  struct ban_entry *entry;
  int found = 0;
  char ip_str[INET6_STR_LEN];
  ip_to_str(af, ip, ip_str, sizeof(ip_str));

  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    u32 bkt = hash_ipv6(ip6);

    spin_lock(&fw->ban_locks_ipv6[bkt]);
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
    spin_unlock(&fw->ban_locks_ipv6[bkt]);
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    u32 bkt = hash_min(ipv4, BAN_HASH_BITS);

    spin_lock(&fw->ban_locks_ipv4[bkt]);
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
    spin_unlock(&fw->ban_locks_ipv4[bkt]);
  }

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
  FW_DEBUG(3, "Result for IP (af=%d) ban check: %s", af, found ? "BANNED" : "NOT BANNED");
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

/* check_flood_protection - 泛洪保护检查
 *
 * 限制每秒最大封禁次数，防止恶意请求导致系统资源耗尽。
 * 使用滑动窗口计数：每秒重置计数器，超过阈值返回 -EBUSY。
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
