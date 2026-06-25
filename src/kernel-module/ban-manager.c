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
#include <linux/printk.h>
#include <linux/timer.h>

extern unsigned int fw_ban_time;
extern unsigned int fw_max_bans_per_second;
extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

extern void free_ban_entry_rcu(struct rcu_head *head);

/* 声明 hash_ipv6 函数（定义在文件后面） */
u32 hash_ipv6(const struct in6_addr *addr);

/* per-entry 过期定时器回调
 *
 * 当定时器到期时，自动删除封禁条目并发送 netlink 事件通知守护进程。
 * 类似 nftables 的 set timeout 机制，内核自动管理过期，零用户空间轮询。
 */
void ban_entry_expire_callback(struct timer_list *t) {
  struct ban_entry *entry = container_of(t, struct ban_entry, expire_timer);
  struct firewall_info *fw = &fw_info;
  u8 af = entry->af;

  if (af == FW_AF_INET) {
    __be32 expired_ip = entry->addr.ipv4;
    /* 从哈希表中删除 */
    u32 bkt = hash_min(expired_ip, BAN_HASH_BITS);
    spin_lock(&fw->ban_locks_ipv4[bkt]);
    /* 二次检查：条目是否还在表中（可能已被手动解封） */
    if (hlist_unhashed(&entry->hash)) {
      spin_unlock(&fw->ban_locks_ipv4[bkt]);
      return;
    }
    list_del_rcu(&entry->ban_node);
    hlist_del_rcu(&entry->hash);
    atomic_dec(&fw->ban_count);
    atomic_inc(&fw->cleanup_expired_total);
    spin_unlock(&fw->ban_locks_ipv4[bkt]);
    call_rcu(&entry->rcu_head, free_ban_entry_rcu);
    /* 通知守护进程 */
    fw_netlink_send_ban_state_change(FW_AF_INET, &expired_ip, 2, 0, "expired", NULL);
    pr_debug("IPv4 封禁自动过期：%pI4\n", &expired_ip);
  } else if (af == FW_AF_INET6) {
    struct in6_addr expired_ip6 = entry->addr.ipv6;
    u32 bkt = hash_ipv6(&expired_ip6);
    spin_lock(&fw->ban_locks_ipv6[bkt]);
    if (hlist_unhashed(&entry->hash)) {
      spin_unlock(&fw->ban_locks_ipv6[bkt]);
      return;
    }
    list_del_rcu(&entry->ban_node);
    hlist_del_rcu(&entry->hash);
    atomic_dec(&fw->ban_count);
    atomic_inc(&fw->cleanup_expired_total);
    spin_unlock(&fw->ban_locks_ipv6[bkt]);
    call_rcu(&entry->rcu_head, free_ban_entry_rcu);
    fw_netlink_send_ban_state_change(FW_AF_INET6, &expired_ip6, 2, 0, "expired", NULL);
    pr_debug("IPv6 封禁自动过期：%pI6c\n", &expired_ip6);
  }
}

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
                       unsigned long unban_time, bool is_permanent, const char *reason,
                       const char *log_msg, unsigned long log_arg, bool *is_new_ban);
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw, u8 af,
                                              const void *ip);
static int __do_unban_ip(struct firewall_info *fw, u8 af, const void *ip, bool permanent_only);

int ban_ip_with_duration(struct firewall_info *fw, u8 af, const void *ip,
                         unsigned long seconds, const char *reason);
int check_flood_protection(void);

/* 计算 IPv6 地址在封禁表中的哈希桶索引
 *
 * 使用 jhash 确保地址分布均匀，减少哈希冲突。
 * fw_hash_seed 在模块初始化时随机生成，防止攻击者构造哈希碰撞。
 */
u32 hash_ipv6(const struct in6_addr *addr) {
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
static int __do_ban_ip_ipv6(struct firewall_info *fw, const struct in6_addr *ip6,
                            struct ban_entry *entry, unsigned long unban_time,
                            bool is_permanent, const char *reason, bool *is_new_ban) {
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
    pr_debug("IPv6 封禁被白名单拒绝\n");
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
      /* 重设 per-entry 过期定时器，防止旧定时器提前删除刚刷新的条目 */
      mod_timer(&existing->expire_timer, unban_time);
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
  strscpy(entry->jail_name, "kernel", sizeof(entry->jail_name));
  strscpy(entry->reason, reason ? reason : "", sizeof(entry->reason));
  atomic_set(&entry->retry_count, 0);
  /* 修复：直接用桶索引 hlist_add_head_rcu，避免 hash_add_rcu 以 bkt6 为 key
   * 重新 hash_min 落到错误桶(会导致重复检查失效、产生重复条目)。
   * IPv4 路径不受影响(其 key=ipv4,hash_min(ipv4,...) 与 bkt4 巧合一致)。*/
  hlist_add_head_rcu(&entry->hash, &fw->ban_table_ipv6[bkt6]);
  list_add_tail_rcu(&entry->ban_node, &fw->active_bans_list);

  /* per-entry 过期定时器：非永久封禁时启动，到期自动删除 */
  if (!is_permanent) {
    timer_setup(&entry->expire_timer, ban_entry_expire_callback, 0);
    mod_timer(&entry->expire_timer, unban_time);
  }

  spin_unlock(&fw->ban_locks_ipv6[bkt6]);
  /* 新插入：同时增加表内计数与累计操作次数 */
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);
  *is_new_ban = true;
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
static int __do_ban_ip_ipv4(struct firewall_info *fw, __be32 ipv4,
                            struct ban_entry *entry, unsigned long unban_time,
                            bool is_permanent, const char *reason, bool *is_new_ban) {
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
    pr_debug("IPv4 封禁被白名单拒绝\n");
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
      /* 重设 per-entry 过期定时器，防止旧定时器提前删除刚刷新的条目 */
      mod_timer(&existing->expire_timer, unban_time);
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
  strscpy(entry->jail_name, "kernel", sizeof(entry->jail_name));
  strscpy(entry->reason, reason ? reason : "", sizeof(entry->reason));
  atomic_set(&entry->retry_count, 0);
  /* 与 IPv6 路径保持一致:直接用桶索引 hlist_add_head_rcu,
   * 杜绝 hash_add_rcu(key) API 误用导致桶错位。*/
  hlist_add_head_rcu(&entry->hash, &fw->ban_table_ipv4[bkt4]);
  list_add_tail_rcu(&entry->ban_node, &fw->active_bans_list);

  /* per-entry 过期定时器：非永久封禁时启动，到期自动删除 */
  if (!is_permanent) {
    timer_setup(&entry->expire_timer, ban_entry_expire_callback, 0);
    mod_timer(&entry->expire_timer, unban_time);
  }

  spin_unlock(&fw->ban_locks_ipv4[bkt4]);
  /* 新插入：同时增加表内计数与累计操作次数 */
  atomic_inc(&fw->ban_count);
  atomic_inc(&fw->total_ban_count);
  *is_new_ban = true;
  return 0;
}

static int __do_ban_ip(struct firewall_info *fw, u8 af, const void *ip,
                       unsigned long unban_time, bool is_permanent, const char *reason,
                       const char *log_msg, unsigned long log_arg, bool *is_new_ban) {
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  int bkt;
  int ret;

  *is_new_ban = false;

  if (!ip) {
    return -EINVAL;
  }

  /* 验证 IP 地址的合法性 */
  if (af == FW_AF_INET) {
    __be32 ipv4 = *(__be32 *)ip;
    ret = validate_ipv4_address(ipv4, NULL, "ban", false);
    if (ret != 0) {
      pr_warn("Invalid IPv4 address for banning: %pI4\n", &ipv4);
      return ret;
    }
  } else if (af == FW_AF_INET6) {
    const struct in6_addr *ipv6 = (const struct in6_addr *)ip;
    ret = validate_ipv6_address(ipv6, NULL, "ban", false);
    if (ret != 0) {
      pr_warn("Invalid IPv6 address for banning: %pI6\n", ipv6);
      return ret;
    }
  } else {
    pr_warn("Invalid address family for banning: %d\n", af);
    return -EINVAL;
  }

  /* 使用 GFP_ATOMIC：此函数可能在 softirq 上下文（netfilter hook）中被调用
   * GFP_KERNEL 可能会睡眠，在 softirq 上下文中会导致 panic */
  entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
  if (!entry) {
    atomic_inc(&fw->alloc_failure_count);
    pr_err("封禁条目内存分配失败\n");
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
        return -EPERM;
      }
    }
  }
  rcu_read_unlock();

  /* 阶段 1.5：保护本机接口 IP，防止误封自身导致网络中断 */
  if (af == FW_AF_INET) {
    __be32 target_ipv4 = *(__be32 *)ip;
    struct net_device *dev;
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
      struct in_device *in_dev = __in_dev_get_rcu(dev);
      if (in_dev) {
        struct in_ifaddr *ifa;
        for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
             ifa = rcu_dereference(ifa->ifa_next)) {
          if (ifa->ifa_local == target_ipv4) {
            rcu_read_unlock();
            kfree(entry);
            pr_warn("拒绝封禁本机接口 IP: %pI4 (dev=%s)\n", &target_ipv4, dev->name);
            return -EPERM;
          }
        }
      }
    }
    rcu_read_unlock();
  } else if (af == FW_AF_INET6) {
    const struct in6_addr *target_ipv6 = (const struct in6_addr *)ip;
    struct net_device *dev;
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
      struct inet6_dev *idev = __in6_dev_get(dev);
      if (idev) {
        struct inet6_ifaddr *ifp;
        read_lock_bh(&idev->lock);
        list_for_each_entry(ifp, &idev->addr_list, if_list) {
          if (ipv6_addr_equal(&ifp->addr, target_ipv6)) {
            read_unlock_bh(&idev->lock);
            rcu_read_unlock();
            kfree(entry);
            pr_warn("拒绝封禁本机接口 IPv6: %pI6c (dev=%s)\n", target_ipv6, dev->name);
            return -EPERM;
          }
        }
        read_unlock_bh(&idev->lock);
      }
    }
    rcu_read_unlock();
  }

  /* 阶段 2：跳过容量检查（按需扩展） */
  spin_unlock(&fw->lock);

  /* 阶段 3：使用每桶锁操作封禁表（不同桶可并行） */
  if (af == FW_AF_INET6) {
    ret = __do_ban_ip_ipv6(fw, (struct in6_addr *)ip, entry, unban_time,
                           is_permanent, reason, is_new_ban);
  } else {
    ret = __do_ban_ip_ipv4(
      fw, *(__be32 *)ip, entry, unban_time, is_permanent, reason, is_new_ban);
  }

  if (ret == -EPERM) {
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

  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    u32 bkt = hash_ipv6(ip6);

    spin_lock(&fw->ban_locks_ipv6[bkt]);
    hlist_for_each_entry(entry, &fw->ban_table_ipv6[bkt], hash) {
      if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, ip6)) {
        if (!permanent_only || READ_ONCE(entry->is_permanent)) {
          /* 取消 per-entry 过期定时器 */
          timer_delete_sync(&entry->expire_timer);
          list_del_rcu(&entry->ban_node);
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
          /* 取消 per-entry 过期定时器 */
          timer_delete_sync(&entry->expire_timer);
          list_del_rcu(&entry->ban_node);
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
    return 0;
  }
  return -ENOENT;
}

int unban_ip(struct firewall_info *fw, u8 af, const void *ip) {
  int ret = __do_unban_ip(fw, af, ip, false);
  if (ret == 0) {
    fw_netlink_send_ban_state_change(af, ip, 2, 0, "unban", NULL);
  }
  return ret;
}
EXPORT_SYMBOL_GPL(unban_ip);

int unban_permanent_ip(struct firewall_info *fw, u8 af, const void *ip) {
  int ret = __do_unban_ip(fw, af, ip, true);
  if (ret == 0) {
    fw_netlink_send_ban_state_change(af, ip, 2, 0, "unban", NULL);
  }
  return ret;
}
EXPORT_SYMBOL_GPL(unban_permanent_ip);

int is_banned(struct firewall_info *fw, u8 af, const void *ip) {
  struct ban_entry *entry;
  unsigned long now = jiffies;
  int found = 0;

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
  return found;
}
EXPORT_SYMBOL_GPL(is_banned);

int ban_ip(struct firewall_info *fw, u8 af, const void *ip, const char *reason) {
  unsigned long ban_secs = READ_ONCE(fw_ban_time);
  unsigned long ban_duration;
  bool is_new_ban = false;
  if (check_mul_overflow(ban_secs, (unsigned long)HZ, &ban_duration)) {
    return -EINVAL;
  }
  int ret = __do_ban_ip(fw, af, ip, jiffies + ban_duration, false, reason ? reason : "manual",
                        "banned for %u seconds", ban_secs, &is_new_ban);
  if (ret == 0 && is_new_ban) {
    fw_netlink_send_ban_state_change(
      af, ip, 1, (u32)ban_secs, reason ? reason : "manual", NULL);
  }
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip);

int ban_ip_permanent(struct firewall_info *fw, u8 af, const void *ip, const char *reason) {
  bool is_new_ban = false;
  int ret = __do_ban_ip(fw, af, ip, 0, true, reason ? reason : "manual",
                        "permanently banned", 0, &is_new_ban);
  if (ret == 0 && is_new_ban) {
    fw_netlink_send_ban_state_change(af, ip, 1, 0, reason ? reason : "manual", NULL);
  }
  return ret;
}
EXPORT_SYMBOL_GPL(ban_ip_permanent);

int is_permanently_banned(struct firewall_info *fw, u8 af, const void *ip) {
  struct ban_entry *entry;
  int found = 0;
  rcu_read_lock();
  entry = __find_ban_entry_rcu(fw, af, ip);
  if (entry && READ_ONCE(entry->is_permanent))
    found = 1;
  rcu_read_unlock();
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
                         unsigned long seconds, const char *reason) {
  unsigned long ban_duration;
  bool is_new_ban = false;
  if (!ip) {
    return -EINVAL;
  }
  if (seconds == 0) {
    return -EINVAL;
  }
  if (check_mul_overflow(seconds, (unsigned long)HZ, &ban_duration)) {
    return -EINVAL;
  }
  int ret = __do_ban_ip(fw, af, ip, jiffies + ban_duration, false, reason ? reason : "manual",
                        "banned for %lu seconds", seconds, &is_new_ban);
  if (ret == 0 && is_new_ban) {
    fw_netlink_send_ban_state_change(
      af, ip, 1, (u32)seconds, reason ? reason : "manual", NULL);
  }
  return ret;
}
