/*
 * netdev.c - 网络设备通知器 (支持 IPv4/IPv6)
 *
 * 包含网络设备事件监听、系统 IP 自动发现和白名单同步相关的函数实现。
 */

#include "firewall.h"
#include <linux/printk.h>

/* 自动发现的临时存储结构 */
struct temp_ip_entry {
  u8 af;
  union {
    __be32 ipv4;
    struct in6_addr ipv6;
  } addr;
  union {
    __be32 ipv4_mask;
    u8 prefix_len;
  } mask;
  char name[16];
};

/*
 * sync_work_handler - 延迟工作队列处理函数（防抖后执行）
 */
void sync_work_handler(struct work_struct *work) {
  struct firewall_info *fw;
  struct temp_ip_entry *current_ips;
  int current_count = 0;
  struct net_device *dev;
  struct whitelist_entry *entry;
  struct hlist_node *tmp;
  u32 bkt;
  int i;

  fw = container_of(work, struct firewall_info, sync_work.work);

  if (unlikely(atomic_read(&fw->shutting_down))) {
    return;
  }

  current_ips = kmalloc_array(MAX_BAN_ENTRIES, sizeof(struct temp_ip_entry), GFP_KERNEL);
  if (!current_ips) {
    pr_err("IP 发现临时数组内存分配失败\n");
    return;
  }

  rcu_read_lock();
  for_each_netdev_rcu(&init_net, dev) {
    if (!(dev->flags & IFF_UP))
      continue;

    /* IPv4 地址发现 */
    {
      struct in_device *in_dev = __in_dev_get_rcu(dev);
      if (in_dev) {
        struct in_ifaddr *ifa;
        for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
             ifa = rcu_dereference(ifa->ifa_next)) {
          /* 跳过容量限制（按需扩展） */
          if (!ifa->ifa_local)
            continue;
          current_ips[current_count].af = FW_AF_INET;
          current_ips[current_count].addr.ipv4 = ifa->ifa_local;
          current_ips[current_count].mask.ipv4_mask = ifa->ifa_mask;
          strscpy(current_ips[current_count].name, dev->name, 16);
          current_count++;
        }
      }
    }

    /* IPv6 地址发现 */
    {
      struct inet6_dev *in6_dev = __in6_dev_get(dev);
      if (in6_dev) {
        struct inet6_ifaddr *ifp;
        read_lock_bh(&in6_dev->lock);
        list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
          /* 跳过容量限制（按需扩展） */
          current_ips[current_count].af = FW_AF_INET6;
          current_ips[current_count].addr.ipv6 = ifp->addr;
          current_ips[current_count].mask.prefix_len = ifp->prefix_len;
          strscpy(current_ips[current_count].name, dev->name, 16);
          current_count++;
        }
        read_unlock_bh(&in6_dev->lock);
      }
    }
  }
  rcu_read_unlock();

  if (current_count == 0) {
    kfree(current_ips);
    return;
  }

  struct current_ip_lookup {
    u8 af;
    union {
      __be32 ipv4;
      struct in6_addr ipv6;
    } addr;
    union {
      __be32 ipv4_mask;
      u8 prefix_len;
    } mask;
    bool found;
  };
  struct current_ip_lookup *lookup_table;
  lookup_table = kmalloc_array(current_count, sizeof(struct current_ip_lookup), GFP_KERNEL);
  if (!lookup_table) {
    kfree(current_ips);
    return;
  }
  for (i = 0; i < current_count; i++) {
    lookup_table[i].af = current_ips[i].af;
    if (current_ips[i].af == FW_AF_INET6) {
      lookup_table[i].addr.ipv6 = current_ips[i].addr.ipv6;
      lookup_table[i].mask.prefix_len = current_ips[i].mask.prefix_len;
    } else {
      lookup_table[i].addr.ipv4 = current_ips[i].addr.ipv4 & current_ips[i].mask.ipv4_mask;
      lookup_table[i].mask.ipv4_mask = current_ips[i].mask.ipv4_mask;
    }
    lookup_table[i].found = false;
  }

  spin_lock(&fw->whitelist_lock);
  hash_for_each_safe(fw->whitelist_table_ipv4, bkt, tmp, entry, hash) {
    if (strcmp(entry->device_name, "manual") == 0 ||
        strcmp(entry->device_name, "restored") == 0)
      continue;
    for (i = 0; i < current_count; i++) {
      if (lookup_table[i].af != FW_AF_INET)
        continue;
      if (entry->addr.ipv4 == lookup_table[i].addr.ipv4 &&
          entry->mask.ipv4_mask == lookup_table[i].mask.ipv4_mask) {
        lookup_table[i].found = true;
        break;
      }
    }
    if (i == current_count) {
      /* 先保存被删条目的信息用于推送 */
      __be32 del_ip = entry->addr.ipv4;
      __be32 del_mask = entry->mask.ipv4_mask;
      char del_dev[16];
      memcpy(del_dev, entry->device_name, sizeof(del_dev));
      hlist_del_rcu(&entry->hash);
      /* 从子网链表中移除（非精确匹配条目） */
      if (entry->mask.ipv4_mask != 0xFFFFFFFF)
        list_del_rcu(&entry->subnet_node);
      atomic_dec(&fw->whitelist_count);
      call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
      /* 推送白名单删除事件 */
      fw_netlink_send_whitelist_state_change(
        FW_AF_INET, &del_ip, inet_mask_len(del_mask), 2, del_dev);
    }
  }
  hash_for_each_safe(fw->whitelist_table_ipv6, bkt, tmp, entry, hash) {
    if (strcmp(entry->device_name, "manual") == 0 ||
        strcmp(entry->device_name, "restored") == 0)
      continue;
    for (i = 0; i < current_count; i++) {
      if (lookup_table[i].af != FW_AF_INET6)
        continue;
      if (ipv6_addr_equal(&entry->addr.ipv6, &lookup_table[i].addr.ipv6) &&
          entry->mask.prefix_len == lookup_table[i].mask.prefix_len) {
        lookup_table[i].found = true;
        break;
      }
    }
    if (i == current_count) {
      /* 先保存被删条目的信息用于推送 */
      struct in6_addr del_ip6 = entry->addr.ipv6;
      u8 del_prefix = entry->mask.prefix_len;
      char del_dev[16];
      memcpy(del_dev, entry->device_name, sizeof(del_dev));
      hlist_del_rcu(&entry->hash);
      /* 从子网链表中移除（非精确匹配条目） */
      if (entry->mask.prefix_len < 128)
        list_del_rcu(&entry->subnet_node);
      atomic_dec(&fw->whitelist_count);
      call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
      /* 推送白名单删除事件 */
      fw_netlink_send_whitelist_state_change(FW_AF_INET6, &del_ip6, del_prefix, 2, del_dev);
    }
  }
  spin_unlock(&fw->whitelist_lock);

  for (i = 0; i < current_count; i++) {
    if (!lookup_table[i].found) {
      int ret;
      if (current_ips[i].af == FW_AF_INET6) {
        ret = add_whitelist_entry(fw, FW_AF_INET6, &current_ips[i].addr.ipv6, NULL,
                                  current_ips[i].mask.prefix_len, current_ips[i].name);
      } else {
        ret = add_whitelist_entry(
          fw, FW_AF_INET, &current_ips[i].addr.ipv4, &current_ips[i].mask.ipv4_mask,
          inet_mask_len(current_ips[i].mask.ipv4_mask), current_ips[i].name);
      }
    }
  }

  /* 重建本地 IP 缓存（热路径优化：避免每次包都走白名单哈希表查找）
   * 使用新数组 + rcu_assign_pointer 原子切换，旧数组由 RCU 回调释放 */
  {
    struct local_ip_cache_entry *new_cache;
    struct local_ip_cache_entry *old_cache;

    new_cache = kmalloc_array(current_count, sizeof(struct local_ip_cache_entry), GFP_KERNEL);
    if (new_cache) {
      for (i = 0; i < current_count; i++) {
        new_cache[i].af = current_ips[i].af;
        if (current_ips[i].af == FW_AF_INET6) {
          new_cache[i].addr.ipv6 = current_ips[i].addr.ipv6;
          new_cache[i].mask.prefix_len = current_ips[i].mask.prefix_len;
        } else {
          new_cache[i].addr.ipv4 = current_ips[i].addr.ipv4 &
                                   current_ips[i].mask.ipv4_mask;
          new_cache[i].mask.ipv4_mask = current_ips[i].mask.ipv4_mask;
        }
      }
      atomic_set(&fw->local_ip_cache_count, current_count);
      /* RCU 发布：确保读侧要么看到完整旧数组，要么看到完整新数组 */
      old_cache = rcu_dereference_protected(fw->local_ip_cache, 1);
      rcu_assign_pointer(fw->local_ip_cache, new_cache);
      /* 旧数组延迟释放（等待所有 RCU reader 完成） */
      if (old_cache) {
        /* 使用 synchronize_rcu 等待所有 reader 完成，然后释放 */
        synchronize_rcu();
        kfree(old_cache);
      }
    } else {
      pr_warn("本地 IP 缓存分配失败，降级为白名单查找\n");
    }
  }

  kfree(lookup_table);
  kfree(current_ips);
}

/*
 * sync_system_ips - 调度 IP 同步工作（带防抖）
 */
void sync_system_ips(struct firewall_info *fw) {
  unsigned long delay = msecs_to_jiffies(500);

  if (unlikely(atomic_read(&fw->shutting_down))) {
    return;
  }

  mod_delayed_work(system_wq, &fw->sync_work, delay);
}
EXPORT_SYMBOL_GPL(sync_system_ips);

/*
 * netdev_event_handler - 网络设备事件回调函数
 */
static int netdev_event_handler(struct notifier_block *nb, unsigned long event, void *ptr) {
  struct firewall_info *fw;
  struct net_device *dev;

  fw = container_of(nb, struct firewall_info, netdev_notifier);

  if (unlikely(atomic_read(&fw->shutting_down)))
    return NOTIFY_DONE;

  dev = netdev_notifier_info_to_dev(ptr);
  if (!dev)
    return NOTIFY_DONE;

  switch (event) {
  case NETDEV_UP:
  case NETDEV_DOWN:
  case NETDEV_CHANGE:
    sync_system_ips(fw);
    break;
  default:
    break;
  }

  return NOTIFY_DONE;
}

/*
 * register_netdev_notifier - 注册网络设备事件监听器
 */
int register_netdev_notifier(struct firewall_info *fw) {
  int ret;

  fw->netdev_notifier.notifier_call = netdev_event_handler;

  ret = register_netdevice_notifier(&fw->netdev_notifier);
  if (ret) {
    fw->netdev_notifier_registered = false;
    return ret;
  }

  fw->netdev_notifier_registered = true;
  return 0;
}
EXPORT_SYMBOL_GPL(register_netdev_notifier);

/*
 * unregister_netdev_notifier - 注销网络设备事件监听器
 */
void unregister_netdev_notifier(struct firewall_info *fw) {
  if (fw->netdev_notifier_registered) {
    unregister_netdevice_notifier(&fw->netdev_notifier);
    fw->netdev_notifier_registered = false;
  } else {
  }
}
EXPORT_SYMBOL_GPL(unregister_netdev_notifier);

/*
 * auto_discover_system_ips - 自动发现系统 IP 并添加到白名单
 */
void auto_discover_system_ips(struct firewall_info *fw) {
  struct temp_ip_entry *temp_ips;
  int temp_count = 0;

  struct net_device *dev;

  temp_ips = kmalloc_array(MAX_BAN_ENTRIES, sizeof(struct temp_ip_entry), GFP_KERNEL);
  if (!temp_ips) {
    pr_err("自动发现系统 IP：临时数组内存分配失败\n");
    return;
  }

  rcu_read_lock();
  for_each_netdev_rcu(&init_net, dev) {
    if (!(dev->flags & IFF_UP))
      continue;

    /* IPv4 发现 */
    {
      struct in_device *in_dev = __in_dev_get_rcu(dev);
      if (in_dev) {
        struct in_ifaddr *ifa;
        for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
             ifa = rcu_dereference(ifa->ifa_next)) {
          /* 跳过容量限制（按需扩展） */
          if (!ifa->ifa_local)
            continue;
          temp_ips[temp_count].af = FW_AF_INET;
          temp_ips[temp_count].addr.ipv4 = ifa->ifa_local;
          temp_ips[temp_count].mask.ipv4_mask = ifa->ifa_mask;
          strscpy(temp_ips[temp_count].name, dev->name, 16);
          temp_count++;
        }
      }
    }

    /* IPv6 发现 */
    {
      struct inet6_dev *in6_dev = __in6_dev_get(dev);
      if (in6_dev) {
        struct inet6_ifaddr *ifp;
        read_lock_bh(&in6_dev->lock);
        list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
          /* 跳过容量限制（按需扩展） */
          temp_ips[temp_count].af = FW_AF_INET6;
          temp_ips[temp_count].addr.ipv6 = ifp->addr;
          temp_ips[temp_count].mask.prefix_len = ifp->prefix_len;
          strscpy(temp_ips[temp_count].name, dev->name, 16);
          temp_count++;
        }
        read_unlock_bh(&in6_dev->lock);
      }
    }
  }
  rcu_read_unlock();

  for (int i = 0; i < temp_count; i++) {
    int ret;
    if (temp_ips[i].af == FW_AF_INET6) {
      ret = add_whitelist_entry(fw, FW_AF_INET6, &temp_ips[i].addr.ipv6, NULL,
                                temp_ips[i].mask.prefix_len, temp_ips[i].name);
    } else {
      ret = add_whitelist_entry(
        fw, FW_AF_INET, &temp_ips[i].addr.ipv4, &temp_ips[i].mask.ipv4_mask,
        inet_mask_len(temp_ips[i].mask.ipv4_mask), temp_ips[i].name);
    }
  }

  kfree(temp_ips);
}
EXPORT_SYMBOL_GPL(auto_discover_system_ips);
