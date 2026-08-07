/*
 * whitelist.c - 白名单管理 (支持 IPv4/IPv6)
 */

#include "firewall.h"
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/printk.h>

extern u32 fw_hash_seed;

/* 计算 IPv6 白名单条目的哈希桶索引
 *
 * 与封禁表使用相同的哈希种子，确保地址分布均匀。
 */
static u32 hash_wl_ipv6(const struct in6_addr *addr) {
  return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) &
         ((1 << WHITELIST_HASH_BITS) - 1);
}

int add_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                        const void *mask, int prefix_len, const char *dev_name) {
  struct whitelist_entry *new_entry;
  struct whitelist_entry *tmp_entry;
  u32 bkt;

  new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
  if (!new_entry) {
    pr_err("白名单条目内存分配失败\n");
    return -ENOMEM;
  }

  new_entry->af = af;
  if (af == FW_AF_INET6) {
    struct in6_addr raw = *(const struct in6_addr *)ip;
    /* 验证 IPv6 前缀长度合法性（0-128） */
    if (prefix_len < 0 || prefix_len > 128) {
      kfree(new_entry);
      pr_debug("无效的 IPv6 前缀长度: %d\n", prefix_len);
      return -EINVAL;
    }
    new_entry->mask.prefix_len = (u8)prefix_len;
    /* 清 host bits，与 procfs 规范化语义一致，避免同一前缀多条目 */
    ipv6_addr_prefix(&new_entry->addr.ipv6, &raw, prefix_len);
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    __be32 msk = *(__be32 *)mask;
    /* 验证 IPv4 子网掩码合法性（必须为连续的 1 后跟连续的 0） */
    if (msk != 0 && msk != 0xFFFFFFFF) {
      __be32 inverted = ~ntohl(msk);
      /* 检查 inverted 是否为 2 的幂减 1（连续的低位 1 表示合法掩码） */
      if ((inverted & (inverted + 1)) != 0) {
        kfree(new_entry);
        pr_debug("无效的 IPv4 子网掩码\n");
        return -EINVAL;
      }
    }
    new_entry->addr.ipv4 = ipv4 & msk;
    new_entry->mask.ipv4_mask = msk;
  }
  if (dev_name)
    strscpy(new_entry->device_name, dev_name, sizeof(new_entry->device_name));
  else
    new_entry->device_name[0] = '\0';

  spin_lock(&fw->whitelist_lock);

  if (af == FW_AF_INET6) {
    bkt = hash_wl_ipv6(&new_entry->addr.ipv6);
    hlist_for_each_entry_rcu(tmp_entry, &fw->whitelist_table_ipv6[bkt], hash,
                             lockdep_is_held(&fw->whitelist_lock)) {
      if (tmp_entry->af == af &&
          ipv6_addr_equal(&tmp_entry->addr.ipv6, &new_entry->addr.ipv6) &&
          tmp_entry->mask.prefix_len == new_entry->mask.prefix_len) {
        spin_unlock(&fw->whitelist_lock);
        kfree(new_entry);
        return 0;
      }
    }
  } else {
    bkt = hash_ipv4(new_entry->addr.ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry_rcu(tmp_entry, &fw->whitelist_table_ipv4[bkt], hash,
                             lockdep_is_held(&fw->whitelist_lock)) {
      if (tmp_entry->af == af && tmp_entry->addr.ipv4 == new_entry->addr.ipv4 &&
          tmp_entry->mask.ipv4_mask == new_entry->mask.ipv4_mask) {
        spin_unlock(&fw->whitelist_lock);
        kfree(new_entry);
        return 0;
      }
    }
  }

  /* 跳过容量检查（按需扩展） */

  /* 修复：IPv6 路径用预计算桶索引直接 hlist_add_head_rcu,
   * 避免 hash_add_rcu 把 hash_wl_ipv6 结果再次 hash_min 落到错误桶
   * (会导致重复检查失效、netfilter 热路径查找 miss)
   * IPv4 路径同样改用 hlist_add_head_rcu 直写预计算桶,
   * 与 ban-manager.c 保持完全一致,杜绝 hash_add_rcu(key) API 误用。 */
  if (af == FW_AF_INET6)
    hlist_add_head_rcu(&new_entry->hash, &fw->whitelist_table_ipv6[bkt]);
  else
    hlist_add_head_rcu(&new_entry->hash, &fw->whitelist_table_ipv4[bkt]);

  /* 子网条目加入专用链表，加速后续子网匹配查找 */
  if (af == FW_AF_INET6) {
    if (new_entry->mask.prefix_len < 128)
      list_add_tail_rcu(&new_entry->subnet_node, &fw->ipv6_subnet_wl);
  } else {
    if (new_entry->mask.ipv4_mask != 0xFFFFFFFF)
      list_add_tail_rcu(&new_entry->subnet_node, &fw->ipv4_subnet_wl);
  }

  atomic_inc(&fw->whitelist_count);
  spin_unlock(&fw->whitelist_lock);

  /* 白名单添加后，解除封禁表中匹配的 IP
   * 精确匹配（/32 / /128）：O(1) 直接定位哈希桶
   * CIDR 子网匹配：O(n) 遍历全表 */
  {
    struct ban_entry *ban;
    struct hlist_node *tmp;
    int removed = 0;

    if (af == FW_AF_INET) {
      __be32 wl_ip = *(__be32 *)ip;
      __be32 wl_mask = *(__be32 *)mask;
      if (wl_mask == 0xFFFFFFFF) {
        /* 精确匹配：直接定位桶，O(1) */
        u32 bkt = hash_ipv4(wl_ip, BAN_HASH_BITS);
        spin_lock_bh(&fw->ban_locks_ipv4[bkt]);
        hlist_for_each_entry_safe(ban, tmp, &fw->ban_table_ipv4[bkt], hash) {
          if (ban->addr.ipv4 == wl_ip) {
            __be32 expired_ip = ban->addr.ipv4;
            /* 取消 per-entry 过期定时器（非 _sync，避免持锁死锁） */
            timer_delete(&ban->expire_timer);
            active_bans_del(fw, ban);
            hlist_del_rcu(&ban->hash);
            atomic_dec(&fw->ban_count);
            call_rcu(&ban->rcu_head, free_ban_entry_rcu);
            removed++;
            fw_netlink_send_ban_state_change(
              FW_AF_INET, &expired_ip, 2, 0, "whitelist", NULL);
          }
        }
        spin_unlock_bh(&fw->ban_locks_ipv4[bkt]);
      } else {
        /* CIDR：RCU 只读收集匹配 IP，再按桶锁解封（禁止持锁遍历时改链） */
        __be32 batch[32];
        int n, i, pass_removed;
        do {
          n = 0;
          pass_removed = 0;
          rcu_read_lock();
          list_for_each_entry_rcu(ban, &fw->active_bans_list, ban_node) {
            if (ban->af != FW_AF_INET)
              continue;
            if ((ban->addr.ipv4 & wl_mask) != (wl_ip & wl_mask))
              continue;
            if (n < (int)ARRAY_SIZE(batch))
              batch[n++] = ban->addr.ipv4;
          }
          rcu_read_unlock();
          for (i = 0; i < n; i++) {
            u32 bkt = hash_ipv4(batch[i], BAN_HASH_BITS);
            struct hlist_node *tmp2;
            spin_lock_bh(&fw->ban_locks_ipv4[bkt]);
            hlist_for_each_entry_safe(ban, tmp2, &fw->ban_table_ipv4[bkt], hash) {
              if (ban->addr.ipv4 != batch[i])
                continue;
              {
                __be32 expired_ip = ban->addr.ipv4;
                timer_delete(&ban->expire_timer);
                active_bans_del(fw, ban);
                hlist_del_rcu(&ban->hash);
                atomic_dec(&fw->ban_count);
                call_rcu(&ban->rcu_head, free_ban_entry_rcu);
                pass_removed++;
                removed++;
                fw_netlink_send_ban_state_change(
                  FW_AF_INET, &expired_ip, 2, 0, "whitelist", NULL);
              }
            }
            spin_unlock_bh(&fw->ban_locks_ipv4[bkt]);
          }
        } while (n == (int)ARRAY_SIZE(batch) && pass_removed > 0);
      }
    } else {
      u8 prefix = (u8)prefix_len;
      if (prefix == 128) {
        /* 精确匹配：直接定位桶，O(1) */
        u32 bkt = hash_ipv6((const struct in6_addr *)ip);
        spin_lock_bh(&fw->ban_locks_ipv6[bkt]);
        hlist_for_each_entry_safe(ban, tmp, &fw->ban_table_ipv6[bkt], hash) {
          if (ban->af == FW_AF_INET6 &&
              ipv6_addr_equal(&ban->addr.ipv6, (const struct in6_addr *)ip)) {
            struct in6_addr expired_ip6 = ban->addr.ipv6;
            /* 取消 per-entry 过期定时器（非 _sync，避免持锁死锁） */
            timer_delete(&ban->expire_timer);
            active_bans_del(fw, ban);
            hlist_del_rcu(&ban->hash);
            atomic_dec(&fw->ban_count);
            call_rcu(&ban->rcu_head, free_ban_entry_rcu);
            removed++;
            fw_netlink_send_ban_state_change(
              FW_AF_INET6, &expired_ip6, 2, 0, "whitelist", NULL);
          }
        }
        spin_unlock_bh(&fw->ban_locks_ipv6[bkt]);
      } else {
        /* CIDR：RCU 收集 + 桶锁解封（小批量循环，控制栈帧） */
        struct in6_addr batch6[16];
        int n, i, pass_removed;
        do {
          n = 0;
          pass_removed = 0;
          rcu_read_lock();
          list_for_each_entry_rcu(ban, &fw->active_bans_list, ban_node) {
            if (ban->af != FW_AF_INET6)
              continue;
            if (!ipv6_prefix_equal(&ban->addr.ipv6, (const struct in6_addr *)ip, prefix))
              continue;
            if (n < (int)ARRAY_SIZE(batch6))
              batch6[n++] = ban->addr.ipv6;
          }
          rcu_read_unlock();
          for (i = 0; i < n; i++) {
            u32 bkt = hash_ipv6(&batch6[i]);
            struct hlist_node *tmp2;
            spin_lock_bh(&fw->ban_locks_ipv6[bkt]);
            hlist_for_each_entry_safe(ban, tmp2, &fw->ban_table_ipv6[bkt], hash) {
              if (ban->af != FW_AF_INET6 || !ipv6_addr_equal(&ban->addr.ipv6, &batch6[i]))
                continue;
              {
                struct in6_addr expired_ip6 = ban->addr.ipv6;
                timer_delete(&ban->expire_timer);
                active_bans_del(fw, ban);
                hlist_del_rcu(&ban->hash);
                atomic_dec(&fw->ban_count);
                call_rcu(&ban->rcu_head, free_ban_entry_rcu);
                pass_removed++;
                removed++;
                fw_netlink_send_ban_state_change(
                  FW_AF_INET6, &expired_ip6, 2, 0, "whitelist", NULL);
              }
            }
            spin_unlock_bh(&fw->ban_locks_ipv6[bkt]);
          }
        } while (n == (int)ARRAY_SIZE(batch6) && pass_removed > 0);
      }
    }

    if (removed > 0) {
      pr_info("白名单添加后解除 %d 个匹配封禁\n", removed);
    }
  }

  /* 事件推送：通知守护进程白名单已添加 */
  fw_netlink_send_whitelist_state_change(af, ip, (u8)prefix_len, 1, dev_name);

  return 0;
}
EXPORT_SYMBOL_GPL(add_whitelist_entry);

int remove_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip, int prefix_len) {
  struct whitelist_entry *entry;
  u32 bkt;
  int found = 0;
  char removed_dev[16] = { 0 };

  spin_lock(&fw->whitelist_lock);
  if (af == FW_AF_INET6) {
    struct in6_addr norm;
    if (prefix_len < 0 || prefix_len > 128) {
      spin_unlock(&fw->whitelist_lock);
      return -EINVAL;
    }
    ipv6_addr_prefix(&norm, (const struct in6_addr *)ip, prefix_len);
    bkt = hash_wl_ipv6(&norm);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv6[bkt], hash) {
      if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, &norm) &&
          entry->mask.prefix_len == (u8)prefix_len) {
        /* 保存设备名（call_rcu 后另一 CPU 可能立即释放） */
        memcpy(removed_dev, entry->device_name, sizeof(removed_dev));
        hlist_del_rcu(&entry->hash);
        /* 从子网链表中移除（非精确匹配条目） */
        if (prefix_len < 128)
          list_del_rcu(&entry->subnet_node);
        atomic_dec(&fw->whitelist_count);
        found = 1;
        call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
        break;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    /* 计算 IPv4 子网掩码：prefix_len=0 时为 0，否则为高位 prefix_len 个 1
     * 使用 htonl(~0U << (32 - prefix_len)) 避免 1ULL << 32 的未定义行为 */
    __be32 mask4 = prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len));
    __be32 net_ipv4 = ipv4 & mask4;
    bkt = hash_ipv4(net_ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->addr.ipv4 == net_ipv4 && entry->mask.ipv4_mask == mask4) {
        /* 保存设备名（call_rcu 后另一 CPU 可能立即释放） */
        memcpy(removed_dev, entry->device_name, sizeof(removed_dev));
        hlist_del_rcu(&entry->hash);
        /* 从子网链表中移除（非精确匹配条目） */
        if (mask4 != 0xFFFFFFFF)
          list_del_rcu(&entry->subnet_node);
        atomic_dec(&fw->whitelist_count);
        found = 1;
        call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
        break;
      }
    }
  }
  spin_unlock(&fw->whitelist_lock);

  if (found) {
    /* 事件推送：通知守护进程白名单已移除 */
    fw_netlink_send_whitelist_state_change(af, ip, (u8)prefix_len, 2, removed_dev);
    return 0;
  }
  return -ENOENT;
}
EXPORT_SYMBOL_GPL(remove_whitelist_entry);

bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip) {
  struct whitelist_entry *entry;
  u32 bkt;

  rcu_read_lock();

  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)ip;
    bkt = hash_wl_ipv6(ip6);
    hlist_for_each_entry_rcu(entry, &fw->whitelist_table_ipv6[bkt], hash) {
      if (entry->af == af && entry->mask.prefix_len == 128 &&
          ipv6_addr_equal(&entry->addr.ipv6, ip6)) {
        rcu_read_unlock();
        return true;
      }
    }
    /* 子网匹配：使用专用子网链表加速前缀匹配 */
    list_for_each_entry_rcu(entry, &fw->ipv6_subnet_wl, subnet_node) {
      u8 prefix = READ_ONCE(entry->mask.prefix_len);
      if (ipv6_prefix_equal(ip6, &entry->addr.ipv6, prefix)) {
        rcu_read_unlock();
        return true;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    bkt = hash_ipv4(ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry_rcu(entry, &fw->whitelist_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->mask.ipv4_mask == 0xFFFFFFFF && entry->addr.ipv4 == ipv4) {
        rcu_read_unlock();
        return true;
      }
    }
    /* 子网匹配：使用专用子网链表加速前缀匹配 */
    list_for_each_entry_rcu(entry, &fw->ipv4_subnet_wl, subnet_node) {
      __be32 wl_mask = READ_ONCE(entry->mask.ipv4_mask);
      __be32 wl_ip = READ_ONCE(entry->addr.ipv4);
      if ((ipv4 & wl_mask) == (wl_ip & wl_mask)) {
        rcu_read_unlock();
        return true;
      }
    }
  }

  rcu_read_unlock();
  return false;
}
EXPORT_SYMBOL_GPL(is_in_whitelist);
