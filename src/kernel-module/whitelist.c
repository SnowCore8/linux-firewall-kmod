/*
 * whitelist.c - 白名单管理 (支持 IPv4/IPv6)
 */

#include "firewall.h"
#include <linux/list.h>

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

  /* 快速容量检查（无锁，可能 stale 但可接受） */
  if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
    return -ENOSPC;
  }

  new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
  if (!new_entry) {
    return -ENOMEM;
  }

  new_entry->af = af;
  if (af == FW_AF_INET6) {
    new_entry->addr.ipv6 = *(const struct in6_addr *)ip;
    /* 验证 IPv6 前缀长度合法性（0-128） */
    if (prefix_len < 0 || prefix_len > 128) {
      kfree(new_entry);
      return -EINVAL;
    }
    new_entry->mask.prefix_len = (u8)prefix_len;
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    __be32 msk = *(__be32 *)mask;
    /* 验证 IPv4 子网掩码合法性（必须为连续的 1 后跟连续的 0） */
    if (msk != 0 && msk != 0xFFFFFFFF) {
      __be32 inverted = ~ntohl(msk);
      /* 检查 inverted 是否为 2 的幂减 1（连续的低位 1 表示合法掩码） */
      if ((inverted & (inverted + 1)) != 0) {
        kfree(new_entry);
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
    bkt = hash_min(new_entry->addr.ipv4, WHITELIST_HASH_BITS);
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

  if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
    spin_unlock(&fw->whitelist_lock);
    kfree(new_entry);
    return -ENOSPC;
  }

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

  return 0;
}
EXPORT_SYMBOL_GPL(add_whitelist_entry);

int remove_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip, int prefix_len) {
  struct whitelist_entry *entry;
  u32 bkt;
  int found = 0;

  spin_lock(&fw->whitelist_lock);
  if (af == FW_AF_INET6) {
    bkt = hash_wl_ipv6((const struct in6_addr *)ip);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv6[bkt], hash) {
      if (entry->af == af &&
          ipv6_addr_equal(&entry->addr.ipv6, (const struct in6_addr *)ip) &&
          entry->mask.prefix_len == (u8)prefix_len) {
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
    __be32 mask4 = prefix_len == 0 ? 0 : htonl(~((1ULL << (32 - prefix_len)) - 1));
    __be32 net_ipv4 = ipv4 & mask4;
    bkt = hash_min(net_ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->addr.ipv4 == net_ipv4 && entry->mask.ipv4_mask == mask4) {
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
    bkt = hash_min(ipv4, WHITELIST_HASH_BITS);
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
