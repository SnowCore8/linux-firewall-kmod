/*
 * whitelist.c - 白名单管理 (支持 IPv4/IPv6)
 */

#include "firewall.h"

extern u32 fw_hash_seed;

static u32 hash_wl_ipv6(const struct in6_addr *addr) {
  return jhash(addr, sizeof(struct in6_addr), fw_hash_seed) &
         ((1 << WHITELIST_HASH_BITS) - 1);
}

int add_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                        const void *mask, int prefix_len,
                        const char *dev_name) {
  struct whitelist_entry *new_entry;
  struct whitelist_entry *tmp_entry;
  u32 bkt;

  FW_DEBUG(1, "ENTRY: add_whitelist_entry(af=%d, prefix=%d, dev=%s)", af,
           prefix_len, dev_name ?: "null");

  /* Fast-path capacity check (lockless, may be stale) */
  if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
    fw_pr_warn("Whitelist full, cannot add entry");
    return -ENOSPC;
  }

  new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
  if (!new_entry) {
    fw_pr_warn("Failed to allocate memory for whitelist entry");
    return -ENOMEM;
  }

  new_entry->af = af;
  if (af == FW_AF_INET6) {
    new_entry->addr.ipv6 = *(const struct in6_addr *)ip;
    new_entry->mask.prefix_len = (u8)prefix_len;
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    __be32 msk = *(__be32 *)mask;
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
    fw_pr_warn("Whitelist full, cannot add entry");
    return -ENOSPC;
  }

  if (af == FW_AF_INET6)
    hash_add_rcu(fw->whitelist_table_ipv6, &new_entry->hash,
                 hash_wl_ipv6(&new_entry->addr.ipv6));
  else
    hash_add_rcu(fw->whitelist_table_ipv4, &new_entry->hash,
                 new_entry->addr.ipv4);
  atomic_inc(&fw->whitelist_count);
  spin_unlock(&fw->whitelist_lock);

  if (af == FW_AF_INET6)
    fw_pr_info("Whitelisted %pI6/%d on %s", &new_entry->addr.ipv6,
               new_entry->mask.prefix_len, dev_name ?: "unknown");
  else
    fw_pr_info("Whitelisted %pI4/%d on %s", &new_entry->addr.ipv4,
               inet_mask_len(new_entry->mask.ipv4_mask), dev_name ?: "unknown");
  return 0;
}
EXPORT_SYMBOL_GPL(add_whitelist_entry);

int remove_whitelist_entry(struct firewall_info *fw, u8 af, const void *ip,
                           int prefix_len) {
  struct whitelist_entry *entry;
  u32 bkt;
  int found = 0;

  FW_DEBUG(1, "ENTRY: remove_whitelist_entry(af=%d, prefix=%d)", af,
           prefix_len);

  spin_lock(&fw->whitelist_lock);
  if (af == FW_AF_INET6) {
    bkt = hash_wl_ipv6((const struct in6_addr *)ip);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv6[bkt], hash) {
      if (entry->af == af &&
          ipv6_addr_equal(&entry->addr.ipv6, (const struct in6_addr *)ip) &&
          entry->mask.prefix_len == (u8)prefix_len) {
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->whitelist_count);
        found = 1;
        call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
        break;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    __be32 mask4 =
        prefix_len == 0 ? 0 : htonl(~((1ULL << (32 - prefix_len)) - 1));
    __be32 net_ipv4 = ipv4 & mask4;
    bkt = hash_min(net_ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry(entry, &fw->whitelist_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->addr.ipv4 == net_ipv4 &&
          entry->mask.ipv4_mask == mask4) {
        hlist_del_rcu(&entry->hash);
        atomic_dec(&fw->whitelist_count);
        found = 1;
        call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
        break;
      }
    }
  }
  spin_unlock(&fw->whitelist_lock);

  char ip_str[INET6_STR_LEN];
  ip_to_str(af, ip, ip_str, sizeof(ip_str));
  if (found) {
    fw_pr_info("Removed %s from whitelist", ip_str);
    return 0;
  }
  fw_pr_warn("%s not found in whitelist", ip_str);
  return -ENOENT;
}
EXPORT_SYMBOL_GPL(remove_whitelist_entry);

bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip) {
  struct whitelist_entry *entry;
  u32 bkt;

  FW_DEBUG(3, "ENTRY: is_in_whitelist(af=%d)", af);
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
    /* 子网匹配 */
    hash_for_each_rcu(fw->whitelist_table_ipv6, bkt, entry, hash) {
      u8 prefix = READ_ONCE(entry->mask.prefix_len);
      if (prefix < 128 && ipv6_prefix_equal(ip6, &entry->addr.ipv6, prefix)) {
        rcu_read_unlock();
        return true;
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)ip;
    bkt = hash_min(ipv4, WHITELIST_HASH_BITS);
    hlist_for_each_entry_rcu(entry, &fw->whitelist_table_ipv4[bkt], hash) {
      if (entry->af == af && entry->mask.ipv4_mask == 0xFFFFFFFF &&
          entry->addr.ipv4 == ipv4) {
        rcu_read_unlock();
        return true;
      }
    }
    hash_for_each_rcu(fw->whitelist_table_ipv4, bkt, entry, hash) {
      __be32 wl_mask = READ_ONCE(entry->mask.ipv4_mask);
      if (wl_mask != 0xFFFFFFFF) {
        __be32 wl_ip = READ_ONCE(entry->addr.ipv4);
        if ((ipv4 & wl_mask) == (wl_ip & wl_mask)) {
          rcu_read_unlock();
          return true;
        }
      }
    }
  }

  rcu_read_unlock();
  return false;
}
EXPORT_SYMBOL_GPL(is_in_whitelist);
