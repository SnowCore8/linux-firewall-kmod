/*
 * netfilter.c - Netfilter 钩子 (支持 IPv4/IPv6)
 */

#include "firewall.h"
#include <linux/if_ether.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

static unsigned int handle_ban_check(u8 af, const void *src_ip) {
  unsigned long now;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  unsigned int bkt;
  bool is_whitelisted = false;
  bool is_banned = false;

  if (unlikely(atomic_read(&fw_info.shutting_down)))
    return NF_ACCEPT;

  now = jiffies;
  rcu_read_lock();

  if (unlikely(atomic_read(&fw_info.shutting_down))) {
    rcu_read_unlock();
    return NF_ACCEPT;
  }

  if (af == FW_AF_INET6) {
    struct in6_addr *ip6 = (struct in6_addr *)src_ip;
    u32 wl_bkt = jhash(ip6, sizeof(struct in6_addr), fw_hash_seed) &
                 ((1 << WHITELIST_HASH_BITS) - 1);

    /* 精确匹配 */
    hlist_for_each_entry_rcu(wl_entry, &fw_info.whitelist_table_ipv6[wl_bkt],
                             hash) {
      if (wl_entry->mask.prefix_len == 128 &&
          ipv6_addr_equal(ip6, &wl_entry->addr.ipv6)) {
        is_whitelisted = true;
        break;
      }
    }

    /* 子网匹配 */
    if (!is_whitelisted) {
      hash_for_each_rcu(fw_info.whitelist_table_ipv6, bkt, wl_entry, hash) {
        u8 prefix = READ_ONCE(wl_entry->mask.prefix_len);
        if (prefix < 128 &&
            ipv6_prefix_equal(ip6, &wl_entry->addr.ipv6, prefix)) {
          is_whitelisted = true;
          break;
        }
      }
    }

    if (!is_whitelisted) {
      u32 ban_bkt = jhash(ip6, sizeof(struct in6_addr), fw_hash_seed) &
                    ((1 << BAN_HASH_BITS) - 1);
      hlist_for_each_entry_rcu(entry, &fw_info.ban_table_ipv6[ban_bkt], hash) {
        if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, ip6)) {
          if (READ_ONCE(entry->is_permanent) ||
              time_before(now, READ_ONCE(entry->unban_time)))
            is_banned = true;
          break;
        }
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)src_ip;
    u32 wl_bkt = hash_min(ipv4, WHITELIST_HASH_BITS);

    hlist_for_each_entry_rcu(wl_entry, &fw_info.whitelist_table_ipv4[wl_bkt],
                             hash) {
      if (wl_entry->mask.ipv4_mask == 0xFFFFFFFF &&
          wl_entry->addr.ipv4 == ipv4) {
        is_whitelisted = true;
        break;
      }
    }

    if (!is_whitelisted) {
      hash_for_each_rcu(fw_info.whitelist_table_ipv4, bkt, wl_entry, hash) {
        __be32 wl_mask = READ_ONCE(wl_entry->mask.ipv4_mask);
        if (wl_mask != 0xFFFFFFFF) {
          __be32 wl_ip = READ_ONCE(wl_entry->addr.ipv4);
          if ((ipv4 & wl_mask) == (wl_ip & wl_mask)) {
            is_whitelisted = true;
            break;
          }
        }
      }
    }

    if (!is_whitelisted) {
      u32 ban_bkt = hash_min(ipv4, BAN_HASH_BITS);
      hlist_for_each_entry_rcu(entry, &fw_info.ban_table_ipv4[ban_bkt], hash) {
        if (entry->af == af && entry->addr.ipv4 == ipv4) {
          if (READ_ONCE(entry->is_permanent) ||
              time_before(now, READ_ONCE(entry->unban_time)))
            is_banned = true;
          break;
        }
      }
    }
  }

  rcu_read_unlock();

  if (unlikely(is_banned)) {
    atomic_inc(&fw_info.packets_dropped);
    return NF_DROP;
  }

  atomic_inc(&fw_info.packets_accepted);
  return NF_ACCEPT;
}

static unsigned int nf_hook_func_ipv4(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
  struct iphdr iph_copy;
  struct iphdr *iph;
  __be32 src_ip;

  if (unlikely(!skb) || unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
    return NF_ACCEPT;

  iph = skb_header_pointer(skb, 0, sizeof(iph_copy), &iph_copy);
  if (!iph || iph->version != 4 || iph->ihl < 5 || iph->ihl > 15)
    return NF_ACCEPT;

  if (iph->ihl * 4 > ntohs(iph->tot_len))
    return NF_ACCEPT;

  {
    __be16 frag_off = iph->frag_off;
    if ((ntohs(frag_off) & IP_MF) || (ntohs(frag_off) & IP_OFFSET)) {
      fw_pr_warn_ratelimited("Fragmented packet from %pI4 passed through",
                             &iph->saddr);
      return NF_ACCEPT;
    }
  }

  src_ip = iph->saddr;
  if (unlikely(src_ip == 0 || src_ip == 0xFFFFFFFF ||
               (ntohl(src_ip) & 0xFF000000) == 0x7F000000 ||
               (ntohl(src_ip) & 0xF0000000) == 0xE0000000 ||
               (ntohl(src_ip) & 0xFF000000) == 0x00000000))
    return NF_ACCEPT;

  return handle_ban_check(FW_AF_INET, &src_ip);
}

static unsigned int nf_hook_func_ipv6(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
  struct ipv6hdr iph6_copy;
  struct ipv6hdr *iph6;
  struct in6_addr src_ip;

  if (unlikely(!skb) || unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
    return NF_ACCEPT;

  iph6 = skb_header_pointer(skb, 0, sizeof(iph6_copy), &iph6_copy);
  if (!iph6 || iph6->version != 6)
    return NF_ACCEPT;

  src_ip = iph6->saddr;
  if (unlikely(ipv6_addr_any(&src_ip) || ipv6_addr_loopback(&src_ip) ||
               ipv6_addr_is_multicast(&src_ip)))
    return NF_ACCEPT;

  if (unlikely((src_ip.s6_addr[0] == 0xFE) &&
               ((src_ip.s6_addr[1] & 0xC0) == 0x80)))
    return NF_ACCEPT;

  return handle_ban_check(FW_AF_INET6, &src_ip);
}

struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook = nf_hook_func_ipv4,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};

struct nf_hook_ops nf_ops_ipv6 __read_mostly = {
    .hook = nf_hook_func_ipv6,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};
