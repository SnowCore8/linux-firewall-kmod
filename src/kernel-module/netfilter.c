/*
 * netfilter.c - Netfilter 钩子 (支持 IPv4/IPv6)
 */

#include "firewall.h"
#include <linux/if_ether.h>
#include <linux/ipv6.h>

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

/* R9-1 修复：使用 per-CPU 计数器避免热路径中的 atomic_inc 缓存一致性开销。
 * 每个 CPU 维护本地计数器，每达到批次阈值时刷新到全局 atomic 计数器。 */
static DEFINE_PER_CPU(struct fw_per_cpu_stats, fw_cpu_stats);

/* 刷新 per-CPU 计数器到全局 atomic 计数器（cleanup.c 中也会调用） */
void fw_flush_cpu_stats(void) {
  struct fw_per_cpu_stats *stats;
  u64 acc, drop;

  stats = this_cpu_ptr(&fw_cpu_stats);
  acc = READ_ONCE(stats->packets_accepted);
  drop = READ_ONCE(stats->packets_dropped);

  if (acc > 0) {
    atomic64_add(acc, &fw_info.packets_accepted);
    WRITE_ONCE(stats->packets_accepted, 0);
  }
  if (drop > 0) {
    atomic64_add(drop, &fw_info.packets_dropped);
    WRITE_ONCE(stats->packets_dropped, 0);
  }
}

static unsigned int handle_ban_check(u8 af, const void *src_ip) {
  unsigned long now;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
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
    u32 ip6_hash = jhash(ip6, sizeof(struct in6_addr), fw_hash_seed);
    u32 wl_bkt = ip6_hash & ((1 << WHITELIST_HASH_BITS) - 1);

    /* 精确匹配（/128 前缀）：使用与封禁表相同的哈希策略，
     * 直接定位到对应桶，O(1) 查找。
     * 子网匹配（前缀 < 128）：由于哈希基于完整 IP 而非前缀，
     * 必须遍历所有桶进行前缀比较，O(n) 查找。
     * 这是哈希桶设计的固有限制：不同前缀长度的子网条目
     * 可能分布在不同的桶中，无法通过单一哈希定位。 */
    hlist_for_each_entry_rcu(wl_entry, &fw_info.whitelist_table_ipv6[wl_bkt], hash) {
      if (wl_entry->mask.prefix_len == 128) {
        /* struct in6_addr 16 字节，超出 READ_ONCE 支持范围。
         * 安全保证：白名单条目在 RCU 发布后不可变（仅增删，不修改），
         * 因此 RCU reader 要么看到完整旧条目，要么看到完整新条目。
         * 使用 barrier() 防止编译器重排序逐个 u32 读取。 */
        const __be32 *src = (__be32 *)wl_entry->addr.ipv6.s6_addr;
        struct in6_addr wl_addr;

        wl_addr.s6_addr32[0] = READ_ONCE(((__be32 *)src)[0]);
        wl_addr.s6_addr32[1] = READ_ONCE(((__be32 *)src)[1]);
        wl_addr.s6_addr32[2] = READ_ONCE(((__be32 *)src)[2]);
        /* 编译器屏障：确保前 3 个 u32 读取完成后才读取第 4 个 */
        barrier();
        wl_addr.s6_addr32[3] = READ_ONCE(((__be32 *)src)[3]);
        if (ipv6_addr_equal(ip6, &wl_addr)) {
          is_whitelisted = true;
          break;
        }
      }
    }

    /* 子网匹配：R9-3 优化 - 使用专用子网链表，避免遍历所有 64 个哈希桶 */
    if (!is_whitelisted) {
      struct whitelist_entry *wl_entry;
      list_for_each_entry_rcu(wl_entry, &fw_info.ipv6_subnet_wl, subnet_node) {
        u8 prefix = READ_ONCE(wl_entry->mask.prefix_len);
        const __be32 *src = (__be32 *)wl_entry->addr.ipv6.s6_addr;
        struct in6_addr wl_addr;

        wl_addr.s6_addr32[0] = READ_ONCE(((__be32 *)src)[0]);
        wl_addr.s6_addr32[1] = READ_ONCE(((__be32 *)src)[1]);
        wl_addr.s6_addr32[2] = READ_ONCE(((__be32 *)src)[2]);
        barrier();
        wl_addr.s6_addr32[3] = READ_ONCE(((__be32 *)src)[3]);
        if (ipv6_prefix_equal(ip6, &wl_addr, prefix)) {
          is_whitelisted = true;
          break;
        }
      }
    }

    if (!is_whitelisted) {
      u32 ban_bkt = ip6_hash & ((1 << BAN_HASH_BITS) - 1);
      hlist_for_each_entry_rcu(entry, &fw_info.ban_table_ipv6[ban_bkt], hash) {
        if (entry->af == af && ipv6_addr_equal(&entry->addr.ipv6, ip6)) {
          if (READ_ONCE(entry->is_permanent) || time_before(now, READ_ONCE(entry->unban_time)))
            is_banned = true;
          break;
        }
      }
    }
  } else {
    __be32 ipv4 = *(__be32 *)src_ip;
    u32 wl_bkt = hash_min(ipv4, WHITELIST_HASH_BITS);

    hlist_for_each_entry_rcu(wl_entry, &fw_info.whitelist_table_ipv4[wl_bkt], hash) {
      if (wl_entry->mask.ipv4_mask == 0xFFFFFFFF && wl_entry->addr.ipv4 == ipv4) {
        is_whitelisted = true;
        break;
      }
    }

    if (!is_whitelisted) {
      struct whitelist_entry *wl_entry;
      /* R9-3 优化：使用专用子网链表，避免遍历所有 64 个哈希桶 */
      list_for_each_entry_rcu(wl_entry, &fw_info.ipv4_subnet_wl, subnet_node) {
        __be32 wl_mask = READ_ONCE(wl_entry->mask.ipv4_mask);
        __be32 wl_ip = READ_ONCE(wl_entry->addr.ipv4);
        if ((ipv4 & wl_mask) == (wl_ip & wl_mask)) {
          is_whitelisted = true;
          break;
        }
      }
    }

    if (!is_whitelisted) {
      u32 ban_bkt = hash_min(ipv4, BAN_HASH_BITS);
      hlist_for_each_entry_rcu(entry, &fw_info.ban_table_ipv4[ban_bkt], hash) {
        if (entry->af == af && entry->addr.ipv4 == ipv4) {
          if (READ_ONCE(entry->is_permanent) || time_before(now, READ_ONCE(entry->unban_time)))
            is_banned = true;
          break;
        }
      }
    }
  }

  rcu_read_unlock();

  if (unlikely(is_banned)) {
    struct fw_per_cpu_stats *stats = this_cpu_ptr(&fw_cpu_stats);
    stats->packets_dropped++;
    if (unlikely(stats->packets_dropped >= FW_PER_CPU_BATCH_SIZE))
      fw_flush_cpu_stats();
    return NF_DROP;
  }

  {
    struct fw_per_cpu_stats *stats = this_cpu_ptr(&fw_cpu_stats);
    stats->packets_accepted++;
    if (unlikely(stats->packets_accepted >= FW_PER_CPU_BATCH_SIZE))
      fw_flush_cpu_stats();
  }
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
      /* 安全：分片包可能绕过基于完整报头的封禁检查，直接丢弃 */
      return NF_DROP;
    }
  }

  src_ip = iph->saddr;
  if (unlikely(src_ip == 0 || src_ip == 0xFFFFFFFF || (ntohl(src_ip) & 0xFF000000) == 0x7F000000 ||
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
  u8 nexthdr;
  struct ipv6_opt_hdr opt;
  unsigned int offset;

  if (unlikely(!skb) || unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
    return NF_ACCEPT;

  iph6 = skb_header_pointer(skb, 0, sizeof(iph6_copy), &iph6_copy);
  if (!iph6 || iph6->version != 6)
    return NF_ACCEPT;

  /* 检查 IPv6 分片扩展头：分片包可能绕过基于完整报头的封禁检查 */
  nexthdr = iph6->nexthdr;
  offset = sizeof(struct ipv6hdr);
  {
    /* 修复：添加最大扩展头遍历次数限制，防止恶意数据包导致 CPU 消耗过多 */
    int ext_hdr_depth = 0;
    const int MAX_EXT_HDR_DEPTH = 8;

    while (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING ||
           nexthdr == NEXTHDR_DEST || nexthdr == NEXTHDR_AUTH) {
      /* 修复：深度限制，防止循环或过多扩展头 */
      if (++ext_hdr_depth > MAX_EXT_HDR_DEPTH) {
        return NF_DROP;
      }
      if (!pskb_may_pull(skb, offset + sizeof(struct ipv6_opt_hdr)))
        break;
      if (skb_header_pointer(skb, offset, sizeof(opt), &opt) == NULL)
        break;
      offset += ipv6_optlen(&opt);
      nexthdr = opt.nexthdr;
    }
  }
  if (nexthdr == NEXTHDR_FRAGMENT) {
    /* 安全：分片包可能绕过封禁检查，直接丢弃 */
    return NF_DROP;
  }

  src_ip = iph6->saddr;
  if (unlikely(ipv6_addr_any(&src_ip) || ipv6_addr_loopback(&src_ip) ||
               ipv6_addr_is_multicast(&src_ip)))
    return NF_ACCEPT;

  if (unlikely((src_ip.s6_addr[0] == 0xFE) && ((src_ip.s6_addr[1] & 0xC0) == 0x80)))
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
