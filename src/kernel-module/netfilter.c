/*
 * netfilter.c - Netfilter 钩子
 *
 * 包含 IPv4 netfilter 钩子函数实现，用于数据包过滤。
 */

#include "firewall.h"
#include <linux/if_ether.h>

/* 内核空间缺少 IP 分片标志宏定义（用户空间 <netinet/ip.h> 中定义） */
#define IP_MF 0x2000     /* 更多分片标志 */
#define IP_OFFSET 0x1FFF /* 分片偏移掩码 */

/* 外部变量声明 */
extern struct firewall_info fw_info;

/*
 * nf_hook_func_ipv4 - IPv4 的 netfilter 钩子函数
 */
static unsigned int nf_hook_func_ipv4(void *priv, struct sk_buff *skb,
                                      const struct nf_hook_state *state) {
  struct iphdr iph_copy;
  struct iphdr *iph;
  __be32 src_ip;
  unsigned long now;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  unsigned int bkt;
  bool is_whitelisted = false;
  bool is_banned = false;

  if (unlikely(!skb))
    return NF_ACCEPT;

  if (unlikely(skb->len < sizeof(struct iphdr)))
    return NF_ACCEPT;

  if (unlikely(!skb_network_header(skb)))
    return NF_ACCEPT;

  if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
    return NF_ACCEPT;

  iph = skb_header_pointer(skb, 0, sizeof(iph_copy), &iph_copy);
  if (!iph)
    return NF_ACCEPT;

  if (iph->version != 4)
    return NF_ACCEPT;

  if (iph->ihl < 5)
    return NF_ACCEPT;

  if (iph->ihl > 15)
    return NF_ACCEPT;

  if (iph->ihl * 4 > ntohs(iph->tot_len))
    return NF_ACCEPT;

  if (ntohs(iph->tot_len) < sizeof(struct iphdr))
    return NF_ACCEPT;

  if (ntohs(iph->tot_len) > skb->len)
    return NF_ACCEPT;

  if (ntohs(iph->tot_len) > ETH_DATA_LEN) {
    /* 记录可疑数据包但仍为封禁目的处理它 */
  }

  /* 检查分片标志（主机字节序比较） */
  {
    __be16 frag_off = iph->frag_off;
    if ((ntohs(frag_off) & IP_MF) || (ntohs(frag_off) & IP_OFFSET)) {
      fw_pr_warn_ratelimited(
          "Fragmented packet from %pI4 passed through (cannot inspect payload)",
          &iph->saddr);
      return NF_ACCEPT;
    }
  }

  src_ip = iph->saddr;

  if (unlikely(src_ip == 0 || src_ip == 0xFFFFFFFF ||
               (ntohl(src_ip) & 0xFF000000) == 0x7F000000 ||
               (ntohl(src_ip) & 0xF0000000) == 0xE0000000 ||
               (ntohl(src_ip) & 0xFF000000) == 0x00000000)) {
    return NF_ACCEPT;
  }

  if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP &&
      iph->protocol != IPPROTO_ICMP) {
    /* 允许其他协议但记录以供调试 */
  }

  now = jiffies;

  if (unlikely(atomic_read(&fw_info.shutting_down)))
    return NF_ACCEPT;

  rcu_read_lock();

  if (unlikely(atomic_read(&fw_info.shutting_down))) {
    rcu_read_unlock();
    return NF_ACCEPT;
  }

  /* 白名单查找优化：
   * 1. 先尝试哈希查找精确匹配的 /32 条目（O(1)）
   * 2. 如果未找到，再遍历查找子网匹配 */
  {
    int wl_iterations = 0;

    /* 步骤 1：使用哈希查找精确匹配的 /32 条目 */
    hash_for_each_possible_rcu(fw_info.whitelist_table, wl_entry, hash,
                               src_ip) {
      if (wl_entry->mask == 0xFFFFFFFF && wl_entry->ip == src_ip) {
        is_whitelisted = true;
        break;
      }
    }

    /* 步骤 2：/32 未匹配时，遍历全表检查子网匹配 */
    if (!is_whitelisted) {
      hash_for_each_rcu(fw_info.whitelist_table, bkt, wl_entry, hash) {
        if (++wl_iterations > MAX_WHITELIST_ENTRIES) {
          fw_pr_warn_ratelimited(
              "whitelist traversal limit reached, possible misconfiguration");
          break;
        }
        if (wl_entry->mask != 0xFFFFFFFF &&
            (src_ip & wl_entry->mask) == (wl_entry->ip & wl_entry->mask)) {
          is_whitelisted = true;
          break;
        }
      }
    }
  }

  if (unlikely(is_whitelisted)) {
    rcu_read_unlock();
    return NF_ACCEPT;
  }

  hash_for_each_possible_rcu(fw_info.ban_table, entry, hash, src_ip) {
    if (compare_ips(entry->ip, src_ip)) {
      if (READ_ONCE(entry->is_permanent) ||
          time_before(now, READ_ONCE(entry->unban_time))) {
        is_banned = true;
      } else {
        is_banned = false;
      }
      break;
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

/* Netfilter 钩子操作结构 */
struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook = nf_hook_func_ipv4,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};
