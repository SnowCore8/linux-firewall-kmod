// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_hook.c - netfilter 钩子注册与报文解析
 *
 * 注册面：只挂 init_net 的 NF_INET_PRE_ROUTING，IPv4/IPv6 各一个钩子，
 * 优先级保持旧实现的取值 NF_IP_PRI_FILTER - 1（在 filter 表之前看到报文）。
 * 钩子只挂 init_net，因此容器/网络命名空间内 veth 侧发出的流量在 init_net 侧
 * 被本钩子看到——`scripts/bench/` 的跨 netns 打流方法依赖这一点。
 *
 * 与旧实现（netfilter.c）的关键差别：
 *
 *   1. RCU 临界区只进一次。旧实现分三处 rcu_read_lock（白名单/封禁判定与
 *      速率违规判定各自进出），新实现把三张表的判定放进 fw_ban_check() 的
 *      同一个临界区里读完。
 *   2. 热路径零自旋锁：端口去重集合落在 per-CPU 槽位（见 fw_rate.h），不再
 *      为了更新 seen_ports 去取速率桶锁。
 *   3. 热路径零共享 cache line 写：统计、直方图、UDP/ICMP 分布全部落本 CPU。
 *   4. 判定顺序固定为
 *        lo 接口进入      ⇒ 放行（环回流量不是外来流量，入口即豁免、不计统计）
 *        白名单命中       ⇒ 放行（永不封禁，跳过速率判定）
 *        本机地址命中     ⇒ 放行（跳过速率判定）
 *        封禁表命中       ⇒ 丢包
 *        皆不命中且 DDoS 开启且目的端口受保护 ⇒ 速率判定，违规即自决封禁并丢包
 *      「目的端口受保护」= 该端口在本机对外监听集合中（由 daemon 扫描 procfs 的
 *      net 表后经 netlink 下发，见 fw_ports.c）。这是**收窄速率判定的作用面**：公网能
 *      打到的只有对外监听端口，防护聚焦于此；内部端口不参与速率判定以免误封。
 *      门控只作用于速率判定分支——封禁表判定对其余端口照常生效，无端口报文
 *      （ICMP / 非首片）一律视为受保护，见 fw_ports_observe()。
 *      lo 接口豁免与旧实现一致（旧实现在入口跳过 IFF_LOOPBACK）；两者互补：
 *      接口侧管「从 lo 进入的流量」，地址侧（源地址合法性）管「从外部接口
 *      伪造回环源」，重写初期只保留了地址侧，这里补回接口侧。
 *      本机地址判定**必须**先于封禁表判定：新设计不再把接口地址写进白名单
 *      （本机豁免由 fw_local.c 承担），顺序颠倒会让本机地址被自己的封禁条目
 *      丢弃，违背契约「本机接口精确地址 ⇒ 直接放行」。
 *   5. TCP 标志异常丢包同时计入 packets_dropped。旧实现只计
 *      tcp_anomaly_dropped、不计 packets_dropped，与「丢弃」的语义不一致；
 *      新实现由 fw_stat_bump(s, false, true) 统一记账。
 *
 * 保留的旧行为：IPv6 扩展头遍历深度上限 8（超限即丢包）、ICMPv6 Echo Request
 * 映射为 IPPROTO_ICMP 让协议阈值覆盖 v6、skb->ip_summed == CHECKSUM_UNNECESSARY
 * 时跳过软件校验和、非首片传 protocol=0（无传输层头）、IPv6 分片路径同样记账。
 *
 * 记账位置与旧实现一致：源地址非法的报文不进任何表、也不计丢弃；TCP 标志异常
 * 的报文已计入直方图但不计全局流量（全局流量在异常判定之后累加）。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/netdevice.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "fw_ban.h"
#include "fw_local.h"
#include "fw_netlink.h"
#include "fw_ports.h"
#include "fw_rate.h"
#include "fw_stats.h"
#include "fw_wl.h"

/* IPv6 扩展头遍历深度上限；超限视为畸变报文直接丢弃（与旧实现一致） */
#define FW_HOOK_MAX_EXT_HDR_DEPTH 8

/*
 * DDoS 自决封禁条目的 jail 名。
 * 旧实现只传 reason，由 daemon 侧按子串推断 jail，只能识别 "SYN flood" /
 * "UDP flood" / "ICMP flood" / "total rate"，"ACK flood" / "RST flood" /
 * "FIN flood" 会被归成 "api"。新实现显式给出 jail，不再依赖推断。
 */
#define FW_HOOK_DDOS_JAIL "ddos"

static unsigned int fw_hook_ipv4(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state);
static unsigned int fw_hook_ipv6(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state);

/* netfilter 钩子注册表：fw_main.c 在 init/exit 中按序注册与注销 */
struct nf_hook_ops nf_ops_ipv4 = {
  .hook = fw_hook_ipv4,
  .pf = NFPROTO_IPV4,
  .hooknum = NF_INET_PRE_ROUTING,
  .priority = NF_IP_PRI_FILTER - 1,
};

struct nf_hook_ops nf_ops_ipv6 = {
  .hook = fw_hook_ipv6,
  .pf = NFPROTO_IPV6,
  .hooknum = NF_INET_PRE_ROUTING,
  .priority = NF_IP_PRI_FILTER - 1,
};

/*
 * 判定主体：一次 RCU 临界区完成白名单 / 本机地址 / 封禁表 / 速率四步判定。
 * 返回 NF_ACCEPT / NF_DROP。
 *
 * 自决封禁在临界区**外**执行：fw_ban_try_add() 会取桶锁、分配内存并推送
 * netlink 事件，旧实现同样在 RCU 外做封禁（不在 RCU 读侧做重活）。
 */
static unsigned int fw_ban_check(u8 af, const void *src, u32 packet_len,
                                 u8 protocol, u8 tcp_flags, u16 dst_port) {
  const char *reason = NULL;
  bool banned = false;
  u64 pps = 0;

  rcu_read_lock();

  /* 关闭中的第二道判断：与钩子入口的第一道配对（双检），
   * 保证置位后不再有新的判定与封禁进入。 */
  if (unlikely(fw_is_shutting_down())) {
    rcu_read_unlock();
    return NF_ACCEPT;
  }

  /* 白名单与本机地址同为「放行且不做速率判定」的短路条件。
   * 端口门控只加在速率判定分支上：封禁表（jail 判定 / 手工下发）对所有端口
   * 一律生效，受保护端口位图收窄的只是「谁参与速率判定」。 */
  if (!fw_wl_lookup(af, src) && !fw_local_lookup(af, src)) {
    if (fw_ban_lookup(af, src)) {
      banned = true;
    } else if (likely(READ_ONCE(fw_ddos_detection)) && fw_ports_observe(dst_port)) {
      reason = fw_rate_observe(af, src, packet_len, protocol, tcp_flags, dst_port, &pps);
    }
  }

  rcu_read_unlock();

  if (unlikely(banned))
    return NF_DROP;

  if (unlikely(reason != NULL)) {
    /*
     * 自决封禁与 procfs / netlink 两条路径共用同一入口：白名单前检 +
     * 泛洪闸门 + 容量检查 + 事件推送一次到位。
     * duration 语义见 fw_types.h：0 表示走 fw_ban_time（旧实现把 0 当永久）。
     * 无论封禁是否成功都丢包：触发违规的报文本身就该丢。
     */
    u32 duration = READ_ONCE(fw_info.ddos_ban_duration);

    if (!duration)
      duration = READ_ONCE(fw_ban_time);

    fw_ban_try_add(af, src, duration, reason, FW_HOOK_DDOS_JAIL, true);
    fw_nl_send_ddos_event(af, src, reason, pps > 0xFFFFFFFFULL ? 0xFFFFFFFFU : (u32)pps);
    return NF_DROP;
  }

  return NF_ACCEPT;
}

static unsigned int fw_hook_ipv4(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
  struct iphdr iph_copy;
  const struct iphdr *iph;
  struct fw_stats_pcpu *s;
  __be32 src;
  u32 pkt_len;
  u8 proto, tcp_flags = 0, icmp_type = 0, icmp_code = 0;
  u16 dst_port = 0;
  bool is_fragment, is_udp = false, is_icmp = false;
  unsigned int verdict;

  (void)priv;
  (void)state;

  /* 退出中的第一道判断：置位后热路径直接放行，不让卸载被新流量拖住 */
  if (fw_is_shutting_down())
    return NF_ACCEPT;

  if (unlikely(!skb))
    return NF_ACCEPT;

  /* lo 接口默认豁免：环回接口上的流量不是外来流量（本机内部通信），
   * 在入口直接放行——不进任何表查询，也不计任何统计。 */
  if (unlikely(skb->dev && (skb->dev->flags & IFF_LOOPBACK)))
    return NF_ACCEPT;

  /* 报文合法性：长度 / 版本 / 头长 / 校验和，非法一律放行（不由防火墙处理） */
  if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
    return NF_ACCEPT;

  iph = skb_header_pointer(skb, 0, sizeof(iph_copy), &iph_copy);
  if (unlikely(!iph))
    return NF_ACCEPT;

  if (unlikely(iph->version != 4 || iph->ihl < 5))
    return NF_ACCEPT;

  pkt_len = ntohs(iph->tot_len);
  if (unlikely(iph->ihl * 4 > pkt_len || pkt_len > skb->len))
    return NF_ACCEPT;

  /* 硬件已校验的报文跳过软件校验和 */
  if (skb->ip_summed != CHECKSUM_UNNECESSARY) {
    if (unlikely(ip_fast_csum((const __u8 *)iph, iph->ihl) != 0))
      return NF_ACCEPT;
  }

  /* 源地址合法性：非法源地址不进任何表查询，也不计丢弃统计 */
  src = iph->saddr;
  if (unlikely(fw_src_is_invalid_ipv4(src)))
    return NF_ACCEPT;

  /* 分片标识：MF 置位或分片偏移非 0 */
  is_fragment = (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
  proto = iph->protocol;

  /* 传输层解析：非首片没有传输层头，传 protocol=0 跳过协议专项判定 */
  if (unlikely(ntohs(iph->frag_off) & IP_OFFSET)) {
    proto = 0;
  } else if (proto == IPPROTO_TCP) {
    struct tcphdr tcph_copy;
    const struct tcphdr *tcph = skb_header_pointer(
      skb, iph->ihl * 4, sizeof(tcph_copy), &tcph_copy);

    if (!tcph) {
      proto = 0;
    } else {
      if (tcph->syn)
        tcp_flags |= FW_TCP_SYN;
      if (tcph->ack)
        tcp_flags |= FW_TCP_ACK;
      if (tcph->rst)
        tcp_flags |= FW_TCP_RST;
      if (tcph->fin)
        tcp_flags |= FW_TCP_FIN;
      dst_port = ntohs(tcph->dest);
    }
  } else if (proto == IPPROTO_UDP) {
    struct udphdr udph_copy;
    const struct udphdr *udph = skb_header_pointer(
      skb, iph->ihl * 4, sizeof(udph_copy), &udph_copy);

    if (udph) {
      is_udp = true;
      dst_port = ntohs(udph->dest);
    }
  } else if (proto == IPPROTO_ICMP) {
    struct icmphdr icmph_copy;
    const struct icmphdr *icmph = skb_header_pointer(
      skb, iph->ihl * 4, sizeof(icmph_copy), &icmph_copy);

    if (!icmph) {
      proto = 0;
    } else {
      /* 类型/代码分布记录全部 ICMP 类型；仅 Echo Request 做 flood 判定 */
      is_icmp = true;
      icmp_type = icmph->type;
      icmp_code = icmph->code;
      if (icmph->type != ICMP_ECHO)
        proto = 0;
    }
  }

  /* 直方图与分布需要传输层解析结果，故与旧实现一样在解析之后统一记账 */
  fw_stat_account(pkt_len, iph->ttl, is_fragment, dst_port, is_udp, is_icmp,
                  icmp_type, icmp_code);

  /* 协议异常：SYN+FIN / SYN+RST / 四标志全零，直接丢弃 */
  if (proto == IPPROTO_TCP && fw_tcp_flag_anomaly(tcp_flags)) {
    s = fw_stats_this_cpu();
    fw_stat_bump(s, false, true);
    return NF_DROP;
  }

  fw_stat_global_traffic(skb->len);

  verdict = fw_ban_check(FW_AF_INET, &src, pkt_len, proto, tcp_flags, dst_port);

  s = fw_stats_this_cpu();
  fw_stat_bump(s, verdict == NF_ACCEPT, false);
  return verdict;
}

static unsigned int fw_hook_ipv6(void *priv, struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
  struct ipv6hdr iph6_copy;
  const struct ipv6hdr *iph6;
  struct ipv6_opt_hdr opt;
  struct fw_stats_pcpu *s;
  struct in6_addr src;
  unsigned int offset;
  u32 pkt_len;
  u8 nexthdr, proto, tcp_flags = 0, icmp_type = 0, icmp_code = 0;
  u16 dst_port = 0;
  bool is_fragment, is_udp = false, is_icmp = false;
  unsigned int verdict;

  (void)priv;
  (void)state;

  if (fw_is_shutting_down())
    return NF_ACCEPT;

  if (unlikely(!skb))
    return NF_ACCEPT;

  /* lo 接口默认豁免：环回接口上的流量不是外来流量（本机内部通信），
   * 在入口直接放行——不进任何表查询，也不计任何统计。 */
  if (unlikely(skb->dev && (skb->dev->flags & IFF_LOOPBACK)))
    return NF_ACCEPT;

  if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
    return NF_ACCEPT;

  iph6 = skb_header_pointer(skb, 0, sizeof(iph6_copy), &iph6_copy);
  if (unlikely(!iph6))
    return NF_ACCEPT;

  if (unlikely(iph6->version != 6))
    return NF_ACCEPT;

  pkt_len = ntohs(iph6->payload_len) + sizeof(struct ipv6hdr);
  if (unlikely(pkt_len > skb->len))
    return NF_ACCEPT;

  /* 扩展头遍历：深度超限即丢包，防止恶意报文耗尽 CPU */
  nexthdr = iph6->nexthdr;
  offset = sizeof(struct ipv6hdr);
  {
    int depth = 0;

    while (nexthdr == NEXTHDR_HOP || nexthdr == NEXTHDR_ROUTING ||
           nexthdr == NEXTHDR_DEST || nexthdr == NEXTHDR_AUTH) {
      if (++depth > FW_HOOK_MAX_EXT_HDR_DEPTH)
        return NF_DROP;
      if (!pskb_may_pull(skb, offset + sizeof(struct ipv6_opt_hdr)))
        break;
      if (!skb_header_pointer(skb, offset, sizeof(opt), &opt))
        break;
      offset += ipv6_optlen(&opt);
      nexthdr = opt.nexthdr;
    }
  }

  src = iph6->saddr;
  if (unlikely(fw_src_is_invalid_ipv6(&src)))
    return NF_ACCEPT;

  /* 分片扩展头之后没有传输层头，与 IPv4 非首片一致传 protocol=0 */
  is_fragment = nexthdr == NEXTHDR_FRAGMENT;
  proto = is_fragment ? 0 : nexthdr;

  if (proto == IPPROTO_TCP) {
    struct tcphdr tcph_copy;
    const struct tcphdr *tcph = skb_header_pointer(skb, offset, sizeof(tcph_copy), &tcph_copy);

    if (!tcph) {
      proto = 0;
    } else {
      if (tcph->syn)
        tcp_flags |= FW_TCP_SYN;
      if (tcph->ack)
        tcp_flags |= FW_TCP_ACK;
      if (tcph->rst)
        tcp_flags |= FW_TCP_RST;
      if (tcph->fin)
        tcp_flags |= FW_TCP_FIN;
      dst_port = ntohs(tcph->dest);
    }
  } else if (proto == IPPROTO_ICMPV6) {
    struct icmp6hdr icmp6h_copy;
    const struct icmp6hdr *icmp6h = skb_header_pointer(
      skb, offset, sizeof(icmp6h_copy), &icmp6h_copy);

    if (!icmp6h) {
      proto = 0;
    } else {
      is_icmp = true;
      icmp_type = icmp6h->icmp6_type;
      icmp_code = icmp6h->icmp6_code;
      /* 仅 Echo Request 做 flood 判定；命中则统一映射为 IPPROTO_ICMP，
       * 让协议阈值覆盖 IPv6（消除 ICMPv6 盲区） */
      if (icmp6h->icmp6_type != ICMPV6_ECHO_REQUEST)
        proto = 0;
      else
        proto = IPPROTO_ICMP;
    }
  } else if (proto == IPPROTO_UDP) {
    struct udphdr udph_copy;
    const struct udphdr *udph = skb_header_pointer(skb, offset, sizeof(udph_copy), &udph_copy);

    if (udph) {
      is_udp = true;
      dst_port = ntohs(udph->dest);
    }
  }

  fw_stat_account(pkt_len, iph6->hop_limit, is_fragment, dst_port, is_udp,
                  is_icmp, icmp_type, icmp_code);

  if (proto == IPPROTO_TCP && fw_tcp_flag_anomaly(tcp_flags)) {
    s = fw_stats_this_cpu();
    fw_stat_bump(s, false, true);
    return NF_DROP;
  }

  fw_stat_global_traffic(skb->len);

  verdict = fw_ban_check(FW_AF_INET6, &src, pkt_len, proto, tcp_flags, dst_port);

  s = fw_stats_this_cpu();
  fw_stat_bump(s, verdict == NF_ACCEPT, false);
  return verdict;
}
