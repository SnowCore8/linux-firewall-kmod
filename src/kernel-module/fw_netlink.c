// SPDX-License-Identifier: Dual MIT/GPL
/*
 * fw_netlink.c - netlink socket、事件推送、指令接收
 *
 * 线格式定义**只有一处**：contract/generated/netlink_uapi.h（由 contract/gen.py
 * 从 netlink.fwidl 生成）。本文件不重复声明任何报文结构——旧实现在 netlink.c
 * 里手抄了 16 个与契约同形的 __packed 结构体，与生成头各改各的，是契约漂移的
 * 主要来源。现在一律用 `struct fw_*`。
 *
 * 与旧实现的行为差别（见 docs/zh/development/kernel-rewrite-design.md）：
 *
 *   1. **DaemonRegisterAck 载荷错位修复**：旧实现把 accepted 写进 12 字节头的
 *      最后一个字节（offset 11）并用 NLMSG_DONE 做 nlmsg_type，契约要求
 *      accepted 是紧随头之后的独立字节（offset 12，总长 13）。本实现按契约写。
 *   2. **分页**：LIST_BANS / LIST_RATES / LIST_WHITELIST 全部按 offset/limit 分页，
 *      单页条目数由 u16 msg_len 上限反推（见各 PAGE_MAX 注释）。旧实现无分页，
 *      780 条以上 msg_len（u16）回绕。
 *   3. **长度用 size_t 累加**，不经过 u16，避免回绕后再赋值。
 *   4. **global_pps/global_bps 用真实间隔折算**：旧实现硬编码 `pkts / 2`，与
 *      daemon 的 2 秒轮询周期耦合（daemon 侧改周期即静默错值）。契约对这两个
 *      字段的定义是「自上次查询以来的平均速率」，因此本实现记录两次查询之间的
 *      实际 jiffies 间隔并据此折算，不再依赖任何跨模块常数。
 *   5. **控制面权限用 netlink_capable(skb, CAP_NET_ADMIN)**，与旧实现一致但
 *      用 6.17 存在的声明（linux/netlink.h）。
 *   6. **单守护进程互斥**：portid 独占；注册时**先探活**旧 portid，已死则立即放行
 *      接管，30 秒活动超时退居「活着但卡死」的兜底。旧实现只有超时这一条判据，
 *      于是 daemon 崩溃（SIGKILL / OOM / panic 都不发注销报文）后最长 30 秒内谁的
 *      注册都会被拒——服务管理器在这段窗口里反复重启也起不来。探活见
 *      `fw_nl_daemon_alive()`。
 *
 * 上下文：netlink input 回调在发送方（daemon 进程）上下文中执行，可睡眠，
 * 因此 SET_CONFIG 触发的 fw_rate_clear_all()（on_each_cpu 同步等待）是安全的。
 *
 * skb 所有权：netlink_unicast / netlink_broadcast 成功与失败都会消费 skb，
 * 因此发送路径绝不 kfree_skb（仅 nlmsg_new → nlmsg_put 失败时释放）。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/capability.h>
#include <linux/jiffies.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <net/net_namespace.h>
#include <net/netlink.h>
#include <net/sock.h>

#include "fw_netlink.h"
#include "fw_ban.h"
#include "fw_wl.h"
#include "fw_stats.h"
#include "fw_rate.h"

/* 协议号：NETLINK_USERSOCK 是线格式的冻结面（契约 header 亦注明） */
#define FW_NL_PROTO NETLINK_USERSOCK

/* 事件多播组；daemon 订阅组 1（与旧实现一致，属冻结面） */
#define FW_NL_GROUP 1

/* 单守护进程互斥兜底：30 秒无消息视为死亡，允许新守护进程接管；注册另先探活（见 fw_nl_daemon_alive） */
#define FW_NL_DAEMON_TIMEOUT (30 * HZ)

/*
 * 探活报文的载荷长度。取 16 字节仅为走真实投递路径；内容全零，使 daemon 侧的
 * 自定义头魔数校验必然失败——这样即便旧 daemon 还活着，探针也只被记成一次
 * malformed 告警，不会执行任何指令或改任何状态（daemon 侧不认「非内核来源」以外的
 * 分流，而探针的 netlink 源 portid 为 0，与内核广播同源）。
 */
#define FW_NL_PROBE_PAYLOAD 16

/*
 * 分页默认页大小与硬上限。
 * 硬上限由 u16 msg_len 上限 65535 与各响应的定长部分反推：
 *   bans        24 + n*94 <= 65535 → n <= 696
 *   whitelist   24 + n*34 <= 65535 → n <= 1926
 *   rates       40 + n*84 <= 65535 → n <= 779
 */
#define FW_NL_DEFAULT_PAGE 256
#define FW_NL_BANS_PAGE_MAX 696
#define FW_NL_WL_PAGE_MAX 1926
#define FW_NL_RATES_PAGE_MAX 779

static struct sock *fw_nl_sock;
static atomic_t fw_nl_seq = ATOMIC_INIT(0);
static u32 fw_nl_daemon_portid;
static unsigned long fw_nl_daemon_activity;

/* 上一次 LIST_RATES_RESPONSE 的时刻，用于把累计增量折算成「包/秒」 */
static unsigned long fw_nl_rates_last_jiffies;

/* ============================================================================
 * 公共发送原语
 * ==========================================================================*/

/* 填公共头：magic / 类型 / 总长 / 序列号（全部大端） */
static void fw_nl_init_hdr(struct fw_msg_hdr *h, u16 type, u32 seq, size_t len) {
  h->magic = cpu_to_be32(FW_NL_MAGIC);
  h->msg_type = cpu_to_be16(type);
  h->msg_len = cpu_to_be16((u16)len);
  h->seq = cpu_to_be32(seq);
}

/*
 * 裸地址字节：IPv4 占前 4 字节、其余置 0；IPv6 占满 16 字节。
 * 先清零再拷贝，避免把栈上的旧字节带进线格式（契约要求定长字段无垃圾）。
 */
static void fw_nl_copy_addr(u8 *dst, u8 af, const void *src) {
  memset(dst, 0, 16);
  if (!src)
    return;
  memcpy(dst, src, af == FW_ADDR_FAMILY_INET ? 4 : 16);
}

/* 定长字符串字段：清零 + strscpy，保证 NUL 结尾且无残留 */
static void fw_nl_copy_str(u8 *dst, size_t len, const char *src) {
  memset(dst, 0, len);
  if (src && src[0])
    strscpy((char *)dst, src, len);
}

/*
 * 分配 skb 并写入公共头。
 * 成功时 *out_skb 回传 skb（发送函数需要它作为 netlink_unicast/broadcast 的
 * 实参）；失败时 *out_skb 置 NULL 且返回 NULL（skb 已释放，调用者不应再动）。
 */
static struct nlmsghdr *fw_nl_begin(struct sk_buff **out_skb, size_t payload,
                                    u16 type, u32 seq) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;

  *out_skb = NULL;
  if (!fw_nl_sock)
    return NULL;

  skb = nlmsg_new(payload, GFP_ATOMIC);
  if (!skb)
    return NULL;

  nlh = nlmsg_put(skb, 0, 0, type, payload, 0);
  if (!nlh) {
    kfree_skb(skb);
    return NULL;
  }

  fw_nl_init_hdr((struct fw_msg_hdr *)nlmsg_data(nlh), type, seq, payload);
  *out_skb = skb;
  return nlh;
}

/* ============================================================================
 * 事件：内核 → daemon（多播组 1）
 * ==========================================================================*/

void fw_nl_send_ddos_event(u8 af, const void *addr, const char *reason, u32 rate_pps) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_ddos_event *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_DDOS_EVENT, atomic_inc_return(&fw_nl_seq));
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->af = af;
  e->rate_pps = cpu_to_be32(rate_pps);
  fw_nl_copy_str(e->reason, sizeof(e->reason), reason);
  fw_nl_copy_addr(e->addr, af, addr);

  ret = netlink_broadcast(fw_nl_sock, skb, 0, FW_NL_GROUP, GFP_ATOMIC);
  if (ret && ret != -ESRCH)
    pr_warn_ratelimited("DdosEvent 广播失败: %d\n", ret);
}

void fw_nl_send_ban_state_change(u8 action, u8 af, const void *addr, u32 duration_secs,
                                 const char *reason, const char *jail) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_ban_state_change *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_BAN_STATE_CHANGE,
                    atomic_inc_return(&fw_nl_seq));
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->action = action;
  e->af = af;
  e->duration_secs = cpu_to_be32(duration_secs);
  fw_nl_copy_addr(e->addr, af, addr);
  fw_nl_copy_str(e->reason, sizeof(e->reason), reason);
  fw_nl_copy_str(e->jail_name, sizeof(e->jail_name), jail);
  e->packets_dropped = cpu_to_be64(atomic64_read(&fw_info.packets_dropped));
  e->packets_accepted = cpu_to_be64(atomic64_read(&fw_info.packets_accepted));
  e->current_bans = cpu_to_be32(fw_ban_count());
  e->whitelist_count = cpu_to_be32(fw_wl_count());

  ret = netlink_broadcast(fw_nl_sock, skb, 0, FW_NL_GROUP, GFP_ATOMIC);
  if (ret && ret != -ESRCH)
    pr_warn_ratelimited("BanStateChange 广播失败: %d\n", ret);
}

void fw_nl_send_whitelist_state_change(u8 action, u8 af, const void *addr,
                                       u8 prefix_len, const char *device) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_whitelist_state_change *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_WHITELIST_STATE_CHANGE,
                    atomic_inc_return(&fw_nl_seq));
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->action = action;
  e->af = af;
  e->prefix_len = prefix_len;
  fw_nl_copy_addr(e->addr, af, addr);
  fw_nl_copy_str(e->device, sizeof(e->device), device);
  e->whitelist_count = cpu_to_be32(fw_wl_count());

  ret = netlink_broadcast(fw_nl_sock, skb, 0, FW_NL_GROUP, GFP_ATOMIC);
  if (ret && ret != -ESRCH)
    pr_warn_ratelimited("WhitelistStateChange 广播失败: %d\n", ret);
}

void fw_nl_send_config_change(u32 flags, u32 ban_time) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_config_change *e;
  int ret;

  nlh = fw_nl_begin(
    &skb, sizeof(*e), FW_MSG_TYPE_CONFIG_CHANGE, atomic_inc_return(&fw_nl_seq));
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->flags = cpu_to_be32(flags);
  e->ban_time = cpu_to_be32(ban_time);
  e->rate_window_seconds = cpu_to_be32(fw_info.rate_window_seconds);
  e->max_packets_per_second = cpu_to_be64(fw_info.max_packets_per_second);
  e->max_bytes_per_second = cpu_to_be64(fw_info.max_bytes_per_second);
  e->max_syn_per_second = cpu_to_be64(fw_info.max_syn_per_second);
  e->max_udp_per_second = cpu_to_be64(fw_info.max_udp_per_second);
  e->max_icmp_per_second = cpu_to_be64(fw_info.max_icmp_per_second);
  e->max_ack_per_second = cpu_to_be64(fw_info.max_ack_per_second);
  e->max_rst_per_second = cpu_to_be64(fw_info.max_rst_per_second);
  e->max_fin_per_second = cpu_to_be64(fw_info.max_fin_per_second);
  e->dynamic_threshold_flags = cpu_to_be32(
    fw_info.dynamic_threshold_enabled ? FW_DYN_THRESHOLD_FLAGS_ENABLED : 0);
  e->dynamic_threshold_ratio_x100 = cpu_to_be32(fw_info.dynamic_threshold_ratio_x100);
  e->baseline_pps = cpu_to_be64(fw_info.baseline_pps);
  e->baseline_bps = cpu_to_be64(fw_info.baseline_bps);
  e->ddos_ban_duration = cpu_to_be32(fw_info.ddos_ban_duration);

  ret = netlink_broadcast(fw_nl_sock, skb, 0, FW_NL_GROUP, GFP_ATOMIC);
  if (ret && ret != -ESRCH)
    pr_warn_ratelimited("ConfigChange 广播失败: %d\n", ret);
}

/* 命令失败通知（单播回发起方） */
static void fw_nl_send_cmd_result(u32 portid, u16 original_cmd, s32 error_code,
                                  u8 af, const void *addr) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_cmd_result *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_CMD_RESULT, atomic_inc_return(&fw_nl_seq));
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->original_cmd = cpu_to_be16(original_cmd);
  e->pad = 0;
  e->error_code = cpu_to_be32((u32)error_code);
  e->af = af;
  fw_nl_copy_addr(e->addr, af, addr);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("CmdResult 单播失败: %d\n", ret);
}

/* 单守护进程注册确认；accepted 为紧随头之后的独立字节（契约 13 字节） */
static void fw_nl_send_register_ack(u32 portid, u32 seq, u8 accepted) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_daemon_register_ack *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_DAEMON_REGISTER_ACK, seq);
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->accepted = accepted;

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("DaemonRegisterAck 单播失败: %d\n", ret);
}

static void fw_nl_send_config_ack(u32 portid, u32 seq, u32 applied, u32 rejected) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_config_ack *e;
  int ret;

  nlh = fw_nl_begin(&skb, sizeof(*e), FW_MSG_TYPE_CONFIG_ACK, seq);
  if (!nlh)
    return;

  e = nlmsg_data(nlh);
  e->applied_flags = cpu_to_be32(applied);
  e->rejected_flags = cpu_to_be32(rejected);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("ConfigAck 单播失败: %d\n", ret);
}

/* ============================================================================
 * 查询响应：内核 → daemon（单播）
 * ==========================================================================*/

/* 分页归一：limit == 0 取默认页大小；超过硬上限则收紧到硬上限 */
static void fw_nl_page(u32 *limit, u32 page_max) {
  if (!*limit)
    *limit = FW_NL_DEFAULT_PAGE;
  if (*limit > page_max)
    *limit = page_max;
}

static void fw_nl_send_bans_page(u32 portid, u32 seq, u32 offset, u32 limit, u32 total) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_list_bans_response *r;
  struct fw_ban_row *rows;
  struct fw_ban_entry *out;
  u32 got, i;
  int ret;

  fw_nl_page(&limit, FW_NL_BANS_PAGE_MAX);
  if (offset >= total)
    limit = 0;

  rows = kcalloc(limit ? limit : 1, sizeof(*rows), GFP_KERNEL);
  if (!rows) {
    fw_nl_send_cmd_result(
      portid, FW_MSG_TYPE_LIST_BANS_QUERY, -ENOMEM, FW_ADDR_FAMILY_INET, NULL);
    return;
  }
  got = limit ? fw_ban_fill_entries(offset, limit, rows) : 0;

  nlh = fw_nl_begin(
    &skb, sizeof(*r) + got * sizeof(*out), FW_MSG_TYPE_LIST_BANS_RESPONSE, seq);
  if (!nlh) {
    kfree(rows);
    return;
  }

  r = nlmsg_data(nlh);
  r->count = cpu_to_be32(got);
  r->total = cpu_to_be32(total);
  r->offset = cpu_to_be32(offset);

  out = (struct fw_ban_entry *)(r + 1);
  for (i = 0; i < got; i++) {
    out[i].af = rows[i].af;
    out[i].is_permanent = rows[i].is_permanent;
    out[i].duration_secs = cpu_to_be32(rows[i].duration_secs);
    out[i].banned_at = cpu_to_be64(rows[i].banned_at);
    fw_nl_copy_addr(out[i].addr, rows[i].af, &rows[i].addr);
    fw_nl_copy_str(out[i].jail_name, sizeof(out[i].jail_name), rows[i].jail_name);
    fw_nl_copy_str(out[i].reason, sizeof(out[i].reason), rows[i].reason);
  }

  kfree(rows);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("ListBansResponse 单播失败: %d\n", ret);
}

static void fw_nl_send_stats_response(u32 portid, u32 seq) {
  struct fw_stats_snapshot s;
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_stats_response *r;
  int ret;

  fw_stats_snapshot(&s);

  nlh = fw_nl_begin(&skb, sizeof(*r), FW_MSG_TYPE_STATS_RESPONSE, seq);
  if (!nlh)
    return;

  r = nlmsg_data(nlh);
  r->current_bans = cpu_to_be64(fw_ban_count());
  r->total_bans = cpu_to_be64(s.total_bans);
  r->total_unbans = cpu_to_be64(s.total_unbans);
  r->whitelist_count = cpu_to_be64(fw_wl_count());
  r->packets_dropped = cpu_to_be64(s.packets_dropped);
  r->packets_accepted = cpu_to_be64(s.packets_accepted);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("StatsResponse 单播失败: %d\n", ret);
}

static void fw_nl_send_whitelist_page(u32 portid, u32 seq, u32 offset, u32 limit, u32 total) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_list_whitelist_response *r;
  struct fw_whitelist_entry *out;
  struct fw_wl_row *rows;
  u32 got, i;
  int ret;

  fw_nl_page(&limit, FW_NL_WL_PAGE_MAX);
  if (offset >= total)
    limit = 0;

  rows = kcalloc(limit ? limit : 1, sizeof(*rows), GFP_KERNEL);
  if (!rows) {
    fw_nl_send_cmd_result(portid, FW_MSG_TYPE_LIST_WHITELIST_QUERY, -ENOMEM,
                          FW_ADDR_FAMILY_INET, NULL);
    return;
  }
  got = limit ? fw_wl_fill_entries(offset, limit, rows) : 0;

  nlh = fw_nl_begin(&skb, sizeof(*r) + got * sizeof(*out),
                    FW_MSG_TYPE_LIST_WHITELIST_RESPONSE, seq);
  if (!nlh) {
    kfree(rows);
    return;
  }

  r = nlmsg_data(nlh);
  r->count = cpu_to_be32(got);
  r->total = cpu_to_be32(total);
  r->offset = cpu_to_be32(offset);

  out = (struct fw_whitelist_entry *)(r + 1);
  for (i = 0; i < got; i++) {
    out[i].af = rows[i].af;
    out[i].prefix_len = rows[i].prefix_len;
    fw_nl_copy_addr(out[i].addr, rows[i].af, &rows[i].addr);
    fw_nl_copy_str(out[i].device, sizeof(out[i].device), rows[i].device_name);
  }

  kfree(rows);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("ListWhitelistResponse 单播失败: %d\n", ret);
}

/*
 * 全局速率的「包/秒」「字节/秒」折算。
 *
 * 这两个字段的定义是「自上次查询以来的平均速率」，而查询周期由 daemon 决定
 * （旧实现把它硬编码成 2 秒，daemon 侧改周期即静默出错）。这里记录两次响应
 * 之间的实际 jiffies 间隔来折算：首次查询没有基准，退回当前窗口长度。
 */
static u32 fw_nl_rates_elapsed_secs(void) {
  unsigned long now = jiffies;
  u64 ms;
  u32 elapsed;

  if (!fw_nl_rates_last_jiffies) {
    elapsed = READ_ONCE(fw_info.rate_window_seconds);
  } else {
    ms = jiffies_to_msecs(now - fw_nl_rates_last_jiffies);
    elapsed = (u32)((ms + 999) / 1000);
  }

  fw_nl_rates_last_jiffies = now;

  return elapsed ? elapsed : 1;
}

static void fw_nl_send_rates_page(u32 portid, u32 seq, u32 offset, u32 limit, u32 total) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_list_rates_response *r;
  struct fw_rate_entry *out;
  struct fw_rate_row *rows;
  u64 bytes = 0;
  u64 pkts = fw_stats_take_traffic(&bytes);
  u32 elapsed = fw_nl_rates_elapsed_secs();
  u32 got, i;
  int ret;

  fw_nl_page(&limit, FW_NL_RATES_PAGE_MAX);
  if (offset >= total)
    limit = 0;

  rows = kcalloc(limit ? limit : 1, sizeof(*rows), GFP_KERNEL);
  if (!rows) {
    fw_nl_send_cmd_result(
      portid, FW_MSG_TYPE_LIST_RATES_QUERY, -ENOMEM, FW_ADDR_FAMILY_INET, NULL);
    return;
  }
  got = limit ? fw_rate_fill_entries(offset, limit, rows) : 0;

  nlh = fw_nl_begin(
    &skb, sizeof(*r) + got * sizeof(*out), FW_MSG_TYPE_LIST_RATES_RESPONSE, seq);
  if (!nlh) {
    kfree(rows);
    return;
  }

  r = nlmsg_data(nlh);
  r->count = cpu_to_be32(got);
  r->total = cpu_to_be32(total);
  r->offset = cpu_to_be32(offset);
  r->global_pps = cpu_to_be64(pkts / elapsed);
  r->global_bps = cpu_to_be64(bytes / elapsed);

  out = (struct fw_rate_entry *)(r + 1);
  for (i = 0; i < got; i++) {
    out[i].af = rows[i].af;
    memset(out[i].pad, 0, sizeof(out[i].pad));
    out[i].packets = cpu_to_be64(rows[i].packets);
    out[i].bytes = cpu_to_be64(rows[i].bytes);
    out[i].syn_packets = cpu_to_be64(rows[i].syn_packets);
    out[i].udp_packets = cpu_to_be64(rows[i].udp_packets);
    out[i].icmp_packets = cpu_to_be64(rows[i].icmp_packets);
    out[i].ack_packets = cpu_to_be64(rows[i].ack_packets);
    out[i].rst_packets = cpu_to_be64(rows[i].rst_packets);
    out[i].fin_packets = cpu_to_be64(rows[i].fin_packets);
    fw_nl_copy_addr(out[i].addr, rows[i].af, &rows[i].addr);
  }

  kfree(rows);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("ListRatesResponse 单播失败: %d\n", ret);
}

static void fw_nl_send_analysis_response(u32 portid, u32 seq) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_analysis_response *r;
  struct fw_analysis_snapshot *s;
  u32 i;
  int ret;

  s = kmalloc(sizeof(*s), GFP_KERNEL);
  if (!s) {
    fw_nl_send_cmd_result(
      portid, FW_MSG_TYPE_ANALYSIS_QUERY, -ENOMEM, FW_ADDR_FAMILY_INET, NULL);
    return;
  }
  fw_stats_read_analysis(s);

  nlh = fw_nl_begin(&skb, sizeof(*r), FW_MSG_TYPE_ANALYSIS_RESPONSE, seq);
  if (!nlh) {
    kfree(s);
    return;
  }

  r = nlmsg_data(nlh);
  for (i = 0; i < FW_PKT_SIZE_BUCKETS; i++)
    r->pkt_sizes[i] = cpu_to_be64(s->pkt_sizes[i]);
  for (i = 0; i < FW_TTL_BUCKETS; i++)
    r->ttl_dist[i] = cpu_to_be64(s->ttl_dist[i]);
  r->ip_frag_total = cpu_to_be64(s->ip_frag_total);
  r->ip_frag_count = cpu_to_be64(s->ip_frag_count);

  r->udp_port_count = cpu_to_be32(s->udp_count);
  r->udp_port_capacity = cpu_to_be32(s->udp_capacity);
  for (i = 0; i < FW_ANALYSIS_UDP_PACK_MAX; i++) {
    r->udp_ports[i].port = cpu_to_be16(s->udp[i].port);
    r->udp_ports[i].packets = cpu_to_be64(s->udp[i].packets);
    r->udp_ports[i].bytes = cpu_to_be64(s->udp[i].bytes);
    r->udp_ports[i].last_seen_secs = cpu_to_be64(s->udp[i].last_seen_secs);
  }

  r->icmp_type_count = cpu_to_be32(s->icmp_count);
  r->icmp_type_capacity = cpu_to_be32(s->icmp_capacity);
  for (i = 0; i < FW_ANALYSIS_ICMP_PACK_MAX; i++) {
    r->icmp_types[i].type = s->icmp[i].type;
    r->icmp_types[i].code = s->icmp[i].code;
    r->icmp_types[i].packets = cpu_to_be64(s->icmp[i].packets);
    r->icmp_types[i].bytes = cpu_to_be64(s->icmp[i].bytes);
    r->icmp_types[i].last_seen_secs = cpu_to_be64(s->icmp[i].last_seen_secs);
  }

  r->port_scan_count = cpu_to_be32(s->port_scan_count);
  r->port_scan_threshold = cpu_to_be32(s->port_scan_threshold);
  for (i = 0; i < PORT_SCAN_MAX_RESULTS; i++) {
    r->port_scanners[i].af = s->port_scanners[i].af;
    memset(r->port_scanners[i].pad, 0, sizeof(r->port_scanners[i].pad));
    fw_nl_copy_addr(r->port_scanners[i].addr, s->port_scanners[i].af,
                    &s->port_scanners[i].addr);
    r->port_scanners[i].metric = cpu_to_be32(s->port_scanners[i].metric);
    r->port_scanners[i].packets = cpu_to_be64(s->port_scanners[i].packets);
  }

  r->service_probe_count = cpu_to_be32(s->service_probe_count);
  r->service_probe_threshold = cpu_to_be32(s->service_probe_threshold);
  for (i = 0; i < SERVICE_PROBE_MAX_RESULTS; i++) {
    r->service_probes[i].af = s->service_probes[i].af;
    memset(r->service_probes[i].pad, 0, sizeof(r->service_probes[i].pad));
    fw_nl_copy_addr(r->service_probes[i].addr, s->service_probes[i].af,
                    &s->service_probes[i].addr);
    r->service_probes[i].metric = cpu_to_be32(s->service_probes[i].metric);
    r->service_probes[i].packets = cpu_to_be64(s->service_probes[i].packets);
  }

  kfree(s);

  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0)
    pr_warn_ratelimited("AnalysisResponse 单播失败: %d\n", ret);
}

/* ============================================================================
 * 接收：daemon → 内核
 * ==========================================================================*/

/*
 * 应用 SET_CONFIG 的一个子集，返回**被拒绝**的标志位（0 表示全部接受）。
 *
 * ban_time 的默认时长是模块参数 fw_ban_time（契约 procfs.fwidl 的
 * BAN_DEFAULT 明示「使用内核默认时长 fw_ban_time」），因此这里直接写该参数，
 * 不再另设 fw_info.ban_time —— 旧实现同时维护两份并需要手工同步（见旧
 * procfs.c 的「同步到 fw_info.ban_time，消除双变量不一致」注释），是漂移源。
 */
static u32 fw_nl_apply_config(const struct fw_set_config *c) {
  u32 flags = be32_to_cpu(c->flags);
  u32 rejected = 0;

  if (flags & FW_CONFIG_FLAGS_BAN_TIME) {
    u32 v = be32_to_cpu(c->ban_time);

    if (v < FW_BAN_TIME_MIN || v > FW_BAN_TIME_MAX)
      rejected |= FW_CONFIG_FLAGS_BAN_TIME;
    else
      WRITE_ONCE(fw_ban_time, v);
  }

  if (flags & FW_CONFIG_FLAGS_RATE_WINDOW) {
    u32 v = be32_to_cpu(c->rate_window_seconds);

    if (!v || v > 60) {
      rejected |= FW_CONFIG_FLAGS_RATE_WINDOW;
    } else {
      WRITE_ONCE(fw_info.rate_window_seconds, v);
      smp_wmb();
      WRITE_ONCE(fw_info.rate_window_jiffies, v * HZ);
      /* 窗口长度变了，旧条目的窗口起点失去意义：清表重建 */
      fw_rate_clear_all();
    }
  }

#define FW_NL_APPLY_U64(bit, field, val) \
  do {                                   \
    if (flags & (bit)) {                 \
      u64 v = be64_to_cpu(val);          \
      if (!v)                            \
        rejected |= (bit);               \
      else                               \
        WRITE_ONCE(fw_info.field, v);    \
    }                                    \
  } while (0)

  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_PPS, max_packets_per_second, c->max_packets_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_BPS, max_bytes_per_second, c->max_bytes_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_SYN, max_syn_per_second, c->max_syn_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_UDP, max_udp_per_second, c->max_udp_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_ICMP, max_icmp_per_second, c->max_icmp_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_ACK, max_ack_per_second, c->max_ack_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_RST, max_rst_per_second, c->max_rst_per_second);
  FW_NL_APPLY_U64(FW_CONFIG_FLAGS_MAX_FIN, max_fin_per_second, c->max_fin_per_second);
#undef FW_NL_APPLY_U64

  if (flags & FW_CONFIG_FLAGS_DYNAMIC_THRESHOLD) {
    u32 dt = be32_to_cpu(c->dynamic_threshold_flags);
    u32 ratio = be32_to_cpu(c->dynamic_threshold_ratio_x100);

    if (!ratio) {
      rejected |= FW_CONFIG_FLAGS_DYNAMIC_THRESHOLD;
    } else {
      WRITE_ONCE(fw_info.dynamic_threshold_ratio_x100, ratio);
      WRITE_ONCE(fw_info.dynamic_threshold_enabled, !!(dt & FW_DYN_THRESHOLD_FLAGS_ENABLED));
    }
  }

  if (flags & FW_CONFIG_FLAGS_BASELINE_UPDATE)
    fw_rate_update_baseline(be64_to_cpu(c->baseline_pps), be64_to_cpu(c->baseline_bps));

  if (flags & FW_CONFIG_FLAGS_DDOS_BAN_DURATION)
    WRITE_ONCE(fw_info.ddos_ban_duration, be32_to_cpu(c->ddos_ban_duration));

  return rejected;
}

static void fw_nl_handle_ban(u32 portid, u16 type, u8 af, const void *addr,
                             u32 duration, const char *reason) {
  int ret;

  if (type == FW_MSG_TYPE_UNBAN_IP) {
    ret = fw_ban_del(af, addr, true);
    if (ret)
      fw_nl_send_cmd_result(portid, type, ret, af, addr);
    return;
  }

  /* 封禁理由缺省为 "manual"，便于在 bans 列表里辨识来源 */
  ret = fw_ban_try_add(af, addr, duration, reason[0] ? reason : "manual", NULL, true);
  if (ret)
    fw_nl_send_cmd_result(portid, type, ret, af, addr);
}

/*
 * 白名单增删。成功后的 WHITELIST_STATE_CHANGE 由本函数推送：fw_wl_add /
 * fw_wl_remove 自身不推送事件（与 fw_ban_add / fw_ban_del 不同，后者在
 * notify=true 时自行推送），因此这里若漏推，daemon 就看不到白名单变化。
 */
static void fw_nl_handle_whitelist(u32 portid, u16 type, u8 af, const void *addr,
                                   u8 prefix_len, const char *device) {
  bool adding = type == FW_MSG_TYPE_ADD_WHITELIST;
  int ret;

  /*
   * 入参约定是**已归一化**地址：fw_wl_add / fw_wl_remove 按 (af, 归一化地址,
   * prefix_len) 去重、并按归一化地址查删。procfs 路径自归一化，netdev 路径由
   * fw_netdev.c 保证；这条若漏了，加 <网络地址>/<prefix> 会入表成主机位非零的
   * 键——与 procfs 加的同一子网各占一条，且按网络地址 remove 查不到。故这里与
   * procfs 同序归一化，且是原地改：后续的移表与事件推送都用归一化值。
   */
  fw_addr_normalize(af, (void *)addr, prefix_len);

  if (adding)
    ret = fw_wl_add(af, addr, prefix_len, device[0] ? device : NULL);
  else
    ret = fw_wl_remove(af, addr, prefix_len);

  if (ret) {
    fw_nl_send_cmd_result(portid, type, ret, af, addr);
    return;
  }

  fw_nl_send_whitelist_state_change(adding ? FW_WHITELIST_ACTION_ADD : FW_WHITELIST_ACTION_REMOVE,
                                    af, addr, prefix_len, device);
}

/*
 * 探测内核记着的旧守护进程 portid 是否仍有一个存活的 socket。
 *
 * 判据：向该 portid 单播一条报文，取返回码。返回负值说明该 portid 已无 socket
 * （本机实测：`netlink_unicast(已死 portid) = -ECONNREFUSED`；对存活 socket 返回
 * 接收方缓冲区剩余字节数，为正）。这里把**任何**负值都当作「已死」——宁可早一步
 * 放行接管，也不要让崩溃后的注册盲窗继续存在。
 *
 * 为什么必须有它：daemon 崩溃（SIGKILL / OOM / panic）不会发出任何注销报文，
 * 内核与用户态都没有这种报文，于是「旧 daemon 是否还在」只能靠探活或等超时。
 *
 * 副作用与失败处置：旧 daemon 若真还活着，会收到这条全零报文，其自定义头魔数
 * 校验必失败，只记一次 malformed 告警，不执行指令、不改状态。skb 分配不出来时
 * 按「仍活着」处理（返回 true），保持原互斥语义，不因内存紧张而误放行。
 */
static bool fw_nl_daemon_alive(void) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  int rc;

  skb = nlmsg_new(FW_NL_PROBE_PAYLOAD, GFP_KERNEL);
  if (!skb)
    return true;

  nlh = nlmsg_put(skb, 0, 0, 0, FW_NL_PROBE_PAYLOAD, 0);
  if (!nlh) {
    kfree_skb(skb); /* 尚未交给 netlink，失败时须自行释放 */
    return true;
  }
  memset(nlmsg_data(nlh), 0, FW_NL_PROBE_PAYLOAD);

  rc = netlink_unicast(fw_nl_sock, skb, fw_nl_daemon_portid, MSG_DONTWAIT);
  return rc >= 0;
}

static void fw_nl_recv_msg(struct sk_buff *skb) {
  while (skb->len >= nlmsg_total_size(0)) {
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    struct fw_msg_hdr *h;
    size_t payload;
    u32 portid = NETLINK_CB(skb).portid;
    u16 type;

    if (!nlmsg_ok(nlh, skb->len))
      break;

    payload = nlh->nlmsg_len - NLMSG_HDRLEN;
    if (payload < sizeof(*h)) {
      pr_warn_ratelimited("netlink: 载荷过短 %zu < %zu\n", payload, sizeof(*h));
      goto next;
    }

    h = nlmsg_data(nlh);
    if (be32_to_cpu(h->magic) != FW_NL_MAGIC) {
      pr_warn_ratelimited("netlink: magic 不匹配 0x%x\n", be32_to_cpu(h->magic));
      goto next;
    }

    /* 任意本地进程都能连 NETLINK_USERSOCK，控制面必须要求 CAP_NET_ADMIN */
    if (!netlink_capable(skb, CAP_NET_ADMIN)) {
      pr_warn_ratelimited("netlink: 拒绝无 CAP_NET_ADMIN 的指令\n");
      goto next;
    }

    type = be16_to_cpu(h->msg_type);

    /* ---- 单守护进程互斥：不同 portid 抢注册时，先探活旧 portid ---- */
    if (type == FW_MSG_TYPE_DAEMON_REGISTER) {
      if (fw_nl_daemon_portid && portid != fw_nl_daemon_portid) {
        bool within_timeout = time_before(jiffies, fw_nl_daemon_activity + FW_NL_DAEMON_TIMEOUT);

        if (within_timeout && fw_nl_daemon_alive()) {
          pr_warn("netlink: 拒绝注册 portid=%u（已注册 %u 仍活跃）\n", portid,
                  fw_nl_daemon_portid);
          fw_nl_send_register_ack(portid, be32_to_cpu(h->seq), 0);
          goto next;
        }
        if (within_timeout)
          pr_info("netlink: 原守护进程 portid=%u 已死，portid=%u 立即接管\n",
                  fw_nl_daemon_portid, portid);
      }
      fw_nl_daemon_portid = portid;
      fw_nl_daemon_activity = jiffies;
      pr_info("netlink: 守护进程已注册 portid=%u\n", portid);
      fw_nl_send_register_ack(portid, be32_to_cpu(h->seq), 1);
      goto next;
    }

    if (!fw_nl_daemon_portid) {
      pr_warn_ratelimited("netlink: 无守护进程注册，丢弃类型 %u\n", type);
      goto next;
    }
    if (portid != fw_nl_daemon_portid) {
      if (time_before(jiffies, fw_nl_daemon_activity + FW_NL_DAEMON_TIMEOUT)) {
        pr_warn_ratelimited("netlink: 拒绝未注册 portid=%u 的指令\n", portid);
        goto next;
      }
      pr_info("netlink: 原守护进程 portid=%u 超时，portid=%u 接管\n",
              fw_nl_daemon_portid, portid);
      fw_nl_daemon_portid = portid;
    }
    fw_nl_daemon_activity = jiffies;

    switch (type) {
    case FW_MSG_TYPE_BAN_IP:
    case FW_MSG_TYPE_UNBAN_IP: {
      const struct fw_ban_ip *c;

      if (payload < sizeof(*c)) {
        pr_warn_ratelimited("netlink: BAN/UNBAN 载荷过短 %zu\n", payload);
        break;
      }
      c = (const struct fw_ban_ip *)h;
      fw_nl_handle_ban(portid, type, c->af, c->addr,
                       be32_to_cpu(c->duration_secs), (const char *)c->reason);
      break;
    }

    case FW_MSG_TYPE_ADD_WHITELIST:
    case FW_MSG_TYPE_REMOVE_WHITELIST: {
      const struct fw_add_whitelist *c;

      if (payload < sizeof(*c)) {
        pr_warn_ratelimited("netlink: 白名单载荷过短 %zu\n", payload);
        break;
      }
      c = (const struct fw_add_whitelist *)h;
      fw_nl_handle_whitelist(
        portid, type, c->af, c->addr, c->prefix_len, (const char *)c->device);
      break;
    }

    case FW_MSG_TYPE_SET_CONFIG: {
      const struct fw_set_config *c;

      if (payload < sizeof(*c)) {
        pr_warn_ratelimited("netlink: SET_CONFIG 载荷过短 %zu\n", payload);
        break;
      }
      c = (const struct fw_set_config *)h;
      {
        u32 requested = be32_to_cpu(c->flags);
        u32 rejected = fw_nl_apply_config(c);

        fw_nl_send_config_ack(portid, be32_to_cpu(h->seq), requested & ~rejected, rejected);
      }
      break;
    }

    case FW_MSG_TYPE_LIST_BANS_QUERY: {
      const struct fw_list_bans_query *q;
      u32 offset = 0, limit = 0;

      if (payload >= sizeof(*q)) {
        q = (const struct fw_list_bans_query *)h;
        offset = be32_to_cpu(q->offset);
        limit = be32_to_cpu(q->limit);
      }
      fw_nl_send_bans_page(portid, be32_to_cpu(h->seq), offset, limit, fw_ban_count());
      break;
    }

    case FW_MSG_TYPE_STATS_QUERY:
      fw_nl_send_stats_response(portid, be32_to_cpu(h->seq));
      break;

    case FW_MSG_TYPE_LIST_WHITELIST_QUERY: {
      const struct fw_list_whitelist_query *q;
      u32 offset = 0, limit = 0;

      if (payload >= sizeof(*q)) {
        q = (const struct fw_list_whitelist_query *)h;
        offset = be32_to_cpu(q->offset);
        limit = be32_to_cpu(q->limit);
      }
      fw_nl_send_whitelist_page(portid, be32_to_cpu(h->seq), offset, limit, fw_wl_count());
      break;
    }

    case FW_MSG_TYPE_LIST_RATES_QUERY: {
      const struct fw_list_rates_query *q;
      u32 offset = 0, limit = 0;

      if (payload >= sizeof(*q)) {
        q = (const struct fw_list_rates_query *)h;
        offset = be32_to_cpu(q->offset);
        limit = be32_to_cpu(q->limit);
      }
      fw_nl_send_rates_page(portid, be32_to_cpu(h->seq), offset, limit, fw_rate_count());
      break;
    }

    case FW_MSG_TYPE_ANALYSIS_QUERY:
      fw_nl_send_analysis_response(portid, be32_to_cpu(h->seq));
      break;

    default:
      pr_warn_ratelimited("netlink: 未知消息类型 %u\n", type);
      break;
    }

  next:
    skb_pull(skb, nlh->nlmsg_len);
  }
}

/* ============================================================================
 * 生命周期
 * ==========================================================================*/

int fw_netlink_init(void) {
  struct netlink_kernel_cfg cfg = {
    .input = fw_nl_recv_msg,
  };

  fw_nl_sock = netlink_kernel_create(&init_net, FW_NL_PROTO, &cfg);
  if (!fw_nl_sock) {
    pr_err("netlink socket 创建失败\n");
    return -ENOMEM;
  }

  atomic_set(&fw_nl_seq, 0);
  fw_nl_daemon_portid = 0;
  fw_nl_daemon_activity = 0;
  fw_nl_rates_last_jiffies = 0;
  pr_info("netlink socket 已创建（proto=%d）\n", FW_NL_PROTO);
  return 0;
}

void fw_netlink_exit(void) {
  if (!fw_nl_sock)
    return;

  netlink_kernel_release(fw_nl_sock);
  fw_nl_sock = NULL;
  fw_nl_daemon_portid = 0;
  fw_nl_rates_last_jiffies = 0;
  pr_info("netlink socket 已释放\n");
}
