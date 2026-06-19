// SPDX-License-Identifier: GPL-2.0
/*
 * netlink.c - Netlink 通信层
 * 
 * 实现内核模块与用户空间守护进程的双向通信：
 * - 内核 → 守护进程：DDoS 检测事件推送
 * - 守护进程 → 内核：封禁/解封指令下发
 */

#include "firewall.h"
#include <linux/netlink.h>
#include <linux/socket.h>
#include <net/sock.h>

/* 全局防火墙信息结构（在 firewall-main.c 中定义） */
extern struct firewall_info fw_info;

/* Netlink 协议号（使用用户自定义协议） */
#define FW_NETLINK_PROTO NETLINK_USERSOCK

/* Netlink 消息魔数，用于验证消息合法性 */
#define FW_NL_MAGIC 0x46574C4E /* "FWLN" */

/* 消息类型定义 */
enum {
  FW_NL_DDOS_EVENT = 1,       /* 内核 → 守护进程：DDoS 违规事件 */
  FW_NL_BAN_IP = 2,           /* 守护进程 → 内核：封禁 IP */
  FW_NL_UNBAN_IP = 3,         /* 守护进程 → 内核：解封 IP */
  FW_NL_SET_CONFIG = 4,       /* 守护进程 → 内核：配置更新 */
  FW_NL_BAN_STATE_CHANGE = 5, /* 内核 → 守护进程：封禁状态变更 */
  FW_NL_LIST_BANS_QUERY = 6,  /* 守护进程 → 内核：查询封禁列表 */
  FW_NL_LIST_BANS_RESPONSE = 7, /* 内核 → 守护进程：封禁列表响应 */
  FW_NL_STATS_QUERY = 8,    /* 守护进程 → 内核：查询统计数据 */
  FW_NL_STATS_RESPONSE = 9, /* 内核 → 守护进程：统计数据响应 */
  FW_NL_LIST_WHITELIST_QUERY = 10,    /* 守护进程 → 内核：查询白名单列表 */
  FW_NL_LIST_WHITELIST_RESPONSE = 11, /* 内核 → 守护进程：白名单列表响应 */
};

/* 消息头结构（20 字节） */
struct fw_nlmsg_hdr {
  __u32 magic;    /* 魔数，用于验证 */
  __u16 msg_type; /* 消息类型 */
  __u16 msg_len;  /* 总长度（含头） */
  __u32 seq;      /* 序列号 */
} __packed;

/* DDoS 事件载荷 */
struct fw_nl_ddos_event {
  struct fw_nlmsg_hdr hdr;
  __u8 af;         /* 地址族：AF_INET / AF_INET6 */
  __u8 reason[32]; /* 违规原因：SYN flood / UDP flood 等 */
  __u32 rate_pps;  /* 当前速率（包/秒） */
  __u8 addr[16];   /* IP 地址（IPv4 用前 4 字节） */
} __packed;

/* 封禁状态变更事件载荷（内核 → 守护进程） */
struct fw_nl_ban_state_change {
  struct fw_nlmsg_hdr hdr;
  __u8 action;         /* 1=ban, 2=unban */
  __u8 af;             /* 地址族 */
  __u32 duration_secs; /* 封禁时长（秒），0 = 永久 */
  __u8 addr[16];       /* IP 地址 */
} __packed;

/* 封禁/解封命令载荷 */
struct fw_nl_ban_cmd {
  struct fw_nlmsg_hdr hdr;
  __u8 af;             /* 地址族 */
  __u32 duration_secs; /* 封禁时长（秒），0 = 永久 */
  __u8 addr[16];       /* IP 地址 */
} __packed;

/* 配置更新载荷 */
struct fw_nl_config_update {
  struct fw_nlmsg_hdr hdr;
  __u32 flags;                  /* 配置项标志位 */
  __u32 ban_time;               /* 封禁时长（秒） */
  __u32 rate_window_seconds;    /* 速率检测窗口（秒） */
  __u64 max_packets_per_second; /* 每秒最大数据包数 */
  __u64 max_bytes_per_second;   /* 每秒最大字节数 */
  __u64 max_syn_per_second;     /* 每秒最大 SYN 包数 */
  __u64 max_udp_per_second;     /* 每秒最大 UDP 包数 */
  __u64 max_icmp_per_second;    /* 每秒最大 ICMP 包数 */
} __packed;

/* 配置项标志位 */
#define FW_NL_CFG_BAN_TIME (1 << 0)
#define FW_NL_CFG_RATE_WINDOW (1 << 1)
#define FW_NL_CFG_MAX_PPS (1 << 2)
#define FW_NL_CFG_MAX_BPS (1 << 3)
#define FW_NL_CFG_MAX_SYN (1 << 4)
#define FW_NL_CFG_MAX_UDP (1 << 5)
#define FW_NL_CFG_MAX_ICMP (1 << 6)

/* 封禁条目（内核 → 守护进程） */
struct fw_nl_ban_entry {
  __u8 af;
  __u8 is_permanent;
  __u32 duration_secs;
  __u64 banned_at;
  __u8 addr[16];
} __packed;

/* 封禁列表响应（内核 → 守护进程） */
struct fw_nl_list_bans_response {
  struct fw_nlmsg_hdr hdr;
  __u32 count;
  /* 后面紧跟 count 个 fw_nl_ban_entry */
} __packed;

/* 统计数据响应（内核 → 守护进程） */
struct fw_nl_stats_response {
  struct fw_nlmsg_hdr hdr;
  __u64 current_bans;
  __u64 total_bans;
  __u64 total_unbans;
  __u64 whitelist_count;
  __u64 packets_dropped;
  __u64 packets_accepted;
} __packed;

/* 白名单条目（内核 → 守护进程） */
struct fw_nl_whitelist_entry {
  __u8 af;             /* 地址族 */
  __u8 prefix_len;     /* 前缀长度（IPv4: 从掩码转换，IPv6: 直接使用） */
  __u8 addr[16];       /* IP 地址 */
  __u8 device[16];     /* 网络设备名称 */
} __packed;

/* 白名单列表响应（内核 → 守护进程） */
struct fw_nl_list_whitelist_response {
  struct fw_nlmsg_hdr hdr;
  __u32 count;
  /* 后面紧跟 count 个 fw_nl_whitelist_entry */
} __packed;

/* 全局 netlink socket */
static struct sock *fw_nl_sock = NULL;

/* 序列号计数器 */
static atomic_t fw_nl_seq = ATOMIC_INIT(0);

/**
 * fw_netlink_send_event - 向守护进程发送 DDoS 事件
 * @af: 地址族
 * @ip: IP 地址指针
 * @reason: 违规原因字符串
 * @rate_pps: 当前速率（包/秒）
 * 
 * 构造 DDoS 事件消息并通过 netlink 广播给守护进程。
 * 如果守护进程未连接，消息会被丢弃（不阻塞）。
 */
int fw_netlink_send_event(u8 af, const void *ip, const char *reason, u32 rate_pps) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_ddos_event *event;
  int ret;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(sizeof(*event), GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_DDOS_EVENT, sizeof(*event), 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  event = (struct fw_nl_ddos_event *)nlmsg_data(nlh);

  /* 填充消息头 */
  event->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  event->hdr.msg_type = cpu_to_be16(FW_NL_DDOS_EVENT);
  event->hdr.msg_len = cpu_to_be16(sizeof(*event));
  event->hdr.seq = cpu_to_be32(atomic_inc_return(&fw_nl_seq));

  /* 填充事件数据 */
  event->af = af;
  strncpy((char *)event->reason, reason, sizeof(event->reason) - 1);
  event->reason[sizeof(event->reason) - 1] = '\0';
  event->rate_pps = cpu_to_be32(rate_pps);

  /* 复制 IP 地址 */
  if (af == FW_AF_INET) {
    memcpy(event->addr, ip, 4);
  } else {
    memcpy(event->addr, ip, 16);
  }

  /* 广播消息（端口 0 表示广播给所有监听者） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    /* -ESRCH 表示没有监听者，这是正常情况 */
    pr_warn_ratelimited("netlink broadcast failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_ban_state_change - 向守护进程发送封禁状态变更事件
 * @af: 地址族
 * @ip: IP 地址指针
 * @action: 操作类型（1=ban, 2=unban）
 * @duration_secs: 封禁时长（秒），0 = 永久
 *
 * 当用户通过 /proc/firewall/bans 手动封禁/解封时调用，
 * 通知守护进程更新 ACTIVE_BAN_CACHE。
 */
int fw_netlink_send_ban_state_change(u8 af, const void *ip, u8 action, u32 duration_secs) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_ban_state_change *event;
  int ret;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(sizeof(*event), GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_BAN_STATE_CHANGE, sizeof(*event), 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  event = (struct fw_nl_ban_state_change *)nlmsg_data(nlh);

  /* 填充消息头 */
  event->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  event->hdr.msg_type = cpu_to_be16(FW_NL_BAN_STATE_CHANGE);
  event->hdr.msg_len = cpu_to_be16(sizeof(*event));
  event->hdr.seq = cpu_to_be32(atomic_inc_return(&fw_nl_seq));

  /* 填充事件数据 */
  event->action = action;
  event->af = af;
  event->duration_secs = cpu_to_be32(duration_secs);

  /* 复制 IP 地址 */
  if (af == FW_AF_INET) {
    memcpy(event->addr, ip, 4);
  } else {
    memcpy(event->addr, ip, 16);
  }

  /* 广播消息（端口 0 表示广播给所有监听者） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    /* -ESRCH 表示没有监听者，这是正常情况 */
    pr_warn_ratelimited("netlink broadcast ban state change failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_list_bans_response - 向守护进程发送封禁列表响应
 * @seq: 请求序列号
 *
 * 响应守护进程的 ListBansQuery 请求，发送当前所有封禁条目。
 * 最多返回 4096 个条目。
 */
int fw_netlink_send_list_bans_response(u32 seq) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_list_bans_response *resp;
  struct fw_nl_ban_entry *entries;
  struct ban_entry *entry;
  u32 hash;
  int max_entries = 4096;
  int resp_size;
  int ret;
  int count = 0;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 计算响应大小：头 + max_entries * 条目大小 */
  resp_size = sizeof(*resp) + max_entries * sizeof(struct fw_nl_ban_entry);

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(resp_size, GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_LIST_BANS_RESPONSE, resp_size, 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  resp = (struct fw_nl_list_bans_response *)nlmsg_data(nlh);
  entries = (struct fw_nl_ban_entry *)(resp + 1);

  /* 先填充响应头（count=0），后面再更新 */
  resp->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  resp->hdr.msg_type = cpu_to_be16(FW_NL_LIST_BANS_RESPONSE);
  resp->hdr.msg_len = cpu_to_be16(resp_size);
  resp->hdr.seq = cpu_to_be32(seq);
  resp->count = 0;

  /* 遍历封禁表填充条目 */
  rcu_read_lock();

  /* IPv4 封禁 */
  hash_for_each_rcu(fw_info.ban_table_ipv4, hash, entry, hash) {
    unsigned long ban_time = READ_ONCE(entry->ban_time);
    unsigned long unban_time = READ_ONCE(entry->unban_time);
    u32 duration_secs;

    if (count >= max_entries) {
      break;
    }

    entries[count].af = FW_AF_INET;
    entries[count].is_permanent = READ_ONCE(entry->is_permanent) ? 1 : 0;

    /* 计算封禁时长（秒） */
    if (entries[count].is_permanent) {
      duration_secs = 0;
    } else {
      duration_secs = (unban_time > ban_time) ? ((unban_time - ban_time) / HZ) : 0;
    }
    entries[count].duration_secs = cpu_to_be32(duration_secs);

    memset(entries[count].addr, 0, sizeof(entries[count].addr));
    memcpy(entries[count].addr, &entry->addr.ipv4, 4);
    count++;
  }

  /* IPv6 封禁 */
  hash_for_each_rcu(fw_info.ban_table_ipv6, hash, entry, hash) {
    unsigned long ban_time = READ_ONCE(entry->ban_time);
    unsigned long unban_time = READ_ONCE(entry->unban_time);
    u32 duration_secs;

    if (count >= max_entries) {
      break;
    }

    entries[count].af = FW_AF_INET6;
    entries[count].is_permanent = READ_ONCE(entry->is_permanent) ? 1 : 0;

    /* 计算封禁时长（秒） */
    if (entries[count].is_permanent) {
      duration_secs = 0;
    } else {
      duration_secs = (unban_time > ban_time) ? ((unban_time - ban_time) / HZ) : 0;
    }
    entries[count].duration_secs = cpu_to_be32(duration_secs);

    memcpy(entries[count].addr, &entry->addr.ipv6, 16);
    count++;
  }

  rcu_read_unlock();

  /* 更新实际数量 */
  resp->count = cpu_to_be32(count);

  /* 广播消息给守护进程（组 1） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink broadcast list bans response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_stats_response - 向守护进程发送统计数据响应
 * @seq: 请求序列号
 *
 * 响应守护进程的 StatsQuery 请求，发送当前统计数据。
 */
int fw_netlink_send_stats_response(u32 seq) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_stats_response *resp;
  int ret;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(sizeof(*resp), GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_STATS_RESPONSE, sizeof(*resp), 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  resp = (struct fw_nl_stats_response *)nlmsg_data(nlh);

  /* 填充消息头 */
  resp->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  resp->hdr.msg_type = cpu_to_be16(FW_NL_STATS_RESPONSE);
  resp->hdr.msg_len = cpu_to_be16(sizeof(*resp));
  resp->hdr.seq = cpu_to_be32(seq);

  /* 填充统计数据 */
  resp->current_bans = cpu_to_be64(atomic_read(&fw_info.ban_count));
  resp->total_bans = cpu_to_be64(atomic_read(&fw_info.total_ban_count));
  resp->total_unbans = cpu_to_be64(atomic_read(&fw_info.total_unban_count));
  resp->whitelist_count = cpu_to_be64(atomic_read(&fw_info.whitelist_count));
  resp->packets_dropped = cpu_to_be64(atomic64_read(&fw_info.packets_dropped));
  resp->packets_accepted = cpu_to_be64(atomic64_read(&fw_info.packets_accepted));

  /* 广播消息给守护进程（组 1） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink broadcast stats response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * ipv4_mask_to_prefix_len - 将 IPv4 子网掩码转换为前缀长度
 * @mask: IPv4 子网掩码（网络字节序）
 *
 * 返回前缀长度（0-32），无效掩码返回 0。
 */
static u8 ipv4_mask_to_prefix_len(__be32 mask) {
  u32 m = be32_to_cpu(mask);
  u8 len = 0;

  while (m & 0x80000000) {
    len++;
    m <<= 1;
  }
  return len;
}

/**
 * fw_netlink_send_list_whitelist_response - 向守护进程发送白名单列表响应
 * @seq: 请求序列号
 *
 * 响应守护进程的 ListWhitelistQuery 请求，发送当前所有白名单条目。
 * 最多返回 64 个条目（MAX_WHITELIST_ENTRIES）。
 */
int fw_netlink_send_list_whitelist_response(u32 seq) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_list_whitelist_response *resp;
  struct fw_nl_whitelist_entry *entries;
  struct whitelist_entry *entry;
  u32 hash;
  int max_entries = MAX_WHITELIST_ENTRIES;
  int resp_size;
  int ret;
  int count = 0;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 计算响应大小：头 + max_entries * 条目大小 */
  resp_size = sizeof(*resp) + max_entries * sizeof(struct fw_nl_whitelist_entry);

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(resp_size, GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_LIST_WHITELIST_RESPONSE, resp_size, 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  resp = (struct fw_nl_list_whitelist_response *)nlmsg_data(nlh);
  entries = (struct fw_nl_whitelist_entry *)(resp + 1);

  /* 先填充响应头 */
  resp->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  resp->hdr.msg_type = cpu_to_be16(FW_NL_LIST_WHITELIST_RESPONSE);
  resp->hdr.msg_len = cpu_to_be16(resp_size);
  resp->hdr.seq = cpu_to_be32(seq);
  resp->count = 0;

  /* 遍历白名单表填充条目 */
  rcu_read_lock();

  /* IPv4 白名单 */
  hash_for_each_rcu(fw_info.whitelist_table_ipv4, hash, entry, hash) {
    if (count >= max_entries) {
      break;
    }

    entries[count].af = FW_AF_INET;
    entries[count].prefix_len = ipv4_mask_to_prefix_len(entry->mask.ipv4_mask);
    memset(entries[count].addr, 0, sizeof(entries[count].addr));
    memcpy(entries[count].addr, &entry->addr.ipv4, 4);
    memset(entries[count].device, 0, sizeof(entries[count].device));
    strncpy((char *)entries[count].device, entry->device_name,
            sizeof(entries[count].device) - 1);
    count++;
  }

  /* IPv6 白名单 */
  hash_for_each_rcu(fw_info.whitelist_table_ipv6, hash, entry, hash) {
    if (count >= max_entries) {
      break;
    }

    entries[count].af = FW_AF_INET6;
    entries[count].prefix_len = entry->mask.prefix_len;
    memcpy(entries[count].addr, &entry->addr.ipv6, 16);
    memset(entries[count].device, 0, sizeof(entries[count].device));
    strncpy((char *)entries[count].device, entry->device_name,
            sizeof(entries[count].device) - 1);
    count++;
  }

  rcu_read_unlock();

  /* 更新实际数量 */
  resp->count = cpu_to_be32(count);

  /* 广播消息给守护进程（组 1） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink broadcast list whitelist response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_recv_msg - 处理守护进程发来的消息
 * @skb: 接收到的 netlink 消息
 * 
 * 解析守护进程发来的封禁/解封指令并执行。
 */
static void fw_netlink_recv_msg(struct sk_buff *skb) {
  struct nlmsghdr *nlh;
  struct fw_nlmsg_hdr *hdr;
  struct fw_nl_ban_cmd *cmd;
  char ip_str[INET6_STR_LEN];

  while (skb->len >= nlmsg_total_size(0)) {
    nlh = nlmsg_hdr(skb);

    /* 检查消息完整性 */
    if (!nlmsg_ok(nlh, skb->len)) {
      break;
    }

    /* 获取自定义消息头 */
    hdr = (struct fw_nlmsg_hdr *)nlmsg_data(nlh);

    /* 验证魔数 */
    if (be32_to_cpu(hdr->magic) != FW_NL_MAGIC) {
      pr_warn("invalid netlink magic: 0x%x\n", be32_to_cpu(hdr->magic));
      goto next;
    }

    /* 根据消息类型处理 */
    switch (be16_to_cpu(hdr->msg_type)) {
    case FW_NL_BAN_IP:
      cmd = (struct fw_nl_ban_cmd *)hdr;
      ip_to_str(cmd->af, cmd->addr, ip_str, sizeof(ip_str));
      pr_info("netlink: ban IP %s for %u seconds\n", ip_str, be32_to_cpu(cmd->duration_secs));

      /* 调用封禁函数 */
      if (be32_to_cpu(cmd->duration_secs) == 0) {
        ban_ip_permanent(&fw_info, cmd->af, cmd->addr);
      } else {
        ban_ip_with_duration(&fw_info, cmd->af, cmd->addr, be32_to_cpu(cmd->duration_secs));
      }
      break;

    case FW_NL_UNBAN_IP:
      cmd = (struct fw_nl_ban_cmd *)hdr;
      ip_to_str(cmd->af, cmd->addr, ip_str, sizeof(ip_str));
      pr_info("netlink: unban IP %s\n", ip_str);

      /* 调用解封函数 */
      unban_ip(&fw_info, cmd->af, cmd->addr);
      break;

    case FW_NL_SET_CONFIG: {
      struct fw_nl_config_update *cfg = (struct fw_nl_config_update *)hdr;
      __u32 flags = be32_to_cpu(cfg->flags);
      int updated = 0;

      /* 配置验证：拒绝危险值 */
      if (flags & FW_NL_CFG_BAN_TIME) {
        __u32 new_ban_time = be32_to_cpu(cfg->ban_time);
        if (new_ban_time == 0) {
          pr_warn("netlink: reject ban_time=0 (ambiguous, use procfs for permanent ban)\n");
          flags &= ~FW_NL_CFG_BAN_TIME;
        }
      }

      if (flags & FW_NL_CFG_MAX_PPS) {
        __u64 new_pps = be64_to_cpu(cfg->max_packets_per_second);
        if (new_pps == 0) {
          pr_warn("netlink: reject max_packets_per_second=0 (would drop all traffic)\n");
          flags &= ~FW_NL_CFG_MAX_PPS;
        }
      }

      if (flags & FW_NL_CFG_MAX_BPS) {
        __u64 new_bps = be64_to_cpu(cfg->max_bytes_per_second);
        if (new_bps == 0) {
          pr_warn("netlink: reject max_bytes_per_second=0 (would drop all traffic)\n");
          flags &= ~FW_NL_CFG_MAX_BPS;
        }
      }

      /* 使用 WRITE_ONCE 确保原子写入和内存可见性 */
      if (flags & FW_NL_CFG_BAN_TIME) {
        WRITE_ONCE(fw_info.ban_time, be32_to_cpu(cfg->ban_time));
        pr_info("netlink: ban_time updated to %u seconds\n", READ_ONCE(fw_info.ban_time));
        updated++;
      }

      if (flags & FW_NL_CFG_RATE_WINDOW) {
        __u32 new_window = be32_to_cpu(cfg->rate_window_seconds);
        WRITE_ONCE(fw_info.rate_window_seconds, new_window);
        smp_wmb(); /* 确保 seconds 写入在 jiffies 之前可见 */
        WRITE_ONCE(fw_info.rate_window_jiffies, msecs_to_jiffies(new_window * 1000));
        /* 清除旧速率条目，确保所有条目使用新窗口 */
        clear_all_rate_entries(&fw_info);
        pr_info("netlink: rate_window updated to %u seconds\n", new_window);
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_PPS) {
        WRITE_ONCE(fw_info.max_packets_per_second, be64_to_cpu(cfg->max_packets_per_second));
        pr_info("netlink: max_packets_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_packets_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_BPS) {
        WRITE_ONCE(fw_info.max_bytes_per_second, be64_to_cpu(cfg->max_bytes_per_second));
        pr_info("netlink: max_bytes_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_bytes_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_SYN) {
        WRITE_ONCE(fw_info.max_syn_per_second, be64_to_cpu(cfg->max_syn_per_second));
        pr_info("netlink: max_syn_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_syn_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_UDP) {
        WRITE_ONCE(fw_info.max_udp_per_second, be64_to_cpu(cfg->max_udp_per_second));
        pr_info("netlink: max_udp_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_udp_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_ICMP) {
        WRITE_ONCE(fw_info.max_icmp_per_second, be64_to_cpu(cfg->max_icmp_per_second));
        pr_info("netlink: max_icmp_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_icmp_per_second));
        updated++;
      }

      pr_info("netlink: config updated, %d items changed\n", updated);
      break;
    }

    case FW_NL_STATS_QUERY:
      pr_info("netlink: stats query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_stats_response(be32_to_cpu(hdr->seq));
      break;

    case FW_NL_LIST_BANS_QUERY:
      pr_info("netlink: list bans query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_list_bans_response(be32_to_cpu(hdr->seq));
      break;

    case FW_NL_LIST_WHITELIST_QUERY:
      pr_info("netlink: list whitelist query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_list_whitelist_response(be32_to_cpu(hdr->seq));
      break;

    default:
      pr_warn("unknown netlink message type: %u\n", be16_to_cpu(hdr->msg_type));
      break;
    }

  next:
    skb_pull(skb, nlh->nlmsg_len);
  }
}

/**
 * fw_netlink_init - 初始化 netlink socket
 * 
 * 创建 netlink socket 并绑定到 FW_NETLINK_PROTO 协议。
 * 设置接收回调函数处理守护进程发来的消息。
 */
int fw_netlink_init(void) {
  struct netlink_kernel_cfg cfg = {
    .input = fw_netlink_recv_msg,
  };

  fw_nl_sock = netlink_kernel_create(&init_net, FW_NETLINK_PROTO, &cfg);
  if (!fw_nl_sock) {
    pr_err("failed to create netlink socket\n");
    return -ENOMEM;
  }

  pr_info("netlink socket initialized (proto=%d)\n", FW_NETLINK_PROTO);
  return 0;
}

/**
 * fw_netlink_exit - 清理 netlink socket
 * 
 * 释放 netlink socket 资源。
 */
void fw_netlink_exit(void) {
  if (fw_nl_sock) {
    netlink_kernel_release(fw_nl_sock);
    fw_nl_sock = NULL;
    pr_info("netlink socket released\n");
  }
}
