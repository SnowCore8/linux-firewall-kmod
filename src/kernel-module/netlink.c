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
  FW_NL_LIST_WHITELIST_QUERY = 10, /* 守护进程 → 内核：查询白名单列表 */
  FW_NL_LIST_WHITELIST_RESPONSE = 11, /* 内核 → 守护进程：白名单列表响应 */
  FW_NL_ADD_WHITELIST = 12, /* 守护进程 → 内核：添加白名单条目 */
  FW_NL_REMOVE_WHITELIST = 13, /* 守护进程 → 内核：移除白名单条目 */
  FW_NL_CONFIG_ACK = 14, /* 内核 → 守护进程：配置更新确认 */
  FW_NL_LIST_RATES_QUERY = 15, /* 守护进程 → 内核：查询速率统计 */
  FW_NL_LIST_RATES_RESPONSE = 16, /* 内核 → 守护进程：速率统计响应 */
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
  __u32 flags;                   /* 配置项标志位 */
  __u32 ban_time;                /* 封禁时长（秒） */
  __u32 rate_window_seconds;     /* 速率检测窗口（秒） */
  __u64 max_packets_per_second;  /* 每秒最大数据包数 */
  __u64 max_bytes_per_second;    /* 每秒最大字节数 */
  __u64 max_syn_per_second;      /* 每秒最大 SYN 包数 */
  __u64 max_udp_per_second;      /* 每秒最大 UDP 包数 */
  __u64 max_icmp_per_second;     /* 每秒最大 ICMP 包数 */
  __u64 max_ack_per_second;      /* 每秒最大 ACK 包数 */
  __u64 max_rst_per_second;      /* 每秒最大 RST 包数 */
  __u64 max_fin_per_second;      /* 每秒最大 FIN 包数 */
  __u32 dynamic_threshold_flags; /* 动态阈值标志（bit0: enabled） */
  __u32 dynamic_threshold_ratio_x100; /* 动态阈值倍数 × 100 */
  __u64 baseline_pps; /* 基线 PPS（用于动态阈值更新） */
  __u64 baseline_bps; /* 基线 BPS（用于动态阈值更新） */
} __packed;

/* 配置项标志位 */
#define FW_NL_CFG_BAN_TIME (1 << 0)
#define FW_NL_CFG_RATE_WINDOW (1 << 1)
#define FW_NL_CFG_MAX_PPS (1 << 2)
#define FW_NL_CFG_MAX_BPS (1 << 3)
#define FW_NL_CFG_MAX_SYN (1 << 4)
#define FW_NL_CFG_MAX_UDP (1 << 5)
#define FW_NL_CFG_MAX_ICMP (1 << 6)
#define FW_NL_CFG_MAX_ACK (1 << 7)
#define FW_NL_CFG_MAX_RST (1 << 8)
#define FW_NL_CFG_MAX_FIN (1 << 9)
#define FW_NL_CFG_DYNAMIC_THRESHOLD (1 << 10)
#define FW_NL_CFG_BASELINE_UPDATE (1 << 11)

/* 动态阈值标志位 */
#define FW_NL_CFG_DT_ENABLED (1 << 0)

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
  __u8 af;         /* 地址族 */
  __u8 prefix_len; /* 前缀长度（IPv4: 从掩码转换，IPv6: 直接使用） */
  __u8 addr[16];   /* IP 地址 */
  __u8 device[16]; /* 网络设备名称 */
} __packed;

/* 白名单列表响应（内核 → 守护进程） */
struct fw_nl_list_whitelist_response {
  struct fw_nlmsg_hdr hdr;
  __u32 count;
  /* 后面紧跟 count 个 fw_nl_whitelist_entry */
} __packed;

/* 白名单操作命令（守护进程 → 内核） */
struct fw_nl_whitelist_cmd {
  struct fw_nlmsg_hdr hdr;
  __u8 af;         /* 地址族 */
  __u8 prefix_len; /* 前缀长度 */
  __u8 addr[16];   /* IP 地址 */
  __u8 device[16]; /* 网络设备名称 */
} __packed;

/* 配置更新确认（内核 → 守护进程） */
struct fw_nl_config_ack {
  struct fw_nlmsg_hdr hdr;
  __u32 applied_flags;  /* 实际生效的配置项标志位 */
  __u32 rejected_flags; /* 被拒绝的配置项标志位 */
} __packed;

/* 速率统计条目（内核 → 守护进程） */
struct fw_nl_rate_entry {
  __u8 af;            /* 地址族 */
  __u8 pad[3];        /* 对齐填充 */
  __u64 packets;      /* 数据包数 */
  __u64 bytes;        /* 字节数 */
  __u64 syn_packets;  /* SYN 包数 */
  __u64 udp_packets;  /* UDP 包数 */
  __u64 icmp_packets; /* ICMP 包数 */
  __u64 ack_packets;  /* ACK 包数 */
  __u64 rst_packets;  /* RST 包数 */
  __u64 fin_packets;  /* FIN 包数 */
  __u8 addr[16];      /* IP 地址 */
} __packed;

/* 速率统计响应（内核 → 守护进程） */
struct fw_nl_list_rates_response {
  struct fw_nlmsg_hdr hdr;
  __u32 count;
  __u32 total; /* 内核中实际条目总数（用于守护进程感知截断） */
  __u64 global_pps; /* 全局 PPS（自上次查询以来的平均包速率） */
  __u64 global_bps; /* 全局 BPS（自上次查询以来的平均字节速率） */
  /* 后面紧跟 count 个 fw_nl_rate_entry */
} __packed;

/* 单次速率响应最大条目数（避免 4MB GFP_ATOMIC 分配） */
#define MAX_RATE_RESPONSE_ENTRIES 4096

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

  /* 事件推送用广播（1:1 绑定，只有一个监听者） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink broadcast event failed: %d\n", ret);
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

  /* 事件推送用广播（1:1 绑定，只有一个监听者） */
  ret = netlink_broadcast(fw_nl_sock, skb, 0, 1, GFP_ATOMIC);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink broadcast ban state change failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_list_bans_response - 向守护进程发送封禁列表响应
 * @seq: 请求序列号
 * @portid: 守护进程 netlink 端口 ID（用于单播回复）
 *
 * 响应守护进程的 ListBansQuery 请求，发送当前所有封禁条目。
 * 最多返回 4096 个条目。
 */
int fw_netlink_send_list_bans_response(u32 seq, u32 portid) {
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
    s64 banned_at;

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

    /* 计算封禁时间（unix 时间戳） */
    banned_at = ktime_get_real_seconds() - (jiffies - ban_time) / HZ;
    entries[count].banned_at = cpu_to_be64(banned_at);

    memset(entries[count].addr, 0, sizeof(entries[count].addr));
    memcpy(entries[count].addr, &entry->addr.ipv4, 4);
    count++;
  }

  /* IPv6 封禁 */
  hash_for_each_rcu(fw_info.ban_table_ipv6, hash, entry, hash) {
    unsigned long ban_time = READ_ONCE(entry->ban_time);
    unsigned long unban_time = READ_ONCE(entry->unban_time);
    u32 duration_secs;
    s64 banned_at;

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

    /* 计算封禁时间（unix 时间戳） */
    banned_at = ktime_get_real_seconds() - (jiffies - ban_time) / HZ;
    entries[count].banned_at = cpu_to_be64(banned_at);

    memcpy(entries[count].addr, &entry->addr.ipv6, 16);
    count++;
  }

  rcu_read_unlock();

  /* 更新实际数量 */
  resp->count = cpu_to_be32(count);

  /* 单播回复给守护进程 */
  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink unicast list bans response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_stats_response - 向守护进程发送统计数据响应
 * @seq: 请求序列号
 * @portid: 守护进程 netlink 端口 ID（用于单播回复）
 *
 * 响应守护进程的 StatsQuery 请求，发送当前统计数据。
 */
int fw_netlink_send_stats_response(u32 seq, u32 portid) {
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

  /* 单播回复给守护进程 */
  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink unicast stats response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fw_netlink_send_config_ack - 向守护进程发送配置更新确认
 * @seq: 请求序列号
 * @applied_flags: 实际生效的配置项标志位
 * @rejected_flags: 被拒绝的配置项标志位
 * @portid: 守护进程 netlink 端口 ID（用于单播回复）
 */
int fw_netlink_send_config_ack(u32 seq, u32 applied_flags, u32 rejected_flags, u32 portid) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_config_ack *ack;
  int ret;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  skb = nlmsg_new(sizeof(*ack), GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  nlh = nlmsg_put(skb, 0, 0, FW_NL_CONFIG_ACK, sizeof(*ack), 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  ack = (struct fw_nl_config_ack *)nlmsg_data(nlh);
  ack->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  ack->hdr.msg_type = cpu_to_be16(FW_NL_CONFIG_ACK);
  ack->hdr.msg_len = cpu_to_be16(sizeof(*ack));
  ack->hdr.seq = cpu_to_be32(seq);
  ack->applied_flags = cpu_to_be32(applied_flags);
  ack->rejected_flags = cpu_to_be32(rejected_flags);

  /* 单播回复给守护进程 */
  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink unicast config ack failed: %d\n", ret);
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
 * @portid: 守护进程 netlink 端口 ID（用于单播回复）
 *
 * 响应守护进程的 ListWhitelistQuery 请求，发送当前所有白名单条目。
 * 最多返回 64 个条目（MAX_WHITELIST_ENTRIES）。
 */
int fw_netlink_send_list_whitelist_response(u32 seq, u32 portid) {
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

  /* 单播回复给守护进程 */
  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink unicast list whitelist response failed: %d\n", ret);
    return ret;
  }

  return 0;
}

/**
 * fill_rate_entry - 填充单个速率条目（消除 IPv4/IPv6 重复代码）
 * @out: 输出缓冲区
 * @entry: 速率条目（RCU 保护下读取）
 * @af: 地址族
 * @now: 当前 jiffies
 *
 * 直接计算实时速率：rate = count * HZ / elapsed_jiffies
 */
static void fill_rate_entry(struct fw_nl_rate_entry *out,
                            struct ip_rate_entry *entry, u8 af, unsigned long now) {
  u64 packets, bytes, syn, udp, icmp, ack, rst, fin;
  unsigned long elapsed;

  /* 读取原始计数（原子操作） */
  packets = atomic64_read(&entry->packet_count);
  bytes = atomic64_read(&entry->byte_count);
  syn = atomic64_read(&entry->syn_count);
  udp = atomic64_read(&entry->udp_count);
  icmp = atomic64_read(&entry->icmp_count);
  ack = atomic64_read(&entry->ack_count);
  rst = atomic64_read(&entry->rst_count);
  fin = atomic64_read(&entry->fin_count);

  /* 计算经过时间（jiffies），避免除零 */
  elapsed = now - entry->window_start;
  if (elapsed == 0) {
    elapsed = 1;
  }

  out->af = af;
  memset(out->pad, 0, sizeof(out->pad));
  out->packets = cpu_to_be64((packets * HZ) / elapsed);
  out->bytes = cpu_to_be64((bytes * HZ) / elapsed);
  out->syn_packets = cpu_to_be64((syn * HZ) / elapsed);
  out->udp_packets = cpu_to_be64((udp * HZ) / elapsed);
  out->icmp_packets = cpu_to_be64((icmp * HZ) / elapsed);
  out->ack_packets = cpu_to_be64((ack * HZ) / elapsed);
  out->rst_packets = cpu_to_be64((rst * HZ) / elapsed);
  out->fin_packets = cpu_to_be64((fin * HZ) / elapsed);
  memset(out->addr, 0, sizeof(out->addr));

  if (af == FW_AF_INET) {
    memcpy(out->addr, &entry->addr.ipv4, 4);
  } else {
    memcpy(out->addr, &entry->addr.ipv6, 16);
  }
}

/**
 * fw_netlink_send_list_rates_response - 向守护进程发送速率统计响应
 * @seq: 请求序列号
 * @portid: 守护进程 netlink 端口 ID（用于单播回复）
 *
 * 响应守护进程的 ListRatesQuery 请求，发送当前所有速率统计条目。
 *
 * 性能优化：
 * 1. 动态内存分配：基于实际条目数，避免 4MB GFP_ATOMIC 分配
 * 2. 单次响应上限 4096 条（MAX_RATE_RESPONSE_ENTRIES），超出截断
 * 3. 响应携带 total 字段，守护进程可感知截断
 * 4. 提取 fill_rate_entry 辅助函数消除 IPv4/IPv6 重复代码
 */
int fw_netlink_send_list_rates_response(u32 seq, u32 portid) {
  struct sk_buff *skb;
  struct nlmsghdr *nlh;
  struct fw_nl_list_rates_response *resp;
  struct fw_nl_rate_entry *entries;
  struct ip_rate_entry *entry;
  u32 hash;
  int max_entries = MAX_RATE_RESPONSE_ENTRIES;
  int resp_size;
  int ret;
  int count = 0;
  int total;
  unsigned long now = jiffies;

  if (!fw_nl_sock) {
    return -ENOTCONN;
  }

  /* 动态计算分配大小：基于实际条目数，避免 4MB 分配 */
  total = atomic_read(&fw_info.rate_count);
  if (total > max_entries) {
    total = max_entries;
  }
  resp_size = sizeof(*resp) + total * sizeof(struct fw_nl_rate_entry);

  /* 分配 netlink 消息缓冲区 */
  skb = nlmsg_new(resp_size, GFP_ATOMIC);
  if (!skb) {
    return -ENOMEM;
  }

  /* 构造消息头 */
  nlh = nlmsg_put(skb, 0, 0, FW_NL_LIST_RATES_RESPONSE, resp_size, 0);
  if (!nlh) {
    kfree_skb(skb);
    return -ENOMEM;
  }

  /* 获取 payload 指针 */
  resp = (struct fw_nl_list_rates_response *)nlmsg_data(nlh);
  entries = (struct fw_nl_rate_entry *)(resp + 1);

  /* 先填充响应头 */
  resp->hdr.magic = cpu_to_be32(FW_NL_MAGIC);
  resp->hdr.msg_type = cpu_to_be16(FW_NL_LIST_RATES_RESPONSE);
  resp->hdr.msg_len = cpu_to_be16(resp_size);
  resp->hdr.seq = cpu_to_be32(seq);
  resp->count = 0;
  resp->total = 0;

  /* 读取并重置全局流量计数器，计算自上次查询以来的平均速率
   * 先 flush 所有 per-CPU 计数器，确保全局计数器包含所有 CPU 的最新数据，
   * 消除最大 1023 包/CPU 的统计延迟。
   * atomic64_xchg 保证原子性地读取当前值并重置为 0，
   * 两次查询间隔约 2 秒，除以间隔得到平均 PPS/BPS */
  {
    u64 pkts, bytes;
    fw_flush_all_cpu_stats();
    pkts = atomic64_xchg(&fw_info.global_traffic_packets, 0);
    bytes = atomic64_xchg(&fw_info.global_traffic_bytes, 0);
    /* 查询间隔约 2 秒，除以 2 得到平均速率 */
    resp->global_pps = cpu_to_be64(pkts / 2);
    resp->global_bps = cpu_to_be64(bytes / 2);
  }

  /* 遍历速率表填充条目 - 直接计算实时速率 */
  rcu_read_lock();

  /* IPv4 的速率统计 */
  hash_for_each_rcu(fw_info.rate_table_ipv4, hash, entry, hash) {
    if (count >= max_entries) {
      break;
    }
    fill_rate_entry(&entries[count], entry, FW_AF_INET, now);
    count++;
  }

  /* IPv6 的速率统计 */
  hash_for_each_rcu(fw_info.rate_table_ipv6, hash, entry, hash) {
    if (count >= max_entries) {
      break;
    }
    fill_rate_entry(&entries[count], entry, FW_AF_INET6, now);
    count++;
  }

  rcu_read_unlock();

  /* 更新实际数量和总数 */
  resp->count = cpu_to_be32(count);
  resp->total = cpu_to_be32(atomic_read(&fw_info.rate_count));

  /* 单播回复给守护进程 */
  ret = netlink_unicast(fw_nl_sock, skb, portid, MSG_DONTWAIT);
  if (ret < 0 && ret != -ESRCH) {
    pr_warn_ratelimited("netlink unicast list rates response failed: %d\n", ret);
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
  int payload_len;

  while (skb->len >= nlmsg_total_size(0)) {
    nlh = nlmsg_hdr(skb);

    /* 检查消息完整性 */
    if (!nlmsg_ok(nlh, skb->len)) {
      break;
    }

    /* 获取自定义消息头 */
    hdr = (struct fw_nlmsg_hdr *)nlmsg_data(nlh);

    /* 计算有效载荷长度（nlmsg_data 之后的字节数） */
    payload_len = nlh->nlmsg_len - NLMSG_HDRLEN;

    /* 验证魔数 */
    if (be32_to_cpu(hdr->magic) != FW_NL_MAGIC) {
      pr_warn("invalid netlink magic: 0x%x\n", be32_to_cpu(hdr->magic));
      goto next;
    }

    /* 所有消息至少包含 fw_nlmsg_hdr */
    if (payload_len < (int)sizeof(struct fw_nlmsg_hdr)) {
      pr_warn("netlink: payload too short: %d < %zu\n", payload_len,
              sizeof(struct fw_nlmsg_hdr));
      goto next;
    }

    /* 获取发送方 portid（用于单播回复） */
    u32 sender_portid = NETLINK_CB(skb).portid;

    /* 根据消息类型处理 */
    switch (be16_to_cpu(hdr->msg_type)) {
    case FW_NL_BAN_IP:
      if (payload_len < (int)sizeof(struct fw_nl_ban_cmd)) {
        pr_warn("netlink: BAN_IP payload too short: %d\n", payload_len);
        break;
      }
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
      if (payload_len < (int)sizeof(struct fw_nl_ban_cmd)) {
        pr_warn("netlink: UNBAN_IP payload too short: %d\n", payload_len);
        break;
      }
      cmd = (struct fw_nl_ban_cmd *)hdr;
      ip_to_str(cmd->af, cmd->addr, ip_str, sizeof(ip_str));
      pr_info("netlink: unban IP %s\n", ip_str);

      /* 调用解封函数 */
      unban_ip(&fw_info, cmd->af, cmd->addr);
      break;

    case FW_NL_SET_CONFIG: {
      if (payload_len < (int)sizeof(struct fw_nl_config_update)) {
        pr_warn("netlink: SET_CONFIG payload too short: %d\n", payload_len);
        break;
      }
      struct fw_nl_config_update *cfg = (struct fw_nl_config_update *)hdr;
      __u32 flags = be32_to_cpu(cfg->flags);
      __u32 original_flags = flags;
      __u32 rejected_flags = 0;
      int updated = 0;

      /* 配置验证：拒绝危险值 */
      if (flags & FW_NL_CFG_BAN_TIME) {
        __u32 new_ban_time = be32_to_cpu(cfg->ban_time);
        if (new_ban_time == 0) {
          pr_warn("netlink: reject ban_time=0 (ambiguous, use procfs for permanent ban)\n");
          rejected_flags |= FW_NL_CFG_BAN_TIME;
          flags &= ~FW_NL_CFG_BAN_TIME;
        }
      }

      if (flags & FW_NL_CFG_MAX_PPS) {
        __u64 new_pps = be64_to_cpu(cfg->max_packets_per_second);
        if (new_pps == 0) {
          pr_warn("netlink: reject max_packets_per_second=0 (would drop all traffic)\n");
          rejected_flags |= FW_NL_CFG_MAX_PPS;
          flags &= ~FW_NL_CFG_MAX_PPS;
        }
      }

      if (flags & FW_NL_CFG_MAX_BPS) {
        __u64 new_bps = be64_to_cpu(cfg->max_bytes_per_second);
        if (new_bps == 0) {
          pr_warn("netlink: reject max_bytes_per_second=0 (would drop all traffic)\n");
          rejected_flags |= FW_NL_CFG_MAX_BPS;
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

      if (flags & FW_NL_CFG_MAX_ACK) {
        WRITE_ONCE(fw_info.max_ack_per_second, be64_to_cpu(cfg->max_ack_per_second));
        pr_info("netlink: max_ack_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_ack_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_RST) {
        WRITE_ONCE(fw_info.max_rst_per_second, be64_to_cpu(cfg->max_rst_per_second));
        pr_info("netlink: max_rst_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_rst_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_MAX_FIN) {
        WRITE_ONCE(fw_info.max_fin_per_second, be64_to_cpu(cfg->max_fin_per_second));
        pr_info("netlink: max_fin_per_second updated to %lu\n",
                READ_ONCE(fw_info.max_fin_per_second));
        updated++;
      }

      if (flags & FW_NL_CFG_DYNAMIC_THRESHOLD) {
        __u32 dt_flags = be32_to_cpu(cfg->dynamic_threshold_flags);
        fw_info.dynamic_threshold_enabled = (dt_flags & FW_NL_CFG_DT_ENABLED) ? true : false;
        WRITE_ONCE(fw_info.dynamic_threshold_ratio_x100,
                   be32_to_cpu(cfg->dynamic_threshold_ratio_x100));
        pr_info("netlink: dynamic_threshold %s, ratio=%u/100\n",
                fw_info.dynamic_threshold_enabled ? "enabled" : "disabled",
                READ_ONCE(fw_info.dynamic_threshold_ratio_x100));
        updated++;
      }

      if (flags & FW_NL_CFG_BASELINE_UPDATE) {
        __u64 pps = be64_to_cpu(cfg->baseline_pps);
        __u64 bps = be64_to_cpu(cfg->baseline_bps);
        update_global_baseline(&fw_info, pps, bps);
        pr_info("netlink: baseline updated to pps=%llu bps=%llu\n", pps, bps);
        updated++;
      }

      pr_info("netlink: config updated, %d items changed\n", updated);

      /* 发送配置确认响应 */
      fw_netlink_send_config_ack(be32_to_cpu(hdr->seq), original_flags & ~rejected_flags,
                                 rejected_flags, sender_portid);
      break;
    }

    case FW_NL_STATS_QUERY:
      pr_info("netlink: stats query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_stats_response(be32_to_cpu(hdr->seq), sender_portid);
      break;

    case FW_NL_LIST_BANS_QUERY:
      pr_info("netlink: list bans query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_list_bans_response(be32_to_cpu(hdr->seq), sender_portid);
      break;

    case FW_NL_LIST_WHITELIST_QUERY:
      pr_info("netlink: list whitelist query received, seq=%u\n",
              be32_to_cpu(hdr->seq));
      fw_netlink_send_list_whitelist_response(be32_to_cpu(hdr->seq), sender_portid);
      break;

    case FW_NL_LIST_RATES_QUERY:
      pr_info("netlink: list rates query received, seq=%u\n", be32_to_cpu(hdr->seq));
      fw_netlink_send_list_rates_response(be32_to_cpu(hdr->seq), sender_portid);
      break;

    case FW_NL_ADD_WHITELIST: {
      if (payload_len < (int)sizeof(struct fw_nl_whitelist_cmd)) {
        pr_warn("netlink: ADD_WHITELIST payload too short: %d\n", payload_len);
        break;
      }
      struct fw_nl_whitelist_cmd *cmd = (struct fw_nl_whitelist_cmd *)hdr;
      char ip_str[INET6_STR_LEN];
      int ret;

      ip_to_str(cmd->af, cmd->addr, ip_str, sizeof(ip_str));
      pr_info("netlink: add whitelist %s/%u dev %s\n", ip_str, cmd->prefix_len,
              cmd->device[0] ? (char *)cmd->device : "(none)");

      if (cmd->af == FW_AF_INET) {
        /* IPv4: 根据 prefix_len 计算子网掩码
         * 使用 htonl(~0U << (32 - prefix_len)) 避免 1 << 32 的未定义行为 */
        __be32 mask;
        if (cmd->prefix_len == 0) {
          mask = 0;
        } else {
          mask = htonl(~0U << (32 - cmd->prefix_len));
        }
        ret = add_whitelist_entry(&fw_info, cmd->af, cmd->addr, &mask, cmd->prefix_len,
                                  cmd->device[0] ? (char *)cmd->device : NULL);
      } else {
        /* IPv6: 直接使用 prefix_len */
        ret = add_whitelist_entry(&fw_info, cmd->af, cmd->addr, NULL, cmd->prefix_len,
                                  cmd->device[0] ? (char *)cmd->device : NULL);
      }
      if (ret < 0) {
        pr_warn("netlink: add whitelist failed: %d\n", ret);
      }
      break;
    }

    case FW_NL_REMOVE_WHITELIST: {
      if (payload_len < (int)sizeof(struct fw_nl_whitelist_cmd)) {
        pr_warn("netlink: REMOVE_WHITELIST payload too short: %d\n", payload_len);
        break;
      }
      struct fw_nl_whitelist_cmd *cmd = (struct fw_nl_whitelist_cmd *)hdr;
      char ip_str[INET6_STR_LEN];
      int ret;

      ip_to_str(cmd->af, cmd->addr, ip_str, sizeof(ip_str));
      pr_info("netlink: remove whitelist %s/%u\n", ip_str, cmd->prefix_len);

      ret = remove_whitelist_entry(&fw_info, cmd->af, cmd->addr, cmd->prefix_len);
      if (ret < 0) {
        pr_warn("netlink: remove whitelist failed: %d\n", ret);
      }
      break;
    }

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
