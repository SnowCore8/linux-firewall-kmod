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
  FW_NL_DDOS_EVENT = 1, /* 内核 → 守护进程：DDoS 违规事件 */
  FW_NL_BAN_IP = 2,     /* 守护进程 → 内核：封禁 IP */
  FW_NL_UNBAN_IP = 3,   /* 守护进程 → 内核：解封 IP */
  FW_NL_SET_CONFIG = 4, /* 守护进程 → 内核：配置更新 */
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

/* 封禁/解封命令载荷 */
struct fw_nl_ban_cmd {
  struct fw_nlmsg_hdr hdr;
  __u8 af;             /* 地址族 */
  __u32 duration_secs; /* 封禁时长（秒），0 = 永久 */
  __u8 addr[16];       /* IP 地址 */
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

  /* 构造消息 */
  event = (struct fw_nl_ddos_event *)nlmsg_put(skb, 0, 0, 0, sizeof(*event), 0);
  if (!event) {
    kfree_skb(skb);
    return -ENOMEM;
  }

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

    case FW_NL_SET_CONFIG:
      /* 配置热更新暂未实现，守护进程通过重启应用新配置 */
      pr_warn("netlink: SET_CONFIG not supported, restart daemon instead\n");
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
