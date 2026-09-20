/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_netlink.h - netlink socket 与收发（fw_netlink.c 的窄接口）
 *
 * 协议冻结面见 contract/netlink.fwidl 与 contract/generated/netlink_uapi.h：
 * NETLINK_USERSOCK、magic 0x46574C4E、12 字节头、全部 packed、多字节大端、
 * 原样地址字节（IPv4 取前 4 字节）、23 种消息类型。
 *
 * 本头只暴露「发送」方向；接收回调是 static，由 fw_netlink_init 注册。
 * 发送函数被 fw_ban.c / fw_wl.c / fw_procfs.c / fw_rate.c 调用，因此放在
 * 各模块均可依赖的位置（不反向依赖它们的内部类型）。
 *
 * 失败处置：所有发送函数内部吞掉错误（netlink 对端不在线是常态），
 * 返回类型为 void，调用者无需处理。
 */

#ifndef FW_NETLINK_H
#define FW_NETLINK_H

#include "fw_types.h"

/* 生命周期：创建/释放内核 socket（fw_main.c 在状态恢复之前调用 init） */
int fw_netlink_init(void);
void fw_netlink_exit(void);

/* ---- 事件（多播，守护进程订阅）---- */

/* DdosEvent：内核自决封禁时推送，rate_pps 为触发时的速率 */
void fw_nl_send_ddos_event(u8 af, const void *addr, const char *reason, u32 rate_pps);

/* BanStateChange：封禁/解封（含自动到期）时推送 */
void fw_nl_send_ban_state_change(u8 action, u8 af, const void *addr, u32 duration_secs,
                                 const char *reason, const char *jail);

/* WhitelistStateChange：白名单增删时推送 */
void fw_nl_send_whitelist_state_change(u8 action, u8 af, const void *addr,
                                       u8 prefix_len, const char *device);

/* ConfigChange：procfs 修改内核运行态配置时推送 */
void fw_nl_send_config_change(u32 flags, u32 ban_time);

#endif /* FW_NETLINK_H */
