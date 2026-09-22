/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_ports.h - 受保护端口位图（对外监听端口 → 参与 DDoS 速率判定）
 *
 * 语义是「纳入防护」而非「豁免」：置位端口 = 该目的端口的入站流量参与 DDoS
 * 速率判定。公网唯一能打到本机的就是这些对外监听端口，防护聚焦于此；未置位
 * 端口不参与速率判定，避免内部流量产生误封。
 *
 * 封禁表（jail 日志判定或手工下发）**不受本位图影响**，仍对所有端口生效——
 * 本位图只收窄「速率判定」的作用面，不改变「已被封禁的 IP 一律丢包」。
 *
 * 无端口报文（ICMP、非首片、传输层解析失败）由调用方以 dst_port == 0 表达，
 * 一律视为受保护，因此 ICMP flood 判定不受本位图收窄（见 fw_hook.c）。
 *
 * 并发：daemon 经 netlink 下发新位图，整块分配 + rcu_assign_pointer 换指针，
 * 旧块 kfree_rcu 释放；热路径只做一次位测试，无锁、无分配、无共享写。
 */

#ifndef FW_PORTS_H
#define FW_PORTS_H

#include "fw_types.h"

/* 生命周期：仅清空已发布的位图（未发布 = 全端口受保护，见下） */
void fw_ports_init(void);
void fw_ports_exit(void);

/*
 * 热路径：该目的端口是否受保护（是否参与 DDoS 速率判定）。
 *
 * **未下发位图时返回 true**——daemon 不在位不等于关掉检测。这是刻意的安全
 * 默认值：位图未就绪时行为与本特性引入前一致（全端口参与速率判定），
 * daemon 起来后下发真实集合才收窄作用面。
 */
bool fw_ports_is_protected(u16 port);

/*
 * 下发新位图（netlink 冷路径）。bitmap 必须是 FW_PROTECTED_PORTS_BYTES 字节；
 * count 只用于展示，内核自行重算置位数。失败返回负错误码，且不改动旧位图。
 */
int fw_ports_replace(const u8 *bitmap);

/* 当前置位端口数；未下发位图时返回 0（此时有效语义是全端口，见 above） */
u32 fw_ports_count(void);

/*
 * 热路径门控：该报文是否参与 DDoS 速率判定（dst_port == 0 表示无端口）。
 *
 * 无端口报文（ICMP、非首片、传输层解析失败）一律返回 true——位图按端口收窄
 * 作用面，不能顺带关掉没有端口的协议判定（ICMP flood 就落在这条路径上）。
 * 只有确实解析出端口、且该端口未置位时才不收窄。
 */
static inline bool fw_ports_observe(u16 dst_port) {
  if (dst_port == 0)
    return true;
  return fw_ports_is_protected(dst_port);
}

/* 是否已下发过位图（procfs 用于区分「全端口」与「已收窄」两种状态） */
bool fw_ports_published(void);

/* procfs 展示：把当前位图快照写入 out（须 FW_PROTECTED_PORTS_BYTES 字节）。
 * 未下发位图时不修改 out 并返回 false。 */
bool fw_ports_snapshot(u8 *out);

#endif /* FW_PORTS_H */
