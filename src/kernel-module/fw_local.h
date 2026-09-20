/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_local.h - 本机接口精确地址集合（开放寻址哈希集）
 *
 * 只豁免**精确主机地址**（IPv4 /32、IPv6 /128），不扩成子网豁免。
 * 旧实现在 procfs 白名单 remove 路径上用子网比较判定「本机接口 IP」，
 * 导致接口配 /24 时整个网段的显式白名单条目都删不掉
 * （契约 defect PROC_WHITELIST_REMOVE_SUBNET_OVERREACH）；本模块与本设计
 * 都不重复该错误模式。
 *
 * 集合由 fw_netdev.c 构建，整体 rcu_assign_pointer 发布；热路径 RCU 只读，
 * 因此运行期不存在「空表 → 失败开放」窗口（钩子注册发生在首次发现之后）。
 */

#ifndef FW_LOCAL_H
#define FW_LOCAL_H

#include "fw_types.h"

/* 生命周期：仅清空已发布的集合。首个集合由 fw_netdev.c 发布 */
void fw_local_init(void);
void fw_local_exit(void);

/* 热路径：RCU 只读查表；未发布集合时返回 false */
bool fw_local_lookup(u8 af, const void *ip);

/* 集合操作（构建发生在 fw_netdev.c 的重新发现路径，非热路径）。
 * capacity == 0 表示按模块参数 fw_max_local_ips 取 2 的幂容量。 */
struct fw_local_set *fw_local_set_alloc(u32 capacity);
bool fw_local_set_insert(struct fw_local_set *set, u8 af, const void *addr);
void fw_local_publish(struct fw_local_set *set);
void fw_local_free_rcu(struct fw_local_set *set);
u32 fw_local_count(void);

#endif /* FW_LOCAL_H */
