/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_netdev.h - netdev notifier 与本机地址集合的重建
 *
 * 职责边界（见 docs/zh/development/kernel-rewrite-design.md「本机地址集合」
 * 与「并发与生命周期」）：
 *
 *   - **首次发现**：fw_netdev_rebuild_local() 由 fw_main.c 在**注册钩子之前**
 *     同步调用，构建并发布第一张 local_set。这消除了旧实现「count == 0 即
 *     判定非本机」的空表窗口——钩子注册时表必然已存在。
 *   - **增量重建**：notifier 事件后 500 ms 防抖，在 delayed work 里重建
 *     **新表** 并 rcu_assign_pointer 发布，旧表交 kfree_rcu。
 *   - 只收集**精确主机地址**（IPv4 /32、IPv6 /128），不扩成子网豁免：
 *     旧实现在白名单 remove 路径上用子网比较判定「本机接口 IP」，
 *     造成 PROC_WHITELIST_REMOVE_SUBNET_OVERREACH，本设计不重复该错误。
 *
 * 白名单联动：重建时对「device_name 既非 manual 也非 restored」的条目做
 * 对账——接口地址已消失的自动条目被静默移除（fw_wl_remove_quiet，不触发
 * 封禁联动），并推送 WHITELIST_STATE_CHANGE(REMOVE)。用户手工添加的条目
 * 与状态恢复的条目不在此列，永不被自动删除。
 */

#ifndef FW_NETDEV_H
#define FW_NETDEV_H

#include "fw_types.h"

/*
 * 首次本机地址发现 + 发布。在钩子注册前调用。
 * 负返回值（-ENOMEM，集合或地址清单分配失败）视为不可恢复：调用者必须放弃
 * 注册钩子。集合为空意味着本机地址会被当成外来地址参与封禁，属严重退化，
 * 不允许带病运行（旧实现「count == 0 即判定非本机」正是这个失败开放窗口）。
 */
int fw_netdev_rebuild_local(void);

/* 注册 notifier（在首次发现之后调用） */
int fw_netdev_init(void);

/* 注销 notifier */
void fw_netdev_exit(void);

/* 取消防抖中的 delayed work（退出路径第一步调用） */
void fw_netdev_cancel_sync(void);

#endif /* FW_NETDEV_H */
