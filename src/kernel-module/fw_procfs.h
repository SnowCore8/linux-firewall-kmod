/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_procfs.h - 12 个 /proc/firewall 条目（fw_procfs.c 的窄接口）
 *
 * 对外文本协议由 contract/procfs.fwidl 冻结，生成物见
 * contract/generated/procfs_uapi.h。本模块只负责：
 *   - 按契约的条目名与权限位创建/销毁条目；
 *   - 读侧：stats 为机器可读的 13 个 key（key 名与数值类型不可改），
 *     其余 11 个为 unstable 人类可读表格；
 *   - 写侧：bans / whitelist / config 三种命令文法（一次 write 一条命令）。
 *
 * 读侧纪律：所有统计类读数先经 fw_stats_* 的「读前先刷」，消除旧实现
 * stats_show 不刷新 per-CPU 计数导致的陈旧读数（缺陷 PROC_STATS_STALE_NO_FLUSH）。
 */

#ifndef FW_PROCFS_H
#define FW_PROCFS_H

#include "fw_types.h"

/* 创建 /proc/firewall 及其全部条目；失败时自行回滚已创建的部分 */
int fw_procfs_init(void);

/* 逆序移除全部条目与根目录 */
void fw_procfs_exit(void);

#endif /* FW_PROCFS_H */
