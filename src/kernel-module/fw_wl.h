/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_wl.h - 白名单（64 精确桶 + 子网链表）
 *
 * 子网链表是必要设计：避免为前缀匹配遍历全部桶。
 * 精确条目只入桶；前缀 < 全长的条目同时入桶与子网链。
 *
 * 容量上限由模块参数 fw_max_whitelist_entries 实施（修复契约 defect
 * PROC_WHITELIST_CAPACITY_UNENFORCED：旧实现「跳过容量检查」）。
 */

#ifndef FW_WL_H
#define FW_WL_H

#include "fw_types.h"

int fw_wl_init(void);
void fw_wl_exit(void);

/* 热路径：RCU 只读（先查精确桶，再查子网链） */
bool fw_wl_lookup(u8 af, const void *ip);

/*
 * 添加白名单。prefix_len 为前缀位数（IPv4 0..32，IPv6 0..128），
 * 等于全长为精确匹配。子网条目按 (af, network/prefix) 归一化后去重。
 */
int fw_wl_add(u8 af, const void *ip, u8 prefix_len, const char *device_name);

/* 移除白名单：必须 (af, 地址, prefix_len) 完全一致才移除 */
int fw_wl_remove(u8 af, const void *ip, u8 prefix_len);

/* 静默移除（netdev 变更路径用）：不触发封禁联动，失败返回负 errno */
int fw_wl_remove_quiet(u8 af, const void *ip, u8 prefix_len);

u32 fw_wl_count(void);

/* 读侧遍历：把 offset 起的至多 limit 条写入 rows，返回写入条数 */
u32 fw_wl_fill_entries(u32 offset, u32 limit, struct fw_wl_row *rows);

/* 是否存在与 (af, addr) 精确相等的条目（用于去重与状态恢复） */
bool fw_wl_has_exact(u8 af, const void *ip);

#endif /* FW_WL_H */
