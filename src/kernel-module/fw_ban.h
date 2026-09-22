/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_ban.h - 封禁表（按 prefix_len 分层的桶表 + RCU + 层内桶锁，per-entry 定时器）
 *
 * 与旧实现的关键差别：
 *   - **容量上限**：新增 fw_max_ban_entries（默认 65535），**在桶锁内**原子检查，
 *     到限拒绝并递增 ban_table_full_rejects —— 这给了该计数器唯一递增点，
 *     修复契约 defect PROC_BAN_TABLE_FULL_NEVER_INC。
 *   - 删除 retry_count（旧实现只有置零、无读取点）。
 *   - **泛洪闸门统一**：fw_ban_flood_allow() 由三条封禁路径（procfs / netlink /
 *     DDoS 自决）统一调用；旧实现只有 procfs 一条路径检查
 *     fw_max_bans_per_second（设计文档「本次新查出的稳定性问题 1」）。
 *   - **前缀封禁**：封禁条目带 prefix_len（32/128 表示精确单机，行为与加该字段
 *     之前完全等价）；查表命中条件从「地址相等」改为「地址落在条目前缀内」，
 *     复用白名单的 fw_prefix_match()。条目身份是 (af, addr, prefix_len) 三元组。
 *
 * 锁：层内桶锁（spin_lock_bh，每层每桶一把）+ ban_layer_lock（位图与层计数）。
 * 热路径只做 RCU 读，无锁。
 */

#ifndef FW_BAN_H
#define FW_BAN_H

#include "fw_types.h"

int fw_ban_init(void);
void fw_ban_exit(void);

/*
 * 热路径：RCU 只读查表（调用者持 RCU 读侧临界区）。
 * 命中含义 = 存在某条目 (af, addr, prefix_len) 使 ip 落在其前缀内。
 */
bool fw_ban_lookup(u8 af, const void *ip);

/*
 * 泛洪闸门：在滑动 1 秒窗口内限制封禁添加速率，超过返回 false。
 * 闸门只对**添加**生效，解封不受限。
 */
bool fw_ban_flood_allow(void);

/*
 * 封禁/解封。prefix_len 为前缀长度（IPv4 0..32，IPv6 0..128）；全长表示精确
 * 单机，是旧接口的等价语义。非法前缀长度按 -EINVAL 拒绝。
 * duration_secs == 0 表示永久；>0 表示临时（per-entry 定时器到期摘链）。
 * reason/jail 可为 NULL（按空串处理）。
 * notify=true 时推送 BAN_STATE_CHANGE 事件（含 prefix_len）。
 */
int fw_ban_add(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
               const char *reason, const char *jail, bool notify);
int fw_ban_del(u8 af, const void *addr, u8 prefix_len, bool notify);

/* 尝试封禁的完整入口（含白名单前检、容量检查、泛洪闸门、事件推送） */
int fw_ban_try_add(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
                   const char *reason, const char *jail, bool notify);

/* 条目计数（stats 与容量判定用） */
u32 fw_ban_count(void);
/*
 * 状态恢复用插入：跳过泛洪闸门，但**保留容量检查**。
 * banned_at 为原始封禁起点的 Unix 秒（0 表示以当前时刻为起点）。
 */
int fw_ban_restore(u8 af, const void *addr, u8 prefix_len, u32 duration_secs,
                   u64 banned_at, const char *reason, const char *jail);

/* 当前泛洪窗口内的封禁尝试次数（procfs stats 的 recent_additions 键） */
unsigned int fw_ban_recent_additions_stat(void);

/* 读侧分页遍历：offset 为「IPv4 表序 + IPv6 表序」的全局下标 */
u32 fw_ban_fill_entries(u32 offset, u32 limit, struct fw_ban_row *rows);

/* 退出清理：摘链 + 取消定时器 + synchronize_rcu + rcu_barrier */
void fw_ban_exit(void);

/* 供白名单变更联动：解封落在某子网/精确地址内的条目 */
void fw_ban_del_matching(u8 af, const void *network, u8 prefix_len);

#endif /* FW_BAN_H */
