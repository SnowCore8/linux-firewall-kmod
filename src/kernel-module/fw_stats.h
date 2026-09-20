/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_stats.h - per-CPU 统计与分析分布（fw_stats.c 的窄接口）
 *
 * 纪律：
 *   - 热路径 `fw_stat_*` 只写本 CPU 内存（无锁、无共享 cache line 写）。
 *   - 任何读侧（procfs 的 stats/5 个分析条目、netlink STATS_QUERY/
 *     ANALYSIS_QUERY）必须先 `fw_stats_flush_all()`，否则读到的是陈旧值
 *     （旧实现正因为漏了这一步而产生 PROC_STATS_STALE_NO_FLUSH）。
 *   - 全局 atomic 只由 flush 与事件回调（冷路径）写。
 */

#ifndef FW_STATS_H
#define FW_STATS_H

#include "fw_types.h"

/* 生命周期：分配/释放 per-CPU 统计块与分析全局表 */
int fw_stats_init(void);
void fw_stats_exit(void);

/* ---------------------------------------------------------------------------
 * 热路径计数（只写本 CPU）
 * ------------------------------------------------------------------------ */

/* 报文基础计数：接受/丢弃各一次，由 fw_hook.c 在判定结果处调用 */
static inline void fw_stat_bump(struct fw_stats_pcpu *s, bool accepted, bool tcp_anomaly) {
  if (accepted)
    s->packets_accepted++;
  else
    s->packets_dropped++;
  if (tcp_anomaly)
    s->tcp_anomaly_dropped++;
}

/* 直方图与分析分布：每包一次，全部落本 CPU 槽位 */
void fw_stat_account(u32 pkt_len, u8 ttl, bool is_fragment, u16 dst_port,
                     bool is_udp, bool is_icmp, u8 icmp_type, u8 icmp_code);

/* 全局流量字节/包（供 daemon 计算基线），同样只写本 CPU */
void fw_stat_global_traffic(u32 pkt_len);

/* 取本 CPU 统计块（热路径用，调用者已在软中断上下文） */
struct fw_stats_pcpu *fw_stats_this_cpu(void);

/* ---------------------------------------------------------------------------
 * 冷路径增量（事件、封禁、拒绝）
 * ------------------------------------------------------------------------ */
void fw_stat_inc_bans(void);
void fw_stat_inc_unbans(void);
void fw_stat_bump_wl_rejects(void);
void fw_stat_bump_ban_full(void);
void fw_stat_bump_alloc_fail(void);
void fw_stat_add_expired(u32 n);
void fw_stat_bump_rate_spill(void);

/* ---------------------------------------------------------------------------
 * 读侧
 * ------------------------------------------------------------------------ */

/* 把所有 CPU 的统计块并入全局 atomic（on_each_cpu，同步完成） */
void fw_stats_flush_all(void);

/* 取统计快照（内部会先 flush）。current_bans/current_whitelist 由调用者
 * 用 fw_ban_count()/fw_wl_count() 补齐，避免 fw_stats 反向依赖其它模块。 */
void fw_stats_snapshot(struct fw_stats_snapshot *out);

/* 取分析数据快照（内部会先 flush） */
void fw_stats_read_analysis(struct fw_analysis_snapshot *out);

/* 取走并清零全局流量计数（返回包数，*bytes 返回字节数） */
u64 fw_stats_take_traffic(u64 *bytes);

#endif /* FW_STATS_H */
