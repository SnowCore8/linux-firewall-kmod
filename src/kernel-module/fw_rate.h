/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_rate.h - 速率表、窗口滚动、EWMA、违规判定
 *
 * 与旧实现的关键差别（见 docs/zh/development/kernel-rewrite-design.md
 * 「速率表」与「热路径重设计」）：
 *
 *   1. **一次查表**。旧实现的 update_rate_stats / check_rate_violation /
 *      check_protocol_violation / check_tcp_flood_violation 各自调用
 *      find_rate_entry_rcu，合计 2.81 次/包。新实现由 fw_rate_observe()
 *      一次查表取到条目指针，同一指针完成窗口滚动 + 四类违规判定。
 *
 *   2. **窗口原始计数落 per-CPU 槽**。旧实现把 packet/byte/syn/udp/... 放在
 *      条目的共享 atomic64 上，多核同源流量争用同一条 cache line。新实现每 CPU
 *      一组直接映射槽（fw_types.h 的 struct fw_rate_cpu_slot），热路径只写本
 *      CPU 内存；窗口滚动时由 cmpxchg 选举出的那个 CPU 汇总各 CPU 槽并清零，
 *      热路径不为此取锁。
 *
 *   3. **热路径不因端口去重取锁**。旧实现只要 dst_port > 0 就取速率桶锁更新
 *      seen_ports（最多 32 项线性扫描）。去重集合移到 per-CPU 槽，滚动时取并集。
 *
 * 槽位分配：一条目占一槽，永不复用他人槽位。建条目时在 slot_lock 下从地址哈希
 * 位置线性探测空槽，整表探不到空槽即视为「表满」——失败开放，见 fw_rate_observe()。
 * 槽位与条目同生命周期，静默超过保留时长的条目由回收工作项（fw_rate_reclaim_work）
 * 释放，使槽表反映「近期活跃源」而不是「历史累积源」。
 */

#ifndef FW_RATE_H
#define FW_RATE_H

#include "fw_types.h"

/* 生命周期：建表、初始化 per-CPU 槽、per-bucket 锁（fw_main.c 按序调用） */
int fw_rate_init(void);
void fw_rate_exit(void);

/*
 * 热路径判定入口（已持 RCU 读锁，调用者即 fw_hook.c 的单次 RCU 临界区）。
 *
 *   addr       源地址（v4 指向 __be32，v6 指向 struct in6_addr）
 *   packet_len 报文长度（用于字节速率）
 *   protocol   IPPROTO_*（0 表示非首片或无法解析传输层，跳过协议专项判定）
 *   tcp_flags  TCP 标志位（protocol != TCP 时为 0）
 *   dst_port   目的端口（非 TCP/UDP 或非首片时为 0；0 表示不入端口去重集合）
 *   out_pps    非 NULL 时写回本条目当前的平滑包速率（用于 DdosEvent.rate_pps）
 *
 * 返回 NULL 表示未违规；否则返回静态字符串常量，可直接作为封禁理由与
 * netlink DdosEvent.reason：
 *   "total rate" / "SYN flood" / "ACK flood" / "RST flood" / "FIN flood" /
 *   "UDP flood" / "ICMP flood"
 *
 * 速率表满时**有意放行**：可跟踪的源地址数达上限（fw_max_rate_entries 与
 * FW_RATE_CPU_SLOTS 的较小值，后者通常是瓶颈）后，新源地址不做速率判定，返回
 * NULL。这是契约里显式记录的失败开放方向（表满时丢包会误伤正常流量，见
 * PROC_RATE_TABLE_FULL_FAILS_OPEN），由 rate_slot_spill 观测并在 procfs rates
 * 表头读出；静默超过保留时长的条目由周期回收工作项释放槽位，故「满」只在活跃
 * 源确实超过上限时才是稳态。
 */
const char *fw_rate_observe(u8 af, const void *addr, u32 packet_len, u8 protocol,
                            u8 tcp_flags, u16 dst_port, u64 *out_pps);

/* 条目计数（stats / 容量判定） */
u32 fw_rate_count(void);

/*
 * 清空全部速率条目（rate_window 变更时调用；旧实现同样在 SET_CONFIG 的
 * bit1 路径清表）。仅冷路径调用。
 */
void fw_rate_clear_all(void);

/*
 * 更新全局基线（EWMA α = 1/100），由 SET_CONFIG 的 BASELINE_UPDATE 位驱动。
 * total_pps 为 daemon 按真实查询间隔折算后的包速率。
 */
void fw_rate_update_baseline(u64 total_pps, u64 total_bps);

/* 读侧分页遍历（netlink LIST_RATES_RESPONSE 与 procfs rates 共用） */
u32 fw_rate_fill_entries(u32 offset, u32 limit, struct fw_rate_row *rows);

/*
 * 端口扫描者 / 服务探测者收集（fw_stats_read_analysis 组合，不单独对外）。
 * port_scanners / service_probes 最多各写满 port_max / probe_max 行；
 * *probe_count 回填服务探测者行数。
 */
void fw_rate_read_scanners(struct fw_scanner_row *port_scanners, u32 port_max,
                           struct fw_scanner_row *service_probes, u32 probe_max,
                           u32 *probe_count);

#endif /* FW_RATE_H */
