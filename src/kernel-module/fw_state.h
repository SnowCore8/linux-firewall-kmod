/* SPDX-License-Identifier: Dual MIT/GPL */
/*
 * fw_state.h - 状态文件读写（fw_state.c 的窄接口）
 *
 * 对外格式是**稳定的运维契约**（daemon 与测试工具都会读它），改动需同步文档：
 *
 *   FW_STATE 1
 *   BAN_V4 <ip> <remaining_secs> <jail> <reason...>
 *   BAN_V6 <ip> <remaining_secs> <jail> <reason...>
 *   WL_V4 <network> <prefix_len> <device>
 *   WL_V6 <network> <prefix_len> <device>
 *   CRC32 <8 位十六进制>
 *
 * 说明：
 *   - remaining_secs == 0 表示永久封禁；> 365 天视为损坏行，跳过。
 *   - jail 内的空白/换行被替换为 '_'（保持行内分隔）；reason 是行尾剩余字段，
 *     可含空格，故放在最后。
 *   - CRC32 覆盖 CRC 行之前的**全部字节**，存的是 crc32_le 的**反码**
 *     （与旧实现一致，便于与既有文件互认）。
 *   - 写盘走「同目录 .tmp → rename」原子替换，避免掉电留下半截文件。
 *   - 恢复**保留容量检查**：条目数达到模块参数上限时按 -ENOSPC 跳过该行并计数，
 *     不再无条件越限恢复。
 */

#ifndef FW_STATE_H
#define FW_STATE_H

#include "fw_types.h"

/* 把当前封禁表与白名单写入 fw_state_file（内部读取该全局参数） */
int fw_state_save(void);

/*
 * 从 fw_state_file 恢复。仅在模块生命周期内执行一次（重复调用直接返回 0）。
 * 白名单先于封禁恢复，这样封禁恢复的白名单前检能命中。
 */
int fw_state_restore(void);

#endif /* FW_STATE_H */
