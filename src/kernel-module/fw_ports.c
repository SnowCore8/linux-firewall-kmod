// SPDX-License-Identifier: MIT OR GPL-2.0-only
/*
 * fw_ports.c - 受保护端口位图的存储与查找
 *
 * 位图固定 65536 位（8KB），一端口一位：置位 = 该端口的入站流量参与 DDoS
 * 速率判定。选位图而非端口数组的理由：无计数、无上限、查找退化成一次位测试，
 * 且整体换指针时不需要遍历重建索引。
 *
 * 并发模型与 fw_local.c 同构：整块 kzalloc → 填充 → rcu_assign_pointer 发布，
 * 旧块 kfree_rcu 释放；发布后内容不再修改，读者只需 RCU。写侧（replace / exit）
 * 另由 fw_ports_lock 串行，避免并发读到旧指针后各自 kfree_rcu 造成重复释放。
 *
 * 空指针语义是**全端口受保护**（而非「无端口受保护」）：daemon 未下发或已退出
 * 时，速率判定的作用面与本特性引入前完全一致，不会静默关掉检测。
 */

#define pr_fmt(fmt) "firewall: " fmt

#include <linux/bitmap.h>
#include <linux/slab.h>

#include "fw_ports.h"
#include "fw_stats.h"

/* 写侧串行锁：replace 与 exit 都做「读旧指针 → 发布新指针 → kfree_rcu 旧块」 */
static DEFINE_MUTEX(fw_ports_lock);

void fw_ports_init(void) {
  RCU_INIT_POINTER(fw_info.protected_ports, NULL);
}

void fw_ports_exit(void) {
  struct fw_protected_ports *ports;

  mutex_lock(&fw_ports_lock);
  ports = rcu_dereference_protected(fw_info.protected_ports, 1);
  RCU_INIT_POINTER(fw_info.protected_ports, NULL);
  if (ports)
    kfree_rcu(ports, rcu);
  mutex_unlock(&fw_ports_lock);
}

/* ============================================================================
 * 热路径
 * ==========================================================================*/

bool fw_ports_is_protected(u16 port) {
  const struct fw_protected_ports *ports = rcu_dereference(fw_info.protected_ports);

  if (unlikely(!ports))
    return true; /* 未下发位图：保持全端口防护，不静默关掉检测 */
  if (unlikely(port >= FW_PROTECTED_PORTS_MAX))
    return false;

  return test_bit(port, ports->bitmap) != 0;
}

/* ============================================================================
 * 下发（netlink 冷路径）
 * ==========================================================================*/

int fw_ports_replace(const u8 *bitmap) {
  struct fw_protected_ports *ports;
  struct fw_protected_ports *old;
  u32 count;

  if (!bitmap)
    return -EINVAL;

  mutex_lock(&fw_ports_lock);

  ports = kzalloc(sizeof(*ports), GFP_KERNEL);
  if (!ports) {
    fw_stat_bump_alloc_fail();
    mutex_unlock(&fw_ports_lock);
    return -ENOMEM;
  }

  memcpy(ports->bitmap, bitmap, FW_PROTECTED_PORTS_BYTES);
  /* 置位数由内核重算，不采信发送方给的 count（展示字段不可作为状态依据） */
  count = bitmap_weight(ports->bitmap, FW_PROTECTED_PORTS_MAX);
  ports->count = count;

  old = rcu_dereference_protected(fw_info.protected_ports, 1);
  rcu_assign_pointer(fw_info.protected_ports, ports);
  if (old)
    kfree_rcu(old, rcu);
  mutex_unlock(&fw_ports_lock);

  pr_info("protected ports updated: %u port(s) now participate in rate detection\n", count);
  return 0;
}

u32 fw_ports_count(void) {
  const struct fw_protected_ports *ports;
  u32 count = 0;

  rcu_read_lock();
  ports = rcu_dereference(fw_info.protected_ports);
  if (ports)
    count = ports->count;
  rcu_read_unlock();

  return count;
}

bool fw_ports_published(void) {
  return rcu_dereference_protected(fw_info.protected_ports, 1) != NULL;
}

bool fw_ports_snapshot(u8 *out) {
  const struct fw_protected_ports *ports;

  if (!out)
    return false;

  rcu_read_lock();
  ports = rcu_dereference(fw_info.protected_ports);
  if (ports)
    memcpy(out, ports->bitmap, FW_PROTECTED_PORTS_BYTES);
  rcu_read_unlock();

  return ports != NULL;
}
