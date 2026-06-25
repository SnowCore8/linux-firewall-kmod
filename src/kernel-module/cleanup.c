/*
 * cleanup.c - RCU 释放回调 (支持 IPv4/IPv6)
 *
 * per-entry 过期由 ban_entry.expire_timer 自动管理，无需全局 cleanup_timer 轮询。
 * 类似 nftables 的 set timeout 机制，内核自动到期删除，零用户空间开销。
 */

#include "firewall.h"

void free_ban_entry_rcu(struct rcu_head *head) {
  struct ban_entry *entry = container_of(head, struct ban_entry, rcu_head);
  kfree(entry);
}

void free_whitelist_entry_rcu(struct rcu_head *head) {
  struct whitelist_entry *entry = container_of(head, struct whitelist_entry, rcu_head);
  kfree(entry);
}
