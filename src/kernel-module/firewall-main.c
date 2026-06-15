/*
 * firewall.c - 用于 IP 封禁的 Linux 内核模块（主入口）
 *
 * 本模块使用 netfilter 钩子提供内核级 IP 封禁功能（支持 IPv4/IPv6）。
 */

#include "firewall.h"
#include <linux/printk.h>
#include <linux/random.h>
#include <linux/version.h>

/* 模块参数（非静态，可从 procfs 访问） */
unsigned int fw_ban_time = DEFAULT_BAN_TIME;
char *state_file = "/var/lib/firewall/state";
unsigned int fw_max_bans_per_second = 200;

module_param(fw_ban_time, uint, 0400);
MODULE_PARM_DESC(fw_ban_time, "封禁持续时间（秒）（默认 600）");
module_param(state_file, charp, 0444);
MODULE_PARM_DESC(state_file, "用于保存/恢复封禁和白名单条目的状态文件路径（默认 "
                             "/var/lib/firewall/state）");
module_param(fw_max_bans_per_second, uint, 0400);
MODULE_PARM_DESC(fw_max_bans_per_second, "泛洪保护下每秒最大封禁添加次数（默认 200）");

/* 全局防火墙信息 */
struct firewall_info fw_info;

/* 全局哈希种子（用于 IPv6 哈希表，防止哈希碰撞攻击） */
u32 fw_hash_seed;

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void) {
  return &fw_info;
}
EXPORT_SYMBOL_GPL(get_fw_info);

/*
 * cleanup_all_entries - 清理所有封禁和白名单条目
 * 修复 S2-5：使用 RCU 安全删除（hlist_del_rcu + call_rcu），
 * 防止 use-after-free。删除后调用 synchronize_rcu() 等待所有 RCU 回调完成。
 */
static void cleanup_all_entries(void) {
  struct ban_entry *entry;
  struct hlist_node *tmp;
  u32 ban_hash;
  struct whitelist_entry *wl;
  u32 wl_hash;

  hash_for_each_safe(fw_info.ban_table_ipv4, ban_hash, tmp, entry, hash) {
    hlist_del_rcu(&entry->hash);
    call_rcu(&entry->rcu_head, free_ban_entry_rcu);
  }

  hash_for_each_safe(fw_info.ban_table_ipv6, ban_hash, tmp, entry, hash) {
    hlist_del_rcu(&entry->hash);
    call_rcu(&entry->rcu_head, free_ban_entry_rcu);
  }

  hash_for_each_safe(fw_info.whitelist_table_ipv4, wl_hash, tmp, wl, hash) {
    hlist_del_rcu(&wl->hash);
    call_rcu(&wl->rcu_head, free_whitelist_entry_rcu);
  }

  hash_for_each_safe(fw_info.whitelist_table_ipv6, wl_hash, tmp, wl, hash) {
    hlist_del_rcu(&wl->hash);
    call_rcu(&wl->rcu_head, free_whitelist_entry_rcu);
  }

  /* 等待所有 RCU 回调完成，确保条目内存被完全释放 */
  synchronize_rcu();
}

/*
 * firewall_init - 模块初始化
 */
static int __init firewall_init(void) {
  int ret;

  pr_info("模块初始化开始\n");

  /* 初始化全局哈希种子（防止哈希碰撞攻击） */
  get_random_bytes(&fw_hash_seed, sizeof(fw_hash_seed));

  if (READ_ONCE(fw_ban_time) < 1) {
    pr_err("无效的 fw_ban_time 参数: %u (必须 >= 1)\n", fw_ban_time);
    return -EINVAL;
  }

  if (READ_ONCE(fw_ban_time) > 365 * 24 * 60 * 60) {
    pr_err("无效的 fw_ban_time 参数: %u (必须 <= 1年)\n", fw_ban_time);
    return -EINVAL;
  }

  spin_lock_init(&fw_info.lock);
  hash_init(fw_info.ban_table_ipv4);
  hash_init(fw_info.ban_table_ipv6);
  atomic_set(&fw_info.ban_count, 0);
  atomic_set(&fw_info.shutting_down, 0);

  /* R9-4: 初始化每桶自旋锁 */
  {
    int i;
    for (i = 0; i < (1 << BAN_HASH_BITS); i++) {
      spin_lock_init(&fw_info.ban_locks_ipv4[i]);
      spin_lock_init(&fw_info.ban_locks_ipv6[i]);
    }
  }

  spin_lock_init(&fw_info.flood_lock);
  fw_info.last_flood_check = jiffies;
  fw_info.recent_additions = 0;

  spin_lock_init(&fw_info.whitelist_lock);
  hash_init(fw_info.whitelist_table_ipv4);
  hash_init(fw_info.whitelist_table_ipv6);
  atomic_set(&fw_info.whitelist_count, 0);

  /* R9-3: 初始化子网白名单 RCU 链表 */
  INIT_LIST_HEAD(&fw_info.ipv4_subnet_wl);
  INIT_LIST_HEAD(&fw_info.ipv6_subnet_wl);

  /* 修复：初始化 IPv4 和 IPv6 独立的清理进度索引 */
  fw_info.cleanup_last_bucket_ipv4 = 0;
  fw_info.cleanup_last_bucket_ipv6 = 0;

  atomic_set(&fw_info.total_ban_count, 0);
  atomic_set(&fw_info.total_unban_count, 0);
  atomic_set(&fw_info.whitelist_reject_count, 0);
  atomic_set(&fw_info.ban_table_full_count, 0);
  atomic_set(&fw_info.alloc_failure_count, 0);
  atomic64_set(&fw_info.packets_dropped, 0);
  atomic64_set(&fw_info.packets_accepted, 0);
  atomic_set(&fw_info.cleanup_cycles, 0);
  atomic_set(&fw_info.cleanup_expired_total, 0);

  if (state_file && strlen(state_file) > 0) {
    restore_state_from_file(state_file);
  }

  INIT_DELAYED_WORK(&fw_info.sync_work, sync_work_handler);

  auto_discover_system_ips(&fw_info);

  ret = register_netdev_notifier(&fw_info);
  if (ret) {
    pr_warn("注册 netdev notifier 失败: %d\n", ret);
  }

  timer_setup(&fw_info.cleanup_timer, cleanup_timer_callback, 0);
  fw_info.timer_initialized = true;
  mod_timer(&fw_info.cleanup_timer,
            jiffies + ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 2);

  ret = create_procfs_entries(&fw_info);
  if (ret) {
    pr_err("创建 procfs 条目失败: %d\n", ret);
    goto err_notifier;
  }

  /* 注册 IPv4 Netfilter 钩子 */
  ret = nf_register_net_hook(&init_net, &nf_ops_ipv4);
  if (ret) {
    pr_err("注册 IPv4 netfilter 钩子失败: %d\n", ret);
    goto err_procfs;
  }

  /* 注册 IPv6 Netfilter 钩子 */
  ret = nf_register_net_hook(&init_net, &nf_ops_ipv6);
  if (ret) {
    pr_err("注册 IPv6 netfilter 钩子失败: %d\n", ret);
    goto err_nf_ipv4;
  }

  pr_info("模块初始化成功 (ban_time=%u, max_bans/s=%u)\n", fw_ban_time, fw_max_bans_per_second);
  return 0;

err_nf_ipv4:
  nf_unregister_net_hook(&init_net, &nf_ops_ipv4);
err_procfs:
  destroy_procfs_entries(&fw_info);
err_notifier:
  atomic_set(&fw_info.shutting_down, 1);
  cancel_delayed_work_sync(&fw_info.sync_work);
  timer_delete_sync(&fw_info.cleanup_timer);
  unregister_netdev_notifier(&fw_info);
  synchronize_rcu();
  cleanup_all_entries();
  return ret;
}

/*
 * firewall_exit - 模块清理
 */
static void __exit firewall_exit(void) {
  pr_info("模块清理开始\n");

  atomic_set(&fw_info.shutting_down, 1);

  cancel_delayed_work_sync(&fw_info.sync_work);

  /* 注销 Netfilter 钩子 */
  nf_unregister_net_hook(&init_net, &nf_ops_ipv4);
  nf_unregister_net_hook(&init_net, &nf_ops_ipv6);
  /* 修复 S2-5：确保所有 RCU 读者退出后再继续清理 */
  synchronize_rcu();

  unregister_netdev_notifier(&fw_info);

  if (fw_info.timer_initialized) {
    timer_delete_sync(&fw_info.cleanup_timer);
    fw_info.timer_initialized = false;
  }

  destroy_procfs_entries(&fw_info);

  synchronize_rcu();

  if (state_file && strlen(state_file) > 0) {
    save_state_to_file(state_file);
  }

  cleanup_all_entries();
  pr_info("模块清理完成\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative, IPv4/IPv6)");
MODULE_VERSION("2.2");
