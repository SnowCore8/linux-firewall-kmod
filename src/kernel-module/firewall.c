/*
 * firewall.c - 用于 IP 封禁的 Linux 内核模块（主入口）
 *
 * 本模块使用 netfilter 钩子提供内核级 IP 封禁功能。
 * 此文件仅保留模块参数声明、全局变量和初始化/退出函数。
 * 其他功能已拆分到独立文件中：
 *   - ban-manager.c: 封禁/解封管理
 *   - whitelist.c: 白名单管理
 *   - cleanup.c: 过期清理
 *   - netdev.c: 网络设备通知器
 *   - procfs.c: procfs 接口
 *   - netfilter.c: Netfilter 钩子
 *   - state-persist.c: 状态持久化
 */

#include "firewall.h"
#include <linux/version.h>

/* 模块参数（非静态，可从 procfs 访问） */
unsigned int fw_ban_time = DEFAULT_BAN_TIME;
char *state_file = "/var/lib/firewall/state";
unsigned int fw_max_bans_per_second = 200;

module_param(fw_ban_time, uint, 0644);
MODULE_PARM_DESC(fw_ban_time, "封禁持续时间（秒）（默认 600）");
module_param(state_file, charp, 0444);
MODULE_PARM_DESC(state_file, "用于保存/恢复封禁和白名单条目的状态文件路径（默认 /var/lib/firewall/state）");
module_param(fw_max_bans_per_second, uint, 0644);
MODULE_PARM_DESC(fw_max_bans_per_second, "泛洪保护下每秒最大封禁添加次数（默认 200）");

/* 全局防火墙信息 */
struct firewall_info fw_info;

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void)
{
    return &fw_info;
}
EXPORT_SYMBOL_GPL(get_fw_info);

/*
 * firewall_init - 模块初始化
 */
static int __init firewall_init(void)
{
    int ret;

    fw_pr_info("Loading firewall module v1.9");

    if (READ_ONCE(fw_ban_time) < 1) {
        fw_pr_err("fw_ban_time must be >= 1");
        return -EINVAL;
    }

    if (READ_ONCE(fw_ban_time) > 365 * 24 * 60 * 60) {
        fw_pr_err("fw_ban_time too large (max 1 year)");
        return -EINVAL;
    }

    spin_lock_init(&fw_info.lock);
    hash_init(fw_info.ban_table);
    atomic_set(&fw_info.ban_count, 0);
    atomic_set(&fw_info.shutting_down, 0);

    spin_lock_init(&fw_info.flood_lock);
    fw_info.last_flood_check = jiffies;
    fw_info.recent_additions = 0;

    spin_lock_init(&fw_info.whitelist_lock);
    hash_init(fw_info.whitelist_table);
    atomic_set(&fw_info.whitelist_count, 0);

    atomic_set(&fw_info.total_ban_count, 0);
    atomic_set(&fw_info.total_unban_count, 0);
    atomic_set(&fw_info.whitelist_reject_count, 0);
    atomic_set(&fw_info.ban_table_full_count, 0);
    atomic_set(&fw_info.alloc_failure_count, 0);
    atomic_set(&fw_info.packets_dropped, 0);
    atomic_set(&fw_info.packets_accepted, 0);
    atomic_set(&fw_info.cleanup_cycles, 0);
    atomic_set(&fw_info.cleanup_expired_total, 0);

    if (state_file && strlen(state_file) > 0) {
        int restore_ret = restore_state_from_file(state_file);
        if (restore_ret < 0) {
            fw_pr_err("Failed to restore state from %s (error %d), starting with clean state",
                      state_file, restore_ret);
        }
    }

    INIT_DELAYED_WORK(&fw_info.sync_work, sync_work_handler);

    auto_discover_system_ips(&fw_info);

    ret = register_netdev_notifier(&fw_info);
    if (ret) {
        fw_pr_warn("Failed to register netdev notifier, IP auto-update disabled");
    }

    timer_setup(&fw_info.cleanup_timer, cleanup_timer_callback, 0);
    fw_info.timer_initialized = true;
    mod_timer(&fw_info.cleanup_timer, jiffies + ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 2);

    ret = create_procfs_entries(&fw_info);
    if (ret)
        goto err_notifier;

    ret = nf_register_net_hook(&init_net, &nf_ops_ipv4);
    if (ret) {
        fw_pr_err("Failed to register IPv4 netfilter hook: %d", ret);
        goto err_procfs;
    }

    fw_pr_info("Module loaded successfully (ban_time=%u, state_file=%s)", fw_ban_time, state_file);
    return 0;

err_procfs:
    destroy_procfs_entries(&fw_info);
err_notifier:
    atomic_set(&fw_info.shutting_down, 1);

    cancel_delayed_work_sync(&fw_info.sync_work);

    timer_delete_sync(&fw_info.cleanup_timer);

    unregister_netdev_notifier(&fw_info);

    synchronize_rcu();

    {
        struct whitelist_entry *wl;
        u32 wl_hash;
        struct hlist_node *tmp;
        hash_for_each_safe(fw_info.whitelist_table, wl_hash, tmp, wl, hash) {
            hash_del(&wl->hash);
            kfree(wl);
        }
    }

    {
        struct ban_entry *entry;
        u32 ban_hash;
        struct hlist_node *tmp;
        hash_for_each_safe(fw_info.ban_table, ban_hash, tmp, entry, hash) {
            hash_del(&entry->hash);
            kfree(entry);
        }
    }

    return ret;
}

/*
 * firewall_exit - 模块清理
 */
static void __exit firewall_exit(void)
{
    struct ban_entry *entry;
    struct hlist_node *tmp;
    u32 ban_hash;
    struct whitelist_entry *wl;
    u32 wl_hash;

    fw_pr_info("Unloading firewall module");

    atomic_set(&fw_info.shutting_down, 1);

    cancel_delayed_work_sync(&fw_info.sync_work);

    nf_unregister_net_hook(&init_net, &nf_ops_ipv4);

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

    hash_for_each_safe(fw_info.ban_table, ban_hash, tmp, entry, hash) {
        hash_del(&entry->hash);
        kfree(entry);
    }

    hash_for_each_safe(fw_info.whitelist_table, wl_hash, tmp, wl, hash) {
        hash_del(&wl->hash);
        kfree(wl);
    }

    fw_pr_info("Module unloaded");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative)");
MODULE_VERSION("2.0");
