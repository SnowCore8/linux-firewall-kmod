/*
 * netdev.c - 网络设备通知器
 *
 * 包含网络设备事件监听、系统 IP 自动发现和白名单同步相关的函数实现。
 */

#include "firewall.h"

/* 自动发现的临时存储结构 */
struct temp_ip_entry {
    __be32 ip;
    __be32 mask;
    char name[16];
};

/* 辅助函数：将 IPv4 转换为字符串 */
static inline void ipv4_to_str(__be32 ip, char *buf, int len)
{
    unsigned int a = ntohl(ip) >> 24;
    unsigned int b = (ntohl(ip) >> 16) & 0xFF;
    unsigned int c = (ntohl(ip) >> 8) & 0xFF;
    unsigned int d = ntohl(ip) & 0xFF;

    if (len < 16) {
        if (len > 0) {
            buf[0] = '\0';
        }
        return;
    }

    snprintf(buf, len, "%u.%u.%u.%u", a, b, c, d);
}

/* 辅助函数：比较 IPv4 地址 */
static inline bool compare_ips(__be32 ip1, __be32 ip2)
{
    return ip1 == ip2;
}

/*
 * sync_work_handler - 延迟工作队列处理函数（防抖后执行）
 */
void sync_work_handler(struct work_struct *work)
{
    struct firewall_info *fw;
    struct temp_ip_entry *current_ips;
    int current_count = 0;
    struct net_device *dev;
    struct in_device *in_dev;
    struct in_ifaddr *ifa;
    struct whitelist_entry *entry;
    struct hlist_node *tmp;
    u32 bkt;
    int i;

    fw = container_of(work, struct firewall_info, sync_work.work);

    FW_DEBUG(1, "ENTRY: sync_work_handler");

    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: sync_work_handler -> void (shutting down)");
        return;
    }

    current_ips = kmalloc_array(MAX_DISCOVERED_IPS, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!current_ips) {
        fw_pr_err("Failed to allocate current_ips");
        return;
    }

    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        if (!(dev->flags & IFF_UP))
            continue;

        in_dev = __in_dev_get_rcu(dev);
        if (in_dev) {
            for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
                 ifa = rcu_dereference(ifa->ifa_next)) {
                if (current_count >= MAX_DISCOVERED_IPS)
                    break;

                if (!ifa->ifa_local)
                    continue;

                current_ips[current_count].ip = ifa->ifa_local;
                current_ips[current_count].mask = ifa->ifa_mask;
                strscpy(current_ips[current_count].name, dev->name, 16);
                current_count++;
            }
        }
    }
    rcu_read_unlock();

    if (current_count == 0) {
        fw_pr_debug("No active network interfaces with IPv4 found");
        kfree(current_ips);
        return;
    }

    struct current_ip_lookup {
        __be32 ip;
        __be32 mask;
        bool found;
    };
    struct current_ip_lookup *lookup_table;
    lookup_table = kmalloc_array(current_count, sizeof(struct current_ip_lookup), GFP_KERNEL);
    if (!lookup_table) {
        fw_pr_err("Failed to allocate lookup_table");
        kfree(current_ips);
        return;
    }
    for (i = 0; i < current_count; i++) {
        lookup_table[i].ip = current_ips[i].ip & current_ips[i].mask;
        lookup_table[i].mask = current_ips[i].mask;
        lookup_table[i].found = false;
    }

    spin_lock(&fw->whitelist_lock);
    hash_for_each_safe(fw->whitelist_table, bkt, tmp, entry, hash) {
        if (strcmp(entry->device_name, "manual") == 0 ||
            strcmp(entry->device_name, "restored") == 0) {
            continue;
        }

        for (i = 0; i < current_count; i++) {
            __be32 normalized_current = current_ips[i].ip & current_ips[i].mask;
            if (entry->ip == normalized_current && entry->mask == current_ips[i].mask) {
                lookup_table[i].found = true;
                break;
            }
        }

        if (i == current_count) {
            char ip_str[INET_ADDRSTRLEN];
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            FW_DEBUG(2, "Removing stale whitelist entry for %s/%d on %s",
                     ip_str, inet_mask_len(entry->mask), entry->device_name);
            hlist_del_rcu(&entry->hash);
            atomic_dec(&fw->whitelist_count);
            call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
        }
    }
    spin_unlock(&fw->whitelist_lock);

    for (i = 0; i < current_count; i++) {
        if (!lookup_table[i].found) {
            if (add_whitelist_entry(fw, current_ips[i].ip, current_ips[i].mask, current_ips[i].name) < 0) {
                fw_pr_warn("Failed to add system IPv4 %pI4 to whitelist during sync", &current_ips[i].ip);
            }
        }
    }

    kfree(lookup_table);
    kfree(current_ips);

    fw_pr_info_ratelimited("Sync complete. Current whitelist entries: %d", atomic_read(&fw->whitelist_count));
    FW_DEBUG(1, "EXIT: sync_work_handler -> void (success, wl_count=%d)", atomic_read(&fw->whitelist_count));
}

/*
 * sync_system_ips - 调度 IP 同步工作（带防抖）
 */
void sync_system_ips(struct firewall_info *fw)
{
    unsigned long delay = msecs_to_jiffies(500);

    FW_DEBUG(1, "ENTRY: sync_system_ips (scheduling with 500ms debounce)");

    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: sync_system_ips -> void (shutting down)");
        return;
    }

    mod_delayed_work(system_wq, &fw->sync_work, delay);

    FW_DEBUG(1, "EXIT: sync_system_ips -> void (work scheduled)");
}
EXPORT_SYMBOL_GPL(sync_system_ips);

/*
 * netdev_event_handler - 网络设备事件回调函数
 */
static int netdev_event_handler(struct notifier_block *nb, unsigned long event, void *ptr)
{
    struct firewall_info *fw;
    struct net_device *dev;

    fw = container_of(nb, struct firewall_info, netdev_notifier);

    if (unlikely(atomic_read(&fw->shutting_down)))
        return NOTIFY_DONE;

    dev = netdev_notifier_info_to_dev(ptr);
    if (!dev)
        return NOTIFY_DONE;

    switch (event) {
    case NETDEV_UP:
    case NETDEV_DOWN:
    case NETDEV_CHANGE:
        fw_pr_debug_ratelimited("Network event %lu on device %s", event, dev->name);
        sync_system_ips(fw);
        break;
    default:
        break;
    }

    return NOTIFY_DONE;
}

/*
 * register_netdev_notifier - 注册网络设备事件监听器
 */
int register_netdev_notifier(struct firewall_info *fw)
{
    int ret;

    FW_DEBUG(1, "ENTRY: register_netdev_notifier");

    fw->netdev_notifier.notifier_call = netdev_event_handler;

    ret = register_netdevice_notifier(&fw->netdev_notifier);
    if (ret) {
        fw_pr_err("Failed to register netdevice notifier: %d", ret);
        fw->netdev_notifier_registered = false;
        FW_DEBUG(1, "EXIT: register_netdev_notifier -> %d", ret);
        return ret;
    }

    fw->netdev_notifier_registered = true;
    fw_pr_info("Network device notifier registered");
    FW_DEBUG(1, "EXIT: register_netdev_notifier -> 0");
    return 0;
}
EXPORT_SYMBOL_GPL(register_netdev_notifier);

/*
 * unregister_netdev_notifier - 注销网络设备事件监听器
 */
void unregister_netdev_notifier(struct firewall_info *fw)
{
    FW_DEBUG(1, "ENTRY: unregister_netdev_notifier");

    if (fw->netdev_notifier_registered) {
        unregister_netdevice_notifier(&fw->netdev_notifier);
        fw->netdev_notifier_registered = false;
        fw_pr_info("Network device notifier unregistered");
    } else {
        fw_pr_debug("Network device notifier was not registered");
    }

    FW_DEBUG(1, "EXIT: unregister_netdev_notifier -> void");
}
EXPORT_SYMBOL_GPL(unregister_netdev_notifier);

/*
 * auto_discover_system_ips - 自动发现系统 IP 并添加到白名单
 */
void auto_discover_system_ips(struct firewall_info *fw)
{
    struct temp_ip_entry *temp_ips;
    int temp_count = 0;

    struct net_device *dev;
    struct in_device *in_dev;
    struct in_ifaddr *ifa;

    FW_DEBUG(1, "ENTRY: auto_discover_system_ips");

    temp_ips = kmalloc_array(MAX_DISCOVERED_IPS, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!temp_ips) {
        fw_pr_err("Failed to allocate temp_ips");
        FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (alloc temp_ips failed)");
        return;
    }

    fw_pr_info_ratelimited("Auto-discovering system IPs...");

    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        if (dev->flags & IFF_LOOPBACK)
            continue;

        if (!(dev->flags & IFF_UP))
            continue;

        in_dev = __in_dev_get_rcu(dev);
        if (in_dev) {
            for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
                 ifa = rcu_dereference(ifa->ifa_next)) {
                if (temp_count >= MAX_DISCOVERED_IPS)
                    break;

                if (!ifa->ifa_local) {
                    continue;
                }

                temp_ips[temp_count].ip = ifa->ifa_local;
                temp_ips[temp_count].mask = ifa->ifa_mask;
                strscpy(temp_ips[temp_count].name, dev->name, 16);
                temp_count++;
            }
        }
    }
    rcu_read_unlock();

    for (int i = 0; i < temp_count; i++) {
        if (add_whitelist_entry(fw, temp_ips[i].ip, temp_ips[i].mask, temp_ips[i].name) < 0) {
            fw_pr_warn("Failed to add system IPv4 %pI4 to whitelist", &temp_ips[i].ip);
        }
    }

    fw_pr_info_ratelimited("Auto-discovery complete. %d entries", atomic_read(&fw->whitelist_count));

    kfree(temp_ips);

    FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (success, wl_count=%d)", atomic_read(&fw->whitelist_count));
}
EXPORT_SYMBOL_GPL(auto_discover_system_ips);
