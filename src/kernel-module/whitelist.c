/*
 * whitelist.c - 白名单管理
 *
 * 包含白名单添加、移除、查询相关的函数实现。
 */

#include "firewall.h"

/* 辅助函数：比较 IPv4 地址 */
static inline bool compare_ips(__be32 ip1, __be32 ip2)
{
    return ip1 == ip2;
}

/*
 * validate_ipv4_address - 统一的 IPv4 地址验证
 */
static int validate_ipv4_address(__be32 ip, const char *ip_str, const char *context)
{
    unsigned int ip_num = ntohl(ip);

    if (ip == 0 || ip == 0xFFFFFFFF) {
        fw_pr_warn("Attempt to %s invalid IPv4: %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0x7F000000) {
        fw_pr_warn("Attempt to %s loopback IPv4: %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xF0000000) == 0xE0000000) {
        fw_pr_warn("Attempt to %s reserved IPv4 (multicast/Class E): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0x00000000) {
        fw_pr_warn("Attempt to %s invalid IPv4 (0.0.0.0/8): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0xFF000000) {
        fw_pr_warn("Attempt to %s invalid IPv4 (255.0.0.0/8): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }

    return 0;
}

/*
 * add_whitelist_entry - 将 IPv4 添加到白名单哈希表
 */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name)
{
    struct whitelist_entry *new_entry;
    struct whitelist_entry *tmp_entry;
    u32 hash;

    FW_DEBUG(1, "ENTRY: add_whitelist_entry(ip=%pI4, mask=%pI4, dev=%s)", &ip, &mask, dev_name ?: "null");

    if (!mask) {
        fw_pr_warn("Invalid mask 0x%08x for IP %pI4", mask, &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid mask)");
        return -EINVAL;
    }

    if (validate_ipv4_address(ip, NULL, "whitelist") < 0) {
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    __be32 normalized_ip = ip & mask;

    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    FW_DEBUG(2, "Attempting to add whitelist entry for %pI4/%d", &normalized_ip, inet_mask_len(mask));

    /* 在锁外分配内存 */
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        FW_DEBUG(1, "Failed to allocate memory for whitelist entry for IP %pI4", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -ENOMEM");
        return -ENOMEM;
    }

    new_entry->ip = normalized_ip;
    new_entry->mask = mask;
    if (dev_name)
        strscpy(new_entry->device_name, dev_name, sizeof(new_entry->device_name));
    else
        new_entry->device_name[0] = '\0';

    spin_lock(&fw->whitelist_lock);

    hash_for_each_possible(fw->whitelist_table, tmp_entry, hash, normalized_ip) {
        if (compare_ips(tmp_entry->ip, normalized_ip) &&
            tmp_entry->mask == mask) {
            spin_unlock(&fw->whitelist_lock);
            kfree(new_entry);
            FW_DEBUG(2, "EXIT: add_whitelist_entry -> 0 (already exists)");
            return 0;
        }
    }

    if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
        spin_unlock(&fw->whitelist_lock);
        kfree(new_entry);
        fw_pr_warn("Whitelist full, cannot add %pI4/%d", &normalized_ip, inet_mask_len(mask));
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -ENOSPC (whitelist full)");
        return -ENOSPC;
    }

    hash_add(fw->whitelist_table, &new_entry->hash, normalized_ip);
    atomic_inc(&fw->whitelist_count);
    spin_unlock(&fw->whitelist_lock);

    FW_DEBUG(1, "Successfully added whitelist entry for %pI4/%d on %s",
             &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    fw_pr_info("Whitelisted %pI4/%d on %s", &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    FW_DEBUG(1, "EXIT: add_whitelist_entry -> 0 (success)");
    return 0;
}
EXPORT_SYMBOL_GPL(add_whitelist_entry);

/*
 * remove_whitelist_entry - 从白名单哈希表中移除 IPv4
 */
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip_input)
{
    struct whitelist_entry *entry;
    u32 hash;
    int found = 0;
    __be32 normalized_ip = ip_input;

    FW_DEBUG(1, "ENTRY: remove_whitelist_entry(ip=%pI4)", &normalized_ip);

    spin_lock(&fw->whitelist_lock);
    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip) {
        if (compare_ips(entry->ip, normalized_ip)) {
            hlist_del_rcu(&entry->hash);
            atomic_dec(&fw->whitelist_count);
            found = 1;
            call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
            FW_DEBUG(2, "Found and removed whitelist entry for %pI4", &normalized_ip);
            break;
        }
    }
    spin_unlock(&fw->whitelist_lock);

    if (found) {
        fw_pr_info("Removed %pI4 from whitelist", &normalized_ip);
        FW_DEBUG(1, "EXIT: remove_whitelist_entry -> 0 (success)");
        return 0;
    }

    fw_pr_warn("%pI4 not found in whitelist", &normalized_ip);
    FW_DEBUG(1, "EXIT: remove_whitelist_entry -> -ENOENT (not found)");
    return -ENOENT;
}
EXPORT_SYMBOL_GPL(remove_whitelist_entry);

/*
 * is_in_whitelist - 检查 IPv4 是否在白名单哈希表中
 */
bool is_in_whitelist(struct firewall_info *fw, __be32 ip)
{
    struct whitelist_entry *entry;
    u32 hash;

    FW_DEBUG(3, "ENTRY: is_in_whitelist(ip=%pI4)", &ip);

    rcu_read_lock();
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        if ((ip & entry->mask) == (entry->ip & entry->mask)) {
            rcu_read_unlock();
            FW_DEBUG(2, "EXIT: is_in_whitelist -> true (matched subnet)");
            return true;
        }
    }
    rcu_read_unlock();
    FW_DEBUG(3, "EXIT: is_in_whitelist -> false (no match)");
    return false;
}
EXPORT_SYMBOL_GPL(is_in_whitelist);
