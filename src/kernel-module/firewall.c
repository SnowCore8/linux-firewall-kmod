/*
 * firewall.c - Linux kernel module for IP banning
 *
 * This module provides kernel-level IP banning functionality
 * using netfilter hooks.
 */

#include "firewall.h"
#include <linux/namei.h>
#include <linux/version.h>

/* Forward declarations for RCU callbacks */
static void free_ban_entry_rcu(struct rcu_head *head);
static void free_whitelist_entry_rcu(struct rcu_head *head);

/* Forward declaration for flood protection function */
static int check_flood_protection(void);

/* Forward declarations for state file functions */
static int save_state_to_file(const char *filename);
static int restore_state_from_file(const char *filename);

/* Helper function: Convert IPv4 to string */
static inline void ipv4_to_str(__be32 ip, char *buf, int len)
{
    unsigned int a = ntohl(ip) >> 24;
    unsigned int b = (ntohl(ip) >> 16) & 0xFF;
    unsigned int c = (ntohl(ip) >> 8) & 0xFF;
    unsigned int d = ntohl(ip) & 0xFF;

    /* Validate buffer size is sufficient for IP string (at least 16 chars: "xxx.xxx.xxx.xxx\0") */
    if (len < 16) {
        if (len > 0) {
            buf[0] = '\0';  /* Null terminate if buffer exists */
        }
        return;
    }

    snprintf(buf, len, "%u.%u.%u.%u", a, b, c, d);
}

/* Helper function: Convert IPv6 to string */
static inline void ipv6_to_str(const struct in6_addr *ip, char *buf, int len)
{
    snprintf(buf, len, "%pI6", ip);
}

/* Helper function: Compare IP addresses */
static inline bool compare_ips(const union ip_address *ip1, const union ip_address *ip2, enum ip_type type)
{
    if (type == IPV4_ADDR) {
        return ip1->ipv4 == ip2->ipv4;
    } else if (type == IPV6_ADDR) {
        return ipv6_addr_equal(&ip1->ipv6, &ip2->ipv6);
    }
    return false;
}

/* Helper function: Generate hash for IP addresses */
static inline u32 generate_ip_hash(const union ip_address *ip, enum ip_type type)
{
    if (type == IPV4_ADDR) {
        return hash_min(ip->ipv4, BAN_HASH_BITS);
    } else if (type == IPV6_ADDR) {
        return hash_32(ip->ipv6.s6_addr32[0] ^ ip->ipv6.s6_addr32[1] ^
                       ip->ipv6.s6_addr32[2] ^ ip->ipv6.s6_addr32[3], BAN_HASH_BITS);
    }
    return 0;
}

/* Helper function: Generate hash for whitelist IP addresses */
static inline u32 generate_wl_ip_hash(const union ip_address *ip, enum ip_type type)
{
    if (type == IPV4_ADDR) {
        return hash_min(ip->ipv4, WHITELIST_HASH_BITS);
    } else if (type == IPV6_ADDR) {
        return hash_32(ip->ipv6.s6_addr32[0] ^ ip->ipv6.s6_addr32[1] ^
                       ip->ipv6.s6_addr32[2] ^ ip->ipv6.s6_addr32[3], WHITELIST_HASH_BITS);
    }
    return 0;
}

/*
 * add_whitelist_entry_v4 - Add an IPv4 to the whitelist hash table
 * Fixed version: Ensures IP is normalized to network address for proper subnet matching
 * Added validation for IP and mask values
 */
int add_whitelist_entry_v4(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name)
{
    struct whitelist_entry *new_entry;  /* 修复：使用 new_entry 避免被 hash_for_each_possible 覆盖 */
    struct whitelist_entry *tmp_entry;  /* 修复：用于遍历哈希表的临时变量 */
    u32 hash;

    FW_DEBUG(1, "ENTRY: add_whitelist_entry_v4(ip=%pI4, mask=%pI4, dev=%s)", &ip, &mask, dev_name ?: "null");

    /* Validate IP and mask inputs */
    if (!mask) {
        printk(KERN_WARNING "firewall: Invalid mask 0x%08x for IP %pI4\n", mask, &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v4 -> -EINVAL (invalid mask)");
        return -EINVAL;
    }

    /* Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc. */
    if (ip == 0 || ip == 0xFFFFFFFF ||
        (ntohl(ip) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
        (ntohl(ip) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
        (ntohl(ip) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
        (ntohl(ip) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
        printk(KERN_WARNING "firewall: Attempt to whitelist invalid IP: %pI4\n", &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v4 -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    __be32 normalized_ip = ip & mask;  // Normalize IP to network address

    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    FW_DEBUG(2, "Attempting to add whitelist entry for %pI4/%d", &normalized_ip, inet_mask_len(mask));

    /* FIX W2: 在锁外分配内存，避免在 spinlock 内睡眠 */
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        FW_DEBUG(1, "Failed to allocate memory for whitelist entry for IP %pI4", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v4 -> -ENOMEM");
        return -ENOMEM;
    }

    /* 初始化 new_entry 字段 */
    new_entry->ip.ipv4 = normalized_ip;  // Store normalized IP (network address)
    new_entry->mask.ipv4 = mask;
    new_entry->type = IPV4_ADDR;
    if (dev_name)
        strscpy(new_entry->device_name, dev_name, sizeof(new_entry->device_name));
    else
        new_entry->device_name[0] = '\0';

    spin_lock(&fw->whitelist_lock);

    /* 修复：使用 tmp_entry 遍历，避免覆盖 new_entry 指针
     * 原 bug: hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip)
     * 会覆盖 entry 指针，导致后续 kfree(entry) 释放错误内存 */
    hash_for_each_possible(fw->whitelist_table, tmp_entry, hash, normalized_ip) {
        if (compare_ips(&tmp_entry->ip, &(union ip_address){.ipv4 = normalized_ip}, IPV4_ADDR) &&
            compare_ips(&tmp_entry->mask, &(union ip_address){.ipv4 = mask}, IPV4_ADDR) &&
            tmp_entry->type == IPV4_ADDR) {
            spin_unlock(&fw->whitelist_lock);
            kfree(new_entry);  /* 修复：释放我们预先分配的 new_entry */
            FW_DEBUG(2, "EXIT: add_whitelist_entry_v4 -> 0 (already exists)");
            return 0;
        }
    }

    if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
        spin_unlock(&fw->whitelist_lock);
        kfree(new_entry);  /* 修复：释放 new_entry */
        printk(KERN_WARNING "firewall: Whitelist full, cannot add %pI4/%d\n", &normalized_ip, inet_mask_len(mask));
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v4 -> -ENOSPC (whitelist full)");
        return -ENOSPC;
    }

    /* 插入哈希表 */
    hash_add(fw->whitelist_table, &new_entry->hash, normalized_ip);  /* 修复：使用 new_entry */
    atomic_inc(&fw->whitelist_count);
    spin_unlock(&fw->whitelist_lock);

    FW_DEBUG(1, "Successfully added whitelist entry for %pI4/%d on %s",
             &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    printk(KERN_INFO "firewall: Whitelisted %pI4/%d on %s\n",
           &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    FW_DEBUG(1, "EXIT: add_whitelist_entry_v4 -> 0 (success)");
    return 0;
}

/*
 * add_whitelist_entry_v6 - Add an IPv6 to the whitelist hash table
 */
int add_whitelist_entry_v6(struct firewall_info *fw, const struct in6_addr *ip, const struct in6_addr *mask, const char *dev_name)
{
    struct whitelist_entry *new_entry;  /* 修复：使用 new_entry 避免被 hash_for_each_possible 覆盖 */
    struct whitelist_entry *tmp_entry;  /* 修复：用于遍历哈希表的临时变量 */
    u32 hash;

    FW_DEBUG(1, "ENTRY: add_whitelist_entry_v6(ip=%pI6, dev=%s)", ip, dev_name ?: "null");

    /* Additional validation: reject invalid IPs like ::, ::1, multicast, etc. */
    if (ipv6_addr_any(ip) || ipv6_addr_loopback(ip) || ipv6_addr_is_multicast(ip)) {
        printk(KERN_WARNING "firewall: Attempt to whitelist invalid IPv6: %pI6\n", ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v6 -> -EINVAL (invalid IPv6)");
        return -EINVAL;
    }

    struct in6_addr normalized_ip;
    for (int i = 0; i < 4; i++) {
        normalized_ip.s6_addr32[i] = ip->s6_addr32[i] & mask->s6_addr32[i];  // Normalize IP to network address
    }

    hash = generate_wl_ip_hash(&(union ip_address){.ipv6 = normalized_ip}, IPV6_ADDR);
    FW_DEBUG(2, "Attempting to add whitelist entry for IPv6 %pI6", &normalized_ip);

    /* FIX W2: 在锁外分配内存，避免在 spinlock 内睡眠 */
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        printk(KERN_WARNING "firewall: Failed to allocate memory for whitelist entry for IPv6 %pI6\n", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v6 -> -ENOMEM (alloc failed)");
        return -ENOMEM;
    }

    /* 初始化 new_entry 字段 */
    new_entry->ip.ipv6 = normalized_ip;  // Store normalized IP (network address)
    new_entry->mask.ipv6 = *mask;
    new_entry->type = IPV6_ADDR;
    if (dev_name)
        strscpy(new_entry->device_name, dev_name, sizeof(new_entry->device_name));
    else
        new_entry->device_name[0] = '\0';

    spin_lock(&fw->whitelist_lock);

    /* 修复：使用 tmp_entry 遍历，避免覆盖 new_entry 指针
     * 原 bug: hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip.s6_addr32[0])
     * 会覆盖 entry 指针，导致后续 kfree(entry) 释放错误内存 */
    hash_for_each_possible(fw->whitelist_table, tmp_entry, hash, normalized_ip.s6_addr32[0]) {
        if (compare_ips(&tmp_entry->ip, &(union ip_address){.ipv6 = normalized_ip}, IPV6_ADDR) &&
            compare_ips(&tmp_entry->mask, &(union ip_address){.ipv6 = *mask}, IPV6_ADDR) &&
            tmp_entry->type == IPV6_ADDR) {
            spin_unlock(&fw->whitelist_lock);
            kfree(new_entry);  /* 修复：释放我们预先分配的 new_entry */
            FW_DEBUG(2, "EXIT: add_whitelist_entry_v6 -> 0 (already exists)");
            return 0;
        }
    }

    if (atomic_read(&fw->whitelist_count) >= MAX_WHITELIST_ENTRIES) {
        spin_unlock(&fw->whitelist_lock);
        kfree(new_entry);  /* 修复：释放 new_entry */
        printk(KERN_WARNING "firewall: Whitelist full, cannot add IPv6 %pI6\n", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry_v6 -> -ENOSPC (whitelist full)");
        return -ENOSPC;
    }

    /* 插入哈希表 */
    hash_add(fw->whitelist_table, &new_entry->hash, normalized_ip.s6_addr32[0]);  /* 修复：使用 new_entry */
    atomic_inc(&fw->whitelist_count);
    spin_unlock(&fw->whitelist_lock);

    printk(KERN_INFO "firewall: Whitelisted IPv6 %pI6 on %s\n", &normalized_ip, dev_name ?: "unknown");
    FW_DEBUG(1, "EXIT: add_whitelist_entry_v6 -> 0 (success)");
    return 0;
}

/*
 * remove_whitelist_entry_v4 - Remove an IPv4 from the whitelist hash table
 * Fixed version: Normalizes IP to network address for consistent removal
 */
int remove_whitelist_entry_v4(struct firewall_info *fw, __be32 ip_input)
{
    struct whitelist_entry *entry;
    u32 hash;
    int found = 0;
    __be32 normalized_ip = ip_input;  // For backward compatibility, assume input is already normalized
                               // OR if removing by network address, use as-is

    FW_DEBUG(1, "ENTRY: remove_whitelist_entry_v4(ip=%pI4)", &normalized_ip);

    /* Look for entries by the exact stored IP (which is normalized network address) */
    spin_lock(&fw->whitelist_lock);
    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv4 = normalized_ip}, IPV4_ADDR) &&
            entry->type == IPV4_ADDR) {  // Compare with the stored normalized IP
            hash_del(&entry->hash);
            atomic_dec(&fw->whitelist_count);
            found = 1;
            /* Use call_rcu for async freeing */
            call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
            FW_DEBUG(2, "Found and removed whitelist entry for %pI4", &normalized_ip);
            break;
        }
    }
    spin_unlock(&fw->whitelist_lock);

    if (found) {
        printk(KERN_INFO "firewall: Removed %pI4 from whitelist\n", &normalized_ip);
        FW_DEBUG(1, "EXIT: remove_whitelist_entry_v4 -> 0 (success)");
        return 0;
    }

    printk(KERN_WARNING "firewall: %pI4 not found in whitelist\n", &normalized_ip);
    FW_DEBUG(1, "EXIT: remove_whitelist_entry_v4 -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * remove_whitelist_entry_v6 - Remove an IPv6 from the whitelist hash table
 */
int remove_whitelist_entry_v6(struct firewall_info *fw, const struct in6_addr *ip_input)
{
    struct whitelist_entry *entry;
    u32 hash;
    int found = 0;

    FW_DEBUG(1, "ENTRY: remove_whitelist_entry_v6(ip=%pI6)", ip_input);

    /* Look for entries by the exact stored IP */
    spin_lock(&fw->whitelist_lock);
    hash = generate_wl_ip_hash(&(union ip_address){.ipv6 = *ip_input}, IPV6_ADDR);
    hash_for_each_possible(fw->whitelist_table, entry, hash, ip_input->s6_addr32[0]) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv6 = *ip_input}, IPV6_ADDR) &&
            entry->type == IPV6_ADDR) {  // Compare with the stored normalized IP
            hash_del(&entry->hash);
            atomic_dec(&fw->whitelist_count);
            found = 1;
            /* Use call_rcu for async freeing */
            call_rcu(&entry->rcu_head, free_whitelist_entry_rcu);
            FW_DEBUG(2, "Found and removed whitelist entry for IPv6 %pI6", ip_input);
            break;
        }
    }
    spin_unlock(&fw->whitelist_lock);

    if (found) {
        printk(KERN_INFO "firewall: Removed %pI6 from whitelist\n", ip_input);
        FW_DEBUG(1, "EXIT: remove_whitelist_entry_v6 -> 0 (success)");
        return 0;
    }

    printk(KERN_WARNING "firewall: %pI6 not found in whitelist\n", ip_input);
    FW_DEBUG(1, "EXIT: remove_whitelist_entry_v6 -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * is_in_whitelist_v4 - Check if an IPv4 is in the whitelist hash table
 * Fixed version: Properly handles subnet matching by checking all entries in the hash table
 * Since different IPs with different masks could fall in the same hash bucket, we need to
 * check all entries to ensure proper subnet matching.
 */
bool is_in_whitelist_v4(struct firewall_info *fw, __be32 ip)
{
    struct whitelist_entry *entry;
    u32 hash;

    FW_DEBUG(3, "ENTRY: is_in_whitelist_v4(ip=%pI4)", &ip);

    rcu_read_lock();
    /* Check ALL entries in the whitelist table to properly handle subnet matching */
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        // Subnet matching logic: check if IP falls within subnet range
        // For example, if whitelist has 192.168.1.0/24 (mask 255.255.255.0),
        // then 192.168.1.100 & 255.255.255.0 == 192.168.1.0 & 255.255.255.0
        // This ensures the IP is within the whitelisted subnet range
        if (entry->type == IPV4_ADDR && ((ip & entry->mask.ipv4) == (entry->ip.ipv4 & entry->mask.ipv4))) {
            rcu_read_unlock();
            FW_DEBUG(2, "EXIT: is_in_whitelist_v4 -> true (matched subnet)");
            return true;
        }
    }
    rcu_read_unlock();
    FW_DEBUG(3, "EXIT: is_in_whitelist_v4 -> false (no match)");
    return false;
}

/*
 * is_in_whitelist_v6 - Check if an IPv6 is in the whitelist hash table
 */
bool is_in_whitelist_v6(struct firewall_info *fw, const struct in6_addr *ip)
{
    struct whitelist_entry *entry;
    u32 hash;

    FW_DEBUG(3, "ENTRY: is_in_whitelist_v6(ip=%pI6)", ip);

    rcu_read_lock();
    /* Check ALL entries in the whitelist table to properly handle subnet matching */
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        if (entry->type == IPV6_ADDR) {
            // Subnet matching logic for IPv6
            struct in6_addr masked_ip, masked_entry;
            for (int i = 0; i < 4; i++) {
                masked_ip.s6_addr32[i] = ip->s6_addr32[i] & entry->mask.ipv6.s6_addr32[i];
                masked_entry.s6_addr32[i] = entry->ip.ipv6.s6_addr32[i] & entry->mask.ipv6.s6_addr32[i];
            }

            if (ipv6_addr_equal(&masked_ip, &masked_entry)) {
                rcu_read_unlock();
                FW_DEBUG(2, "EXIT: is_in_whitelist_v6 -> true (matched subnet)");
                return true;
            }
        }
    }
    rcu_read_unlock();
    FW_DEBUG(3, "EXIT: is_in_whitelist_v6 -> false (no match)");
    return false;
}

/* Module parameters (non-static, accessible from procfs) */
unsigned int fw_ban_time = DEFAULT_BAN_TIME;
unsigned int fw_max_retries = DEFAULT_MAX_RETRIES;
unsigned int fw_findtime = DEFAULT_FINDTIME;
char *state_file = "/var/lib/firewall/state";

module_param(fw_ban_time, uint, 0644);
MODULE_PARM_DESC(fw_ban_time, "Ban duration in seconds (default 600)");
module_param(fw_max_retries, uint, 0644);
MODULE_PARM_DESC(fw_max_retries, "Max retries before ban (default 3)");
module_param(fw_findtime, uint, 0644);
MODULE_PARM_DESC(fw_findtime, "Find time window in seconds (default 600)");
module_param(state_file, charp, 0644);
MODULE_PARM_DESC(state_file, "Path to state file for saving/restoring ban and whitelist entries (default /var/lib/firewall/state)");

/* Global firewall info */
struct firewall_info fw_info;

/*
 * ban_ip_v4 - Add an IPv4 to the ban list
 * Optimized version: Uses rwlock for better concurrency
 */
int ban_ip_v4(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int ret = 0;
    u32 hash;

    FW_DEBUG(1, "ENTRY: ban_ip_v4(ip=%pI4)", &ip);

    /* Validate IP input */
    if (!ip) {
        printk(KERN_ERR "firewall: Invalid IP address for banning: %pI4\n", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_v4 -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Attempting to ban IPv4: %pI4", &ip);

    /* Check whitelist first with read lock */
    if (is_in_whitelist_v4(fw, ip)) {
        printk(KERN_WARNING "firewall: REFUSED to ban whitelisted IP %pI4\n", &ip);
        FW_DEBUG(2, "IP %pI4 is in whitelist, refusing to ban", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_v4 -> -EPERM (whitelisted)");
        return -EPERM;
    }

    /* Check if already banned with read lock */
    if (is_banned_v4(fw, ip)) {
        FW_DEBUG(2, "IP %pI4 is already banned");
        FW_DEBUG(1, "EXIT: ban_ip_v4 -> 0 (already banned)");
        return 0;
    }

    spin_lock(&fw->lock);

    /* Double-check after acquiring lock */
    hash = hash_min(ip, BAN_HASH_BITS);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv4 = ip}, IPV4_ADDR) &&
            entry->type == IPV4_ADDR) {
            if (time_before(jiffies, entry->unban_time)) {
                // Still banned - return early
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "IP %pI4 still banned, returning early");
                FW_DEBUG(1, "EXIT: ban_ip_v4 -> 0 (still banned under lock)");
                return 0;
            } else {
                // Entry exists but expired - update it
                entry->ban_time = jiffies;
                /* FIX P1-5: Use READ_ONCE for atomic access to fw_ban_time */
                entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
                atomic_set(&entry->retry_count, 0);
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "Updated expired ban entry for IP %pI4");
                FW_DEBUG(1, "EXIT: ban_ip_v4 -> 0 (updated expired entry)");
                return 0;
            }
        }
    }

    if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
        spin_unlock(&fw->lock);
        printk(KERN_WARNING "firewall: Ban table full, cannot ban %pI4\n", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_v4 -> -ENOSPC (ban table full)");
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);  /* Use GFP_ATOMIC to avoid sleeping in interrupt context */
    if (!entry) {
        spin_unlock(&fw->lock);
        printk(KERN_ERR "firewall: Failed to allocate memory for ban entry for IP %pI4\n", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_v4 -> -ENOMEM (alloc failed)");
        return -ENOMEM;
    }

    entry->ip.ipv4 = ip;
    entry->type = IPV4_ADDR;
    entry->ban_time = jiffies;
    /* FIX P1-5: Use READ_ONCE to atomically read fw_ban_time to prevent
     * torn reads when the value is being concurrently updated via procfs. */
    entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
    atomic_set(&entry->retry_count, 0);
    entry->being_freed = false;  /* 初始化防止双重释放标记 */

    hash_add(fw->ban_table, &entry->hash, ip);
    atomic_inc(&fw->ban_count);

    spin_unlock(&fw->lock);

    FW_DEBUG(1, "Successfully added ban entry for IP %pI4", &ip);
    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding when
     * many IPs are being banned in a short time period. */
    net_info_ratelimited("firewall: IP %pI4 banned for %u seconds\n", &ip, READ_ONCE(fw_ban_time));
    FW_DEBUG(1, "EXIT: ban_ip_v4 -> 0 (success)");
    return ret;
}

/*
 * ban_ip_v6 - Add an IPv6 to the ban list
 * Optimized version: Uses proper memory allocation in critical sections
 */
int ban_ip_v6(struct firewall_info *fw, const struct in6_addr *ip)
{
    struct ban_entry *entry;
    int ret = 0;
    u32 hash;

    FW_DEBUG(1, "ENTRY: ban_ip_v6(ip=%pI6)", ip);

    /* Validate IP input */
    if (!ip) {
        printk(KERN_ERR "firewall: Invalid IPv6 address for banning\n");
        FW_DEBUG(1, "EXIT: ban_ip_v6 -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    /* Check whitelist first */
    if (is_in_whitelist_v6(fw, ip)) {
        printk(KERN_WARNING "firewall: REFUSED to ban whitelisted IPv6 %pI6\n", ip);
        FW_DEBUG(1, "EXIT: ban_ip_v6 -> -EPERM (whitelisted)");
        return -EPERM;
    }

    /* Check if already banned */
    if (is_banned_v6(fw, ip)) {
        FW_DEBUG(1, "EXIT: ban_ip_v6 -> 0 (already banned)");
        return 0;
    }

    spin_lock(&fw->lock);

    /* Double-check after acquiring lock */
    hash = generate_ip_hash(&(union ip_address){.ipv6 = *ip}, IPV6_ADDR);
    hash_for_each_possible(fw->ban_table, entry, hash, ip->s6_addr32[0]) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv6 = *ip}, IPV6_ADDR) &&
            entry->type == IPV6_ADDR) {
            if (time_before(jiffies, entry->unban_time)) {
                // Still banned - return early
                spin_unlock(&fw->lock);
                FW_DEBUG(1, "EXIT: ban_ip_v6 -> 0 (still banned under lock)");
                return 0;
            } else {
                // Entry exists but expired - update it
                entry->ban_time = jiffies;
                /* FIX P1-5: Use READ_ONCE for atomic access to fw_ban_time */
                entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
                atomic_set(&entry->retry_count, 0);
                spin_unlock(&fw->lock);
                FW_DEBUG(1, "EXIT: ban_ip_v6 -> 0 (updated expired entry)");
                return 0;
            }
        }
    }

    if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
        spin_unlock(&fw->lock);
        printk(KERN_WARNING "firewall: Ban table full, cannot ban IPv6 %pI6\n", ip);
        FW_DEBUG(1, "EXIT: ban_ip_v6 -> -ENOSPC (ban table full)");
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);  /* Use GFP_ATOMIC to avoid sleeping in interrupt context */
    if (!entry) {
        spin_unlock(&fw->lock);
        printk(KERN_ERR "firewall: Failed to allocate memory for ban entry for IPv6 %pI6\n", ip);
        FW_DEBUG(1, "EXIT: ban_ip_v6 -> -ENOMEM (alloc failed)");
        return -ENOMEM;
    }

    entry->ip.ipv6 = *ip;
    entry->type = IPV6_ADDR;
    entry->ban_time = jiffies;
    /* FIX P1-5: Use READ_ONCE to atomically read fw_ban_time to prevent
     * torn reads when the value is being concurrently updated via procfs. */
    entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
    atomic_set(&entry->retry_count, 0);
    entry->being_freed = false;  /* 初始化防止双重释放标记 */

    hash_add(fw->ban_table, &entry->hash, ip->s6_addr32[0]);
    atomic_inc(&fw->ban_count);

    spin_unlock(&fw->lock);

    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
    net_info_ratelimited("firewall: IPv6 %pI6 banned for %u seconds\n", ip, READ_ONCE(fw_ban_time));
    FW_DEBUG(1, "EXIT: ban_ip_v6 -> 0 (success)");
    return ret;
}

/*
 * unban_ip_v4 - Remove an IPv4 from the ban list
 * Optimized version: Uses proper locking and memory management
 */
int unban_ip_v4(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int found = 0;
    char ip_str[INET_ADDRSTRLEN];

    FW_DEBUG(1, "ENTRY: unban_ip_v4(ip=%pI4)", &ip);

    ipv4_to_str(ip, ip_str, sizeof(ip_str));

    spin_lock(&fw->lock);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv4 = ip}, IPV4_ADDR) &&
            entry->type == IPV4_ADDR) {
            /* 修复: 设置 being_freed 标记，防止并发 cleanup 导致的双重释放 */
            entry->being_freed = true;
            hash_del(&entry->hash);
            atomic_dec(&fw->ban_count);
            found = 1;
            call_rcu(&entry->rcu_head, free_ban_entry_rcu);
            FW_DEBUG(2, "Found and removed ban entry for IP %s", ip_str);
            break;
        }
    }
    spin_unlock(&fw->lock);

    if (found) {
        /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
        net_info_ratelimited("firewall: IP %s unbanned\n", ip_str);
        FW_DEBUG(1, "EXIT: unban_ip_v4 -> 0 (success)");
        return 0;
    }
    printk(KERN_DEBUG "firewall: IP %s not found in ban list\n", ip_str);
    FW_DEBUG(1, "EXIT: unban_ip_v4 -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * unban_ip_v6 - Remove an IPv6 from the ban list
 */
int unban_ip_v6(struct firewall_info *fw, const struct in6_addr *ip)
{
    struct ban_entry *entry;
    int found = 0;
    char ip_str[INET6_ADDRSTRLEN];

    FW_DEBUG(1, "ENTRY: unban_ip_v6(ip=%pI6)", ip);

    ipv6_to_str(ip, ip_str, sizeof(ip_str));

    spin_lock(&fw->lock);
    hash_for_each_possible(fw->ban_table, entry, hash, ip->s6_addr32[0]) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv6 = *ip}, IPV6_ADDR) &&
            entry->type == IPV6_ADDR) {
            /* 修复: 设置 being_freed 标记，防止并发 cleanup 导致的双重释放 */
            entry->being_freed = true;
            hash_del(&entry->hash);
            atomic_dec(&fw->ban_count);
            found = 1;
            call_rcu(&entry->rcu_head, free_ban_entry_rcu);
            FW_DEBUG(2, "Found and removed ban entry for IPv6 %s", ip_str);
            break;
        }
    }
    spin_unlock(&fw->lock);

    if (found) {
        /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
        net_info_ratelimited("firewall: IPv6 %s unbanned\n", ip_str);
        FW_DEBUG(1, "EXIT: unban_ip_v6 -> 0 (success)");
        return 0;
    }
    printk(KERN_DEBUG "firewall: IPv6 %s not found in ban list\n", ip_str);
    FW_DEBUG(1, "EXIT: unban_ip_v6 -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * is_banned_v4 - Check if an IPv4 is banned
 * Returns: 1 if banned (valid), 0 if not banned or expired
 */
int is_banned_v4(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    unsigned long now = jiffies;
    int found = 0;

    FW_DEBUG(3, "Checking if IPv4 %pI4 is banned", &ip);

    rcu_read_lock();
    hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv4 = ip}, IPV4_ADDR) &&
            entry->type == IPV4_ADDR) {
            if (time_after(now, entry->unban_time)) {
                /* Entry exists but expired - remove it */
                /* We can't remove here under RCU read lock, so just return 0 */
                FW_DEBUG(2, "Found expired ban entry for IPv4 %pI4", &ip);
                found = 0;
            } else {
                /* Valid banned entry */
                FW_DEBUG(2, "Found active ban entry for IPv4 %pI4", &ip);
                found = 1;
            }
            break;
        }
    }
    rcu_read_unlock();

    FW_DEBUG(3, "Result for IPv4 %pI4 ban check: %s", &ip, found ? "BANNED" : "NOT BANNED");
    return found;
}

/*
 * is_banned_v6 - Check if an IPv6 is banned
 * Returns: 1 if banned (valid), 0 if not banned or expired
 */
int is_banned_v6(struct firewall_info *fw, const struct in6_addr *ip)
{
    struct ban_entry *entry;
    unsigned long now = jiffies;
    int found = 0;

    FW_DEBUG(3, "ENTRY: is_banned_v6(ip=%pI6)", ip);

    rcu_read_lock();
    hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip->s6_addr32[0]) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv6 = *ip}, IPV6_ADDR) &&
            entry->type == IPV6_ADDR) {
            if (time_after(now, entry->unban_time)) {
                /* Entry exists but expired - remove it */
                /* We can't remove here under RCU read lock, so just return 0 */
                FW_DEBUG(2, "Found expired ban entry for IPv6 %pI6", ip);
                found = 0;
            } else {
                /* Valid banned entry */
                FW_DEBUG(2, "Found active ban entry for IPv6 %pI6", ip);
                found = 1;
            }
            break;
        }
    }
    rcu_read_unlock();

    FW_DEBUG(3, "Result for IPv6 %pI6 ban check: %s", ip, found ? "BANNED" : "NOT BANNED");
    return found;
}

/*
 * cleanup_expired_bans - Remove expired ban entries
 * Optimized version: Early exit when no entries to clean
 * Note: Collect entries to free, then call_rcu for async freeing (not in lock).
 */
static void free_ban_entry_rcu(struct rcu_head *head)
{
    struct ban_entry *entry = container_of(head, struct ban_entry, rcu_head);
    FW_DEBUG(3, "Freeing ban entry via RCU callback");
    kfree(entry);
}

static void free_whitelist_entry_rcu(struct rcu_head *head)
{
    struct whitelist_entry *entry = container_of(head, struct whitelist_entry, rcu_head);
    FW_DEBUG(3, "Freeing whitelist entry via RCU callback");
    kfree(entry);
}

void cleanup_expired_bans(struct firewall_info *fw)
{
    struct ban_entry *entry;
    struct hlist_node *tmp;
    unsigned long now = jiffies;
    int removed = 0;
    int processed = 0;
    int max_processed_per_call = 50;  /* Limit processing per call to prevent long lock holds */
    int start_bucket = fw->cleanup_last_bucket;  /* Start from where we left off last time */

    FW_DEBUG(2, "ENTRY: cleanup_expired_bans(current_count=%d, start_bucket=%d)", atomic_read(&fw->ban_count), start_bucket);

    /* Early exit if no entries to clean */
    if (atomic_read(&fw->ban_count) == 0) {
        fw->cleanup_last_bucket = 0;  /* Reset for next cycle */
        FW_DEBUG(3, "No entries to clean, exiting early");
        FW_DEBUG(2, "EXIT: cleanup_expired_bans -> void (no entries)");
        return;
    }

    spin_lock(&fw->lock);

    /* Early exit if no entries to clean after lock acquired */
    if (atomic_read(&fw->ban_count) == 0) {
        spin_unlock(&fw->lock);
        fw->cleanup_last_bucket = 0;  /* Reset for next cycle */
        FW_DEBUG(3, "No entries to clean after lock acquired, exiting early");
        FW_DEBUG(2, "EXIT: cleanup_expired_bans -> void (no entries after lock)");
        return;
    }

    /* Process only a subset of buckets each call to distribute load */
    unsigned int ban_table_size = 1 << BAN_HASH_BITS;

    for (int i = 0; i < (1 << 3) && processed < max_processed_per_call; i++) {  /* Process up to 8 buckets per call */
        int current_bucket = (start_bucket + i) % ban_table_size;

        /* hlist_for_each_entry_safe 保证即使当前 entry 被删除，tmp 仍指向下一个有效节点
         * 因此在循环内调用 hlist_del_rcu 删除 entry 是安全的，不会破坏遍历 */
        hlist_for_each_entry_safe(entry, tmp, &fw->ban_table[current_bucket], hash) {
            if (processed >= max_processed_per_call) {
                break;
            }

            /* 修复: 检查是否已被标记为释放中，防止双重释放
             * 理论上可能存在同一条目被多次处理的风险，
             * 通过 being_freed 标记确保每个条目只被释放一次。
             */
            if (entry->being_freed) {
                processed++;
                continue;
            }

            if (time_after(now, entry->unban_time)) {
                /* 修复: 标记为正在释放，防止并发场景下的双重释放 */
                entry->being_freed = true;

                /* FIX P1-4: Use hlist_del_rcu instead of hlist_del to safely
                 * remove entry while RCU readers may still be accessing it.
                 * hlist_del is not safe when concurrent RCU traversal is possible
                 * in the netfilter hook functions. */
                hlist_del_rcu(&entry->hash);
                atomic_dec(&fw->ban_count);
                removed++;
                /* Use call_rcu for async freeing (not in lock) */
                call_rcu(&entry->rcu_head, free_ban_entry_rcu);
                FW_DEBUG(2, "Removed expired ban entry");
            }
            processed++;
        }
    }

    /* Update the starting bucket for the next call */
    fw->cleanup_last_bucket = (start_bucket + (1 << 3)) % ban_table_size;  /* Advance by 8 buckets */

    spin_unlock(&fw->lock);

    if (removed > 0) {
        FW_DEBUG(1, "Cleaned up %d expired ban entries", removed);
        /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding during mass cleanup */
        net_info_ratelimited("firewall: Cleaned up %d expired ban entries\n", removed);
    } else {
        FW_DEBUG(3, "No expired entries found during cleanup");
    }

    /* If we cleaned up entries, reschedule cleanup sooner to continue cleaning */
    if (removed > 0 && atomic_read(&fw->ban_count) > 0) {
        /* FIX: Check shutting_down before re-arming timer to prevent race during shutdown */
        if (unlikely(atomic_read(&fw->shutting_down))) {
            FW_DEBUG(2, "EXIT: cleanup_expired_bans -> void (shutting down, skip timer)");
            return;
        }
        mod_timer(&fw->cleanup_timer, jiffies + HZ/10);  /* Retry in 100ms if there might be more to clean */
        FW_DEBUG(2, "Rescheduled cleanup for 100ms due to remaining entries");
    } else {
        FW_DEBUG(3, "No more entries to clean, using standard timer interval");
    }

    FW_DEBUG(2, "EXIT: cleanup_expired_bans -> void (removed=%d, processed=%d)", removed, processed);
}

/*
 * auto_discover_system_ips - Collect IPv4 and IPv6 IPs in RCU, then whitelist outside (FIX: RCU+GFP_KERNEL)
 */
/* Temporary storage structures for auto-discovery (moved to heap to reduce stack usage) */
struct temp_ip_entry {
    __be32 ip;
    __be32 mask;
    char name[16];
    enum ip_type type;
};

struct temp_ipv6_entry {
    struct in6_addr ip;
    struct in6_addr mask;
    char name[16];
};

void auto_discover_system_ips(struct firewall_info *fw)
{
    /* Allocate on heap to avoid large stack frames */
    struct temp_ip_entry *temp_ips;
    int temp_count = 0;
    struct temp_ipv6_entry *temp_ips6;
    int temp_count6 = 0;

    struct net_device *dev;
    struct in_device *in_dev;
    struct in_ifaddr *ifa;
    struct inet6_dev *in6_dev;
    struct inet6_ifaddr *ifa6;

    FW_DEBUG(1, "ENTRY: auto_discover_system_ips");

    /* Allocate temporary arrays on heap */
    temp_ips = kmalloc_array(64, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!temp_ips) {
        printk(KERN_ERR "firewall: Failed to allocate temp_ips\n");
        FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (alloc temp_ips failed)");
        return;
    }

    temp_ips6 = kmalloc_array(64, sizeof(struct temp_ipv6_entry), GFP_KERNEL);
    if (!temp_ips6) {
        printk(KERN_ERR "firewall: Failed to allocate temp_ips6\n");
        kfree(temp_ips);
        FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (alloc temp_ips6 failed)");
        return;
    }

    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
    net_info_ratelimited("firewall: Auto-discovering system IPs...\n");

    /* FIX C2: 阶段 1 - RCU 保护下收集 IPv4 地址
     * 修复说明: __in_dev_get_rcu(dev) 内部已经使用 rcu_dereference 保护，
     * 但为代码清晰和防御性编程，显式使用 rcu_dereference 保护 ifa_list 遍历。
     * RCU 读锁 (rcu_read_lock/unlock) 保证在遍历期间网络设备列表不会被修改。
     */
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        if (dev->flags & IFF_LOOPBACK) {
            if (temp_count < 64) {
                temp_ips[temp_count].ip = htonl(0x7f000001);
                temp_ips[temp_count].mask = htonl(0xff000000);
                strscpy(temp_ips[temp_count].name, dev->name, 16);
                temp_ips[temp_count].type = IPV4_ADDR;
                temp_count++;
            }
        }

        if (!(dev->flags & IFF_UP))
            continue;

        // Collect IPv4 addresses
        in_dev = __in_dev_get_rcu(dev);
        if (in_dev) {
            /* 修复: 使用 rcu_dereference 显式保护 ifa_list 遍历
             * __in_dev_get_rcu 返回的 in_dev 指针由 RCU 保护，
             * in_dev->ifa_list 的遍历也需要 RCU dereference 保护以防止并发修改。
             */
            for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
                 ifa = rcu_dereference(ifa->ifa_next)) {
                if (temp_count >= 64)
                    break;

                /* 验证 IP 地址的有效性 */
                if (!ifa->ifa_local) {
                    continue;  /* Skip invalid IP addresses */
                }

                temp_ips[temp_count].ip = ifa->ifa_local;  /* 使用 ifa_local 而不是 ifa_address */
                temp_ips[temp_count].mask = ifa->ifa_mask;
                strscpy(temp_ips[temp_count].name, dev->name, 16);
                temp_ips[temp_count].type = IPV4_ADDR;
                temp_count++;
            }
        }
    }
    rcu_read_unlock();

    /* FIX C2: 阶段 2 - 单独遍历 IPv6，使用 rtnl_lock 保护网络设备遍历 */
    rtnl_lock();
    for_each_netdev(&init_net, dev) {
        if (!(dev->flags & IFF_UP))
            continue;

        in6_dev = __in6_dev_get(dev);
        if (in6_dev) {
            struct list_head *p;
            read_lock_bh(&in6_dev->lock);
            list_for_each(p, &in6_dev->addr_list) {
                if (temp_count6 >= 64)
                    break;

                ifa6 = list_entry(p, struct inet6_ifaddr, if_list);

                if (ifa6->flags & (IFA_F_TENTATIVE | IFA_F_DEPRECATED))
                    continue;  // Skip tentative or deprecated addresses

                // Only add global addresses, not link-local
                if (ifa6->scope == RT_SCOPE_UNIVERSE) {
                    // Store in temporary array, add outside RCU lock
                    temp_ips6[temp_count6].ip = ifa6->addr;

                    // Construct mask from prefix_len
                    memset(&temp_ips6[temp_count6].mask, 0, sizeof(struct in6_addr));
                    int prefix_len = ifa6->prefix_len;
                    int bytes = prefix_len / 8;
                    int bits = prefix_len % 8;
                    for (int i = 0; i < bytes; i++) {
                        temp_ips6[temp_count6].mask.s6_addr[i] = 0xFF;
                    }
                    if (bits > 0) {
                        temp_ips6[temp_count6].mask.s6_addr[bytes] = 0xFF << (8 - bits);
                    }
                    strscpy(temp_ips6[temp_count6].name, dev->name, 16);
                    temp_count6++;
                }
            }
            read_unlock_bh(&in6_dev->lock);
        }
    }
    rtnl_unlock();

    /* Add IPv4 IPs outside RCU lock (safe for GFP_KERNEL) */
    for (int i = 0; i < temp_count; i++) {
        if (temp_ips[i].type == IPV4_ADDR) {
            if (add_whitelist_entry_v4(fw, temp_ips[i].ip, temp_ips[i].mask, temp_ips[i].name) < 0) {
                printk(KERN_WARNING "firewall: Failed to add system IPv4 %pI4 to whitelist\n",
                       &temp_ips[i].ip);
            }
        }
    }

    /* Add IPv6 IPs outside RCU lock (safe for GFP_KERNEL) */
    for (int i = 0; i < temp_count6; i++) {
        if (add_whitelist_entry_v6(fw, &temp_ips6[i].ip, &temp_ips6[i].mask, temp_ips6[i].name) < 0) {
            printk(KERN_WARNING "firewall: Failed to add system IPv6 to whitelist\n");
        }
    }

    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
    net_info_ratelimited("firewall: Auto-discovery complete. %d entries\n",
           atomic_read(&fw->whitelist_count));

    /* Free temporary arrays */
    kfree(temp_ips);
    kfree(temp_ips6);

    FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (success, wl_count=%d)", atomic_read(&fw->whitelist_count));
}

/*
 * cleanup_timer_callback - Timer callback for periodic cleanup
 * Optimized version: Reduced frequency and improved efficiency
 */
static void cleanup_timer_callback(struct timer_list *t)
{
    struct firewall_info *fw = container_of(t, struct firewall_info, cleanup_timer);

    FW_DEBUG(3, "ENTRY: cleanup_timer_callback");

    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: cleanup_timer_callback -> void (shutting down)");
        return;
    }

    cleanup_expired_bans(fw);

    /* Re-check shutting_down before re-arming timer to prevent race during shutdown */
    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: cleanup_timer_callback -> void (shutting down after cleanup)");
        return;
    }

    /* Adjust cleanup interval: use minimum of ban_time/4 or 30 seconds to balance performance and memory usage */
    /* FIX P1-5: Use READ_ONCE for atomic access to fw_ban_time */
    unsigned long cleanup_interval = max(HZ * 30UL, ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 4);
    FW_DEBUG(3, "Re-arming cleanup timer with interval=%lu jiffies", cleanup_interval);
    mod_timer(&fw->cleanup_timer, jiffies + cleanup_interval);

    FW_DEBUG(3, "EXIT: cleanup_timer_callback -> void (timer re-armed)");
}

/*
 * ban_list_show - Show current ban list (supports IPv4 and IPv6)
 */
static int ban_list_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct ban_entry *entry;
    u32 hash;
    unsigned long now = jiffies;
    char ip_str[INET6_ADDRSTRLEN];
    int count = 0;

    FW_DEBUG(3, "ENTRY: ban_list_show");

    seq_printf(m, "Current banned IPs:\n");
    seq_printf(m, "-------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->ban_table, hash, entry, hash) {
        if (!time_after(now, entry->unban_time)) {
            if (entry->type == IPV4_ADDR) {
                ipv4_to_str(entry->ip.ipv4, ip_str, sizeof(ip_str));
            } else if (entry->type == IPV6_ADDR) {
                ipv6_to_str(&entry->ip.ipv6, ip_str, sizeof(ip_str));
            } else {
                /* FIX Extra-7: Use strscpy instead of strcpy to prevent
                 * potential buffer overflow and ensure null termination. */
                strscpy(ip_str, "Invalid", sizeof(ip_str));  // Should not happen
            }
            seq_printf(m, "%-40s (expires in %lus)\n",
                       ip_str,
                       (entry->unban_time - now) / HZ);
            count++;
        }
    }
    rcu_read_unlock();

    seq_printf(m, "-------------------\n");
    seq_printf(m, "Total: %d active bans\n", atomic_read(&fw->ban_count));
    FW_DEBUG(3, "EXIT: ban_list_show -> 0 (shown=%d)", count);
    return 0;
}

static int ban_list_open(struct inode *inode, struct file *file)
{
    return single_open(file, ban_list_show, NULL);
}

static const struct proc_ops ban_list_fops = {
    .proc_open = ban_list_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * add_ban_write - Procfs write handler for banning IPs (supports IPv4 and IPv6)
 */
static ssize_t add_ban_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    char ip_str[INET6_ADDRSTRLEN + 2];
    __be32 ipv4;
    struct in6_addr ipv6;
    ssize_t len;

    FW_DEBUG(2, "ENTRY: add_ban_write(count=%zu)", count);

    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: add_ban_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: add_ban_write -> 0 (empty input)");
        return 0;
    }
    /* Limit input to prevent buffer overflow */
    if (count > sizeof(ip_str) - 1) {
        FW_DEBUG(1, "EXIT: add_ban_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(ip_str) - 1));

    if (copy_from_user(ip_str, buf, len)) {
        FW_DEBUG(1, "EXIT: add_ban_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    /* Ensure null termination */
    ip_str[len] = '\0';
    if (len > 0 && ip_str[len - 1] == '\n')
        ip_str[len - 1] = '\0';

    /* Validate that we have a null terminator within our buffer bounds */
    if (strnlen(ip_str, sizeof(ip_str)) >= sizeof(ip_str)) {
        FW_DEBUG(1, "EXIT: add_ban_write -> -EINVAL (not null-terminated)");
        return -EINVAL;  /* String not properly null-terminated within buffer */
    }

    FW_DEBUG(2, "Processing ban request for IP: %s", ip_str);

    // Check if it's a valid IPv4 address
    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        // Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc.
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
            printk(KERN_WARNING "firewall: Attempt to ban invalid IPv4: %s\n", ip_str);
            return -EINVAL;
        }

        // Additional validation: reject Class E (reserved for future use) but allow some valid single addresses
        // Class E is 240.0.0.0/4 (240.0.0.0 - 255.255.255.255)
        // However, 254.255.255.255 is a valid unicast address that should be banned
        // Only reject addresses in the 240.0.0.0/4 range except 254.255.255.255
        unsigned int ip_num = ntohl(ipv4);
        if ((ip_num >= 0xF0000000 && ip_num < 0xFE000000) || ip_num == 0xFFFFFFFF) {
            // Reject 240.0.0.0 - 253.255.255.255 (true Class E reserved)
            // But allow 254.0.0.0 - 254.255.255.255 and 255.0.0.0 (with other checks)
            printk(KERN_WARNING "firewall: Attempt to ban reserved IPv4 Class E: %s\n", ip_str);
            return -EINVAL;
        }

        // Additional validation: check for private/reserved IP ranges that shouldn't be banned in typical scenarios
        // This adds an extra layer of protection against accidental misconfiguration
        unsigned int ip_class_a = (ntohl(ipv4) >> 24) & 0xFF;
        unsigned int ip_class_b = (ntohl(ipv4) >> 16) & 0xFF;

        // Check for RFC 1918 private networks (should these really be banned?)
        if ((ip_class_a == 10) ||  // 10.0.0.0/8
            (ip_class_a == 172 && ip_class_b >= 16 && ip_class_b <= 31) ||  // 172.16.0.0/12
            (ip_class_a == 192 && ip_class_b == 168)) {  // 192.168.0.0/16
            printk(KERN_WARNING "firewall: Attempt to ban private IPv4 range %pI4 - this may be unintended\n", &ipv4);
        }

        // Check flood protection
        if (check_flood_protection() < 0) {
            printk(KERN_WARNING "firewall: Flood protection triggered - too many ban requests\n");
            return -EBUSY;
        }

        int result = ban_ip_v4(&fw_info, ipv4);
        if (result < 0) {
            if (result == -EPERM) {
                printk(KERN_INFO "firewall: Requested IPv4 %s is in whitelist, not banned\n", ip_str);
            } else if (result == -ENOMEM) {
                printk(KERN_ERR "firewall: Failed to allocate memory for ban entry for IPv4 %s\n", ip_str);
            } else if (result == -ENOSPC) {
                printk(KERN_WARNING "firewall: Ban table full, cannot ban IPv4 %s\n", ip_str);
            } else {
                printk(KERN_ERR "firewall: Unknown error %d when trying to ban IPv4 %s\n", result, ip_str);
            }
            FW_DEBUG(1, "EXIT: add_ban_write -> %d (ban_ip_v4 failed)", result);
            return result;
        }
    }
    // Check if it's a valid IPv6 address
    else if (in6_pton(ip_str, -1, ipv6.s6_addr, -1, NULL)) {
        // Additional validation: reject invalid IPv6 addresses
        if (ipv6_addr_any(&ipv6) || ipv6_addr_loopback(&ipv6) || ipv6_addr_is_multicast(&ipv6)) {
            printk(KERN_WARNING "firewall: Attempt to ban invalid IPv6: %s\n", ip_str);
            return -EINVAL;
        }

        // Check flood protection
        if (check_flood_protection() < 0) {
            printk(KERN_WARNING "firewall: Flood protection triggered - too many ban requests\n");
            return -EBUSY;
        }

        int result = ban_ip_v6(&fw_info, &ipv6);
        if (result < 0) {
            if (result == -EPERM) {
                printk(KERN_INFO "firewall: Requested IPv6 %s is in whitelist, not banned\n", ip_str);
            } else if (result == -ENOMEM) {
                printk(KERN_ERR "firewall: Failed to allocate memory for ban entry for IPv6 %s\n", ip_str);
            } else if (result == -ENOSPC) {
                printk(KERN_WARNING "firewall: Ban table full, cannot ban IPv6 %s\n", ip_str);
            } else {
                printk(KERN_ERR "firewall: Unknown error %d when trying to ban IPv6 %s\n", result, ip_str);
            }
            FW_DEBUG(1, "EXIT: add_ban_write -> %d (ban_ip_v6 failed)", result);
            return result;
        }
    }
    else {
        printk(KERN_WARNING "firewall: Invalid IP address format: %s\n", ip_str);
        FW_DEBUG(1, "EXIT: add_ban_write -> -EINVAL (invalid IP format)");
        return -EINVAL;
    }

    FW_DEBUG(1, "EXIT: add_ban_write -> %zu (success)", count);
    return count;
}

/*
 * check_flood_protection - Check if adding this entry would exceed flood limits
 * Current policy: Max 200 additions per second (increased from 50 for better testability)
 */
static int check_flood_protection(void)
{
    unsigned long now = jiffies;
    unsigned long one_second = HZ;  // One second in jiffies

    spin_lock(&fw_info.flood_lock);

    // Reset counter if more than 1 second has passed since last check
    if (time_after(now, fw_info.last_flood_check + one_second)) {
        fw_info.recent_additions = 1;  // This addition counts as the first
        fw_info.last_flood_check = now;
    } else {
        // Increment addition counter
        fw_info.recent_additions++;

        // Check if we've exceeded the limit (e.g., 200 additions per second)
        if (fw_info.recent_additions > 200) {
            spin_unlock(&fw_info.flood_lock);
            return -EBUSY;  // Too many additions in the time window
        }
    }

    spin_unlock(&fw_info.flood_lock);
    return 0;
}

/*
 * remove_ban_write - Procfs write handler for unbanning IPs (supports IPv4 and IPv6)
 */
static ssize_t remove_ban_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *ppos)
{
    char ip_str[INET6_ADDRSTRLEN + 2];
    __be32 ipv4;
    struct in6_addr ipv6;
    ssize_t len = min(count, (size_t)(sizeof(ip_str) - 1));

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (count == 0)
        return 0;
    if (copy_from_user(ip_str, buf, len))
        return -EFAULT;

    ip_str[len] = '\0';
    if (len > 0 && ip_str[len - 1] == '\n')
        ip_str[len - 1] = '\0';

    /* Validate that we have a null terminator within our buffer bounds */
    if (strnlen(ip_str, sizeof(ip_str)) >= sizeof(ip_str)) {
        return -EINVAL;  /* String not properly null-terminated within buffer */
    }

    // Check if it's a valid IPv4 address
    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        // Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc.
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
            printk(KERN_WARNING "firewall: Attempt to unban invalid IPv4: %s\n", ip_str);
            return -EINVAL;
        }

        if (unban_ip_v4(&fw_info, ipv4) < 0)
            return -ENOENT;
    }
    // Check if it's a valid IPv6 address
    else if (in6_pton(ip_str, -1, ipv6.s6_addr, -1, NULL)) {
        // Additional validation: reject invalid IPv6 addresses
        if (ipv6_addr_any(&ipv6) || ipv6_addr_loopback(&ipv6) || ipv6_addr_is_multicast(&ipv6)) {
            printk(KERN_WARNING "firewall: Attempt to unban invalid IPv6: %s\n", ip_str);
            return -EINVAL;
        }

        if (unban_ip_v6(&fw_info, &ipv6) < 0)
            return -ENOENT;
    }
    else {
        printk(KERN_WARNING "firewall: Invalid IP address format: %s\n", ip_str);
        return -EINVAL;
    }

    return count;
}

static const struct proc_ops add_ban_fops = {
    .proc_write = add_ban_write,
};

static const struct proc_ops remove_ban_fops = {
    .proc_write = remove_ban_write,
};

/*
 * whitelist_show - Procfs show handler for whitelist hash table (supports IPv4 and IPv6)
 */
static int whitelist_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct whitelist_entry *entry;
    u32 hash;
    char ip_str[INET6_ADDRSTRLEN];
    int prefix_len;

    seq_printf(m, "Whitelisted IPs (protected from ban):\n");
    seq_printf(m, "--------------------------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        // For subnets, we need to display the network address
        if (entry->type == IPV4_ADDR) {
            __be32 network_addr = entry->ip.ipv4 & entry->mask.ipv4;
            ipv4_to_str(network_addr, ip_str, sizeof(ip_str));
            prefix_len = inet_mask_len(entry->mask.ipv4);
            seq_printf(m, "%s/%d  on %s\n",
                       ip_str,
                       prefix_len,
                       entry->device_name);
        } else if (entry->type == IPV6_ADDR) {
            // For IPv6, we need to calculate the prefix length differently
            int bits = 0;
            for (int i = 0; i < 16; i++) {
                unsigned char b = entry->mask.ipv6.s6_addr[i];
                while (b) {
                    bits++;
                    b &= b - 1;  // Remove the lowest set bit
                }
            }
            ipv6_to_str(&entry->ip.ipv6, ip_str, sizeof(ip_str));
            seq_printf(m, "%s/%d  on %s\n",
                       ip_str,
                       bits,
                       entry->device_name);
        }
    }
    rcu_read_unlock();

    seq_printf(m, "--------------------------------------\n");
    seq_printf(m, "Total: %d entries\n", atomic_read(&fw->whitelist_count));
    return 0;
}

static int whitelist_open(struct inode *inode, struct file *file)
{
    return single_open(file, whitelist_show, NULL);
}

/*
 * whitelist_add_write - Add IP to whitelist (supports IPv4 and IPv6)
 */
static ssize_t whitelist_add_write(struct file *file, const char __user *buf,
                                    size_t count, loff_t *ppos)
{
    char input[INET6_ADDRSTRLEN + 8];  // Support IPv6 address + CIDR notation
    ssize_t len = min(count, (size_t)(sizeof(input) - 1));
    __be32 ipv4, mask4;
    struct in6_addr ipv6, mask6;
    int prefix_len = 32;
    int max_prefix = 32;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (count == 0)
        return 0;
    if (copy_from_user(input, buf, len))
        return -EFAULT;

    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    /* Validate that we have a null terminator within our buffer bounds */
    if (strnlen(input, sizeof(input)) >= sizeof(input)) {
        return -EINVAL;  /* String not properly null-terminated within buffer */
    }

    char *slash = strchr(input, '/');
    if (slash) {
        *slash = '\0';
        if (kstrtoint(slash + 1, 10, &prefix_len) < 0)
            return -EINVAL;
    }

    // Check if it's a valid IPv4 address
    if (in4_pton(input, -1, (u8 *)&ipv4, -1, NULL)) {
        max_prefix = 32;
        if (prefix_len < 0 || prefix_len > max_prefix)
            return -EINVAL;

        // Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc.
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
            printk(KERN_WARNING "firewall: Attempt to whitelist invalid IPv4: %s\n", input);
            return -EINVAL;
        }

        // Calculate network mask based on prefix length
        mask4 = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));
        __be32 normalized_ip = ipv4 & mask4;  // Normalize the IP to the network address

        if (add_whitelist_entry_v4(&fw_info, normalized_ip, mask4, "manual") < 0)
            return -ENOSPC;
    }
    // Check if it's a valid IPv6 address
    else if (in6_pton(input, -1, ipv6.s6_addr, -1, NULL)) {
        max_prefix = 128;
        if (prefix_len < 0 || prefix_len > max_prefix)
            return -EINVAL;

        // Additional validation: reject invalid IPv6 addresses
        if (ipv6_addr_any(&ipv6) || ipv6_addr_loopback(&ipv6) || ipv6_addr_is_multicast(&ipv6)) {
            printk(KERN_WARNING "firewall: Attempt to whitelist invalid IPv6: %s\n", input);
            return -EINVAL;
        }

        // Calculate IPv6 network mask based on prefix length
        memset(&mask6, 0, sizeof(mask6));
        int bytes = prefix_len / 8;
        int bits = prefix_len % 8;
        for (int i = 0; i < bytes; i++) {
            mask6.s6_addr[i] = 0xFF;
        }
        if (bits > 0) {
            mask6.s6_addr[bytes] = 0xFF << (8 - bits);
        }

        // Normalize the IPv6 address to the network address
        struct in6_addr normalized_ipv6;
        for (int i = 0; i < 16; i++) {
            normalized_ipv6.s6_addr[i] = ipv6.s6_addr[i] & mask6.s6_addr[i];
        }

        if (add_whitelist_entry_v6(&fw_info, &normalized_ipv6, &mask6, "manual") < 0)
            return -ENOSPC;
    }
    else {
        printk(KERN_WARNING "firewall: Invalid IP address format: %s\n", input);
        return -EINVAL;
    }

    return count;
}

/*
 * whitelist_remove_write - Remove IP from whitelist (supports IPv4 and IPv6)
 * Fixed version: Handles both individual IPs and subnets correctly by normalizing to network address
 */
static ssize_t whitelist_remove_write(struct file *file, const char __user *buf,
                                       size_t count, loff_t *ppos)
{
    char input[INET6_ADDRSTRLEN + 8];  // Support IPv6 address + CIDR notation
    ssize_t len = min(count, (size_t)(sizeof(input) - 1));
    __be32 ipv4, mask4 = 0xFFFFFFFF;  // Default to /32 (single IP)
    struct in6_addr ipv6, mask6;
    int prefix_len = 32;
    int max_prefix = 32;

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (count == 0)
        return 0;
    if (copy_from_user(input, buf, len))
        return -EFAULT;

    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    /* Validate that we have a null terminator within our buffer bounds */
    if (strnlen(input, sizeof(input)) >= sizeof(input)) {
        return -EINVAL;  /* String not properly null-terminated within buffer */
    }

    char *slash = strchr(input, '/');
    if (slash) {
        *slash = '\0';
        if (kstrtoint(slash + 1, 10, &prefix_len) < 0)
            return -EINVAL;
    }

    // Check if it's a valid IPv4 address
    if (in4_pton(input, -1, (u8 *)&ipv4, -1, NULL)) {
        max_prefix = 32;
        if (prefix_len < 0 || prefix_len > max_prefix)
            return -EINVAL;

        // Calculate network mask based on prefix length
        mask4 = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));

        // Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc.
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
            printk(KERN_WARNING "firewall: Attempt to remove invalid IPv4 from whitelist: %s\n", input);
            return -EINVAL;
        }

        // Normalize the IP to the network address for removal
        __be32 normalized_ip = ipv4 & mask4;

        if (remove_whitelist_entry_v4(&fw_info, normalized_ip) < 0)
            return -ENOENT;
    }
    // Check if it's a valid IPv6 address
    else if (in6_pton(input, -1, ipv6.s6_addr, -1, NULL)) {
        max_prefix = 128;
        if (prefix_len < 0 || prefix_len > max_prefix)
            return -EINVAL;

        // Calculate IPv6 network mask based on prefix length
        memset(&mask6, 0, sizeof(mask6));
        int bytes = prefix_len / 8;
        int bits = prefix_len % 8;
        for (int i = 0; i < bytes; i++) {
            mask6.s6_addr[i] = 0xFF;
        }
        if (bits > 0) {
            mask6.s6_addr[bytes] = 0xFF << (8 - bits);
        }

        // Additional validation: reject invalid IPv6 addresses
        if (ipv6_addr_any(&ipv6) || ipv6_addr_loopback(&ipv6) || ipv6_addr_is_multicast(&ipv6)) {
            printk(KERN_WARNING "firewall: Attempt to remove invalid IPv6 from whitelist: %s\n", input);
            return -EINVAL;
        }

        // Normalize the IPv6 address to the network address for removal
        struct in6_addr normalized_ipv6;
        for (int i = 0; i < 16; i++) {
            normalized_ipv6.s6_addr[i] = ipv6.s6_addr[i] & mask6.s6_addr[i];
        }

        if (remove_whitelist_entry_v6(&fw_info, &normalized_ipv6) < 0)
            return -ENOENT;
    }
    else {
        printk(KERN_WARNING "firewall: Invalid IP address format: %s\n", input);
        return -EINVAL;
    }

    return count;
}

static const struct proc_ops whitelist_fops = {
    .proc_open = whitelist_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static const struct proc_ops whitelist_add_fops = {
    .proc_write = whitelist_add_write,
};

static const struct proc_ops whitelist_remove_fops = {
    .proc_write = whitelist_remove_write,
};

/*
 * config_show / config_write - Procfs handlers for configuration
 * Moved before create_procfs_entries to avoid forward declaration issues
 */
static int config_show(struct seq_file *m, void *v)
{
    /* FIX P1-5: Use READ_ONCE for atomic access to module parameters */
    seq_printf(m, "Current firewall configuration:\n");
    seq_printf(m, "--------------------------------\n");
    seq_printf(m, "ban_time: %u seconds\n", READ_ONCE(fw_ban_time));
    seq_printf(m, "max_retries: %u\n", READ_ONCE(fw_max_retries));
    seq_printf(m, "findtime: %u seconds\n", READ_ONCE(fw_findtime));
    seq_printf(m, "Banned entries: %d\n", atomic_read(&fw_info.ban_count));
    seq_printf(m, "Whitelisted entries: %d\n", atomic_read(&fw_info.whitelist_count));
    return 0;
}

static int config_open(struct inode *inode, struct file *file)
{
    return single_open(file, config_show, NULL);
}

static ssize_t config_write(struct file *file, const char __user *buf,
                             size_t count, loff_t *ppos)
{
    char input[256];
    char param[64];
    unsigned int value;
    ssize_t len = min(count, (size_t)(sizeof(input) - 1));

    if (!capable(CAP_NET_ADMIN))
        return -EPERM;
    if (count == 0)
        return 0;
    if (copy_from_user(input, buf, len))
        return -EFAULT;

    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    if (sscanf(input, "%63s %u", param, &value) != 2) {
        printk(KERN_ERR "firewall: Invalid config format. Use: param value\n");
        return -EINVAL;
    }

    if (strcmp(param, "ban_time") == 0) {
        if (value < 1 || value > 365 * 24 * 60 * 60) {  // 1 year max
            printk(KERN_ERR "firewall: ban_time must be between 1 and %d seconds\n", 365 * 24 * 60 * 60);
            return -EINVAL;
        }
        /* FIX P1-5: Use WRITE_ONCE to atomically write fw_ban_time to prevent
         * torn writes when the value is being concurrently read from netfilter hooks. */
        WRITE_ONCE(fw_ban_time, value);
        printk(KERN_INFO "firewall: ban_time updated to %u seconds\n", value);
    } else if (strcmp(param, "max_retries") == 0) {
        if (value < 1 || value > 1000) {  // Reasonable upper limit
            printk(KERN_ERR "firewall: max_retries must be between 1 and 1000\n");
            return -EINVAL;
        }
        /* FIX P1-5: Use WRITE_ONCE for atomic access to fw_max_retries */
        WRITE_ONCE(fw_max_retries, value);
        printk(KERN_INFO "firewall: max_retries updated to %u\n", value);
    } else if (strcmp(param, "findtime") == 0) {
        if (value < 1 || value > 365 * 24 * 60 * 60) {  // 1 year max
            printk(KERN_ERR "firewall: findtime must be between 1 and %d seconds\n", 365 * 24 * 60 * 60);
            return -EINVAL;
        }
        /* FIX P1-5: Use WRITE_ONCE for atomic access to fw_findtime */
        WRITE_ONCE(fw_findtime, value);
        printk(KERN_INFO "firewall: findtime updated to %u seconds\n", value);
    } else {
        printk(KERN_ERR "firewall: Unknown parameter: %s\n", param);
        return -EINVAL;
    }

    return count;
}

static const struct proc_ops config_fops = {
    .proc_open = config_open,
    .proc_read = seq_read,
    .proc_write = config_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * create_procfs_entries - Create procfs interface
 */
int create_procfs_entries(struct firewall_info *fw)
{
    struct proc_dir_entry *entry;

    fw->proc_dir = proc_mkdir("firewall", NULL);
    if (!fw->proc_dir) {
        printk(KERN_ERR "firewall: Failed to create /proc/firewall\n");
        return -ENOMEM;
    }

    entry = proc_create("ban_list", 0400, fw->proc_dir, &ban_list_fops);  /* Only readable by owner */
    if (!entry)
        goto err_cleanup;
    fw->proc_ban_list = entry;

    entry = proc_create("add_ban", 0200, fw->proc_dir, &add_ban_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_add_ban = entry;

    entry = proc_create("remove_ban", 0200, fw->proc_dir, &remove_ban_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_remove_ban = entry;

    entry = proc_create("config", 0600, fw->proc_dir, &config_fops);  /* Read/write for configuration */
    if (!entry)
        goto err_cleanup;
    fw->proc_config = entry;

    entry = proc_create("whitelist", 0400, fw->proc_dir, &whitelist_fops);  /* Only readable by owner */
    if (!entry)
        goto err_cleanup;
    fw->proc_whitelist = entry;

    entry = proc_create("whitelist_add", 0200, fw->proc_dir, &whitelist_add_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_whitelist_add = entry;

    entry = proc_create("whitelist_remove", 0200, fw->proc_dir, &whitelist_remove_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_whitelist_remove = entry;

    printk(KERN_INFO "firewall: Procfs entries created\n");
    return 0;

err_cleanup:
    destroy_procfs_entries(fw);
    return -ENOMEM;
}

/*
 * destroy_procfs_entries - Remove procfs entries
 */
void destroy_procfs_entries(struct firewall_info *fw)
{
    if (fw->proc_config)
        proc_remove(fw->proc_config);
    if (fw->proc_whitelist_remove)
        proc_remove(fw->proc_whitelist_remove);
    if (fw->proc_whitelist_add)
        proc_remove(fw->proc_whitelist_add);
    if (fw->proc_whitelist)
        proc_remove(fw->proc_whitelist);
    if (fw->proc_settings)
        proc_remove(fw->proc_settings);
    if (fw->proc_remove_ban)
        proc_remove(fw->proc_remove_ban);
    if (fw->proc_add_ban)
        proc_remove(fw->proc_add_ban);
    if (fw->proc_ban_list)
        proc_remove(fw->proc_ban_list);
    if (fw->proc_dir)
        proc_remove(fw->proc_dir);
}

/*
 * nf_hook_func_ipv4 - Netfilter hook function for IPv4
 * Enhanced version: Improved skb validation and additional safety checks
 */
static unsigned int nf_hook_func_ipv4(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr iph_copy;
    struct iphdr *iph;
    __be32 src_ip;
    unsigned long now;
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    unsigned int bkt;
    bool is_whitelisted = false;
    bool is_banned = false;

    if (unlikely(!skb))
        return NF_ACCEPT;

    /* Additional validation: verify packet integrity */
    if (unlikely(skb->len < sizeof(struct iphdr)))
        return NF_ACCEPT;

    /* Validate network header is set and points to valid data */
    if (unlikely(!skb_network_header(skb)))
        return NF_ACCEPT;

    /* Verify that we can safely pull the IP header */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
        return NF_ACCEPT;

    /* Safely copy IP header to prevent reading from non-linear skb data */
    iph = skb_header_pointer(skb, 0, sizeof(iph_copy), &iph_copy);
    if (!iph)
        return NF_ACCEPT;

    /* Additional validation: check IP header fields for validity */
    if (iph->version != 4)  /* IPv4 only */
        return NF_ACCEPT;

    if (iph->ihl < 5)  /* Minimum IP header length is 5 words */
        return NF_ACCEPT;

    if (iph->ihl > 15)  /* Maximum IP header length is 15 words (60 bytes) */
        return NF_ACCEPT;

    if (iph->ihl * 4 > ntohs(iph->tot_len))  /* Header length must not exceed total length */
        return NF_ACCEPT;

    if (ntohs(iph->tot_len) < sizeof(struct iphdr))  /* Packet length check */
        return NF_ACCEPT;

    if (ntohs(iph->tot_len) > skb->len)  /* Total length must not exceed skb length */
        return NF_ACCEPT;

    /* Strict validation: check for maximum allowed packet size to prevent oversized packets */
    if (ntohs(iph->tot_len) > 0xFFFF) {  /* IP specification maximum size (65535 bytes) */
        return NF_ACCEPT;
    }

    /* Additional check: consider extremely large packets suspicious (MTU is typically 1500 bytes) */
    if (ntohs(iph->tot_len) > 9000) {  /* Jumbo frames are typically max ~9000 bytes */
        /* Log the suspicious packet but still process it for banning purposes */
    }

    /* Check for IP fragmentation - only process unfragmented packets or first fragments */
    if (ntohs(iph->frag_off) & IP_MF || (ntohs(iph->frag_off) & 0x1FFF) != 0) {
        /* Fragmented packets are allowed through - complex to handle in kernel space */
        return NF_ACCEPT;
    }

    src_ip = iph->saddr;

    /* Validate source IP is not reserved/private for internal use */
    if (unlikely(src_ip == 0 ||                      /* 0.0.0.0 */
                 src_ip == 0xFFFFFFFF ||            /* 255.255.255.255 */
                 (ntohl(src_ip) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
                 (ntohl(src_ip) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
                 (ntohl(src_ip) & 0xFF000000) == 0x00000000)) { /* 0.x.x.x */
        return NF_ACCEPT;
    }

    /* Additional validation: validate protocol field for common protocols */
    if (iph->protocol != IPPROTO_TCP &&
        iph->protocol != IPPROTO_UDP &&
        iph->protocol != IPPROTO_ICMP) {
        /* Allow other protocols but log for debugging */
    }

    now = jiffies;

    /* 修复: 在 RCU 锁内再次检查 shutdown 状态，防止竞态窗口
     * 前面的检查在 RCU 锁外，存在微小窗口可能访问已释放内存。
     * 在锁内二次检查确保安全性。 */
    if (unlikely(atomic_read(&fw_info.shutting_down)))
        return NF_ACCEPT;

    /* RCU read lock for whitelist and ban table access */
    rcu_read_lock();

    /* 修复: 在 RCU 锁内再次检查 shutdown 状态（双重检查） */
    if (unlikely(atomic_read(&fw_info.shutting_down))) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* FIX P0-2: Whitelist traversal with performance protection.
     * Since whitelist requires subnet matching (IP & mask == entry_ip & mask),
     * we must traverse all entries. However, we add iteration limit protection
     * to prevent performance collapse when the table is large. */
    {
        int wl_iterations = 0;
        hash_for_each_rcu(fw_info.whitelist_table, bkt, wl_entry, hash) {
            /* Add max iteration protection to prevent performance collapse */
            if (++wl_iterations > MAX_WHITELIST_ENTRIES) {
                net_warn_ratelimited("firewall: whitelist traversal limit reached, possible misconfiguration\n");
                break;
            }
            if (wl_entry->type == IPV4_ADDR &&
                ((src_ip & wl_entry->mask.ipv4) == (wl_entry->ip.ipv4 & wl_entry->mask.ipv4))) {
                is_whitelisted = true;
                break;
            }
        }
    }

    if (unlikely(is_whitelisted)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Second check: ban list - only check if not whitelisted */
    /* FIX P1-6: Pass src_ip directly to hash_for_each_possible_rcu instead of
     * pre-computing hash, ensuring consistency with hash_add which also uses
     * the key parameter for hash computation internally. */
    hash_for_each_possible_rcu(fw_info.ban_table, entry, hash, src_ip) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv4 = src_ip}, IPV4_ADDR) &&
            entry->type == IPV4_ADDR) {
            if (time_after(now, entry->unban_time)) {
                /* Entry exists but expired - treat as not banned */
                is_banned = false;
            } else {
                /* Valid banned entry */
                is_banned = true;
            }
            break;
        }
    }

    rcu_read_unlock();

    if (unlikely(is_banned))
        return NF_DROP;

    return NF_ACCEPT;
}

/*
 * nf_hook_func_ipv6 - Netfilter hook function for IPv6
 */
static unsigned int nf_hook_func_ipv6(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct ipv6hdr ip6h_copy;
    struct ipv6hdr *ip6h;
    struct in6_addr src_ip;
    unsigned long now;
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    u32 hash;
    unsigned int bkt;
    bool is_whitelisted = false;
    bool is_banned = false;

    if (unlikely(!skb))
        return NF_ACCEPT;

    /* Additional validation: verify packet integrity */
    if (unlikely(skb->len < sizeof(struct ipv6hdr)))
        return NF_ACCEPT;

    /* Validate network header is set and points to valid data */
    if (unlikely(!skb_network_header(skb)))
        return NF_ACCEPT;

    /* Verify that we can safely pull the IPv6 header */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
        return NF_ACCEPT;

    /* FIX P0-1: Use skb_header_pointer instead of ipv6_hdr(skb) to safely
     * access IPv6 header from potentially non-linear or paged skb data.
     * Direct ipv6_hdr(skb) can cause kernel crash when data is not contiguous. */
    ip6h = skb_header_pointer(skb, 0, sizeof(ip6h_copy), &ip6h_copy);
    if (!ip6h)
        return NF_ACCEPT;

    /* Additional validation: check IPv6 header fields for validity */
    if (ip6h->version != 6)  /* IPv6 only */
        return NF_ACCEPT;

    /* 验证 IPv6 包长度：payload_len + 头部大小不应超过 skb 总长度
     * 注意：skb->len 是 32 位 unsigned int，已经是主机字节序，不应使用 ntohs()
     * payload_len 是 16 位网络字节序，需要转换 */
    if ((u16)(ntohs(ip6h->payload_len)) + sizeof(struct ipv6hdr) > skb->len)
        return NF_ACCEPT;

    src_ip = ip6h->saddr;

    /* Validate source IP is not reserved/private for internal use */
    if (ipv6_addr_any(&src_ip) || ipv6_addr_loopback(&src_ip) || ipv6_addr_is_multicast(&src_ip)) {
        return NF_ACCEPT;
    }

    /* Always allow link-local addresses (fe80::/10) */
    if ((src_ip.s6_addr[0] == 0xFE) && ((src_ip.s6_addr[1] & 0xC0) == 0x80)) {
        return NF_ACCEPT;
    }

    now = jiffies;

    /* 修复: 在 RCU 锁内再次检查 shutdown 状态，防止竞态窗口
     * 前面的检查在 RCU 锁外，存在微小窗口可能访问已释放内存。
     * 在锁内二次检查确保安全性。 */
    if (unlikely(atomic_read(&fw_info.shutting_down)))
        return NF_ACCEPT;

    /* RCU read lock for whitelist and ban table access */
    rcu_read_lock();

    /* 修复: 在 RCU 锁内再次检查 shutdown 状态（双重检查） */
    if (unlikely(atomic_read(&fw_info.shutting_down))) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* FIX P0-2: Whitelist traversal with performance protection.
     * Since whitelist requires subnet matching for IPv6, we must traverse all entries.
     * Add iteration limit protection to prevent performance collapse. */
    {
        int wl_iterations = 0;
        hash_for_each_rcu(fw_info.whitelist_table, bkt, wl_entry, hash) {
            /* Add max iteration protection to prevent performance collapse */
            if (++wl_iterations > MAX_WHITELIST_ENTRIES) {
                net_warn_ratelimited("firewall: ipv6 whitelist traversal limit reached\n");
                break;
            }
            if (wl_entry->type == IPV6_ADDR) {
                // Subnet matching logic for IPv6
                struct in6_addr masked_ip, masked_entry;
                for (int i = 0; i < 4; i++) {
                    masked_ip.s6_addr32[i] = src_ip.s6_addr32[i] & wl_entry->mask.ipv6.s6_addr32[i];
                    masked_entry.s6_addr32[i] = wl_entry->ip.ipv6.s6_addr32[i] & wl_entry->mask.ipv6.s6_addr32[i];
                }

                if (ipv6_addr_equal(&masked_ip, &masked_entry)) {
                    is_whitelisted = true;
                    break;
                }
            }
        }
    }

    if (unlikely(is_whitelisted)) {
        rcu_read_unlock();
        return NF_ACCEPT;
    }

    /* Second check: ban list - only check if not whitelisted */
    hash = generate_ip_hash(&(union ip_address){.ipv6 = src_ip}, IPV6_ADDR);
    hash_for_each_possible_rcu(fw_info.ban_table, entry, hash, src_ip.s6_addr32[0]) {
        if (compare_ips(&entry->ip, &(union ip_address){.ipv6 = src_ip}, IPV6_ADDR) &&
            entry->type == IPV6_ADDR) {
            if (time_after(now, entry->unban_time)) {
                /* Entry exists but expired - treat as not banned */
                is_banned = false;
            } else {
                /* Valid banned entry */
                is_banned = true;
            }
            break;
        }
    }

    rcu_read_unlock();

    if (unlikely(is_banned))
        return NF_DROP;

    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook = nf_hook_func_ipv4,
    .pf = NFPROTO_IPV4,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};

static struct nf_hook_ops nf_ops_ipv6 __read_mostly = {
    .hook = nf_hook_func_ipv6,
    .pf = NFPROTO_IPV6,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FILTER - 1,
};

/* State persistence functions */
int save_state_to_file(const char *filename)
{
    struct file *file;
    char buffer[512];
    loff_t pos = 0;
    int written;
    int err;

    /* 临时存储结构 - 在 RCU 锁内收集数据，锁外执行 I/O 操作 */
    struct saved_ban_entry {
        char ip_str[INET6_ADDRSTRLEN];
        bool is_ipv4;
        union {
            __be32 ipv4;
            struct in6_addr ipv6;
        };
        unsigned long remaining_time;
    };

    struct saved_whitelist_entry {
        char ip_str[INET6_ADDRSTRLEN];
        bool is_ipv4;
        union {
            __be32 ipv4;
            struct in6_addr ipv6;
        };
        int prefix_len;
        char device_name[16];
    };

    /* 限制保存数量，避免大分配 */
    #define MAX_SAVE_BAN 1024
    #define MAX_SAVE_WL 64

    struct saved_ban_entry *ban_entries = NULL;
    struct saved_whitelist_entry *wl_entries = NULL;
    int ban_count = 0;
    int wl_count = 0;
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    u32 hash;

    if (!filename || !*filename) {
        printk(KERN_ERR "firewall: Invalid filename for state save\n");
        return -EINVAL;
    }

    /* Security validation: Check for directory traversal in filename */
    if (strstr(filename, "../") || strstr(filename, "/..")) {
        printk(KERN_ERR "firewall: Potential directory traversal in filename: %s\n", filename);
        return -EINVAL;
    }

    /* Security validation: Ensure the filename starts with a safe path */
    if (strncmp(filename, "/var/lib/", 9) != 0 &&
        strncmp(filename, "/tmp/", 5) != 0 &&
        strncmp(filename, "/etc/", 5) != 0) {
        printk(KERN_WARNING "firewall: State file path outside allowed directories: %s\n", filename);
        /* Only allow saving to safe directories */
        if (strchr(filename, '/') && filename[0] != '/') {
            printk(KERN_ERR "firewall: Relative path not allowed for state file: %s\n", filename);
            return -EINVAL;
        }
    }

    /* Additional security: Check if the file exists and is a symlink */
    /* We use kern_path to check file attributes without opening it */
    struct path path;
    /* Use LOOKUP_FOLLOW to resolve symlinks safely */
    unsigned int lookup_flags = LOOKUP_FOLLOW;
    err = kern_path(filename, lookup_flags, &path);
    if (!err) {
        /* File exists - get its attributes */
        struct kstat stat_buf2;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        int getattr_err = vfs_getattr(&path, &stat_buf2, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#else
        int getattr_err = vfs_getattr(&path, &stat_buf2);
#endif
        if (getattr_err) {
            /* 修复: vfs_getattr 失败时也需释放 path，防止引用泄漏 */
            net_warn_ratelimited("firewall: Cannot stat file %s, proceeding anyway\n", filename);
            path_put(&path);
        } else {
            /* Check if it's a symbolic link - use S_ISLNK on stat mode */
            if (S_ISLNK(stat_buf2.mode)) {
                printk(KERN_ERR "firewall: Refusing to write to symbolic link: %s\n", filename);
                path_put(&path); /* Release the path reference */
                return -EACCES;
            }
            /* Check if it's a directory */
            if (S_ISDIR(stat_buf2.mode)) {
                printk(KERN_ERR "firewall: Refusing to write to directory: %s\n", filename);
                path_put(&path); /* Release the path reference */
                return -EISDIR;
            }
            path_put(&path); /* Release the path reference */
        }
    } else {
        /* File doesn't exist, which is fine for creation */
        err = 0; /* Reset error since non-existence is OK */
    }

    /* 阶段1: 分配临时数组（GFP_KERNEL 可以睡眠，安全） */
    ban_entries = kmalloc_array(MAX_SAVE_BAN, sizeof(struct saved_ban_entry), GFP_KERNEL);
    if (!ban_entries) {
        printk(KERN_ERR "firewall: Failed to allocate memory for saving ban entries\n");
        return -ENOMEM;
    }

    wl_entries = kmalloc_array(MAX_SAVE_WL, sizeof(struct saved_whitelist_entry), GFP_KERNEL);
    if (!wl_entries) {
        kfree(ban_entries);
        printk(KERN_ERR "firewall: Failed to allocate memory for saving whitelist entries\n");
        return -ENOMEM;
    }

    /* 阶段2: RCU 锁内收集 ban 条目（仅复制数据到临时数组，不调用可能睡眠的函数） */
    rcu_read_lock();
    hash_for_each_rcu(fw_info.ban_table, hash, entry, hash) {
        unsigned long remaining_time = (entry->unban_time - jiffies) / HZ;
        if (remaining_time > 0 && ban_count < MAX_SAVE_BAN) {
            if (entry->type == IPV4_ADDR) {
                ipv4_to_str(entry->ip.ipv4, ban_entries[ban_count].ip_str, sizeof(ban_entries[ban_count].ip_str));
                ban_entries[ban_count].is_ipv4 = true;
                ban_entries[ban_count].ipv4 = entry->ip.ipv4;
                ban_entries[ban_count].remaining_time = remaining_time;
                ban_count++;
            } else if (entry->type == IPV6_ADDR) {
                ipv6_to_str(&entry->ip.ipv6, ban_entries[ban_count].ip_str, sizeof(ban_entries[ban_count].ip_str));
                ban_entries[ban_count].is_ipv4 = false;
                ban_entries[ban_count].ipv6 = entry->ip.ipv6;
                ban_entries[ban_count].remaining_time = remaining_time;
                ban_count++;
            }
        }
    }
    rcu_read_unlock();

    /* 阶段3: RCU 锁内收集 whitelist 条目 */
    rcu_read_lock();
    hash_for_each_rcu(fw_info.whitelist_table, hash, wl_entry, hash) {
        if (wl_count < MAX_SAVE_WL) {
            if (wl_entry->type == IPV4_ADDR) {
                __be32 network_addr = wl_entry->ip.ipv4 & wl_entry->mask.ipv4;
                ipv4_to_str(network_addr, wl_entries[wl_count].ip_str, sizeof(wl_entries[wl_count].ip_str));
                wl_entries[wl_count].is_ipv4 = true;
                wl_entries[wl_count].ipv4 = wl_entry->ip.ipv4;
                wl_entries[wl_count].prefix_len = inet_mask_len(wl_entry->mask.ipv4);
                strscpy(wl_entries[wl_count].device_name, wl_entry->device_name, sizeof(wl_entries[wl_count].device_name));
                wl_count++;
            } else if (wl_entry->type == IPV6_ADDR) {
                int bits = 0;
                for (int i = 0; i < 16; i++) {
                    unsigned char b = wl_entry->mask.ipv6.s6_addr[i];
                    while (b) {
                        bits++;
                        b &= b - 1;
                    }
                }
                ipv6_to_str(&wl_entry->ip.ipv6, wl_entries[wl_count].ip_str, sizeof(wl_entries[wl_count].ip_str));
                wl_entries[wl_count].is_ipv4 = false;
                wl_entries[wl_count].ipv6 = wl_entry->ip.ipv6;
                wl_entries[wl_count].prefix_len = bits;
                strscpy(wl_entries[wl_count].device_name, wl_entry->device_name, sizeof(wl_entries[wl_count].device_name));
                wl_count++;
            }
        }
    }
    rcu_read_unlock();

    /* 阶段4: 锁外打开文件（可以安全睡眠） */
    file = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (IS_ERR(file)) {
        printk(KERN_ERR "firewall: Failed to open file for saving state: %s\n", filename);
        kfree(ban_entries);
        kfree(wl_entries);
        return PTR_ERR(file);
    }

    /* 阶段5: 锁外写入 ban 条目 */
    for (int i = 0; i < ban_count; i++) {
        if (ban_entries[i].is_ipv4) {
            written = snprintf(buffer, sizeof(buffer), "BAN_V4 %s %lu\n",
                             ban_entries[i].ip_str, ban_entries[i].remaining_time);
        } else {
            written = snprintf(buffer, sizeof(buffer), "BAN_V6 %s %lu\n",
                             ban_entries[i].ip_str, ban_entries[i].remaining_time);
        }

        if (kernel_write(file, buffer, written, &pos) != written) {
            printk(KERN_ERR "firewall: Failed to write ban entry to state file\n");
            filp_close(file, NULL);
            kfree(ban_entries);
            kfree(wl_entries);
            return -EIO;
        }
    }

    /* 阶段6: 锁外写入 whitelist 条目 */
    for (int i = 0; i < wl_count; i++) {
        if (wl_entries[i].is_ipv4) {
            written = snprintf(buffer, sizeof(buffer), "WL_V4 %s %d %s\n",
                              wl_entries[i].ip_str, wl_entries[i].prefix_len, wl_entries[i].device_name);
        } else {
            written = snprintf(buffer, sizeof(buffer), "WL_V6 %s %d %s\n",
                              wl_entries[i].ip_str, wl_entries[i].prefix_len, wl_entries[i].device_name);
        }

        if (kernel_write(file, buffer, written, &pos) != written) {
            printk(KERN_ERR "firewall: Failed to write whitelist entry to state file\n");
            filp_close(file, NULL);
            kfree(ban_entries);
            kfree(wl_entries);
            return -EIO;
        }
    }

    /* 阶段7: 锁外关闭文件 */
    filp_close(file, NULL);

    /* 阶段8: 释放临时数组 */
    kfree(ban_entries);
    kfree(wl_entries);

    printk(KERN_INFO "firewall: State saved to %s (ban: %d, wl: %d)\n", filename, ban_count, wl_count);
    return 0;
}

int restore_state_from_file(const char *filename)
{
    struct file *file;
    char *buffer;
    loff_t pos = 0;
    ssize_t bytes_read;
    char *line, *token;

    if (!filename || !*filename) {
        printk(KERN_ERR "firewall: Invalid filename for state restore\n");
        return -EINVAL;
    }

    /* Allocate buffer on heap to avoid large stack frame */
    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "firewall: Failed to allocate buffer for state restore\n");
        return -ENOMEM;
    }

    /* Open file for reading */
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        printk(KERN_INFO "firewall: State file does not exist: %s\n", filename);
        kfree(buffer);
        return 0; /* Not an error, just no saved state to restore */
    }

    /* Read entire file into buffer */
    bytes_read = kernel_read(file, buffer, PAGE_SIZE - 1, &pos);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';

        line = buffer;
        while ((token = strsep(&line, "\n")) != NULL) {
            if (*token == '\0') continue; /* Skip empty lines */

            /* Parse the line */
            char *cmd = strsep(&token, " ");
            if (!cmd) continue;

            if (strcmp(cmd, "BAN_V4") == 0 && token) {
                char *ip_str = strsep(&token, " ");
                char *time_str = strsep(&token, " ");

                if (ip_str && time_str) {
                    __be32 ip;
                    if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
                        /* Check if IP is whitelisted before restoring ban */
                        if (is_in_whitelist_v4(&fw_info, ip)) {
                            printk(KERN_INFO "firewall: Skipping restored ban for whitelisted IP %s\n", ip_str);
                            continue;
                        }

                        unsigned long remaining_time;
                        if (kstrtoul(time_str, 10, &remaining_time) == 0) {
                            /* FIX C4: 验证 remaining_time 合理性：不能超过 1 年，不能为 0 */
                            if (remaining_time == 0 || remaining_time > 365UL * 24 * 60 * 60) {
                                printk(KERN_WARNING "firewall: Skipping ban with invalid remaining time: %lu\n", remaining_time);
                                continue;
                            }

                            /* FIX C4: 检查整数溢出：remaining_time * HZ 不能溢出 */
                            if (remaining_time > (ULONG_MAX / HZ)) {
                                printk(KERN_WARNING "firewall: Skipping ban - remaining_time * HZ would overflow\n");
                                continue;
                            }

                            unsigned long ban_duration = remaining_time * HZ;

                            /* FIX C4: 检查 jiffies + ban_duration 是否会溢出回绕 */
                            unsigned long unban_time;
                            if (jiffies > ULONG_MAX - ban_duration) {
                                /* jiffies 即将回绕，使用最大安全值 */
                                unban_time = jiffies + min(ban_duration, ULONG_MAX - jiffies);
                                printk(KERN_WARNING "firewall: Jiffies wrap protection applied for ban restoration\n");
                            } else {
                                unban_time = jiffies + ban_duration;
                            }

                            /* Add ban entry with calculated unban time */
                            struct ban_entry *entry;

                            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                            if (!entry) {
                                printk(KERN_ERR "firewall: Failed to allocate memory for restored ban entry\n");
                                continue;
                            }

                            entry->ip.ipv4 = ip;
                            entry->type = IPV4_ADDR;
                            entry->ban_time = jiffies;
                            entry->unban_time = unban_time;
                            atomic_set(&entry->retry_count, 0);
                            entry->being_freed = false;  /* 初始化防止双重释放标记 */

                            spin_lock(&fw_info.lock);
                            hash_add(fw_info.ban_table, &entry->hash, ip);
                            atomic_inc(&fw_info.ban_count);
                            spin_unlock(&fw_info.lock);

                            printk(KERN_INFO "firewall: Restored ban for IPv4 %s (expires in %lu seconds)\n",
                                   ip_str, remaining_time);
                        }
                    }
                }
            } else if (strcmp(cmd, "BAN_V6") == 0 && token) {
                char *ip_str = strsep(&token, " ");
                char *time_str = strsep(&token, " ");

                if (ip_str && time_str) {
                    struct in6_addr ip;
                    if (in6_pton(ip_str, -1, ip.s6_addr, -1, NULL)) {
                        /* Check if IP is whitelisted before restoring ban */
                        if (is_in_whitelist_v6(&fw_info, &ip)) {
                            printk(KERN_INFO "firewall: Skipping restored ban for whitelisted IPv6 %s\n", ip_str);
                            continue;
                        }

                        unsigned long remaining_time;
                        if (kstrtoul(time_str, 10, &remaining_time) == 0) {
                            /* FIX C4: 验证 remaining_time 合理性：不能超过 1 年，不能为 0 */
                            if (remaining_time == 0 || remaining_time > 365UL * 24 * 60 * 60) {
                                printk(KERN_WARNING "firewall: Skipping ban with invalid remaining time: %lu\n", remaining_time);
                                continue;
                            }

                            /* FIX C4: 检查整数溢出：remaining_time * HZ 不能溢出 */
                            if (remaining_time > (ULONG_MAX / HZ)) {
                                printk(KERN_WARNING "firewall: Skipping ban - remaining_time * HZ would overflow\n");
                                continue;
                            }

                            unsigned long ban_duration = remaining_time * HZ;

                            /* FIX C4: 检查 jiffies + ban_duration 是否会溢出回绕 */
                            unsigned long unban_time;
                            if (jiffies > ULONG_MAX - ban_duration) {
                                /* jiffies 即将回绕，使用最大安全值 */
                                unban_time = jiffies + min(ban_duration, ULONG_MAX - jiffies);
                                printk(KERN_WARNING "firewall: Jiffies wrap protection applied for ban restoration\n");
                            } else {
                                unban_time = jiffies + ban_duration;
                            }

                            /* Add ban entry with calculated unban time */
                            struct ban_entry *entry;

                            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                            if (!entry) {
                                printk(KERN_ERR "firewall: Failed to allocate memory for restored ban entry\n");
                                continue;
                            }

                            entry->ip.ipv6 = ip;
                            entry->type = IPV6_ADDR;
                            entry->ban_time = jiffies;
                            entry->unban_time = unban_time;
                            atomic_set(&entry->retry_count, 0);
                            entry->being_freed = false;  /* 初始化防止双重释放标记 */

                            spin_lock(&fw_info.lock);
                            hash_add(fw_info.ban_table, &entry->hash, ip.s6_addr32[0]);
                            atomic_inc(&fw_info.ban_count);
                            spin_unlock(&fw_info.lock);

                            printk(KERN_INFO "firewall: Restored ban for IPv6 %s (expires in %lu seconds)\n",
                                   ip_str, remaining_time);
                        }
                    }
                }
            } else if (strcmp(cmd, "WL_V4") == 0 && token) {
                char *ip_str = strsep(&token, " ");
                char *mask_str = strsep(&token, " ");
                char *dev_name = strsep(&token, " ");

                if (ip_str && mask_str) {
                    __be32 ip, mask = 0xFFFFFFFF;
                    int prefix_len;

                    if (kstrtoint(mask_str, 10, &prefix_len) == 0) {
                        /* Calculate network mask based on prefix length */
                        mask = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));

                        if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
                            __be32 normalized_ip = ip & mask;

                            /* Add whitelist entry */
                            int result = add_whitelist_entry_v4(&fw_info, normalized_ip, mask,
                                                                dev_name ? dev_name : "restored");
                            if (result == 0) {
                                printk(KERN_INFO "firewall: Restored whitelist entry for IPv4 %s/%d\n",
                                       ip_str, prefix_len);
                            }
                        }
                    }
                }
            } else if (strcmp(cmd, "WL_V6") == 0 && token) {
                char *ip_str = strsep(&token, " ");
                char *mask_str = strsep(&token, " ");
                char *dev_name = strsep(&token, " ");

                if (ip_str && mask_str) {
                    struct in6_addr ip, mask;
                    int prefix_len;

                    if (kstrtoint(mask_str, 10, &prefix_len) == 0) {
                        /* Calculate IPv6 network mask based on prefix length */
                        memset(&mask, 0, sizeof(mask));
                        int bytes = prefix_len / 8;
                        int bits = prefix_len % 8;
                        for (int i = 0; i < bytes; i++) {
                            mask.s6_addr[i] = 0xFF;
                        }
                        if (bits > 0) {
                            mask.s6_addr[bytes] = 0xFF << (8 - bits);
                        }

                        if (in6_pton(ip_str, -1, ip.s6_addr, -1, NULL)) {
                            /* Normalize the IPv6 address to the network address */
                            struct in6_addr normalized_ip;
                            for (int i = 0; i < 16; i++) {
                                normalized_ip.s6_addr[i] = ip.s6_addr[i] & mask.s6_addr[i];
                            }

                            /* Add whitelist entry */
                            int result = add_whitelist_entry_v6(&fw_info, &normalized_ip, &mask,
                                                                dev_name ? dev_name : "restored");
                            if (result == 0) {
                                printk(KERN_INFO "firewall: Restored whitelist entry for IPv6 %s/%d\n",
                                       ip_str, prefix_len);
                            }
                        }
                    }
                }
            }
        }
    }

    filp_close(file, NULL);
    kfree(buffer);
    printk(KERN_INFO "firewall: State restored from %s\n", filename);
    return 0;
}

/*
 * firewall_init - Module initialization
 */
static int __init firewall_init(void)
{
    int ret;

    printk(KERN_INFO "firewall: Loading firewall module v1.4\n");

    /* 参数下界检查 - 防止 0 或过小值导致异常行为 */
    /* FIX P1-5: Use READ_ONCE for atomic access to module parameters */
    if (READ_ONCE(fw_ban_time) < 1) {
        printk(KERN_ERR "firewall: fw_ban_time must be >= 1\n");
        return -EINVAL;
    }
    if (READ_ONCE(fw_max_retries) < 1) {
        printk(KERN_ERR "firewall: fw_max_retries must be >= 1\n");
        return -EINVAL;
    }
    if (READ_ONCE(fw_findtime) < 1) {
        printk(KERN_ERR "firewall: fw_findtime must be >= 1\n");
        return -EINVAL;
    }

    /* 参数上界检查 - 防止过大的值导致整数溢出 */
    if (READ_ONCE(fw_ban_time) > 365 * 24 * 60 * 60) {  /* 1 year max */
        printk(KERN_ERR "firewall: fw_ban_time too large (max 1 year)\n");
        return -EINVAL;
    }
    if (READ_ONCE(fw_findtime) > 365 * 24 * 60 * 60) {  /* 1 year max */
        printk(KERN_ERR "firewall: fw_findtime too large (max 1 year)\n");
        return -EINVAL;
    }
    if (READ_ONCE(fw_max_retries) > 1000) {  /* Reasonable upper limit */
        printk(KERN_ERR "firewall: fw_max_retries too large (max 1000)\n");
        return -EINVAL;
    }

    /* Additional validation: ban time should not be less than findtime */
    /* FIX P1-5: Use READ_ONCE for atomic access to module parameters */
    if (READ_ONCE(fw_ban_time) < READ_ONCE(fw_findtime)) {
        printk(KERN_WARNING "firewall: fw_ban_time (%u) is less than fw_findtime (%u), adjusting ban time\n",
               READ_ONCE(fw_ban_time), READ_ONCE(fw_findtime));
        /* FIX P1-5: Use WRITE_ONCE for atomic write */
        WRITE_ONCE(fw_ban_time, READ_ONCE(fw_findtime));  /* Ensure ban time is at least findtime */
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

    /* Restore state from file if available */
    if (state_file && strlen(state_file) > 0) {
        restore_state_from_file(state_file);
    }

    auto_discover_system_ips(&fw_info);

    timer_setup(&fw_info.cleanup_timer, cleanup_timer_callback, 0);
    fw_info.timer_initialized = true;  /* 标记定时器已初始化 */
    /* FIX P1-5: Use READ_ONCE for atomic access to fw_ban_time */
    mod_timer(&fw_info.cleanup_timer, jiffies + ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 2);

    ret = create_procfs_entries(&fw_info);
    if (ret)
        goto err_timer;

    ret = nf_register_net_hook(&init_net, &nf_ops_ipv4);
    if (ret) {
        printk(KERN_ERR "firewall: Failed to register IPv4 netfilter hook: %d\n", ret);
        goto err_procfs;
    }

    ret = nf_register_net_hook(&init_net, &nf_ops_ipv6);
    if (ret) {
        printk(KERN_ERR "firewall: Failed to register IPv6 netfilter hook: %d\n", ret);
        nf_unregister_net_hook(&init_net, &nf_ops_ipv4);
        goto err_procfs;
    }

    printk(KERN_INFO "firewall: Module loaded successfully (ban_time=%u, max_retries=%u, findtime=%u, state_file=%s)\n",
           fw_ban_time, fw_max_retries, fw_findtime, state_file);
    return 0;

err_procfs:
    destroy_procfs_entries(&fw_info);
err_timer:
    timer_delete_sync(&fw_info.cleanup_timer);
    return ret;
}

/*
 * firewall_exit - Module cleanup
 */
static void __exit firewall_exit(void)
{
    struct ban_entry *entry;
    struct hlist_node *tmp;
    u32 ban_hash;
    struct whitelist_entry *wl;
    u32 wl_hash;

    printk(KERN_INFO "firewall: Unloading firewall module\n");

    /* FIX C5: 设置关闭标志，阻止新操作 */
    atomic_set(&fw_info.shutting_down, 1);

    /* FIX C5: 1. 先注销 netfilter hooks，阻止新包进入 */
    nf_unregister_net_hook(&init_net, &nf_ops_ipv6);
    nf_unregister_net_hook(&init_net, &nf_ops_ipv4);

    /* FIX C5: 2. 停止定时器 */
    if (fw_info.timer_initialized) {
        timer_delete_sync(&fw_info.cleanup_timer);
        fw_info.timer_initialized = false;
    }

    /* FIX C5: 3. 销毁 procfs 入口，阻止用户空间操作 */
    destroy_procfs_entries(&fw_info);

    /* FIX C5: 4. 等待所有 RCU 读者退出 */
    synchronize_rcu();

    /* FIX C5: 5. 现在安全保存状态（无并发访问） */
    if (state_file && strlen(state_file) > 0) {
        save_state_to_file(state_file);
    }

    /* Now it's safe to free all entries since no RCU readers can be accessing them */
    /* Free all ban entries */
    hash_for_each_safe(fw_info.ban_table, ban_hash, tmp, entry, hash) {
        hash_del(&entry->hash);
        kfree(entry);  /* Directly free since no RCU readers can access after synchronize_rcu() */
    }

    /* Free all whitelist entries */
    hash_for_each_safe(fw_info.whitelist_table, wl_hash, tmp, wl, hash) {
        hash_del(&wl->hash);
        kfree(wl);  /* Directly free since no RCU readers can access after synchronize_rcu() */
    }

    /* NOTE: ban_table and whitelist_table are statically allocated via DECLARE_HASHTABLE
     * embedded in struct firewall_info. They are NOT dynamically allocated with kmalloc,
     * so we must NOT call kfree on them. Doing so would cause a kernel OOPS/crash. */

    printk(KERN_INFO "firewall: Module unloaded\n");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative)");
MODULE_VERSION("1.4");
