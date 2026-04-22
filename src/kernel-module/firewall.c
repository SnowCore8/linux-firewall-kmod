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

/* Helper function: Compare IPv4 addresses - simplified for IPv4 only */
static inline bool compare_ips(__be32 ip1, __be32 ip2)
{
    return ip1 == ip2;
}

/* Helper function: Generate hash for IPv4 addresses */
static inline u32 generate_ip_hash(__be32 ip)
{
    return hash_min(ip, BAN_HASH_BITS);
}

/* Helper function: Generate hash for whitelist IPv4 addresses */
static inline u32 generate_wl_ip_hash(__be32 ip)
{
    return hash_min(ip, WHITELIST_HASH_BITS);
}

/*
 * add_whitelist_entry - Add an IPv4 to the whitelist hash table
 * Fixed version: Ensures IP is normalized to network address for proper subnet matching
 * Added validation for IP and mask values
 */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name)
{
    struct whitelist_entry *new_entry;  /* 修复：使用 new_entry 避免被 hash_for_each_possible 覆盖 */
    struct whitelist_entry *tmp_entry;  /* 修复：用于遍历哈希表的临时变量 */
    u32 hash;

    FW_DEBUG(1, "ENTRY: add_whitelist_entry(ip=%pI4, mask=%pI4, dev=%s)", &ip, &mask, dev_name ?: "null");

    /* Validate IP and mask inputs */
    if (!mask) {
        fw_pr_warn("Invalid mask 0x%08x for IP %pI4", mask, &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid mask)");
        return -EINVAL;
    }

    /* Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc. */
    if (ip == 0 || ip == 0xFFFFFFFF ||
        (ntohl(ip) & 0xFF000000) == 0x7F000000 ||  // 127.x.x.x
        (ntohl(ip) & 0xF0000000) == 0xE0000000 ||  // 224.0.0.0/4 (multicast)
        (ntohl(ip) & 0xFF000000) == 0x00000000 ||  // 0.0.0.0/8
        (ntohl(ip) & 0xFF000000) == 0xFF000000) {  // 255.0.0.0/8
        fw_pr_warn("Attempt to whitelist invalid IP: %pI4", &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    __be32 normalized_ip = ip & mask;  // Normalize IP to network address

    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    FW_DEBUG(2, "Attempting to add whitelist entry for %pI4/%d", &normalized_ip, inet_mask_len(mask));

    /* FIX W2: 在锁外分配内存，避免在 spinlock 内睡眠 */
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        FW_DEBUG(1, "Failed to allocate memory for whitelist entry for IP %pI4", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -ENOMEM");
        return -ENOMEM;
    }

    /* 初始化 new_entry 字段 */
    new_entry->ip = normalized_ip;  /* Store normalized IP (network address) */
    new_entry->mask = mask;
    if (dev_name)
        strscpy(new_entry->device_name, dev_name, sizeof(new_entry->device_name));
    else
        new_entry->device_name[0] = '\0';

    spin_lock(&fw->whitelist_lock);

    /* 修复：使用 tmp_entry 遍历，避免覆盖 new_entry 指针 */
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
        kfree(new_entry);  /* 修复：释放 new_entry */
        fw_pr_warn("Whitelist full, cannot add %pI4/%d", &normalized_ip, inet_mask_len(mask));
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -ENOSPC (whitelist full)");
        return -ENOSPC;
    }

    /* 插入哈希表 */
    hash_add(fw->whitelist_table, &new_entry->hash, normalized_ip);  /* 修复：使用 new_entry */
    atomic_inc(&fw->whitelist_count);
    spin_unlock(&fw->whitelist_lock);

    FW_DEBUG(1, "Successfully added whitelist entry for %pI4/%d on %s",
             &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    fw_pr_info("Whitelisted %pI4/%d on %s", &normalized_ip, inet_mask_len(mask), dev_name ?: "unknown");
    FW_DEBUG(1, "EXIT: add_whitelist_entry -> 0 (success)");
    return 0;
}

/*
 * remove_whitelist_entry - Remove an IPv4 from the whitelist hash table
 * Fixed version: Normalizes IP to network address for consistent removal
 */
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip_input)
{
    struct whitelist_entry *entry;
    u32 hash;
    int found = 0;
    __be32 normalized_ip = ip_input;  // For backward compatibility, assume input is already normalized
                               // OR if removing by network address, use as-is

    FW_DEBUG(1, "ENTRY: remove_whitelist_entry(ip=%pI4)", &normalized_ip);

    /* Look for entries by the exact stored IP (which is normalized network address) */
    spin_lock(&fw->whitelist_lock);
    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip) {
        if (compare_ips(entry->ip, normalized_ip)) {
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
        fw_pr_info("Removed %pI4 from whitelist", &normalized_ip);
        FW_DEBUG(1, "EXIT: remove_whitelist_entry -> 0 (success)");
        return 0;
    }

    fw_pr_warn("%pI4 not found in whitelist", &normalized_ip);
    FW_DEBUG(1, "EXIT: remove_whitelist_entry -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * is_in_whitelist - Check if an IPv4 is in the whitelist hash table
 * Fixed version: Properly handles subnet matching by checking all entries in the hash table
 * Since different IPs with different masks could fall in the same hash bucket, we need to
 * check all entries to ensure proper subnet matching.
 */
bool is_in_whitelist(struct firewall_info *fw, __be32 ip)
{
    struct whitelist_entry *entry;
    u32 hash;

    FW_DEBUG(3, "ENTRY: is_in_whitelist(ip=%pI4)", &ip);

    rcu_read_lock();
    /* Check ALL entries in the whitelist table to properly handle subnet matching.
     * NOTE: This is O(n) because different prefix lengths can hash to different buckets.
     * For the common case of /32 entries, we could use hash_for_each_possible_rcu(),
     * but subnets require full traversal. With MAX_WHITELIST_ENTRIES=64, this is acceptable.
     */
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        /* Subnet matching logic: check if IP falls within subnet range */
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

/* Module parameters (non-static, accessible from procfs) */
unsigned int fw_ban_time = DEFAULT_BAN_TIME;
char *state_file = "/var/lib/firewall/state";

module_param(fw_ban_time, uint, 0644);
MODULE_PARM_DESC(fw_ban_time, "Ban duration in seconds (default 600)");
module_param(state_file, charp, 0644);
MODULE_PARM_DESC(state_file, "Path to state file for saving/restoring ban and whitelist entries (default /var/lib/firewall/state)");

/* Global firewall info - made static to prevent external access */
static struct firewall_info fw_info;

/* Export function to provide controlled access to fw_info */
struct firewall_info *get_fw_info(void)
{
    return &fw_info;
}
EXPORT_SYMBOL_GPL(get_fw_info);

/*
 * ban_ip - Add an IPv4 to the ban list
 * Optimized version: Uses rwlock for better concurrency
 */
int ban_ip(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    int ret = 0;
    u32 hash;

    FW_DEBUG(1, "ENTRY: ban_ip(ip=%pI4)", &ip);

    /* Validate IP input */
    if (!ip) {
        fw_pr_err("Invalid IP address for banning: %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Attempting to ban IPv4: %pI4", &ip);

    /* Acquire lock before any checks to eliminate TOCTOU race condition.
     * This ensures whitelist check and ban operation are atomic. */
    spin_lock(&fw->lock);

    /* Check whitelist under lock protection to prevent TOCTOU race.
     * Another thread could add the IP to whitelist between an unlocked
     * check and the actual ban operation. */
    hash_for_each(fw->whitelist_table, hash, wl_entry, hash) {
        if ((ip & wl_entry->mask) == (wl_entry->ip & wl_entry->mask)) {
            spin_unlock(&fw->lock);
            atomic_inc(&fw->whitelist_reject_count);
            fw_pr_warn("REFUSED to ban whitelisted IP %pI4", &ip);
            FW_DEBUG(2, "IP %pI4 is in whitelist, refusing to ban", &ip);
            FW_DEBUG(1, "EXIT: ban_ip -> -EPERM (whitelisted)");
            return -EPERM;
        }
    }

    /* Check if already banned under same lock to ensure consistency */
    hash = hash_min(ip, BAN_HASH_BITS);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            if (time_before(jiffies, entry->unban_time)) {
                /* Still banned - return early */
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "IP %pI4 still banned, returning early", &ip);
                FW_DEBUG(1, "EXIT: ban_ip -> 0 (already banned under lock)");
                return 0;
            } else {
                /* Entry exists but expired - update it */
                entry->ban_time = jiffies;
                entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
                atomic_set(&entry->retry_count, 0);
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "Updated expired ban entry for IP %pI4", &ip);
                FW_DEBUG(1, "EXIT: ban_ip -> 0 (updated expired entry)");
                return 0;
            }
        }
    }

    if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
        spin_unlock(&fw->lock);
        atomic_inc(&fw->ban_table_full_count);
        fw_pr_warn("Ban table full, cannot ban %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip -> -ENOSPC (ban table full)");
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);  /* Use GFP_ATOMIC to avoid sleeping in interrupt context */
    if (!entry) {
        spin_unlock(&fw->lock);
        atomic_inc(&fw->alloc_failure_count);
        fw_pr_err("Failed to allocate memory for ban entry for IP %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip -> -ENOMEM (alloc failed)");
        return -ENOMEM;
    }

    entry->ip = ip;
    entry->ban_time = jiffies;
    /* FIX P1-5: Use READ_ONCE to atomically read fw_ban_time to prevent
     * torn reads when the value is being concurrently updated via procfs. */
    entry->unban_time = jiffies + (unsigned long)READ_ONCE(fw_ban_time) * HZ;
    entry->is_permanent = false;  /* Default to temporary ban */
    atomic_set(&entry->retry_count, 0);

    hash_add(fw->ban_table, &entry->hash, ip);
    atomic_inc(&fw->ban_count);
    atomic_inc(&fw->total_ban_count);

    spin_unlock(&fw->lock);

    FW_DEBUG(1, "Successfully added ban entry for IP %pI4", &ip);
    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding when
     * many IPs are being banned in a short time period. */
    fw_pr_info_ratelimited("IP %pI4 banned for %u seconds", &ip, READ_ONCE(fw_ban_time));
    FW_DEBUG(1, "EXIT: ban_ip -> 0 (success)");
    return ret;
}

/*
 * ban_ip_permanent - Add an IPv4 to the permanent ban list
 * Permanent bans never expire (unban_time = 0)
 */
int ban_ip_permanent(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    u32 hash;

    FW_DEBUG(1, "ENTRY: ban_ip_permanent(ip=%pI4)", &ip);

    /* Validate IP input */
    if (!ip) {
        fw_pr_err("Invalid IP address for permanent banning: %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_permanent -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Attempting to permanently ban IPv4: %pI4", &ip);

    /* Acquire lock before any checks to eliminate TOCTOU race condition. */
    spin_lock(&fw->lock);

    /* Check whitelist under lock protection */
    hash_for_each(fw->whitelist_table, hash, wl_entry, hash) {
        if ((ip & wl_entry->mask) == (wl_entry->ip & wl_entry->mask)) {
            spin_unlock(&fw->lock);
            atomic_inc(&fw->whitelist_reject_count);
            fw_pr_warn("REFUSED to permanently ban whitelisted IP %pI4", &ip);
            FW_DEBUG(2, "IP %pI4 is in whitelist, refusing to ban", &ip);
            FW_DEBUG(1, "EXIT: ban_ip_permanent -> -EPERM (whitelisted)");
            return -EPERM;
        }
    }

    /* Check if already banned under same lock */
    hash = hash_min(ip, BAN_HASH_BITS);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            if (entry->is_permanent || time_before(jiffies, entry->unban_time)) {
                /* Still banned or permanent - return early */
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "IP %pI4 already banned, returning early", &ip);
                FW_DEBUG(1, "EXIT: ban_ip_permanent -> 0 (already banned)");
                return 0;
            } else {
                /* Entry exists but expired - update it to permanent */
                entry->ban_time = jiffies;
                entry->unban_time = 0;  /* Permanent */
                entry->is_permanent = true;
                atomic_set(&entry->retry_count, 0);
                spin_unlock(&fw->lock);
                FW_DEBUG(2, "Updated expired ban entry to permanent for IP %pI4", &ip);
                fw_pr_info("IP %pI4 permanently banned", &ip);
                FW_DEBUG(1, "EXIT: ban_ip_permanent -> 0 (updated to permanent)");
                return 0;
            }
        }
    }

    /* Check ban table capacity - permanent bans also consume entries */
    if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
        spin_unlock(&fw->lock);
        atomic_inc(&fw->ban_table_full_count);
        fw_pr_warn("Ban table full, cannot add permanent ban for %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_permanent -> -ENOSPC (ban table full)");
        return -ENOSPC;
    }

    entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
    if (!entry) {
        spin_unlock(&fw->lock);
        atomic_inc(&fw->alloc_failure_count);
        fw_pr_err("Failed to allocate memory for permanent ban entry for IP %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_permanent -> -ENOMEM (alloc failed)");
        return -ENOMEM;
    }

    entry->ip = ip;
    entry->ban_time = jiffies;
    entry->unban_time = 0;  /* Permanent ban - never expires */
    entry->is_permanent = true;
    atomic_set(&entry->retry_count, 0);

    hash_add(fw->ban_table, &entry->hash, ip);
    atomic_inc(&fw->ban_count);
    atomic_inc(&fw->total_ban_count);

    spin_unlock(&fw->lock);

    FW_DEBUG(1, "Successfully added permanent ban entry for IP %pI4", &ip);
    fw_pr_info("IP %pI4 permanently banned (permanent)", &ip);
    FW_DEBUG(1, "EXIT: ban_ip_permanent -> 0 (success)");
    return 0;
}

/*
 * unban_ip - Remove an IPv4 from the ban list
 * Optimized version: Uses proper locking and memory management
 */
int unban_ip(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int found = 0;
    char ip_str[INET_ADDRSTRLEN];

    FW_DEBUG(1, "ENTRY: unban_ip(ip=%pI4)", &ip);

    ipv4_to_str(ip, ip_str, sizeof(ip_str));

    spin_lock(&fw->lock);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
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
        atomic_inc(&fw->total_unban_count);
        /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
        fw_pr_info_ratelimited("IP %s unbanned", ip_str);
        FW_DEBUG(1, "EXIT: unban_ip -> 0 (success)");
        return 0;
    }
    fw_pr_debug("IP %s not found in ban list", ip_str);
    FW_DEBUG(1, "EXIT: unban_ip -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * unban_permanent_ip - Remove a permanent ban entry
 * Only removes entries marked as permanent
 */
int unban_permanent_ip(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int found = 0;
    char ip_str[INET_ADDRSTRLEN];

    FW_DEBUG(1, "ENTRY: unban_permanent_ip(ip=%pI4)", &ip);

    ipv4_to_str(ip, ip_str, sizeof(ip_str));

    spin_lock(&fw->lock);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            if (entry->is_permanent) {
                hash_del(&entry->hash);
                atomic_dec(&fw->ban_count);
                found = 1;
                call_rcu(&entry->rcu_head, free_ban_entry_rcu);
                FW_DEBUG(2, "Found and removed permanent ban entry for IP %s", ip_str);
            }
            break;
        }
    }
    spin_unlock(&fw->lock);

    if (found) {
        atomic_inc(&fw->total_unban_count);
        fw_pr_info("IP %s permanently unbanned", ip_str);
        FW_DEBUG(1, "EXIT: unban_permanent_ip -> 0 (success)");
        return 0;
    }
    fw_pr_warn("IP %s not found in permanent ban list", ip_str);
    FW_DEBUG(1, "EXIT: unban_permanent_ip -> -ENOENT (not found)");
    return -ENOENT;
}

/*
 * is_banned - Check if an IPv4 is banned
 * Returns: 1 if banned (valid), 0 if not banned or expired
 */
int is_banned(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    unsigned long now = jiffies;
    int found = 0;

    FW_DEBUG(3, "Checking if IPv4 %pI4 is banned", &ip);

    rcu_read_lock();
    hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            /* Check if permanent ban (never expires) */
            if (entry->is_permanent) {
                FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
                found = 1;
            } else if (time_after(now, entry->unban_time)) {
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
 * is_permanently_banned - Check if an IPv4 is permanently banned
 * Returns 1 if permanently banned, 0 otherwise
 */
int is_permanently_banned(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int found = 0;

    FW_DEBUG(3, "Checking if IPv4 %pI4 is permanently banned", &ip);

    rcu_read_lock();
    hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            if (entry->is_permanent) {
                FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
                found = 1;
            }
            break;
        }
    }
    rcu_read_unlock();

    FW_DEBUG(3, "Result for IPv4 %pI4 permanent ban check: %s", &ip, found ? "PERMANENTLY BANNED" : "NOT PERMANENTLY BANNED");
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

    /* Increment cleanup cycle counter */
    atomic_inc(&fw->cleanup_cycles);

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

            /* Skip permanent bans - they never expire */
            if (entry->is_permanent) {
                processed++;
                continue;
            }

            if (time_after(now, entry->unban_time)) {
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
        atomic_add(removed, &fw->cleanup_expired_total);
        FW_DEBUG(1, "Cleaned up %d expired ban entries", removed);
        /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding during mass cleanup */
        fw_pr_info_ratelimited("Cleaned up %d expired ban entries", removed);
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
 * auto_discover_system_ips - Collect IPv4 IPs in RCU, then whitelist outside (FIX: RCU+GFP_KERNEL)
 */
/* Temporary storage structures for auto-discovery (moved to heap to reduce stack usage) */
struct temp_ip_entry {
    __be32 ip;
    __be32 mask;
    char name[16];
};

void auto_discover_system_ips(struct firewall_info *fw)
{
    /* Allocate on heap to avoid large stack frames */
    struct temp_ip_entry *temp_ips;
    int temp_count = 0;

    struct net_device *dev;
    struct in_device *in_dev;
    struct in_ifaddr *ifa;

    FW_DEBUG(1, "ENTRY: auto_discover_system_ips");

    /* Allocate temporary arrays on heap */
    temp_ips = kmalloc_array(64, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!temp_ips) {
        fw_pr_err("Failed to allocate temp_ips");
        FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (alloc temp_ips failed)");
        return;
    }

    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
    fw_pr_info_ratelimited("Auto-discovering system IPs...");

    /* FIX C2: RCU 保护下收集 IPv4 地址
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
                temp_count++;
            }
        }

        if (!(dev->flags & IFF_UP))
            continue;

        /* Collect IPv4 addresses */
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
                temp_count++;
            }
        }
    }
    rcu_read_unlock();

    /* Add IPv4 IPs outside RCU lock (safe for GFP_KERNEL) */
    for (int i = 0; i < temp_count; i++) {
        if (add_whitelist_entry(fw, temp_ips[i].ip, temp_ips[i].mask, temp_ips[i].name) < 0) {
            fw_pr_warn("Failed to add system IPv4 %pI4 to whitelist", &temp_ips[i].ip);
        }
    }

    /* FIX Extra-8: Use net_info_ratelimited to prevent log flooding */
    fw_pr_info_ratelimited("Auto-discovery complete. %d entries", atomic_read(&fw->whitelist_count));

    /* Free temporary arrays */
    kfree(temp_ips);

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
 * ban_list_show - Show current ban list (IPv4 only)
 */
static int ban_list_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct ban_entry *entry;
    u32 hash;
    unsigned long now = jiffies;
    char ip_str[INET_ADDRSTRLEN];
    int count = 0;
    int temporary_count = 0;
    int permanent_count = 0;

    FW_DEBUG(3, "ENTRY: ban_list_show");

    seq_printf(m, "Current banned IPs:\n");
    seq_printf(m, "-------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->ban_table, hash, entry, hash) {
        /* Check if permanent ban (never expires) */
        if (entry->is_permanent) {
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            seq_printf(m, "%-40s (PERMANENT)\n", ip_str);
            permanent_count++;
            count++;
        } else if (!time_after(now, entry->unban_time)) {
            /* Temporary ban - check expiration */
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            seq_printf(m, "%-40s (expires in %lus)\n",
                       ip_str,
                       (entry->unban_time - now) / HZ);
            temporary_count++;
            count++;
        }
    }
    rcu_read_unlock();

    seq_printf(m, "-------------------\n");
    seq_printf(m, "Total: %d active bans (%d permanent, %d temporary)\n",
               count, permanent_count, temporary_count);
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

/* Forward declarations for permanent ban procfs handlers */
static ssize_t permanent_add_ban_write(struct file *file, const char __user *buf,
                                        size_t count, loff_t *ppos);
static ssize_t permanent_remove_ban_write(struct file *file, const char __user *buf,
                                           size_t count, loff_t *ppos);

static const struct proc_ops permanent_add_fops = {
    .proc_write = permanent_add_ban_write,
    .proc_lseek = default_llseek,
};

static const struct proc_ops permanent_remove_fops = {
    .proc_write = permanent_remove_ban_write,
    .proc_lseek = default_llseek,
};

/*
 * add_ban_write - Procfs write handler for banning IPs (IPv4 only)
 */
static ssize_t add_ban_write(struct file *file, const char __user *buf,
                              size_t count, loff_t *ppos)
{
    char ip_str[INET_ADDRSTRLEN + 2];
    __be32 ipv4;
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

    /* Check if it's a valid IPv4 address */
    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        /* Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc. */
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  /* 0.0.0.0/8 */
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  /* 255.0.0.0/8 */
            fw_pr_warn("Attempt to ban invalid IPv4: %s", ip_str);
            return -EINVAL;
        }

        /* Additional validation: reject Class E (reserved for future use) but allow some valid single addresses */
        /* Class E is 240.0.0.0/4 (240.0.0.0 - 255.255.255.255) */
        /* However, 254.255.255.255 is a valid unicast address that should be banned */
        /* Only reject addresses in the 240.0.0.0/4 range except 254.255.255.255 */
        unsigned int ip_num = ntohl(ipv4);
        if ((ip_num >= 0xF0000000 && ip_num < 0xFE000000) || ip_num == 0xFFFFFFFF) {
            /* Reject 240.0.0.0 - 253.255.255.255 (true Class E reserved) */
            /* But allow 254.0.0.0 - 254.255.255.255 and 255.0.0.0 (with other checks) */
            fw_pr_warn("Attempt to ban reserved IPv4 Class E: %s", ip_str);
            return -EINVAL;
        }

        /* Additional validation: check for private/reserved IP ranges that shouldn't be banned in typical scenarios */
        /* This adds an extra layer of protection against accidental misconfiguration */
        unsigned int ip_class_a = (ntohl(ipv4) >> 24) & 0xFF;
        unsigned int ip_class_b = (ntohl(ipv4) >> 16) & 0xFF;

        /* Check for RFC 1918 private networks (should these really be banned?) */
        if ((ip_class_a == 10) ||  /* 10.0.0.0/8 */
            (ip_class_a == 172 && ip_class_b >= 16 && ip_class_b <= 31) ||  /* 172.16.0.0/12 */
            (ip_class_a == 192 && ip_class_b == 168)) {  /* 192.168.0.0/16 */
            fw_pr_warn("Attempt to ban private IPv4 range %pI4 - this may be unintended", &ipv4);
        }

        /* Check flood protection */
        if (check_flood_protection() < 0) {
            fw_pr_warn("Flood protection triggered - too many ban requests");
            return -EBUSY;
        }

        int result = ban_ip(&fw_info, ipv4);
        if (result < 0) {
            if (result == -EPERM) {
                fw_pr_info("Requested IPv4 %s is in whitelist, not banned", ip_str);
            } else if (result == -ENOMEM) {
                fw_pr_err("Failed to allocate memory for ban entry for IPv4 %s", ip_str);
            } else if (result == -ENOSPC) {
                fw_pr_warn("Ban table full, cannot ban IPv4 %s", ip_str);
            } else {
                fw_pr_err("Unknown error %d when trying to ban IPv4 %s", result, ip_str);
            }
            FW_DEBUG(1, "EXIT: add_ban_write -> %d (ban_ip failed)", result);
            return result;
        }
    }
    else {
        fw_pr_warn("Invalid IP address format: %s", ip_str);
        FW_DEBUG(1, "EXIT: add_ban_write -> -EINVAL (invalid IP format)");
        return -EINVAL;
    }

    FW_DEBUG(1, "EXIT: add_ban_write -> %zu (success)", count);
    return count;
}

/*
 * permanent_add_ban_write - Add a permanent ban via procfs
 * Permanent bans never expire and persist across module reloads (via SQLite in daemon)
 */
static ssize_t permanent_add_ban_write(struct file *file, const char __user *buf,
                                        size_t count, loff_t *ppos)
{
    char ip_str[INET_ADDRSTRLEN + 2];
    __be32 ipv4;
    ssize_t len;

    FW_DEBUG(2, "ENTRY: permanent_add_ban_write(count=%zu)", count);

    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: permanent_add_ban_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: permanent_add_ban_write -> 0 (empty input)");
        return 0;
    }
    if (count > sizeof(ip_str) - 1) {
        FW_DEBUG(1, "EXIT: permanent_add_ban_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(ip_str) - 1));

    if (copy_from_user(ip_str, buf, len)) {
        FW_DEBUG(1, "EXIT: permanent_add_ban_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    ip_str[len] = '\0';
    if (len > 0 && ip_str[len - 1] == '\n')
        ip_str[len - 1] = '\0';

    if (strnlen(ip_str, sizeof(ip_str)) >= sizeof(ip_str)) {
        FW_DEBUG(1, "EXIT: permanent_add_ban_write -> -EINVAL (not null-terminated)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Processing permanent ban request for IP: %s", ip_str);

    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {
            fw_pr_warn("Attempt to permanently ban invalid IPv4: %s", ip_str);
            return -EINVAL;
        }

        unsigned int ip_num = ntohl(ipv4);
        if ((ip_num >= 0xF0000000 && ip_num < 0xFE000000) || ip_num == 0xFFFFFFFF) {
            fw_pr_warn("Attempt to permanently ban reserved IPv4 Class E: %s", ip_str);
            return -EINVAL;
        }

        /* Permanent bans bypass flood protection */
        /* No flood protection check for permanent bans */

        int result = ban_ip_permanent(&fw_info, ipv4);
        if (result < 0) {
            if (result == -EPERM) {
                fw_pr_info("Requested IPv4 %s is in whitelist, not permanently banned", ip_str);
            } else if (result == -ENOMEM) {
                fw_pr_err("Failed to allocate memory for permanent ban entry for IPv4 %s", ip_str);
            } else if (result == -ENOSPC) {
                fw_pr_warn("Ban table full, cannot permanently ban IPv4 %s", ip_str);
            } else {
                fw_pr_err("Unknown error %d when trying to permanently ban IPv4 %s", result, ip_str);
            }
            FW_DEBUG(1, "EXIT: permanent_add_ban_write -> %d (ban_ip_permanent failed)", result);
            return result;
        }
    } else {
        fw_pr_warn("Invalid IP address format for permanent ban: %s", ip_str);
        FW_DEBUG(1, "EXIT: permanent_add_ban_write -> -EINVAL (invalid IP format)");
        return -EINVAL;
    }

    FW_DEBUG(1, "EXIT: permanent_add_ban_write -> %zu (success)", count);
    return count;
}

/*
 * permanent_remove_ban_write - Remove a permanent ban via procfs
 */
static ssize_t permanent_remove_ban_write(struct file *file, const char __user *buf,
                                           size_t count, loff_t *ppos)
{
    char ip_str[INET_ADDRSTRLEN + 2];
    __be32 ipv4;
    ssize_t len;

    FW_DEBUG(2, "ENTRY: permanent_remove_ban_write(count=%zu)", count);

    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: permanent_remove_ban_write -> 0 (empty input)");
        return 0;
    }
    if (count > sizeof(ip_str) - 1) {
        FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(ip_str) - 1));

    if (copy_from_user(ip_str, buf, len)) {
        FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    ip_str[len] = '\0';
    if (len > 0 && ip_str[len - 1] == '\n')
        ip_str[len - 1] = '\0';

    if (strnlen(ip_str, sizeof(ip_str)) >= sizeof(ip_str)) {
        FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> -EINVAL (not null-terminated)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Processing permanent unban request for IP: %s", ip_str);

    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        int result = unban_permanent_ip(&fw_info, ipv4);
        if (result < 0) {
            if (result == -ENOENT) {
                fw_pr_warn("IP %s not found in permanent ban list", ip_str);
            } else {
                fw_pr_err("Failed to remove permanent ban for IP %s (error %d)", ip_str, result);
            }
            FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> %d (unban_permanent_ip failed)", result);
            return result;
        }
    } else {
        fw_pr_warn("Invalid IP address format for permanent unban: %s", ip_str);
        FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> -EINVAL (invalid IP format)");
        return -EINVAL;
    }

    FW_DEBUG(1, "EXIT: permanent_remove_ban_write -> %zu (success)", count);
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
 * remove_ban_write - Procfs write handler for unbanning IPs (IPv4 only)
 */
static ssize_t remove_ban_write(struct file *file, const char __user *buf,
                                 size_t count, loff_t *ppos)
{
    char ip_str[INET_ADDRSTRLEN + 2];
    __be32 ipv4;
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

    /* Check if it's a valid IPv4 address */
    if (in4_pton(ip_str, -1, (u8 *)&ipv4, -1, NULL)) {
        /* Additional validation: reject invalid IPs like 0.0.0.0, 255.255.255.255, multicast, etc. */
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  /* 0.0.0.0/8 */
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  /* 255.0.0.0/8 */
            fw_pr_warn("Attempt to unban invalid IPv4: %s", ip_str);
            return -EINVAL;
        }

        if (unban_ip(&fw_info, ipv4) < 0)
            return -ENOENT;
    }
    else {
        fw_pr_warn("Invalid IP address format: %s", ip_str);
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
 * whitelist_show - Procfs show handler for whitelist hash table (IPv4 only)
 */
static int whitelist_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct whitelist_entry *entry;
    u32 hash;
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;

    seq_printf(m, "Whitelisted IPs (protected from ban):\n");
    seq_printf(m, "--------------------------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        /* For subnets, we need to display the network address */
        __be32 network_addr = entry->ip & entry->mask;
        ipv4_to_str(network_addr, ip_str, sizeof(ip_str));
        prefix_len = inet_mask_len(entry->mask);
        seq_printf(m, "%s/%d  on %s\n",
                   ip_str,
                   prefix_len,
                   entry->device_name);
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
 * whitelist_add_write - Add IP to whitelist (IPv4 only)
 */
static ssize_t whitelist_add_write(struct file *file, const char __user *buf,
                                    size_t count, loff_t *ppos)
{
    char input[INET_ADDRSTRLEN + 8];
    ssize_t len = min(count, (size_t)(sizeof(input) - 1));
    __be32 ipv4, mask4;
    int prefix_len = 32;

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

    /* Check if it's a valid IPv4 address */
    if (in4_pton(input, -1, (u8 *)&ipv4, -1, NULL)) {
        if (prefix_len < 0 || prefix_len > 32)
            return -EINVAL;

        /* Additional validation: reject invalid IPs */
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  /* 0.0.0.0/8 */
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  /* 255.0.0.0/8 */
            fw_pr_warn("Attempt to whitelist invalid IPv4: %s", input);
            return -EINVAL;
        }

        /* Calculate network mask based on prefix length */
        mask4 = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));
        __be32 normalized_ip = ipv4 & mask4;

        if (add_whitelist_entry(&fw_info, normalized_ip, mask4, "manual") < 0)
            return -ENOSPC;
    }
    else {
        fw_pr_warn("Invalid IP address format: %s", input);
        return -EINVAL;
    }

    return count;
}

/*
 * whitelist_remove_write - Remove IP from whitelist (IPv4 only)
 * Fixed version: Handles both individual IPs and subnets correctly by normalizing to network address
 */
static ssize_t whitelist_remove_write(struct file *file, const char __user *buf,
                                       size_t count, loff_t *ppos)
{
    char input[INET_ADDRSTRLEN + 8];
    ssize_t len = min(count, (size_t)(sizeof(input) - 1));
    __be32 ipv4, mask4 = 0xFFFFFFFF;  /* Default to /32 (single IP) */
    int prefix_len = 32;

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

    /* Check if it's a valid IPv4 address */
    if (in4_pton(input, -1, (u8 *)&ipv4, -1, NULL)) {
        if (prefix_len < 0 || prefix_len > 32)
            return -EINVAL;

        /* Calculate network mask based on prefix length */
        mask4 = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));

        /* Additional validation: reject invalid IPs */
        if (ipv4 == 0 || ipv4 == 0xFFFFFFFF ||
            (ntohl(ipv4) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
            (ntohl(ipv4) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
            (ntohl(ipv4) & 0xFF000000) == 0x00000000 ||  /* 0.0.0.0/8 */
            (ntohl(ipv4) & 0xFF000000) == 0xFF000000) {  /* 255.0.0.0/8 */
            fw_pr_warn("Attempt to remove invalid IPv4 from whitelist: %s", input);
            return -EINVAL;
        }

        /* Normalize the IP to the network address for removal */
        __be32 normalized_ip = ipv4 & mask4;

        if (remove_whitelist_entry(&fw_info, normalized_ip) < 0)
            return -ENOENT;
    }
    else {
        fw_pr_warn("Invalid IP address format: %s", input);
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
    char *value_str;
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

    /* Use strsep for more robust parameter parsing */
    char *input_ptr = input;
    char *token;

    token = strsep(&input_ptr, " \t");
    if (!token || strlen(token) == 0 || strlen(token) >= sizeof(param)) {
        fw_pr_err("Invalid config format. Use: param value");
        return -EINVAL;
    }
    strncpy(param, token, sizeof(param) - 1);
    param[sizeof(param) - 1] = '\0';

    value_str = input_ptr;
    if (!value_str || strlen(value_str) == 0) {
        fw_pr_err("Missing value for parameter: %s", param);
        return -EINVAL;
    }

    /* Parse value using modern kstrtoul for better error handling */
    unsigned long val;
    int rc = kstrtoul(value_str, 10, &val);
    if (rc != 0 || val == 0 || val > UINT_MAX) {
        fw_pr_err("Invalid value: %s", value_str);
        return -EINVAL;
    }
    value = (unsigned int)val;

    if (strcmp(param, "ban_time") == 0) {
        if (value < 1 || value > 365 * 24 * 60 * 60) {  /* 1 year max */
            fw_pr_err("ban_time must be between 1 and %d seconds", 365 * 24 * 60 * 60);
            return -EINVAL;
        }
        /* FIX P1-5: Use WRITE_ONCE to atomically write fw_ban_time to prevent
         * torn writes when the value is being concurrently updated via procfs. */
        WRITE_ONCE(fw_ban_time, value);
        fw_pr_info("ban_time updated to %u seconds", value);
    } else {
        fw_pr_err("Unknown parameter: %s", param);
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
 * stats_show - Show firewall statistics
 */
static int stats_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;

    seq_printf(m, "total_bans %u\n", atomic_read(&fw->total_ban_count));
    seq_printf(m, "total_unbans %u\n", atomic_read(&fw->total_unban_count));
    seq_printf(m, "whitelist_rejects %u\n", atomic_read(&fw->whitelist_reject_count));
    seq_printf(m, "ban_table_full_rejects %u\n", atomic_read(&fw->ban_table_full_count));
    seq_printf(m, "alloc_failures %u\n", atomic_read(&fw->alloc_failure_count));
    seq_printf(m, "packets_dropped %u\n", atomic_read(&fw->packets_dropped));
    seq_printf(m, "packets_accepted %u\n", atomic_read(&fw->packets_accepted));
    seq_printf(m, "cleanup_cycles %u\n", atomic_read(&fw->cleanup_cycles));
    seq_printf(m, "cleanup_expired_total %u\n", atomic_read(&fw->cleanup_expired_total));
    seq_printf(m, "current_bans %d\n", atomic_read(&fw->ban_count));
    seq_printf(m, "current_whitelist %d\n", atomic_read(&fw->whitelist_count));
    seq_printf(m, "recent_additions %u\n", fw->recent_additions);

    return 0;
}

static int stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, stats_show, NULL);
}

static const struct proc_ops stats_fops = {
    .proc_open = stats_open,
    .proc_read = seq_read,
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
        fw_pr_err("Failed to create /proc/firewall");
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

    entry = proc_create("permanent_add_ban", 0200, fw->proc_dir, &permanent_add_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_permanent_add = entry;

    entry = proc_create("permanent_remove_ban", 0200, fw->proc_dir, &permanent_remove_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_permanent_remove = entry;

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

    entry = proc_create("stats", 0400, fw->proc_dir, &stats_fops);
    if (!entry) {
        fw_pr_err("Failed to create proc stats entry\n");
        goto err_cleanup;
    }
    fw->proc_stats = entry;

    fw_pr_info("Procfs entries created");
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
    if (fw->proc_stats)
        proc_remove(fw->proc_stats);
    if (fw->proc_config)
        proc_remove(fw->proc_config);
    if (fw->proc_permanent_remove)
        proc_remove(fw->proc_permanent_remove);
    if (fw->proc_permanent_add)
        proc_remove(fw->proc_permanent_add);
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
    if (ntohs(iph->frag_off) & htons(0x2000) || (ntohs(iph->frag_off) & 0x1FFF) != 0) {
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
                fw_pr_warn_ratelimited("whitelist traversal limit reached, possible misconfiguration");
                break;
            }
            if ((src_ip & wl_entry->mask) == (wl_entry->ip & wl_entry->mask)) {
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
        if (compare_ips(entry->ip, src_ip)) {
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

    if (unlikely(is_banned)) {
        atomic_inc(&fw_info.packets_dropped);
        return NF_DROP;
    }

    atomic_inc(&fw_info.packets_accepted);
    return NF_ACCEPT;
}

static struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook = nf_hook_func_ipv4,
    .pf = NFPROTO_IPV4,
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
        char ip_str[INET_ADDRSTRLEN];
        __be32 ipv4;
        unsigned long remaining_time;
    };

    struct saved_whitelist_entry {
        char ip_str[INET_ADDRSTRLEN];
        __be32 ipv4;
        __be32 mask;
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
    /* Variables for TOCTOU protection - declared at function scope */
    dev_t saved_dev = 0;
    ino_t saved_ino = 0;
    bool file_checked = false;

    if (!filename || !*filename) {
        fw_pr_err("Invalid filename for state save");
        return -EINVAL;
    }

    /* Security validation: Check for directory traversal in filename */
    if (strstr(filename, "../") || strstr(filename, "/..")) {
        fw_pr_err("Potential directory traversal in filename: %s", filename);
        return -EINVAL;
    }

    /* Security validation: Ensure the filename starts with a safe path */
    if (strncmp(filename, "/var/lib/", 9) != 0 &&
        strncmp(filename, "/tmp/", 5) != 0 &&
        strncmp(filename, "/etc/", 5) != 0) {
        fw_pr_warn("State file path outside allowed directories: %s", filename);
        /* Only allow saving to safe directories */
        if (strchr(filename, '/') && filename[0] != '/') {
            fw_pr_err("Relative path not allowed for state file: %s", filename);
            return -EINVAL;
        }
    }

    /* Additional security: Check if the file exists and is a symlink */
    struct path path;
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
            fw_pr_warn_ratelimited("Cannot stat file %s, proceeding anyway", filename);
            goto out_path_put;
        }
        /* Check if it's a symbolic link */
        if (S_ISLNK(stat_buf2.mode)) {
            fw_pr_err("Refusing to write to symbolic link: %s", filename);
            err = -EACCES;
            goto out_path_put;
        }
        /* Check if it's a directory */
        if (S_ISDIR(stat_buf2.mode)) {
            fw_pr_err("Refusing to write to directory: %s", filename);
            err = -EISDIR;
            goto out_path_put;
        }
        /* Store inode/dev for consistency check later - assign to outer scope vars */
        saved_dev = stat_buf2.dev;
        saved_ino = stat_buf2.ino;
        file_checked = true;
out_path_put:
        path_put(&path);
    } else {
        /* File doesn't exist, which is fine for creation */
        err = 0;
    }

    /* 阶段1: 分配临时数组（GFP_KERNEL 可以睡眠，安全） */
    ban_entries = kmalloc_array(MAX_SAVE_BAN, sizeof(struct saved_ban_entry), GFP_KERNEL);
    if (!ban_entries) {
        fw_pr_err("Failed to allocate memory for saving ban entries");
        return -ENOMEM;
    }

    wl_entries = kmalloc_array(MAX_SAVE_WL, sizeof(struct saved_whitelist_entry), GFP_KERNEL);
    if (!wl_entries) {
        kfree(ban_entries);
        fw_pr_err("Failed to allocate memory for saving whitelist entries");
        return -ENOMEM;
    }

    /* 阶段2: RCU 锁内收集 ban 条目 */
    rcu_read_lock();
    hash_for_each_rcu(fw_info.ban_table, hash, entry, hash) {
        unsigned long remaining_time = (entry->unban_time - jiffies) / HZ;
        if (remaining_time > 0 && ban_count < MAX_SAVE_BAN) {
            ipv4_to_str(entry->ip, ban_entries[ban_count].ip_str, sizeof(ban_entries[ban_count].ip_str));
            ban_entries[ban_count].ipv4 = entry->ip;
            ban_entries[ban_count].remaining_time = remaining_time;
            ban_count++;
        }
    }
    rcu_read_unlock();

    /* 阶段3: RCU 锁内收集 whitelist 条目 */
    rcu_read_lock();
    hash_for_each_rcu(fw_info.whitelist_table, hash, wl_entry, hash) {
        if (wl_count < MAX_SAVE_WL) {
            __be32 network_addr = wl_entry->ip & wl_entry->mask;
            ipv4_to_str(network_addr, wl_entries[wl_count].ip_str, sizeof(wl_entries[wl_count].ip_str));
            wl_entries[wl_count].ipv4 = wl_entry->ip;
            wl_entries[wl_count].mask = wl_entry->mask;
            wl_entries[wl_count].prefix_len = inet_mask_len(wl_entry->mask);
            strscpy(wl_entries[wl_count].device_name, wl_entry->device_name, sizeof(wl_entries[wl_count].device_name));
            wl_count++;
        }
    }
    rcu_read_unlock();

    /* 阶段4: 锁外打开文件（使用 O_NOFOLLOW 防止符号链接攻击） */
    file = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (IS_ERR(file)) {
        fw_pr_err("Failed to open file for saving state: %s", filename);
        kfree(ban_entries);
        kfree(wl_entries);
        return PTR_ERR(file);
    }

    /* Inode consistency check: verify opened file matches the one we checked */
    {
        struct kstat open_stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        int getattr_err = vfs_getattr(&file->f_path, &open_stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#else
        int getattr_err = vfs_getattr(&file->f_path, &open_stat);
#endif
        if (!getattr_err && file_checked) {
            if (open_stat.ino != saved_ino || open_stat.dev != saved_dev) {
                fw_pr_err("File inode changed between check and open (TOCTOU): %s", filename);
                filp_close(file, NULL);
                kfree(ban_entries);
                kfree(wl_entries);
                return -EACCES;
            }
        }
    }

    /* 阶段5: 锁外写入 ban 条目 */
    for (int i = 0; i < ban_count; i++) {
        written = snprintf(buffer, sizeof(buffer), "BAN_V4 %s %lu\n",
                         ban_entries[i].ip_str, ban_entries[i].remaining_time);

        if (kernel_write(file, buffer, written, &pos) != written) {
            fw_pr_err("Failed to write ban entry to state file");
            filp_close(file, NULL);
            kfree(ban_entries);
            kfree(wl_entries);
            return -EIO;
        }
    }

    /* 阶段6: 锁外写入 whitelist 条目 */
    for (int i = 0; i < wl_count; i++) {
        written = snprintf(buffer, sizeof(buffer), "WL_V4 %s %d %s\n",
                          wl_entries[i].ip_str, wl_entries[i].prefix_len, wl_entries[i].device_name);

        if (kernel_write(file, buffer, written, &pos) != written) {
            fw_pr_err("Failed to write whitelist entry to state file");
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

    fw_pr_info("State saved to %s (ban: %d, wl: %d)", filename, ban_count, wl_count);
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
        fw_pr_err("Invalid filename for state restore");
        return -EINVAL;
    }

    /* Allocate buffer on heap to avoid large stack frame */
    buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buffer) {
        fw_pr_err("Failed to allocate buffer for state restore");
        return -ENOMEM;
    }

    /* Open file for reading */
    file = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(file)) {
        fw_pr_info("State file does not exist: %s", filename);
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
                        if (is_in_whitelist(&fw_info, ip)) {
                            fw_pr_info("Skipping restored ban for whitelisted IP %s", ip_str);
                            continue;
                        }

                        unsigned long remaining_time;
                        if (kstrtoul(time_str, 10, &remaining_time) == 0) {
                            /* FIX C4: 验证 remaining_time 合理性：不能超过 1 年，不能为 0 */
                            if (remaining_time == 0 || remaining_time > 365UL * 24 * 60 * 60) {
                                fw_pr_warn("Skipping ban with invalid remaining time: %lu", remaining_time);
                                continue;
                            }

                            /* FIX C4: 检查整数溢出：remaining_time * HZ 不能溢出 */
                            if (remaining_time > (ULONG_MAX / HZ)) {
                                fw_pr_warn("Skipping ban - remaining_time * HZ would overflow");
                                continue;
                            }

                            unsigned long ban_duration = remaining_time * HZ;

                            /* FIX C4: 检查 jiffies + ban_duration 是否会溢出回绕 */
                            unsigned long unban_time;
                            if (jiffies > ULONG_MAX - ban_duration) {
                                /* jiffies 即将回绕，使用最大安全值 */
                                unban_time = jiffies + min(ban_duration, ULONG_MAX - jiffies);
                                fw_pr_warn("Jiffies wrap protection applied for ban restoration");
                            } else {
                                unban_time = jiffies + ban_duration;
                            }

                            /* Add ban entry with calculated unban time */
                            struct ban_entry *entry;

                            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                            if (!entry) {
                                fw_pr_err("Failed to allocate memory for restored ban entry");
                                continue;
                            }

                            entry->ip = ip;
                            entry->ban_time = jiffies;
                            entry->unban_time = unban_time;
                            atomic_set(&entry->retry_count, 0);

                            spin_lock(&fw_info.lock);
                            hash_add(fw_info.ban_table, &entry->hash, ip);
                            atomic_inc(&fw_info.ban_count);
                            spin_unlock(&fw_info.lock);

                            fw_pr_info("Restored ban for IPv4 %s (expires in %lu seconds)", ip_str, remaining_time);
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
                            int result = add_whitelist_entry(&fw_info, normalized_ip, mask,
                                                                dev_name ? dev_name : "restored");
                            if (result == 0) {
                                fw_pr_info("Restored whitelist entry for IPv4 %s/%d", ip_str, prefix_len);
                            }
                        }
                    }
                }
            }
        }
    }

    filp_close(file, NULL);
    kfree(buffer);
    fw_pr_info("State restored from %s", filename);
    return 0;
}

/*
 * firewall_init - Module initialization
 */
static int __init firewall_init(void)
{
    int ret;

    fw_pr_info("Loading firewall module v1.4");

    /* 参数下界检查 - 防止 0 或过小值导致异常行为 */
    /* FIX P1-5: Use READ_ONCE for atomic access to module parameters */
    if (READ_ONCE(fw_ban_time) < 1) {
        fw_pr_err("fw_ban_time must be >= 1");
        return -EINVAL;
    }

    /* 参数上界检查 - 防止过大的值导致整数溢出 */
    if (READ_ONCE(fw_ban_time) > 365 * 24 * 60 * 60) {  /* 1 year max */
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

    /* Initialize statistics counters */
    atomic_set(&fw_info.total_ban_count, 0);
    atomic_set(&fw_info.total_unban_count, 0);
    atomic_set(&fw_info.whitelist_reject_count, 0);
    atomic_set(&fw_info.ban_table_full_count, 0);
    atomic_set(&fw_info.alloc_failure_count, 0);
    atomic_set(&fw_info.packets_dropped, 0);
    atomic_set(&fw_info.packets_accepted, 0);
    atomic_set(&fw_info.cleanup_cycles, 0);
    atomic_set(&fw_info.cleanup_expired_total, 0);

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
        fw_pr_err("Failed to register IPv4 netfilter hook: %d", ret);
        goto err_procfs;
    }

    fw_pr_info("Module loaded successfully (ban_time=%u, state_file=%s)", fw_ban_time, state_file);
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

    fw_pr_info("Unloading firewall module");

    /* FIX C5: 设置关闭标志，阻止新操作 */
    atomic_set(&fw_info.shutting_down, 1);

    /* FIX C5: 1. 先注销 netfilter hooks，阻止新包进入 */
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

    fw_pr_info("Module unloaded");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative)");
MODULE_VERSION("1.6");
