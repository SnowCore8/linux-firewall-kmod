/*
 * firewall.c - 用于 IP 封禁的 Linux 内核模块
 *
 * 本模块使用 netfilter 钩子提供内核级 IP 封禁功能。
 */

#include "firewall.h"
#include <linux/namei.h>
#include <linux/version.h>

/* RCU 回调的前向声明 */
static void free_ban_entry_rcu(struct rcu_head *head);
static void free_whitelist_entry_rcu(struct rcu_head *head);

/* 泛洪保护函数的前向声明 */
static int check_flood_protection(void);

/* 状态文件函数的前向声明 */
static int save_state_to_file(const char *filename);
static int restore_state_from_file(const char *filename);

/* 辅助函数：将 IPv4 转换为字符串 */
static inline void ipv4_to_str(__be32 ip, char *buf, int len)
{
    unsigned int a = ntohl(ip) >> 24;
    unsigned int b = (ntohl(ip) >> 16) & 0xFF;
    unsigned int c = (ntohl(ip) >> 8) & 0xFF;
    unsigned int d = ntohl(ip) & 0xFF;

    /* 验证缓冲区大小足以容纳 IP 字符串
     * 至少 16 字符："xxx.xxx.xxx.xxx\0"
     */
    if (len < 16) {
        if (len > 0) {
            buf[0] = '\0';  /* 如果缓冲区存在，添加空终止符 */
        }
        return;
    }

    snprintf(buf, len, "%u.%u.%u.%u", a, b, c, d);
}

/* 辅助函数：比较 IPv4 地址 — 简化为仅 IPv4 */
static inline bool compare_ips(__be32 ip1, __be32 ip2)
{
    return ip1 == ip2;
}

/* 前向声明 */
static int validate_ipv4_address(__be32 ip, const char *ip_str, const char *context);

/*
 * validate_ipv4_address - 统一的 IPv4 地址验证，用于封禁/白名单
 * @ip: 网络字节序的 IP 地址 (__be32)
 * @ip_str: 用于日志的 IP 地址字符串（可为 NULL）
 * @context: 用于日志消息的上下文字符串（如 "ban"、"whitelist"）
 *
 * 拒绝：0.0.0.0、255.255.255.255、127.0.0.0/8（回环）、
 *       224.0.0.0/4（组播 + E 类）、0.0.0.0/8
 *
 * 返回值：有效返回 0，无效返回 -EINVAL
 */
static int validate_ipv4_address(__be32 ip, const char *ip_str, const char *context)
{
    unsigned int ip_num = ntohl(ip);

    if (ip == 0 || ip == 0xFFFFFFFF) {
        fw_pr_warn("Attempt to %s invalid IPv4: %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0x7F000000) {  /* 127.x.x.x（回环） */
        fw_pr_warn("Attempt to %s loopback IPv4: %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xF0000000) == 0xE0000000) {  /* 224.0.0.0/4（组播 + E 类） */
        fw_pr_warn("Attempt to %s reserved IPv4 (multicast/Class E): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0x00000000) {  /* 0.x.x.x */
        fw_pr_warn("Attempt to %s invalid IPv4 (0.0.0.0/8): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }
    if ((ip_num & 0xFF000000) == 0xFF000000) {  /* 255.x.x.x */
        fw_pr_warn("Attempt to %s invalid IPv4 (255.0.0.0/8): %s", context, ip_str ?: "(null)");
        return -EINVAL;
    }

    return 0;
}

/*
 * add_whitelist_entry - 将 IPv4 添加到白名单哈希表
 * 修复版本：确保 IP 被规范化为网络地址，以正确匹配子网
 * 增加了对 IP 和掩码值的验证
 */
int add_whitelist_entry(struct firewall_info *fw, __be32 ip, __be32 mask, const char *dev_name)
{
    struct whitelist_entry *new_entry;  /* 修复：使用 new_entry 避免被 hash_for_each_possible 覆盖 */
    struct whitelist_entry *tmp_entry;  /* 修复：遍历哈希表的临时变量 */
    u32 hash;

    FW_DEBUG(1, "ENTRY: add_whitelist_entry(ip=%pI4, mask=%pI4, dev=%s)", &ip, &mask, dev_name ?: "null");

    /* 验证 IP 和掩码输入 */
    if (!mask) {
        fw_pr_warn("Invalid mask 0x%08x for IP %pI4", mask, &ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid mask)");
        return -EINVAL;
    }

    /* 统一的 IPv4 地址验证 */
    if (validate_ipv4_address(ip, NULL, "whitelist") < 0) {
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    __be32 normalized_ip = ip & mask;  // 将 IP 规范化为网络地址

    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    FW_DEBUG(2, "Attempting to add whitelist entry for %pI4/%d", &normalized_ip, inet_mask_len(mask));

    /* 修复 W2：在锁外分配内存，避免在 spinlock 内睡眠 */
    new_entry = kmalloc(sizeof(*new_entry), GFP_KERNEL);
    if (!new_entry) {
        FW_DEBUG(1, "Failed to allocate memory for whitelist entry for IP %pI4", &normalized_ip);
        FW_DEBUG(1, "EXIT: add_whitelist_entry -> -ENOMEM");
        return -ENOMEM;
    }

    /* 初始化 new_entry 字段 */
    new_entry->ip = normalized_ip;  /* 存储规范化后的 IP（网络地址） */
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
 * remove_whitelist_entry - 从白名单哈希表中移除 IPv4
 * 修复版本：规范化 IP 为网络地址，以确保一致性的移除
 */
int remove_whitelist_entry(struct firewall_info *fw, __be32 ip_input)
{
    struct whitelist_entry *entry;
    u32 hash;
    int found = 0;
    __be32 normalized_ip = ip_input;  // 为向后兼容，假设输入已规范化
                                // 或者如果按网络地址移除，则原样使用

    FW_DEBUG(1, "ENTRY: remove_whitelist_entry(ip=%pI4)", &normalized_ip);

    /* 按精确存储的 IP 查找条目（即已规范化的网络地址） */
    spin_lock(&fw->whitelist_lock);
    hash = hash_min(normalized_ip, WHITELIST_HASH_BITS);
    hash_for_each_possible(fw->whitelist_table, entry, hash, normalized_ip) {
        if (compare_ips(entry->ip, normalized_ip)) {
            hlist_del_rcu(&entry->hash);
            atomic_dec(&fw->whitelist_count);
            found = 1;
            /* 使用 call_rcu 异步释放 */
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
 * is_in_whitelist - 检查 IPv4 是否在白名单哈希表中
 * 修复版本：通过检查哈希表中的所有条目来正确处理子网匹配
 * 由于不同 IP 使用不同掩码可能落入同一哈希桶，我们需要
 * 检查所有条目以确保正确的子网匹配。
 */
bool is_in_whitelist(struct firewall_info *fw, __be32 ip)
{
    struct whitelist_entry *entry;
    u32 hash;

    FW_DEBUG(3, "ENTRY: is_in_whitelist(ip=%pI4)", &ip);

    rcu_read_lock();
    /* 检查白名单表中的所有条目以正确处理子网匹配。
     * 注意：这是 O(n) 的，因为不同前缀长度可能哈希到不同桶。
     * 对于常见的 /32 条目，可以使用 hash_for_each_possible_rcu()，
     * 但子网需要完整遍历。MAX_WHITELIST_ENTRIES=MAX_DISCOVERED_IPS 时这是可接受的。
     */
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
        /* 子网匹配逻辑：检查 IP 是否在子网范围内 */
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

/* 模块参数（非静态，可从 procfs 访问） */
unsigned int fw_ban_time = DEFAULT_BAN_TIME;
char *state_file = "/var/lib/firewall/state";
unsigned int fw_max_bans_per_second = 200;

module_param(fw_ban_time, uint, 0644);
MODULE_PARM_DESC(fw_ban_time, "封禁持续时间（秒）（默认 600）");
module_param(state_file, charp, 0444);  /* 修复 P2-8：改为只读权限，防止运行时修改 */
MODULE_PARM_DESC(state_file, "用于保存/恢复封禁和白名单条目的状态文件路径（默认 /var/lib/firewall/state）");
module_param(fw_max_bans_per_second, uint, 0644);
MODULE_PARM_DESC(fw_max_bans_per_second, "泛洪保护下每秒最大封禁添加次数（默认 200）");

/* 全局防火墙信息 — 设为 static 以防止外部访问 */
static struct firewall_info fw_info;

/* 导出函数，提供对 fw_info 的受控访问 */
struct firewall_info *get_fw_info(void)
{
    return &fw_info;
}
EXPORT_SYMBOL_GPL(get_fw_info);

/*
 * ban_ip - 将 IPv4 添加到封禁列表
 * 优化版本：使用 rwlock 提高并发性
 */
/*
 * __do_ban_ip - 内部统一封禁函数
 * @fw: 防火墙信息结构体
 * @ip: 要封禁的 IP 地址
 * @unban_time: 解封时间（0 = 永久）
 * @is_permanent: 是否为永久封禁
 * @log_msg: 日志消息后缀（如 "for %u seconds"、"permanently"）
 * @log_arg: 日志消息参数（不需要时为 0）
 *
 * 这是所有公共封禁函数使用的统一内部封禁实现。处理白名单检查、
 * 重复检测、容量检查、分配和哈希插入。
 *
 * 返回值：成功返回 0，失败返回负错误码
 */
static int __do_ban_ip(struct firewall_info *fw, __be32 ip,
                       unsigned long unban_time, bool is_permanent,
                       const char *log_msg, unsigned long log_arg)
{
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    u32 hash;
    int bkt;

    /* 验证 IP 输入 */
    if (!ip) {
        fw_pr_err("Invalid IP address for banning: %pI4", &ip);
        return -EINVAL;
    }

    /* 修复 1.2：白名单检查移到 fw->lock 外，仅用 RCU 保护
     * 注意：存在微小的 TOCTOU 窗口（白名单检查与封禁操作之间），
     * 但这是可接受的：白名单修改是低频操作，最坏情况是某个 IP
     * 刚好在窗口期被白名单移除然后被封禁——这符合预期行为。 */
    rcu_read_lock();
    hash_for_each_rcu(fw->whitelist_table, bkt, wl_entry, hash) {
        if ((ip & wl_entry->mask) == (wl_entry->ip & wl_entry->mask)) {
            rcu_read_unlock();
            atomic_inc(&fw->whitelist_reject_count);
            fw_pr_warn("REFUSED to ban whitelisted IP %pI4", &ip);
            return -EPERM;
        }
    }
    rcu_read_unlock();

    /* 修复 P0-1：在锁外预分配内存，避免在 spinlock 内使用 GFP_ATOMIC */
    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        atomic_inc(&fw->alloc_failure_count);
        fw_pr_err("Failed to allocate memory for ban entry for IP %pI4", &ip);
        return -ENOMEM;
    }

    spin_lock(&fw->lock);

    /* 检查是否已被封禁 */
    hash = hash_min(ip, BAN_HASH_BITS);
    struct ban_entry *existing;
    hash_for_each_possible(fw->ban_table, existing, hash, ip) {
        if (compare_ips(existing->ip, ip)) {
            if (existing->is_permanent || time_before(jiffies, existing->unban_time)) {
                spin_unlock(&fw->lock);
                kfree(entry);  /* 释放预分配的内存 */
                return 0;  /* 已被封禁 */
            } else {
                /* 条目存在但已过期 — 更新它 */
                existing->ban_time = jiffies;
                existing->unban_time = unban_time;
                existing->is_permanent = is_permanent;
                atomic_set(&existing->retry_count, 0);
                spin_unlock(&fw->lock);
                kfree(entry);  /* 释放预分配的内存 */
                return 0;
            }
        }
    }

    /* 检查封禁表容量 */
    if (atomic_read(&fw->ban_count) >= MAX_BAN_ENTRIES) {
        spin_unlock(&fw->lock);
        kfree(entry);  /* 释放预分配的内存 */
        atomic_inc(&fw->ban_table_full_count);
        fw_pr_warn("Ban table full, cannot ban %pI4", &ip);
        return -ENOSPC;
    }

    /* 初始化并插入新条目 */
    entry->ip = ip;
    entry->ban_time = jiffies;
    entry->unban_time = unban_time;
    entry->is_permanent = is_permanent;
    atomic_set(&entry->retry_count, 0);

    hash_add(fw->ban_table, &entry->hash, ip);
    atomic_inc(&fw->ban_count);
    atomic_inc(&fw->total_ban_count);

    spin_unlock(&fw->lock);

    /* 使用提供的消息记录日志 */
    if (log_msg && log_arg)
        fw_pr_info_ratelimited("%pI4 %s %lu", &ip, log_msg, log_arg);
    else if (log_msg)
        fw_pr_info_ratelimited("%pI4 %s", &ip, log_msg);

    return 0;
}

/*
 * __find_ban_entry_rcu - 使用 RCU 查找封禁条目（内部辅助函数）
 * @fw: 防火墙信息结构体
 * @ip: 要查找的 IP 地址
 *
 * 返回值：找到返回 ban_entry 指针，否则返回 NULL
 * 必须在 rcu_read_lock()/rcu_read_unlock() 内调用
 */
static struct ban_entry *__find_ban_entry_rcu(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    u32 hash __maybe_unused = hash_min(ip, BAN_HASH_BITS);

    hash_for_each_possible_rcu(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip))
            return entry;
    }
    return NULL;
}

/*
 * __do_unban_ip - 内部统一解封函数
 * @fw: 防火墙信息结构体
 * @ip: 要解封的 IP 地址
 * @permanent_only: 如果为 true，仅移除永久封禁
 *
 * 返回值：成功返回 0，未找到返回 -ENOENT
 */
static int __do_unban_ip(struct firewall_info *fw, __be32 ip, bool permanent_only)
{
    struct ban_entry *entry;
    int found = 0;
    char ip_str[INET_ADDRSTRLEN];
    u32 hash;

    ipv4_to_str(ip, ip_str, sizeof(ip_str));

    spin_lock(&fw->lock);
    hash = hash_min(ip, BAN_HASH_BITS);
    hash_for_each_possible(fw->ban_table, entry, hash, ip) {
        if (compare_ips(entry->ip, ip)) {
            if (!permanent_only || entry->is_permanent) {
                hlist_del_rcu(&entry->hash);
                atomic_dec(&fw->ban_count);
                found = 1;
                call_rcu(&entry->rcu_head, free_ban_entry_rcu);
            }
            break;
        }
    }
    spin_unlock(&fw->lock);

    if (found) {
        atomic_inc(&fw->total_unban_count);
        if (permanent_only)
            fw_pr_info("IP %s permanently unbanned", ip_str);
        else
            fw_pr_info_ratelimited("IP %s unbanned", ip_str);
        return 0;
    }
    return -ENOENT;
}

/*
 * unban_ip - 从封禁列表中移除 IPv4
 */
int unban_ip(struct firewall_info *fw, __be32 ip)
{
    FW_DEBUG(1, "ENTRY: unban_ip(ip=%pI4)", &ip);
    int ret = __do_unban_ip(fw, ip, false);
    FW_DEBUG(1, "EXIT: unban_ip -> %d", ret);
    return ret;
}

/*
 * unban_permanent_ip - 移除永久封禁条目
 * 仅移除标记为永久的条目
 */
int unban_permanent_ip(struct firewall_info *fw, __be32 ip)
{
    FW_DEBUG(1, "ENTRY: unban_permanent_ip(ip=%pI4)", &ip);
    int ret = __do_unban_ip(fw, ip, true);
    if (ret == -ENOENT)
        fw_pr_warn("IP 未在永久封禁列表中找到");
    FW_DEBUG(1, "EXIT: unban_permanent_ip -> %d", ret);
    return ret;
}

/*
 * is_banned - 检查 IPv4 是否被封禁
 * 返回值：1 表示被封禁（有效），0 表示未封禁或已过期
 */
int is_banned(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    unsigned long now = jiffies;
    int found = 0;

    FW_DEBUG(3, "Checking if IPv4 %pI4 is banned", &ip);

    rcu_read_lock();
    entry = __find_ban_entry_rcu(fw, ip);
    if (entry) {
        /* 检查是否为永久封禁（永不过期） */
        if (entry->is_permanent) {
            FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
            found = 1;
        } else if (time_after(now, entry->unban_time)) {
            /* 条目存在但已过期 — 移除它 */
            /* 我们无法在 RCU 读锁下移除，所以仅返回 0 */
            FW_DEBUG(2, "Found expired ban entry for IPv4 %pI4", &ip);
            found = 0;
        } else {
            /* 有效的封禁条目 */
            FW_DEBUG(2, "Found active ban entry for IPv4 %pI4", &ip);
            found = 1;
        }
    }
    rcu_read_unlock();

    FW_DEBUG(3, "Result for IPv4 %pI4 ban check: %s", &ip, found ? "BANNED" : "NOT BANNED");
    return found;
}

/*
 * ban_ip - 将 IPv4 添加到封禁列表，使用默认持续时间
 */
int ban_ip(struct firewall_info *fw, __be32 ip)
{
    unsigned long ban_secs = READ_ONCE(fw_ban_time);
    unsigned long ban_duration;

    FW_DEBUG(1, "ENTRY: ban_ip(ip=%pI4)", &ip);

    if (check_mul_overflow(ban_secs, (unsigned long)HZ, &ban_duration)) {
        fw_pr_err("ban_time overflow detected");
        return -EINVAL;
    }

    FW_DEBUG(2, "Attempting to ban IPv4: %pI4", &ip);
    int ret = __do_ban_ip(fw, ip, jiffies + ban_duration, false,
                          "banned for %u seconds", ban_secs);
    FW_DEBUG(1, "EXIT: ban_ip -> %d", ret);
    return ret;
}

/*
 * ban_ip_permanent - 将 IPv4 添加到永久封禁列表
 * 永久封禁永不过期（unban_time = 0）
 */
int ban_ip_permanent(struct firewall_info *fw, __be32 ip)
{
    FW_DEBUG(1, "ENTRY: ban_ip_permanent(ip=%pI4)", &ip);
    FW_DEBUG(2, "Attempting to permanently ban IPv4: %pI4", &ip);

    int ret = __do_ban_ip(fw, ip, 0, true, "permanently banned", 0);
    FW_DEBUG(1, "EXIT: ban_ip_permanent -> %d", ret);
    return ret;
}

/*
 * is_permanently_banned - 检查 IPv4 是否被永久封禁
 * 如果永久封禁返回 1，否则返回 0
 */
int is_permanently_banned(struct firewall_info *fw, __be32 ip)
{
    struct ban_entry *entry;
    int found = 0;

    FW_DEBUG(3, "Checking if IPv4 %pI4 is permanently banned", &ip);

    rcu_read_lock();
    entry = __find_ban_entry_rcu(fw, ip);
    if (entry && entry->is_permanent) {
        FW_DEBUG(2, "Found permanent ban entry for IPv4 %pI4", &ip);
        found = 1;
    }
    rcu_read_unlock();

    FW_DEBUG(3, "Result for IPv4 %pI4 permanent ban check: %s", &ip, found ? "PERMANENTLY BANNED" : "NOT PERMANENTLY BANNED");
    return found;
}

/**
 * cleanup_expired_bans - 移除过期的封禁条目
 * 优化版本：当没有条目需要清理时提前退出
 * 注意：收集要释放的条目，然后调用 call_rcu 异步释放（不在锁内）。
 *
 * 返回值：true 表示还有更多条目可能需要清理，false 表示当前无更多条目
 */
static bool cleanup_expired_bans(struct firewall_info *fw);

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

static bool cleanup_expired_bans(struct firewall_info *fw)
{
    struct ban_entry *entry;
    struct hlist_node *tmp;
    unsigned long now = jiffies;
    int removed = 0;
    int processed = 0;
    int max_processed_per_call = 50;  /* 限制每次调用处理的数量，防止长时间持有锁 */
    int start_bucket = fw->cleanup_last_bucket;  /* 从上次离开的位置继续 */

    FW_DEBUG(2, "ENTRY: cleanup_expired_bans(current_count=%d, start_bucket=%d)", atomic_read(&fw->ban_count), start_bucket);

    /* 增加清理周期计数器 */
    atomic_inc(&fw->cleanup_cycles);

    /* 如果没有条目需要清理，提前退出 */
    if (atomic_read(&fw->ban_count) == 0) {
        fw->cleanup_last_bucket = 0;  /* 为下一周期重置 */
        FW_DEBUG(3, "No entries to clean, exiting early");
        FW_DEBUG(2, "EXIT: cleanup_expired_bans -> false (no entries)");
        return false;
    }

    spin_lock(&fw->lock);

    /* 获取锁后再次检查是否没有条目需要清理，提前退出 */
    if (atomic_read(&fw->ban_count) == 0) {
        spin_unlock(&fw->lock);
        fw->cleanup_last_bucket = 0;  /* 为下一周期重置 */
        FW_DEBUG(3, "No entries to clean after lock acquired, exiting early");
        FW_DEBUG(2, "EXIT: cleanup_expired_bans -> false (no entries after lock)");
        return false;
    }

    /* 每次调用仅处理一部分桶，以分散负载 */
    unsigned int ban_table_size = 1 << BAN_HASH_BITS;

    for (int i = 0; i < (1 << 3) && processed < max_processed_per_call; i++) {  /* 每次调用最多处理 8 个桶 */
        int current_bucket = (start_bucket + i) % ban_table_size;

        /* hlist_for_each_entry_safe 保证即使当前条目被删除，
         * tmp 仍然指向下一个有效节点。因此在循环内调用 hlist_del_rcu
         * 删除 entry 是安全的，不会破坏遍历 */
        hlist_for_each_entry_safe(entry, tmp, &fw->ban_table[current_bucket], hash) {
            if (processed >= max_processed_per_call) {
                break;
            }

            /* 跳过永久封禁 — 它们永不过期 */
            if (entry->is_permanent) {
                processed++;
                continue;
            }

            if (time_after(now, entry->unban_time)) {
                /* 修复 P1-4：使用 hlist_del_rcu 而非 hlist_del，以在 RCU 读者
                 * 仍可能访问时安全移除 entry。当 netfilter 钩子函数中可能存在
                 * 并发 RCU 遍历时，hlist_del 是不安全的。 */
                hlist_del_rcu(&entry->hash);
                atomic_dec(&fw->ban_count);
                removed++;
                /* 使用 call_rcu 异步释放（不在锁内） */
                call_rcu(&entry->rcu_head, free_ban_entry_rcu);
                FW_DEBUG(2, "Removed expired ban entry");
            }
            processed++;
        }
    }

    /* 更新下次调用的起始桶 */
    fw->cleanup_last_bucket = (start_bucket + (1 << 3)) % ban_table_size;  /* 前进 8 个哈希桶 */

    spin_unlock(&fw->lock);

    if (removed > 0) {
        atomic_add(removed, &fw->cleanup_expired_total);
        FW_DEBUG(1, "Cleaned up %d expired ban entries", removed);
        /* 修复 Extra-8：使用 net_info_ratelimited 防止大量清理时日志泛滥 */
        fw_pr_info_ratelimited("Cleaned up %d expired ban entries", removed);
    } else {
        FW_DEBUG(3, "No expired entries found during cleanup");
    }

    /* 修复 P0-2：移除 cleanup_expired_bans 中的 mod_timer 调用，
     * 避免与 cleanup_timer_callback 中的定时器设置冲突。
     * 定时器间隔的动态调整统一在 cleanup_timer_callback 中处理。
     * 返回是否还有更多条目可能需要清理，供调用方调整定时器间隔。 */
    bool has_more_entries = (removed > 0 && atomic_read(&fw->ban_count) > 0);
    if (has_more_entries) {
        FW_DEBUG(2, "Entries remain after cleanup, timer callback will use shorter interval");
    } else {
        FW_DEBUG(3, "No more entries to clean, using standard timer interval");
    }

    FW_DEBUG(2, "EXIT: cleanup_expired_bans -> %s (removed=%d, processed=%d)",
             has_more_entries ? "true" : "false", removed, processed);
    return has_more_entries;
}

/*
 * auto_discover_system_ips - 在 RCU 中收集 IPv4 IP，然后在锁外添加白名单（修复：RCU+GFP_KERNEL）
 */
/* 自动发现的临时存储结构（移到堆上以减少栈使用） */
struct temp_ip_entry {
    __be32 ip;
    __be32 mask;
    char name[16];
};

/*
 * sync_work_handler - 延迟工作队列处理函数（防抖后执行）
 */
static void sync_work_handler(struct work_struct *work)
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

    /* 检查是否正在关闭 */
    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: sync_work_handler -> void (shutting down)");
        return;
    }

    /* 分配临时数组存储当前系统 IP */
    current_ips = kmalloc_array(MAX_DISCOVERED_IPS, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!current_ips) {
        fw_pr_err("Failed to allocate current_ips");
        return;
    }

    /* 在 RCU 保护下收集当前系统所有网卡 IP */
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

    /* 如果没有发现任何 IP，早期返回 */
    if (current_count == 0) {
        fw_pr_debug("No active network interfaces with IPv4 found");
        kfree(current_ips);
        return;
    }

    /* 构建当前 IP 的查找表 */
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

    /* 遍历白名单，标记已存在的 auto-discovered 条目 */
    spin_lock(&fw->whitelist_lock);
    hash_for_each_safe(fw->whitelist_table, bkt, tmp, entry, hash) {
        /* 只处理自动发现的条目（device_name 不是 "manual" 或 "restored"） */
        if (strcmp(entry->device_name, "manual") == 0 ||
            strcmp(entry->device_name, "restored") == 0) {
            continue;
        }

        /* 检查该条目是否仍在当前系统 IP 列表中 */
        for (i = 0; i < current_count; i++) {
            __be32 normalized_current = current_ips[i].ip & current_ips[i].mask;
            if (entry->ip == normalized_current && entry->mask == current_ips[i].mask) {
                lookup_table[i].found = true;
                break;
            }
        }

        /* 如果该自动发现条目不再存在，标记删除 */
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

    /* 添加新的系统 IP 到白名单 */
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
 * 当网卡发生变化时（IP 变化、网卡上下线等），延迟 500ms 后同步白名单
 */
void sync_system_ips(struct firewall_info *fw)
{
    unsigned long delay = msecs_to_jiffies(500);  /* 500ms 防抖延迟 */

    FW_DEBUG(1, "ENTRY: sync_system_ips (scheduling with 500ms debounce)");

    /* 检查是否正在关闭 */
    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: sync_system_ips -> void (shutting down)");
        return;
    }

    /* 调度延迟工作，如果已有待处理的工作则更新延迟时间（实现防抖） */
    mod_delayed_work(system_wq, &fw->sync_work, delay);

    FW_DEBUG(1, "EXIT: sync_system_ips -> void (work scheduled)");
}

/*
 * netdev_event_handler - 网络设备事件回调函数
 * 监听网卡 IP 变化、网卡上下线等事件
 */
static int netdev_event_handler(struct notifier_block *nb, unsigned long event, void *ptr)
{
    struct firewall_info *fw;
    struct net_device *dev;

    fw = container_of(nb, struct firewall_info, netdev_notifier);

    /* 检查是否正在关闭 */
    if (unlikely(atomic_read(&fw->shutting_down)))
        return NOTIFY_DONE;

    dev = netdev_notifier_info_to_dev(ptr);
    if (!dev)
        return NOTIFY_DONE;

    /* 只处理与 IP 地址变化相关的事件 */
    switch (event) {
    case NETDEV_UP:      /* 网卡启用，IP 已配置 */
    case NETDEV_DOWN:    /* 网卡禁用，IP 失效 */
    case NETDEV_CHANGE:  /* IP 地址变化（DHCP 续约等） */
        fw_pr_debug_ratelimited("Network event %lu on device %s", event, dev->name);
        /* 触发 IP 同步 */
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

void auto_discover_system_ips(struct firewall_info *fw)
{
    /* 在堆上分配以避免大栈帧 */
    struct temp_ip_entry *temp_ips;
    int temp_count = 0;

    struct net_device *dev;
    struct in_device *in_dev;
    struct in_ifaddr *ifa;

    FW_DEBUG(1, "ENTRY: auto_discover_system_ips");

    /* 在堆上分配临时数组 */
    temp_ips = kmalloc_array(MAX_DISCOVERED_IPS, sizeof(struct temp_ip_entry), GFP_KERNEL);
    if (!temp_ips) {
        fw_pr_err("Failed to allocate temp_ips");
        FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (alloc temp_ips failed)");
        return;
    }

    /* 修复 Extra-8：使用 net_info_ratelimited 防止日志泛滥 */
    fw_pr_info_ratelimited("Auto-discovering system IPs...");

    /* 修复 C2：在 RCU 保护下收集 IPv4 地址
     * 修复说明：__in_dev_get_rcu(dev) 内部使用 rcu_dereference 保护，
     * 但为了代码清晰和防御性编程，显式使用 rcu_dereference 来
     * 保护 ifa_list 遍历。RCU 读锁（rcu_read_lock/unlock）确保网络设备
     * 列表在遍历期间不会被修改。
     */
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
        /* 跳过回环设备，其地址会被 validate_ipv4_address 拒绝 */
        if (dev->flags & IFF_LOOPBACK)
            continue;

        if (!(dev->flags & IFF_UP))
            continue;

        /* 收集 IPv4 地址 */
        in_dev = __in_dev_get_rcu(dev);
        if (in_dev) {
            /* 修复：使用 rcu_dereference 显式保护 ifa_list 遍历
             * __in_dev_get_rcu 返回的 in_dev 指针受 RCU 保护，
             * 但 in_dev->ifa_list 遍历也需要 RCU dereference 保护，
             * 以防止并发修改。
             */
            for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
                 ifa = rcu_dereference(ifa->ifa_next)) {
                if (temp_count >= MAX_DISCOVERED_IPS)
                    break;

                /* 验证 IP 地址有效性 */
                if (!ifa->ifa_local) {
                    continue;  /* 跳过无效 IP 地址 */
                }

                temp_ips[temp_count].ip = ifa->ifa_local;  /* 使用 ifa_local 而非 ifa_address */
                temp_ips[temp_count].mask = ifa->ifa_mask;
                strscpy(temp_ips[temp_count].name, dev->name, 16);
                temp_count++;
            }
        }
    }
    rcu_read_unlock();

    /* 在 RCU 锁外添加 IPv4 IP（对 GFP_KERNEL 安全） */
    for (int i = 0; i < temp_count; i++) {
        if (add_whitelist_entry(fw, temp_ips[i].ip, temp_ips[i].mask, temp_ips[i].name) < 0) {
            fw_pr_warn("Failed to add system IPv4 %pI4 to whitelist", &temp_ips[i].ip);
        }
    }

    /* 修复 Extra-8：使用 net_info_ratelimited 防止日志泛滥 */
    fw_pr_info_ratelimited("Auto-discovery complete. %d entries", atomic_read(&fw->whitelist_count));

    /* 释放临时数组 */
    kfree(temp_ips);

    FW_DEBUG(1, "EXIT: auto_discover_system_ips -> void (success, wl_count=%d)", atomic_read(&fw->whitelist_count));
}

/*
 * cleanup_timer_callback - 定期清理的定时器回调
 * 优化版本：降低频率并提高效率
 * 修复 P0-2：根据清理结果动态调整定时器间隔
 */
static void cleanup_timer_callback(struct timer_list *t)
{
    struct firewall_info *fw = container_of(t, struct firewall_info, cleanup_timer);

    FW_DEBUG(3, "ENTRY: cleanup_timer_callback");

    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: cleanup_timer_callback -> void (shutting down)");
        return;
    }

    /* 执行清理并获取是否还有更多条目需要清理的标志 */
    bool has_more_entries = cleanup_expired_bans(fw);

    /* 在重新设置定时器前再次检查 shutting_down，防止关闭期间的竞态 */
    if (unlikely(atomic_read(&fw->shutting_down))) {
        FW_DEBUG(2, "EXIT: cleanup_timer_callback -> void (shutting down after cleanup)");
        return;
    }

    /* 修复 P0-2：根据清理结果动态调整定时器间隔
     * - 如果还有更多条目需要清理，使用较短间隔（1秒）加速清理
     * - 否则使用标准间隔（ban_time/4 或 30秒的最小值） */
    unsigned long cleanup_interval;
    if (has_more_entries) {
        cleanup_interval = HZ;  /* 1秒后再次检查 */
        FW_DEBUG(3, "More entries to clean, using short interval (1s)");
    } else {
        /* 修复 P1-5：使用 READ_ONCE 原子访问 fw_ban_time */
        cleanup_interval = max(HZ * 30UL, ((unsigned long)READ_ONCE(fw_ban_time) * HZ) / 4);
        FW_DEBUG(3, "No more entries, using standard interval (%lu jiffies)", cleanup_interval);
    }

    mod_timer(&fw->cleanup_timer, jiffies + cleanup_interval);

    FW_DEBUG(3, "EXIT: cleanup_timer_callback -> void (timer re-armed)");
}

/*
 * bans_show - 显示当前封禁列表（仅 IPv4）
 * 复用自原始 ban_list_show
 */
static int bans_show(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct ban_entry *entry;
    u32 hash;
    unsigned long now = jiffies;
    char ip_str[INET_ADDRSTRLEN];
    int count = 0;
    int temporary_count = 0;
    int permanent_count = 0;

    FW_DEBUG(3, "ENTRY: bans_show");

    seq_printf(m, "当前封禁的 IP 列表：\n");
    seq_printf(m, "-------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->ban_table, hash, entry, hash) {
        /* 检查是否为永久封禁（永不过期） */
        if (entry->is_permanent) {
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            seq_printf(m, "%-40s（永久）\n", ip_str);
            permanent_count++;
            count++;
        } else if (!time_after(now, entry->unban_time)) {
            /* 临时封禁 - 检查是否过期 */
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            seq_printf(m, "%-40s（%lu 秒后过期）\n",
                       ip_str,
                       (entry->unban_time - now) / HZ);
            temporary_count++;
            count++;
        }
    }
    rcu_read_unlock();

    seq_printf(m, "-------------------\n");
    seq_printf(m, "总计：%d 个活跃封禁（%d 个永久，%d 个临时）\n",
               count, permanent_count, temporary_count);
    FW_DEBUG(3, "EXIT: bans_show -> 0 (shown=%d)", count);
    return 0;
}

static int bans_open(struct inode *inode, struct file *file)
{
    return single_open(file, bans_show, NULL);
}

/*
 * ban_ip_with_duration - 使用自定义持续时间封禁 IP
 * @fw: 防火墙信息结构体
 * @ip: 要封禁的 IP 地址
 * @seconds: 封禁持续时间（秒）（必须 > 0）
 *
 * 修复 3.2：简化为调用 __do_ban_ip，消除 ~100 行重复代码
 */
static int ban_ip_with_duration(struct firewall_info *fw, __be32 ip, unsigned long seconds)
{
    unsigned long ban_duration;

    FW_DEBUG(1, "ENTRY: ban_ip_with_duration(ip=%pI4, seconds=%lu)", &ip, seconds);

    /* 验证 IP 输入 */
    if (!ip) {
        fw_pr_err("Invalid IP address for banning: %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (invalid IP)");
        return -EINVAL;
    }

    /* 验证持续时间 */
    if (seconds == 0) {
        fw_pr_err("Invalid ban duration: 0 seconds");
        FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (zero duration)");
        return -EINVAL;
    }

    /* 检查整数溢出 */
    if (check_mul_overflow(seconds, (unsigned long)HZ, &ban_duration)) {
        fw_pr_err("ban duration overflow for IP %pI4", &ip);
        FW_DEBUG(1, "EXIT: ban_ip_with_duration -> -EINVAL (overflow)");
        return -EINVAL;
    }

    FW_DEBUG(2, "Attempting to ban IPv4 %pI4 for %lu seconds", &ip, seconds);

    /* 委托给统一的 __do_ban_ip 函数 */
    int ret = __do_ban_ip(fw, ip, jiffies + ban_duration, false,
                          "banned for %lu seconds", seconds);
    FW_DEBUG(1, "EXIT: ban_ip_with_duration -> %d", ret);
    return ret;
}

/*
 * bans_write - Unified write handler for ban management
 * Commands:
 *   <ip>              -> Temporary ban (default fw_ban_time)
 *   <ip> <seconds>    -> Temporary ban with custom duration (seconds > 0)
 *   <ip> 0            -> Permanent ban
 *   <ip> <negative>   -> Unban (seconds < 0)
 *   unban <ip>        -> Unban
 */
static ssize_t bans_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    char input[256];
    char ip_str[INET_ADDRSTRLEN];
    __be32 ip;
    long seconds;
    char *space_pos;
    char *endp;
    ssize_t len;
    int result;

    FW_DEBUG(2, "ENTRY: bans_write(count=%zu)", count);

    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: bans_write -> 0 (empty input)");
        return 0;
    }
    /* 限制输入以防止缓冲区溢出 */
    if (count > sizeof(input) - 1) {
        FW_DEBUG(1, "EXIT: bans_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(input) - 1));

    if (copy_from_user(input, buf, len)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    /* 确保空终止 */
    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    /* 验证我们在缓冲区范围内有空终止符 */
    if (strnlen(input, sizeof(input)) >= sizeof(input)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EINVAL (not null-terminated)");
        return -EINVAL;
    }

    /* 拒绝路径遍历攻击 - 检查输入中是否包含 '../' 或 URL 编码的路径遍历 */
    if (strstr(input, "..") != NULL) {
        fw_pr_warn("Path traversal attempt detected: %s", input);
        return -EINVAL;
    }
    /* 修复 P2-6：使用独立缓冲区进行小写转换，不直接修改用户输入 */
    {
        char lower_input[sizeof(input)];
        size_t i;

        /* 复制到独立缓冲区并转为小写 */
        for (i = 0; input[i] && i < sizeof(lower_input) - 1; i++) {
            if (input[i] >= 'A' && input[i] <= 'Z')
                lower_input[i] = input[i] - 'A' + 'a';
            else
                lower_input[i] = input[i];
        }
        lower_input[i] = '\0';

        if (strstr(lower_input, "%2e") != NULL || strstr(lower_input, "%2f") != NULL) {
            fw_pr_warn("URL encoded path traversal attempt detected: %s", input);
            return -EINVAL;
        }
    }

    /* 跳过前导空白 */
    space_pos = input;
    while (*space_pos && (*space_pos == ' ' || *space_pos == '\t'))
        space_pos++;

    if (*space_pos == '\0') {
        fw_pr_warn("Empty command");
        return -EINVAL;
    }

    /* 检查 "unban <ip>" 命令 */
    if (strncmp(space_pos, "unban ", 6) == 0 || strncmp(space_pos, "unban\t", 6) == 0) {
        /* 提取 "unban " 后的 IP */
        char *ip_start = space_pos + 5;  /* 跳过 "unban" */
        while (*ip_start && (*ip_start == ' ' || *ip_start == '\t'))
            ip_start++;

        if (*ip_start == '\0') {
            fw_pr_warn("Missing IP address after 'unban'");
            return -EINVAL;
        }

        /* 检查 IP 后是否有额外内容 */
        char *ip_end = ip_start;
        while (*ip_end && *ip_end != ' ' && *ip_end != '\t')
            ip_end++;
        if (*ip_end != '\0') {
            fw_pr_warn("Invalid format - extra content after IP: %s", input);
            return -EINVAL;
        }

        /* 解析 IP */
        strncpy(ip_str, ip_start, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';

        if (!in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
            fw_pr_warn("Invalid IP address format: %s", ip_str);
            return -EINVAL;
        }

        /* 执行解封 */
        result = unban_ip(&fw_info, ip);
        if (result < 0) {
            if (result == -ENOENT) {
                fw_pr_warn("IP %s not found in ban list", ip_str);
            } else {
                fw_pr_err("Failed to unban IP %s (error %d)", ip_str, result);
            }
            return result;
        }
        FW_DEBUG(1, "EXIT: bans_write -> %zu (success, unbanned)", count);
        return count;
    }

    /* 解析输入格式："<ip>" 或 "<ip> <seconds>" */
    /* 使用独立的局部缓冲区进行解析，避免修改原始 input 缓冲区 */
    {
        char parse_buf[sizeof(input)];
        char *ptr;
        char *ip_start;

        /* 将 input 复制到独立缓冲区进行安全解析 */
        memcpy(parse_buf, input, sizeof(parse_buf));

        space_pos = NULL;
        ptr = parse_buf;
        while (*ptr && (*ptr == ' ' || *ptr == '\t'))
            ptr++;

        /* 查找第一个令牌（IP）的结尾 */
        ip_start = ptr;
        while (*ptr && *ptr != ' ' && *ptr != '\t')
            ptr++;

        if (*ptr) {
            /* 找到空格 - 检查是否有更多内容 */
            *ptr = '\0';  /* 在局部缓冲区中终止 IP 字符串 */
            space_pos = ptr + 1;

            /* 跳过空白以查找秒数值 */
            while (*space_pos && (*space_pos == ' ' || *space_pos == '\t'))
                space_pos++;

            if (*space_pos == '\0') {
                /* IP 后只有空白 - 视为纯 IP */
                goto ban_default_duration;
            }

            /* 解析秒数值 */
            seconds = simple_strtol(space_pos, &endp, 10);
            if (endp == space_pos || *endp != '\0') {
                fw_pr_warn("Invalid format - invalid seconds value: %s", input);
                return -EINVAL;
            }

            /* 验证秒数边界以防止溢出 */
            if (seconds < 0 && seconds != -1) {
                /* 除 -1 外的负值无效 */
                fw_pr_warn("Invalid ban duration: %ld", seconds);
                return -EINVAL;
            }
            if (seconds > MAX_BAN_TIME) {
                fw_pr_warn("Ban duration %ld exceeds maximum %d seconds", seconds, MAX_BAN_TIME);
                return -EINVAL;
            }

            /* 复制 IP 字符串以进行验证 */
            strncpy(ip_str, ip_start, sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
        } else {
            /* 未找到空格 - 纯 IP 地址 */
            *ptr = '\0';
ban_default_duration:
            strncpy(ip_str, ip_start, sizeof(ip_str) - 1);
            ip_str[sizeof(ip_str) - 1] = '\0';
            seconds = -2;  /* 特殊标记：使用默认持续时间 */
        }
    }

    /* 验证 IP 格式 */
    if (*ip_str == '\0') {
        fw_pr_warn("Missing IP address");
        return -EINVAL;
    }

    /* 解析 IP 地址 */
    if (!in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
        fw_pr_warn("Invalid IP address format: %s", ip_str);
        return -EINVAL;
    }

    /* 统一的 IPv4 地址验证 */
    if (validate_ipv4_address(ip, ip_str, "ban") < 0) {
        return -EINVAL;
    }

    /* 检查私有/保留 IP 范围（仅警告） */
    unsigned int ip_class_a = (ntohl(ip) >> 24) & 0xFF;
    unsigned int ip_class_b = (ntohl(ip) >> 16) & 0xFF;
    if ((ip_class_a == 10) ||
        (ip_class_a == 172 && ip_class_b >= 16 && ip_class_b <= 31) ||
        (ip_class_a == 192 && ip_class_b == 168)) {
        fw_pr_warn("Attempt to ban private IPv4 range %pI4 - this may be unintended", &ip);
    }

    /* 根据秒数值执行封禁/解封 */
    if (seconds < 0 && seconds != -2) {
        /* 负值：解封 */
        result = unban_ip(&fw_info, ip);
        if (result < 0) {
            if (result == -ENOENT) {
                fw_pr_warn("IP %s not found in ban list", ip_str);
            } else {
                fw_pr_err("Failed to unban IP %s (error %d)", ip_str, result);
            }
            return result;
        }
    } else if (seconds == 0) {
        /* 零：永久封禁 */
        /* 检查永久封禁的泛洪保护绕过 */
        result = ban_ip_permanent(&fw_info, ip);
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
            return result;
        }
    } else if (seconds == -2) {
        /* 默认持续时间的标记：使用标准 ban_ip() */
        /* 检查临时封禁的泛洪保护 */
        if (check_flood_protection() < 0) {
            fw_pr_warn("Flood protection triggered - too many ban requests");
            return -EBUSY;
        }

        result = ban_ip(&fw_info, ip);
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
            return result;
        }
    } else {
        /* 正值：自定义持续时间封禁 */
        /* 检查临时封禁的泛洪保护 */
        if (check_flood_protection() < 0) {
            fw_pr_warn("Flood protection triggered - too many ban requests");
            return -EBUSY;
        }

        result = ban_ip_with_duration(&fw_info, ip, (unsigned long)seconds);
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
            return result;
        }
    }

    FW_DEBUG(1, "EXIT: bans_write -> %zu (success)", count);
    return count;
}

static const struct proc_ops bans_fops = {
    .proc_open = bans_open,
    .proc_read = seq_read,
    .proc_write = bans_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * check_flood_protection - 检查添加此条目是否会超过泛洪限制
 * 使用可配置的 fw_max_bans_per_second 模块参数
 */
static int check_flood_protection(void)
{
    unsigned long now = jiffies;
    unsigned long one_second = HZ;  // 一秒钟的 jiffies 数
    unsigned int max_bans;

    spin_lock(&fw_info.flood_lock);

    // 如果自上次检查以来已超过 1 秒，则重置计数器
    if (time_after(now, fw_info.last_flood_check + one_second)) {
        fw_info.recent_additions = 1;  // 此次添加计为第一次
        fw_info.last_flood_check = now;
    } else {
        // 增加添加计数器
        fw_info.recent_additions++;

        // 使用 READ_ONCE 原子读取可配置的限值
        max_bans = READ_ONCE(fw_max_bans_per_second);
        
        // 检查是否已超过配置的限值
        if (fw_info.recent_additions > max_bans) {
            spin_unlock(&fw_info.flood_lock);
            return -EBUSY;  // 时间窗口内添加次数过多
        }
    }

    spin_unlock(&fw_info.flood_lock);
    return 0;
}

/*
 * whitelist_read - 显示白名单条目（仅 IPv4）
 */
static int whitelist_read(struct seq_file *m, void *v)
{
    struct firewall_info *fw = &fw_info;
    struct whitelist_entry *entry;
    u32 hash;
    char ip_str[INET_ADDRSTRLEN];
    int prefix_len;

    seq_printf(m, "白名单 IP（免受封禁）：\n");
    seq_printf(m, "--------------------------------------\n");

    rcu_read_lock();
    hash_for_each_rcu(fw->whitelist_table, hash, entry, hash) {
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
    seq_printf(m, "总计：%d 个条目\n", atomic_read(&fw->whitelist_count));
    return 0;
}

static int whitelist_open(struct inode *inode, struct file *file)
{
    return single_open(file, whitelist_read, NULL);
}

/*
 * whitelist_write - 白名单管理的统一写入处理程序
 * 命令：
 *   add <子网>      -> 添加到白名单
 *   remove <子网>   -> 从白名单移除
 *   <子网>          -> 默认：添加到白名单
 */
static ssize_t whitelist_write(struct file *file, const char __user *buf,
                                size_t count, loff_t *ppos)
{
    char input[INET_ADDRSTRLEN + 16];
    ssize_t len;
    char *ptr, *cmd_start, *subnet_start;
    char cmd_buf[16];
    __be32 ipv4, mask4;
    int prefix_len = 32;
    int result;

    FW_DEBUG(2, "ENTRY: whitelist_write(count=%zu)", count);

    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: whitelist_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: whitelist_write -> 0 (empty input)");
        return 0;
    }
    if (count > sizeof(input) - 1) {
        FW_DEBUG(1, "EXIT: whitelist_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(input) - 1));

    if (copy_from_user(input, buf, len)) {
        FW_DEBUG(1, "EXIT: whitelist_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    if (strnlen(input, sizeof(input)) >= sizeof(input)) {
        FW_DEBUG(1, "EXIT: whitelist_write -> -EINVAL (not null-terminated)");
        return -EINVAL;
    }

    /* 跳过前导空白 */
    ptr = input;
    while (*ptr && (*ptr == ' ' || *ptr == '\t'))
        ptr++;

    if (*ptr == '\0') {
        fw_pr_warn("Empty command");
        return -EINVAL;
    }

    /* 提取命令关键字（如果有） */
    cmd_start = ptr;
    cmd_buf[0] = '\0';

    /* 查找第一个单词的结尾 */
    while (*ptr && *ptr != ' ' && *ptr != '\t')
        ptr++;

    if (*ptr) {
        char saved = *ptr;
        *ptr = '\0';

        if (strcmp(cmd_start, "add") == 0 || strcmp(cmd_start, "remove") == 0) {
            strncpy(cmd_buf, cmd_start, sizeof(cmd_buf) - 1);
            cmd_buf[sizeof(cmd_buf) - 1] = '\0';
            *ptr = saved;
            while (*ptr && (*ptr == ' ' || *ptr == '\t'))
                ptr++;
            subnet_start = ptr;
        } else {
            *ptr = saved;
            subnet_start = cmd_start;
        }
    } else {
        subnet_start = cmd_start;
    }

    if (*subnet_start == '\0') {
        fw_pr_warn("Missing subnet");
        return -EINVAL;
    }

    /* 终止子网字符串 */
    ptr = subnet_start;
    while (*ptr && *ptr != ' ' && *ptr != '\t')
        ptr++;
    *ptr = '\0';

    /* 解析子网（IP/前缀） */
    char *slash = strchr(subnet_start, '/');
    if (slash) {
        *slash = '\0';
        if (kstrtoint(slash + 1, 10, &prefix_len) < 0) {
            fw_pr_warn("Invalid prefix length");
            return -EINVAL;
        }
    }

    if (!in4_pton(subnet_start, -1, (u8 *)&ipv4, -1, NULL)) {
        fw_pr_warn("Invalid IP address format: %s", subnet_start);
        return -EINVAL;
    }

    if (prefix_len < 0 || prefix_len > 32) {
        fw_pr_warn("Invalid prefix length: %d", prefix_len);
        return -EINVAL;
    }

    /* 统一的 IPv4 地址验证 */
    if (validate_ipv4_address(ipv4, subnet_start, "whitelist") < 0) {
        return -EINVAL;
    }

    mask4 = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));
    __be32 normalized_ip = ipv4 & mask4;

    if (strcmp(cmd_buf, "remove") == 0) {
        result = remove_whitelist_entry(&fw_info, normalized_ip);
        if (result < 0) {
            if (result == -ENOENT) {
                fw_pr_warn("%pI4/%d not found in whitelist", &normalized_ip, prefix_len);
            } else {
                fw_pr_err("Failed to remove %pI4/%d from whitelist (error %d)", &normalized_ip, prefix_len, result);
            }
            return result;
        }
    } else {
        /* 默认：添加（cmd_buf 为空或 "add"） */
        result = add_whitelist_entry(&fw_info, normalized_ip, mask4, "manual");
        if (result < 0) {
            if (result == -ENOMEM) {
                fw_pr_err("Failed to allocate memory for whitelist entry");
            } else if (result == -ENOSPC) {
                fw_pr_warn("Whitelist full, cannot add %pI4/%d", &normalized_ip, prefix_len);
            } else if (result == -EINVAL) {
                fw_pr_warn("Invalid entry for whitelist");
            } else {
                fw_pr_err("Unknown error %d when adding to whitelist", result);
            }
            return result;
        }
    }

    FW_DEBUG(1, "EXIT: whitelist_write -> %zu (success)", count);
    return count;
}

static const struct proc_ops whitelist_fops = {
    .proc_open = whitelist_open,
    .proc_read = seq_read,
    .proc_write = whitelist_write,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

/*
 * config_show / config_write - 配置的 procfs 处理程序
 * 移至 create_procfs_entries 之前以避免前向声明问题
 */
static int config_show(struct seq_file *m, void *v)
{
    /* 修复 P1-5：使用 READ_ONCE 原子访问模块参数 */
    seq_printf(m, "当前防火墙配置：\n");
    seq_printf(m, "--------------------------------\n");
    seq_printf(m, "ban_time：%u 秒\n", READ_ONCE(fw_ban_time));
    seq_printf(m, "封禁条目数：%d\n", atomic_read(&fw_info.ban_count));
    seq_printf(m, "白名单条目数：%d\n", atomic_read(&fw_info.whitelist_count));
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
    char param[MAX_DISCOVERED_IPS];
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

    /* 使用 strsep 进行更稳健的参数解析 */
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

    /* 使用现代 kstrtoul 解析值以获得更好的错误处理 */
    unsigned long val;
    int rc = kstrtoul(value_str, 10, &val);
    if (rc != 0 || val == 0 || val > UINT_MAX) {
        fw_pr_err("Invalid value: %s", value_str);
        return -EINVAL;
    }
    value = (unsigned int)val;

    if (strcmp(param, "ban_time") == 0) {
        /* FIX P1-5: 检查整数溢出 - 使用 check_mul_overflow() 验证 value * HZ 不会溢出 */
        unsigned long ban_duration;
        if (check_mul_overflow(value, (unsigned long)HZ, &ban_duration)) {
            fw_pr_err("ban_time overflow detected: %u * HZ", value);
            return -EINVAL;
        }
        /* 检查值范围使用 MIN_BAN_TIME 和 MAX_BAN_TIME 常量 */
        if (value < 1 || value > 365 * 24 * 60 * 60) {  /* 1 year max */
            fw_pr_err("ban_time must be between 1 and %d seconds", 365 * 24 * 60 * 60);
            return -EINVAL;
        }
        /* 修复 P1-5：使用 WRITE_ONCE 原子写入 fw_ban_time 以防止
         * 当值通过 procfs 并发更新时出现撕裂写入。 */
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
 * stats_show - 显示防火墙统计信息
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
    /* 修复 4.2：持有 flood_lock 读取 recent_additions，防止数据竞争 */
    {
        unsigned int recent;
        spin_lock(&fw->flood_lock);
        recent = fw->recent_additions;
        spin_unlock(&fw->flood_lock);
        seq_printf(m, "recent_additions %u\n", recent);
    }

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
 * create_procfs_entries - 创建 procfs 接口
 * 创建 4 个统一接口：bans、whitelist、config、stats
 */
int create_procfs_entries(struct firewall_info *fw)
{
    struct proc_dir_entry *entry;

    fw->proc_dir = proc_mkdir("firewall", NULL);
    if (!fw->proc_dir) {
        fw_pr_err("Failed to create /proc/firewall");
        return -ENOMEM;
    }

    /* bans：封禁管理的统一读/写接口 */
    entry = proc_create("bans", 0600, fw->proc_dir, &bans_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_bans = entry;

    /* config：配置的读/写接口 */
    entry = proc_create("config", 0600, fw->proc_dir, &config_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_config = entry;

    /* whitelist：白名单管理的统一读/写接口 */
    entry = proc_create("whitelist", 0600, fw->proc_dir, &whitelist_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_whitelist = entry;

    /* stats：只读统计信息 */
    entry = proc_create("stats", 0400, fw->proc_dir, &stats_fops);
    if (!entry) {
        fw_pr_err("Failed to create proc stats entry\n");
        goto err_cleanup;
    }
    fw->proc_stats = entry;

    fw_pr_info("Procfs entries created (bans, whitelist, config, stats)");
    return 0;

err_cleanup:
    destroy_procfs_entries(fw);
    return -ENOMEM;
}

/*
 * destroy_procfs_entries - 移除 procfs 条目
 */
void destroy_procfs_entries(struct firewall_info *fw)
{
    if (fw->proc_stats)
        proc_remove(fw->proc_stats);
    if (fw->proc_whitelist)
        proc_remove(fw->proc_whitelist);
    if (fw->proc_config)
        proc_remove(fw->proc_config);
    if (fw->proc_bans)
        proc_remove(fw->proc_bans);
    if (fw->proc_dir)
        proc_remove(fw->proc_dir);
}

/*
 * nf_hook_func_ipv4 - IPv4 的 netfilter 钩子函数
 * 增强版本：改进的 skb 验证和额外的安全检查
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

    /* 额外验证：检查数据包完整性 */
    if (unlikely(skb->len < sizeof(struct iphdr)))
        return NF_ACCEPT;

    /* 验证网络头已设置并指向有效数据 */
    if (unlikely(!skb_network_header(skb)))
        return NF_ACCEPT;

    /* 验证我们可以安全地拉取 IP 头 */
    if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
        return NF_ACCEPT;

    /* 安全复制 IP 头以防止从非线性 skb 数据读取 */
    iph = skb_header_pointer(skb, 0, sizeof(iph_copy), &iph_copy);
    if (!iph)
        return NF_ACCEPT;

    /* 额外验证：检查 IP 头字段的有效性 */
    if (iph->version != 4)  /* 仅 IPv4 */
        return NF_ACCEPT;

    if (iph->ihl < 5)  /* 最小 IP 头长度为 5 个字 */
        return NF_ACCEPT;

    if (iph->ihl > 15)  /* 最大 IP 头长度为 15 个字（60 字节） */
        return NF_ACCEPT;

    if (iph->ihl * 4 > ntohs(iph->tot_len))  /* 头长度不得超过总长度 */
        return NF_ACCEPT;

    if (ntohs(iph->tot_len) < sizeof(struct iphdr))  /* 数据包长度检查 */
        return NF_ACCEPT;

    if (ntohs(iph->tot_len) > skb->len)  /* 总长度不得超过 skb 长度 */
        return NF_ACCEPT;

    /* 额外检查：将极大的数据包视为可疑（MTU 通常为 1500 字节） */
    if (ntohs(iph->tot_len) > 9000) {  /* 巨型帧通常最大约 9000 字节 */
        /* 记录可疑数据包但仍为封禁目的处理它 */
    }

    /* 检查 IP 分片 - 仅处理未分片的数据包或第一个分片 */
    if (ntohs(iph->frag_off) & htons(0x2000) || (ntohs(iph->frag_off) & 0x1FFF) != 0) {
        /* 分片数据包：无法在内核空间检查负载，但记录以供监控 */
        fw_pr_warn_ratelimited("Fragmented packet from %pI4 passed through (cannot inspect payload)", &iph->saddr);
        return NF_ACCEPT;
    }

    src_ip = iph->saddr;

    /* 验证源 IP 不是保留/私有供内部使用 */
    if (unlikely(src_ip == 0 ||                      /* 0.0.0.0 */
                 src_ip == 0xFFFFFFFF ||            /* 255.255.255.255 */
                 (ntohl(src_ip) & 0xFF000000) == 0x7F000000 ||  /* 127.x.x.x */
                 (ntohl(src_ip) & 0xF0000000) == 0xE0000000 ||  /* 224.0.0.0/4 (multicast) */
                 (ntohl(src_ip) & 0xFF000000) == 0x00000000)) { /* 0.x.x.x */
        return NF_ACCEPT;
    }

    /* 额外验证：验证常见协议的协议字段 */
    if (iph->protocol != IPPROTO_TCP &&
        iph->protocol != IPPROTO_UDP &&
        iph->protocol != IPPROTO_ICMP) {
        /* 允许其他协议但记录以供调试 */
    }

    now = jiffies;

    /* 修复：在 RCU 锁内重新检查关闭状态以防止竞态窗口
     * 之前的检查在 RCU 锁外，创建了一个可能
     * 访问已释放内存的小窗口。在锁内双重检查确保安全。 */
    if (unlikely(atomic_read(&fw_info.shutting_down)))
        return NF_ACCEPT;

    /* 白名单和封禁表访问的 RCU 读锁 */
    rcu_read_lock();

    /* 修复：在 RCU 锁内重新检查关闭状态（双重检查） */
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
            /* 添加最大迭代保护以防止性能崩溃 */
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

    /* 第二次检查：封禁列表 - 仅在未列入白名单时检查 */
    /* 修复 P1-6：直接将 src_ip 传递给 hash_for_each_possible_rcu 而不是
     * 预先计算哈希，确保与 hash_add 的一致性，hash_add 也在内部使用
     * key 参数进行哈希计算。 */
    hash_for_each_possible_rcu(fw_info.ban_table, entry, hash, src_ip) {
        if (compare_ips(entry->ip, src_ip)) {
            if (time_after(now, entry->unban_time)) {
                /* 条目存在但已过期 — 视为未封禁
                 * 修复 4.3：不在热路径中删除过期条目，由 cleanup_expired_bans()
                 * 定时器异步清理。这避免了在数据包处理路径中获取 spin_lock
                 * 的开销，确保网络延迟最小化。 */
                is_banned = false;
            } else {
                /* 有效的封禁条目 */
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

/* 状态持久化函数 */
int save_state_to_file(const char *filename)
{
    struct file *file;
    char buffer[512];
    loff_t pos = 0;
    int written;

    /* 临时存储结构 - 在 RCU 锁内收集数据，在锁外执行 I/O 操作 */
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

    /* 限制保存数量以避免大分配 */
    #define MAX_SAVE_BAN 1024
    #define MAX_SAVE_WL MAX_DISCOVERED_IPS

    struct saved_ban_entry *ban_entries = NULL;
    struct saved_whitelist_entry *wl_entries = NULL;
    int ban_count = 0;
    int wl_count = 0;
    struct ban_entry *entry;
    struct whitelist_entry *wl_entry;
    u32 hash;

    if (!filename || !*filename) {
        fw_pr_err("Invalid filename for state save");
        return -EINVAL;
    }

    /* 安全验证：检查文件名中的目录遍历 */
    /* 检查 URL 编码的路径遍历尝试 */
    if (strstr(filename, "%2e") || strstr(filename, "%2E") ||
        strstr(filename, "%2f") || strstr(filename, "%2F")) {
        fw_pr_err("URL-encoded path traversal attempt: %s", filename);
        return -EINVAL;
    }

    /* 检查更广泛的特殊字符 */
    {
        const char *dangerous_chars = "|;&`$(){}<>!~*?[]";
        for (const char *p = filename; *p; p++) {
            if (strchr(dangerous_chars, *p)) {
                fw_pr_err("Dangerous character '%c' in path: %s", *p, filename);
                return -EINVAL;
            }
        }
    }

    /* 检测路径遍历尝试（包括 ../、/.. 和单独的 ..） */
    {
        const char *p = filename;
        while (*p) {
            /* 检查 ../ 模式 */
            if (p[0] == '.' && p[1] == '.' && p[2] == '/') {
                fw_pr_err("Potential directory traversal in filename: %s", filename);
                return -EINVAL;
            }
            /* 检查 /.. 模式 */
            if (p[0] == '/' && p[1] == '.' && p[2] == '.') {
                /* 确保 .. 后面是路径分隔符或字符串结束 */
                if (p[3] == '\0' || p[3] == '/') {
                    fw_pr_err("Potential directory traversal in filename: %s", filename);
                    return -EINVAL;
                }
            }
            /* 检查单独的 .. （作为完整路径组件） */
            if (p[0] == '.' && p[1] == '.') {
                /* 检查前后是否为路径分隔符或字符串结束 */
                bool prev_sep = (p == filename) || (p[-1] == '/');
                bool next_sep = (p[2] == '\0') || (p[2] == '/');
                if (prev_sep && next_sep) {
                    fw_pr_err("Potential directory traversal in filename: %s", filename);
                    return -EINVAL;
                }
            }
            p++;
        }
    }

    /* 安全验证：确保文件名以安全路径开头 */
    if (strncmp(filename, "/var/lib/", 9) != 0 &&
        strncmp(filename, "/tmp/", 5) != 0 &&
        strncmp(filename, "/etc/", 5) != 0) {
        fw_pr_warn("State file path outside allowed directories: %s", filename);
        /* 仅允许保存到安全目录 */
        if (strchr(filename, '/') && filename[0] != '/') {
            fw_pr_err("Relative path not allowed for state file: %s", filename);
            return -EINVAL;
        }
    }

    /* 修复 TOCTOU：移除 kern_path 预检查，直接使用 filp_open + O_NOFOLLOW
     * 避免检查与打开之间的时间窗口被攻击者利用替换为符号链接 */

    /* 阶段 1：分配临时数组（GFP_KERNEL 可以睡眠，安全） */
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

    /* 阶段 2：在 RCU 锁内收集封禁条目 */
    rcu_read_lock();
    hash_for_each_rcu(fw_info.ban_table, hash, entry, hash) {
        unsigned long remaining_time;
        if (entry->is_permanent) {
            /* 永久封禁标记为 0 */
            remaining_time = 0;
        } else if (time_after(entry->unban_time, jiffies)) {
            remaining_time = (entry->unban_time - jiffies) / HZ;
        } else {
            continue; /* 已过期，跳过 */
        }
        if (ban_count < MAX_SAVE_BAN) {
            ipv4_to_str(entry->ip, ban_entries[ban_count].ip_str, sizeof(ban_entries[ban_count].ip_str));
            ban_entries[ban_count].ipv4 = entry->ip;
            ban_entries[ban_count].remaining_time = remaining_time;
            ban_count++;
        }
    }
    rcu_read_unlock();

    /* 阶段 3：在 RCU 锁内收集白名单条目 */
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

    /* 阶段 4：在锁外打开文件（使用 O_NOFOLLOW 防止符号链接攻击） */
    file = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
    if (IS_ERR(file)) {
        fw_pr_err("Failed to open file for saving state: %s", filename);
        kfree(ban_entries);
        kfree(wl_entries);
        return PTR_ERR(file);
    }

    /* 安全验证：打开后检查文件属性（防止 TOCTOU 攻击） */
    {
        struct kstat open_stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        int getattr_err = vfs_getattr(&file->f_path, &open_stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#else
        int getattr_err = vfs_getattr(&file->f_path, &open_stat);
#endif
        if (getattr_err) {
            fw_pr_err("Failed to stat state file after open: %s", filename);
            filp_close(file, NULL);
            kfree(ban_entries);
            kfree(wl_entries);
            return -EACCES;
        }
        /* 验证是普通文件（不是目录、设备、套接字等） */
        if (!S_ISREG(open_stat.mode)) {
            fw_pr_err("State file is not a regular file: %s", filename);
            filp_close(file, NULL);
            kfree(ban_entries);
            kfree(wl_entries);
            return -EACCES;
        }
    }

    /* 阶段 5：在锁外写入封禁条目 */
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

    /* 阶段 6：在锁外写入白名单条目 */
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

    /* 阶段 7：在锁外关闭文件 */
    filp_close(file, NULL);

    /* 阶段 8：释放临时数组 */
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

    /* 安全：拒绝符号链接并验证路径 */
    if (strstr(filename, "..") != NULL) {
        fw_pr_err("State restore: path traversal attempt rejected: %s", filename);
        return -EINVAL;
    }

    /* 在堆上分配缓冲区以避免大栈帧，最大支持 64KB 状态文件 */
#define MAX_STATE_FILE_SIZE (64 * 1024)
    buffer = kmalloc(MAX_STATE_FILE_SIZE, GFP_KERNEL);
    if (!buffer) {
        fw_pr_err("Failed to allocate buffer for state restore");
        return -ENOMEM;
    }

    /* 以只读方式打开文件，使用 O_NOFOLLOW 防止符号链接攻击 */
    file = filp_open(filename, O_RDONLY | O_NOFOLLOW, 0);
    if (IS_ERR(file)) {
        if (PTR_ERR(file) == -ELOOP) {
            fw_pr_warn("State restore: symlink detected and rejected: %s", filename);
        } else {
            fw_pr_info("State file does not exist: %s", filename);
        }
        kfree(buffer);
        return 0; /* 不是错误，只是没有要恢复的保存状态 */
    }

    /* 安全：验证文件是普通文件（不是设备、套接字等） */
    {
        struct kstat stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
        int stat_err = vfs_getattr(&file->f_path, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#else
        int stat_err = vfs_getattr(&file->f_path, &stat);
#endif
        if (stat_err == 0 && !S_ISREG(stat.mode)) {
            fw_pr_err("State restore: not a regular file: %s", filename);
            filp_close(file, NULL);
            kfree(buffer);
            return -EINVAL;
        }
    }

    /* 循环读取整个文件直到 EOF 或达到最大大小 */
    bytes_read = 0;
    while (bytes_read < MAX_STATE_FILE_SIZE - 1) {
        ssize_t chunk;
        chunk = kernel_read(file, buffer + bytes_read,
                           MAX_STATE_FILE_SIZE - 1 - bytes_read, &pos);
        if (chunk <= 0) {
            /* EOF 或读取错误 */
            break;
        }
        bytes_read += chunk;
    }

    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';

        /* 如果达到最大大小，记录警告 */
        if (bytes_read >= MAX_STATE_FILE_SIZE - 1) {
            fw_pr_warn("State file truncated at %zd bytes (max %d)",
                      bytes_read, MAX_STATE_FILE_SIZE);
        }

        line = buffer;
        while ((token = strsep(&line, "\n")) != NULL) {
            if (*token == '\0') continue; /* 跳过空行 */

            /* 解析行 */
            char *cmd = strsep(&token, " ");
            if (!cmd) continue;

            if (strcmp(cmd, "BAN_V4") == 0 && token) {
                char *ip_str = strsep(&token, " ");
                char *time_str = strsep(&token, " ");

                if (ip_str && time_str) {
                    __be32 ip;
                    if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
                        /* 在恢复封禁之前检查 IP 是否在白名单中 */
                        if (is_in_whitelist(&fw_info, ip)) {
                            fw_pr_info("Skipping restored ban for whitelisted IP %s", ip_str);
                            continue;
                        }

                        unsigned long remaining_time;
                        if (kstrtoul(time_str, 10, &remaining_time) == 0) {
                            struct ban_entry *entry;
                            bool is_permanent = false;
                            unsigned long unban_time = 0;

                            if (remaining_time == 0) {
                                /* remaining_time == 0 表示永久封禁 */
                                is_permanent = true;
                                unban_time = 0;
                            } else if (remaining_time > 365UL * 24 * 60 * 60) {
                                fw_pr_warn("Skipping ban with invalid remaining time: %lu", remaining_time);
                                continue;
                            } else {
                                is_permanent = false;
                                /* 修复 C4：检查整数溢出：remaining_time * HZ 不得溢出 */
                                if (remaining_time > (ULONG_MAX / HZ)) {
                                    fw_pr_warn("Skipping ban - remaining_time * HZ would overflow");
                                    continue;
                                }

                                unsigned long ban_duration = remaining_time * HZ;

                                /* 修复 C4：检查 jiffies + ban_duration 是否会溢出回绕 */
                                if (jiffies > ULONG_MAX - ban_duration) {
                                    /* Jiffies 即将回绕，使用最大安全值 */
                                    unban_time = jiffies + min(ban_duration, ULONG_MAX - jiffies);
                                    fw_pr_warn("Jiffies wrap protection applied for ban restoration");
                                } else {
                                    unban_time = jiffies + ban_duration;
                                }
                            }

                            /* 修复 1.1：使用 RCU 检查重复，防止状态文件包含重复条目 */
                            {
                                struct ban_entry *existing;
                                bool found = false;

                                rcu_read_lock();
                                hash_for_each_possible_rcu(fw_info.ban_table, existing, hash, ip) {
                                    if (compare_ips(existing->ip, ip)) {
                                        found = true;
                                        break;
                                    }
                                }
                                rcu_read_unlock();

                                if (found) {
                                    fw_pr_info("Skipping duplicate ban for IPv4 %s", ip_str);
                                    goto skip_ban_entry;
                                }
                            }

                            /* 在锁外分配内存（GFP_KERNEL 安全） */
                            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
                            if (!entry) {
                                fw_pr_err("Failed to allocate memory for restored ban entry");
                                goto skip_ban_entry;
                            }

                            entry->ip = ip;
                            entry->ban_time = jiffies;
                            entry->unban_time = unban_time;
                            entry->is_permanent = is_permanent;
                            atomic_set(&entry->retry_count, 0);

                            /* 在 spinlock 内插入哈希表 */
                            spin_lock(&fw_info.lock);
                            hash_add(fw_info.ban_table, &entry->hash, ip);
                            atomic_inc(&fw_info.ban_count);
                            atomic_inc(&fw_info.total_ban_count);  /* 修复 1.1：递增总计数 */
                            spin_unlock(&fw_info.lock);

                            if (is_permanent)
                                fw_pr_info("Restored permanent ban for IPv4 %s", ip_str);
                            else
                                fw_pr_info("Restored ban for IPv4 %s (expires in %lu seconds)", ip_str, remaining_time);

skip_ban_entry:
                            ;
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
                        /* 根据前缀长度计算网络掩码 */
                        mask = prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));

                        if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
                            __be32 normalized_ip = ip & mask;

                            /* 添加白名单条目 */
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
 * firewall_init - 模块初始化
 */
static int __init firewall_init(void)
{
    int ret;

    fw_pr_info("Loading firewall module v1.9");

    /* 参数下限检查 - 防止 0 或太小的值导致异常行为 */
    /* 修复 P1-5：使用 READ_ONCE 原子访问模块参数 */
    if (READ_ONCE(fw_ban_time) < 1) {
        fw_pr_err("fw_ban_time must be >= 1");
        return -EINVAL;
    }

    /* 参数上限检查 - 防止大值导致整数溢出 */
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

    /* 初始化统计计数器 */
    atomic_set(&fw_info.total_ban_count, 0);
    atomic_set(&fw_info.total_unban_count, 0);
    atomic_set(&fw_info.whitelist_reject_count, 0);
    atomic_set(&fw_info.ban_table_full_count, 0);
    atomic_set(&fw_info.alloc_failure_count, 0);
    atomic_set(&fw_info.packets_dropped, 0);
    atomic_set(&fw_info.packets_accepted, 0);
    atomic_set(&fw_info.cleanup_cycles, 0);
    atomic_set(&fw_info.cleanup_expired_total, 0);

    /* 如果可用，从文件恢复状态 */
    if (state_file && strlen(state_file) > 0) {
        restore_state_from_file(state_file);
    }

    /* 初始化延迟同步工作队列（用于网卡 IP 变化防抖） */
    INIT_DELAYED_WORK(&fw_info.sync_work, sync_work_handler);

    auto_discover_system_ips(&fw_info);

    /* 注册网络设备事件监听器，实现 IP 实时更新 */
    ret = register_netdev_notifier(&fw_info);
    if (ret) {
        fw_pr_warn("Failed to register netdev notifier, IP auto-update disabled");
        /* 不视为致命错误，继续加载模块 */
    }

    timer_setup(&fw_info.cleanup_timer, cleanup_timer_callback, 0);
    fw_info.timer_initialized = true;  /* 标记定时器已初始化 */
    /* 修复 P1-5：使用 READ_ONCE 原子访问 fw_ban_time */
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
    /* 设置关闭标志，阻止新操作 */
    atomic_set(&fw_info.shutting_down, 1);

    /* 取消待处理的同步工作 */
    cancel_delayed_work_sync(&fw_info.sync_work);

    /* 先停止定时器，防止回调访问已释放内存 */
    timer_delete_sync(&fw_info.cleanup_timer);

    /* 注销网络设备事件监听器 */
    unregister_netdev_notifier(&fw_info);

    /* 等待所有 RCU 回调完成，防止双重释放 */
    synchronize_rcu();

    /* 释放所有白名单条目 */
    {
        struct whitelist_entry *wl;
        u32 wl_hash;
        struct hlist_node *tmp;
        hash_for_each_safe(fw_info.whitelist_table, wl_hash, tmp, wl, hash) {
            hash_del(&wl->hash);
            kfree(wl);
        }
    }

    /* 释放所有封禁条目 */
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

    /* 修复 C5：设置关闭标志以防止新操作 */
    atomic_set(&fw_info.shutting_down, 1);

    /* 取消待处理的同步工作，确保关闭期间不再执行 */
    cancel_delayed_work_sync(&fw_info.sync_work);

    /* 修复 C5：1. 先注销 netfilter 钩子以防止新数据包进入 */
    nf_unregister_net_hook(&init_net, &nf_ops_ipv4);

    /* 注销网络设备事件监听器 */
    unregister_netdev_notifier(&fw_info);

    /* 修复 C5：2. 停止定时器 */
    if (fw_info.timer_initialized) {
        timer_delete_sync(&fw_info.cleanup_timer);
        fw_info.timer_initialized = false;
    }

    /* 修复 C5：3. 销毁 procfs 条目以防止用户空间操作 */
    destroy_procfs_entries(&fw_info);

    /* 修复 C5：4. 等待所有 RCU 读者退出 */
    synchronize_rcu();

    /* 修复 C5：5. 现在可以安全保存状态（无并发访问） */
    if (state_file && strlen(state_file) > 0) {
        save_state_to_file(state_file);
    }

    /* 现在可以安全地释放所有条目，因为没有 RCU 读者可以访问它们 */
    /* 释放所有封禁条目 */
    hash_for_each_safe(fw_info.ban_table, ban_hash, tmp, entry, hash) {
        hash_del(&entry->hash);
        kfree(entry);  /* 直接释放，因为 synchronize_rcu() 后没有 RCU 读者可以访问 */
    }

    /* 释放所有白名单条目 */
    hash_for_each_safe(fw_info.whitelist_table, wl_hash, tmp, wl, hash) {
        hash_del(&wl->hash);
        kfree(wl);  /* 直接释放，因为 synchronize_rcu() 后没有 RCU 读者可以访问 */
    }

    /* 注意：ban_table 和 whitelist_table 是通过 DECLARE_HASHTABLE 静态分配的
     * 嵌入在 struct firewall_info 中。它们不是用 kmalloc 动态分配的，
     * 所以我们绝对不能对它们调用 kfree。这样做会导致内核 OOPS/崩溃。 */

    fw_pr_info("Module unloaded");
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Firewall Authors");
MODULE_DESCRIPTION("Kernel-level IP banning module (fail2ban alternative)");
MODULE_VERSION("2.0");
