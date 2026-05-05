/*
 * procfs.c - procfs 接口
 *
 * 包含所有 procfs 文件操作相关的函数实现，包括 bans、whitelist、config、stats 接口。
 */

#include "firewall.h"

/* 外部变量声明 */
extern unsigned int fw_ban_time;
extern char *state_file;
extern unsigned int fw_max_bans_per_second;
extern struct firewall_info fw_info;

/* 前向声明 */
static int bans_show(struct seq_file *m, void *v);
static int bans_open(struct inode *inode, struct file *file);
static ssize_t bans_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos);

/*
 * bans_show - 显示当前封禁列表
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
        if (entry->is_permanent) {
            ipv4_to_str(entry->ip, ip_str, sizeof(ip_str));
            seq_printf(m, "%-40s（永久）\n", ip_str);
            permanent_count++;
            count++;
        } else if (!time_after(now, entry->unban_time)) {
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

/* ============================================================================
 * bans_write 辅助函数 - 拆分单一职责
 * ========================================================================== */

/**
 * validate_ban_input - 校验用户输入的安全性和格式
 * @input: 用户输入字符串（已拷贝到内核空间）
 * 返回: 0 表示校验通过，负数错误码表示失败
 */
static int validate_ban_input(const char *input)
{
    if (strstr(input, "..") != NULL) {
        fw_pr_warn("Path traversal attempt detected: %s", input);
        return -EINVAL;
    }

    {
        char lower_input[256];
        size_t i;

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

    return 0;
}

/**
 * parse_ban_command - 解析封禁命令类型和 IP 地址
 * @input: 用户输入字符串
 * @ip_str: 输出参数，存储解析出的 IP 字符串
 * @ip_str_size: ip_str 缓冲区大小
 * @is_unban: 输出参数，是否为 unban 命令
 * 返回: 0 表示解析成功，负数错误码表示失败
 */
static int parse_ban_command(const char *input, char *ip_str, size_t ip_str_size,
                             bool *is_unban)
{
    const char *cmd_ptr = input;

    /* 跳过前导空白 */
    while (*cmd_ptr && (*cmd_ptr == ' ' || *cmd_ptr == '\t'))
        cmd_ptr++;

    if (*cmd_ptr == '\0') {
        fw_pr_warn("Empty command");
        return -EINVAL;
    }

    /* 检查是否为 unban 命令 */
    if (strncmp(cmd_ptr, "unban ", 6) == 0 || strncmp(cmd_ptr, "unban\t", 6) == 0) {
        const char *ip_start = cmd_ptr + 5;
        while (*ip_start && (*ip_start == ' ' || *ip_start == '\t'))
            ip_start++;

        if (*ip_start == '\0') {
            fw_pr_warn("Missing IP address after 'unban'");
            return -EINVAL;
        }

        const char *ip_end = ip_start;
        while (*ip_end && *ip_end != ' ' && *ip_end != '\t')
            ip_end++;
        if (*ip_end != '\0') {
            fw_pr_warn("Invalid format - extra content after IP: %s", input);
            return -EINVAL;
        }

        strncpy(ip_str, ip_start, ip_str_size - 1);
        ip_str[ip_str_size - 1] = '\0';
        *is_unban = true;
        return 0;
    }

    /* ban 命令：提取 IP 地址 */
    {
        const char *ptr = cmd_ptr;
        const char *ip_start = ptr;

        while (*ptr && *ptr != ' ' && *ptr != '\t')
            ptr++;

        if (*ptr == '\0' || *(ptr + 1) == '\0') {
            /* 只有 IP，无持续时间 */
            strncpy(ip_str, ip_start, ip_str_size - 1);
            ip_str[ip_str_size - 1] = '\0';
        } else {
            /* IP 后面有内容，提取 IP 部分 */
            size_t ip_len = ptr - ip_start;
            if (ip_len >= ip_str_size)
                ip_len = ip_str_size - 1;
            strncpy(ip_str, ip_start, ip_len);
            ip_str[ip_len] = '\0';
        }
    }

    *is_unban = false;
    return 0;
}

/**
 * parse_ban_duration - 解析封禁持续时间
 * @input: 用户输入字符串
 * 返回: 持续时间（秒），特殊值含义：
 *       -2 = 使用默认持续时间
 *       -1 = unban 操作
 *        0 = 永久封禁
 *       >0 = 指定秒数
 *       负数错误码 = 解析失败
 */
static long parse_ban_duration(const char *input)
{
    const char *ptr = input;
    const char *space_pos = NULL;

    /* 跳过前导空白 */
    while (*ptr && (*ptr == ' ' || *ptr == '\t'))
        ptr++;

    /* 找到 IP 后的空白位置 */
    while (*ptr && *ptr != ' ' && *ptr != '\t')
        ptr++;

    if (*ptr == '\0') {
        /* 没有持续时间，使用默认值 */
        return -2;
    }

    /* 跳过空白，定位到持续时间内 */
    space_pos = ptr + 1;
    while (*space_pos && (*space_pos == ' ' || *space_pos == '\t'))
        space_pos++;

    if (*space_pos == '\0') {
        /* 空白后无内容，使用默认值 */
        return -2;
    }

    {
        char *endp;
        long seconds = simple_strtol(space_pos, &endp, 10);

        if (endp == space_pos || *endp != '\0') {
            fw_pr_warn("Invalid format - invalid seconds value: %s", input);
            return -EINVAL;
        }

        if (seconds < 0 && seconds != -1) {
            fw_pr_warn("Invalid ban duration: %ld", seconds);
            return -EINVAL;
        }

        if (seconds > MAX_BAN_TIME) {
            fw_pr_warn("Ban duration %ld exceeds maximum %d seconds", seconds, MAX_BAN_TIME);
            return -EINVAL;
        }

        return seconds;
    }
}

/**
 * execute_ban_action - 执行封禁/解封动作
 * @ip: IPv4 地址
 * @ip_str: IP 字符串（用于日志）
 * @seconds: 持续时间（由 parse_ban_duration 解析）
 * @is_unban: 是否为解封操作
 * 返回: 0 表示成功，负数错误码表示失败
 */
static int execute_ban_action(__be32 ip, const char *ip_str, long seconds, bool is_unban)
{
    int result;

    if (is_unban || (seconds < 0 && seconds != -2)) {
        /* 解封操作 */
        result = unban_ip(&fw_info, ip);
        if (result < 0) {
            if (result == -ENOENT)
                fw_pr_warn("IP %s not found in ban list", ip_str);
            else
                fw_pr_err("Failed to unban IP %s (error %d)", ip_str, result);
            return result;
        }
        return 0;
    }

    if (seconds == 0) {
        /* 永久封禁 */
        result = ban_ip_permanent(&fw_info, ip);
        if (result < 0) {
            if (result == -EPERM)
                fw_pr_info("Requested IPv4 %s is in whitelist, not permanently banned", ip_str);
            else if (result == -ENOMEM)
                fw_pr_err("Failed to allocate memory for permanent ban entry for IPv4 %s", ip_str);
            else if (result == -ENOSPC)
                fw_pr_warn("Ban table full, cannot permanently ban IPv4 %s", ip_str);
            else
                fw_pr_err("Unknown error %d when trying to permanently ban IPv4 %s", result, ip_str);
            return result;
        }
        return 0;
    }

    /* 需要泛洪保护的情况：默认持续时间或指定持续时间 */
    if (check_flood_protection() < 0) {
        fw_pr_warn("Flood protection triggered - too many ban requests");
        return -EBUSY;
    }

    if (seconds == -2) {
        /* 默认持续时间封禁 */
        result = ban_ip(&fw_info, ip);
    } else {
        /* 指定持续时间封禁 */
        result = ban_ip_with_duration(&fw_info, ip, (unsigned long)seconds);
    }

    if (result < 0) {
        if (result == -EPERM)
            fw_pr_info("Requested IPv4 %s is in whitelist, not banned", ip_str);
        else if (result == -ENOMEM)
            fw_pr_err("Failed to allocate memory for ban entry for IPv4 %s", ip_str);
        else if (result == -ENOSPC)
            fw_pr_warn("Ban table full, cannot ban IPv4 %s", ip_str);
        else
            fw_pr_err("Unknown error %d when trying to ban IPv4 %s", result, ip_str);
        return result;
    }

    return 0;
}

/*
 * bans_write - 封禁管理的统一写入处理程序
 * 支持的命令格式：
 *   "unban <ip>"      - 解封 IP
 *   "<ip>"            - 使用默认持续时间封禁
 *   "<ip> <seconds>"  - 指定持续时间封禁（秒）
 *   "<ip> 0"          - 永久封禁
 *   "<ip> -1"         - 解封 IP
 */
static ssize_t bans_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos)
{
    char input[256];
    char ip_str[INET_ADDRSTRLEN];
    __be32 ip;
    long seconds;
    ssize_t len;
    int result;
    bool is_unban = false;

    FW_DEBUG(2, "ENTRY: bans_write(count=%zu)", count);

    /* 权限和输入长度校验 */
    if (!capable(CAP_NET_ADMIN)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EPERM (no capability)");
        return -EPERM;
    }
    if (count == 0) {
        FW_DEBUG(2, "EXIT: bans_write -> 0 (empty input)");
        return 0;
    }
    if (count > sizeof(input) - 1) {
        FW_DEBUG(1, "EXIT: bans_write -> -EINVAL (input too large: %zu)", count);
        return -EINVAL;
    }
    len = min(count, (size_t)(sizeof(input) - 1));

    if (copy_from_user(input, buf, len)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EFAULT (copy_from_user failed)");
        return -EFAULT;
    }

    input[len] = '\0';
    if (len > 0 && input[len - 1] == '\n')
        input[len - 1] = '\0';

    if (strnlen(input, sizeof(input)) >= sizeof(input)) {
        FW_DEBUG(1, "EXIT: bans_write -> -EINVAL (not null-terminated)");
        return -EINVAL;
    }

    /* 安全性校验 */
    result = validate_ban_input(input);
    if (result < 0)
        return result;

    /* 解析命令类型和 IP */
    result = parse_ban_command(input, ip_str, sizeof(ip_str), &is_unban);
    if (result < 0)
        return result;

    /* 解析 IP 地址 */
    if (!in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
        fw_pr_warn("Invalid IP address format: %s", ip_str);
        return -EINVAL;
    }

    /* 验证 IP 合法性 */
    if (validate_ipv4_address(ip, ip_str, "ban") < 0) {
        return -EINVAL;
    }

    /* 私有 IP 警告 */
    {
        unsigned int ip_class_a = (ntohl(ip) >> 24) & 0xFF;
        unsigned int ip_class_b = (ntohl(ip) >> 16) & 0xFF;
        if ((ip_class_a == 10) ||
            (ip_class_a == 172 && ip_class_b >= 16 && ip_class_b <= 31) ||
            (ip_class_a == 192 && ip_class_b == 168)) {
            fw_pr_warn("Attempt to ban private IPv4 range %pI4 - this may be unintended", &ip);
        }
    }

    /* 解析持续时间（仅对 ban 命令需要） */
    if (!is_unban) {
        seconds = parse_ban_duration(input);
        if (seconds < 0 && seconds != -1 && seconds != -2) {
            return (int)seconds;
        }
    } else {
        seconds = -1; /* unban 操作 */
    }

    /* 执行封禁/解封动作 */
    result = execute_ban_action(ip, ip_str, seconds, is_unban);
    if (result < 0)
        return result;

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
 * whitelist_read - 显示白名单条目
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

    ptr = input;
    while (*ptr && (*ptr == ' ' || *ptr == '\t'))
        ptr++;

    if (*ptr == '\0') {
        fw_pr_warn("Empty command");
        return -EINVAL;
    }

    cmd_start = ptr;
    cmd_buf[0] = '\0';

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

    ptr = subnet_start;
    while (*ptr && *ptr != ' ' && *ptr != '\t')
        ptr++;
    *ptr = '\0';

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
 * config_show - 显示配置
 */
static int config_show(struct seq_file *m, void *v)
{
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

/*
 * config_write - 配置写入处理程序
 */
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

    unsigned long val;
    int rc = kstrtoul(value_str, 10, &val);
    if (rc != 0 || val == 0 || val > UINT_MAX) {
        fw_pr_err("Invalid value: %s", value_str);
        return -EINVAL;
    }
    value = (unsigned int)val;

    if (strcmp(param, "ban_time") == 0) {
        unsigned long ban_duration;
        if (check_mul_overflow(value, (unsigned long)HZ, &ban_duration)) {
            fw_pr_err("ban_time overflow detected: %u * HZ", value);
            return -EINVAL;
        }
        if (value < 1 || value > 365 * 24 * 60 * 60) {
            fw_pr_err("ban_time must be between 1 and %d seconds", 365 * 24 * 60 * 60);
            return -EINVAL;
        }
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
 */
int create_procfs_entries(struct firewall_info *fw)
{
    struct proc_dir_entry *entry;

    fw->proc_dir = proc_mkdir("firewall", NULL);
    if (!fw->proc_dir) {
        fw_pr_err("Failed to create /proc/firewall");
        return -ENOMEM;
    }

    entry = proc_create("bans", 0600, fw->proc_dir, &bans_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_bans = entry;

    entry = proc_create("config", 0600, fw->proc_dir, &config_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_config = entry;

    entry = proc_create("whitelist", 0600, fw->proc_dir, &whitelist_fops);
    if (!entry)
        goto err_cleanup;
    fw->proc_whitelist = entry;

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
EXPORT_SYMBOL_GPL(create_procfs_entries);

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
EXPORT_SYMBOL_GPL(destroy_procfs_entries);
