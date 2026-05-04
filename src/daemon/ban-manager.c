/*
 * ban-manager.c - 封禁/解封操作
 */

#include "firewall-daemon.h"
#include "ban-manager.h"

/*
 * validate_ipv4 - 验证并解析IPv4地址字符串
 * @ip: 要验证的IP地址字符串
 * @out: 存储解析后地址的输出结构（可为NULL）
 *
 * 返回值：成功返回0，失败返回-1
 * 
 * 验证内容：
 * - 非NULL、非空字符串
 * - 长度 < INET_ADDRSTRLEN
 * - 通过 inet_pton 验证有效的IPv4格式
 * - 拒绝：0.0.0.0、255.255.255.255、127.0.0.0/8、224.0.0.0/4（组播）
 */
int validate_ipv4(const char *ip, validated_ip_t *out)
{
    struct in_addr addr4;
    size_t ip_len;

    if (!ip) {
        return -1;
    }

    ip_len = strlen(ip);
    if (ip_len == 0 || ip_len >= INET_ADDRSTRLEN) {
        return -1;
    }

    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        return -1;
    }

    // 额外验证：拒绝无效IPv4地址，如 0.0.0.0、127.x.x.x、组播地址等
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x（回环地址）
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4（组播地址）
        return -1;
    }

    if (out) {
        out->addr = addr4;
        out->ip_num = addr4.s_addr;  // 网络字节序
    }

    return 0;
}

/* 安全的procfs文件操作辅助函数 */
int secure_procfs_write(const char *path, const char *data, size_t data_len) {
    int fd;
    ssize_t written;
    size_t total_written = 0;

    /* 验证输入参数 */
    if (!path || !data || data_len == 0) {
        daemon_log_err("Invalid parameters to secure_procfs_write");
        return -1;
    }

    /* 安全检查：验证路径在 /proc/firewall/ 内 */
    if (strncmp(path, PROCFS_DIR "/", sizeof(PROCFS_DIR)) != 0) {
        daemon_log_err("secure_procfs_write: path outside %s: %s", PROCFS_DIR, path);
        return -1;
    }

    /* 拒绝路径遍历尝试 */
    if (strstr(path, "..") != NULL) {
        daemon_log_err("secure_procfs_write: path traversal attempt: %s", path);
        return -1;
    }

    /* 检查数据长度以防止过长的写入 */
    if (data_len > 256) {
        daemon_log_err("Data too long for procfs write (%zu bytes)", data_len);
        return -1;
    }

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    // 以可控方式写入数据
    while (total_written < data_len) {
        written = write(fd, data + total_written, data_len - total_written);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;  // 被中断或资源暂时不可用，重试
            } else {
                daemon_log_err("Failed to write to %s: %s", path, strerror(errno));
                close(fd);
                return -1;
            }
        }
        total_written += written;
    }

    // 关闭文件描述符
    if (close(fd) < 0) {
        daemon_log_warn("Failed to close %s: %s", path, strerror(errno));
        /* 写入成功，因此返回成功。procfs 关闭失败很罕见且通常非致命（如 EINTR）。*/
    }

    return 0;
}

/*
 * execute_ban_action - 统一的封禁/解封操作
 * @action: 要执行的封禁/解封操作类型
 * @ip: IPv4地址字符串
 *
 * 返回值：成功返回0，失败返回-1
 */
int execute_ban_action(ban_action_t action, const char *ip)
{
    validated_ip_t validated;
    char cmd_buf[INET_ADDRSTRLEN + 16];
    int cmd_len;

    if (!ip) {
        daemon_log_err("NULL IP address provided to execute_ban_action");
        return -1;
    }

    if (validate_ipv4(ip, &validated) < 0) {
        daemon_log_err("Invalid IPv4 address: %s", ip);
        return -1;
    }

    /* 根据操作类型格式化命令 */
    switch (action) {
    case BAN_ACTION_TEMP:
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", ip);
        break;
    case BAN_ACTION_PERMANENT:
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s 0\n", ip);
        break;
    case BAN_ACTION_UNBAN:
    case BAN_ACTION_UNBAN_PERM:
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "unban %s\n", ip);
        break;
    default:
        daemon_log_err("Unknown ban action type: %d", action);
        return -1;
    }

    if (cmd_len < 0 || (size_t)cmd_len >= sizeof(cmd_buf)) {
        daemon_log_err("Command buffer overflow for IP %s", ip);
        return -1;
    }

    /* 通过procfs写入内核模块 */
    if (secure_procfs_write(BANS_PATH, cmd_buf, (size_t)cmd_len) < 0) {
        daemon_log_err("Failed to write to %s", BANS_PATH);
        return -1;
    }

    /* 处理永久封禁操作的SQLite持久化 */
    if (sqlite_db) {
        int sqlite_rc = 0;
        if (action == BAN_ACTION_PERMANENT) {
            sqlite_rc = sqlite_add_permanent_ban(sqlite_db, ip, validated.ip_num,
                                                 "manual permanent ban", "manual");
        } else if (action == BAN_ACTION_UNBAN_PERM) {
            sqlite_rc = sqlite_remove_permanent_ban(sqlite_db, ip);
        }

        if (sqlite_rc != 0 && sqlite_rc != -2) {  /* -2 = 已存在（不是错误） */
            daemon_log_warn("SQLite operation failed for IP %s (action=%d, rc=%d)", ip, action, sqlite_rc);
        }
    }

    /* 更新封禁操作的统计和日志 */
    if (action == BAN_ACTION_TEMP || action == BAN_ACTION_PERMANENT) {
        atomic_fetch_add(&daemon_stats.ips_banned, 1);
    }

    /* 记录操作日志 */
    switch (action) {
    case BAN_ACTION_TEMP:
        daemon_log_info("Banned IP %s", ip);
        break;
    case BAN_ACTION_PERMANENT:
        daemon_log_info("Permanently banned IP %s", ip);
        break;
    case BAN_ACTION_UNBAN:
        daemon_log_info("Unbanned IP %s", ip);
        break;
    case BAN_ACTION_UNBAN_PERM:
        daemon_log_info("Removed permanent ban for IP %s", ip);
        break;
    }

    return 0;
}

/* 向后兼容的包装函数 */
int ban_ip(const char *ip)
{
    return execute_ban_action(BAN_ACTION_TEMP, ip);
}

int ban_ip_permanent(const char *ip)
{
    return execute_ban_action(BAN_ACTION_PERMANENT, ip);
}

int unban_ip(const char *ip)
{
    return execute_ban_action(BAN_ACTION_UNBAN, ip);
}

int unban_permanent_ip(const char *ip)
{
    return execute_ban_action(BAN_ACTION_UNBAN_PERM, ip);
}

/* 清理过期封禁和部分行缓冲区（可选，内核已处理） */
void cleanup_expired_bans(void)
{
    /* 内核模块通过定时器自动清理 */
    /* 此函数是未来同步逻辑的占位符 */

    /* 同时定期清理部分行缓冲区以防止累积 */
    cleanup_partial_line_buffer();
}