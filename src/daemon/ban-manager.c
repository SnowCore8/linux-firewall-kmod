/*
 * ban-manager.c - Ban/unban operations
 */

#include "firewall-daemon.h"
#include "ban-manager.h"

/*
 * validate_ipv4 - Validate and parse an IPv4 address string
 * @ip: IP address string to validate
 * @out: Output structure to store parsed address (may be NULL)
 *
 * Returns: 0 on success, -1 on failure
 * 
 * Validates:
 * - Non-NULL, non-empty string
 * - Length < INET_ADDRSTRLEN
 * - Valid IPv4 format via inet_pton
 * - Rejects: 0.0.0.0, 255.255.255.255, 127.0.0.0/8, 224.0.0.0/4 (multicast)
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

    // Additional validation: reject invalid IPv4 IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4 (multicast)
        return -1;
    }

    if (out) {
        out->addr = addr4;
        out->ip_num = addr4.s_addr;  // network byte order
    }

    return 0;
}

/* Secure procfs file operation helper */
int secure_procfs_write(const char *path, const char *data, size_t data_len) {
    int fd;
    ssize_t written;
    size_t total_written = 0;

    /* Validate inputs */
    if (!path || !data || data_len == 0) {
        daemon_log_err("Invalid parameters to secure_procfs_write");
        return -1;
    }

    /* Security: Validate path is within /proc/firewall/ */
    if (strncmp(path, PROCFS_DIR "/", sizeof(PROCFS_DIR)) != 0) {
        daemon_log_err("secure_procfs_write: path outside %s: %s", PROCFS_DIR, path);
        return -1;
    }

    /* Reject path traversal attempts */
    if (strstr(path, "..") != NULL) {
        daemon_log_err("secure_procfs_write: path traversal attempt: %s", path);
        return -1;
    }

    /* Check data length to prevent excessively long writes */
    if (data_len > 256) {
        daemon_log_err("Data too long for procfs write (%zu bytes)", data_len);
        return -1;
    }

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    // Write data in a controlled manner
    while (total_written < data_len) {
        written = write(fd, data + total_written, data_len - total_written);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;  // Interrupted or resource temporarily unavailable, try again
            } else {
                daemon_log_err("Failed to write to %s: %s", path, strerror(errno));
                close(fd);
                return -1;
            }
        }
        total_written += written;
    }

    // Close file descriptor
    if (close(fd) < 0) {
        daemon_log_warn("Failed to close %s: %s", path, strerror(errno));
        /* Write succeeded, so return success. Close failure on procfs
         * is rare and typically non-fatal (e.g., EINTR). */
    }

    return 0;
}

/*
 * execute_ban_action - Unified ban/unban operation
 * @action: Type of ban/unban action to perform
 * @ip: IPv4 address string
 *
 * Returns: 0 on success, -1 on failure
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

    /* Format command based on action type */
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

    /* Write to kernel module via procfs */
    if (secure_procfs_write(BANS_PATH, cmd_buf, (size_t)cmd_len) < 0) {
        daemon_log_err("Failed to write to %s", BANS_PATH);
        return -1;
    }

    /* Handle SQLite persistence for permanent ban actions */
    if (sqlite_db) {
        int sqlite_rc = 0;
        if (action == BAN_ACTION_PERMANENT) {
            sqlite_rc = sqlite_add_permanent_ban(sqlite_db, ip, validated.ip_num,
                                                 "manual permanent ban", "manual");
        } else if (action == BAN_ACTION_UNBAN_PERM) {
            sqlite_rc = sqlite_remove_permanent_ban(sqlite_db, ip);
        }

        if (sqlite_rc != 0 && sqlite_rc != -2) {  /* -2 = already exists (not an error) */
            daemon_log_warn("SQLite operation failed for IP %s (action=%d, rc=%d)", ip, action, sqlite_rc);
        }
    }

    /* Update statistics and log for ban actions */
    if (action == BAN_ACTION_TEMP || action == BAN_ACTION_PERMANENT) {
        atomic_fetch_add(&daemon_stats.ips_banned, 1);
    }

    /* Log the action */
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

/* Backward-compatible wrapper functions */
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

/* Cleanup expired bans and partial line buffer (optional, kernel handles this) */
void cleanup_expired_bans(void)
{
    /* Kernel module handles automatic cleanup via timer */
    /* This function is placeholder for future sync logic */

    /* Also clean up the partial line buffer periodically to prevent accumulation */
    cleanup_partial_line_buffer();
}