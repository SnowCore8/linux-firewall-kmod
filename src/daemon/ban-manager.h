/*
 * ban-manager.h - Header for ban/unban operations
 */

#ifndef BAN_MANAGER_H
#define BAN_MANAGER_H

#include "firewall-daemon.h"

/* Validate and parse an IPv4 address string */
int validate_ipv4(const char *ip, validated_ip_t *out);

/* Secure procfs file operation helper */
int secure_procfs_write(const char *path, const char *data, size_t data_len);

/* Unified ban/unban operation */
int execute_ban_action(ban_action_t action, const char *ip);

/* Backward-compatible wrapper functions */
int ban_ip(const char *ip);
int ban_ip_permanent(const char *ip);
int unban_ip(const char *ip);
int unban_permanent_ip(const char *ip);

/* Cleanup expired bans and partial line buffer */
void cleanup_expired_bans(void);

#endif /* BAN_MANAGER_H */