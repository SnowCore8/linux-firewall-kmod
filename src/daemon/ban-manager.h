/*
 * ban-manager.h - 封禁/解封操作头文件 (支持 IPv4/IPv6)
 */

#ifndef BAN_MANAGER_H
#define BAN_MANAGER_H

#include "firewall-daemon.h"

/* 验证并解析 IPv4 地址字符串 (向后兼容) */
int validate_ipv4(const char *ip, validated_ip_t *out);

/* 验证并解析 IP 地址字符串 (支持 IPv4/IPv6) */
int validate_ip(const char *ip, validated_ip_t *out);

/* 安全的 procfs 文件操作辅助函数 */
int secure_procfs_write(const char *path, const char *data, size_t data_len);

/* 统一的封禁/解封操作 */
int execute_ban_action(ban_action_t action, const char *ip);

/* 向后兼容的包装函数 */
int ban_ip(const char *ip);
int ban_ip_permanent(const char *ip);
int unban_ip(const char *ip);
int unban_permanent_ip(const char *ip);

/* 清理过期的封禁和不完整行缓冲区 */
void cleanup_expired_bans(void);

/* R9-9: 关闭缓存的 procfs fd（用于守护进程关闭时清理） */
void close_cached_bans_fd(void);

#endif /* BAN_MANAGER_H */
