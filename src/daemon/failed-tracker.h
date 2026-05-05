/*
 * failed-tracker.h - 失败尝试跟踪函数头文件
 */

#ifndef FAILED_TRACKER_H
#define FAILED_TRACKER_H

#include "firewall-daemon.h"

/* 在特定 jail 中按 IP 查找失败条目 */
struct failed_entry *find_entry_for_jail(struct jail *j, const char *ip);

/* 在特定 jail 中创建新的失败条目 */
struct failed_entry *create_entry_for_jail(struct jail *j, const char *ip);

/* 移除失败条目（每个 jail） */
void remove_entry_for_jail(struct jail *j, const char *ip);

/* 统计时间窗口内的近期失败次数 */
unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries);

/* 处理失败时间戳 - 添加时间戳并管理缓冲区溢出 */
void process_failed_timestamps(struct failed_entry *entry, time_t now, time_t findtime);

/* 检查阈值，如果超过则封禁 */
void check_and_ban(struct failed_entry *entry, const char *ip,
                   unsigned int max_retries, unsigned int findtime,
                   const char *jail_name);

/* 处理失败登录尝试 - 支持 jail 的版本 */
void handle_failed_attempt_for_jail(struct jail *j, const char *ip,
                                   unsigned int max_retries, unsigned int findtime);

/* 修复 3.3：删除废弃的全局函数声明（handle_failed_attempt, find_entry, create_entry, remove_entry） */

#endif /* FAILED_TRACKER_H */