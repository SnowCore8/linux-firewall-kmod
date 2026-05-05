/*
 * log-parser.h - 日志解析和 IP 提取函数头文件
 */

#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include "firewall-daemon.h"

/* 从日志行提取 IPv4 地址（非正则模式下的回退方案） */
int extract_ipv4(const char *line, char *ip_out, size_t ip_size);

/* 从日志行提取 IP 地址（仅 IPv4） */
int extract_ip(const char *line, char *ip_out, size_t ip_size);

/* 从日志行提取并验证 IP 的辅助函数 */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out,
                            size_t ip_size);

/* 解析日志行，如果是失败登录则提取 IP - 使用 jail 的 PCRE2 正则 */
int parse_log_line(struct jail *j, const char *line, char *ip_out,
                   size_t ip_size);

#endif /* LOG_PARSER_H */