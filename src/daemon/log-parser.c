/*
 * log-parser.c - 日志解析和IP提取函数
 */

#include "firewall-daemon.h"
#include "log-parser.h"

/* 从日志行中提取IPv4地址（非正则模式的回退方案） */
int extract_ipv4(const char *line, char *ip_out, size_t ip_size)
{
    const char *ptr = line;
    int octets[4];

    /* 搜索模式：数字.数字.数字.数字 */
    while (*ptr) {
        if (sscanf(ptr, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            /* 验证每个字节段 */
            if (octets[0] >= 0 && octets[0] <= 255 &&
                octets[1] >= 0 && octets[1] <= 255 &&
                octets[2] >= 0 && octets[2] <= 255 &&
                octets[3] >= 0 && octets[3] <= 255) {

                snprintf(ip_out, ip_size, "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                /* 使用 inet_pton 验证 */
                unsigned char buf[4];
                if (inet_pton(AF_INET, ip_out, buf) == 1) {
                    /* 额外验证：拒绝无效IP，如 0.0.0.0、127.x.x.x、组播地址等 */
                    unsigned int ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
                    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
                        octets[0] == 127 ||  // 127.x.x.x（回环地址）
                        (octets[0] >= 224 && octets[0] <= 239)) {  // 224.0.0.0/4（组播地址）
                        /* 跳过无效IP：越过整个类IP模式 */
                        while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
                        continue;
                    }

                    /* 边界检查：确保下一个字符不是数字或点（词边界） */
                    const char *ip_end = ptr;
                    while (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) ip_end++;
                    if (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) {
                        /* 后面还有更多数字/点 - 不是完整的IP，跳过 */
                        ptr = ip_end;
                        continue;
                    }

                    return 1;
                }
            }
        }
        /* sscanf 未匹配或字节段无效：跳过数字和点以避免重复扫描 */
        if (isdigit((unsigned char)*ptr) || *ptr == '.') {
            while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
        } else {
            ptr++;
        }
    }

    return 0;
}

/* 从日志行中提取IP地址（仅IPv4） */
int extract_ip(const char *line, char *ip_out, size_t ip_size)
{
    return extract_ipv4(line, ip_out, ip_size);
}

/* 辅助函数：从日志行中提取并验证IP。
 * 如果成功提取有效IP则返回1，否则返回0。
 * 使用 jail 的正则表达式进行解析。 */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out, size_t ip_size)
{
    char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr4;

    if (!parse_log_line(j, log_line, ip_buf, sizeof(ip_buf))) {
        return 0;
    }

    /* 验证IPv4 */
    if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
        unsigned int ip_num = ntohl(addr4.s_addr);
        /* 拒绝无效/保留的IPv4地址 */
        if (ip_num == 0 ||                                  /* 0.0.0.0 */
            ip_num == 0xFFFFFFFF ||                         /* 255.255.255.255 */
            ((ip_num >> 24) & 0xFF) == 127 ||              /* 127.x.x.x（回环地址） */
            (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) { /* 组播地址 */
            return 0;
        }
        atomic_fetch_add(&daemon_stats.ips_extracted, 1);
        size_t copy_len = strlen(ip_buf);
        if (copy_len >= ip_size) copy_len = ip_size - 1;
        memcpy(ip_out, ip_buf, copy_len);
        ip_out[copy_len] = '\0';
        return 1;
    }

    return 0;
}

/* 解析日志行，如果是失败登录则提取IP - 使用 jail 的 PCRE2 正则表达式 */
int parse_log_line(struct jail *j, const char *line, char *ip_out, size_t ip_size)
{
    const char *ip_start;
    size_t ip_len;

    /* 长度验证以防止极长的日志行 */
    size_t line_len = strlen(line);
    if (line_len > 8192) {
        daemon_log_warn("Log line too long (%zu bytes), skipping", line_len);
        return 0;
    }

    /* 使用 jail 编译的 PCRE2 正则表达式检查失败登录 */
    if (j && j->regex_compiled && j->compiled_regex && j->match_data) {
        int regex_result = pcre2_match(j->compiled_regex, (PCRE2_SPTR)line,
                                        (PCRE2_SIZE)line_len, 0, 0,
                                        j->match_data, NULL);
        if (regex_result >= 0) {
            /* 获取捕获的子串 */
            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(j->match_data);
            int num_groups = regex_result;

            /* 动态查找IP捕获组 - 从后向前搜索 */
            int ip_group = -1;
            for (int g = num_groups - 1; g >= 1; g--) {
                if (ovector[g * 2] != PCRE2_UNSET && ovector[g * 2 + 1] > ovector[g * 2]) {
                    /* 验证此捕获组包含类IP模式 */
                    size_t capture_len = ovector[g * 2 + 1] - ovector[g * 2];
                    if (capture_len >= 7 && capture_len < INET_ADDRSTRLEN) {  /* 最小长度："1.1.1.1" */
                        /* 快速验证：首字符应为数字 */
                        const char *capture_start = line + ovector[g * 2];
                        if (capture_start[0] >= '0' && capture_start[0] <= '9') {
                            ip_group = g;
                            break;
                        }
                    }
                }
            }

            if (ip_group < 0) {
                daemon_log_warn("No valid IP capture group found in regex match for jail '%s'", j->name);
                return 0;
            }

            /* 添加边界检查以防止越界读取 */
            if ((size_t)ovector[ip_group * 2 + 1] > line_len) {
                daemon_log_warn("Regex match exceeds line length in jail '%s'", j->name);
                return 0;
            }
            ip_start = line + ovector[ip_group * 2];
            ip_len = ovector[ip_group * 2 + 1] - ovector[ip_group * 2];

            if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                daemon_log_warn("Invalid IP length in jail '%s' log: %zu", j->name, ip_len);
                return 0;
            }

            char ip_buf[INET_ADDRSTRLEN];
            memcpy(ip_buf, ip_start, ip_len);
            ip_buf[ip_len] = '\0';
            strncpy(ip_out, ip_buf, ip_size - 1);
            ip_out[ip_size - 1] = '\0';
            return 1;
        } else if (regex_result != PCRE2_ERROR_NOMATCH) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(regex_result, errbuf, sizeof(errbuf));
            daemon_log_warn("Regex error in jail '%s' pattern: %s", j->name, errbuf);
        }
    }

    /* 回退方案：简单字符串匹配（如果正则表达式未编译） */
    if (!j || !j->regex_compiled) {
        if (strstr(line, "Failed password for") ||
            strstr(line, "authentication failure")) {
            return extract_ip(line, ip_out, ip_size);
        }
    }

    return 0;
}