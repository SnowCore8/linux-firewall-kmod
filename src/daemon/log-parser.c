/*
 * log-parser.c - 日志解析和IP提取函数 (支持 IPv4/IPv6)
 */

#include "log-parser.h"
#include "firewall-daemon.h"

static const char *find_ip_candidate(const char **ptr, const char *line) {
  const char *start;
  const char *end;

  (void)line;

  /* 查找第一个数字或十六进制字符 (IPv6 可能以字母开头) */
  while (**ptr && !isxdigit((unsigned char)**ptr))
    (*ptr)++;
  if (!**ptr)
    return NULL;

  start = *ptr;

  /* 找到可能的 IP 地址结束位置 (IPv4: 数字和点; IPv6: 十六进制和冒号) */
  end = *ptr;
  while (*end && (isxdigit((unsigned char)*end) || *end == '.' || *end == ':'))
    end++;

  *ptr = start + 1;

  return start;
}

static int validate_ip_candidate(const char *start, const char *end,
                                 const char *line, char *ip_out,
                                 size_t ip_size) {
  size_t ip_len;
  struct in_addr addr4;
  struct in6_addr addr6;

  ip_len = (size_t)(end - start);

  /* IP 地址长度检查 */
  if (ip_len < 7 || ip_len >= INET6_ADDRSTRLEN)
    return 0;

  /* 验证词边界 */
  if (start > line && (isxdigit((unsigned char)start[-1]) || start[-1] == '.' ||
                       start[-1] == ':'))
    return 0;
  if (*end && (isxdigit((unsigned char)*end) || *end == '.' || *end == ':'))
    return 0;

  char ip_buf[INET6_ADDRSTRLEN];
  memcpy(ip_buf, start, ip_len);
  ip_buf[ip_len] = '\0';

  /* 尝试 IPv4 */
  if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
    unsigned int ip_num = ntohl(addr4.s_addr);
    unsigned int ip_class_a = (ip_num >> 24) & 0xFF;
    if (ip_num == 0 || ip_num == 0xFFFFFFFF || ip_class_a == 127 ||
        (ip_class_a >= 224 && ip_class_a <= 239))
      return 0;
    strncpy(ip_out, ip_buf, ip_size - 1);
    ip_out[ip_size - 1] = '\0';
    return 1;
  }

  /* 尝试 IPv6 */
  if (ip_len >= 2 && inet_pton(AF_INET6, ip_buf, &addr6) == 1) {
    if (IN6_IS_ADDR_LOOPBACK(&addr6) || IN6_IS_ADDR_MULTICAST(&addr6) ||
        IN6_IS_ADDR_UNSPECIFIED(&addr6) || IN6_IS_ADDR_LINKLOCAL(&addr6))
      return 0;
    strncpy(ip_out, ip_buf, ip_size - 1);
    ip_out[ip_size - 1] = '\0';
    return 1;
  }

  return 0;
}

int extract_ipv4(const char *line, char *ip_out, size_t ip_size) {
  const char *ptr = line;
  const char *start;
  const char *end;

  while (*ptr) {
    /* 只查找 IPv4 (数字和点) */
    while (*ptr && !isdigit((unsigned char)*ptr))
      ptr++;
    if (!*ptr)
      break;

    start = ptr;
    end = ptr;
    while (*end && (isdigit((unsigned char)*end) || *end == '.'))
      end++;

    ptr = start + 1;

    size_t ip_len = (size_t)(end - start);
    if (ip_len < 7 || ip_len >= INET_ADDRSTRLEN)
      continue;

    if (start > line && (isdigit((unsigned char)start[-1]) || start[-1] == '.'))
      continue;
    if (*end && (isdigit((unsigned char)*end) || *end == '.'))
      continue;

    char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    memcpy(ip_buf, start, ip_len);
    ip_buf[ip_len] = '\0';

    if (inet_pton(AF_INET, ip_buf, &addr) == 1) {
      unsigned int ip_num = ntohl(addr.s_addr);
      unsigned int ip_class_a = (ip_num >> 24) & 0xFF;
      if (ip_num == 0 || ip_num == 0xFFFFFFFF || ip_class_a == 127 ||
          (ip_class_a >= 224 && ip_class_a <= 239))
        continue;

      strncpy(ip_out, ip_buf, ip_size - 1);
      ip_out[ip_size - 1] = '\0';
      return 1;
    }
  }

  return 0;
}

/* 从日志行中提取IP地址（支持 IPv4/IPv6） */
int extract_ip(const char *line, char *ip_out, size_t ip_size) {
  const char *ptr = line;
  const char *start;
  const char *end;

  while (*ptr) {
    start = find_ip_candidate(&ptr, line);
    if (!start)
      break;

    end = start;
    /* 修复 W2-5：限制贪婪匹配长度，避免捕获过长字符串导致误识别 */
    while (*end &&
           (isxdigit((unsigned char)*end) || *end == '.' || *end == ':') &&
           (size_t)(end - start) < INET6_ADDRSTRLEN)
      end++;

    if (validate_ip_candidate(start, end, line, ip_out, ip_size))
      return 1;
  }

  return 0;
}

/* 辅助函数：从日志行中提取并验证IP (支持 IPv4/IPv6) */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out,
                            size_t ip_size) {
  char ip_buf[INET6_ADDRSTRLEN];
  struct in_addr addr4;
  struct in6_addr addr6;

  if (!parse_log_line(j, log_line, ip_buf, sizeof(ip_buf))) {
    return 0;
  }

  /* 尝试 IPv4 */
  if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF || ((ip_num >> 24) & 0xFF) == 127 ||
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {
      return 0;
    }
    atomic_fetch_add(&daemon_stats.ips_extracted, 1);
    size_t copy_len = strlen(ip_buf);
    if (copy_len >= ip_size)
      copy_len = ip_size - 1;
    memcpy(ip_out, ip_buf, copy_len);
    ip_out[copy_len] = '\0';
    return 1;
  }

  /* 尝试 IPv6 */
  if (inet_pton(AF_INET6, ip_buf, &addr6) == 1) {
    if (IN6_IS_ADDR_LOOPBACK(&addr6) || IN6_IS_ADDR_MULTICAST(&addr6) ||
        IN6_IS_ADDR_UNSPECIFIED(&addr6) || IN6_IS_ADDR_LINKLOCAL(&addr6)) {
      return 0;
    }
    atomic_fetch_add(&daemon_stats.ips_extracted, 1);
    size_t copy_len = strlen(ip_buf);
    if (copy_len >= ip_size)
      copy_len = ip_size - 1;
    memcpy(ip_out, ip_buf, copy_len);
    ip_out[copy_len] = '\0';
    return 1;
  }

  return 0;
}

static int match_pcre2_regex(struct jail *j, const char *line, size_t line_len,
                             char *ip_out, size_t ip_size) {
  int regex_result;
  PCRE2_SIZE *ovector;
  int num_groups;
  int ip_group = -1;
  const char *ip_start;
  size_t ip_len;
  char ip_buf[INET6_ADDRSTRLEN];

  regex_result =
      pcre2_match(j->compiled_regex, (PCRE2_SPTR)line, (PCRE2_SIZE)line_len, 0,
                  0, j->match_data, NULL);

  if (regex_result < 0) {
    if (regex_result != PCRE2_ERROR_NOMATCH) {
      PCRE2_UCHAR errbuf[256];
      pcre2_get_error_message(regex_result, errbuf, sizeof(errbuf));
      daemon_log_warn("Regex error in jail '%s' pattern: %s", j->name, errbuf);
    }
    return 0;
  }

  ovector = pcre2_get_ovector_pointer(j->match_data);
  num_groups = regex_result;

  /* 动态查找IP捕获组 */
  for (int g = num_groups - 1; g >= 1; g--) {
    if (ovector[g * 2] != PCRE2_UNSET && ovector[g * 2 + 1] > ovector[g * 2]) {
      size_t capture_len = ovector[g * 2 + 1] - ovector[g * 2];
      if (capture_len >= 7 && capture_len < INET6_ADDRSTRLEN) {
        const char *capture_start = line + ovector[g * 2];
        if (isxdigit((unsigned char)capture_start[0])) {
          ip_group = g;
          break;
        }
      }
    }
  }

  if (ip_group < 0) {
    daemon_log_warn(
        "No valid IP capture group found in regex match for jail '%s'",
        j->name);
    return -1;
  }

  if ((size_t)ovector[ip_group * 2 + 1] > line_len) {
    daemon_log_warn("Regex match exceeds line length in jail '%s'", j->name);
    return -1;
  }

  ip_start = line + ovector[ip_group * 2];
  ip_len = ovector[ip_group * 2 + 1] - ovector[ip_group * 2];

  if (ip_len >= INET6_ADDRSTRLEN || ip_len == 0) {
    daemon_log_warn("Invalid IP length in jail '%s' log: %zu", j->name, ip_len);
    return -1;
  }

  memcpy(ip_buf, ip_start, ip_len);
  ip_buf[ip_len] = '\0';
  strncpy(ip_out, ip_buf, ip_size - 1);
  ip_out[ip_size - 1] = '\0';
  return 1;
}

static int fallback_string_match(const char *line, char *ip_out,
                                 size_t ip_size) {
  if (strstr(line, "Failed password for") ||
      strstr(line, "authentication failure")) {
    return extract_ip(line, ip_out, ip_size);
  }
  return 0;
}

int parse_log_line(struct jail *j, const char *line, char *ip_out,
                   size_t ip_size) {
  int result;

  size_t line_len = strlen(line);
  if (line_len > 8192) {
    daemon_log_warn("Log line too long (%zu bytes), skipping", line_len);
    return 0;
  }

  if (j && j->regex_compiled && j->compiled_regex && j->match_data) {
    result = match_pcre2_regex(j, line, line_len, ip_out, ip_size);
    if (result == 1)
      return 1;
    if (result == -1)
      return 0;
  }

  if (!j || !j->regex_compiled)
    return fallback_string_match(line, ip_out, ip_size);

  return 0;
}
