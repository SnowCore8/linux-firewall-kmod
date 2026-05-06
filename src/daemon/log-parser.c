/*
 * log-parser.c - 日志解析和IP提取函数
 */

#include "log-parser.h"
#include "firewall-daemon.h"

/* 从日志行中提取IPv4地址（使用标准库函数解析） */

/**
 * find_ip_candidate - 查找下一个可能的IP地址候选位置
 * @ptr: 当前扫描位置（输入/输出）
 * @line: 日志行起始位置
 * 返回: 候选IP的起始位置，如果未找到则返回NULL
 */
static const char *find_ip_candidate(const char **ptr, const char *line) {
  const char *start;
  const char *end;

  /* line 参数预留用于未来边界检查，当前未使用 */
  (void)line;

  /* 快速查找第一个数字 */
  while (**ptr && !isdigit((unsigned char)**ptr))
    (*ptr)++;
  if (!**ptr)
    return NULL;

  start = *ptr;

  /* 找到可能的 IP 地址结束位置 */
  end = *ptr;
  while (*end && (isdigit((unsigned char)*end) || *end == '.'))
    end++;

  /* 更新指针位置 */
  *ptr = start + 1;

  return start;
}

/**
 * validate_ip_candidate - 验证IP候选字符串是否有效
 * @start: 候选IP起始位置
 * @end: 候选IP结束位置
 * @line: 日志行起始位置
 * @ip_out: 输出缓冲区
 * @ip_size: 缓冲区大小
 * 返回: 1 表示有效，0 表示无效
 */
static int validate_ip_candidate(const char *start, const char *end,
                                 const char *line, char *ip_out,
                                 size_t ip_size) {
  size_t ip_len;
  char ip_buf[INET_ADDRSTRLEN];
  struct in_addr addr;
  unsigned int ip_num, ip_class_a;

  ip_len = (size_t)(end - start);

  /* IP 地址长度检查 */
  if (ip_len < 7 || ip_len >= INET_ADDRSTRLEN)
    return 0;

  /* 验证词边界：IP 地址前后不能是数字或点 */
  if (start > line &&
      (isdigit((unsigned char)start[-1]) || start[-1] == '.'))
    return 0;
  if (*end && (isdigit((unsigned char)*end) || *end == '.'))
    return 0;

  /* 复制到临时缓冲区 */
  memcpy(ip_buf, start, ip_len);
  ip_buf[ip_len] = '\0';

  /* 使用标准库函数 inet_pton 解析 IP 地址 */
  if (inet_pton(AF_INET, ip_buf, &addr) != 1)
    return 0;

  /* 验证 IP 地址有效性 */
  ip_num = ntohl(addr.s_addr);
  ip_class_a = (ip_num >> 24) & 0xFF;
  if (ip_num == 0 || ip_num == 0xFFFFFFFF || ip_class_a == 127 ||
      (ip_class_a >= 224 && ip_class_a <= 239))
    return 0; /* 无效 IP */

  /* 验证通过，复制结果 */
  strncpy(ip_out, ip_buf, ip_size - 1);
  ip_out[ip_size - 1] = '\0';
  return 1;
}

int extract_ipv4(const char *line, char *ip_out, size_t ip_size) {
  const char *ptr = line;
  const char *start;
  const char *end;

  while (*ptr) {
    start = find_ip_candidate(&ptr, line);
    if (!start)
      break;

    /* 重新定位 end 位置 */
    end = start;
    while (*end && (isdigit((unsigned char)*end) || *end == '.'))
      end++;

    if (validate_ip_candidate(start, end, line, ip_out, ip_size))
      return 1;
  }

  return 0;
}

/* 从日志行中提取IP地址（仅IPv4） */
int extract_ip(const char *line, char *ip_out, size_t ip_size) {
  return extract_ipv4(line, ip_out, ip_size);
}

/* 辅助函数：从日志行中提取并验证IP。
 * 如果成功提取有效IP则返回1，否则返回0。
 * 使用 jail 的正则表达式进行解析。 */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out,
                            size_t ip_size) {
  char ip_buf[INET_ADDRSTRLEN];
  struct in_addr addr4;

  if (!parse_log_line(j, log_line, ip_buf, sizeof(ip_buf))) {
    return 0;
  }

  /* 验证IPv4 */
  if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
    unsigned int ip_num = ntohl(addr4.s_addr);
    /* 拒绝无效/保留的IPv4地址 */
    if (ip_num == 0 ||                    /* 0.0.0.0 */
        ip_num == 0xFFFFFFFF ||           /* 255.255.255.255 */
        ((ip_num >> 24) & 0xFF) == 127 || /* 127.x.x.x（回环地址） */
        (((ip_num >> 24) & 0xFF) >= 224 &&
         ((ip_num >> 24) & 0xFF) <= 239)) { /* 组播地址 */
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

/**
 * match_pcre2_regex - 使用jail的PCRE2正则表达式匹配日志行
 * @j: jail结构
 * @line: 日志行
 * @line_len: 日志行长度
 * @ip_out: 输出缓冲区
 * @ip_size: 缓冲区大小
 * 返回: 1 表示匹配成功，0 表示未匹配，-1 表示错误
 */
static int match_pcre2_regex(struct jail *j, const char *line, size_t line_len,
                             char *ip_out, size_t ip_size) {
  pcre2_match_context *mcontext = NULL;
  int regex_result;
  PCRE2_SIZE *ovector;
  int num_groups;
  int ip_group = -1;
  const char *ip_start;
  size_t ip_len;
  char ip_buf[INET_ADDRSTRLEN];

  /* 设置匹配限制以防止 ReDoS 攻击 */
  mcontext = pcre2_match_context_create(NULL);
  if (mcontext) {
    pcre2_set_match_limit(mcontext, 10000);   /* 最大回溯次数 */
    pcre2_set_depth_limit(mcontext, 1000);    /* 最大递归深度 */
  }

  regex_result =
      pcre2_match(j->compiled_regex, (PCRE2_SPTR)line, (PCRE2_SIZE)line_len,
                  0, 0, j->match_data, mcontext);

  if (mcontext)
    pcre2_match_context_free(mcontext);

  if (regex_result < 0) {
    if (regex_result != PCRE2_ERROR_NOMATCH) {
      PCRE2_UCHAR errbuf[256];
      pcre2_get_error_message(regex_result, errbuf, sizeof(errbuf));
      daemon_log_warn("Regex error in jail '%s' pattern: %s", j->name, errbuf);
    }
    return 0; /* 未匹配 */
  }

  /* 获取捕获的子串 */
  ovector = pcre2_get_ovector_pointer(j->match_data);
  num_groups = regex_result;

  /* 动态查找IP捕获组 - 从后向前搜索 */
  for (int g = num_groups - 1; g >= 1; g--) {
    if (ovector[g * 2] != PCRE2_UNSET &&
        ovector[g * 2 + 1] > ovector[g * 2]) {
      size_t capture_len = ovector[g * 2 + 1] - ovector[g * 2];
      if (capture_len >= 7 && capture_len < INET_ADDRSTRLEN) {
        const char *capture_start = line + ovector[g * 2];
        if (capture_start[0] >= '0' && capture_start[0] <= '9') {
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

  /* 添加边界检查以防止越界读取 */
  if ((size_t)ovector[ip_group * 2 + 1] > line_len) {
    daemon_log_warn("Regex match exceeds line length in jail '%s'", j->name);
    return -1;
  }

  ip_start = line + ovector[ip_group * 2];
  ip_len = ovector[ip_group * 2 + 1] - ovector[ip_group * 2];

  if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
    daemon_log_warn("Invalid IP length in jail '%s' log: %zu", j->name,
                    ip_len);
    return -1;
  }

  memcpy(ip_buf, ip_start, ip_len);
  ip_buf[ip_len] = '\0';
  strncpy(ip_out, ip_buf, ip_size - 1);
  ip_out[ip_size - 1] = '\0';
  return 1;
}

/**
 * fallback_string_match - 回退方案：简单字符串匹配
 * @line: 日志行
 * @ip_out: 输出缓冲区
 * @ip_size: 缓冲区大小
 * 返回: 1 表示匹配成功，0 表示未匹配
 */
static int fallback_string_match(const char *line, char *ip_out,
                                 size_t ip_size) {
  if (strstr(line, "Failed password for") ||
      strstr(line, "authentication failure")) {
    return extract_ip(line, ip_out, ip_size);
  }
  return 0;
}

/* 解析日志行，如果是失败登录则提取IP - 使用 jail 的 PCRE2 正则表达式 */
int parse_log_line(struct jail *j, const char *line, char *ip_out,
                   size_t ip_size) {
  int result;

  /* 长度验证以防止极长的日志行 */
  size_t line_len = strlen(line);
  if (line_len > 8192) {
    daemon_log_warn("Log line too long (%zu bytes), skipping", line_len);
    return 0;
  }

  /* 使用 jail 编译的 PCRE2 正则表达式检查失败登录 */
  if (j && j->regex_compiled && j->compiled_regex && j->match_data) {
    result = match_pcre2_regex(j, line, line_len, ip_out, ip_size);
    if (result == 1)
      return 1;
    if (result == -1)
      return 0; /* 正则错误 */
  }

  /* 回退方案：简单字符串匹配（如果正则表达式未编译） */
  if (!j || !j->regex_compiled)
    return fallback_string_match(line, ip_out, ip_size);

  return 0;
}