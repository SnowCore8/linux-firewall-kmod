/*
 * procfs.c - procfs 接口 (支持 IPv4/IPv6)
 *
 * 包含所有 procfs 文件操作相关的函数实现，包括 bans、whitelist、config、stats
 * 接口。
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
static ssize_t bans_write(struct file *file, const char __user *buf,
                          size_t count, loff_t *ppos);

/*
 * bans_show - 显示当前封禁列表
 */
static int bans_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  struct ban_entry *entry;
  u32 hash;
  unsigned long now = jiffies;
  char ip_str[INET6_STR_LEN];
  int count = 0;
  int temporary_count = 0;
  int permanent_count = 0;

  FW_DEBUG(3, "ENTRY: bans_show");

  seq_printf(m, "Banned IP List:\n");
  seq_printf(m, "-------------------\n");

  /* IPv4 封禁 */
  rcu_read_lock();
  hash_for_each_rcu(fw->ban_table_ipv4, hash, entry, hash) {
    bool is_permanent = READ_ONCE(entry->is_permanent);
    unsigned long unban_time = READ_ONCE(entry->unban_time);
    if (is_permanent) {
      ip_to_str(FW_AF_INET, &entry->addr.ipv4, ip_str, sizeof(ip_str));
      seq_printf(m, "%-40s (permanent)\n", ip_str);
      permanent_count++;
      count++;
    } else if (!time_after(now, unban_time)) {
      ip_to_str(FW_AF_INET, &entry->addr.ipv4, ip_str, sizeof(ip_str));
      seq_printf(m, "%-40s (expires in %lu seconds)\n", ip_str, (unban_time - now) / HZ);
      temporary_count++;
      count++;
    }
  }

  /* IPv6 封禁 */
  hash_for_each_rcu(fw->ban_table_ipv6, hash, entry, hash) {
    bool is_permanent = READ_ONCE(entry->is_permanent);
    unsigned long unban_time = READ_ONCE(entry->unban_time);
    if (is_permanent) {
      ip_to_str(FW_AF_INET6, &entry->addr.ipv6, ip_str, sizeof(ip_str));
      seq_printf(m, "%-40s (permanent)\n", ip_str);
      permanent_count++;
      count++;
    } else if (!time_after(now, unban_time)) {
      ip_to_str(FW_AF_INET6, &entry->addr.ipv6, ip_str, sizeof(ip_str));
      seq_printf(m, "%-40s (expires in %lu seconds)\n", ip_str, (unban_time - now) / HZ);
      temporary_count++;
      count++;
    }
  }
  rcu_read_unlock();

  seq_printf(m, "-------------------\n");
  seq_printf(m, "Total: %d active bans (%d permanent, %d temporary)\n", count,
             permanent_count, temporary_count);
  FW_DEBUG(3, "EXIT: bans_show -> 0 (shown=%d)", count);
  return 0;
}

static int bans_open(struct inode *inode, struct file *file) {
  return single_open(file, bans_show, NULL);
}

/* ============================================================================
 * bans_write 辅助函数 - 拆分单一职责
 * ========================================================================== */

/**
 * validate_ban_input - 校验用户输入的安全性和格式
 */
static int validate_ban_input(const char *input) {
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
 * validate_and_copy_ip - 验证 IP 长度并复制到输出缓冲区
 * M5 修复：增强缓冲区大小检查，确保 ip_str_size 足够容纳 IP 地址和 null 终止符
 */
static int validate_and_copy_ip(const char *ip_start, const char *ip_end,
                                char *ip_str, size_t ip_str_size) {
  size_t ip_len = (size_t)(ip_end - ip_start);

  /* M5 修复：确保 ip_str_size 至少为 1（容纳 null 终止符），
   * 并且 ip_len + 1 <= ip_str_size（容纳 IP 地址和 null 终止符） */
  if (ip_len == 0 || ip_str_size == 0 || ip_len >= INET6_ADDRSTRLEN || ip_len + 1 > ip_str_size) {
    fw_pr_warn("Invalid IP address length: %zu (buffer size: %zu)", ip_len, ip_str_size);
    return -EINVAL;
  }

  strncpy(ip_str, ip_start, ip_len);
  ip_str[ip_len] = '\0';
  return 0;
}

/**
 * parse_unban_command - 解析 unban 命令并提取 IP 地址
 */
static int parse_unban_command(const char *cmd_ptr, const char *input,
                               char *ip_str, size_t ip_str_size) {
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

  return validate_and_copy_ip(ip_start, ip_end, ip_str, ip_str_size);
}

/**
 * parse_ban_command - 解析封禁命令类型和 IP 地址
 */
static int parse_ban_command(const char *input, char *ip_str,
                             size_t ip_str_size, bool *is_unban) {
  const char *cmd_ptr = input;

  while (*cmd_ptr && (*cmd_ptr == ' ' || *cmd_ptr == '\t'))
    cmd_ptr++;

  if (*cmd_ptr == '\0') {
    fw_pr_warn("Empty command");
    return -EINVAL;
  }

  if (strncmp(cmd_ptr, "unban ", 6) == 0 || strncmp(cmd_ptr, "unban\t", 6) == 0) {
    int ret = parse_unban_command(cmd_ptr, input, ip_str, ip_str_size);
    if (ret == 0)
      *is_unban = true;
    return ret;
  }

  const char *ptr = cmd_ptr;
  const char *ip_start = ptr;

  while (*ptr && *ptr != ' ' && *ptr != '\t')
    ptr++;

  return validate_and_copy_ip(ip_start, ptr, ip_str, ip_str_size) == 0 ?
           (*is_unban = false, 0) :
           -EINVAL;
}

/**
 * find_duration_start - 查找持续时间字符串的起始位置
 */
static const char *find_duration_start(const char *input) {
  const char *ptr = input;

  while (*ptr && (*ptr == ' ' || *ptr == '\t'))
    ptr++;

  while (*ptr && *ptr != ' ' && *ptr != '\t')
    ptr++;

  if (*ptr == '\0')
    return NULL;

  ptr++;
  while (*ptr && (*ptr == ' ' || *ptr == '\t'))
    ptr++;

  return (*ptr == '\0') ? NULL : ptr;
}

/**
 * validate_duration_string - 验证持续时间字符串并解析为数值
 */
static long validate_duration_string(const char *duration_str, const char *input) {
  long seconds;
  int ret = kstrtol(duration_str, 10, &seconds);

  if (ret != 0) {
    fw_pr_warn("Invalid format - invalid seconds value: %s", input);
    return -EINVAL;
  }

  const char *endp = duration_str;
  while (*endp >= '0' && *endp <= '9')
    endp++;
  if (*endp != '\0' && *endp != ' ' && *endp != '\t' && *endp != '\n') {
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

/**
 * parse_ban_duration - 解析封禁持续时间
 */
static long parse_ban_duration(const char *input) {
  const char *duration_start = find_duration_start(input);

  if (!duration_start)
    return -2;

  return validate_duration_string(duration_start, input);
}

/**
 * execute_unban_action - 执行解封操作
 */
static int execute_unban_action(struct firewall_info *fw, u8 af, const void *ip,
                                const char *ip_str) {
  int result = unban_ip(fw, af, ip);

  if (result < 0) {
    if (result == -ENOENT)
      fw_pr_warn("IP %s not found in ban list", ip_str);
    else
      fw_pr_err("Failed to unban IP %s (error %d)", ip_str, result);
    return result;
  }
  return 0;
}

/**
 * execute_permanent_ban - 执行永久封禁操作
 */
static int execute_permanent_ban(struct firewall_info *fw, u8 af,
                                 const void *ip, const char *ip_str) {
  int result = ban_ip_permanent(fw, af, ip);

  if (result < 0) {
    if (result == -EPERM)
      fw_pr_info("Requested IP %s is in whitelist, not permanently banned", ip_str);
    else if (result == -ENOMEM)
      fw_pr_err("Failed to allocate memory for permanent ban entry for IP %s", ip_str);
    else if (result == -ENOSPC)
      fw_pr_warn("Ban table full, cannot permanently ban IP %s", ip_str);
    else
      fw_pr_err("Unknown error %d when trying to permanently ban IP %s", result, ip_str);
    return result;
  }
  return 0;
}

/**
 * execute_temporary_ban - 执行临时封禁操作（带泛洪保护）
 */
static int execute_temporary_ban(struct firewall_info *fw, u8 af, const void *ip,
                                 const char *ip_str, long seconds) {
  int result;

  if (check_flood_protection() < 0) {
    fw_pr_warn("Flood protection triggered - too many ban requests");
    return -EBUSY;
  }

  if (seconds == -2) {
    result = ban_ip(fw, af, ip);
  } else {
    result = ban_ip_with_duration(fw, af, ip, (unsigned long)seconds);
  }

  if (result < 0) {
    if (result == -EPERM)
      fw_pr_info("Requested IP %s is in whitelist, not banned", ip_str);
    else if (result == -ENOMEM)
      fw_pr_err("Failed to allocate memory for ban entry for IP %s", ip_str);
    else if (result == -ENOSPC)
      fw_pr_warn("Ban table full, cannot ban IP %s", ip_str);
    else
      fw_pr_err("Unknown error %d when trying to ban IP %s", result, ip_str);
    return result;
  }
  return 0;
}

/**
 * execute_ban_action - 执行封禁/解封动作
 */
static int execute_ban_action(u8 af, const void *ip, const char *ip_str,
                              long seconds, bool is_unban) {
  if (is_unban || (seconds < 0 && seconds != -2))
    return execute_unban_action(&fw_info, af, ip, ip_str);

  if (seconds == 0)
    return execute_permanent_ban(&fw_info, af, ip, ip_str);

  return execute_temporary_ban(&fw_info, af, ip, ip_str, seconds);
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
                          size_t count, loff_t *ppos) {
  char input[256];
  char ip_str[INET6_STR_LEN];
  u8 af;
  union {
    __be32 ipv4;
    struct in6_addr ipv6;
  } ip_addr;
  long seconds;
  ssize_t len;
  int result;
  bool is_unban = false;

  FW_DEBUG(2, "ENTRY: bans_write(count=%zu)", count);

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

  if (len > 0 && len < sizeof(input)) {
    size_t actual_len = strnlen(input, len);
    if (actual_len >= len)
      input[len] = '\0';
  }

  input[len] = '\0';
  if (len > 0 && input[len - 1] == '\n')
    input[len - 1] = '\0';

  if (strnlen(input, sizeof(input)) >= sizeof(input)) {
    FW_DEBUG(1, "EXIT: bans_write -> -EINVAL (not null-terminated)");
    return -EINVAL;
  }

  {
    size_t i;
    for (i = 0; i < len && input[i] != '\0'; i++) {
      char c = input[i];
      if (c < 0x20 && c != '\t') {
        fw_pr_warn("Invalid control character 0x%02x at position %zu", c, i);
        return -EINVAL;
      }
    }
  }

  result = validate_ban_input(input);
  if (result < 0)
    return result;

  result = parse_ban_command(input, ip_str, sizeof(ip_str), &is_unban);
  if (result < 0)
    return result;

  /* 解析 IP 地址：先尝试 IPv4，再尝试 IPv6 */
  if (in4_pton(ip_str, -1, (u8 *)&ip_addr.ipv4, -1, NULL)) {
    af = FW_AF_INET;
    if (validate_ipv4_address(ip_addr.ipv4, ip_str, "ban", false) < 0)
      return -EINVAL;
  } else if (in6_pton(ip_str, -1, (u8 *)&ip_addr.ipv6, -1, NULL)) {
    af = FW_AF_INET6;
    if (validate_ipv6_address(&ip_addr.ipv6, ip_str, "ban", false) < 0)
      return -EINVAL;
  } else {
    fw_pr_warn("Invalid IP address format: %s", ip_str);
    return -EINVAL;
  }

  /* 私有 IP 警告 (仅 IPv4) */
  if (af == FW_AF_INET) {
    unsigned int ip_class_a = (ntohl(ip_addr.ipv4) >> 24) & 0xFF;
    unsigned int ip_class_b = (ntohl(ip_addr.ipv4) >> 16) & 0xFF;
    if ((ip_class_a == 10) || (ip_class_a == 172 && ip_class_b >= 16 && ip_class_b <= 31) ||
        (ip_class_a == 192 && ip_class_b == 168)) {
      fw_pr_warn("Attempt to ban private IPv4 range %s - this may be unintended", ip_str);
    }
  }

  if (!is_unban) {
    seconds = parse_ban_duration(input);
    if (seconds < 0 && seconds != -1 && seconds != -2)
      return (int)seconds;
  } else {
    seconds = -1;
  }

  result = execute_ban_action(af, &ip_addr, ip_str, seconds, is_unban);
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
static int whitelist_read(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  struct whitelist_entry *entry;
  u32 hash;
  char ip_str[INET6_STR_LEN];
  int count = 0;

  seq_printf(m, "Whitelisted IPs (protected from banning):\n");
  seq_printf(m, "--------------------------------------\n");

  rcu_read_lock();

  /* IPv4 白名单 */
  hash_for_each_rcu(fw->whitelist_table_ipv4, hash, entry, hash) {
    __be32 wl_ip = READ_ONCE(entry->addr.ipv4);
    __be32 wl_mask = READ_ONCE(entry->mask.ipv4_mask);
    __be32 network_addr = wl_ip & wl_mask;
    ip_to_str(FW_AF_INET, &network_addr, ip_str, sizeof(ip_str));
    seq_printf(m, "%s/%d  on %s\n", ip_str, inet_mask_len(wl_mask), entry->device_name);
    count++;
  }

  /* IPv6 白名单 */
  hash_for_each_rcu(fw->whitelist_table_ipv6, hash, entry, hash) {
    u8 prefix_len = READ_ONCE(entry->mask.prefix_len);
    struct in6_addr addr_copy = entry->addr.ipv6;
    seq_printf(m, "%pI6/%d  on %s\n", &addr_copy, prefix_len, entry->device_name);
    count++;
  }

  rcu_read_unlock();

  seq_printf(m, "--------------------------------------\n");
  seq_printf(m, "Total: %d entries\n", atomic_read(&fw->whitelist_count));
  return 0;
}

static int whitelist_open(struct inode *inode, struct file *file) {
  return single_open(file, whitelist_read, NULL);
}

/* ============================================================================
 * whitelist_write 辅助函数
 * ========================================================================== */

static char *extract_command_token(char **ptr, char *cmd_buf, size_t cmd_buf_size) {
  char *cmd_start = *ptr;

  while (**ptr && **ptr != ' ' && **ptr != '\t')
    (*ptr)++;

  if (**ptr) {
    char saved = **ptr;
    **ptr = '\0';

    if (strcmp(cmd_start, "add") == 0 || strcmp(cmd_start, "remove") == 0) {
      size_t cmd_len = strlen(cmd_start);
      if (cmd_len >= cmd_buf_size) {
        **ptr = saved;
        return NULL;
      }
      memcpy(cmd_buf, cmd_start, cmd_len);
      cmd_buf[cmd_len] = '\0';
      **ptr = saved;
      (*ptr)++;
      while (**ptr && (**ptr == ' ' || **ptr == '\t'))
        (*ptr)++;
      return *ptr;
    }
    **ptr = saved;
  }

  return cmd_start;
}

static int parse_whitelist_command(char *input, char *cmd_buf,
                                   size_t cmd_buf_size, char **subnet_out) {
  char *ptr = input;

  while (*ptr && (*ptr == ' ' || *ptr == '\t'))
    ptr++;

  if (*ptr == '\0') {
    fw_pr_warn("Empty command");
    return -EINVAL;
  }

  cmd_buf[0] = '\0';

  char *subnet_start = extract_command_token(&ptr, cmd_buf, cmd_buf_size);

  if (!subnet_start || *subnet_start == '\0') {
    fw_pr_warn("Missing subnet or invalid command");
    return -EINVAL;
  }

  ptr = subnet_start;
  while (*ptr && *ptr != ' ' && *ptr != '\t')
    ptr++;
  *ptr = '\0';

  *subnet_out = subnet_start;
  return 0;
}

static int parse_whitelist_subnet(char *subnet_str, u8 *af_out, void *ip_out,
                                  int *prefix_len_out) {
  int prefix_len = -1;
  u8 af;

  /* 检查是否有前缀长度 */
  char *slash = strchr(subnet_str, '/');
  if (slash) {
    *slash = '\0';
    if (kstrtoint(slash + 1, 10, &prefix_len) < 0) {
      fw_pr_warn("Invalid prefix length");
      return -EINVAL;
    }
  }

  /* 尝试解析 IPv4 */
  if (in4_pton(subnet_str, -1, (u8 *)ip_out, -1, NULL)) {
    af = FW_AF_INET;
    if (prefix_len == -1)
      prefix_len = 32;
    if (prefix_len < 0 || prefix_len > 32) {
      fw_pr_warn("Invalid prefix length: %d", prefix_len);
      return -EINVAL;
    }
    if (validate_ipv4_address(*(__be32 *)ip_out, subnet_str, "whitelist", true) < 0)
      return -EINVAL;
  } else if (in6_pton(subnet_str, -1, (u8 *)ip_out, -1, NULL)) {
    af = FW_AF_INET6;
    if (prefix_len == -1)
      prefix_len = 128;
    if (prefix_len < 0 || prefix_len > 128) {
      fw_pr_warn("Invalid prefix length: %d", prefix_len);
      return -EINVAL;
    }
    if (validate_ipv6_address(
          (const struct in6_addr *)ip_out, subnet_str, "whitelist", true) < 0)
      return -EINVAL;
  } else {
    fw_pr_warn("Invalid IP address format: %s", subnet_str);
    return -EINVAL;
  }

  *af_out = af;
  *prefix_len_out = prefix_len;
  return 0;
}

static int execute_whitelist_action(u8 af, void *ip, int prefix_len, const char *cmd) {
  int result;

  if (strcmp(cmd, "remove") == 0) {
    result = remove_whitelist_entry(&fw_info, af, ip, prefix_len);
    if (result < 0) {
      char ip_str[INET6_STR_LEN];
      ip_to_str(af, ip, ip_str, sizeof(ip_str));
      if (result == -ENOENT) {
        fw_pr_warn("%s/%d not found in whitelist", ip_str, prefix_len);
      } else {
        fw_pr_err("Failed to remove %s/%d from whitelist (error %d)", ip_str,
                  prefix_len, result);
      }
      return result;
    }
  } else {
    union {
      __be32 ipv4;
      struct in6_addr ipv6;
    } normalized;

    if (af == FW_AF_INET6) {
      struct in6_addr mask;
      ipv6_addr_set(&mask, 0, 0, 0, 0);
      if (prefix_len > 0) {
        int i;
        for (i = 0; i < 16; i++) {
          int bits = (prefix_len > (i * 8 + 8)) ? 8 :
                     (prefix_len > (i * 8))     ? (prefix_len - i * 8) :
                                                  0;
          mask.s6_addr[i] = (u8)(0xFF << (8 - bits));
        }
      }
      struct in6_addr *addr = (struct in6_addr *)ip;
      int i;
      for (i = 0; i < 16; i++)
        normalized.ipv6.s6_addr[i] = addr->s6_addr[i] & mask.s6_addr[i];
    } else {
      __be32 mask4 = prefix_len == 0 ? 0 : htonl(~((1ULL << (32 - prefix_len)) - 1));
      normalized.ipv4 = *(__be32 *)ip & mask4;
      af = FW_AF_INET;
    }

    result = add_whitelist_entry(
      &fw_info, af, &normalized,
      af == FW_AF_INET6 ?
        NULL :
        (__be32[]){ prefix_len == 0 ? 0 : htonl(~((1ULL << (32 - prefix_len)) - 1)) },
      prefix_len, "manual");
    if (result < 0) {
      if (result == -ENOMEM) {
        fw_pr_err("Failed to allocate memory for whitelist entry");
      } else if (result == -ENOSPC) {
        fw_pr_warn("Whitelist full, cannot add entry");
      } else if (result == -EINVAL) {
        fw_pr_warn("Invalid entry for whitelist");
      } else {
        fw_pr_err("Unknown error %d when adding to whitelist", result);
      }
      return result;
    }
  }

  return 0;
}

/*
 * whitelist_write - 白名单管理的统一写入处理程序
 */
static ssize_t whitelist_write(struct file *file, const char __user *buf,
                               size_t count, loff_t *ppos) {
  char input[INET6_STR_LEN + 16];
  ssize_t len;
  char cmd_buf[16];
  char *subnet_str;
  u8 af;
  union {
    __be32 ipv4;
    struct in6_addr ipv6;
  } ip_addr;
  int prefix_len;
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

  result = parse_whitelist_command(input, cmd_buf, sizeof(cmd_buf), &subnet_str);
  if (result < 0)
    return result;

  result = parse_whitelist_subnet(subnet_str, &af, &ip_addr, &prefix_len);
  if (result < 0)
    return result;

  result = execute_whitelist_action(af, &ip_addr, prefix_len, cmd_buf);
  if (result < 0)
    return result;

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
static int config_show(struct seq_file *m, void *v) {
  seq_printf(m, "Current Firewall Configuration:\n");
  seq_printf(m, "--------------------------------\n");
  seq_printf(m, "ban_time: %u seconds\n", READ_ONCE(fw_ban_time));
  seq_printf(m, "Ban entries: %d\n", atomic_read(&fw_info.ban_count));
  seq_printf(m, "Whitelist entries: %d\n", atomic_read(&fw_info.whitelist_count));
  return 0;
}

static int config_open(struct inode *inode, struct file *file) {
  return single_open(file, config_show, NULL);
}

/* ============================================================================
 * config_write 辅助函数
 * ========================================================================== */

static int parse_config_input(char *input, char *param, size_t param_size, char **value_str_out) {
  char *input_ptr = input;
  char *token;

  token = strsep(&input_ptr, " \t");
  if (!token || strlen(token) == 0 || strlen(token) >= param_size) {
    fw_pr_err("Invalid config format. Use: param value");
    return -EINVAL;
  }
  strncpy(param, token, param_size - 1);
  param[param_size - 1] = '\0';

  *value_str_out = input_ptr;
  if (!*value_str_out || strlen(*value_str_out) == 0) {
    fw_pr_err("Missing value for parameter: %s", param);
    return -EINVAL;
  }

  return 0;
}

static int apply_config_ban_time(unsigned int value) {
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
  return 0;
}

/*
 * config_write - 配置写入处理程序
 */
static ssize_t config_write(struct file *file, const char __user *buf,
                            size_t count, loff_t *ppos) {
  char input[256];
  char param[64];
  char *value_str;
  ssize_t len;
  int result;

  if (!capable(CAP_NET_ADMIN))
    return -EPERM;
  if (count == 0)
    return 0;
  if (count > sizeof(input) - 1)
    return -EINVAL;

  len = min(count, (size_t)(sizeof(input) - 1));
  if (copy_from_user(input, buf, len))
    return -EFAULT;

  input[len] = '\0';
  if (len > 0 && input[len - 1] == '\n')
    input[len - 1] = '\0';

  /* 修复 R6-6：控制字符校验（参考 bans_write 第 418-427 行） */
  {
    size_t i;
    for (i = 0; i < len && input[i] != '\0'; i++) {
      char c = input[i];
      if (c < 0x20 && c != '\t') {
        fw_pr_warn("Invalid control character 0x%02x at position %zu", c, i);
        return -EINVAL;
      }
    }
  }

  result = parse_config_input(input, param, sizeof(param), &value_str);
  if (result < 0)
    return result;

  /* 先检查参数名是否存在，再解析数值，避免无效参数名时误导用户 */
  if (strcmp(param, "ban_time") == 0) {
    unsigned long val;
    int rc = kstrtoul(value_str, 10, &val);
    if (rc != 0 || val == 0 || val > UINT_MAX) {
      fw_pr_err("Invalid value for ban_time: %s", value_str);
      return -EINVAL;
    }
    result = apply_config_ban_time((unsigned int)val);
    if (result < 0)
      return result;
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
 *
 * 说明：
 * - 以下计数器仅反映经过 ban 检查的包(分片 / 非法源 IP 不计入)。
 * - atomic_t 为有符号整型,通过显式强转避免有符号/无符号格式符误用。
 */
static int stats_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;

  seq_printf(m, "total_bans %u\n", (unsigned int)atomic_read(&fw->total_ban_count));
  seq_printf(m, "total_unbans %u\n", (unsigned int)atomic_read(&fw->total_unban_count));
  seq_printf(m, "whitelist_rejects %u\n",
             (unsigned int)atomic_read(&fw->whitelist_reject_count));
  seq_printf(m, "ban_table_full_rejects %u\n",
             (unsigned int)atomic_read(&fw->ban_table_full_count));
  seq_printf(m, "alloc_failures %u\n", (unsigned int)atomic_read(&fw->alloc_failure_count));
  seq_printf(m, "packets_dropped %llu\n",
             (unsigned long long)atomic64_read(&fw->packets_dropped));
  seq_printf(m, "packets_accepted %llu\n",
             (unsigned long long)atomic64_read(&fw->packets_accepted));
  seq_printf(m, "cleanup_cycles %u\n", (unsigned int)atomic_read(&fw->cleanup_cycles));
  seq_printf(m, "cleanup_expired_total %u\n",
             (unsigned int)atomic_read(&fw->cleanup_expired_total));
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

static int stats_open(struct inode *inode, struct file *file) {
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
int create_procfs_entries(struct firewall_info *fw) {
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
void destroy_procfs_entries(struct firewall_info *fw) {
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
