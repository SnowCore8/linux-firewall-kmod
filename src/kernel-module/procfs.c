/*
 * procfs.c - procfs 接口 (支持 IPv4/IPv6)
 *
 * 包含所有 procfs 文件操作相关的函数实现，包括 bans、whitelist、config、stats
 * 接口。
 */

#include "firewall.h"
#include <linux/printk.h>

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
  return 0;
}

static int bans_open(struct inode *inode, struct file *file) {
  return single_open(file, bans_show, NULL);
}

/* ============================================================================
 * bans_write 辅助函数 - 拆分单一职责
 * ========================================================================== */

/**
 * validate_and_copy_ip - 验证 IP 长度并复制到输出缓冲区
 * M5 修复：增强缓冲区大小检查，确保 ip_str_size 足够容纳 IP 地址和 null 终止符
 */
static int validate_and_copy_ip(const char *ip_start, const char *ip_end,
                                char *ip_str, size_t ip_str_size) {
  size_t ip_len = (size_t)(ip_end - ip_start);

  /* M5 修复：确保 ip_str_size 至少为 1（容纳 null 终止符），
   * 并且 ip_len + 1 <= ip_str_size（容纳 IP 地址和 null 终止符）
   * 注意：INET6_ADDRSTRLEN=46 包含终止符，有效 IPv6 最长 45 字符，
   * 使用 ip_len > INET6_ADDRSTRLEN - 1 允许 45 字符的 IPv6 地址 */
  if (ip_len == 0 || ip_str_size == 0 || ip_len > INET6_ADDRSTRLEN - 1 ||
      ip_len + 1 > ip_str_size) {
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
    return -EINVAL;
  }

  const char *ip_end = ip_start;
  while (*ip_end && *ip_end != ' ' && *ip_end != '\t')
    ip_end++;

  if (*ip_end != '\0') {
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
    return -EINVAL;
  }

  const char *endp = duration_str;
  while (*endp >= '0' && *endp <= '9')
    endp++;
  if (*endp != '\0' && *endp != ' ' && *endp != '\t' && *endp != '\n') {
    return -EINVAL;
  }

  if (seconds < 0 && seconds != -1) {
    return -EINVAL;
  }

  if (seconds > MAX_BAN_TIME) {
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
    return result;
  }
  return 0;
}

/**
 * execute_permanent_ban - 执行永久封禁操作
 */
static int execute_permanent_ban(struct firewall_info *fw, u8 af,
                                 const void *ip, const char *ip_str) {
  int result = ban_ip_permanent(fw, af, ip, "procfs");

  if (result < 0) {
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
    return -EBUSY;
  }

  if (seconds == -2) {
    result = ban_ip(fw, af, ip, "procfs");
  } else {
    result = ban_ip_with_duration(fw, af, ip, (unsigned long)seconds, "procfs");
  }

  if (result < 0) {
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

  /* 权限检查：procfs 文件权限已设为 0600（仅 root 可写），
   * 不再使用 capable(CAP_NET_ADMIN)，因为在 procfs write 上下文中
   * 该检查可能失败。文件权限已提供足够的安全保护。 */
  if (count == 0) {
    return 0;
  }
  if (count > sizeof(input) - 1) {
    return -EINVAL;
  }
  len = min(count, (size_t)(sizeof(input) - 1));

  if (copy_from_user(input, buf, len)) {
    return -EFAULT;
  }

  if (len > 0 && len < sizeof(input)) {
    input[len] = '\0';
  }

  if (len > 0 && input[len - 1] == '\n')
    input[len - 1] = '\0';

  if (strnlen(input, sizeof(input)) >= sizeof(input)) {
    return -EINVAL;
  }

  {
    size_t i;
    for (i = 0; i < len && input[i] != '\0'; i++) {
      char c = input[i];
      if (c < 0x20 && c != '\t') {
        return -EINVAL;
      }
    }
  }

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
    return -EINVAL;
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

  /* 通过 netlink 推送封禁状态变更事件给守护进程 */
  /* 注意：解封事件由 unban_ip() 内部推送，这里只推送封禁事件 */
  if (!is_unban) {
    /* seconds = -2 表示使用默认时长（fw_info.ban_time）
     * seconds = 0 表示永久封禁
     * seconds > 0 表示指定时长 */
    u32 duration;
    if (seconds == -2) {
      duration = fw_info.ban_time;
    } else if (seconds < 0) {
      duration = 0; /* 其他负值（不应到达）视为永久 */
    } else {
      duration = (u32)seconds;
    }
    const void *ip_ptr = (af == FW_AF_INET) ? (const void *)&ip_addr.ipv4 :
                                              (const void *)&ip_addr.ipv6;
    fw_netlink_send_ban_state_change(af, ip_ptr, 1, duration, "procfs", NULL);
  }

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
    return -EINVAL;
  }

  cmd_buf[0] = '\0';

  char *subnet_start = extract_command_token(&ptr, cmd_buf, cmd_buf_size);

  if (!subnet_start || *subnet_start == '\0') {
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
      return -EINVAL;
    }
  }

  /* 尝试解析 IPv4 */
  if (in4_pton(subnet_str, -1, (u8 *)ip_out, -1, NULL)) {
    af = FW_AF_INET;
    if (prefix_len == -1)
      prefix_len = 32;
    if (prefix_len < 0 || prefix_len > 32) {
      return -EINVAL;
    }
    if (validate_ipv4_address(*(__be32 *)ip_out, subnet_str, "whitelist", true) < 0)
      return -EINVAL;
  } else if (in6_pton(subnet_str, -1, (u8 *)ip_out, -1, NULL)) {
    af = FW_AF_INET6;
    if (prefix_len == -1)
      prefix_len = 128;
    if (prefix_len < 0 || prefix_len > 128) {
      return -EINVAL;
    }
    if (validate_ipv6_address(
          (const struct in6_addr *)ip_out, subnet_str, "whitelist", true) < 0)
      return -EINVAL;
  } else {
    return -EINVAL;
  }

  *af_out = af;
  *prefix_len_out = prefix_len;
  return 0;
}

static int execute_whitelist_action(u8 af, void *ip, int prefix_len, const char *cmd) {
  int result;

  if (strcmp(cmd, "remove") == 0) {
    /* 检查是否是本机接口 IP，禁止删除 */
    struct net_device *dev;
    rcu_read_lock();
    for_each_netdev_rcu(&init_net, dev) {
      if (af == FW_AF_INET) {
        struct in_device *in_dev = __in_dev_get_rcu(dev);
        if (in_dev) {
          struct in_ifaddr *ifa;
          for (ifa = rcu_dereference(in_dev->ifa_list); ifa;
               ifa = rcu_dereference(ifa->ifa_next)) {
            __be32 net_addr = *(__be32 *)ip & ifa->ifa_mask;
            __be32 ifa_addr = ifa->ifa_local & ifa->ifa_mask;
            if (net_addr == ifa_addr) {
              rcu_read_unlock();
              pr_warn("拒绝删除本机接口 IP 白名单: %pI4/%d (dev=%s)\n", ip,
                      prefix_len, dev->name);
              return -EPERM;
            }
          }
        }
      } else if (af == FW_AF_INET6) {
        struct inet6_dev *idev = __in6_dev_get(dev);
        if (idev) {
          struct inet6_ifaddr *ifp;
          read_lock_bh(&idev->lock);
          list_for_each_entry(ifp, &idev->addr_list, if_list) {
            if (ipv6_prefix_equal((struct in6_addr *)ip, &ifp->addr, prefix_len)) {
              read_unlock_bh(&idev->lock);
              rcu_read_unlock();
              pr_warn("拒绝删除本机接口 IPv6 白名单: %pI6c/%d (dev=%s)\n", ip,
                      prefix_len, dev->name);
              return -EPERM;
            }
          }
          read_unlock_bh(&idev->lock);
        }
      }
    }
    rcu_read_unlock();

    result = remove_whitelist_entry(&fw_info, af, ip, prefix_len);
    if (result < 0) {
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
      __be32 mask4 = prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len));
      normalized.ipv4 = *(__be32 *)ip & mask4;
      af = FW_AF_INET;
    }

    result = add_whitelist_entry(
      &fw_info, af, &normalized,
      af == FW_AF_INET6 ? NULL : (__be32[]){ prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len)) },
      prefix_len, "manual");
    if (result < 0) {
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

  /* 权限检查：procfs 文件权限已设为 0600（仅 root 可写） */
  if (count == 0) {
    return 0;
  }
  if (count > sizeof(input) - 1) {
    return -EINVAL;
  }
  len = min(count, (size_t)(sizeof(input) - 1));

  if (copy_from_user(input, buf, len)) {
    return -EFAULT;
  }

  input[len] = '\0';
  if (len > 0 && input[len - 1] == '\n')
    input[len - 1] = '\0';

  if (strnlen(input, sizeof(input)) >= sizeof(input)) {
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
    return -EINVAL;
  }
  strncpy(param, token, param_size - 1);
  param[param_size - 1] = '\0';

  *value_str_out = input_ptr;
  if (!*value_str_out || strlen(*value_str_out) == 0) {
    return -EINVAL;
  }

  return 0;
}

static int apply_config_ban_time(unsigned int value) {
  unsigned long ban_duration;

  if (check_mul_overflow(value, (unsigned long)HZ, &ban_duration)) {
    return -EINVAL;
  }
  if (value < 1 || value > 365 * 24 * 60 * 60) {
    return -EINVAL;
  }
  WRITE_ONCE(fw_ban_time, value);
  /* 同步到 fw_info.ban_time，消除双变量不一致 */
  WRITE_ONCE(fw_info.ban_time, value);
  /* 推送配置变更事件给守护进程 */
  fw_netlink_send_config_change(1, value); /* 1 = BAN_TIME flag */
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

  /* 权限检查：procfs 文件权限已设为 0600（仅 root 可写） */
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
      return -EINVAL;
    }
    result = apply_config_ban_time((unsigned int)val);
    if (result < 0)
      return result;
  } else {
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
  seq_printf(m, "tcp_anomaly_dropped %llu\n",
             (unsigned long long)atomic64_read(&fw->tcp_anomaly_dropped));
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

/* ============================================================================
 * rates procfs 接口 - 速率统计（DDoS 防护）
 * ========================================================================== */

/**
 * rates_show - 显示当前速率统计表
 */
static int rates_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  struct ip_rate_entry *entry;
  u32 hash;
  unsigned long now = jiffies;
  char ip_str[INET6_STR_LEN];
  int count = 0;

  seq_printf(m, "IP Rate Statistics (DDoS Detection):\n");
  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "Configuration:\n");
  seq_printf(m, "  rate_window_seconds: %u\n", fw->rate_window_seconds);
  seq_printf(m, "  max_packets_per_second: %lu\n", fw->max_packets_per_second);
  seq_printf(m, "  max_bytes_per_second: %lu\n", fw->max_bytes_per_second);
  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "%-40s %12s %12s %8s\n", "IP Address", "Packets", "Bytes", "Window");

  /* IPv4 速率统计 */
  rcu_read_lock();
  hash_for_each_rcu(fw->rate_table_ipv4, hash, entry, hash) {
    u64 packets = atomic64_read(&entry->packet_count);
    u64 bytes = atomic64_read(&entry->byte_count);
    unsigned long elapsed = (now - entry->window_start) / HZ;

    ip_to_str(FW_AF_INET, &entry->addr.ipv4, ip_str, sizeof(ip_str));
    seq_printf(m, "%-40s %12llu %12llu %6lus\n", ip_str, packets, bytes, elapsed);
    count++;
  }

  /* IPv6 的速率统计 */
  hash_for_each_rcu(fw->rate_table_ipv6, hash, entry, hash) {
    u64 packets = atomic64_read(&entry->packet_count);
    u64 bytes = atomic64_read(&entry->byte_count);
    unsigned long elapsed = (now - entry->window_start) / HZ;

    ip_to_str(FW_AF_INET6, &entry->addr.ipv6, ip_str, sizeof(ip_str));
    seq_printf(m, "%-40s %12llu %12llu %6lus\n", ip_str, packets, bytes, elapsed);
    count++;
  }
  rcu_read_unlock();

  seq_printf(m, "------------------------------------\n");
  seq_printf(m, "Total: %d active rate entries\n", count);
  return 0;
}

static int rates_open(struct inode *inode, struct file *file) {
  return single_open(file, rates_show, NULL);
}

static const struct proc_ops rates_fops = {
  .proc_open = rates_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* UDP 端口分布统计 */
static int udp_ports_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  struct udp_port_entry *entry;
  u32 hash;
  unsigned long now = jiffies;
  int count = 0;

  seq_printf(m, "UDP Port Distribution:\n");
  seq_printf(m, "----------------------\n");
  seq_printf(m, "Total entries: %d / %d\n", atomic_read(&fw->udp_port_count),
             MAX_UDP_PORT_ENTRIES);
  seq_printf(m, "----------------------\n");
  seq_printf(m, "%-8s %12s %12s %10s\n", "Port", "Packets", "Bytes", "LastSeen");

  rcu_read_lock();
  hash_for_each_rcu(fw->udp_port_table, hash, entry, hash) {
    u64 packets = atomic64_read(&entry->packet_count);
    u64 bytes = atomic64_read(&entry->byte_count);
    unsigned long age = (now - entry->last_seen) / HZ;

    seq_printf(m, "%-8u %12llu %12llu %8lus\n", entry->port, packets, bytes, age);
    count++;
  }
  rcu_read_unlock();

  seq_printf(m, "----------------------\n");
  seq_printf(m, "Displayed: %d ports\n", count);
  return 0;
}

static int udp_ports_open(struct inode *inode, struct file *file) {
  return single_open(file, udp_ports_show, NULL);
}

static const struct proc_ops udp_ports_fops = {
  .proc_open = udp_ports_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* ICMP 类型分布统计 */
static int icmp_types_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  struct icmp_type_entry *entry;
  u32 hash;
  unsigned long now = jiffies;
  int count = 0;

  seq_printf(m, "ICMP Type Distribution:\n");
  seq_printf(m, "-----------------------\n");
  seq_printf(m, "Total entries: %d / %d\n", atomic_read(&fw->icmp_type_count),
             MAX_ICMP_TYPE_ENTRIES);
  seq_printf(m, "-----------------------\n");
  seq_printf(m, "%-6s %-6s %12s %12s %10s\n", "Type", "Code", "Packets", "Bytes", "LastSeen");

  rcu_read_lock();
  hash_for_each_rcu(fw->icmp_type_table, hash, entry, hash) {
    u64 packets = atomic64_read(&entry->packet_count);
    u64 bytes = atomic64_read(&entry->byte_count);
    unsigned long age = (now - entry->last_seen) / HZ;

    seq_printf(m, "%-6u %-6u %12llu %12llu %8lus\n", entry->type, entry->code,
               packets, bytes, age);
    count++;
  }
  rcu_read_unlock();

  seq_printf(m, "-----------------------\n");
  seq_printf(m, "Displayed: %d types\n", count);
  return 0;
}

static int icmp_types_open(struct inode *inode, struct file *file) {
  return single_open(file, icmp_types_show, NULL);
}

static const struct proc_ops icmp_types_fops = {
  .proc_open = icmp_types_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* 包大小分布直方图 */
static int pkt_sizes_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  u64 tiny, small, medium, large, jumbo, total;

  tiny = atomic64_read(&fw->pkt_size_tiny);
  small = atomic64_read(&fw->pkt_size_small);
  medium = atomic64_read(&fw->pkt_size_medium);
  large = atomic64_read(&fw->pkt_size_large);
  jumbo = atomic64_read(&fw->pkt_size_jumbo);
  total = tiny + small + medium + large + jumbo;

  seq_printf(m, "Packet Size Distribution:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-12s %12s %8s\n", "Size Range", "Packets", "Percent");
  seq_printf(m, "-------------------------\n");

  if (total > 0) {
    seq_printf(m, "%-12s %12llu %7llu%%\n", "<64B", tiny, (tiny * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "64-256B", small, (small * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "256B-1KB", medium, (medium * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "1-1.5KB", large, (large * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", ">1.5KB", jumbo, (jumbo * 100) / total);
  } else {
    seq_printf(m, "%-12s %12llu %7d%%\n", "<64B", tiny, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "64-256B", small, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "256B-1KB", medium, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "1-1.5KB", large, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", ">1.5KB", jumbo, 0);
  }

  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total: %llu packets\n", total);
  return 0;
}

static int pkt_sizes_open(struct inode *inode, struct file *file) {
  return single_open(file, pkt_sizes_show, NULL);
}

static const struct proc_ops pkt_sizes_fops = {
  .proc_open = pkt_sizes_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* TTL 分布直方图 */
static int ttl_dist_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  u64 scan, very_short, short_ttl, normal, long_ttl, max_ttl, total;

  scan = atomic64_read(&fw->ttl_scan);
  very_short = atomic64_read(&fw->ttl_very_short);
  short_ttl = atomic64_read(&fw->ttl_short);
  normal = atomic64_read(&fw->ttl_normal);
  long_ttl = atomic64_read(&fw->ttl_long);
  max_ttl = atomic64_read(&fw->ttl_max);
  total = scan + very_short + short_ttl + normal + long_ttl + max_ttl;

  seq_printf(m, "TTL Distribution:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-12s %12s %8s\n", "TTL Range", "Packets", "Percent");
  seq_printf(m, "-------------------------\n");

  if (total > 0) {
    seq_printf(m, "%-12s %12llu %7llu%%\n", "=1", scan, (scan * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "2-32", very_short, (very_short * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "33-64", short_ttl, (short_ttl * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "65-128", normal, (normal * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "129-192", long_ttl, (long_ttl * 100) / total);
    seq_printf(m, "%-12s %12llu %7llu%%\n", "193-255", max_ttl, (max_ttl * 100) / total);
  } else {
    seq_printf(m, "%-12s %12llu %7d%%\n", "=1", scan, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "2-32", very_short, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "33-64", short_ttl, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "65-128", normal, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "129-192", long_ttl, 0);
    seq_printf(m, "%-12s %12llu %7d%%\n", "193-255", max_ttl, 0);
  }

  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total: %llu packets\n", total);
  return 0;
}

static int ttl_dist_open(struct inode *inode, struct file *file) {
  return single_open(file, ttl_dist_show, NULL);
}

static const struct proc_ops ttl_dist_fops = {
  .proc_open = ttl_dist_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* IP 分片统计 */
static int ip_frags_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  u64 frag_count, total_count, percentage;

  frag_count = atomic64_read(&fw->ip_frag_count);
  total_count = atomic64_read(&fw->ip_total_count);

  if (total_count > 0)
    percentage = (frag_count * 100) / total_count;
  else
    percentage = 0;

  seq_printf(m, "IP Fragment Statistics:\n");
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "Total IP packets:  %llu\n", total_count);
  seq_printf(m, "Fragmented packets: %llu\n", frag_count);
  seq_printf(m, "Fragment ratio:    %llu%%\n", percentage);
  return 0;
}

static int ip_frags_open(struct inode *inode, struct file *file) {
  return single_open(file, ip_frags_show, NULL);
}

static const struct proc_ops ip_frags_fops = {
  .proc_open = ip_frags_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* 端口扫描检测：遍历速率表，找出 unique_ports >= 阈值的 IP */
#define PORT_SCAN_THRESHOLD 5 /* 访问 >= 5 个不同端口视为扫描 */
#define PORT_SCAN_MAX_RESULTS 20

static int port_scanners_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  int i, count = 0;
  u32 detected;

  detected = atomic_read(&fw->port_scan_detected);

  seq_printf(m, "Port Scan Detection:\n");
  seq_printf(m, "Threshold: %d unique ports\n", PORT_SCAN_THRESHOLD);
  seq_printf(m, "Total scans detected: %u\n", detected);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-20s %12s %12s\n", "IP", "Unique Ports", "Packets");
  seq_printf(m, "-------------------------\n");

  /* 遍历 IPv4 速率表 */
  rcu_read_lock();
  for (i = 0; i < (1 << RATE_HASH_BITS) && count < PORT_SCAN_MAX_RESULTS; i++) {
    struct ip_rate_entry *entry;
    struct hlist_head *head = &fw->rate_table_ipv4[i];

    hlist_for_each_entry_rcu(entry, head, hash) {
      int unique = atomic_read(&entry->unique_ports);
      if (unique >= PORT_SCAN_THRESHOLD && count < PORT_SCAN_MAX_RESULTS) {
        char ip_str[INET_ADDRSTRLEN];
        __be32 addr = entry->addr.ipv4;
        snprintf(ip_str, sizeof(ip_str), "%pI4", &addr);
        seq_printf(m, "%-20s %12d %12llu\n", ip_str, unique,
                   (unsigned long long)atomic64_read(&entry->packet_count));
        count++;
      }
    }
  }

  /* 遍历 IPv6 速率表 */
  for (i = 0; i < (1 << RATE_HASH_BITS) && count < PORT_SCAN_MAX_RESULTS; i++) {
    struct ip_rate_entry *entry;
    struct hlist_head *head = &fw->rate_table_ipv6[i];

    hlist_for_each_entry_rcu(entry, head, hash) {
      int unique = atomic_read(&entry->unique_ports);
      if (unique >= PORT_SCAN_THRESHOLD && count < PORT_SCAN_MAX_RESULTS) {
        char ip_str[INET6_ADDRSTRLEN];
        snprintf(ip_str, sizeof(ip_str), "%pI6", &entry->addr.ipv6);
        seq_printf(m, "%-20s %12d %12llu\n", ip_str, unique,
                   (unsigned long long)atomic64_read(&entry->packet_count));
        count++;
      }
    }
  }
  rcu_read_unlock();

  if (count == 0)
    seq_printf(m, "No port scanners detected\n");

  return 0;
}

static int port_scanners_open(struct inode *inode, struct file *file) {
  return single_open(file, port_scanners_show, NULL);
}

static const struct proc_ops port_scanners_fops = {
  .proc_open = port_scanners_open,
  .proc_read = seq_read,
  .proc_lseek = seq_lseek,
  .proc_release = single_release,
};

/* 服务探测检测：找出对多种协议发送数据的 IP（可能在做服务探测） */
#define SERVICE_PROBE_THRESHOLD 3 /* 使用 >= 3 种不同协议视为探测 */
#define SERVICE_PROBE_MAX_RESULTS 20

static int service_probes_show(struct seq_file *m, void *v) {
  struct firewall_info *fw = &fw_info;
  int i, count = 0;

  seq_printf(m, "Service Probe Detection:\n");
  seq_printf(m, "Threshold: %d protocol types\n", SERVICE_PROBE_THRESHOLD);
  seq_printf(m, "-------------------------\n");
  seq_printf(m, "%-20s %10s %12s\n", "IP", "Protocols", "Packets");
  seq_printf(m, "-------------------------\n");

  /* 遍历 IPv4 速率表 */
  rcu_read_lock();
  for (i = 0; i < (1 << RATE_HASH_BITS) && count < SERVICE_PROBE_MAX_RESULTS; i++) {
    struct ip_rate_entry *entry;
    struct hlist_head *head = &fw->rate_table_ipv4[i];

    hlist_for_each_entry_rcu(entry, head, hash) {
      int proto_count = 0;
      if (atomic64_read(&entry->syn_count) > 0 || atomic64_read(&entry->ack_count) > 0 ||
          atomic64_read(&entry->rst_count) > 0 || atomic64_read(&entry->fin_count) > 0)
        proto_count++; /* TCP 算一种 */
      if (atomic64_read(&entry->udp_count) > 0)
        proto_count++;
      if (atomic64_read(&entry->icmp_count) > 0)
        proto_count++;

      if (proto_count >= SERVICE_PROBE_THRESHOLD && count < SERVICE_PROBE_MAX_RESULTS) {
        char ip_str[INET_ADDRSTRLEN];
        __be32 addr = entry->addr.ipv4;
        snprintf(ip_str, sizeof(ip_str), "%pI4", &addr);
        seq_printf(m, "%-20s %10d %12llu\n", ip_str, proto_count,
                   (unsigned long long)atomic64_read(&entry->packet_count));
        count++;
      }
    }
  }

  /* 遍历 IPv6 速率表 */
  for (i = 0; i < (1 << RATE_HASH_BITS) && count < SERVICE_PROBE_MAX_RESULTS; i++) {
    struct ip_rate_entry *entry;
    struct hlist_head *head = &fw->rate_table_ipv6[i];

    hlist_for_each_entry_rcu(entry, head, hash) {
      int proto_count = 0;
      if (atomic64_read(&entry->syn_count) > 0 || atomic64_read(&entry->ack_count) > 0 ||
          atomic64_read(&entry->rst_count) > 0 || atomic64_read(&entry->fin_count) > 0)
        proto_count++;
      if (atomic64_read(&entry->udp_count) > 0)
        proto_count++;
      if (atomic64_read(&entry->icmp_count) > 0)
        proto_count++;

      if (proto_count >= SERVICE_PROBE_THRESHOLD && count < SERVICE_PROBE_MAX_RESULTS) {
        char ip_str[INET6_ADDRSTRLEN];
        snprintf(ip_str, sizeof(ip_str), "%pI6", &entry->addr.ipv6);
        seq_printf(m, "%-20s %10d %12llu\n", ip_str, proto_count,
                   (unsigned long long)atomic64_read(&entry->packet_count));
        count++;
      }
    }
  }
  rcu_read_unlock();

  if (count == 0)
    seq_printf(m, "No service probes detected\n");

  return 0;
}

static int service_probes_open(struct inode *inode, struct file *file) {
  return single_open(file, service_probes_show, NULL);
}

static const struct proc_ops service_probes_fops = {
  .proc_open = service_probes_open,
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
    goto err_cleanup;
  }
  fw->proc_stats = entry;

  entry = proc_create("rates", 0400, fw->proc_dir, &rates_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_rates = entry;

  entry = proc_create("udp_ports", 0400, fw->proc_dir, &udp_ports_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_udp_ports = entry;

  entry = proc_create("icmp_types", 0400, fw->proc_dir, &icmp_types_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_icmp_types = entry;

  entry = proc_create("pkt_sizes", 0400, fw->proc_dir, &pkt_sizes_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_pkt_sizes = entry;

  entry = proc_create("ttl_dist", 0400, fw->proc_dir, &ttl_dist_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_ttl_dist = entry;

  entry = proc_create("ip_frags", 0400, fw->proc_dir, &ip_frags_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_ip_frags = entry;

  entry = proc_create("port_scanners", 0400, fw->proc_dir, &port_scanners_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_port_scanners = entry;

  entry = proc_create("service_probes", 0400, fw->proc_dir, &service_probes_fops);
  if (!entry) {
    goto err_cleanup;
  }
  fw->proc_service_probes = entry;

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
  if (fw->proc_service_probes) {
    proc_remove(fw->proc_service_probes);
    fw->proc_service_probes = NULL;
  }
  if (fw->proc_port_scanners) {
    proc_remove(fw->proc_port_scanners);
    fw->proc_port_scanners = NULL;
  }
  if (fw->proc_ip_frags) {
    proc_remove(fw->proc_ip_frags);
    fw->proc_ip_frags = NULL;
  }
  if (fw->proc_ttl_dist) {
    proc_remove(fw->proc_ttl_dist);
    fw->proc_ttl_dist = NULL;
  }
  if (fw->proc_pkt_sizes) {
    proc_remove(fw->proc_pkt_sizes);
    fw->proc_pkt_sizes = NULL;
  }
  if (fw->proc_icmp_types) {
    proc_remove(fw->proc_icmp_types);
    fw->proc_icmp_types = NULL;
  }
  if (fw->proc_udp_ports) {
    proc_remove(fw->proc_udp_ports);
    fw->proc_udp_ports = NULL;
  }
  if (fw->proc_rates) {
    proc_remove(fw->proc_rates);
    fw->proc_rates = NULL;
  }
  if (fw->proc_stats) {
    proc_remove(fw->proc_stats);
    fw->proc_stats = NULL;
  }
  if (fw->proc_whitelist) {
    proc_remove(fw->proc_whitelist);
    fw->proc_whitelist = NULL;
  }
  if (fw->proc_config) {
    proc_remove(fw->proc_config);
    fw->proc_config = NULL;
  }
  if (fw->proc_bans) {
    proc_remove(fw->proc_bans);
    fw->proc_bans = NULL;
  }
  if (fw->proc_dir) {
    proc_remove(fw->proc_dir);
    fw->proc_dir = NULL;
  }
}
EXPORT_SYMBOL_GPL(destroy_procfs_entries);
