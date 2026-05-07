/*
 * ban-manager.c - 封禁/解封操作
 */

#include "ban-manager.h"
#include "firewall-daemon.h"

/*
 * validate_ipv4 - 验证并解析IPv4地址字符串
 * @ip: 要验证的IP地址字符串
 * @out: 存储解析后地址的输出结构（可为NULL）
 *
 * 返回值：成功返回0，失败返回-1
 *
 * 验证内容：
 * - 非NULL、非空字符串
 * - 长度 < INET_ADDRSTRLEN
 * - 通过 inet_pton 验证有效的IPv4格式
 * - 拒绝：0.0.0.0、255.255.255.255、127.0.0.0/8、224.0.0.0/4（组播）
 */
int validate_ipv4(const char *ip, validated_ip_t *out) {
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

  // 额外验证：拒绝无效IPv4地址，如 0.0.0.0、127.x.x.x、组播地址等
  unsigned int ip_num = ntohl(addr4.s_addr);
  if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
      ((ip_num >> 24) & 0xFF) == 127 || // 127.x.x.x（回环地址）
      (((ip_num >> 24) & 0xFF) >= 224 &&
       ((ip_num >> 24) & 0xFF) <= 239)) { // 224.0.0.0/4（组播地址）
    return -1;
  }

  if (out) {
    out->addr = addr4;
    out->ip_num = addr4.s_addr; // 网络字节序
  }

  return 0;
}

/* 安全的procfs文件操作辅助函数 */

/**
 * validate_procfs_path - 验证procfs路径的安全性
 * @path: 要验证的路径
 * 返回: 0 表示验证通过，-1 表示失败
 */
static int validate_procfs_path(const char *path) {
  const char *p;

  /* 验证路径在 /proc/firewall/ 内 */
  if (strncmp(path, PROCFS_DIR "/", sizeof(PROCFS_DIR) + 1) != 0) {
    daemon_log_err("secure_procfs_write: path outside %s: %s", PROCFS_DIR,
                   path);
    return -1;
  }

  /* 拒绝路径遍历尝试 */
  if (strstr(path, "..") != NULL) {
    daemon_log_err("secure_procfs_write: path traversal attempt: %s", path);
    return -1;
  }

  /* 验证路径只包含安全字符 */
  for (p = path + sizeof(PROCFS_DIR); *p; p++) {
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '/' || *p == '-' || *p == '_' ||
          *p == '.')) {
      daemon_log_err("secure_procfs_write: invalid character in path: %s "
                     "(char: '%c' at offset %ld)",
                     path, *p, (long)(p - path));
      return -1;
    }
  }

  /* 验证路径不以/结尾 */
  size_t path_len = strlen(path);
  if (path_len > 0 && path[path_len - 1] == '/') {
    daemon_log_err("secure_procfs_write: path ends with '/': %s", path);
    return -1;
  }

  return 0;
}

/**
 * verify_procfs_fd - 验证文件描述符指向procfs路径
 * @fd: 文件描述符
 * 返回: 0 表示验证通过，-1 表示失败
 */
static int verify_procfs_fd(int fd) {
  char proc_fd_path[64];
  char link_target[PATH_MAX];
  ssize_t link_len;

  snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/self/fd/%d", fd);
  link_len = readlink(proc_fd_path, link_target, sizeof(link_target) - 1);
  if (link_len < 0) {
    daemon_log_err("Failed to read link for fd %d: %s", fd, strerror(errno));
    return -1;
  }
  link_target[link_len] = '\0';

  /* 验证目标路径确实是procfs路径 */
  if (strncmp(link_target, "/proc/firewall/", 15) != 0) {
    daemon_log_err("secure_procfs_write: fd %d points to non-procfs path: "
                   "%s (expected /proc/firewall/...)",
                   fd, link_target);
    return -1;
  }

  return 0;
}

/**
 * write_to_procfs_fd - 向已打开的procfs文件描述符写入数据
 * @fd: 文件描述符
 * @data: 要写入的数据
 * @data_len: 数据长度
 * 返回: 0 表示成功，-1 表示失败
 */
static int write_to_procfs_fd(int fd, const char *data, size_t data_len) {
  ssize_t written;
  size_t total_written = 0;

  while (total_written < data_len) {
    written = write(fd, data + total_written, data_len - total_written);
    if (written < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue; /* 被中断或资源暂时不可用，重试 */

      daemon_log_err("Failed to write to procfs fd %d: %s", fd,
                     strerror(errno));
      return -1;
    }
    total_written += written;
  }

  return 0;
}

int secure_procfs_write(const char *path, const char *data, size_t data_len) {
  int fd = -1;
  int ret = -1;

  /* 验证输入参数 */
  if (!path || !data || data_len == 0) {
    daemon_log_err("Invalid parameters to secure_procfs_write");
    goto cleanup;
  }

  /* 验证路径安全性 */
  if (validate_procfs_path(path) < 0)
    goto cleanup;

  /* 检查数据长度 - 内核模块 procfs 内部缓冲区有限 */
  if (data_len > 64) {
    daemon_log_err("Data too long for procfs write (%zu bytes, max 64)",
                   data_len);
    goto cleanup;
  }

  /* 打开文件（禁止跟随符号链接） */
  fd = open(path, O_WRONLY | O_NOFOLLOW);
  if (fd < 0) {
    daemon_log_err("Failed to open %s: %s", path, strerror(errno));
    goto cleanup;
  }

  /* 验证文件描述符指向procfs */
  if (verify_procfs_fd(fd) < 0)
    goto cleanup;

  /* 写入数据 */
  if (write_to_procfs_fd(fd, data, data_len) < 0)
    goto cleanup;

  ret = 0; /* 成功 */

cleanup:
  /* 统一资源清理 */
  if (fd >= 0) {
    if (close(fd) < 0 && ret == 0)
      daemon_log_warn("Failed to close %s: %s", path, strerror(errno));
  }

  return ret;
}

/**
 * format_ban_command - 根据操作类型格式化封禁命令
 * @action: 封禁操作类型
 * @ip: IPv4地址字符串
 * @cmd_buf: 输出缓冲区
 * @cmd_buf_size: 缓冲区大小
 * 返回: 写入的字节数，失败返回-1
 */
static int format_ban_command(ban_action_t action, const char *ip,
                              char *cmd_buf, size_t cmd_buf_size) {
  int cmd_len;

  switch (action) {
  case BAN_ACTION_TEMP:
    cmd_len = snprintf(cmd_buf, cmd_buf_size, "%s\n", ip);
    break;
  case BAN_ACTION_PERMANENT:
    cmd_len = snprintf(cmd_buf, cmd_buf_size, "%s 0\n", ip);
    break;
  case BAN_ACTION_UNBAN:
  case BAN_ACTION_UNBAN_PERM:
    cmd_len = snprintf(cmd_buf, cmd_buf_size, "unban %s\n", ip);
    break;
  default:
    daemon_log_err("Unknown ban action type: %d", action);
    return -1;
  }

  if (cmd_len < 0 || (size_t)cmd_len >= cmd_buf_size) {
    daemon_log_err("Command buffer overflow for IP %s", ip);
    return -1;
  }

  return cmd_len;
}

/**
 * execute_sqlite_action - 执行SQLite持久化操作
 * @action: 封禁操作类型
 * @ip: IPv4地址字符串
 * @validated: 已验证的IP结构
 * 返回: 0 表示成功，负数表示失败
 *
 * 安全考虑：对于永久封禁/解封操作，SQLite 持久化失败必须返回错误，
 * 否则系统重启后封禁状态丢失，安全策略被绕过。
 */
static int execute_sqlite_action(ban_action_t action, const char *ip,
                                 validated_ip_t validated) {
  int sqlite_rc = 0;

  if (!sqlite_db)
    return 0;

  if (action == BAN_ACTION_PERMANENT) {
    sqlite_rc = sqlite_add_permanent_ban(sqlite_db, ip, validated.ip_num,
                                         "manual permanent ban", "manual");
  } else if (action == BAN_ACTION_UNBAN_PERM) {
    sqlite_rc = sqlite_remove_permanent_ban(sqlite_db, ip);
  }

  if (sqlite_rc != 0 && sqlite_rc != -2) { /* -2 = 已存在（不是错误） */
    daemon_log_warn("SQLite operation failed for IP %s (action=%d, rc=%d)", ip,
                    action, sqlite_rc);
    /* 安全考虑：永久封禁/解封操作的 SQLite 失败必须返回错误，
     * 防止重启后封禁状态丢失导致安全策略被绕过 */
    if (action == BAN_ACTION_PERMANENT || action == BAN_ACTION_UNBAN_PERM) {
      return sqlite_rc;
    }
  }

  return 0;
}

/**
 * log_ban_action - 记录封禁操作日志和更新统计
 * @action: 封禁操作类型
 * @ip: IPv4地址字符串
 */
static void log_ban_action(ban_action_t action, const char *ip) {
  /* 更新统计 */
  if (action == BAN_ACTION_TEMP || action == BAN_ACTION_PERMANENT)
    atomic_fetch_add(&daemon_stats.ips_banned, 1);

  /* 记录操作日志 */
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
  default:
    break;
  }
}

/*
 * execute_ban_action - 统一的封禁/解封操作
 * @action: 要执行的封禁/解封操作类型
 * @ip: IPv4地址字符串
 *
 * 返回值：成功返回0，失败返回-1
 */
int execute_ban_action(ban_action_t action, const char *ip) {
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

  /* 格式化命令 */
  cmd_len = format_ban_command(action, ip, cmd_buf, sizeof(cmd_buf));
  if (cmd_len < 0)
    return -1;

  /* 通过procfs写入内核模块 */
  if (secure_procfs_write(BANS_PATH, cmd_buf, (size_t)cmd_len) < 0) {
    daemon_log_err("Failed to write to %s", BANS_PATH);
    return -1;
  }

  /* 处理SQLite持久化 */
  int sqlite_rc = execute_sqlite_action(action, ip, validated);
  if (sqlite_rc < 0) {
    daemon_log_err("SQLite persistence failed for IP %s (action=%d, rc=%d)", ip,
                   action, sqlite_rc);
    /* 安全考虑：永久封禁/解封操作的 SQLite 失败必须返回错误，
     * 由 execute_sqlite_action 已返回负值，此处直接阻断操作 */
    return -1;
  }

  /* 记录操作日志和更新统计 */
  log_ban_action(action, ip);

  return 0;
}

/* 向后兼容的包装函数 */
int ban_ip(const char *ip) { return execute_ban_action(BAN_ACTION_TEMP, ip); }

int ban_ip_permanent(const char *ip) {
  return execute_ban_action(BAN_ACTION_PERMANENT, ip);
}

int unban_ip(const char *ip) {
  return execute_ban_action(BAN_ACTION_UNBAN, ip);
}

int unban_permanent_ip(const char *ip) {
  return execute_ban_action(BAN_ACTION_UNBAN_PERM, ip);
}

/* 清理过期封禁和部分行缓冲区（可选，内核已处理） */
void cleanup_expired_bans(void) {
  /* 内核模块通过定时器自动清理 */
  /* 此函数是未来同步逻辑的占位符 */

  /* 同时定期清理部分行缓冲区以防止累积 */
  cleanup_partial_line_buffer();
}