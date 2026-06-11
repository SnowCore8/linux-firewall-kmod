/*
 * ban-manager.c - 封禁/解封操作 (支持 IPv4/IPv6)
 */

#include "ban-manager.h"
#include "firewall-daemon.h"

/* Forward declarations for functions used by cached fd logic */
static int verify_procfs_fd(int fd);
static int write_to_procfs_fd(int fd, const char *data, size_t data_len);

/* R9-9 修复：缓存 procfs fd，避免每次封禁操作都 open/close。
 * 在首次写入时打开并验证，之后复用。如果写入失败则重新打开。 */
static _Atomic(int) cached_bans_fd = -1;
static pthread_mutex_t bans_fd_mutex = PTHREAD_MUTEX_INITIALIZER;

/* 获取或重新打开缓存的 bans procfs fd */
static int get_cached_bans_fd(void) {
  int fd = atomic_load(&cached_bans_fd);
  if (fd >= 0) {
    /* 快速路径：验证 fd 仍然有效 */
    if (verify_procfs_fd(fd) == 0)
      return fd;
    /* fd 已失效，关闭并重新打开 */
    close(fd);
    atomic_store(&cached_bans_fd, -1);
  }

  /* 慢速路径：打开并验证 */
  pthread_mutex_lock(&bans_fd_mutex);
  /* 双重检查 */
  fd = atomic_load(&cached_bans_fd);
  if (fd >= 0 && verify_procfs_fd(fd) == 0) {
    pthread_mutex_unlock(&bans_fd_mutex);
    return fd;
  }
  if (fd >= 0)
    close(fd);

  fd = open(BANS_PATH, O_WRONLY | O_NOFOLLOW);
  if (fd < 0) {
    LOG_ERR("Failed to open %s: %s", BANS_PATH, strerror(errno));
    pthread_mutex_unlock(&bans_fd_mutex);
    return -1;
  }

  if (verify_procfs_fd(fd) < 0) {
    close(fd);
    pthread_mutex_unlock(&bans_fd_mutex);
    return -1;
  }

  atomic_store(&cached_bans_fd, fd);
  pthread_mutex_unlock(&bans_fd_mutex);
  return fd;
}

/* 关闭缓存的 bans fd（用于守护进程关闭时清理） */
void close_cached_bans_fd(void) {
  int fd = atomic_exchange(&cached_bans_fd, -1);
  if (fd >= 0)
    close(fd);
}

/*
 * validate_ipv4 - 验证并解析IPv4地址字符串 (向后兼容)
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

  unsigned int ip_num = ntohl(addr4.s_addr);
  if (ip_num == 0 || ip_num == 0xFFFFFFFF || ((ip_num >> 24) & 0xFF) == 127 ||
      (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {
    return -1;
  }

  if (out) {
    out->af = AF_INET;
    out->addr.addr4 = addr4;
    out->ip_num = addr4.s_addr;
  }

  return 0;
}

/*
 * validate_ip - 验证并解析IP地址字符串 (支持 IPv4/IPv6)
 */
int validate_ip(const char *ip, validated_ip_t *out) {
  struct in_addr addr4;
  struct in6_addr addr6;
  size_t ip_len;

  if (!ip)
    return -1;

  ip_len = strlen(ip);
  if (ip_len == 0 || ip_len >= INET6_ADDRSTRLEN)
    return -1;

  /* 先尝试 IPv4 */
  if (inet_pton(AF_INET, ip, &addr4) == 1) {
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF || ((ip_num >> 24) & 0xFF) == 127 ||
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {
      return -1;
    }
    if (out) {
      out->af = AF_INET;
      out->addr.addr4 = addr4;
      out->ip_num = addr4.s_addr;
    }
    return 0;
  }

  /* 再尝试 IPv6 */
  if (inet_pton(AF_INET6, ip, &addr6) == 1) {
    /* 拒绝 ::1 (loopback) 和 multicast */
    if (IN6_IS_ADDR_LOOPBACK(&addr6) || IN6_IS_ADDR_MULTICAST(&addr6) ||
        IN6_IS_ADDR_UNSPECIFIED(&addr6)) {
      return -1;
    }
    /* 拒绝 link-local (fe80::/10) */
    if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
      return -1;
    }
    if (out) {
      out->af = AF_INET6;
      out->addr.addr6 = addr6;
      out->ip_num = 0;
    }
    return 0;
  }

  return -1;
}

/* 安全的procfs文件操作辅助函数 */

static int validate_procfs_path(const char *path) {
  const char *p;

  if (strncmp(path, PROCFS_DIR "/", strlen(PROCFS_DIR) + 1) != 0) {
    LOG_ERR("secure_procfs_write: path outside %s: %s", PROCFS_DIR, path);
    return -1;
  }

  if (strstr(path, "..") != NULL) {
    LOG_ERR("secure_procfs_write: path traversal attempt: %s", path);
    return -1;
  }

  for (p = path + sizeof(PROCFS_DIR); *p; p++) {
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '/' || *p == '-' || *p == '_' || *p == '.')) {
      LOG_ERR("secure_procfs_write: invalid character in path: %s "
              "(char: '%c' at offset %ld)",
              path, *p, (long)(p - path));
      return -1;
    }
  }

  size_t path_len = strlen(path);
  if (path_len > 0 && path[path_len - 1] == '/') {
    LOG_ERR("secure_procfs_write: path ends with '/': %s", path);
    return -1;
  }

  return 0;
}

static int verify_procfs_fd(int fd) {
  char proc_fd_path[64];
  char link_target[PATH_MAX];
  ssize_t link_len;

  snprintf(proc_fd_path, sizeof(proc_fd_path), "/proc/self/fd/%d", fd);
  link_len = readlink(proc_fd_path, link_target, sizeof(link_target) - 1);
  if (link_len < 0) {
    LOG_ERR("Failed to read link for fd %d: %s", fd, strerror(errno));
    return -1;
  }
  link_target[link_len] = '\0';

  if (strncmp(link_target, "/proc/firewall/", 15) != 0) {
    LOG_ERR("secure_procfs_write: fd %d points to non-procfs path: "
            "%s (expected /proc/firewall/...)",
            fd, link_target);
    return -1;
  }

  return 0;
}

static int write_to_procfs_fd(int fd, const char *data, size_t data_len) {
  ssize_t written;
  size_t total_written = 0;

  while (total_written < data_len) {
    written = write(fd, data + total_written, data_len - total_written);
    if (written < 0) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      LOG_ERR("Failed to write to procfs fd %d: %s", fd, strerror(errno));
      return -1;
    }
    total_written += written;
  }

  return 0;
}

int secure_procfs_write(const char *path, const char *data, size_t data_len) {
  int fd = -1;
  int ret = -1;
  bool using_cached = false;

  if (!path || !data || data_len == 0) {
    LOG_ERR("Invalid parameters to secure_procfs_write");
    goto cleanup;
  }

  if (validate_procfs_path(path) < 0)
    goto cleanup;

  if (data_len > 64) {
    LOG_ERR("Data too long for procfs write (%zu bytes, max 64)", data_len);
    goto cleanup;
  }

  /* R9-9: 对 bans 路径使用缓存的 fd，避免每次 open/close */
  if (strcmp(path, BANS_PATH) == 0) {
    fd = get_cached_bans_fd();
    if (fd < 0)
      goto cleanup;
    using_cached = true;
  } else {
    fd = open(path, O_WRONLY | O_NOFOLLOW);
    if (fd < 0) {
      LOG_ERR("Failed to open %s: %s", path, strerror(errno));
      goto cleanup;
    }
    if (verify_procfs_fd(fd) < 0)
      goto cleanup;
  }

  if (write_to_procfs_fd(fd, data, data_len) < 0) {
    /* R9-9: 如果使用缓存 fd 写入失败，关闭并标记为无效，下次重新打开 */
    if (using_cached) {
      atomic_store(&cached_bans_fd, -1);
      close(fd);
      fd = -1;
    }
    goto cleanup;
  }

  ret = 0;

cleanup:
  /* R9-9: 缓存 fd 不关闭，仅关闭非缓存路径的 fd */
  if (fd >= 0 && !using_cached) {
    if (close(fd) < 0 && ret == 0)
      LOG_WARN("Failed to close %s: %s", path, strerror(errno));
  }

  return ret;
}

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
    /* fall-through: UNBAN and UNBAN_PERM use the same "unban" command format */
  case BAN_ACTION_UNBAN_PERM:
    cmd_len = snprintf(cmd_buf, cmd_buf_size, "unban %s\n", ip);
    break;
  default:
    LOG_ERR("Unknown ban action type: %d", action);
    return -1;
  }

  if (cmd_len < 0 || (size_t)cmd_len >= cmd_buf_size) {
    LOG_ERR("Command buffer overflow for IP %s", ip);
    return -1;
  }

  return cmd_len;
}

static int execute_sqlite_action(ban_action_t action, const char *ip, validated_ip_t validated) {
  int sqlite_rc = 0;

  if (!sqlite_db)
    return 0;

  if (action == BAN_ACTION_PERMANENT) {
    sqlite_rc = sqlite_add_permanent_ban(
      sqlite_db, ip, validated.ip_num, "manual permanent ban", "manual");
  } else if (action == BAN_ACTION_UNBAN_PERM) {
    sqlite_rc = sqlite_remove_permanent_ban(sqlite_db, ip);
  }

  if (sqlite_rc != 0 && sqlite_rc != -2) {
    LOG_WARN("SQLite operation failed for IP %s (action=%d, rc=%d)", ip, action, sqlite_rc);
    if (action == BAN_ACTION_PERMANENT || action == BAN_ACTION_UNBAN_PERM) {
      return sqlite_rc;
    }
  }

  return 0;
}

static void log_ban_action(ban_action_t action, const char *ip) {
  if (action == BAN_ACTION_TEMP || action == BAN_ACTION_PERMANENT)
    atomic_fetch_add(&daemon_stats.ips_banned, 1);

  switch (action) {
  case BAN_ACTION_TEMP:
    LOG_INFO("Banned IP %s", ip);
    break;
  case BAN_ACTION_PERMANENT:
    LOG_INFO("Permanently banned IP %s", ip);
    break;
  case BAN_ACTION_UNBAN:
    LOG_INFO("Unbanned IP %s", ip);
    break;
  case BAN_ACTION_UNBAN_PERM:
    LOG_INFO("Removed permanent ban for IP %s", ip);
    break;
  default:
    break;
  }
}

/*
 * execute_ban_action - 统一的封禁/解封操作 (支持 IPv4/IPv6)
 */
int execute_ban_action(ban_action_t action, const char *ip) {
  validated_ip_t validated;
  char cmd_buf[INET6_ADDRSTRLEN + 16];
  int cmd_len;

  if (!ip) {
    LOG_ERR("NULL IP address provided to execute_ban_action");
    return -1;
  }

  if (validate_ip(ip, &validated) < 0) {
    LOG_ERR("Invalid IP address: %s", ip);
    return -1;
  }

  cmd_len = format_ban_command(action, ip, cmd_buf, sizeof(cmd_buf));
  if (cmd_len < 0)
    return -1;

  if (secure_procfs_write(BANS_PATH, cmd_buf, (size_t)cmd_len) < 0) {
    LOG_ERR("Failed to write to %s: %s", BANS_PATH, strerror(errno));
    return -1;
  }

  int sqlite_rc = execute_sqlite_action(action, ip, validated);
  if (sqlite_rc < 0) {
    LOG_ERR("SQLite persistence failed for IP %s (action=%d, rc=%d)", ip, action, sqlite_rc);
    return -1;
  }

  log_ban_action(action, ip);

  return 0;
}

/* 向后兼容的包装函数 */
int ban_ip(const char *ip) {
  return execute_ban_action(BAN_ACTION_TEMP, ip);
}

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
  cleanup_partial_line_buffer();
}
