/*
 * state-persist.c - 状态持久化 (支持 IPv4/IPv6)
 *
 * 包含将封禁和白名单状态保存到文件以及从文件恢复的函数实现。
 */

#include "firewall.h"
#include <linux/namei.h>
#include <linux/version.h>

/* 外部变量声明 */
extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

/* 辅助函数：验证文件路径安全 */
static int validate_state_path(const char *filename) {
  if (!filename || !*filename) {
    fw_pr_err("Invalid filename for state save");
    return -EINVAL;
  }

  if (strstr(filename, "%2e") || strstr(filename, "%2E") ||
      strstr(filename, "%2f") || strstr(filename, "%2F")) {
    fw_pr_err("URL-encoded path traversal attempt: %s", filename);
    return -EINVAL;
  }

  {
    const char *dangerous_chars = "|;&`$(){}<>!~*?[]";
    for (const char *p = filename; *p; p++) {
      if (strchr(dangerous_chars, *p)) {
        fw_pr_err("Dangerous character '%c' in path: %s", *p, filename);
        return -EINVAL;
      }
    }
  }

  {
    const char *p = filename;
    while (*p) {
      if (p[0] == '.' && p[1] == '.' && p[2] == '/') {
        fw_pr_err("Potential directory traversal in filename: %s", filename);
        return -EINVAL;
      }
      if (p[0] == '/' && p[1] == '.' && p[2] == '.') {
        if (p[3] == '\0' || p[3] == '/') {
          fw_pr_err("Potential directory traversal in filename: %s", filename);
          return -EINVAL;
        }
      }
      if (p[0] == '.' && p[1] == '.') {
        bool prev_sep = (p == filename) || (p[-1] == '/');
        bool next_sep = (p[2] == '\0') || (p[2] == '/');
        if (prev_sep && next_sep) {
          fw_pr_err("Potential directory traversal in filename: %s", filename);
          return -EINVAL;
        }
      }
      p++;
    }
  }

  if (strncmp(filename, "/var/lib/", 9) != 0 &&
      strncmp(filename, "/tmp/", 5) != 0 &&
      strncmp(filename, "/etc/", 5) != 0) {
    fw_pr_err("State file path outside allowed directories, rejected: %s",
              filename);
    return -EPERM;
  }

  return 0;
}

/*
 * save_state_to_file - 将当前状态保存到文件
 */
int save_state_to_file(const char *filename) {
  struct file *file;
  char buffer[512];
  loff_t pos = 0;
  int written;
  int ret = 0;

  struct saved_ban_entry_v4 {
    __be32 ipv4;
    unsigned long remaining_time;
  };

  struct saved_ban_entry_v6 {
    struct in6_addr ipv6;
    unsigned long remaining_time;
  };

  struct saved_whitelist_entry_v4 {
    __be32 ipv4;
    __be32 mask;
    char device_name[16];
  };

  struct saved_whitelist_entry_v6 {
    struct in6_addr ipv6;
    u8 prefix_len;
    char device_name[16];
  };

#define MAX_SAVE_BAN 1024
#define MAX_SAVE_WL MAX_DISCOVERED_IPS

  struct saved_ban_entry_v4 *ban_entries_v4 = NULL;
  struct saved_ban_entry_v6 *ban_entries_v6 = NULL;
  struct saved_whitelist_entry_v4 *wl_entries_v4 = NULL;
  struct saved_whitelist_entry_v6 *wl_entries_v6 = NULL;
  int ban_count_v4 = 0, ban_count_v6 = 0;
  int wl_count_v4 = 0, wl_count_v6 = 0;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  u32 hash;

  if (validate_state_path(filename) < 0)
    return -EINVAL;

  ban_entries_v4 = kmalloc_array(MAX_SAVE_BAN,
                                 sizeof(struct saved_ban_entry_v4), GFP_KERNEL);
  ban_entries_v6 = kmalloc_array(MAX_SAVE_BAN,
                                 sizeof(struct saved_ban_entry_v6), GFP_KERNEL);
  wl_entries_v4 = kmalloc_array(
      MAX_SAVE_WL, sizeof(struct saved_whitelist_entry_v4), GFP_KERNEL);
  wl_entries_v6 = kmalloc_array(
      MAX_SAVE_WL, sizeof(struct saved_whitelist_entry_v6), GFP_KERNEL);
  if (!ban_entries_v4 || !ban_entries_v6 || !wl_entries_v4 || !wl_entries_v6) {
    kfree(ban_entries_v4);
    kfree(ban_entries_v6);
    kfree(wl_entries_v4);
    kfree(wl_entries_v6);
    fw_pr_err("Failed to allocate memory for saving state entries");
    return -ENOMEM;
  }

  /* 收集 IPv4 封禁 */
  rcu_read_lock();
  hash_for_each_rcu(fw_info.ban_table_ipv4, hash, entry, hash) {
    unsigned long remaining_time;
    if (READ_ONCE(entry->is_permanent))
      remaining_time = 0;
    else if (time_after(READ_ONCE(entry->unban_time), jiffies))
      remaining_time = (READ_ONCE(entry->unban_time) - jiffies) / HZ;
    else
      continue;
    if (ban_count_v4 < MAX_SAVE_BAN) {
      ban_entries_v4[ban_count_v4].ipv4 = READ_ONCE(entry->addr.ipv4);
      ban_entries_v4[ban_count_v4].remaining_time = remaining_time;
      ban_count_v4++;
    }
  }
  rcu_read_unlock();

  /* 收集 IPv6 封禁 */
  rcu_read_lock();
  hash_for_each_rcu(fw_info.ban_table_ipv6, hash, entry, hash) {
    unsigned long remaining_time;
    if (READ_ONCE(entry->is_permanent))
      remaining_time = 0;
    else if (time_after(READ_ONCE(entry->unban_time), jiffies))
      remaining_time = (READ_ONCE(entry->unban_time) - jiffies) / HZ;
    else
      continue;
    if (ban_count_v6 < MAX_SAVE_BAN) {
      memcpy(&ban_entries_v6[ban_count_v6].ipv6, &entry->addr.ipv6,
             sizeof(struct in6_addr));
      ban_entries_v6[ban_count_v6].remaining_time = remaining_time;
      ban_count_v6++;
    }
  }
  rcu_read_unlock();

  /* 收集 IPv4 白名单 */
  rcu_read_lock();
  hash_for_each_rcu(fw_info.whitelist_table_ipv4, hash, wl_entry, hash) {
    if (wl_count_v4 < MAX_SAVE_WL) {
      wl_entries_v4[wl_count_v4].ipv4 = READ_ONCE(wl_entry->addr.ipv4);
      wl_entries_v4[wl_count_v4].mask = READ_ONCE(wl_entry->mask.ipv4_mask);
      strscpy(wl_entries_v4[wl_count_v4].device_name, wl_entry->device_name,
              sizeof(wl_entries_v4[wl_count_v4].device_name));
      wl_count_v4++;
    }
  }
  rcu_read_unlock();

  /* 收集 IPv6 白名单 */
  rcu_read_lock();
  hash_for_each_rcu(fw_info.whitelist_table_ipv6, hash, wl_entry, hash) {
    if (wl_count_v6 < MAX_SAVE_WL) {
      memcpy(&wl_entries_v6[wl_count_v6].ipv6, &wl_entry->addr.ipv6,
             sizeof(struct in6_addr));
      wl_entries_v6[wl_count_v6].prefix_len =
          READ_ONCE(wl_entry->mask.prefix_len);
      strscpy(wl_entries_v6[wl_count_v6].device_name, wl_entry->device_name,
              sizeof(wl_entries_v6[wl_count_v6].device_name));
      wl_count_v6++;
    }
  }
  rcu_read_unlock();

  file = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
  if (IS_ERR(file)) {
    fw_pr_err("Failed to open file for saving state: %s", filename);
    ret = -EIO;
    goto out_free;
  }

  ino_t saved_ino = 0;
  dev_t saved_dev = 0;
  {
    struct kstat open_stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    int getattr_err = vfs_getattr(&file->f_path, &open_stat, STATX_BASIC_STATS,
                                  AT_STATX_SYNC_AS_STAT);
#else
    int getattr_err = vfs_getattr(&file->f_path, &open_stat);
#endif
    if (getattr_err || !S_ISREG(open_stat.mode)) {
      fw_pr_err("Failed to stat state file or not regular: %s", filename);
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
    saved_ino = open_stat.ino;
    saved_dev = open_stat.dev;
  }

  /* 写入 IPv4 封禁 */
  for (int i = 0; i < ban_count_v4; i++) {
    char ip_str[INET_ADDRSTRLEN];
    ip_to_str(FW_AF_INET, &ban_entries_v4[i].ipv4, ip_str, sizeof(ip_str));
    written = snprintf(buffer, sizeof(buffer), "BAN_V4 %s %lu\n", ip_str,
                       ban_entries_v4[i].remaining_time);
    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write ban entry to state file");
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
  }

  /* 写入 IPv6 封禁 */
  for (int i = 0; i < ban_count_v6; i++) {
    char ip_str[INET6_STR_LEN];
    ip_to_str(FW_AF_INET6, &ban_entries_v6[i].ipv6, ip_str, sizeof(ip_str));
    written = snprintf(buffer, sizeof(buffer), "BAN_V6 %s %lu\n", ip_str,
                       ban_entries_v6[i].remaining_time);
    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write ban entry to state file");
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
  }

  /* 写入 IPv4 白名单 */
  for (int i = 0; i < wl_count_v4; i++) {
    char ip_str[INET_ADDRSTRLEN];
    __be32 net_addr = wl_entries_v4[i].ipv4 & wl_entries_v4[i].mask;
    ip_to_str(FW_AF_INET, &net_addr, ip_str, sizeof(ip_str));
    written = snprintf(buffer, sizeof(buffer), "WL_V4 %s %d %s\n", ip_str,
                       inet_mask_len(wl_entries_v4[i].mask),
                       wl_entries_v4[i].device_name);
    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write whitelist entry to state file");
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
  }

  /* 写入 IPv6 白名单 */
  for (int i = 0; i < wl_count_v6; i++) {
    written = snprintf(buffer, sizeof(buffer), "WL_V6 %pI6 %d %s\n",
                       &wl_entries_v6[i].ipv6, wl_entries_v6[i].prefix_len,
                       wl_entries_v6[i].device_name);
    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write whitelist entry to state file");
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
  }

  /* TOCTOU 验证 */
  {
    struct kstat close_stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    int getattr_err = vfs_getattr(&file->f_path, &close_stat, STATX_BASIC_STATS,
                                  AT_STATX_SYNC_AS_STAT);
#else
    int getattr_err = vfs_getattr(&file->f_path, &close_stat);
#endif
    if (getattr_err || close_stat.ino != saved_ino ||
        close_stat.dev != saved_dev) {
      fw_pr_err(
          "State file inode changed during write (possible TOCTOU attack): %s",
          filename);
      filp_close(file, NULL);
      ret = -EIO;
      goto out_free;
    }
  }

  filp_close(file, NULL);
  fw_pr_info("State saved to %s (ban v4: %d, ban v6: %d, wl v4: %d, wl v6: %d)",
             filename, ban_count_v4, ban_count_v6, wl_count_v4, wl_count_v6);

out_free:
  kfree(ban_entries_v4);
  kfree(ban_entries_v6);
  kfree(wl_entries_v4);
  kfree(wl_entries_v6);
  return ret;
}
EXPORT_SYMBOL_GPL(save_state_to_file);

/* 防止重复恢复状态的标记（模块生命周期内仅恢复一次） */
static bool state_restored = false;

/*
 * restore_state_from_file - 从文件恢复状态
 */
int restore_state_from_file(const char *filename) {
  struct file *file;
  char *buffer;
  loff_t pos = 0;
  ssize_t bytes_read;
  char *line, *token;
  int restored_ban_count = 0, restored_wl_count = 0;
  const int max_restore_bans = MAX_BAN_ENTRIES;
  const int max_restore_wl = MAX_DISCOVERED_IPS;

  /* 修复 S2-3：防止重复恢复状态导致竞态 */
  if (state_restored)
    return 0;

  if (!filename || !*filename) {
    fw_pr_err("Invalid filename for state restore");
    return -EINVAL;
  }

  if (validate_state_path(filename) < 0)
    return -EINVAL;

#define MAX_STATE_FILE_SIZE (128 * 1024)
  buffer = kmalloc(MAX_STATE_FILE_SIZE, GFP_KERNEL);
  if (!buffer) {
    fw_pr_err("Failed to allocate buffer for state restore");
    return -ENOMEM;
  }

  file = filp_open(filename, O_RDONLY | O_NOFOLLOW, 0);
  if (IS_ERR(file)) {
    if (PTR_ERR(file) == -ELOOP)
      fw_pr_warn("State restore: symlink detected and rejected: %s", filename);
    else
      fw_pr_info("State file does not exist: %s", filename);
    kfree(buffer);
    return 0;
  }

  {
    struct kstat stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    int stat_err = vfs_getattr(&file->f_path, &stat, STATX_BASIC_STATS,
                               AT_STATX_SYNC_AS_STAT);
#else
    int stat_err = vfs_getattr(&file->f_path, &stat);
#endif
    if (stat_err == 0 && !S_ISREG(stat.mode)) {
      fw_pr_err("State restore: not a regular file: %s", filename);
      filp_close(file, NULL);
      kfree(buffer);
      return -EINVAL;
    }
  }

  bytes_read = 0;
  while (bytes_read < MAX_STATE_FILE_SIZE - 1) {
    ssize_t chunk;
    chunk = kernel_read(file, buffer + bytes_read,
                        MAX_STATE_FILE_SIZE - 1 - bytes_read, &pos);
    if (chunk <= 0)
      break;
    bytes_read += chunk;
  }

  /* 修复 R6-5：状态文件超过大小时添加警告日志 */
  if (bytes_read >= MAX_STATE_FILE_SIZE - 1) {
    fw_pr_warn("State file truncated at %d bytes (max %d)",
               (int)bytes_read, MAX_STATE_FILE_SIZE - 1);
  }

  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';

    line = buffer;
    while ((token = strsep(&line, "\n")) != NULL) {
      if (*token == '\0')
        continue;

      char *cmd = strsep(&token, " ");
      if (!cmd || !*cmd)
        continue;

      /* 恢复 IPv4 封禁 */
      if (strcmp(cmd, "BAN_V4") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *time_str = strsep(&token, " ");

        /* 修复 W2-6：增强格式校验，确保只有预期的字段 */
        if (ip_str && time_str && (!token || *token == '\0')) {
          __be32 ip;
          if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
            if (is_in_whitelist(&fw_info, FW_AF_INET, &ip)) {
              fw_pr_info("Skipping restored ban for whitelisted IP %s", ip_str);
              continue;
            }

            if (restored_ban_count >= max_restore_bans) {
              fw_pr_warn("Maximum ban entries (%d) reached during restore",
                         max_restore_bans);
              continue;
            }

            unsigned long remaining_time;
            if (kstrtoul(time_str, 10, &remaining_time) == 0) {
              struct ban_entry *entry;
              bool is_permanent = false;
              unsigned long unban_time = 0;

              if (remaining_time == 0) {
                is_permanent = true;
              } else if (remaining_time > 365UL * 24 * 60 * 60) {
                fw_pr_warn("Skipping ban with invalid remaining time: %lu",
                           remaining_time);
                continue;
              } else {
                unsigned long ban_duration;
                if (check_mul_overflow(remaining_time, (unsigned long)HZ,
                                       &ban_duration)) {
                  fw_pr_warn("Ban duration overflow for IP %s, skipping",
                             ip_str);
                  continue;
                }
                unban_time = jiffies + ban_duration;
              }

              entry = kmalloc(sizeof(*entry), GFP_KERNEL);
              if (!entry) {
                fw_pr_err("Failed to allocate memory for restored ban entry");
                continue;
              }

              entry->af = FW_AF_INET;
              entry->addr.ipv4 = ip;
              entry->ban_time = jiffies;
              entry->unban_time = unban_time;
              entry->is_permanent = is_permanent;
              atomic_set(&entry->retry_count, 0);

              spin_lock(&fw_info.lock);
              {
                u32 bkt4 = hash_min(ip, BAN_HASH_BITS);
                struct ban_entry *existing;
                bool duplicate = false;

                hlist_for_each_entry_rcu(existing,
                                         &fw_info.ban_table_ipv4[bkt4], hash,
                                         lockdep_is_held(&fw_info.lock)) {
                  if (existing->af == FW_AF_INET && existing->addr.ipv4 == ip) {
                    duplicate = true;
                    break;
                  }
                }

                if (duplicate) {
                  spin_unlock(&fw_info.lock);
                  kfree(entry);
                  fw_pr_info("Skipping duplicate ban entry for IP %s", ip_str);
                } else {
                  hash_add_rcu(fw_info.ban_table_ipv4, &entry->hash, ip);
                  atomic_inc(&fw_info.ban_count);
                  atomic_inc(&fw_info.total_ban_count);
                  spin_unlock(&fw_info.lock);
                  restored_ban_count++;
                }
              }
            }
          }
        }
        /* 恢复 IPv6 封禁 */
      } else if (strcmp(cmd, "BAN_V6") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *time_str = strsep(&token, " ");

        if (ip_str && time_str && (!token || *token == '\0')) {
          struct in6_addr ip6;
          if (in6_pton(ip_str, -1, (u8 *)&ip6, -1, NULL)) {
            if (is_in_whitelist(&fw_info, FW_AF_INET6, &ip6)) {
              fw_pr_info("Skipping restored ban for whitelisted IP %s", ip_str);
              continue;
            }

            if (restored_ban_count >= max_restore_bans)
              continue;

            unsigned long remaining_time;
            if (kstrtoul(time_str, 10, &remaining_time) == 0) {
              struct ban_entry *entry;
              bool is_permanent = false;
              unsigned long unban_time = 0;

              if (remaining_time == 0) {
                is_permanent = true;
              } else if (remaining_time > 365UL * 24 * 60 * 60) {
                continue;
              } else {
                unsigned long ban_duration;
                if (check_mul_overflow(remaining_time, (unsigned long)HZ,
                                       &ban_duration)) {
                  fw_pr_warn("Ban duration overflow for IP %s, skipping",
                             ip_str);
                  continue;
                }
                unban_time = jiffies + ban_duration;
              }

              entry = kmalloc(sizeof(*entry), GFP_KERNEL);
              if (!entry)
                continue;

              entry->af = FW_AF_INET6;
              entry->addr.ipv6 = ip6;
              entry->ban_time = jiffies;
              entry->unban_time = unban_time;
              entry->is_permanent = is_permanent;
              atomic_set(&entry->retry_count, 0);

              spin_lock(&fw_info.lock);
              {
                u32 bkt6 = jhash(&ip6, sizeof(ip6), fw_hash_seed) &
                           ((1 << BAN_HASH_BITS) - 1);
                struct ban_entry *existing;
                bool duplicate = false;

                hlist_for_each_entry_rcu(existing,
                                         &fw_info.ban_table_ipv6[bkt6], hash,
                                         lockdep_is_held(&fw_info.lock)) {
                  if (existing->af == FW_AF_INET6 &&
                      ipv6_addr_equal(&existing->addr.ipv6, &ip6)) {
                    duplicate = true;
                    break;
                  }
                }

                if (duplicate) {
                  spin_unlock(&fw_info.lock);
                  kfree(entry);
                  fw_pr_info("Skipping duplicate ban entry for IP %s", ip_str);
                } else {
                  hash_add_rcu(fw_info.ban_table_ipv6, &entry->hash, bkt6);
                  atomic_inc(&fw_info.ban_count);
                  atomic_inc(&fw_info.total_ban_count);
                  spin_unlock(&fw_info.lock);
                  restored_ban_count++;
                }
              }
            }
          }
        }
        /* 恢复 IPv4 白名单 */
      } else if (strcmp(cmd, "WL_V4") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *mask_str = strsep(&token, " ");
        char *dev_name = strsep(&token, " ");

        if (ip_str && mask_str) {
          __be32 ip, mask;
          int prefix_len;

          if (restored_wl_count >= max_restore_wl)
            continue;

          if (kstrtoint(mask_str, 10, &prefix_len) == 0) {
            mask =
                prefix_len == 0 ? 0 : htonl(~((1ULL << (32 - prefix_len)) - 1));

            if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
              __be32 normalized_ip = ip & mask;
              int result = add_whitelist_entry(
                  &fw_info, FW_AF_INET, &normalized_ip, &mask, prefix_len,
                  dev_name ? dev_name : "restored");
              if (result == 0)
                restored_wl_count++;
            }
          }
        }
        /* 恢复 IPv6 白名单 */
      } else if (strcmp(cmd, "WL_V6") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *prefix_str = strsep(&token, " ");
        char *dev_name = strsep(&token, " ");

        if (ip_str && prefix_str) {
          struct in6_addr ip6;
          int prefix_len;

          if (restored_wl_count >= max_restore_wl)
            continue;

          if (kstrtoint(prefix_str, 10, &prefix_len) == 0) {
            if (in6_pton(ip_str, -1, (u8 *)&ip6, -1, NULL)) {
              int result = add_whitelist_entry(
                  &fw_info, FW_AF_INET6, &ip6, NULL, prefix_len,
                  dev_name ? dev_name : "restored");
              if (result == 0)
                restored_wl_count++;
            }
          }
        }
      }
    }
  }

  filp_close(file, NULL);
  kfree(buffer);

  /* 修复 S2-3：标记已恢复，防止重复调用 */
  state_restored = true;

  fw_pr_info("State restored from %s (ban: %d, wl: %d)", filename,
             restored_ban_count, restored_wl_count);
  return 0;
}
EXPORT_SYMBOL_GPL(restore_state_from_file);
