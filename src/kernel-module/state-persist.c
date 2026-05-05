/*
 * state-persist.c - 状态持久化
 *
 * 包含将封禁和白名单状态保存到文件以及从文件恢复的函数实现。
 */

#include "firewall.h"
#include <linux/namei.h>
#include <linux/version.h>

/* 外部变量声明 */
extern struct firewall_info fw_info;

/*
 * save_state_to_file - 将当前状态保存到文件
 */
int save_state_to_file(const char *filename) {
  struct file *file;
  char buffer[512];
  loff_t pos = 0;
  int written;

  struct saved_ban_entry {
    char ip_str[INET_ADDRSTRLEN];
    __be32 ipv4;
    unsigned long remaining_time;
  };

  struct saved_whitelist_entry {
    char ip_str[INET_ADDRSTRLEN];
    __be32 ipv4;
    __be32 mask;
    int prefix_len;
    char device_name[16];
  };

#define MAX_SAVE_BAN 1024
#define MAX_SAVE_WL MAX_DISCOVERED_IPS

  struct saved_ban_entry *ban_entries = NULL;
  struct saved_whitelist_entry *wl_entries = NULL;
  int ban_count = 0;
  int wl_count = 0;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  u32 hash;

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

  ban_entries =
      kmalloc_array(MAX_SAVE_BAN, sizeof(struct saved_ban_entry), GFP_KERNEL);
  if (!ban_entries) {
    fw_pr_err("Failed to allocate memory for saving ban entries");
    return -ENOMEM;
  }

  wl_entries = kmalloc_array(MAX_SAVE_WL, sizeof(struct saved_whitelist_entry),
                             GFP_KERNEL);
  if (!wl_entries) {
    kfree(ban_entries);
    fw_pr_err("Failed to allocate memory for saving whitelist entries");
    return -ENOMEM;
  }

  rcu_read_lock();
  hash_for_each_rcu(fw_info.ban_table, hash, entry, hash) {
    unsigned long remaining_time;
    if (entry->is_permanent) {
      remaining_time = 0;
    } else if (time_after(entry->unban_time, jiffies)) {
      remaining_time = (entry->unban_time - jiffies) / HZ;
    } else {
      continue;
    }
    if (ban_count < MAX_SAVE_BAN) {
      ipv4_to_str(entry->ip, ban_entries[ban_count].ip_str,
                  sizeof(ban_entries[ban_count].ip_str));
      ban_entries[ban_count].ipv4 = entry->ip;
      ban_entries[ban_count].remaining_time = remaining_time;
      ban_count++;
    }
  }
  rcu_read_unlock();

  rcu_read_lock();
  hash_for_each_rcu(fw_info.whitelist_table, hash, wl_entry, hash) {
    if (wl_count < MAX_SAVE_WL) {
      __be32 network_addr = wl_entry->ip & wl_entry->mask;
      ipv4_to_str(network_addr, wl_entries[wl_count].ip_str,
                  sizeof(wl_entries[wl_count].ip_str));
      wl_entries[wl_count].ipv4 = wl_entry->ip;
      wl_entries[wl_count].mask = wl_entry->mask;
      wl_entries[wl_count].prefix_len = inet_mask_len(wl_entry->mask);
      strscpy(wl_entries[wl_count].device_name, wl_entry->device_name,
              sizeof(wl_entries[wl_count].device_name));
      wl_count++;
    }
  }
  rcu_read_unlock();

  file = filp_open(filename, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
  if (IS_ERR(file)) {
    fw_pr_err("Failed to open file for saving state: %s", filename);
    kfree(ban_entries);
    kfree(wl_entries);
    return PTR_ERR(file);
  }

  /* 记录打开时的 inode 信息，用于后续 TOCTOU 验证 */
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
    if (getattr_err) {
      fw_pr_err("Failed to stat state file after open: %s", filename);
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EACCES;
    }
    if (!S_ISREG(open_stat.mode)) {
      fw_pr_err("State file is not a regular file: %s", filename);
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EACCES;
    }
    /* 保存 inode 和设备号，用于写入后验证一致性 */
    saved_ino = open_stat.ino;
    saved_dev = open_stat.dev;
  }

  for (int i = 0; i < ban_count; i++) {
    written = snprintf(buffer, sizeof(buffer), "BAN_V4 %s %lu\n",
                       ban_entries[i].ip_str, ban_entries[i].remaining_time);

    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write ban entry to state file");
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EIO;
    }
  }

  for (int i = 0; i < wl_count; i++) {
    written = snprintf(buffer, sizeof(buffer), "WL_V4 %s %d %s\n",
                       wl_entries[i].ip_str, wl_entries[i].prefix_len,
                       wl_entries[i].device_name);

    if (kernel_write(file, buffer, written, &pos) != written) {
      fw_pr_err("Failed to write whitelist entry to state file");
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EIO;
    }
  }

  /* 写入完成后验证 inode 一致性，防止 TOCTOU 攻击 */
  {
    struct kstat close_stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    int getattr_err = vfs_getattr(&file->f_path, &close_stat, STATX_BASIC_STATS,
                                  AT_STATX_SYNC_AS_STAT);
#else
    int getattr_err = vfs_getattr(&file->f_path, &close_stat);
#endif
    if (getattr_err != 0) {
      fw_pr_err("Failed to stat state file after write: %s", filename);
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EACCES;
    }
    if (close_stat.ino != saved_ino || close_stat.dev != saved_dev) {
      fw_pr_err(
          "State file inode changed during write (possible TOCTOU attack): %s",
          filename);
      filp_close(file, NULL);
      kfree(ban_entries);
      kfree(wl_entries);
      return -EACCES;
    }
  }

  filp_close(file, NULL);

  kfree(ban_entries);
  kfree(wl_entries);

  fw_pr_info("State saved to %s (ban: %d, wl: %d)", filename, ban_count,
             wl_count);
  return 0;
}
EXPORT_SYMBOL_GPL(save_state_to_file);

/*
 * restore_state_from_file - 从文件恢复状态
 */
int restore_state_from_file(const char *filename) {
  struct file *file;
  char *buffer;
  loff_t pos = 0;
  ssize_t bytes_read;
  char *line, *token;

  if (!filename || !*filename) {
    fw_pr_err("Invalid filename for state restore");
    return -EINVAL;
  }

  if (strstr(filename, "..") != NULL) {
    fw_pr_err("State restore: path traversal attempt rejected: %s", filename);
    return -EINVAL;
  }

#define MAX_STATE_FILE_SIZE (64 * 1024)
  buffer = kmalloc(MAX_STATE_FILE_SIZE, GFP_KERNEL);
  if (!buffer) {
    fw_pr_err("Failed to allocate buffer for state restore");
    return -ENOMEM;
  }

  file = filp_open(filename, O_RDONLY | O_NOFOLLOW, 0);
  if (IS_ERR(file)) {
    if (PTR_ERR(file) == -ELOOP) {
      fw_pr_warn("State restore: symlink detected and rejected: %s", filename);
    } else {
      fw_pr_info("State file does not exist: %s", filename);
    }
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
    if (chunk <= 0) {
      break;
    }
    bytes_read += chunk;
  }

  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';

    if (bytes_read >= MAX_STATE_FILE_SIZE - 1) {
      fw_pr_warn("State file truncated at %zd bytes (max %d)", bytes_read,
                 MAX_STATE_FILE_SIZE);
    }

    line = buffer;
    while ((token = strsep(&line, "\n")) != NULL) {
      if (*token == '\0')
        continue;

      char *cmd = strsep(&token, " ");
      if (!cmd)
        continue;

      if (strcmp(cmd, "BAN_V4") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *time_str = strsep(&token, " ");

        if (ip_str && time_str) {
          __be32 ip;
          if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
            if (is_in_whitelist(&fw_info, ip)) {
              fw_pr_info("Skipping restored ban for whitelisted IP %s", ip_str);
              continue;
            }

            unsigned long remaining_time;
            if (kstrtoul(time_str, 10, &remaining_time) == 0) {
              struct ban_entry *entry;
              bool is_permanent = false;
              unsigned long unban_time = 0;

              if (remaining_time == 0) {
                is_permanent = true;
                unban_time = 0;
              } else if (remaining_time > 365UL * 24 * 60 * 60) {
                fw_pr_warn("Skipping ban with invalid remaining time: %lu",
                           remaining_time);
                continue;
              } else {
                is_permanent = false;
                if (remaining_time > (ULONG_MAX / HZ)) {
                  fw_pr_warn(
                      "Skipping ban - remaining_time * HZ would overflow");
                  continue;
                }

                unsigned long ban_duration = remaining_time * HZ;

                if (jiffies > ULONG_MAX - ban_duration) {
                  unban_time = jiffies + min(ban_duration, ULONG_MAX - jiffies);
                  fw_pr_warn(
                      "Jiffies wrap protection applied for ban restoration");
                } else {
                  unban_time = jiffies + ban_duration;
                }
              }

              {
                struct ban_entry *existing;
                bool found = false;

                rcu_read_lock();
                hash_for_each_possible_rcu(fw_info.ban_table, existing, hash,
                                           ip) {
                  if (compare_ips(existing->ip, ip)) {
                    found = true;
                    break;
                  }
                }
                rcu_read_unlock();

                if (found) {
                  fw_pr_info("Skipping duplicate ban for IPv4 %s", ip_str);
                  goto skip_ban_entry;
                }
              }

              entry = kmalloc(sizeof(*entry), GFP_KERNEL);
              if (!entry) {
                fw_pr_err("Failed to allocate memory for restored ban entry");
                goto skip_ban_entry;
              }

              entry->ip = ip;
              entry->ban_time = jiffies;
              entry->unban_time = unban_time;
              entry->is_permanent = is_permanent;
              atomic_set(&entry->retry_count, 0);

              spin_lock(&fw_info.lock);
              hash_add_rcu(fw_info.ban_table, &entry->hash, ip);
              atomic_inc(&fw_info.ban_count);
              atomic_inc(&fw_info.total_ban_count);
              spin_unlock(&fw_info.lock);

              if (is_permanent)
                fw_pr_info("Restored permanent ban for IPv4 %s", ip_str);
              else
                fw_pr_info("Restored ban for IPv4 %s (expires in %lu seconds)",
                           ip_str, remaining_time);

            skip_ban_entry:;
            }
          }
        }
      } else if (strcmp(cmd, "WL_V4") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *mask_str = strsep(&token, " ");
        char *dev_name = strsep(&token, " ");

        if (ip_str && mask_str) {
          __be32 ip, mask = 0xFFFFFFFF;
          int prefix_len;

          if (kstrtoint(mask_str, 10, &prefix_len) == 0) {
            mask =
                prefix_len == 0 ? 0 : htonl(~((1U << (32 - prefix_len)) - 1));

            if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
              __be32 normalized_ip = ip & mask;

              int result =
                  add_whitelist_entry(&fw_info, normalized_ip, mask,
                                      dev_name ? dev_name : "restored");
              if (result == 0) {
                fw_pr_info("Restored whitelist entry for IPv4 %s/%d", ip_str,
                           prefix_len);
              }
            }
          }
        }
      }
    }
  }

  filp_close(file, NULL);
  kfree(buffer);
  fw_pr_info("State restored from %s", filename);
  return 0;
}
EXPORT_SYMBOL_GPL(restore_state_from_file);
