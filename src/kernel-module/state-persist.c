/*
 * state-persist.c - 状态持久化 (支持 IPv4/IPv6)
 *
 * 包含将封禁和白名单状态保存到文件以及从文件恢复的函数实现。
 */

#include "firewall.h"
#include <linux/crc32.h>
#include <linux/kmod.h>
#include <linux/namei.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/timer.h>

/* 声明 ban_entry_expire_callback 函数（定义在 ban-manager.c 中） */
extern void ban_entry_expire_callback(struct timer_list *t);
#include <linux/version.h>

/* 外部变量声明 */
extern struct firewall_info fw_info;
extern u32 fw_hash_seed;

/* 辅助函数：验证文件路径安全 */
static int validate_state_path(const char *filename) {
  if (!filename || !*filename) {
    return -EINVAL;
  }

  if (strstr(filename, "%2e") || strstr(filename, "%2E") ||
      strstr(filename, "%2f") || strstr(filename, "%2F")) {
    return -EINVAL;
  }

  {
    const char *dangerous_chars = "|;&`$(){}<>!~*?[]";
    for (const char *p = filename; *p; p++) {
      if (strchr(dangerous_chars, *p)) {
        return -EINVAL;
      }
    }
  }

  {
    const char *p = filename;
    while (*p) {
      if (p[0] == '.' && p[1] == '.' && p[2] == '/') {
        return -EINVAL;
      }
      if (p[0] == '/' && p[1] == '.' && p[2] == '.') {
        if (p[3] == '\0' || p[3] == '/') {
          return -EINVAL;
        }
      }
      if (p[0] == '.' && p[1] == '.') {
        bool prev_sep = (p == filename) || (p[-1] == '/');
        bool next_sep = (p[2] == '\0') || (p[2] == '/');
        if (prev_sep && next_sep) {
          return -EINVAL;
        }
      }
      p++;
    }
  }

  if (strncmp(filename, "/var/lib/", 9) != 0 &&
      strncmp(filename, "/tmp/", 5) != 0 && strncmp(filename, "/etc/", 5) != 0) {
    return -EPERM;
  }

  return 0;
}

/* 将 jail 字段中的空白替换为 '_'，避免破坏空格分隔行格式 */
static void sanitize_field_token(char *s, size_t n) {
  size_t i;
  for (i = 0; i < n && s[i]; i++) {
    if (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')
      s[i] = '_';
  }
}

static int write_state_chunk(struct file *file, loff_t *pos, u32 *crc,
                             const char *buf, int len) {
  if (len <= 0)
    return -EINVAL;
  if (kernel_write(file, buf, len, pos) != len)
    return -EIO;
  *crc = crc32_le(*crc, buf, len);
  return 0;
}

/* 同目录 tmp → final 原子替换（依赖 rename(2) 语义） */
static int fw_atomic_replace_file(const char *tmp_path, const char *final_path) {
  char *argv[] = { "/bin/mv", "-f", (char *)tmp_path, (char *)final_path, NULL };
  char *envp[] = { "HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };
  int ret;

  ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
  if (ret) {
    pr_err("状态文件原子替换失败 (%s -> %s): %d\n", tmp_path, final_path, ret);
    return -EIO;
  }
  return 0;
}

static void fw_unlink_path(const char *path) {
  char *argv[] = { "/bin/rm", "-f", (char *)path, NULL };
  char *envp[] = { "HOME=/", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", NULL };

  (void)call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
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
    char jail_name[32];
    char reason[32];
  };

  struct saved_ban_entry_v6 {
    struct in6_addr ipv6;
    unsigned long remaining_time;
    char jail_name[32];
    char reason[32];
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

/* 状态保存缓冲区大小（自适应：基于实际条目数动态分配） */
#define MAX_SAVE_BAN 4096
#define MAX_SAVE_WL 4096

  struct saved_ban_entry_v4 *ban_entries_v4 = NULL;
  struct saved_ban_entry_v6 *ban_entries_v6 = NULL;
  struct saved_whitelist_entry_v4 *wl_entries_v4 = NULL;
  struct saved_whitelist_entry_v6 *wl_entries_v6 = NULL;
  int ban_count_v4 = 0, ban_count_v6 = 0;
  int wl_count_v4 = 0, wl_count_v6 = 0;
  int truncated = 0;
  struct ban_entry *entry;
  struct whitelist_entry *wl_entry;
  u32 hash;
  char *tmp_path = NULL;
  u32 crc = ~0U;

  if (validate_state_path(filename) < 0) {
    pr_debug("状态文件路径验证失败: %s\n", filename);
    return -EINVAL;
  }

  tmp_path = kasprintf(GFP_KERNEL, "%s.tmp", filename);
  if (!tmp_path) {
    pr_err("状态保存临时路径分配失败\n");
    return -ENOMEM;
  }
  if (validate_state_path(tmp_path) < 0) {
    pr_err("状态临时文件路径验证失败: %s\n", tmp_path);
    kfree(tmp_path);
    return -EINVAL;
  }

  ban_entries_v4 = kmalloc_array(MAX_SAVE_BAN, sizeof(struct saved_ban_entry_v4), GFP_KERNEL);
  ban_entries_v6 = kmalloc_array(MAX_SAVE_BAN, sizeof(struct saved_ban_entry_v6), GFP_KERNEL);
  wl_entries_v4 = kmalloc_array(
    MAX_SAVE_WL, sizeof(struct saved_whitelist_entry_v4), GFP_KERNEL);
  wl_entries_v6 = kmalloc_array(
    MAX_SAVE_WL, sizeof(struct saved_whitelist_entry_v6), GFP_KERNEL);
  if (!ban_entries_v4 || !ban_entries_v6 || !wl_entries_v4 || !wl_entries_v6) {
    kfree(ban_entries_v4);
    kfree(ban_entries_v6);
    kfree(wl_entries_v4);
    kfree(wl_entries_v6);
    kfree(tmp_path);
    pr_err("状态保存内存分配失败\n");
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
      strscpy(ban_entries_v4[ban_count_v4].jail_name, entry->jail_name,
              sizeof(ban_entries_v4[ban_count_v4].jail_name));
      strscpy(ban_entries_v4[ban_count_v4].reason, entry->reason,
              sizeof(ban_entries_v4[ban_count_v4].reason));
      ban_count_v4++;
    } else {
      truncated = 1;
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
      memcpy(&ban_entries_v6[ban_count_v6].ipv6, &entry->addr.ipv6, sizeof(struct in6_addr));
      ban_entries_v6[ban_count_v6].remaining_time = remaining_time;
      strscpy(ban_entries_v6[ban_count_v6].jail_name, entry->jail_name,
              sizeof(ban_entries_v6[ban_count_v6].jail_name));
      strscpy(ban_entries_v6[ban_count_v6].reason, entry->reason,
              sizeof(ban_entries_v6[ban_count_v6].reason));
      ban_count_v6++;
    } else {
      truncated = 1;
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
    } else {
      truncated = 1;
    }
  }
  rcu_read_unlock();

  /* 收集 IPv6 白名单 */
  rcu_read_lock();
  hash_for_each_rcu(fw_info.whitelist_table_ipv6, hash, wl_entry, hash) {
    if (wl_count_v6 < MAX_SAVE_WL) {
      memcpy(&wl_entries_v6[wl_count_v6].ipv6, &wl_entry->addr.ipv6, sizeof(struct in6_addr));
      wl_entries_v6[wl_count_v6].prefix_len = READ_ONCE(wl_entry->mask.prefix_len);
      strscpy(wl_entries_v6[wl_count_v6].device_name, wl_entry->device_name,
              sizeof(wl_entries_v6[wl_count_v6].device_name));
      wl_count_v6++;
    } else {
      truncated = 1;
    }
  }
  rcu_read_unlock();

  file = filp_open(tmp_path, O_CREAT | O_WRONLY | O_TRUNC | O_NOFOLLOW, 0600);
  if (IS_ERR(file)) {
    ret = -EIO;
    goto out_free;
  }

  written = snprintf(buffer, sizeof(buffer), "FW_STATE 1\n");
  if (write_state_chunk(file, &pos, &crc, buffer, written)) {
    filp_close(file, NULL);
    fw_unlink_path(tmp_path);
    ret = -EIO;
    goto out_free;
  }

  /* 写入 IPv4 封禁：reason 为行尾剩余字段，可含空格 */
  for (int i = 0; i < ban_count_v4; i++) {
    char ip_str[INET_ADDRSTRLEN];
    char jail[32];
    const char *reason = ban_entries_v4[i].reason[0] ? ban_entries_v4[i].reason : "(none)";
    strscpy(jail, ban_entries_v4[i].jail_name, sizeof(jail));
    sanitize_field_token(jail, sizeof(jail));
    ip_to_str(FW_AF_INET, &ban_entries_v4[i].ipv4, ip_str, sizeof(ip_str));
    written = snprintf(buffer, sizeof(buffer), "BAN_V4 %s %lu %s %s\n", ip_str,
                       ban_entries_v4[i].remaining_time, jail, reason);
    if (write_state_chunk(file, &pos, &crc, buffer, written)) {
      filp_close(file, NULL);
      fw_unlink_path(tmp_path);
      ret = -EIO;
      goto out_free;
    }
  }

  /* 写入 IPv6 封禁 */
  for (int i = 0; i < ban_count_v6; i++) {
    char ip_str[INET6_STR_LEN];
    char jail[32];
    const char *reason = ban_entries_v6[i].reason[0] ? ban_entries_v6[i].reason : "(none)";
    strscpy(jail, ban_entries_v6[i].jail_name, sizeof(jail));
    sanitize_field_token(jail, sizeof(jail));
    ip_to_str(FW_AF_INET6, &ban_entries_v6[i].ipv6, ip_str, sizeof(ip_str));
    written = snprintf(buffer, sizeof(buffer), "BAN_V6 %s %lu %s %s\n", ip_str,
                       ban_entries_v6[i].remaining_time, jail, reason);
    if (write_state_chunk(file, &pos, &crc, buffer, written)) {
      filp_close(file, NULL);
      fw_unlink_path(tmp_path);
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
                       inet_mask_len(wl_entries_v4[i].mask), wl_entries_v4[i].device_name);
    if (write_state_chunk(file, &pos, &crc, buffer, written)) {
      filp_close(file, NULL);
      fw_unlink_path(tmp_path);
      ret = -EIO;
      goto out_free;
    }
  }

  /* 写入 IPv6 白名单 */
  for (int i = 0; i < wl_count_v6; i++) {
    written = snprintf(buffer, sizeof(buffer), "WL_V6 %pI6 %d %s\n",
                       &wl_entries_v6[i].ipv6, wl_entries_v6[i].prefix_len,
                       wl_entries_v6[i].device_name);
    if (write_state_chunk(file, &pos, &crc, buffer, written)) {
      filp_close(file, NULL);
      fw_unlink_path(tmp_path);
      ret = -EIO;
      goto out_free;
    }
  }

  written = snprintf(buffer, sizeof(buffer), "CRC32 %08x\n", ~crc);
  if (kernel_write(file, buffer, written, &pos) != written) {
    filp_close(file, NULL);
    fw_unlink_path(tmp_path);
    ret = -EIO;
    goto out_free;
  }

  if (vfs_fsync(file, 0) != 0) {
    filp_close(file, NULL);
    fw_unlink_path(tmp_path);
    ret = -EIO;
    goto out_free;
  }

  filp_close(file, NULL);

  ret = fw_atomic_replace_file(tmp_path, filename);
  if (ret)
    fw_unlink_path(tmp_path);

  if (!ret && truncated)
    pr_warn("状态保存已截断：上限 ban=%d wl=%d（已写 v4_ban=%d v6_ban=%d v4_wl=%d v6_wl=%d）\n",
            MAX_SAVE_BAN, MAX_SAVE_WL, ban_count_v4, ban_count_v6, wl_count_v4, wl_count_v6);

out_free:
  kfree(ban_entries_v4);
  kfree(ban_entries_v6);
  kfree(wl_entries_v4);
  kfree(wl_entries_v6);
  kfree(tmp_path);
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

  /* 修复 S2-3：防止重复恢复状态导致竞态 */
  if (state_restored)
    return 0;

  if (!filename || !*filename) {
    pr_debug("状态文件名为空\n");
    return -EINVAL;
  }

  if (validate_state_path(filename) < 0) {
    pr_debug("状态文件路径验证失败: %s\n", filename);
    return -EINVAL;
  }

#define MAX_STATE_FILE_SIZE (128 * 1024)
  buffer = kmalloc(MAX_STATE_FILE_SIZE, GFP_KERNEL);
  if (!buffer) {
    pr_err("状态恢复内存分配失败\n");
    return -ENOMEM;
  }

  file = filp_open(filename, O_RDONLY | O_NOFOLLOW, 0);
  if (IS_ERR(file)) {
    kfree(buffer);
    return 0;
  }

  {
    struct kstat stat;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    int stat_err = vfs_getattr(&file->f_path, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
#else
    int stat_err = vfs_getattr(&file->f_path, &stat);
#endif
    if (stat_err == 0 && !S_ISREG(stat.mode)) {
      filp_close(file, NULL);
      kfree(buffer);
      return -EINVAL;
    }
  }

  bytes_read = 0;
  while (bytes_read < MAX_STATE_FILE_SIZE - 1) {
    ssize_t chunk;
    chunk = kernel_read(
      file, buffer + bytes_read, MAX_STATE_FILE_SIZE - 1 - bytes_read, &pos);
    if (chunk <= 0)
      break;
    bytes_read += chunk;
  }

  if (bytes_read > 0) {
    buffer[bytes_read] = '\0';

    /* 若存在 CRC32 行则校验（旧文件无该行则跳过，保持兼容） */
    {
      char *crc_line = NULL;
      char *p = buffer;
      char *last = NULL;
      while ((p = strstr(p, "\nCRC32 ")) != NULL) {
        last = p + 1;
        p = last;
      }
      if (!last && strncmp(buffer, "CRC32 ", 6) == 0)
        last = buffer;
      if (last && strncmp(last, "CRC32 ", 6) == 0) {
        u32 expect = 0, got;
        size_t body_len = (size_t)(last - buffer);
        if (sscanf(last + 6, "%x", &expect) == 1) {
          got = ~crc32_le(~0U, buffer, body_len);
          if (got != expect) {
            pr_err("状态文件校验和失败：expect=%08x got=%08x，拒绝恢复\n", expect, got);
            filp_close(file, NULL);
            kfree(buffer);
            return -EINVAL;
          }
        }
        crc_line = last;
        *crc_line = '\0'; /* 避免后续当数据行解析 */
      }
    }

    line = buffer;
    while ((token = strsep(&line, "\n")) != NULL) {
      if (*token == '\0')
        continue;

      char *cmd = strsep(&token, " ");
      if (!cmd || !*cmd)
        continue;

      if (strcmp(cmd, "FW_STATE") == 0 || strcmp(cmd, "CRC32") == 0)
        continue;

      /* 恢复 IPv4 封禁 */
      if (strcmp(cmd, "BAN_V4") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *time_str = strsep(&token, " ");
        char *jail_str = strsep(&token, " ");
        /* reason 取行尾剩余（可含空格），兼容旧版单 token */
        char *reason_str = token;

        /* 修复 W2-6：增强格式校验，确保只有预期的字段 */
        if (ip_str && time_str) {
          __be32 ip;
          if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
            if (is_in_whitelist(&fw_info, FW_AF_INET, &ip)) {
              continue;
            }

            /* 跳过容量限制（按需恢复） */

            unsigned long remaining_time;
            if (kstrtoul(time_str, 10, &remaining_time) == 0) {
              struct ban_entry *entry;
              bool is_permanent = false;
              unsigned long unban_time = 0;
              unsigned long ban_duration = 0;

              if (remaining_time == 0) {
                is_permanent = true;
              } else if (remaining_time > 365UL * 24 * 60 * 60) {
                continue;
              } else {
                if (check_mul_overflow(remaining_time, (unsigned long)HZ, &ban_duration)) {
                  continue;
                }
                unban_time = jiffies + ban_duration;
              }

              entry = kzalloc(sizeof(*entry), GFP_KERNEL);
              if (!entry) {
                continue;
              }

              entry->af = FW_AF_INET;
              entry->addr.ipv4 = ip;
              /* ban_time 保持原始语义：unban_time - 剩余时长 = 原始封禁起点 */
              entry->ban_time = unban_time ? (unban_time - ban_duration) : jiffies;
              entry->unban_time = unban_time;
              entry->is_permanent = is_permanent;
              strscpy(entry->jail_name, jail_str ? jail_str : "api",
                      sizeof(entry->jail_name));
              /* 恢复 reason：
               * - "(none)" 表示原始 reason 为空，保留空字符串
               * - "restored" 是旧版 fallback 标记，用 jail_name 替代
               * - 其他值直接使用
               * kzalloc 已将 reason 置零；仅在有有效字符串时覆盖 */
              if (reason_str && strcmp(reason_str, "(none)") != 0 &&
                  strcmp(reason_str, "restored") != 0) {
                strscpy(entry->reason, reason_str, sizeof(entry->reason));
              } else if (jail_str && strcmp(jail_str, "api") != 0 &&
                         (!reason_str || strcmp(reason_str, "restored") == 0)) {
                strscpy(entry->reason, jail_str, sizeof(entry->reason));
              }
              atomic_set(&entry->retry_count, 0);
              /* 始终初始化定时器（永久封禁不启动），避免 cleanup/unban 操作未初始化 timer */
              timer_setup(&entry->expire_timer, ban_entry_expire_callback, 0);

              /* 修复：使用每桶锁替代全局锁，提高并发性能 */
              {
                u32 bkt4 = hash_ipv4(ip, BAN_HASH_BITS);
                struct ban_entry *existing;
                bool duplicate = false;

                spin_lock_bh(&fw_info.ban_locks_ipv4[bkt4]);
                hlist_for_each_entry_rcu(existing, &fw_info.ban_table_ipv4[bkt4], hash) {
                  if (existing->af == FW_AF_INET && existing->addr.ipv4 == ip) {
                    duplicate = true;
                    break;
                  }
                }

                if (duplicate) {
                  spin_unlock_bh(&fw_info.ban_locks_ipv4[bkt4]);
                  kfree(entry);
                } else {
                  /* 与 ban-manager.c IPv4 路径保持一致:直接用桶索引 hlist_add_head_rcu */
                  hlist_add_head_rcu(&entry->hash, &fw_info.ban_table_ipv4[bkt4]);
                  active_bans_add(&fw_info, entry);

                  /* 启动 per-entry 过期定时器（非永久封禁时） */
                  if (!is_permanent)
                    mod_timer(&entry->expire_timer, unban_time);

                  atomic_inc(&fw_info.ban_count);
                  atomic_inc(&fw_info.total_ban_count);
                  spin_unlock_bh(&fw_info.ban_locks_ipv4[bkt4]);
                  restored_ban_count++;
                  /* 推送恢复的封禁事件给守护进程，使用真实的 reason 和 jail_name */
                  fw_netlink_send_ban_state_change(
                    FW_AF_INET, &ip, 1, is_permanent ? 0 : (u32)remaining_time,
                    entry->reason, entry->jail_name);
                }
              }
            }
          }
        }
        /* 恢复 IPv6 封禁 */
      } else if (strcmp(cmd, "BAN_V6") == 0 && token) {
        char *ip_str = strsep(&token, " ");
        char *time_str = strsep(&token, " ");
        char *jail_str = strsep(&token, " ");
        char *reason_str = token;

        if (ip_str && time_str) {
          struct in6_addr ip6;
          if (in6_pton(ip_str, -1, (u8 *)&ip6, -1, NULL)) {
            if (is_in_whitelist(&fw_info, FW_AF_INET6, &ip6)) {
              continue;
            }

            /* 跳过容量限制（按需恢复） */

            unsigned long remaining_time;
            if (kstrtoul(time_str, 10, &remaining_time) == 0) {
              struct ban_entry *entry;
              bool is_permanent = false;
              unsigned long unban_time = 0;
              unsigned long ban_duration = 0;

              if (remaining_time == 0) {
                is_permanent = true;
              } else if (remaining_time > 365UL * 24 * 60 * 60) {
                continue;
              } else {
                if (check_mul_overflow(remaining_time, (unsigned long)HZ, &ban_duration)) {
                  continue;
                }
                unban_time = jiffies + ban_duration;
              }

              entry = kzalloc(sizeof(*entry), GFP_KERNEL);
              if (!entry)
                continue;

              entry->af = FW_AF_INET6;
              entry->addr.ipv6 = ip6;
              /* ban_time 保持原始语义：unban_time - 剩余时长 = 原始封禁起点 */
              entry->ban_time = unban_time ? (unban_time - ban_duration) : jiffies;
              entry->unban_time = unban_time;
              entry->is_permanent = is_permanent;
              strscpy(entry->jail_name, jail_str ? jail_str : "api",
                      sizeof(entry->jail_name));
              /* 恢复 reason：
               * - "(none)" 表示原始 reason 为空，保留空字符串
               * - "restored" 是旧版 fallback 标记，用 jail_name 替代
               * - 其他值直接使用
               * kzalloc 已将 reason 置零；仅在有有效字符串时覆盖 */
              if (reason_str && strcmp(reason_str, "(none)") != 0 &&
                  strcmp(reason_str, "restored") != 0) {
                strscpy(entry->reason, reason_str, sizeof(entry->reason));
              } else if (jail_str && strcmp(jail_str, "api") != 0 &&
                         (!reason_str || strcmp(reason_str, "restored") == 0)) {
                strscpy(entry->reason, jail_str, sizeof(entry->reason));
              }
              atomic_set(&entry->retry_count, 0);
              /* 始终初始化定时器（永久封禁不启动），避免 cleanup/unban 操作未初始化 timer */
              timer_setup(&entry->expire_timer, ban_entry_expire_callback, 0);

              /* 修复：使用每桶锁替代全局锁，提高并发性能 */
              {
                u32 bkt6 = hash_ipv6(&ip6);
                struct ban_entry *existing;
                bool duplicate = false;

                spin_lock_bh(&fw_info.ban_locks_ipv6[bkt6]);
                hlist_for_each_entry_rcu(existing, &fw_info.ban_table_ipv6[bkt6], hash) {
                  if (existing->af == FW_AF_INET6 &&
                      ipv6_addr_equal(&existing->addr.ipv6, &ip6)) {
                    duplicate = true;
                    break;
                  }
                }

                if (duplicate) {
                  spin_unlock_bh(&fw_info.ban_locks_ipv6[bkt6]);
                  kfree(entry);
                } else {
                  /* 修复：直接用桶索引 hlist_add_head_rcu，避免 hash_add_rcu 以 bkt6 为 key
                   * 重新 hash_min 落到错误桶(同 ban-manager.c 路径) */
                  hlist_add_head_rcu(&entry->hash, &fw_info.ban_table_ipv6[bkt6]);
                  active_bans_add(&fw_info, entry);

                  /* 启动 per-entry 过期定时器（非永久封禁时） */
                  if (!is_permanent)
                    mod_timer(&entry->expire_timer, unban_time);
                  atomic_inc(&fw_info.ban_count);
                  atomic_inc(&fw_info.total_ban_count);
                  spin_unlock_bh(&fw_info.ban_locks_ipv6[bkt6]);
                  restored_ban_count++;
                  /* 推送恢复的封禁事件给守护进程，使用真实的 reason 和 jail_name */
                  fw_netlink_send_ban_state_change(
                    FW_AF_INET6, &ip6, 1, is_permanent ? 0 : (u32)remaining_time,
                    entry->reason, entry->jail_name);
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

          /* 跳过容量限制（按需恢复） */

          if (kstrtoint(mask_str, 10, &prefix_len) == 0) {
            mask = prefix_len == 0 ? 0 : htonl(~0U << (32 - prefix_len));

            if (in4_pton(ip_str, -1, (u8 *)&ip, -1, NULL)) {
              __be32 normalized_ip = ip & mask;
              int result = add_whitelist_entry(&fw_info, FW_AF_INET,
                                               &normalized_ip, &mask, prefix_len,
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

          /* 跳过容量限制（按需恢复） */

          if (kstrtoint(prefix_str, 10, &prefix_len) == 0) {
            if (in6_pton(ip_str, -1, (u8 *)&ip6, -1, NULL)) {
              int result = add_whitelist_entry(&fw_info, FW_AF_INET6, &ip6, NULL, prefix_len,
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

  return 0;
}
EXPORT_SYMBOL_GPL(restore_state_from_file);
