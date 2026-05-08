/*
 * failed-tracker.c - 失败尝试跟踪函数
 */

#include "failed-tracker.h"
#include "ban-manager.h"
#include "firewall-daemon.h"
#include "jail-manager.h"

/* 在特定 jail 中按IP查找失败条目 */
struct failed_entry *find_entry_for_jail(struct jail *j, const char *ip) {
  if (!j || !j->failed_hash || !ip)
    return NULL;

  khint_t k = kh_get(ip_map, j->failed_hash, ip);
  if (k != kh_end(j->failed_hash)) {
    return kh_value(j->failed_hash, k);
  }
  return NULL;
}

/* 在特定 jail 中创建新的失败条目 */
struct failed_entry *create_entry_for_jail(struct jail *j, const char *ip) {
  if (!j || !ip)
    return NULL;

  /* 如果需要则初始化哈希表 */
  if (!j->failed_hash) {
    j->failed_hash = kh_init(ip_map);
    if (!j->failed_hash) {
      daemon_log_err("Failed to initialize hash table for jail '%s'", j->name);
      return NULL;
    }
  }

  /* 检查条目是否已存在 */
  int ret;
  khint_t k = kh_put(ip_map, j->failed_hash, ip, &ret);
  if (ret == 0) {
    return kh_value(j->failed_hash, k); /* 已存在 */
  }
  if (ret < 0) {
    daemon_log_err("Failed to resize hash table for jail '%s'", j->name);
    return NULL;
  }

  /* 键所有权：用堆分配的副本替换栈指针 */
  char *key_copy = strdup(ip);
  if (!key_copy) {
    daemon_log_err("Failed to allocate memory for hash key");
    /* 注意：此时 kh_key 仍指向原始 ip 参数（非堆分配），无需释放 */
    kh_del(ip_map, j->failed_hash, k); /* 移除空槽位 */
    return NULL;
  }
  kh_key(j->failed_hash, k) = key_copy;

  /* 创建新条目 */
  struct failed_entry *entry = calloc(1, sizeof(*entry));
  if (!entry) {
    daemon_log_err("Failed to allocate memory for failed entry");
    /* 键已设置为 key_copy，必须先释放键再删除条目 */
    free((char *)kh_key(j->failed_hash, k));
    kh_key(j->failed_hash, k) = NULL;
    kh_del(ip_map, j->failed_hash, k); /* 移除空槽位 */
    return NULL;
  }

  strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
  entry->ip[sizeof(entry->ip) - 1] = '\0';
  entry->count = 0;
  entry->recent_head = 0; /* R9-7: 初始化滑动窗口起始索引 */

  kh_value(j->failed_hash, k) = entry;
  return entry;
}

/* 移除失败条目（每个jail） */
void remove_entry_for_jail(struct jail *j, const char *ip) {
  if (!j || !j->failed_hash || !ip)
    return;

  khint_t k = kh_get(ip_map, j->failed_hash, ip);
  if (k != kh_end(j->failed_hash)) {
    free(kh_value(j->failed_hash, k));
    free((char *)kh_key(j->failed_hash, k)); /* 释放堆分配的键 */
    kh_del(ip_map, j->failed_hash, k);
  }
}

/* 统计时间窗口内的近期失败次数 */
unsigned int count_recent(struct failed_entry *entry, time_t window,
                          unsigned int max_retries) {
  time_t now = time(NULL);
  unsigned int count = 0;

  /* 验证参数以防止潜在问题 */
  if (!entry || window <= 0) {
    daemon_log_debug("Invalid parameters to count_recent");
    return 0;
  }

  /* R9-7 优化：使用滑动窗口起始索引，避免每次从头线性扫描。
   * 先进过期时间戳，缩小扫描范围，最坏情况仍为 O(n) 但平均 O(1)。 */
  unsigned int start = entry->recent_head;
  if (start >= entry->count)
    start = 0;

  /* 跳过过期时间戳 */
  while (start < entry->count && now >= entry->timestamps[start] &&
         (now - entry->timestamps[start]) > window) {
    start++;
  }
  entry->recent_head = start;

  /* 只扫描窗口内的时间戳 */
  for (unsigned int i = start; i < entry->count; i++) {
    if (now >= entry->timestamps[i]) {
      time_t diff = now - entry->timestamps[i];
      if (diff <= window) {
        count++;
      }
    }
    if (count > max_retries)
      break;
  }

  return count;
}

/*
 * process_failed_timestamps - 添加时间戳并管理缓冲区溢出
 * @entry: 要更新的失败条目
 * @now: 当前时间戳
 * @findtime: 统计失败次数的时间窗口
 */
void process_failed_timestamps(struct failed_entry *entry, time_t now,
                               time_t findtime) {
  /* 修复 W2-1：编译时检查 memmove 大小计算不会溢出 */
  _Static_assert(MAX_FAILED_TIMESTAMPS < (SIZE_MAX / sizeof(time_t)),
                 "MAX_FAILED_TIMESTAMPS * sizeof(time_t) would overflow");

  if (entry->count < MAX_FAILED_TIMESTAMPS) {
    entry->timestamps[entry->count++] = now;
  } else {
    /* 移动时间戳为新时间戳腾出空间 */
    memmove(entry->timestamps, entry->timestamps + 1,
            (MAX_FAILED_TIMESTAMPS - 1) * sizeof(time_t));
    entry->timestamps[MAX_FAILED_TIMESTAMPS - 1] = now;

    /* R9-7: 移动后重置滑动窗口索引（因为所有时间戳都向前移动了一位） */
    if (entry->recent_head > 0)
      entry->recent_head--;

    /* 过滤掉过期的时间戳 */
    time_t oldest_valid = now - findtime;
    int new_count = 0;
    for (int i = 0; i < MAX_FAILED_TIMESTAMPS; i++) {
      if (entry->timestamps[i] >= oldest_valid) {
        if (new_count != i) {
          entry->timestamps[new_count] = entry->timestamps[i];
        }
        new_count++;
      }
    }
    entry->count = new_count;
    entry->recent_head = 0; /* 重置滑动窗口索引 */
  }
}

/*
 * check_and_ban - 检查阈值，如果超过则封禁
 * @entry: 要检查的失败条目
 * @ip: IP地址字符串
 * @max_retries: 最大允许失败次数
 * @findtime: 统计失败次数的时间窗口
 * @jail_name: Jail名称用于日志记录（NULL表示全局）
 */
void check_and_ban(struct failed_entry *entry, const char *ip,
                   unsigned int max_retries, unsigned int findtime,
                   const char *jail_name) {
  unsigned int recent_fails = count_recent(entry, findtime, max_retries);

  if (recent_fails >= max_retries) {
    if (jail_name) {
      daemon_log_warn(
          "IP %s exceeded %d failures in %d seconds in jail '%s', banning", ip,
          recent_fails, findtime, jail_name);
    } else {
      daemon_log_warn("IP %s exceeded %d failures in %d seconds, banning", ip,
                      recent_fails, findtime);
    }

    if (ban_ip(ip) == 0) {
      if (jail_name) {
        daemon_log_info(
            "Successfully banned IP %s after %d failed attempts in jail '%s'",
            ip, recent_fails, jail_name);
      } else {
        daemon_log_info("Successfully banned IP %s after %d failed attempts",
                        ip, recent_fails);
      }
    } else {
      if (jail_name) {
        daemon_log_err("Failed to ban IP %s after %d failed attempts in jail "
                       "'%s', keeping entry for retry",
                       ip, recent_fails, jail_name);
      } else {
        daemon_log_err("Failed to ban IP %s after %d failed attempts, keeping "
                       "entry for retry",
                       ip, recent_fails);
      }
    }
  } else {
    if (jail_name) {
      daemon_log_debug(
          "IP %s has %d failed attempts in %d seconds in jail '%s'", ip,
          recent_fails, findtime, jail_name);
    } else {
      daemon_log_debug("IP %s has %d failed attempts in %d seconds", ip,
                       recent_fails, findtime);
    }
  }
}

/* 处理失败登录尝试 - 支持jail的版本 */
void handle_failed_attempt_for_jail(struct jail *j, const char *ip,
                                    unsigned int max_retries,
                                    unsigned int findtime) {
  struct failed_entry *entry;
  time_t now;

  if (!ip || !*ip) {
    daemon_log_err(
        "Invalid IP address provided to handle_failed_attempt_for_jail");
    return;
  }

  atomic_fetch_add(&daemon_stats.failed_attempts, 1);

  entry = find_entry_for_jail(j, ip);
  if (!entry) {
    entry = create_entry_for_jail(j, ip);
    if (!entry) {
      daemon_log_err("Failed to create entry for IP %s", ip);
      return;
    }
  }

  now = time(NULL);
  process_failed_timestamps(entry, now, findtime);
  check_and_ban(entry, ip, max_retries, findtime, j->name);

  /* 成功封禁后移除条目 */
  if (count_recent(entry, findtime, max_retries) >= max_retries) {
    remove_entry_for_jail(j, ip);
  }
}

/* 修复 3.3：删除废弃的全局版本函数（handle_failed_attempt, find_entry,
 * create_entry, remove_entry） 这些函数仅用于向后兼容，现已无外部调用者。
 * 新代码应使用 _for_jail 后缀的 Jail 感知版本。 */