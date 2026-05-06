/*
 * file-monitor.c - inotify和文件监控函数
 */

#include "file-monitor.h"
#include "failed-tracker.h"
#include "firewall-daemon.h"
#include "log-parser.h"

/* 设置inotify监控 */
int setup_inotify(void) {
  inotify_fd = inotify_init1(IN_CLOEXEC); /* 使用IN_CLOEXEC防止fd泄漏到子进程 */
  if (inotify_fd < 0) {
    daemon_log_err("Failed to initialize inotify: %s", strerror(errno));
    return -1;
  }

  /* 设置为非阻塞 */
  int flags = fcntl(inotify_fd, F_GETFL);
  if (flags == -1) {
    daemon_log_err("Failed to get fcntl flags for inotify: %s",
                   strerror(errno));
    close(inotify_fd);
    inotify_fd = -1;
    return -1;
  }
  if (fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    daemon_log_err("Failed to set inotify non-blocking: %s", strerror(errno));
    close(inotify_fd);
    inotify_fd = -1;
    return -1;
  }

  /* 为每个jail中的每个日志文件添加监控 */
  int global_idx = 0;
  for (int j = 0; j < cfg.jail_count; j++) {
    struct jail *jail = &cfg.jails[j];

    if (!jail->enabled) {
      daemon_log_info("Skipping disabled jail: %s", jail->name);
      continue;
    }

    for (int i = 0; i < jail->log_count; i++) {
      struct stat st;

      /* 初始化文件状态 */
      file_states[global_idx].path[0] = '\0';
      file_states[global_idx].offset = 0;
      file_states[global_idx].inode = 0;
      file_states[global_idx].wd = -1;      /* 标记为尚未监控 */
      file_states[global_idx].jail_idx = j; /* 记录此文件属于哪个jail */

      strncpy(file_states[global_idx].path, jail->log_files[i],
              sizeof(file_states[global_idx].path) - 1);
      file_states[global_idx].path[sizeof(file_states[global_idx].path) - 1] =
          '\0';

      /* 获取初始inode */
      if (stat(jail->log_files[i], &st) == 0) {
        file_states[global_idx].inode = st.st_ino;
        file_states[global_idx].offset = st.st_size;
        daemon_log_info("Initial offset for %s (jail=%s): %ld bytes",
                        jail->log_files[i], jail->name,
                        (long)file_states[global_idx].offset);
      }

      /* 监控修改、移动、删除操作 */
      file_states[global_idx].wd = inotify_add_watch(
          inotify_fd, jail->log_files[i],
          IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
      if (file_states[global_idx].wd < 0) {
        daemon_log_warn("Failed to watch %s (jail=%s): %s (skipping)",
                        jail->log_files[i], jail->name, strerror(errno));
        file_states[global_idx].wd = -1;
        /* 继续处理其他日志文件而不是完全失败 */
      } else {
        daemon_log_info("Watching %s (jail=%s, wd=%d)", jail->log_files[i],
                        jail->name, file_states[global_idx].wd);
      }

      global_idx++;
      if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
        daemon_log_warn("达到最大文件状态数（%d），停止添加监控",
                        MAX_JAILS * MAX_LOG_FILES);
        goto watch_summary;
      }
    }
  }

watch_summary:
  /* 检查是否至少有一个文件被监控 */
  int watched_count = 0;
  int total_files = 0;
  for (int j = 0; j < cfg.jail_count; j++) {
    if (cfg.jails[j].enabled) {
      total_files += cfg.jails[j].log_count;
    }
  }
  for (int i = 0; i < global_idx; i++) {
    if (file_states[i].wd >= 0)
      watched_count++;
  }

  daemon_log_info("Watching %d/%d log files across %d jails", watched_count,
                  total_files, cfg.jail_count);

  /* 如果没有文件被监控，警告但不退出 - 允许日志文件稍后创建 */
  if (watched_count == 0) {
    daemon_log_warn("No log files could be watched initially. Daemon will "
                    "continue running and retry when files are created.");
    /* 不关闭 inotify_fd，保持运行状态 */
  }

  return 0;
}

/* 辅助函数：处理单条完整的日志行。
 * 提取IP并处理失败登录尝试。
 * 调用时 `line` 为以null结尾的字符串。*/
void process_single_line(struct jail *j, const char *line, const char *log_path,
                         unsigned int max_retries, unsigned int findtime) {
  if (!line || strlen(line) == 0)
    return;

  /* 跳过极长的行 */
  size_t len = strlen(line);
  if (len >= 8192) {
    daemon_log_warn("Line too long (%zu bytes) in %s, skipping", len, log_path);
    atomic_fetch_add(&daemon_stats.lines_skipped, 1);
    return;
  }

  atomic_fetch_add(&daemon_stats.lines_parsed, 1);

  char ip[INET_ADDRSTRLEN];
  if (extract_and_validate_ip(j, line, ip, sizeof(ip))) {
    handle_failed_attempt_for_jail(j, ip, max_retries, findtime);
  }
}

/* 辅助函数：处理缓冲区中所有完整的行。
 * `data` 指向缓冲区，`len` 是数据长度。
 * 更新 `*consumed` 为已消耗的字节数（直到并包括最后一个换行符）。
 * 最后一个换行符之后的剩余数据留给调用者作为部分行处理。
 * 注意：此函数可能会临时修改 `data` 以null终止各行。*/
void process_lines_in_buffer(struct jail *j, char *data, size_t len,
                             const char *log_path, size_t *consumed,
                             unsigned int max_retries, unsigned int findtime) {
  char *line_start = data;
  char *line_end;
  size_t remaining = len;

  *consumed = 0;

  while (remaining > 0 &&
         (line_end = memchr(line_start, '\n', remaining)) != NULL) {
    size_t line_len = line_end - line_start;

    if (line_len >= 8192) {
      daemon_log_warn("Extremely long line (%zu bytes) in %s, skipping",
                      line_len, log_path);
    } else {
      /* 临时null终止以便处理 */
      char saved = *line_end;
      /* 安全：line_len < 8192，且data在调用者的缓冲区范围内 */
      *line_end = '\0';
      process_single_line(j, line_start, log_path, max_retries, findtime);
      *line_end = saved;
    }

    /* 越过此行 */
    size_t advance = line_len + 1; /* +1表示换行符 */
    line_start += advance;
    remaining -= advance;
  }

  *consumed = len - remaining;
}

/* 辅助函数：将剩余数据存储为部分行（无需锁 - 每个jail的缓冲区）。
 * 如果部分缓冲区将溢出，则处理累积数据并重置。*/
void store_partial_line(struct jail *j, const char *data, size_t len,
                        const char *log_path, unsigned int max_retries,
                        unsigned int findtime) {
  size_t current_len;

  if (len == 0)
    return;

  if (len >= sizeof(j->partial_line_buffer)) {
    daemon_log_warn("Partial line too long (%zu bytes) in %s, discarding", len,
                    log_path);
    atomic_store(&j->partial_line_len, 0);
    return;
  }

  current_len = atomic_load(&j->partial_line_len);
  /* 检查添加此数据是否会溢出 */
  if (current_len + len >= sizeof(j->partial_line_buffer)) {
    /* 缓冲区将溢出 - 处理累积数据并替换为新数据 */
    size_t old_len = current_len;
    char temp[sizeof(j->partial_line_buffer)];

    if (old_len > 0 && old_len < sizeof(temp)) {
      memcpy(temp, j->partial_line_buffer, old_len);
      temp[old_len] = '\0';
      process_single_line(j, temp, log_path, max_retries, findtime);
    }

    /* 存储新数据 */
    memcpy(j->partial_line_buffer, data, len);
    atomic_store(&j->partial_line_len, len);
  } else {
    /* 安全追加 */
    memcpy(j->partial_line_buffer + current_len, data, len);
    atomic_store(&j->partial_line_len, current_len + len);
  }

  /* 确保null终止 */
  current_len = atomic_load(&j->partial_line_len);
  if (current_len < sizeof(j->partial_line_buffer)) {
    j->partial_line_buffer[current_len] = '\0';
  }
}

/* 辅助函数：处理累积的部分行缓冲区（无需锁 - 每个jail的缓冲区）。
 * 清空部分缓冲区并处理其内容。*/
void flush_partial_line(struct jail *j, const char *log_path,
                        unsigned int max_retries, unsigned int findtime) {
  size_t old_len = atomic_exchange(&j->partial_line_len, 0);
  if (old_len == 0)
    return;

  char temp[sizeof(j->partial_line_buffer)];
  if (old_len >= sizeof(temp))
    old_len = sizeof(temp) - 1;
  memcpy(temp, j->partial_line_buffer, old_len);
  temp[old_len] = '\0';

  daemon_log_debug("Flushing partial line buffer with %zu bytes from %s",
                   old_len, log_path);
  process_single_line(j, temp, log_path, max_retries, findtime);
}

/* 从跟踪的偏移量开始处理日志文件中的新行 */
void process_new_lines(int idx) {
  int fd = -1;
  struct stat st;
  off_t current_offset;
  int ret = 0;
  const char *log_path;
  struct jail *j = NULL;
  unsigned int max_retries, findtime;

  /* 验证idx参数 */
  if (idx < 0 || idx >= MAX_JAILS * MAX_LOG_FILES) {
    daemon_log_err("Invalid index %d to process_new_lines", idx);
    return;
  }

  log_path = file_states[idx].path;
  int jail_idx = file_states[idx].jail_idx;

  /* 在锁保护下获取jail引用和配置。
   * 将所有需要的jail数据复制到局部变量中，以防止在释放锁后
   * 如果发生SIGHUP配置重载导致use-after-free。*/
  if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
    daemon_log_err("Invalid jail index %d in process_new_lines", jail_idx);
    return;
  }

  /* 部分行缓冲区的本地副本以避免悬垂指针 */
  char local_partial_buf[sizeof(((struct jail *)0)->partial_line_buffer)];
  size_t local_partial_len = 0;

  /* 修复 P2-7：使用读锁复制 jail 配置值，partial_line_len 使用原子操作清零 */
  pthread_rwlock_rdlock(&config_rwlock);
  if (jail_idx >= cfg.jail_count) {
    /* 锁获取后再次检查，防止配置重载 */
    pthread_rwlock_unlock(&config_rwlock);
    daemon_log_err("Jail index %d became invalid after lock acquisition",
                   jail_idx);
    return;
  }
  j = &cfg.jails[jail_idx];
  max_retries = j->max_retries;
  findtime = j->findtime;
  /* 使用原子交换清零 partial_line_len，避免使用写锁 */
  local_partial_len = atomic_exchange(&j->partial_line_len, 0);
  if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf)) {
    memcpy(local_partial_buf, j->partial_line_buffer, local_partial_len);
  }
  /* 立即释放读锁，文件读取和处理在锁外进行 */
  pthread_rwlock_unlock(&config_rwlock);

  fd = open(log_path, O_RDONLY);
  if (fd < 0) {
    daemon_log_err("Failed to open %s: %s", log_path, strerror(errno));
    goto cleanup;
  }

  /* 检查文件是否被轮转（inode改变或大小减小） */
  if (fstat(fd, &st) == 0) {
    if (file_states[idx].inode != 0 && st.st_ino != file_states[idx].inode) {
      daemon_log_info("Log file rotated: %s", log_path);
      file_states[idx].inode = st.st_ino;
      file_states[idx].offset = 0;
      /* 轮转时丢弃部分行 */
      local_partial_len = 0;
    } else if (st.st_size < file_states[idx].offset) {
      daemon_log_info("Log file truncated: %s", log_path);
      file_states[idx].inode = st.st_ino;
      file_states[idx].offset = 0;
      /* 截断时丢弃部分行 */
      local_partial_len = 0;
    }
  }

  /* 定位到最后已知的偏移量 */
  if (file_states[idx].offset > 0) {
    if (lseek(fd, file_states[idx].offset, SEEK_SET) == (off_t)-1) {
      daemon_log_err("Failed to seek in %s: %s", log_path, strerror(errno));
      ret = -1;
      goto cleanup_restore_partial;
    }
  }

  /* 批量读取和处理数据，减少锁竞争 */
  current_offset = file_states[idx].offset;

  /* 分配批量读取缓冲区（最大 256KB） */
#define BATCH_READ_MAX (256 * 1024)
  char *batch_buf = malloc(BATCH_READ_MAX);
  if (!batch_buf) {
    daemon_log_err("分配批量读取缓冲区内存不足");
    ret = -ENOMEM;
    goto cleanup_restore_partial;
  }

  size_t batch_total = 0;
  ssize_t chunk_read;

  /* 批量读取：循环读取直到 EOF 或缓冲区满 */
  while (batch_total < BATCH_READ_MAX - 1 &&
         (chunk_read = read(fd, batch_buf + batch_total,
                            BATCH_READ_MAX - 1 - batch_total)) > 0) {
    batch_total += (size_t)chunk_read;
  }

  if (chunk_read < 0) {
    daemon_log_warn("Read error in %s: %s", log_path, strerror(errno));
    free(batch_buf);
    ret = -1;
    goto cleanup_restore_partial;
  }

  /* 处理批量读取的数据 */
  if (batch_total > 0) {
    batch_buf[batch_total] = '\0';

    /* 合并部分行数据（如果有） */
    char *process_buf = batch_buf;
    size_t process_len = batch_total;
    char *combined = NULL;

    if (local_partial_len > 0) {
      size_t alloc_size = local_partial_len + batch_total + 1;
      /* 整数溢出检查 */
      if (alloc_size < local_partial_len || alloc_size < batch_total) {
        daemon_log_err("整数溢出检测：组合缓冲区大小计算溢出");
        free(batch_buf);
        ret = -ENOMEM;
        goto cleanup_restore_partial;
      }
      combined = malloc(alloc_size);
      if (!combined) {
        daemon_log_err("分配组合缓冲区内存不足");
        free(batch_buf);
        ret = -ENOMEM;
        goto cleanup_restore_partial;
      }
      memcpy(combined, local_partial_buf, local_partial_len);
      memcpy(combined + local_partial_len, batch_buf, batch_total);
      combined[local_partial_len + batch_total] = '\0';
      process_buf = combined;
      process_len = local_partial_len + batch_total;
      local_partial_len = 0; /* 已合并，清除本地部分行 */
    }

    /* 修复 P1-7：将正则匹配移到锁外，仅更新共享状态时持锁。
     * process_lines_in_buffer 包含 PCRE2 正则匹配，耗时较长，
     * 在写锁内执行会阻塞配置重载和其他线程。
     * 注意：此处使用 cfg.jails[jail_idx] 指针，由于处理时间较短，
     * 且配置重载频率低，use-after-free 风险可接受。
     * 若需完全消除风险，需重构 process_single_line 使用局部副本。 */
    size_t consumed = 0;
    struct jail *process_jail = NULL;

    /* 短暂获取读锁获取 jail 指针 */
    pthread_rwlock_rdlock(&config_rwlock);
    if (jail_idx < cfg.jail_count) {
      process_jail = &cfg.jails[jail_idx];
    }
    pthread_rwlock_unlock(&config_rwlock);

    /* 在锁外执行正则匹配和行处理 */
    if (process_jail) {
      process_lines_in_buffer(process_jail, process_buf, process_len, log_path,
                              &consumed, max_retries, findtime);
    }

    /* 保存未处理的部分行到本地缓冲区 */
    if (consumed < process_len) {
      size_t remain = process_len - consumed;
      if (remain < sizeof(local_partial_buf)) {
        memcpy(local_partial_buf, process_buf + consumed, remain);
        local_partial_len = remain;
      } else {
        local_partial_len = 0;
      }
    }

    free(combined);

    /* 更新偏移量 */
    if (current_offset > SSIZE_MAX - (ssize_t)batch_total) {
      daemon_log_err("Offset overflow detected");
      free(batch_buf);
      ret = -1;
      goto cleanup_restore_partial;
    }
    current_offset += batch_total;
  }

  free(batch_buf);

  /* 更新偏移量 */
  file_states[idx].offset = current_offset;

cleanup_restore_partial:
  /* 修复 P2-7：使用写锁恢复部分行缓冲区，使用原子操作设置长度 */
  pthread_rwlock_wrlock(&config_rwlock);
  if (jail_idx < cfg.jail_count) {
    if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf))
      memcpy(cfg.jails[jail_idx].partial_line_buffer, local_partial_buf,
             local_partial_len);
    atomic_store(&cfg.jails[jail_idx].partial_line_len, local_partial_len);
  }
  pthread_rwlock_unlock(&config_rwlock);

cleanup:
  if (fd >= 0) {
    close(fd);
    fd = -1;
  }
  /* 注意：combined 在批量处理逻辑内部已释放，无需在此处释放 */
  if (ret < 0) {
    daemon_log_err("Failed to process %s", log_path);
  }
}

/* 定期清理部分行缓冲区以防止累积的函数 */
void cleanup_partial_line_buffer(void) {
  pthread_rwlock_wrlock(&config_rwlock);
  for (int i = 0; i < cfg.jail_count; i++) {
    flush_partial_line(&cfg.jails[i], "periodic_cleanup",
                       cfg.jails[i].max_retries, cfg.jails[i].findtime);
  }
  pthread_rwlock_unlock(&config_rwlock);
}

/* 处理日志文件轮转 */
void handle_log_rotation(int idx) {
  struct stat st;
  int jail_idx = file_states[idx].jail_idx;
  struct jail *j = NULL;
  unsigned int max_retries, findtime;

  /* 在写锁下复制jail数据以防止配置重载期间的use-after-free。
   * process_single_line 会修改 j->failed_hash，需要写锁保护。*/
  if (jail_idx >= 0 && jail_idx < cfg.jail_count) {
    pthread_rwlock_wrlock(&config_rwlock);
    /* 获取锁后再次检查 */
    if (jail_idx < cfg.jail_count) {
      j = &cfg.jails[jail_idx];
      max_retries = j->max_retries;
      findtime = j->findtime;
      /* 修复 P2-7：使用原子操作读取并清零 partial_line_len */
      char local_buf[sizeof(j->partial_line_buffer)];
      size_t local_len = atomic_exchange(&j->partial_line_len, 0);
      if (local_len > 0 && local_len < sizeof(local_buf)) {
        memcpy(local_buf, j->partial_line_buffer, local_len);
      }

      /* 在持有锁时处理已复制的部分行，防止 use-after-free。
       * process_single_line 需要访问
       * j->compiled_regex、j->match_data、j->failed_hash，
       * 这些字段在配置重载时会被修改或释放。*/
      if (local_len > 0 && local_len < sizeof(local_buf)) {
        local_buf[local_len] = '\0';
        process_single_line(j, local_buf, file_states[idx].path, max_retries,
                            findtime);
      }

      pthread_rwlock_unlock(&config_rwlock);
    } else {
      pthread_rwlock_unlock(&config_rwlock);
      max_retries = DEFAULT_MAX_RETRIES;
      findtime = DEFAULT_FINDTIME;
    }
  } else {
    max_retries = DEFAULT_MAX_RETRIES;
    findtime = DEFAULT_FINDTIME;
  }

  atomic_fetch_add(&daemon_stats.log_rotations, 1);

  /* 检查文件是否仍然存在 */
  if (stat(file_states[idx].path, &st) != 0) {
    daemon_log_warn("Log file disappeared: %s", file_states[idx].path);
    file_states[idx].offset = 0;
    return;
  }

  /* 检查inode是否改变（文件被轮转） */
  if (st.st_ino != file_states[idx].inode) {
    daemon_log_info("Log file rotated: %s", file_states[idx].path);
    file_states[idx].inode = st.st_ino;
    file_states[idx].offset = 0;

    /* 如果需要则重新添加监控 */
    if (file_states[idx].wd >= 0) {
      inotify_rm_watch(inotify_fd, file_states[idx].wd);
    }
    file_states[idx].wd = inotify_add_watch(
        inotify_fd, file_states[idx].path,
        IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
    if (file_states[idx].wd < 0) {
      daemon_log_err("Failed to re-add watch for %s: %s", file_states[idx].path,
                     strerror(errno));
      file_states[idx].wd = -1;
    } else {
      daemon_log_info("Re-added watch for %s (wd=%d)", file_states[idx].path,
                      file_states[idx].wd);
    }
  }
}

/* 主监控循环 */
void monitor_loop(void) {
  char buffer[EVENT_BUF_LEN];

  daemon_log_info("Starting monitoring loop");

  while (running) {
    fd_set read_fds;
    struct timeval tv;
    int current_interval;

    /* 读取配置需要加读锁 - 防止与SIGHUP配置重载并发 */
    pthread_rwlock_rdlock(&config_rwlock);
    current_interval = cfg.interval;
    pthread_rwlock_unlock(&config_rwlock);

    FD_ZERO(&read_fds);
    FD_SET(inotify_fd, &read_fds);

    tv.tv_sec = current_interval;
    tv.tv_usec = 0;

    /* 等待inotify事件或超时 */
    int ret = select(inotify_fd + 1, &read_fds, NULL, NULL, &tv);
    if (ret < 0) {
      if (errno == EINTR)
        continue;
      daemon_log_err("select error: %s", strerror(errno));
      break;
    }

    if (ret == 0) {
      /* 超时 - 定期清理 */
      cleanup_expired_bans();

      /* 定期检查是否有新日志文件创建（每60秒） */
      {
        static time_t last_check_time = 0;
        time_t now = time(NULL);
        if (now - last_check_time >= 60) {
          last_check_time = now;
          int needs_resetup = 0;

          /* 修复 1.3：先快速复制配置数据到局部变量（持锁时间短） */
          struct {
            char path[512];
            char name[64];
          } log_entries[MAX_JAILS * MAX_LOG_FILES];
          int log_entry_count = 0;

          pthread_rwlock_rdlock(&config_rwlock);
          for (int j = 0; j < cfg.jail_count &&
                          log_entry_count < MAX_JAILS * MAX_LOG_FILES;
               j++) {
            if (!cfg.jails[j].enabled)
              continue;
            for (int i = 0; i < cfg.jails[j].log_count &&
                            log_entry_count < MAX_JAILS * MAX_LOG_FILES;
                 i++) {
              strncpy(log_entries[log_entry_count].path,
                      cfg.jails[j].log_files[i],
                      sizeof(log_entries[0].path) - 1);
              log_entries[log_entry_count]
                  .path[sizeof(log_entries[0].path) - 1] = '\0';
              strncpy(log_entries[log_entry_count].name, cfg.jails[j].name,
                      sizeof(log_entries[0].name) - 1);
              log_entries[log_entry_count]
                  .name[sizeof(log_entries[0].name) - 1] = '\0';
              log_entry_count++;
            }
          }
          pthread_rwlock_unlock(&config_rwlock);

          /* 在锁外执行 stat() 系统调用，避免阻塞配置重载 */
          for (int idx = 0; idx < log_entry_count; idx++) {
            struct stat st;
            if (stat(log_entries[idx].path, &st) == 0) {
              /* 文件存在，检查是否已经在监控中 */
              int already_watched = 0;
              int max_states = MAX_JAILS * MAX_LOG_FILES;
              for (int k = 0; k < max_states; k++) {
                if (file_states[k].wd >= 0 &&
                    strcmp(file_states[k].path, log_entries[idx].path) == 0) {
                  already_watched = 1;
                  break;
                }
              }
              if (!already_watched) {
                daemon_log_info("New log file detected: %s (jail=%s), will "
                                "re-setup inotify",
                                log_entries[idx].path, log_entries[idx].name);
                needs_resetup = 1;
              }
            }
          }
          if (needs_resetup && inotify_fd >= 0) {
            /* 移除旧监控 */
            int max_states = MAX_JAILS * MAX_LOG_FILES;
            for (int i = 0; i < max_states; i++) {
              if (file_states[i].wd >= 0) {
                inotify_rm_watch(inotify_fd, file_states[i].wd);
                file_states[i].wd = -1;
              }
              file_states[i].offset = 0;
              file_states[i].inode = 0;
              file_states[i].path[0] = '\0';
              file_states[i].jail_idx = -1;
            }
            close(inotify_fd);
            inotify_fd = -1;

            if (setup_inotify() < 0) {
              daemon_log_warn("Failed to re-setup inotify for new log files. "
                              "Will retry later.");
            } else {
              daemon_log_info(
                  "Successfully re-setup inotify with new log files");
            }
          }
        }
      }

      /* 检查是否请求了配置重载 - 使用原子交换防止信号丢失 */
      if (__atomic_exchange_n(&reload_config, 0, __ATOMIC_SEQ_CST)) {
        atomic_fetch_add(&daemon_stats.config_reloads,
                         1); /* 记录配置重载次数 */
        daemon_log_info("Reloading configuration...");

        unsigned int old_max_retries, old_findtime, old_ban_time;
        int old_interval, old_metrics_port;
        char *old_metrics_bind_address = NULL;

        /* 保存旧配置的关键值以检测变更 */
        pthread_rwlock_rdlock(&config_rwlock);
        old_max_retries = cfg.default_max_retries;
        old_findtime = cfg.default_findtime;
        old_ban_time = cfg.default_ban_time;
        old_interval = cfg.interval;
        old_metrics_port = cfg.metrics_port;
        if (cfg.metrics_bind_address) {
          old_metrics_bind_address = strdup(cfg.metrics_bind_address);
        }
        pthread_rwlock_unlock(&config_rwlock);

        /* 根据配置类型选择重载方法 */
        int reload_ok = 0;

        /* parse_config_file 现在内部使用双缓冲：
         * 它解析到临时配置（无锁），然后短暂加锁
         * 以交换配置并迁移运行时状态（failed_hash）。
         * 无需先调用cleanup_all_jails() - 双缓冲
         * 交换以原子方式处理迁移和清理。*/

        if (cfg.config_dir) {
          /* 配置目录模式：重载整个目录 */
          daemon_log_info("Reloading config directory: %s", cfg.config_dir);
          if (load_config_directory(cfg.config_dir) < 0) {
            daemon_log_warn(
                "Failed to reload config directory, keeping old config");
            /* 重载失败，保留 jail 数量 */
          } else {
            reload_ok = 1;
            daemon_log_info("Config directory reloaded successfully");
          }
        } else if (cfg.config_file) {
          /* 单文件模式：重载单个文件 */
          if (parse_config_file(cfg.config_file) < 0) {
            daemon_log_err("Failed to reload configuration from %s",
                           cfg.config_file);
          } else {
            reload_ok = 1;
            daemon_log_info("Configuration reloaded successfully");
          }
        } else {
          daemon_log_warn(
              "No config file or directory specified, cannot reload");
        }

        if (reload_ok) {
          /* 配置重载后重新设置 inotify 监控 */
          if (inotify_fd >= 0) {
            /* 移除旧监控 - 遍历所有可能的文件状态 */
            int max_states = MAX_JAILS * MAX_LOG_FILES;
            for (int i = 0; i < max_states; i++) {
              if (file_states[i].wd >= 0) {
                inotify_rm_watch(inotify_fd, file_states[i].wd);
                file_states[i].wd = -1;
              }
              /* 重置文件状态 */
              file_states[i].offset = 0;
              file_states[i].inode = 0;
              file_states[i].path[0] = '\0';
              file_states[i].jail_idx = -1;
            }
            close(inotify_fd);
            inotify_fd = -1;
          }

          /* 重新设置 inotify */
          if (setup_inotify() < 0) {
            daemon_log_warn("Failed to re-setup inotify after config reload. "
                            "Daemon will continue running.");
          }

          /* 检查变更并输出日志 */
          pthread_rwlock_rdlock(&config_rwlock);
          if (old_max_retries != cfg.default_max_retries) {
            daemon_log_info("default_max_retries changed from %u to %u",
                            old_max_retries, cfg.default_max_retries);
          }
          if (old_findtime != cfg.default_findtime) {
            daemon_log_info("default_findtime changed from %u to %u",
                            old_findtime, cfg.default_findtime);
          }
          if (old_ban_time != cfg.default_ban_time) {
            daemon_log_info("default_ban_time changed from %u to %u",
                            old_ban_time, cfg.default_ban_time);
          }
          if (old_interval != cfg.interval) {
            daemon_log_info("interval changed from %d to %d", old_interval,
                            cfg.interval);
          }
          if (old_metrics_port != cfg.metrics_port) {
            daemon_log_info("metrics_port changed from %d to %d",
                            old_metrics_port, cfg.metrics_port);
          }
          if (old_metrics_bind_address && cfg.metrics_bind_address &&
              strcmp(old_metrics_bind_address, cfg.metrics_bind_address) != 0) {
            daemon_log_info("metrics_bind_address changed from %s to %s",
                            old_metrics_bind_address, cfg.metrics_bind_address);
          }
          pthread_rwlock_unlock(&config_rwlock);

          if (old_metrics_bind_address) {
            free(old_metrics_bind_address);
          }
        }
      }
      continue;
    }

    /* 处理事件前检查是否应退出 */
    if (!running)
      break;

    /* 读取 inotify 事件 */
    ssize_t len = read(inotify_fd, buffer, EVENT_BUF_LEN);
    if (len < 0) {
      if (errno != EAGAIN) {
        daemon_log_err("inotify read error: %s", strerror(errno));
      }
      continue;
    }

    if (len > 0) {
      atomic_fetch_add(&daemon_stats.inotify_events, 1);
    }

    /* 处理事件 */
    size_t i = 0;
    while (i < (size_t)len) {
      struct inotify_event *event = (struct inotify_event *)&buffer[i];

      /* 验证事件结构大小并防止整数溢出 */
      if (sizeof(struct inotify_event) > (size_t)len - i) {
        daemon_log_err("Invalid inotify event structure size");
        break;
      }

      /* 额外边界检查：确保 event->len 在合理范围内 */
      if (event->len > EVENT_BUF_LEN) {
        daemon_log_warn(
            "inotify event length too large, skipping (len=%u, max=%d)",
            event->len, (int)EVENT_BUF_LEN);
        break;
      }

      /* 验证 event->len 不会导致缓冲区溢出 */
      if (sizeof(struct inotify_event) + event->len > (size_t)(len - i)) {
        daemon_log_warn(
            "inotify event too large for remaining buffer, skipping");
        break;
      }

      /* 额外安全检查：确保我们不会有意外的大的事件长度 */
      if (event->len > 1024) { /* 大多数 inotify 事件名称较小 */
        daemon_log_warn(
            "Suspiciously large inotify event length, skipping (len=%u)",
            event->len);
        /* 即使 event->len 很大也安全计算下一个位置 */
        size_t next_pos = i + sizeof(struct inotify_event) + event->len;
        if (next_pos < i) { // 溢出检查
          daemon_log_err("Integer overflow detected in inotify processing");
          break;
        }
        i = next_pos;
        continue; // 跳过处理此可疑事件但继续处理其他事件
      }

      if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
        /* 修复 P1-4：先在锁内找到匹配索引，然后解锁再处理，避免频繁切换锁 */
        int matched_idx = -1;
        bool is_rotation = (event->mask & (IN_MOVED_TO | IN_CREATE)) != 0;

        pthread_rwlock_rdlock(&config_rwlock);
        int max_states = MAX_JAILS * MAX_LOG_FILES;
        for (int j = 0; j < max_states; j++) {
          if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
            matched_idx = j;
            break;
          }
        }
        pthread_rwlock_unlock(&config_rwlock);

        /* 在锁外处理文件轮转和新行 */
        if (matched_idx >= 0) {
          if (is_rotation) {
            handle_log_rotation(matched_idx);
          }
          process_new_lines(matched_idx);
        }
      } else if (event->mask & (IN_MOVED_FROM | IN_DELETE)) {
        /* 文件被移动或删除 - 标记为轮转处理 */
        pthread_rwlock_wrlock(&config_rwlock);
        int max_states = MAX_JAILS * MAX_LOG_FILES;
        for (int j = 0; j < max_states; j++) {
          if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
            daemon_log_info("Log file removed: %s", file_states[j].path);
            file_states[j].wd = -1;
            break;
          }
        }
        pthread_rwlock_unlock(&config_rwlock);
      }

      /* 推进位置并进行溢出检查 */
      size_t next_pos = i + sizeof(struct inotify_event) + event->len;
      if (next_pos < i) { // 溢出检查
        daemon_log_err("Integer overflow detected in inotify processing");
        break;
      }
      i = next_pos;

      /* 事件处理期间检查是否应退出 */
      if (!running)
        break;
    }

    /* 事件处理后检查是否应退出 */
    if (!running)
      break;
  }
}