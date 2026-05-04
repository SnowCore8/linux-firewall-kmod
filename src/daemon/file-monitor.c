/*
 * file-monitor.c - inotify和文件监控函数
 */

#include "firewall-daemon.h"
#include "log-parser.h"
#include "failed-tracker.h"
#include "file-monitor.h"

/* 设置inotify监控 */
int setup_inotify(void)
{
    inotify_fd = inotify_init1(IN_CLOEXEC);  /* 使用IN_CLOEXEC防止fd泄漏到子进程 */
    if (inotify_fd < 0) {
        daemon_log_err("Failed to initialize inotify: %s", strerror(errno));
        return -1;
    }

    /* 设置为非阻塞 */
    int flags = fcntl(inotify_fd, F_GETFL);
    if (flags == -1) {
        daemon_log_err("Failed to get fcntl flags for inotify: %s", strerror(errno));
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
            file_states[global_idx].wd = -1;  /* 标记为尚未监控 */
            file_states[global_idx].jail_idx = j;  /* 记录此文件属于哪个jail */

            strncpy(file_states[global_idx].path, jail->log_files[i], sizeof(file_states[global_idx].path) - 1);
            file_states[global_idx].path[sizeof(file_states[global_idx].path) - 1] = '\0';

            /* 获取初始inode */
            if (stat(jail->log_files[i], &st) == 0) {
                file_states[global_idx].inode = st.st_ino;
                file_states[global_idx].offset = st.st_size;
                daemon_log_info("Initial offset for %s (jail=%s): %ld bytes", jail->log_files[i], jail->name, (long)file_states[global_idx].offset);
            }

            /* 监控修改、移动、删除操作 */
            file_states[global_idx].wd = inotify_add_watch(inotify_fd, jail->log_files[i],
                IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
            if (file_states[global_idx].wd < 0) {
                daemon_log_warn("Failed to watch %s (jail=%s): %s (skipping)", jail->log_files[i], jail->name, strerror(errno));
                file_states[global_idx].wd = -1;
                /* 继续处理其他日志文件而不是完全失败 */
            } else {
                daemon_log_info("Watching %s (jail=%s, wd=%d)", jail->log_files[i], jail->name, file_states[global_idx].wd);
            }

            global_idx++;
            if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
                daemon_log_warn("达到最大文件状态数（%d），停止添加监控", MAX_JAILS * MAX_LOG_FILES);
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
        if (file_states[i].wd >= 0) watched_count++;
    }
    if (watched_count == 0) {
        daemon_log_err("No log files could be watched");
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }
    daemon_log_info("Watching %d/%d log files across %d jails", watched_count, total_files, cfg.jail_count);

    return 0;
}

/* 辅助函数：处理单条完整的日志行。
 * 提取IP并处理失败登录尝试。
 * 调用时 `line` 为以null结尾的字符串。*/
void process_single_line(struct jail *j, const char *line, const char *log_path,
                        unsigned int max_retries, unsigned int findtime)
{
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
void process_lines_in_buffer(struct jail *j, char *data, size_t len, const char *log_path, size_t *consumed,
                            unsigned int max_retries, unsigned int findtime)
{
    char *line_start = data;
    char *line_end;
    size_t remaining = len;

    *consumed = 0;

    while (remaining > 0 && (line_end = memchr(line_start, '\n', remaining)) != NULL) {
        size_t line_len = line_end - line_start;

        if (line_len >= 8192) {
            daemon_log_warn("Extremely long line (%zu bytes) in %s, skipping", line_len, log_path);
        } else {
            /* 临时null终止以便处理 */
            char saved = *line_end;
            /* 安全：line_len < 8192，且data在调用者的缓冲区范围内 */
            *line_end = '\0';
            process_single_line(j, line_start, log_path, max_retries, findtime);
            *line_end = saved;
        }

        /* 越过此行 */
        size_t advance = line_len + 1;  /* +1表示换行符 */
        line_start += advance;
        remaining -= advance;
    }

    *consumed = len - remaining;
}

/* 辅助函数：将剩余数据存储为部分行（无需锁 - 每个jail的缓冲区）。
 * 如果部分缓冲区将溢出，则处理累积数据并重置。*/
void store_partial_line(struct jail *j, const char *data, size_t len, const char *log_path,
                       unsigned int max_retries, unsigned int findtime)
{
    if (len == 0) return;
    
    if (len >= sizeof(j->partial_line_buffer)) {
        daemon_log_warn("Partial line too long (%zu bytes) in %s, discarding", len, log_path);
        j->partial_line_len = 0;
        return;
    }
    
    /* 检查添加此数据是否会溢出 */
    if (j->partial_line_len + len >= sizeof(j->partial_line_buffer)) {
        /* 缓冲区将溢出 - 处理累积数据并替换为新数据 */
        size_t old_len = j->partial_line_len;
        char temp[sizeof(j->partial_line_buffer)];
        
        if (old_len > 0 && old_len < sizeof(temp)) {
            memcpy(temp, j->partial_line_buffer, old_len);
            temp[old_len] = '\0';
            process_single_line(j, temp, log_path, max_retries, findtime);
        }
        
        /* 存储新数据 */
        memcpy(j->partial_line_buffer, data, len);
        j->partial_line_len = len;
    } else {
        /* 安全追加 */
        memcpy(j->partial_line_buffer + j->partial_line_len, data, len);
        j->partial_line_len += len;
    }
    
    /* 确保null终止 */
    if (j->partial_line_len < sizeof(j->partial_line_buffer)) {
        j->partial_line_buffer[j->partial_line_len] = '\0';
    }
}

/* 辅助函数：处理累积的部分行缓冲区（无需锁 - 每个jail的缓冲区）。
 * 清空部分缓冲区并处理其内容。*/
void flush_partial_line(struct jail *j, const char *log_path,
                       unsigned int max_retries, unsigned int findtime)
{
    if (j->partial_line_len == 0) return;
    
    size_t old_len = j->partial_line_len;
    char temp[sizeof(j->partial_line_buffer)];
    if (old_len >= sizeof(temp))
        old_len = sizeof(temp) - 1;
    memcpy(temp, j->partial_line_buffer, old_len);
    temp[old_len] = '\0';
    j->partial_line_len = 0;
    
    daemon_log_debug("Flushing partial line buffer with %zu bytes from %s", old_len, log_path);
    process_single_line(j, temp, log_path, max_retries, findtime);
}

/* 从跟踪的偏移量开始处理日志文件中的新行 */
void process_new_lines(int idx)
{
    int fd = -1;
    struct stat st;
    off_t current_offset;
    char buffer[8192];
    ssize_t bytes_read;
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

    /* 加写锁以安全复制jail配置值和部分行缓冲区。
     * 使用写锁是因为我们需要修改 j->partial_line_len。
     * 持有写锁直到处理完成，以防止配置重载导致 use-after-free。*/
    if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
        daemon_log_err("Invalid jail index %d in process_new_lines", jail_idx);
        return;
    }
    
    /* 持有写锁时复制jail配置值和部分行缓冲区 */
    pthread_rwlock_wrlock(&config_rwlock);
    if (jail_idx >= cfg.jail_count) {
        /* 锁获取后再次检查，防止配置重载 */
        pthread_rwlock_unlock(&config_rwlock);
        daemon_log_err("Jail index %d became invalid after lock acquisition", jail_idx);
        return;
    }
    j = &cfg.jails[jail_idx];
    max_retries = j->max_retries;
    findtime = j->findtime;
    /* 持有锁时复制部分行缓冲区 */
    local_partial_len = j->partial_line_len;
    if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf)) {
        memcpy(local_partial_buf, j->partial_line_buffer, local_partial_len);
    }
    /* 清除jail的部分缓冲区，因为我们现在拥有数据 */
    j->partial_line_len = 0;
    /* 注意：写锁将在处理完成后释放，以防止配置重载期间 use-after-free */

    fd = open(log_path, O_RDONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", log_path, strerror(errno));
        /* 失败时恢复部分缓冲区（写锁已持有） */
        if (jail_idx < cfg.jail_count) {
            cfg.jails[jail_idx].partial_line_len = local_partial_len;
            if (local_partial_len > 0)
                memcpy(cfg.jails[jail_idx].partial_line_buffer, local_partial_buf, local_partial_len);
        }
        pthread_rwlock_unlock(&config_rwlock);
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

    /* 分块读取和处理数据 */
    current_offset = file_states[idx].offset;

    /* 将分配移到循环外部以便于清理 */
    char *combined = NULL;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  /* 确保安全null终止 */

        /* 使用本地部分缓冲区处理数据 */
        if (local_partial_len > 0) {
            /* 有部分行数据，需要合并和处理 */
            combined = malloc(local_partial_len + (size_t)bytes_read + 1);
            if (!combined) {
                daemon_log_err("分配组合缓冲区内存不足");
                /* 丢弃部分数据，直接处理新数据 */
                size_t consumed = 0;
                process_lines_in_buffer(j, buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);
                if (consumed < (size_t)bytes_read) {
                    /* 将剩余数据存储为本地缓冲区中的新部分行 */
                    size_t remain = (size_t)bytes_read - consumed;
                    if (remain < sizeof(local_partial_buf)) {
                        memcpy(local_partial_buf, buffer + consumed, remain);
                        local_partial_len = remain;
                    } else {
                        local_partial_len = 0;
                    }
                }
                current_offset += bytes_read;
                continue;
            }

            memcpy(combined, local_partial_buf, local_partial_len);
            memcpy(combined + local_partial_len, buffer, bytes_read);
            combined[local_partial_len + (size_t)bytes_read] = '\0';
            size_t total_len = local_partial_len + (size_t)bytes_read;

            /* 已合并，清除本地部分行 */
            local_partial_len = 0;

            /* 处理完整的行 */
            size_t consumed = 0;
            process_lines_in_buffer(j, combined, total_len, log_path, &consumed, max_retries, findtime);

            /* 将任何剩余数据存储为本地缓冲区中的新部分行 */
            if (consumed < total_len) {
                size_t remain = total_len - consumed;
                if (remain < sizeof(local_partial_buf)) {
                    memcpy(local_partial_buf, combined + consumed, remain);
                    local_partial_len = remain;
                } else {
                    local_partial_len = 0;
                }
            }

            free(combined);
            combined = NULL;
        } else {
            /* 无部分行 - 直接处理缓冲区 */
            size_t consumed = 0;
            process_lines_in_buffer(j, buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);

            if (consumed < (size_t)bytes_read) {
                size_t remain = (size_t)bytes_read - consumed;
                if (remain < sizeof(local_partial_buf)) {
                    memcpy(local_partial_buf, buffer + consumed, remain);
                    local_partial_len = remain;
                } else {
                    local_partial_len = 0;
                }
            }
        }

        /* 更新偏移量时防止整数溢出 */
        if (current_offset > SSIZE_MAX - bytes_read) {
            daemon_log_err("Integer overflow in file offset calculation");
            ret = -1;
            goto cleanup_restore_partial;
        }
        current_offset += bytes_read;
    }

    if (bytes_read < 0) {
        daemon_log_warn("Read error in %s: %s", log_path, strerror(errno));
        ret = -1;
        goto cleanup_restore_partial;
    }

    /* 更新偏移量 */
    file_states[idx].offset = current_offset;

cleanup_restore_partial:
    /* 在写锁下将部分行缓冲区恢复到jail（写锁已持有） */
    if (jail_idx < cfg.jail_count) {
        cfg.jails[jail_idx].partial_line_len = local_partial_len;
        if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf))
            memcpy(cfg.jails[jail_idx].partial_line_buffer, local_partial_buf, local_partial_len);
    }
    pthread_rwlock_unlock(&config_rwlock);

cleanup:
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
    free(combined);
    if (ret < 0) {
        daemon_log_err("Failed to process %s", log_path);
    }
}

/* 定期清理部分行缓冲区以防止累积的函数 */
void cleanup_partial_line_buffer(void)
{
    pthread_rwlock_wrlock(&config_rwlock);
    for (int i = 0; i < cfg.jail_count; i++) {
        flush_partial_line(&cfg.jails[i], "periodic_cleanup",
                          cfg.jails[i].max_retries, cfg.jails[i].findtime);
    }
    pthread_rwlock_unlock(&config_rwlock);
}

/* 处理日志文件轮转 */
void handle_log_rotation(int idx)
{
    struct stat st;
    int jail_idx = file_states[idx].jail_idx;
    struct jail *j = NULL;
    unsigned int max_retries, findtime;

    /* 在读锁下复制jail数据以防止配置重载期间的use-after-free */
    if (jail_idx >= 0 && jail_idx < cfg.jail_count) {
        pthread_rwlock_rdlock(&config_rwlock);
        /* 获取锁后再次检查 */
        if (jail_idx < cfg.jail_count) {
            j = &cfg.jails[jail_idx];
            max_retries = j->max_retries;
            findtime = j->findtime;
            /* 持有锁时复制并清除部分行缓冲区 */
            char local_buf[sizeof(j->partial_line_buffer)];
            size_t local_len = j->partial_line_len;
            if (local_len > 0 && local_len < sizeof(local_buf)) {
                memcpy(local_buf, j->partial_line_buffer, local_len);
            }
            j->partial_line_len = 0;
            pthread_rwlock_unlock(&config_rwlock);

            /* 不持有锁处理已复制的部分行 */
            if (local_len > 0 && local_len < sizeof(local_buf)) {
                local_buf[local_len] = '\0';
                process_single_line(j, local_buf, file_states[idx].path, max_retries, findtime);
            }
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
        file_states[idx].wd = inotify_add_watch(inotify_fd, file_states[idx].path,
            IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
        if (file_states[idx].wd < 0) {
            daemon_log_err("Failed to re-add watch for %s: %s", file_states[idx].path, strerror(errno));
            file_states[idx].wd = -1;
        } else {
            daemon_log_info("Re-added watch for %s (wd=%d)", file_states[idx].path, file_states[idx].wd);
        }
    }
}

/* 主监控循环 */
void monitor_loop(void)
{
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
            if (errno == EINTR) continue;
            daemon_log_err("select error: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* 超时 - 定期清理 */
            cleanup_expired_bans();

            /* 检查是否请求了配置重载 - 使用原子交换防止信号丢失 */
            if (__atomic_exchange_n(&reload_config, 0, __ATOMIC_SEQ_CST)) {
                atomic_fetch_add(&daemon_stats.config_reloads, 1);  /* 记录配置重载次数 */
                daemon_log_info("Reloading configuration...");

                unsigned int old_max_retries, old_findtime, old_ban_time;
                int old_interval, old_metrics_port;

                /* 保存旧配置的关键值以检测变更 */
                pthread_rwlock_rdlock(&config_rwlock);
                old_max_retries = cfg.default_max_retries;
                old_findtime = cfg.default_findtime;
                old_ban_time = cfg.default_ban_time;
                old_interval = cfg.interval;
                old_metrics_port = cfg.metrics_port;
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
                        daemon_log_warn("Failed to reload config directory, keeping old config");
                        /* 重载失败，保留 jail 数量 */
                    } else {
                        reload_ok = 1;
                        daemon_log_info("Config directory reloaded successfully");
                    }
                } else if (cfg.config_file) {
                    /* 单文件模式：重载单个文件 */
                    if (parse_config_file(cfg.config_file) < 0) {
                        daemon_log_err("Failed to reload configuration from %s", cfg.config_file);
                    } else {
                        reload_ok = 1;
                        daemon_log_info("Configuration reloaded successfully");
                    }
                } else {
                    daemon_log_warn("No config file or directory specified, cannot reload");
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
                        daemon_log_err("Failed to re-setup inotify after config reload");
                        running = 0;  /* 安全退出 */
                    }

                    /* 检查变更并输出日志 */
                    pthread_rwlock_rdlock(&config_rwlock);
                    if (old_max_retries != cfg.default_max_retries) {
                        daemon_log_info("default_max_retries changed from %u to %u", old_max_retries, cfg.default_max_retries);
                    }
                    if (old_findtime != cfg.default_findtime) {
                        daemon_log_info("default_findtime changed from %u to %u", old_findtime, cfg.default_findtime);
                    }
                    if (old_ban_time != cfg.default_ban_time) {
                        daemon_log_info("default_ban_time changed from %u to %u", old_ban_time, cfg.default_ban_time);
                    }
                    if (old_interval != cfg.interval) {
                        daemon_log_info("interval changed from %d to %d", old_interval, cfg.interval);
                    }
                    if (old_metrics_port != cfg.metrics_port) {
                        daemon_log_info("metrics_port changed from %d to %d", old_metrics_port, cfg.metrics_port);
                    }
                    pthread_rwlock_unlock(&config_rwlock);
                }
            }
            continue;
        }

        /* 处理事件前检查是否应退出 */
        if (!running) break;

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
                daemon_log_warn("inotify event length too large, skipping (len=%u, max=%d)", event->len, (int)EVENT_BUF_LEN);
                break;
            }

            /* 验证 event->len 不会导致缓冲区溢出 */
            if (sizeof(struct inotify_event) + event->len > (size_t)(len - i)) {
                daemon_log_warn("inotify event too large for remaining buffer, skipping");
                break;
            }

            /* 额外安全检查：确保我们不会有意外的大的事件长度 */
            if (event->len > 1024) {  /* 大多数 inotify 事件名称较小 */
                daemon_log_warn("Suspiciously large inotify event length, skipping (len=%u)", event->len);
                /* 即使 event->len 很大也安全计算下一个位置 */
                size_t next_pos = i + sizeof(struct inotify_event) + event->len;
                if (next_pos < i) {  // 溢出检查
                    daemon_log_err("Integer overflow detected in inotify processing");
                    break;
                }
                i = next_pos;
                continue;  // 跳过处理此可疑事件但继续处理其他事件
            }

            if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                /* 文件被修改或创建 - 查找匹配的文件 */
                pthread_rwlock_rdlock(&config_rwlock);
                int max_states = MAX_JAILS * MAX_LOG_FILES;
                for (int j = 0; j < max_states; j++) {
                    if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
                        /* 检查文件是否被轮转 */
                        if (event->mask & (IN_MOVED_TO | IN_CREATE)) {
                            pthread_rwlock_unlock(&config_rwlock);
                            handle_log_rotation(j);
                            pthread_rwlock_rdlock(&config_rwlock);
                        }
                        /* 处理新行 */
                        pthread_rwlock_unlock(&config_rwlock);
                        process_new_lines(j);
                        pthread_rwlock_rdlock(&config_rwlock);
                        break;
                    }
                }
                pthread_rwlock_unlock(&config_rwlock);
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
            if (next_pos < i) {  // 溢出检查
                daemon_log_err("Integer overflow detected in inotify processing");
                break;
            }
            i = next_pos;

            /* 事件处理期间检查是否应退出 */
            if (!running) break;
        }

        /* 事件处理后检查是否应退出 */
        if (!running) break;
    }
}