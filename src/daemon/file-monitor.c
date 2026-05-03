/*
 * file-monitor.c - Inotify and file monitoring functions
 */

#include "firewall-daemon.h"
#include "log-parser.h"
#include "failed-tracker.h"
#include "file-monitor.h"

/* Setup inotify monitoring */
int setup_inotify(void)
{
    inotify_fd = inotify_init1(IN_CLOEXEC);  /* Use IN_CLOEXEC to prevent fd leak to child processes */
    if (inotify_fd < 0) {
        daemon_log_err("Failed to initialize inotify: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
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

    /* Add watches for each log file in each jail */
    int global_idx = 0;
    for (int j = 0; j < cfg.jail_count; j++) {
        struct jail *jail = &cfg.jails[j];

        if (!jail->enabled) {
            daemon_log_info("Skipping disabled jail: %s", jail->name);
            continue;
        }

        for (int i = 0; i < jail->log_count; i++) {
            struct stat st;

            /* Initialize file state */
            file_states[global_idx].path[0] = '\0';
            file_states[global_idx].offset = 0;
            file_states[global_idx].inode = 0;
            file_states[global_idx].wd = -1;  /* Mark as not watching yet */
            file_states[global_idx].jail_idx = j;  /* Record which jail this file belongs to */

            strncpy(file_states[global_idx].path, jail->log_files[i], sizeof(file_states[global_idx].path) - 1);
            file_states[global_idx].path[sizeof(file_states[global_idx].path) - 1] = '\0';

            /* Get initial inode */
            if (stat(jail->log_files[i], &st) == 0) {
                file_states[global_idx].inode = st.st_ino;
                file_states[global_idx].offset = st.st_size;
                daemon_log_info("Initial offset for %s (jail=%s): %ld bytes", jail->log_files[i], jail->name, (long)file_states[global_idx].offset);
            }

            /* Watch for modifications, moves, deletes */
            file_states[global_idx].wd = inotify_add_watch(inotify_fd, jail->log_files[i],
                IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
            if (file_states[global_idx].wd < 0) {
                daemon_log_warn("Failed to watch %s (jail=%s): %s (skipping)", jail->log_files[i], jail->name, strerror(errno));
                file_states[global_idx].wd = -1;
                /* Continue with other log files instead of failing entirely */
            } else {
                daemon_log_info("Watching %s (jail=%s, wd=%d)", jail->log_files[i], jail->name, file_states[global_idx].wd);
            }

            global_idx++;
            if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
                daemon_log_warn("Maximum file states reached (%d), stopping watch addition", MAX_JAILS * MAX_LOG_FILES);
                goto watch_summary;
            }
        }
    }

watch_summary:
    /* Check if at least one file is being watched */
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

/* Helper: Process a single complete log line.
 * Extracts IP and handles failed login attempt.
 * Called with null-terminated line in `line`. */
void process_single_line(struct jail *j, const char *line, const char *log_path,
                        unsigned int max_retries, unsigned int findtime)
{
    if (!line || strlen(line) == 0)
        return;

    /* Skip extremely long lines */
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

/* Helper: Process all complete lines in a buffer.
 * `data` points to the buffer, `len` is the data length.
 * Updates `*consumed` to the number of bytes consumed (up to and including last newline).
 * Any remaining data after the last newline is left for the caller to handle as partial.
 * NOTE: This function may temporarily modify `data` to null-terminate lines. */
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
            /* Temporarily null-terminate for processing */
            char saved = *line_end;
            /* Safe: line_len < 8192, and data is within caller's buffer */
            *line_end = '\0';
            process_single_line(j, line_start, log_path, max_retries, findtime);
            *line_end = saved;
        }

        /* Move past this line */
        size_t advance = line_len + 1;  /* +1 for newline */
        line_start += advance;
        remaining -= advance;
    }

    *consumed = len - remaining;
}

/* Helper: Store remaining data as partial line (no lock needed - per-jail buffer).
 * If partial buffer would overflow, processes accumulated data and resets. */
void store_partial_line(struct jail *j, const char *data, size_t len, const char *log_path,
                       unsigned int max_retries, unsigned int findtime)
{
    if (len == 0) return;
    
    if (len >= sizeof(j->partial_line_buffer)) {
        daemon_log_warn("Partial line too long (%zu bytes) in %s, discarding", len, log_path);
        j->partial_line_len = 0;
        return;
    }
    
    /* Check if adding this data would overflow */
    if (j->partial_line_len + len >= sizeof(j->partial_line_buffer)) {
        /* Buffer would overflow - process accumulated data and replace with new data */
        size_t old_len = j->partial_line_len;
        char temp[sizeof(j->partial_line_buffer)];
        
        if (old_len > 0 && old_len < sizeof(temp)) {
            memcpy(temp, j->partial_line_buffer, old_len);
            temp[old_len] = '\0';
            process_single_line(j, temp, log_path, max_retries, findtime);
        }
        
        /* Store new data */
        memcpy(j->partial_line_buffer, data, len);
        j->partial_line_len = len;
    } else {
        /* Safe to append */
        memcpy(j->partial_line_buffer + j->partial_line_len, data, len);
        j->partial_line_len += len;
    }
    
    /* Ensure null termination */
    if (j->partial_line_len < sizeof(j->partial_line_buffer)) {
        j->partial_line_buffer[j->partial_line_len] = '\0';
    }
}

/* Helper: Process accumulated partial line buffer (no lock needed - per-jail buffer).
 * Drains the partial buffer and processes its content. */
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

/* Process new lines from log file starting from tracked offset */
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

    /* Validate idx parameter */
    if (idx < 0 || idx >= MAX_JAILS * MAX_LOG_FILES) {
        daemon_log_err("Invalid index %d to process_new_lines", idx);
        return;
    }

    log_path = file_states[idx].path;
    int jail_idx = file_states[idx].jail_idx;

    /* Get jail reference and configuration under lock protection.
     * Copy ALL jail data we need to local variables to prevent use-after-free
     * if SIGHUP config reload happens after we release the lock. */
    if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
        daemon_log_err("Invalid jail index %d in process_new_lines", jail_idx);
        return;
    }
    
    /* Local copy of partial line buffer to avoid dangling pointer */
    char local_partial_buf[sizeof(((struct jail *)0)->partial_line_buffer)];
    size_t local_partial_len = 0;

    /* Lock to safely copy jail configuration values and partial line buffer */
    pthread_mutex_lock(&config_mutex);
    j = &cfg.jails[jail_idx];
    max_retries = j->max_retries;
    findtime = j->findtime;
    /* Copy partial line buffer while holding lock */
    local_partial_len = j->partial_line_len;
    if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf)) {
        memcpy(local_partial_buf, j->partial_line_buffer, local_partial_len);
    }
    /* Clear the jail's partial buffer since we now own the data */
    j->partial_line_len = 0;
    pthread_mutex_unlock(&config_mutex);

    fd = open(log_path, O_RDONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", log_path, strerror(errno));
        /* Restore partial buffer on failure */
        pthread_mutex_lock(&config_mutex);
        if (jail_idx < cfg.jail_count) {
            cfg.jails[jail_idx].partial_line_len = local_partial_len;
            if (local_partial_len > 0)
                memcpy(cfg.jails[jail_idx].partial_line_buffer, local_partial_buf, local_partial_len);
        }
        pthread_mutex_unlock(&config_mutex);
        goto cleanup;
    }

    /* Check if file was rotated (inode changed or size decreased) */
    if (fstat(fd, &st) == 0) {
        if (file_states[idx].inode != 0 && st.st_ino != file_states[idx].inode) {
            daemon_log_info("Log file rotated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            /* Discard partial line on rotation */
            local_partial_len = 0;
        } else if (st.st_size < file_states[idx].offset) {
            daemon_log_info("Log file truncated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            /* Discard partial line on truncation */
            local_partial_len = 0;
        }
    }

    /* Seek to last known offset */
    if (file_states[idx].offset > 0) {
        if (lseek(fd, file_states[idx].offset, SEEK_SET) == (off_t)-1) {
            daemon_log_err("Failed to seek in %s: %s", log_path, strerror(errno));
            ret = -1;
            goto cleanup_restore_partial;
        }
    }

    /* Read and process data in chunks */
    current_offset = file_states[idx].offset;

    /* Move allocations outside the loop for easier cleanup */
    char *combined = NULL;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  /* Ensure null termination for safety */

        /* Process data using local partial buffer */
        if (local_partial_len > 0) {
            /* Has partial line data, need to merge and process */
            combined = malloc(local_partial_len + (size_t)bytes_read + 1);
            if (!combined) {
                daemon_log_err("Out of memory allocating combined buffer");
                /* Discard partial data, process new data directly */
                size_t consumed = 0;
                process_lines_in_buffer(j, buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);
                if (consumed < (size_t)bytes_read) {
                    /* Store remaining as new partial in local buffer */
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

            /* Clear local partial since we merged it */
            local_partial_len = 0;

            /* Process complete lines */
            size_t consumed = 0;
            process_lines_in_buffer(j, combined, total_len, log_path, &consumed, max_retries, findtime);

            /* Store any remaining data as new partial line in local buffer */
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
            /* No partial line - process buffer directly */
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

        /* Prevent integer overflow when updating offset */
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

    /* Update offset */
    file_states[idx].offset = current_offset;

cleanup_restore_partial:
    /* Restore partial line buffer to jail under lock */
    pthread_mutex_lock(&config_mutex);
    if (jail_idx < cfg.jail_count) {
        cfg.jails[jail_idx].partial_line_len = local_partial_len;
        if (local_partial_len > 0 && local_partial_len < sizeof(local_partial_buf))
            memcpy(cfg.jails[jail_idx].partial_line_buffer, local_partial_buf, local_partial_len);
    }
    pthread_mutex_unlock(&config_mutex);

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

/* Function to periodically clean up partial line buffer to prevent accumulation */
void cleanup_partial_line_buffer(void)
{
    pthread_mutex_lock(&config_mutex);
    for (int i = 0; i < cfg.jail_count; i++) {
        flush_partial_line(&cfg.jails[i], "periodic_cleanup",
                          cfg.jails[i].max_retries, cfg.jails[i].findtime);
    }
    pthread_mutex_unlock(&config_mutex);
}

/* Handle log file rotation */
void handle_log_rotation(int idx)
{
    struct stat st;
    int jail_idx = file_states[idx].jail_idx;
    struct jail *j = NULL;
    unsigned int max_retries, findtime;

    /* Copy jail data under lock to prevent use-after-free during config reload */
    if (jail_idx >= 0 && jail_idx < cfg.jail_count) {
        pthread_mutex_lock(&config_mutex);
        /* Double-check after acquiring lock */
        if (jail_idx < cfg.jail_count) {
            j = &cfg.jails[jail_idx];
            max_retries = j->max_retries;
            findtime = j->findtime;
            /* Copy and clear partial line buffer while holding lock */
            char local_buf[sizeof(j->partial_line_buffer)];
            size_t local_len = j->partial_line_len;
            if (local_len > 0 && local_len < sizeof(local_buf)) {
                memcpy(local_buf, j->partial_line_buffer, local_len);
            }
            j->partial_line_len = 0;
            pthread_mutex_unlock(&config_mutex);

            /* Process the copied partial line without holding lock */
            if (local_len > 0 && local_len < sizeof(local_buf)) {
                local_buf[local_len] = '\0';
                process_single_line(j, local_buf, file_states[idx].path, max_retries, findtime);
            }
        } else {
            pthread_mutex_unlock(&config_mutex);
            max_retries = DEFAULT_MAX_RETRIES;
            findtime = DEFAULT_FINDTIME;
        }
    } else {
        max_retries = DEFAULT_MAX_RETRIES;
        findtime = DEFAULT_FINDTIME;
    }

    atomic_fetch_add(&daemon_stats.log_rotations, 1);

    /* Check if file still exists */
    if (stat(file_states[idx].path, &st) != 0) {
        daemon_log_warn("Log file disappeared: %s", file_states[idx].path);
        file_states[idx].offset = 0;
        return;
    }

    /* Check if inode changed (file was rotated) */
    if (st.st_ino != file_states[idx].inode) {
        daemon_log_info("Log file rotated: %s", file_states[idx].path);
        file_states[idx].inode = st.st_ino;
        file_states[idx].offset = 0;

        /* Re-add watch if needed */
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

/* Main monitoring loop */
void monitor_loop(void)
{
    char buffer[EVENT_BUF_LEN];

    daemon_log_info("Starting monitoring loop");

    while (running) {
        fd_set read_fds;
        struct timeval tv;
        int current_interval;

        /* Reading configuration requires locking - prevent concurrency with SIGHUP config reload */
        pthread_mutex_lock(&config_mutex);
        current_interval = cfg.interval;
        pthread_mutex_unlock(&config_mutex);

        FD_ZERO(&read_fds);
        FD_SET(inotify_fd, &read_fds);

        tv.tv_sec = current_interval;
        tv.tv_usec = 0;

        /* Wait for inotify events or timeout */
        int ret = select(inotify_fd + 1, &read_fds, NULL, NULL, &tv);
        if (ret < 0) {
            if (errno == EINTR) continue;
            daemon_log_err("select error: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* Timeout - periodic cleanup */
            cleanup_expired_bans();

            /* Check if config reload was requested - use atomic exchange to prevent lost signals */
            if (__atomic_exchange_n(&reload_config, 0, __ATOMIC_SEQ_CST)) {
                daemon_log_info("Reloading configuration...");

                unsigned int old_max_retries, old_findtime, old_ban_time;
                int old_interval, old_metrics_port;

                /* Save key values of old configuration for change detection */
                pthread_mutex_lock(&config_mutex);
                old_max_retries = cfg.default_max_retries;
                old_findtime = cfg.default_findtime;
                old_ban_time = cfg.default_ban_time;
                old_interval = cfg.interval;
                old_metrics_port = cfg.metrics_port;
                pthread_mutex_unlock(&config_mutex);

                /* Select reload method based on configuration type */
                int reload_ok = 0;

                /* parse_config_file now uses double-buffering internally:
                 * it parses into a temp config (no lock), then briefly locks
                 * to swap configs and migrate runtime state (failed_hash).
                 * NO need to call cleanup_all_jails() first - the double-buffer
                 * swap handles migration and cleanup atomically. */

                if (cfg.config_dir) {
                    /* Configuration directory mode: reload entire directory */
                    daemon_log_info("Reloading config directory: %s", cfg.config_dir);
                    if (load_config_directory(cfg.config_dir) < 0) {
                        daemon_log_warn("Failed to reload config directory, keeping old config");
                        /* Restore jail count since reload failed */
                    } else {
                        reload_ok = 1;
                        daemon_log_info("Config directory reloaded successfully");
                    }
                } else if (cfg.config_file) {
                    /* Single file mode: reload single file */
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
                    /* Re-setup inotify watches after config reload */
                    if (inotify_fd >= 0) {
                        /* Remove old watches - iterate through all possible file states */
                        int max_states = MAX_JAILS * MAX_LOG_FILES;
                        for (int i = 0; i < max_states; i++) {
                            if (file_states[i].wd >= 0) {
                                inotify_rm_watch(inotify_fd, file_states[i].wd);
                                file_states[i].wd = -1;
                            }
                            /* Reset file state */
                            file_states[i].offset = 0;
                            file_states[i].inode = 0;
                            file_states[i].path[0] = '\0';
                            file_states[i].jail_idx = -1;
                        }
                        close(inotify_fd);
                        inotify_fd = -1;
                    }

                    /* Re-setup inotify */
                    if (setup_inotify() < 0) {
                        daemon_log_err("Failed to re-setup inotify after config reload");
                        running = 0;  /* Safe exit */
                    }

                    /* Check changes and output logs */
                    pthread_mutex_lock(&config_mutex);
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
                    pthread_mutex_unlock(&config_mutex);
                }
            }
            continue;
        }

        /* Check if we should exit before processing events */
        if (!running) break;

        /* Read inotify events */
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

        /* Process events */
        size_t i = 0;
        while (i < (size_t)len) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            /* Validate event structure size and prevent integer overflow */
            if (sizeof(struct inotify_event) > (size_t)len - i) {
                daemon_log_err("Invalid inotify event structure size");
                break;
            }

            /* Additional boundary check: ensure event->len is within reasonable bounds */
            if (event->len > EVENT_BUF_LEN) {
                daemon_log_warn("inotify event length too large, skipping (len=%u, max=%d)", event->len, (int)EVENT_BUF_LEN);
                break;
            }

            /* Verify event->len doesn't cause buffer overflow */
            if (sizeof(struct inotify_event) + event->len > (size_t)(len - i)) {
                daemon_log_warn("inotify event too large for remaining buffer, skipping");
                break;
            }

            /* Additional safety check: ensure we don't have an unexpectedly large event length */
            if (event->len > 1024) {  /* Most inotify events have small names */
                daemon_log_warn("Suspiciously large inotify event length, skipping (len=%u)", event->len);
                /* Calculate next position safely even with large event->len */
                size_t next_pos = i + sizeof(struct inotify_event) + event->len;
                if (next_pos < i) {  // Overflow check
                    daemon_log_err("Integer overflow detected in inotify processing");
                    break;
                }
                i = next_pos;
                continue;  // Skip processing this suspicious event but continue with others
            }

            if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                /* File was modified or created - find matching file */
                pthread_mutex_lock(&config_mutex);
                int max_states = MAX_JAILS * MAX_LOG_FILES;
                for (int j = 0; j < max_states; j++) {
                    if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
                        /* Check if file was rotated */
                        if (event->mask & (IN_MOVED_TO | IN_CREATE)) {
                            pthread_mutex_unlock(&config_mutex);
                            handle_log_rotation(j);
                            pthread_mutex_lock(&config_mutex);
                        }
                        /* Process new lines */
                        pthread_mutex_unlock(&config_mutex);
                        process_new_lines(j);
                        pthread_mutex_lock(&config_mutex);
                        break;
                    }
                }
                pthread_mutex_unlock(&config_mutex);
            } else if (event->mask & (IN_MOVED_FROM | IN_DELETE)) {
                /* File was moved or deleted - mark for rotation handling */
                pthread_mutex_lock(&config_mutex);
                int max_states = MAX_JAILS * MAX_LOG_FILES;
                for (int j = 0; j < max_states; j++) {
                    if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
                        daemon_log_info("Log file removed: %s", file_states[j].path);
                        file_states[j].wd = -1;
                        break;
                    }
                }
                pthread_mutex_unlock(&config_mutex);
            }

            /* Advance position with overflow check */
            size_t next_pos = i + sizeof(struct inotify_event) + event->len;
            if (next_pos < i) {  // Overflow check
                daemon_log_err("Integer overflow detected in inotify processing");
                break;
            }
            i = next_pos;

            /* Check if we should exit during event processing */
            if (!running) break;
        }

        /* Check if we should exit after processing events */
        if (!running) break;
    }
}