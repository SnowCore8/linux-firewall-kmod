/*
 * file-monitor.h - Header for inotify and file monitoring functions
 */

#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include "firewall-daemon.h"

/* Setup inotify monitoring */
int setup_inotify(void);

/* Helper: Process a single complete log line */
void process_single_line(struct jail *j, const char *line, const char *log_path,
                        unsigned int max_retries, unsigned int findtime);

/* Helper: Process all complete lines in a buffer */
void process_lines_in_buffer(struct jail *j, char *data, size_t len, const char *log_path, size_t *consumed,
                            unsigned int max_retries, unsigned int findtime);

/* Helper: Store remaining data as partial line */
void store_partial_line(struct jail *j, const char *data, size_t len, const char *log_path,
                       unsigned int max_retries, unsigned int findtime);

/* Helper: Process accumulated partial line buffer */
void flush_partial_line(struct jail *j, const char *log_path,
                       unsigned int max_retries, unsigned int findtime);

/* Process new lines from log file starting from tracked offset */
void process_new_lines(int idx);

/* Function to periodically clean up partial line buffer to prevent accumulation */
void cleanup_partial_line_buffer(void);

/* Handle log file rotation */
void handle_log_rotation(int idx);

/* Main monitoring loop */
void monitor_loop(void);

#endif /* FILE_MONITOR_H */