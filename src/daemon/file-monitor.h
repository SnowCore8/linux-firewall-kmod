/*
 * file-monitor.h - inotify 和文件监控函数头文件
 */

#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include "firewall-daemon.h"

/* 设置 inotify 监控 */
int setup_inotify(void);

/* 辅助函数：处理单条完整日志行 */
void process_single_line(struct jail *j, const char *line, const char *log_path,
                         unsigned int max_retries, unsigned int findtime);

/* 辅助函数：处理缓冲区中的所有完整行 */
void process_lines_in_buffer(struct jail *j, char *data, size_t len,
                             const char *log_path, size_t *consumed,
                             unsigned int max_retries, unsigned int findtime);

/* 辅助函数：将剩余数据存储为不完整行 */
void store_partial_line(struct jail *j, const char *data, size_t len, const char *log_path,
                        unsigned int max_retries, unsigned int findtime);

/* 辅助函数：处理累积的不完整行缓冲区 */
void flush_partial_line(struct jail *j, const char *log_path,
                        unsigned int max_retries, unsigned int findtime);

/* 从跟踪的偏移量开始处理日志文件的新行 */
void process_new_lines(int idx);

/* 定期清理不完整行缓冲区以防止累积 */
void cleanup_partial_line_buffer(void);

/* 处理日志文件轮转 */
void handle_log_rotation(int idx);

/* 主监控循环 */
void monitor_loop(void);

#endif /* FILE_MONITOR_H */