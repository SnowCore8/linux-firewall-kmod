/*
 * log.c - 守护进程统一日志后端实现
 *
 * 提供:
 *   1. 全局日志状态变量定义(log_runtime_level / log_file_fp)
 *   2. 文件输出初始化/关闭函数(log_init_file / log_close_file)
 *
 * 这些状态在 .h 中声明,在此处定义。include 顺序保证
 * main.c 是第一个使用 LOG_* 的 TU(但当前主守护进程是 firewall-daemon.c)。
 *
 * 设计要点:
 *   - 日志文件使用 append 模式打开(O_APPEND),保证多进程/多线程写入原子性
 *   - 每次写入后立即 fflush,简化监控和崩溃后的现场保留
 *   - 互斥锁保护 fprintf 调用以避免交错(尽管 O_APPEND 已保证原子)
 *   - 启动时权限不足不致命:回退到 syslog-only 并 LOG_WARN
 */

#define LOG_COMPONENT_DAEMON
#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* 全局日志状态 - 在 .h 中声明 */
int log_runtime_level = LOG_LEVEL_INFO;
FILE *log_file_fp = NULL;
pthread_mutex_t log_file_mutex = PTHREAD_MUTEX_INITIALIZER;
/* 默认 LOG_DEST_BOTH: 双写 syslog + 文件(历史兼容行为)。
 * 默认 LOG_FORMAT_PLAIN: 纯文本,保留现有 grep 工作流。
 * 用户在 default.yaml 中可显式覆盖这两个值。 */
log_destination_t log_destination = LOG_DEST_BOTH;
log_format_t log_format = LOG_FORMAT_PLAIN;

/* 打开独立日志文件(append 模式)
 *
 * 成功返回 0,失败返回 -1(errno 被设置)。
 * 调用前应已持有/不持锁均可(此函数内部上锁保护 fp 写入)。
 *
 * 行为:
 *   1. 关闭旧 fp(如已打开)
 *   2. O_CREAT|O_APPEND|O_WRONLY 打开新文件
 *   3. 父目录不存在时尝试 mkdir(0755)
 *   4. 失败时回退到 syslog-only 模式(不致命)
 */
int log_init_file(const char *path) {
  if (!path || !*path)
    return -1;

  pthread_mutex_lock(&log_file_mutex);

  /* 关闭旧 fp */
  if (log_file_fp) {
    fclose(log_file_fp);
    log_file_fp = NULL;
  }

  /* 父目录可能不存在,尝试创建 */
  char *path_dup = strdup(path);
  if (!path_dup) {
    pthread_mutex_unlock(&log_file_mutex);
    return -1;
  }
  char *dir_slash = strrchr(path_dup, '/');
  if (dir_slash && dir_slash != path_dup) {
    *dir_slash = '\0';
    struct stat st;
    if (stat(path_dup, &st) != 0) {
      if (mkdir(path_dup, 0755) != 0 && errno != EEXIST) {
        int saved = errno;
        free(path_dup);
        pthread_mutex_unlock(&log_file_mutex);
        errno = saved;
        return -1;
      }
    }
  }
  free(path_dup);

  /* 打开文件:append + close-on-exec */
  int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
  if (fd < 0) {
    int saved = errno;
    pthread_mutex_unlock(&log_file_mutex);
    errno = saved;
    return -1;
  }

  FILE *fp = fdopen(fd, "a");
  if (!fp) {
    int saved = errno;
    close(fd);
    pthread_mutex_unlock(&log_file_mutex);
    errno = saved;
    return -1;
  }

  log_file_fp = fp;
  pthread_mutex_unlock(&log_file_mutex);
  return 0;
}

/* 关闭日志文件 - 之后 LOG_* 不再写文件,但仍输出到 syslog */
void log_close_file(void) {
  pthread_mutex_lock(&log_file_mutex);
  if (log_file_fp) {
    fclose(log_file_fp);
    log_file_fp = NULL;
  }
  pthread_mutex_unlock(&log_file_mutex);
}
