/*
 * log.h - 守护进程统一日志系统
 *
 * 为所有守护进程模块提供统一的 5 级日志 API:
 *   - LOG_LEVEL_NONE  (0) - 无日志
 *   - LOG_LEVEL_ERR   (1) - 错误日志 - 始终输出
 *   - LOG_LEVEL_WARN  (2) - 警告日志 - 重要警告
 *   - LOG_LEVEL_INFO  (3) - 信息日志 - 正常操作
 *   - LOG_LEVEL_DEBUG (4) - 调试日志 - 开发调试
 *
 * 用法 - 两种方式任选其一:
 *
 * 方式 A (主守护进程):  #include "firewall-daemon.h" 即可
 *                      - 自动使用 LOG_COMPONENT="daemon" 与
 *                        日志前缀 "firewall: " (向后兼容)
 *
 * 方式 B (子模块):     #include "firewall-daemon.h"
 *                      #undef LOG_COMPONENT
 *                      #define LOG_COMPONENT "exporter"
 *                      #undef LOG_FMT_PREFIX
 *                      #define LOG_FMT_PREFIX "firewall[exporter]: "
 *                      - 切换到 "exporter" 组件 + 方括号格式
 *
 * 日志格式:
 *   - syslog:     "firewall[<component>]: <msg>" / "firewall: <msg>"
 *   - 日志文件:   "2026-06-11 15:30:00 [<component>] <LEVEL>: <msg>"
 *
 * 输出目的地:
 *   1. syslog (始终启用)
 *   2. 可选独立日志文件 (cfg.log_file 非空时启用)
 *      通过 log_init_file() / log_close_file() 控制
 *
 * 协议:
 *   1. 所有日志通过 syslog 输出
 *   2. 启动早期(openlog 之前) 使用 bootstrap_emit_*() 输出到 stderr
 *   3. 限流宏按"每秒最多 1 条真实日志 + 1 条/分钟汇总"实现
 *   4. 日志文件输出线程安全(内部 pthread_mutex 保护)
 *
 * 与旧 API 的对应关系:
 *   daemon_log_err/warn/info/debug  -> LOG_ERR/WARN/INFO/DEBUG
 *   sqlite_log_err/warn/info        -> LOG_*   (LOG_COMPONENT = "sqlite")
 *   exporter_log_err/warn/info      -> LOG_*   (LOG_COMPONENT = "exporter")
 *
 * 新增能力:
 *   - 各模块统一具备 5 级日志 (sqlite/exporter 此前缺少 debug)
 *   - 统一的限流宏(替代 http-exporter.c 中散落的内联实现)
 *   - 启动期 bootstrap_emit_*() 辅助函数(替代启动期的 fprintf(stderr))
 *   - 可选独立日志文件输出(log_init_file() / log_close_file())
 *   - 运行时 log_level 过滤(log_set_level() / log_get_level())
 */

#ifndef FIREWALL_DAEMON_LOG_H
#define FIREWALL_DAEMON_LOG_H

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

/* 组件名 - 由各 .c 文件提供(必须为字符串字面量) */
#ifndef LOG_COMPONENT
#  define LOG_COMPONENT "daemon"
#endif

/* 日志级别常量(独立于 syslog 的 LOG_INFO 等,避免命名冲突) */
#define LOG_LEVEL_NONE 0
#define LOG_LEVEL_ERR 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_INFO 3
#define LOG_LEVEL_DEBUG 4

/* 编译时日志级别上限：仅 <= LOG_MAX_LEVEL 的级别被编译进二进制。
 * 运行时可通过 -DLOG_MAX_LEVEL=N 调整，默认 INFO。
 * 注：运行时还会用 log_runtime_level 二次过滤 */
#ifndef LOG_MAX_LEVEL
#  define LOG_MAX_LEVEL LOG_LEVEL_INFO
#endif

/* 是否启用限流版本(0 时所有 RATELIMITED 宏退化为普通宏) */
#ifndef LOG_ENABLE_RATELIMIT
#  define LOG_ENABLE_RATELIMIT 1
#endif

/* ============================================================================
 * syslog 优先级值(硬编码 POSIX 标准值)
 * ============================================================================
 * syslog.h 已将 LOG_ERR/LOG_INFO 等定义为整型常量(优先级值)。
 * 我们要重用这些名字作为函数式宏(用户友好),所以先取消它们,
 * 然后用硬编码的 POSIX 优先级值替代。
 *   LOG_EMERG=0, LOG_ALERT=1, LOG_CRIT=2,  LOG_ERR=3,
 *   LOG_WARNING=4, LOG_NOTICE=5, LOG_INFO=6, LOG_DEBUG=7
 */
#define _PRIO_ERR 3
#define _PRIO_WARNING 4
#define _PRIO_NOTICE 5
#define _PRIO_INFO 6
#define _PRIO_DEBUG 7

/* 取消 syslog 整型常量定义,腾出名字给函数式宏使用 */
#ifdef LOG_ERR
#  undef LOG_ERR
#endif
#ifdef LOG_WARNING
#  undef LOG_WARNING
#endif
#ifdef LOG_NOTICE
#  undef LOG_NOTICE
#endif
#ifdef LOG_INFO
#  undef LOG_INFO
#endif
#ifdef LOG_DEBUG
#  undef LOG_DEBUG
#endif

/* ============================================================================
 * 日志前缀
 * ============================================================================
 * 主守护进程组件使用历史无方括号格式以保持向后兼容;
 * 子模块统一使用方括号格式便于日志路由/过滤。 */
#ifndef LOG_FMT_PREFIX
#  ifdef LOG_COMPONENT_DAEMON
#    define LOG_FMT_PREFIX "firewall: "
#  else
#    define LOG_FMT_PREFIX "firewall[" LOG_COMPONENT "]: "
#  endif
#endif

/* 内部别名,简化宏展开 */
#define _LOG_FMT_PREFIX LOG_FMT_PREFIX

/* ============================================================================
 * 运行时日志后端 - destination 路由 + 级别过滤 + 格式选择
 * ============================================================================
 * 编译时 LOG_MAX_LEVEL 决定哪些级别被编译进二进制(零运行时开销);
 * 运行时 log_runtime_level 决定哪些级别实际输出(可动态调整)。
 * 三个独立可调维度:
 *   1. log_destination - 输出目的地(syslog/journal/file/both)
 *   2. log_file_fp      - 文件输出开关(由 log_init_file 控)
 *   3. log_format       - 文件输出格式(plain/json)
 * 这些状态由 log_init_file() / log_close_file() / log_set_level() /
 * log_set_destination() / log_set_format() 管理。 */

/* 输出目的地枚举 - 决定 LOG_* 调用路由到哪里 */
typedef enum {
  LOG_DEST_SYSLOG = 0, /* 仅 syslog (POSIX syslog(),systemd 会自动捕获到 journald) */
  LOG_DEST_FILE = 1,   /* 仅独立日志文件 */
  LOG_DEST_BOTH = 2,   /* 双写 syslog + 文件(默认,兼容历史行为) */
  LOG_DEST_JOURNAL = 3 /* 仅 journald (直接用 sd_journal_send,需 libsystemd) */
} log_destination_t;

/* 文件输出格式枚举 - 仅当 destination 包含 file 时生效 */
typedef enum {
  LOG_FORMAT_PLAIN = 0, /* 纯文本 (默认,向后兼容现有 grep 工作流) */
  LOG_FORMAT_JSON = 1   /* JSON Lines (每行一个 JSON 对象,适合 filebeat/Vector) */
} log_format_t;

extern int log_runtime_level; /* 运行时级别上限,默认 LOG_LEVEL_INFO */
extern FILE *log_file_fp;     /* 日志文件指针,NULL 表示不写文件 */
extern pthread_mutex_t log_file_mutex; /* 保护文件写入的互斥锁 */
extern log_destination_t log_destination; /* 当前路由目的地,默认 LOG_DEST_BOTH */
extern log_format_t log_format;           /* 当前文件格式,默认 LOG_FORMAT_PLAIN */

static inline void log_set_level(int level) {
  if (level >= LOG_LEVEL_NONE && level <= LOG_LEVEL_DEBUG)
    log_runtime_level = level;
}

static inline int log_get_level(void) {
  return log_runtime_level;
}

static inline void log_set_destination(log_destination_t dest) {
  log_destination = dest;
}

static inline log_destination_t log_get_destination(void) {
  return log_destination;
}

static inline void log_set_format(log_format_t fmt) {
  log_format = fmt;
}

static inline log_format_t log_get_format(void) {
  return log_format;
}

/* 独立日志文件管理(由 log.c 实现) */
int log_init_file(const char *path);
void log_close_file(void);

/* 写入文件后端 - 由 LOG_* 宏在调用方根据 destination 决定后调用,
 * 使用互斥锁保护并发写入。
 * level: 日志级别数字(1-4)
 * full_fmt: 完整格式字符串(已含前缀,变参)
 * ap: 变长参数列表
 * 注意:此函数消费 va_list 一次,如需多次使用,调用方需 va_copy
 *
 * 输出格式由 log_format 决定:
 *   - LOG_FORMAT_PLAIN:  YYYY-MM-DD HH:MM:SS [component] LEVEL: full_msg
 *   - LOG_FORMAT_JSON:   {"ts":"...","prio":N,"component":"X","level":"INFO","msg":"..."}
 * 注意: JSON 模式只是包装消息文本,不解析消息内部的 key=value 对。
 * 消息内的结构化字段调用方应直接写在 fmt 串中(如 "(jail=sshd action=ban)"),
 * 这样 plain/json 两种格式都包含这些 key=value,grep/jq 都能消费。 */
static inline void log_emit_file(int level, const char *full_fmt, va_list ap) {
  if (!log_file_fp)
    return;
  if (level > log_runtime_level)
    return;

  pthread_mutex_lock(&log_file_mutex);

  /* 时间戳: PLAIN 用空格分隔,JSON 用 ISO-8601 */
  time_t now = time(NULL);
  struct tm tm_buf;
  localtime_r(&now, &tm_buf);
  char ts_plain[32];
  char ts_json[32];
  strftime(ts_plain, sizeof(ts_plain), "%Y-%m-%d %H:%M:%S", &tm_buf);
  strftime(ts_json, sizeof(ts_json), "%Y-%m-%dT%H:%M:%S%z", &tm_buf);

  /* 级别字符串 + syslog priority 数字 */
  const char *lvl_str = "INFO";
  int prio = 6; /* LOG_INFO */
  switch (level) {
  case LOG_LEVEL_ERR:
    lvl_str = "ERROR";
    prio = 3; /* LOG_ERR */
    break;
  case LOG_LEVEL_WARN:
    lvl_str = "WARN";
    prio = 4; /* LOG_WARNING */
    break;
  case LOG_LEVEL_INFO:
    lvl_str = "INFO";
    prio = 6; /* LOG_INFO */
    break;
  case LOG_LEVEL_DEBUG:
    lvl_str = "DEBUG";
    prio = 7; /* LOG_DEBUG */
    break;
  default:
    lvl_str = "?";
    prio = 6;
    break;
  }

  if (log_format == LOG_FORMAT_JSON) {
    /* JSON Lines: {"ts":"...","prio":N,"component":"X","level":"INFO","msg":"..."}
     * msg 字段先 vsnprintf 渲染为完整文本(替换 %s %d 等),再做最少 JSON 转义:
     *   - " -> \"   (关键,会破坏 JSON)
     *   - \ -> \\   (转义反斜杠)
     *   - \n 暂不转义(消息通常单行,换行符极罕见,留作未来扩展)
     * 体积估算: 比 plain 大约 30-40% */
    char msg_buf[1024];
    vsnprintf(msg_buf, sizeof(msg_buf), full_fmt, ap);

    fputs("{\"ts\":\"", log_file_fp);
    fputs(ts_json, log_file_fp);
    fprintf(log_file_fp, "\",\"prio\":%d,\"component\":\"%s\",\"level\":\"%s\",\"msg\":\"",
            prio, LOG_COMPONENT, lvl_str);
    for (const char *p = msg_buf; *p; p++) {
      if (*p == '"') {
        fputc('\\', log_file_fp);
        fputc('"', log_file_fp);
      } else if (*p == '\\') {
        fputc('\\', log_file_fp);
        fputc('\\', log_file_fp);
      } else {
        fputc(*p, log_file_fp);
      }
    }
    fputs("\"}\n", log_file_fp);
  } else {
    /* PLAIN: YYYY-MM-DD HH:MM:SS [component] LEVEL: full_msg */
    fprintf(log_file_fp, "%s [%s] %s: ", ts_plain, LOG_COMPONENT, lvl_str);
    vfprintf(log_file_fp, full_fmt, ap);
    fputc('\n', log_file_fp);
  }

  fflush(log_file_fp); /* 守护进程通常低流量,直接 flush 便于监控 */
  pthread_mutex_unlock(&log_file_mutex);
}

/* ============================================================================
 * 公共日志宏 - 通过 helper 函数避开 variadic 宏的 GCC 限制
 * ============================================================================
 * 直接在宏里使用 va_start 在无变参调用(如 LOG_INFO("just a string"))时会触发
 * 'va_start used in function with fixed arguments' 错误。解决方案是把 va_start
 * 移到真正的变参函数体内,_log_emit_* 即为这些变参 helper。
 *
 * 路由逻辑(由 log_destination 决定):
 *   - LOG_DEST_SYSLOG:  仅 vsyslog
 *   - LOG_DEST_FILE:    仅 log_emit_file
 *   - LOG_DEST_BOTH:    vsyslog + log_emit_file(默认,双写)
 *   - LOG_DEST_JOURNAL: 暂退化为 vsyslog(systemd 会自动捕获)
 *   文件输出格式(plain/json)由 log_format 决定,在 log_emit_file 内部处理。 */

static inline void _log_emit_err(const char *fmt, ...) {
  va_list ap, ap_copy;
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  char full_fmt[1024];
  snprintf(full_fmt, sizeof(full_fmt), "%s%s", _LOG_FMT_PREFIX, fmt);
  if (log_destination == LOG_DEST_SYSLOG || log_destination == LOG_DEST_BOTH ||
      log_destination == LOG_DEST_JOURNAL) {
    vsyslog(_PRIO_ERR, full_fmt, ap);
  }
  if (log_destination == LOG_DEST_FILE || log_destination == LOG_DEST_BOTH) {
    log_emit_file(LOG_LEVEL_ERR, full_fmt, ap_copy);
  }
  va_end(ap);
  va_end(ap_copy);
}

static inline void _log_emit_warn(const char *fmt, ...) {
  va_list ap, ap_copy;
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  char full_fmt[1024];
  snprintf(full_fmt, sizeof(full_fmt), "%s%s", _LOG_FMT_PREFIX, fmt);
  if (log_destination == LOG_DEST_SYSLOG || log_destination == LOG_DEST_BOTH ||
      log_destination == LOG_DEST_JOURNAL) {
    vsyslog(_PRIO_WARNING, full_fmt, ap);
  }
  if (log_destination == LOG_DEST_FILE || log_destination == LOG_DEST_BOTH) {
    log_emit_file(LOG_LEVEL_WARN, full_fmt, ap_copy);
  }
  va_end(ap);
  va_end(ap_copy);
}

static inline void _log_emit_info(const char *fmt, ...) {
  va_list ap, ap_copy;
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  char full_fmt[1024];
  snprintf(full_fmt, sizeof(full_fmt), "%s%s", _LOG_FMT_PREFIX, fmt);
  if (log_destination == LOG_DEST_SYSLOG || log_destination == LOG_DEST_BOTH ||
      log_destination == LOG_DEST_JOURNAL) {
    vsyslog(_PRIO_INFO, full_fmt, ap);
  }
  if (log_destination == LOG_DEST_FILE || log_destination == LOG_DEST_BOTH) {
    log_emit_file(LOG_LEVEL_INFO, full_fmt, ap_copy);
  }
  va_end(ap);
  va_end(ap_copy);
}

static inline void _log_emit_debug(const char *fmt, ...) {
  va_list ap, ap_copy;
  va_start(ap, fmt);
  va_copy(ap_copy, ap);
  char full_fmt[1024];
  snprintf(full_fmt, sizeof(full_fmt), "%s%s", _LOG_FMT_PREFIX, fmt);
  if (log_destination == LOG_DEST_SYSLOG || log_destination == LOG_DEST_BOTH ||
      log_destination == LOG_DEST_JOURNAL) {
    vsyslog(_PRIO_DEBUG, full_fmt, ap);
  }
  if (log_destination == LOG_DEST_FILE || log_destination == LOG_DEST_BOTH) {
    log_emit_file(LOG_LEVEL_DEBUG, full_fmt, ap_copy);
  }
  va_end(ap);
  va_end(ap_copy);
}

#define LOG_ERR(...)                    \
  do {                                  \
    if (LOG_LEVEL_ERR <= LOG_MAX_LEVEL) \
      _log_emit_err(__VA_ARGS__);       \
  } while (0)

#define LOG_WARN(...)                    \
  do {                                   \
    if (LOG_LEVEL_WARN <= LOG_MAX_LEVEL) \
      _log_emit_warn(__VA_ARGS__);       \
  } while (0)

#define LOG_INFO(...)                    \
  do {                                   \
    if (LOG_LEVEL_INFO <= LOG_MAX_LEVEL) \
      _log_emit_info(__VA_ARGS__);       \
  } while (0)

#define LOG_DEBUG(...)                    \
  do {                                    \
    if (LOG_LEVEL_DEBUG <= LOG_MAX_LEVEL) \
      _log_emit_debug(__VA_ARGS__);       \
  } while (0)

/* ============================================================================
 * 限流宏 - 防止高频日志淹没系统
 * ============================================================================
 * 设计: 每秒最多 1 条真实日志;同一秒内的第 2 条开始丢弃并仅在每分钟
 * 输出 1 条"压制中"汇总。所有限流日志共享一个时间窗口(以 last_log_sec 为准)。
 * 注意: 这是"防刷屏"型限流,不是漏桶;高频事件至少能见到 1 条/秒。 */

#if LOG_ENABLE_RATELIMIT

/* 内部: 通用限流函数(由 LOG_*_RATELIMITED 调用)
 * 实现: 每秒重置计数器;首条正常输出;后续触发"汇总"提示。 */
static inline void _log_ratelimited_emit(int syslog_prio, const char *fmt, ...) {
  static time_t _lr_last_sec = 0;
  static unsigned int _lr_count_this_sec = 0;
  static time_t _lr_suppress_last_warn = 0;
  time_t _lr_now = time(NULL);
  va_list _lr_ap;

  if (_lr_now != _lr_last_sec) {
    _lr_last_sec = _lr_now;
    _lr_count_this_sec = 0;
  }
  _lr_count_this_sec++;

  if (_lr_count_this_sec == 1) {
    va_start(_lr_ap, fmt);
    vsyslog(syslog_prio, fmt, _lr_ap);
    va_end(_lr_ap);
  } else if (_lr_now - _lr_suppress_last_warn >= 60) {
    _lr_suppress_last_warn = _lr_now;
    syslog(_PRIO_WARNING, _LOG_FMT_PREFIX "log rate-limited: %u+ messages suppressed in last second",
           _lr_count_this_sec);
  }
}

#  define LOG_ERR_RATELIMITED(fmt, ...) \
    _log_ratelimited_emit(_PRIO_ERR, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__)
#  define LOG_WARN_RATELIMITED(fmt, ...) \
    _log_ratelimited_emit(_PRIO_WARNING, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__)
#  define LOG_INFO_RATELIMITED(fmt, ...) \
    _log_ratelimited_emit(_PRIO_INFO, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__)
#  define LOG_DEBUG_RATELIMITED(fmt, ...) \
    _log_ratelimited_emit(_PRIO_DEBUG, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__)

#else /* LOG_ENABLE_RATELIMIT == 0 */

#  define LOG_ERR_RATELIMITED(fmt, ...) LOG_ERR(fmt, ##__VA_ARGS__)
#  define LOG_WARN_RATELIMITED(fmt, ...) LOG_WARN(fmt, ##__VA_ARGS__)
#  define LOG_INFO_RATELIMITED(fmt, ...) LOG_INFO(fmt, ##__VA_ARGS__)
#  define LOG_DEBUG_RATELIMITED(fmt, ...) LOG_DEBUG(fmt, ##__VA_ARGS__)

#endif /* LOG_ENABLE_RATELIMIT */

/* ============================================================================
 * 启动期输出 (在 openlog() 之前)
 * ============================================================================
 * 在 openlog() 之前任何日志都应该走 stderr,而不是 syslog。
 * 这些辅助函数使用与运行期一致的前缀格式与级别标记,确保风格统一。 */

static inline void bootstrap_emit_err(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, _LOG_FMT_PREFIX "ERROR: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static inline void bootstrap_emit_warn(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, _LOG_FMT_PREFIX "WARN: ");
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

static inline void bootstrap_emit_info(const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, _LOG_FMT_PREFIX);
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
}

#endif /* FIREWALL_DAEMON_LOG_H */
