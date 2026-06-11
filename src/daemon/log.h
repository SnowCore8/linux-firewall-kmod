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
 *   - 组件名 == "daemon" 时: "firewall: <msg>" (保持向后兼容)
 *   - 其他组件:            "firewall[<component>]: <msg>"
 *
 * 协议:
 *   1. 所有日志通过 syslog 输出
 *   2. 启动早期(openlog 之前) 使用 bootstrap_emit_*() 输出到 stderr
 *   3. 限流宏按"每秒最多 1 条真实日志 + 1 条/分钟汇总"实现
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
 */

#ifndef FIREWALL_DAEMON_LOG_H
#define FIREWALL_DAEMON_LOG_H

#include <stdarg.h>
#include <stdio.h>
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
 * 运行时可通过 -DLOG_MAX_LEVEL=N 调整，默认 INFO。 */
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
 * 子模块统一使用方括号格式便于日志路由/过滤。
 *
 * 用户可手动覆盖 LOG_FMT_PREFIX(参考本文件顶部"方式 B")。 */
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
 * 公共日志宏
 * ========================================================================== */

#define LOG_ERR(fmt, ...)                                    \
  do {                                                       \
    if (LOG_LEVEL_ERR <= LOG_MAX_LEVEL)                      \
      syslog(_PRIO_ERR, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__); \
  } while (0)

#define LOG_WARN(fmt, ...)                                       \
  do {                                                           \
    if (LOG_LEVEL_WARN <= LOG_MAX_LEVEL)                         \
      syslog(_PRIO_WARNING, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__); \
  } while (0)

#define LOG_INFO(fmt, ...)                                    \
  do {                                                        \
    if (LOG_LEVEL_INFO <= LOG_MAX_LEVEL)                      \
      syslog(_PRIO_INFO, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__); \
  } while (0)

#define LOG_DEBUG(fmt, ...)                                    \
  do {                                                         \
    if (LOG_LEVEL_DEBUG <= LOG_MAX_LEVEL)                      \
      syslog(_PRIO_DEBUG, _LOG_FMT_PREFIX fmt, ##__VA_ARGS__); \
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
