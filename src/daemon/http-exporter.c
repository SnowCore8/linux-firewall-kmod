/*
 * http-exporter.c - 防火墙守护进程的 Prometheus HTTP 导出器
 *
 * 使用 libmicrohttpd 实现符合 RFC 规范的 HTTP 服务器。
 * 提供 /metrics 和 /health 端点用于 Prometheus 监控。
 * 在独立的 pthread 线程中运行。
 *
 * 功能特性：
 *   - 基于 libmicrohttpd 的 HTTP 服务器（符合 RFC 规范）
 *   - Prometheus 文本格式输出
 *   - 从 /proc/firewall/stats 读取内核统计信息
 *   - 从共享 daemon_stats 结构读取守护进程统计信息
 *   - 默认监听 127.0.0.1:9119
 *   - 支持 Basic Auth 认证（通过 metrics_username/metrics_password 配置）
 *   - 内置通过 MHD_OPTION_CONNECTION_LIMIT 实现的限流
 */

#define _GNU_SOURCE
#include "firewall-daemon.h" /* 修复 P1-5：访问 cfg.metrics_bind_address */
#include <errno.h>
#include <microhttpd.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* ============================================================================
 * 配置参数
 * ========================================================================== */
#define EXPORTER_DEFAULT_PORT 9119
#define EXPORTER_BUFFER_SIZE 16384 /* 增加到 16KB 以容纳所有指标 */
#define EXPORTER_MAX_CONNECTIONS 10
#define EXPORTER_CONNECTION_TIMEOUT 5

/* Procfs 路径 */
#define PROCFS_STATS_PATH "/proc/firewall/stats"

/* ============================================================================
 * HTTP 导出器运行标志（用于优雅关闭）
 * ========================================================================== */
static atomic_bool http_exporter_running = false;

/* 修复 1.4：线程 ID 同步机制，防止 stop_http_exporter 读到无效线程 ID */
static pthread_t exporter_thread_id;
static pthread_mutex_t thread_id_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t thread_id_cond = PTHREAD_COND_INITIALIZER;
static bool thread_id_ready = false;
/* 修复问题8：跟踪线程是否成功创建，防止对未创建的线程调用 join */
static atomic_bool exporter_thread_created = false;

/* 修复 R8-2：Basic Auth 暴力破解防护 - 失败计数器和临时锁定 */
static _Atomic(unsigned long) auth_failures = 0;
static _Atomic(time_t) last_failure_time = 0;
#define AUTH_FAILURE_THRESHOLD 10  /* 10 次失败后触发锁定 */
#define AUTH_LOCKOUT_DURATION 60   /* 锁定 60 秒 */

/* ============================================================================
 * 日志辅助函数（使用 syslog 以保持与守护进程一致）
 * ========================================================================== */
#define exporter_log_err(fmt, ...)                                             \
  syslog(LOG_ERR, "firewall[exporter]: ERROR: " fmt, ##__VA_ARGS__)
#define exporter_log_warn(fmt, ...)                                            \
  syslog(LOG_WARNING, "firewall[exporter]: WARN: " fmt, ##__VA_ARGS__)
#define exporter_log_info(fmt, ...)                                            \
  syslog(LOG_INFO, "firewall[exporter]: " fmt, ##__VA_ARGS__)

/* 安全审计日志速率限制：防止认证失败日志淹没系统日志 */
static inline void exporter_log_warn_ratelimited(const char *fmt, ...) {
  static time_t last_warn = 0;
  static int warn_count = 0;
  time_t now = time(NULL);
  va_list args;

  if (now != last_warn) {
    last_warn = now;
    warn_count = 0;
  }
  warn_count++;
  /* 每秒最多输出 1 条，超额仅在每分钟输出一次汇总 */
  if (warn_count > 1) {
    if (warn_count == 2)
      syslog(
          LOG_WARNING,
          "firewall[exporter]: WARN: suppressing repeated auth failure logs");
    return;
  }

  va_start(args, fmt);
  vsyslog(LOG_WARNING, fmt, args);
  va_end(args);
}

/* ============================================================================
 * HTTP 安全头辅助函数（修复 R8-1 + R8-4）
 * ========================================================================== */

/**
 * add_security_headers - 为 HTTP 响应添加安全头
 * @response: MHD 响应对象
 *
 * 添加以下安全头以防止常见 Web 攻击：
 * - X-Content-Type-Options: nosniff (防止 MIME 嗅探)
 * - X-Frame-Options: DENY (防止点击劫持)
 * - X-Content-Security-Policy: default-src 'none' (限制资源加载)
 * - Cache-Control: no-store (防止敏感数据缓存)
 */
static void add_security_headers(struct MHD_Response *response) {
  MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
  MHD_add_response_header(response, "X-Frame-Options", "DENY");
  MHD_add_response_header(response, "X-Content-Security-Policy",
                          "default-src 'none'");
  MHD_add_response_header(response, "Cache-Control", "no-store");
}

/* ============================================================================
 * 内核统计信息读取器
 * ========================================================================== */

/* 从 procfs 文件中读取单个整数值 */
static int read_procfs_int(const char *path, unsigned long *out) {
  FILE *fp;
  char line[256];
  unsigned long value = 0;

  fp = fopen(path, "r");
  if (!fp)
    return -1;

  if (fgets(line, sizeof(line), fp)) {
    char *colon = strchr(line, ':');
    char *endptr;
    if (colon) {
      errno = 0;
      value = strtoul(colon + 1, &endptr, 10);
      if (errno != 0 || (*endptr != '\n' && *endptr != '\0' && *endptr != ' '))
        value = 0;
    } else {
      errno = 0;
      value = strtoul(line, &endptr, 10);
      if (errno != 0 || (*endptr != '\n' && *endptr != '\0' && *endptr != ' '))
        value = 0;
    }
    *out = value;
    fclose(fp);
    return 0;
  }

  fclose(fp);
  return -1;
}

/* 根据键名从 /proc/firewall/stats 中读取特定整数值 */
static int read_procfs_stats_key(const char *key, unsigned long *value) {
  FILE *fp;
  char line[256];
  int found = 0;

  fp = fopen("/proc/firewall/stats", "r");
  if (!fp)
    return -1;

  while (fgets(line, sizeof(line), fp)) {
    char name[128];
    unsigned long val;
    if (sscanf(line, "%127s %lu", name, &val) == 2) {
      if (strcmp(name, key) == 0) {
        *value = val;
        found = 1;
        break;
      }
    }
  }
  fclose(fp);
  return found ? 0 : -1;
}

/* ============================================================================
 * 指标生成
 * ========================================================================== */

/**
 * read_kernel_stats - 读取内核统计信息
 * @stats: 输出参数，存储内核统计信息
 */
typedef struct {
  unsigned long banned;
  unsigned long total_bans;
  unsigned long total_unbans;
  unsigned long whitelist_count;
} kernel_stats_t;

static void read_kernel_stats(kernel_stats_t *stats) {
  unsigned long current_bans = 0;
  read_procfs_stats_key("current_bans", &current_bans);
  read_procfs_stats_key("total_bans", &stats->total_bans);
  read_procfs_stats_key("total_unbans", &stats->total_unbans);
  read_procfs_stats_key("current_whitelist", &stats->whitelist_count);
  stats->banned = current_bans;
}

/**
 * read_daemon_stats - 读取守护进程统计信息
 * @stats: 输出参数，存储守护进程统计信息
 */
typedef struct {
  unsigned long lines_parsed;
  unsigned long ips_extracted;
  unsigned long ips_banned;
  unsigned long failed_attempts;
  unsigned long config_reloads;
  unsigned long inotify_events;
  unsigned long log_rotations;
  unsigned long lines_skipped;
  unsigned long regex_matches;
} daemon_stats_snapshot_t;

static void read_daemon_stats(daemon_stats_snapshot_t *stats) {
  stats->lines_parsed = atomic_load(&daemon_stats.lines_parsed);
  stats->ips_extracted = atomic_load(&daemon_stats.ips_extracted);
  stats->ips_banned = atomic_load(&daemon_stats.ips_banned);
  stats->failed_attempts = atomic_load(&daemon_stats.failed_attempts);
  stats->config_reloads = atomic_load(&daemon_stats.config_reloads);
  stats->inotify_events = atomic_load(&daemon_stats.inotify_events);
  stats->log_rotations = atomic_load(&daemon_stats.log_rotations);
  stats->lines_skipped = atomic_load(&daemon_stats.lines_skipped);
  stats->regex_matches = atomic_load(&daemon_stats.regex_matches_sshd);
}

/**
 * format_kernel_metrics - 格式化内核指标到缓冲区
 * @buf: 输出缓冲区
 * @buf_size: 缓冲区大小
 * @offset: 当前写入偏移
 * @stats: 内核统计信息
 * 返回: 写入的字节数
 */
static int format_kernel_metrics(char *buf, size_t buf_size, int offset,
                                 const kernel_stats_t *stats) {
  return snprintf(
      buf + offset, buf_size - offset,
      "# HELP firewall_kernel_banned_ips_current Current number of banned IPs "
      "in kernel\n"
      "# TYPE firewall_kernel_banned_ips_current gauge\n"
      "firewall_kernel_banned_ips_current %lu\n"
      "\n"
      "# HELP firewall_kernel_total_bans_total Total number of ban operations "
      "in kernel\n"
      "# TYPE firewall_kernel_total_bans_total counter\n"
      "firewall_kernel_total_bans_total %lu\n"
      "\n"
      "# HELP firewall_kernel_total_unbans_total Total number of unban "
      "operations in kernel\n"
      "# TYPE firewall_kernel_total_unbans_total counter\n"
      "firewall_kernel_total_unbans_total %lu\n"
      "\n"
      "# HELP firewall_kernel_whitelist_count Current number of whitelisted "
      "IPs\n"
      "# TYPE firewall_kernel_whitelist_count gauge\n"
      "firewall_kernel_whitelist_count %lu\n"
      "\n",
      stats->banned, stats->total_bans, stats->total_unbans,
      stats->whitelist_count);
}

/**
 * format_daemon_counter_metrics - 格式化守护进程计数器指标
 * @buf: 输出缓冲区
 * @buf_size: 缓冲区大小
 * @offset: 当前写入偏移
 * @stats: 守护进程统计信息
 * 返回: 写入的字节数
 */
static int format_daemon_counter_metrics(char *buf, size_t buf_size, int offset,
                                         const daemon_stats_snapshot_t *stats) {
  return snprintf(
      buf + offset, buf_size - offset,
      "# HELP firewall_daemon_lines_parsed_total Total log lines parsed by "
      "daemon\n"
      "# TYPE firewall_daemon_lines_parsed_total counter\n"
      "firewall_daemon_lines_parsed_total %lu\n"
      "\n"
      "# HELP firewall_daemon_ips_extracted_total Total IP addresses extracted "
      "from logs\n"
      "# TYPE firewall_daemon_ips_extracted_total counter\n"
      "firewall_daemon_ips_extracted_total %lu\n"
      "\n"
      "# HELP firewall_daemon_ips_banned_total Total IP addresses banned by "
      "daemon\n"
      "# TYPE firewall_daemon_ips_banned_total counter\n"
      "firewall_daemon_ips_banned_total %lu\n"
      "\n"
      "# HELP firewall_daemon_failed_attempts_total Total failed login "
      "attempts detected\n"
      "# TYPE firewall_daemon_failed_attempts_total counter\n"
      "firewall_daemon_failed_attempts_total %lu\n"
      "\n"
      "# HELP firewall_daemon_config_reloads_total Total configuration "
      "reloads\n"
      "# TYPE firewall_daemon_config_reloads_total counter\n"
      "firewall_daemon_config_reloads_total %lu\n"
      "\n"
      "# HELP firewall_daemon_inotify_events_total Total inotify events "
      "received\n"
      "# TYPE firewall_daemon_inotify_events_total counter\n"
      "firewall_daemon_inotify_events_total %lu\n"
      "\n"
      "# HELP firewall_daemon_log_rotations_total Total log rotation events "
      "detected\n"
      "# TYPE firewall_daemon_log_rotations_total counter\n"
      "firewall_daemon_log_rotations_total %lu\n"
      "\n"
      "# HELP firewall_daemon_lines_skipped_total Total log lines skipped (too "
      "long or invalid)\n"
      "# TYPE firewall_daemon_lines_skipped_total counter\n"
      "firewall_daemon_lines_skipped_total %lu\n"
      "\n"
      "# HELP firewall_daemon_regex_matches_total Total regex pattern matches "
      "across all jails\n"
      "# TYPE firewall_daemon_regex_matches_total counter\n"
      "firewall_daemon_regex_matches_total %lu\n"
      "\n",
      stats->lines_parsed, stats->ips_extracted, stats->ips_banned,
      stats->failed_attempts, stats->config_reloads, stats->inotify_events,
      stats->log_rotations, stats->lines_skipped, stats->regex_matches);
}

/**
 * format_daemon_uptime_metric - 格式化守护进程运行时间指标
 * @buf: 输出缓冲区
 * @buf_size: 缓冲区大小
 * @offset: 当前写入偏移
 * @uptime: 运行时间（秒）
 * 返回: 写入的字节数
 */
static int format_daemon_uptime_metric(char *buf, size_t buf_size, int offset,
                                       time_t uptime) {
  return snprintf(
      buf + offset, buf_size - offset,
      "# HELP firewall_daemon_uptime_seconds Daemon uptime in seconds\n"
      "# TYPE firewall_daemon_uptime_seconds gauge\n"
      "firewall_daemon_uptime_seconds %ld\n"
      "\n",
      (long)uptime);
}

/**
 * format_daemon_metrics - 格式化守护进程指标到缓冲区
 * @buf: 输出缓冲区
 * @buf_size: 缓冲区大小
 * @offset: 当前写入偏移
 * @stats: 守护进程统计信息
 * @uptime: 运行时间（秒）
 * 返回: 写入的字节数
 */
static int format_daemon_metrics(char *buf, size_t buf_size, int offset,
                                 const daemon_stats_snapshot_t *stats,
                                 time_t uptime) {
  int written;

  written = format_daemon_counter_metrics(buf, buf_size, offset, stats);
  if (written < 0 || (size_t)written >= buf_size - offset)
    return -1;
  offset += written;

  return format_daemon_uptime_metric(buf, buf_size, offset, uptime);
}

/* 生成 Prometheus 指标文本 */
static int generate_metrics(char *buf, size_t buf_size) {
  kernel_stats_t k_stats;
  daemon_stats_snapshot_t d_stats;
  time_t uptime;
  int offset = 0;
  int written;

  /* 读取内核统计信息 */
  read_kernel_stats(&k_stats);

  /* 读取守护进程统计信息 */
  read_daemon_stats(&d_stats);

  uptime = time(NULL) - daemon_stats.start_time;

  /* 格式化内核指标 */
  written = format_kernel_metrics(buf, buf_size, offset, &k_stats);
  if (written < 0 || (size_t)written >= buf_size - offset)
    return -1;
  offset += written;

  /* 格式化守护进程指标 */
  written = format_daemon_metrics(buf, buf_size, offset, &d_stats, uptime);
  if (written < 0 || (size_t)written >= buf_size - offset)
    return -1;
  offset += written;

  return offset;
}

/* ============================================================================
 * libmicrohttpd 请求处理器
 * ========================================================================== */

/**
 * base64_decode_simple - 简单的 Base64 解码（用于 Basic Auth）
 * @input: Base64 编码字符串
 * @output: 解码输出缓冲区
 * @output_size: 输出缓冲区大小
 * 返回: 解码后的字节数，失败返回 -1
 */
static int base64_decode_simple(const char *input, char *output,
                                size_t output_size) {
  /* 安全考虑：全部初始化为 0xFF（无效值），防止未初始化条目默认为 0
   * 与 'A' 的值相同，导致攻击者可通过特殊字符伪造 Base64 输入 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"
  static const unsigned char decode_table[256] = {
      [0 ... 255] = 0xFF, ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,
      ['E'] = 4,          ['F'] = 5,  ['G'] = 6,  ['H'] = 7,  ['I'] = 8,
      ['J'] = 9,          ['K'] = 10, ['L'] = 11, ['M'] = 12, ['N'] = 13,
      ['O'] = 14,         ['P'] = 15, ['Q'] = 16, ['R'] = 17, ['S'] = 18,
      ['T'] = 19,         ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
      ['Y'] = 24,         ['Z'] = 25, ['a'] = 26, ['b'] = 27, ['c'] = 28,
      ['d'] = 29,         ['e'] = 30, ['f'] = 31, ['g'] = 32, ['h'] = 33,
      ['i'] = 34,         ['j'] = 35, ['k'] = 36, ['l'] = 37, ['m'] = 38,
      ['n'] = 39,         ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
      ['s'] = 44,         ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48,
      ['x'] = 49,         ['y'] = 50, ['z'] = 51, ['0'] = 52, ['1'] = 53,
      ['2'] = 54,         ['3'] = 55, ['4'] = 56, ['5'] = 57, ['6'] = 58,
      ['7'] = 59,         ['8'] = 60, ['9'] = 61, ['+'] = 62, ['/'] = 63,
  };
#pragma GCC diagnostic pop
  size_t in_len = strlen(input);
  size_t out_idx = 0;

  if (in_len % 4 != 0)
    return -1;

  for (size_t i = 0; i < in_len && out_idx < output_size; i += 4) {
    /* 防御性检查：确保不越界读取 */
    if (i + 3 >= in_len)
      return -1;

    /* 安全考虑：检查字符是否为合法 Base64 字符（非 0xFF）
     * 防止控制字符、高 ASCII 等非法字符被当作有效输入处理 */
    unsigned char c0 = (unsigned char)input[i];
    unsigned char c1 = (unsigned char)input[i + 1];
    unsigned char c2 = (unsigned char)input[i + 2];
    unsigned char c3 = (unsigned char)input[i + 3];

    /* RFC 4648: '=' 填充只能出现在最后两个位置 */
    if (c0 == '=' || c1 == '=')
      return -1;
    if (c2 == '=' || c3 == '=') {
      /* '=' 仅允许出现在最后两个位置，此处简化处理：
       * 仅跳过 '=' 的查表，但仍需确保非 '=' 字符合法 */
    }
    if (input[i] != '=' && decode_table[c0] == 0xFF)
      return -1;
    if (input[i + 1] != '=' && decode_table[c1] == 0xFF)
      return -1;
    if (input[i + 2] != '=' && decode_table[c2] == 0xFF)
      return -1;
    if (input[i + 3] != '=' && decode_table[c3] == 0xFF)
      return -1;

    int b0 = (input[i] == '=') ? 0 : decode_table[c0];
    int b1 = (input[i + 1] == '=') ? 0 : decode_table[c1];
    int b2 = (input[i + 2] == '=') ? 0 : decode_table[c2];
    int b3 = (input[i + 3] == '=') ? 0 : decode_table[c3];

    output[out_idx++] = (unsigned char)((b0 << 2) | (b1 >> 4));
    /* 修复 W2-7：使用 out_idx + 1 < output_size 确保 null 终止符有空间 */
    if (input[i + 2] != '=' && out_idx + 1 < output_size)
      output[out_idx++] = (unsigned char)((b1 << 4) | (b2 >> 2));
    if (input[i + 3] != '=' && out_idx + 1 < output_size)
      output[out_idx++] = (unsigned char)((b2 << 6) | b3);
  }

  return (int)out_idx;
}

/**
 * constant_time_compare - 恒定时间字符串比较（防时序攻击）
 * @a: 第一个缓冲区
 * @b: 第二个缓冲区
 * @len: 比较长度（以较短者为准）
 * 返回: 0 表示相等，非 0 表示不等
 *
 * 安全考虑：使用异或累加方式比较，确保无论何时不匹配都执行
 * 相同次数的操作，防止攻击者通过响应时间差异逐位猜测密码。
 */
static int constant_time_compare(const void *a, const void *b, size_t len) {
  const unsigned char *pa = (const unsigned char *)a;
  const unsigned char *pb = (const unsigned char *)b;
  volatile unsigned char result = 0;

  for (size_t i = 0; i < len; i++) {
    result |= pa[i] ^ pb[i];
  }

  /* 编译器屏障：防止编译器优化掉 volatile 写入或重排序循环 */
  __asm__ volatile("" ::: "memory");

  return (int)result;
}

/**
 * check_basic_auth - 验证 HTTP Basic Auth 凭据
 * @auth_header: Authorization 头值（如 "Basic dXNlcjpwYXNz"）
 * 返回: 1 表示认证成功，0 表示失败，-1 表示未配置认证
 *
 * 注意：当未配置用户名/密码时，跳过认证（向后兼容）。
 */
static int check_basic_auth_header(const char *auth_header) {
  char cfg_user[64] = {0};
  char cfg_pass[128] = {0};

  pthread_rwlock_rdlock(&config_rwlock);
  if (cfg.metrics_username && strlen(cfg.metrics_username) > 0) {
    strncpy(cfg_user, cfg.metrics_username, sizeof(cfg_user) - 1);
    cfg_user[sizeof(cfg_user) - 1] = '\0';
  }
  if (cfg.metrics_password && strlen(cfg.metrics_password) > 0) {
    strncpy(cfg_pass, cfg.metrics_password, sizeof(cfg_pass) - 1);
    cfg_pass[sizeof(cfg_pass) - 1] = '\0';
  }
  pthread_rwlock_unlock(&config_rwlock);

  /* 未配置认证时跳过检查（向后兼容） */
  if (strlen(cfg_user) == 0 || strlen(cfg_pass) == 0) {
    return -1;
  }

  /* 修复 R8-2：暴力破解防护 - 检查是否处于锁定状态 */
  time_t now = time(NULL);
  time_t last = atomic_load(&last_failure_time);
  if (atomic_load(&auth_failures) >= AUTH_FAILURE_THRESHOLD &&
      (now - last) < AUTH_LOCKOUT_DURATION) {
    exporter_log_warn_ratelimited(
        "Auth temporarily locked due to too many failures (%lu failures in "
        "%ld seconds)",
        atomic_load(&auth_failures), (long)(now - last));
    return 0;
  }

  if (!auth_header || strncmp(auth_header, "Basic ", 6) != 0) {
    /* 修复 R8-2：记录认证失败 */
    atomic_fetch_add(&auth_failures, 1);
    atomic_store(&last_failure_time, time(NULL));
    return 0;
  }

  /* 解码 Base64 凭据 */
  /* 安全考虑：缓冲区增大至 256 字节，与输入缓冲区一致，
   * 防止 Base64 解码后长度接近边界时 null 终止符写入越界 */
  char decoded[256];
  int decoded_len =
      base64_decode_simple(auth_header + 6, decoded, sizeof(decoded) - 1);
  if (decoded_len <= 0) {
    /* 修复 R8-2：记录 Base64 解码失败 */
    atomic_fetch_add(&auth_failures, 1);
    atomic_store(&last_failure_time, time(NULL));
    return 0;
  }
  /* 安全考虑：边界检查，防止 decoded_len 等于缓冲区大小时越界写入 */
  if (decoded_len >= (int)sizeof(decoded)) {
    decoded_len = (int)sizeof(decoded) - 1;
  }
  decoded[decoded_len] = '\0';

  /* 查找 user:pass 分隔符 */
  char *colon = strchr(decoded, ':');
  if (!colon) {
    /* 修复 R8-2：记录格式错误失败 */
    atomic_fetch_add(&auth_failures, 1);
    atomic_store(&last_failure_time, time(NULL));
    return 0;
  }
  *colon = '\0';
  char *auth_user = decoded;
  char *auth_pass = colon + 1;

  /* 安全考虑：使用恒定时间比较替代 strcmp，防止时序攻击 */
  size_t user_len = strlen(cfg_user);
  size_t pass_len = strlen(cfg_pass);
  size_t auth_user_len = strlen(auth_user);
  size_t auth_pass_len = strlen(auth_pass);

  /* 长度不同直接判定失败（长度比较不泄露密码内容） */
  int result = (user_len != auth_user_len || pass_len != auth_pass_len) ? 0
               : (constant_time_compare(cfg_user, auth_user, user_len) == 0 &&
                  constant_time_compare(cfg_pass, auth_pass, pass_len) == 0)
                   ? 1
                   : 0;

  /* 安全考虑：认证完成后立即清零敏感缓冲区，防止内存残留 */
  memset(decoded, 0, sizeof(decoded));
  memset(cfg_pass, 0, sizeof(cfg_pass));

  /* 修复 R8-2：认证成功时重置失败计数器，失败时递增 */
  if (result == 1) {
    atomic_store(&auth_failures, 0);
  } else {
    atomic_fetch_add(&auth_failures, 1);
    atomic_store(&last_failure_time, time(NULL));
  }

  return result;
}

/**
 * send_unauthorized_response - 发送 401 Unauthorized 响应
 * @connection: MHD 连接
 * 返回: MHD_Result
 */
static enum MHD_Result
send_unauthorized_response(struct MHD_Connection *connection) {
  struct MHD_Response *response;
  const char *body = "401 Unauthorized\r\n";
  int ret;

  response = MHD_create_response_from_buffer(strlen(body), (void *)body,
                                             MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;
  MHD_add_response_header(response, "WWW-Authenticate",
                          "Basic realm=\"firewall-metrics\"");
  /* 修复 R8-4：401 响应同样需要安全头 */
  add_security_headers(response);
  ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, response);
  MHD_destroy_response(response);
  return ret == MHD_YES ? MHD_YES : MHD_NO;
}

/**
 * send_error_response - 发送错误响应
 * @connection: MHD 连接
 * @status_code: HTTP 状态码
 * @body: 响应体
 * 返回: MHD_Result
 */
static enum MHD_Result send_error_response(struct MHD_Connection *connection,
                                           int status_code, const char *body) {
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer(strlen(body), (void *)body,
                                             MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;
  /* 修复 R8-4：错误响应同样需要安全头 */
  add_security_headers(response);
  ret = MHD_queue_response(connection, status_code, response);
  MHD_destroy_response(response);
  return ret == MHD_YES ? MHD_YES : MHD_NO;
}

/**
 * handle_metrics_request - 处理 /metrics 请求
 * @connection: MHD 连接
 * 返回: MHD_Result
 */
static enum MHD_Result
handle_metrics_request(struct MHD_Connection *connection) {
  char metrics_buf[EXPORTER_BUFFER_SIZE];
  struct MHD_Response *response;
  int len;
  int ret;

  len = generate_metrics(metrics_buf, sizeof(metrics_buf));
  if (len < 0 || (size_t)len >= sizeof(metrics_buf)) {
    exporter_log_err("Metrics buffer overflow");
    return send_error_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR,
                               "500 Internal Server Error\r\n");
  }

  response =
      MHD_create_response_from_buffer(len, metrics_buf, MHD_RESPMEM_MUST_COPY);
  if (!response)
    return MHD_NO;
  MHD_add_response_header(response, "Content-Type",
                          "text/plain; version=0.0.4; charset=utf-8");
  /* 修复 R8-1：添加安全头防止 MIME 嗅探、点击劫持等攻击 */
  add_security_headers(response);
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);
  return ret == MHD_YES ? MHD_YES : MHD_NO;
}

/**
 * handle_health_request - 处理 /health 或 /healthz 请求
 * @connection: MHD 连接
 * 返回: MHD_Result
 */
static enum MHD_Result
handle_health_request(struct MHD_Connection *connection) {
  const char *health_body = "{\"status\":\"ok\"}\n";
  struct MHD_Response *response;
  int ret;

  response = MHD_create_response_from_buffer(
      strlen(health_body), (void *)health_body, MHD_RESPMEM_PERSISTENT);
  if (!response)
    return MHD_NO;
  MHD_add_response_header(response, "Content-Type", "application/json");
  /* 修复 R8-4：/health 端点同样需要安全头 */
  add_security_headers(response);
  ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
  MHD_destroy_response(response);
  return ret == MHD_YES ? MHD_YES : MHD_NO;
}

static enum MHD_Result
answer_to_connection(void *cls, struct MHD_Connection *connection,
                     const char *url, const char *method, const char *version,
                     const char *upload_data, size_t *upload_data_size,
                     void **con_cls) {
  const char *auth_header;

  /* 忽略未使用参数的警告 */
  (void)cls;
  (void)version;
  (void)upload_data;
  (void)upload_data_size;
  (void)con_cls;

  /* 仅接受 GET 请求 */
  if (strcmp(method, "GET") != 0) {
    return send_error_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED,
                               "405 Method Not Allowed\r\n");
  }

  /* Basic Auth 认证检查（/health 端点跳过认证） */
  if (strcmp(url, "/health") != 0 && strcmp(url, "/healthz") != 0) {
    auth_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
                                              "Authorization");
    int auth_result = check_basic_auth_header(auth_header);
    if (auth_result == 0) {
      /* 安全考虑：使用 ratelimited 日志防止攻击者通过频繁请求淹没系统日志 */
      exporter_log_warn_ratelimited("Unauthorized access attempt to %s", url);
      return send_unauthorized_response(connection);
    }
    /* auth_result == -1 表示未配置认证，跳过 */
  }

  /* 路由请求 */
  if (strcmp(url, "/metrics") == 0) {
    return handle_metrics_request(connection);
  } else if (strcmp(url, "/health") == 0 || strcmp(url, "/healthz") == 0) {
    return handle_health_request(connection);
  } else {
    return send_error_response(connection, MHD_HTTP_NOT_FOUND,
                               "404 Not Found\r\n");
  }
}

/* ============================================================================
 * HTTP 服务器主循环
 * ========================================================================== */

/**
 * setup_bind_address - 设置绑定地址并初始化sockaddr_in结构
 * @bind_addr: 输出参数，sockaddr_in结构
 * @bind_addr_buf: 本地缓冲区，用于安全复制配置字符串
 * @listen_port: 监听端口
 * 返回: 实际使用的绑定地址字符串
 */
static const char *setup_bind_address(struct sockaddr_in *bind_addr,
                                      char *bind_addr_buf, int listen_port) {
  const char *bind_address = "127.0.0.1"; /* 默认绑定 localhost */

  /* 从全局配置读取绑定地址 */
  pthread_rwlock_rdlock(&config_rwlock);
  if (cfg.metrics_bind_address && strlen(cfg.metrics_bind_address) > 0) {
    /* 持锁期间复制字符串到本地缓冲区，防止配置重载时 Use-After-Free */
    size_t addr_len = strlen(cfg.metrics_bind_address);
    if (addr_len < sizeof(bind_addr_buf)) {
      memcpy(bind_addr_buf, cfg.metrics_bind_address, addr_len);
      bind_addr_buf[addr_len] = '\0';
      bind_address = bind_addr_buf;
    }
  }
  pthread_rwlock_unlock(&config_rwlock);

  /* 初始化 sockaddr_in 结构 */
  memset(bind_addr, 0, sizeof(*bind_addr));
  bind_addr->sin_family = AF_INET;
  bind_addr->sin_port = htons((uint16_t)listen_port);
  if (inet_pton(AF_INET, bind_address, &bind_addr->sin_addr) != 1) {
    exporter_log_err("Invalid bind address: %s, falling back to 127.0.0.1",
                     bind_address);
    inet_pton(AF_INET, "127.0.0.1", &bind_addr->sin_addr);
  }

  return bind_address;
}

/**
 * start_mhd_daemon - 启动libmicrohttpd守护进程
 * @listen_port: 监听端口
 * @bind_addr: 绑定地址结构
 * 返回: MHD_Daemon指针，失败返回NULL
 */
static struct MHD_Daemon *
start_mhd_daemon(int listen_port, const struct sockaddr_in *bind_addr) {
  return MHD_start_daemon(
      MHD_USE_SELECT_INTERNALLY | MHD_USE_ERROR_LOG, (uint16_t)listen_port,
      NULL, NULL, &answer_to_connection, NULL, MHD_OPTION_CONNECTION_LIMIT,
      EXPORTER_MAX_CONNECTIONS, MHD_OPTION_CONNECTION_TIMEOUT,
      EXPORTER_CONNECTION_TIMEOUT, MHD_OPTION_SOCK_ADDR, bind_addr,
      MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL, MHD_OPTION_END);
}

/**
 * start_http_exporter - 启动 Prometheus HTTP 导出器线程
 * @port: 监听的端口号（以 void* 传递以保持 pthread 兼容性）
 *
 * 该函数在独立的线程中运行，使用 libmicrohttpd 提供轻量级 HTTP 服务器
 * 用于 Prometheus 指标收集。
 *
 * 返回值：NULL（pthread 约定）
 */
void *start_http_exporter(void *port) {
  int listen_port = port ? (int)(long)port : EXPORTER_DEFAULT_PORT;
  struct MHD_Daemon *daemon;
  char bind_addr_buf[INET_ADDRSTRLEN];
  struct sockaddr_in bind_addr;
  const char *bind_address;

  /* 设置绑定地址 */
  bind_address = setup_bind_address(&bind_addr, bind_addr_buf, listen_port);

  /* 修复 1.4：使用条件变量同步线程 ID */
  pthread_mutex_lock(&thread_id_mutex);
  exporter_thread_id = pthread_self();
  thread_id_ready = true;
  pthread_cond_signal(&thread_id_cond);
  pthread_mutex_unlock(&thread_id_mutex);

  /* 修复问题8：标记线程已成功创建 */
  atomic_store(&exporter_thread_created, true);

  /* 标记导出器为运行状态 */
  atomic_store(&http_exporter_running, true);

  /* 启动 MHD 守护进程 */
  daemon = start_mhd_daemon(listen_port, &bind_addr);

  if (daemon == NULL) {
    exporter_log_err("Failed to start HTTP daemon on %s:%d: %s", bind_address,
                     listen_port, strerror(errno));
    exporter_log_info("Prometheus exporter disabled (port may be in use)");
    atomic_store(&http_exporter_running, false);
    return NULL;
  }

  exporter_log_info("Prometheus exporter listening on %s:%d (libmicrohttpd)",
                    bind_address, listen_port);

  /* 阻塞直到线程收到停止信号 */
  while (atomic_load(&http_exporter_running)) {
    sleep(1);
  }

  MHD_stop_daemon(daemon);
  exporter_log_info("Prometheus exporter stopped");
  return NULL;
}

/**
 * stop_http_exporter - 向 HTTP 导出器线程发送停止信号
 *
 * 从 cleanup() 调用以优雅关闭导出器线程。
 * 修复 1.4：等待线程 ID 就绪后调用 pthread_join 确保线程完全结束。
 * 修复问题8：仅在成功创建后才调用 pthread_join，防止线程泄漏。
 */
void stop_http_exporter(void) {
  if (atomic_load(&http_exporter_running)) {
    atomic_store(&http_exporter_running, false);

    /* 修复问题8：仅在成功创建后才等待和 join 线程 */
    if (atomic_load(&exporter_thread_created)) {
      /* 等待线程 ID 就绪，防止线程还未初始化就 join */
      pthread_mutex_lock(&thread_id_mutex);
      while (!thread_id_ready) {
        pthread_cond_wait(&thread_id_cond, &thread_id_mutex);
      }
      pthread_mutex_unlock(&thread_id_mutex);

      /* 安全 join：检查线程是否仍然有效 */
      int join_err = pthread_join(exporter_thread_id, NULL);
      if (join_err != 0 && join_err != ESRCH) {
        /* ESRCH 表示线程已退出，其他错误记录日志 */
        exporter_log_warn("pthread_join failed: %s", strerror(join_err));
      }
    }
  }
}
