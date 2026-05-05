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
 *   - 默认监听 0.0.0.0:9119
 *   - 内置通过 MHD_OPTION_CONNECTION_LIMIT 实现的限流
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <syslog.h>
#include <microhttpd.h>
#include "firewall-daemon.h"  /* 修复 P1-5：访问 cfg.metrics_bind_address */

/* ============================================================================
 * 配置参数
 * ========================================================================== */
#define EXPORTER_DEFAULT_PORT 9119
#define EXPORTER_BUFFER_SIZE  16384  /* 增加到 16KB 以容纳所有指标 */
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

/* ============================================================================
 * 日志辅助函数（使用 syslog 以保持与守护进程一致）
 * ========================================================================== */
#define exporter_log_err(fmt, ...) \
    syslog(LOG_ERR, "firewall[exporter]: ERROR: " fmt, ##__VA_ARGS__)
#define exporter_log_warn(fmt, ...) \
    syslog(LOG_WARNING, "firewall[exporter]: WARN: " fmt, ##__VA_ARGS__)
#define exporter_log_info(fmt, ...) \
    syslog(LOG_INFO, "firewall[exporter]: " fmt, ##__VA_ARGS__)

/* ============================================================================
 * 内核统计信息读取器
 * ========================================================================== */

/* 从 procfs 文件中读取单个整数值 */
static int read_procfs_int(const char *path, unsigned long *out)
{
    FILE *fp;
    char line[256];
    unsigned long value = 0;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    if (fgets(line, sizeof(line), fp)) {
        char *colon = strchr(line, ':');
        if (colon) {
            value = strtoul(colon + 1, NULL, 10);
        } else {
            value = strtoul(line, NULL, 10);
        }
        *out = value;
        fclose(fp);
        return 0;
    }

    fclose(fp);
    return -1;
}

/* 根据键名从 /proc/firewall/stats 中读取特定整数值 */
static int read_procfs_stats_key(const char *key, unsigned long *value)
{
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

/* 生成 Prometheus 指标文本 */
static int generate_metrics(char *buf, size_t buf_size)
{
    unsigned long kernel_banned = 0;
    unsigned long kernel_total_bans = 0;
    unsigned long kernel_total_unbans = 0;
    unsigned long kernel_whitelist_count = 0;
    unsigned long kernel_current_bans = 0;
    time_t uptime;

    /* 从 procfs 读取内核统计信息 */
    read_procfs_stats_key("current_bans", &kernel_current_bans);
    read_procfs_stats_key("total_bans", &kernel_total_bans);
    read_procfs_stats_key("total_unbans", &kernel_total_unbans);
    read_procfs_stats_key("current_whitelist", &kernel_whitelist_count);
    kernel_banned = kernel_current_bans;

    /* 读取守护进程统计信息 */
    unsigned long d_lines_parsed = atomic_load(&daemon_stats.lines_parsed);
    unsigned long d_ips_extracted = atomic_load(&daemon_stats.ips_extracted);
    unsigned long d_ips_banned = atomic_load(&daemon_stats.ips_banned);
    unsigned long d_failed_attempts = atomic_load(&daemon_stats.failed_attempts);
    unsigned long d_config_reloads = atomic_load(&daemon_stats.config_reloads);
    unsigned long d_inotify_events = atomic_load(&daemon_stats.inotify_events);
    unsigned long d_log_rotations = atomic_load(&daemon_stats.log_rotations);
    unsigned long d_lines_skipped = atomic_load(&daemon_stats.lines_skipped);
    unsigned long d_regex_matches = atomic_load(&daemon_stats.regex_matches_sshd);

    uptime = time(NULL) - daemon_stats.start_time;

    return snprintf(buf, buf_size,
        "# HELP firewall_kernel_banned_ips_current Current number of banned IPs in kernel\n"
        "# TYPE firewall_kernel_banned_ips_current gauge\n"
        "firewall_kernel_banned_ips_current %lu\n"
        "\n"
        "# HELP firewall_kernel_total_bans_total Total number of ban operations in kernel\n"
        "# TYPE firewall_kernel_total_bans_total counter\n"
        "firewall_kernel_total_bans_total %lu\n"
        "\n"
        "# HELP firewall_kernel_total_unbans_total Total number of unban operations in kernel\n"
        "# TYPE firewall_kernel_total_unbans_total counter\n"
        "firewall_kernel_total_unbans_total %lu\n"
        "\n"
        "# HELP firewall_kernel_whitelist_count Current number of whitelisted IPs\n"
        "# TYPE firewall_kernel_whitelist_count gauge\n"
        "firewall_kernel_whitelist_count %lu\n"
        "\n"
        "# HELP firewall_daemon_lines_parsed_total Total log lines parsed by daemon\n"
        "# TYPE firewall_daemon_lines_parsed_total counter\n"
        "firewall_daemon_lines_parsed_total %lu\n"
        "\n"
        "# HELP firewall_daemon_ips_extracted_total Total IP addresses extracted from logs\n"
        "# TYPE firewall_daemon_ips_extracted_total counter\n"
        "firewall_daemon_ips_extracted_total %lu\n"
        "\n"
        "# HELP firewall_daemon_ips_banned_total Total IP addresses banned by daemon\n"
        "# TYPE firewall_daemon_ips_banned_total counter\n"
        "firewall_daemon_ips_banned_total %lu\n"
        "\n"
        "# HELP firewall_daemon_failed_attempts_total Total failed login attempts detected\n"
        "# TYPE firewall_daemon_failed_attempts_total counter\n"
        "firewall_daemon_failed_attempts_total %lu\n"
        "\n"
        "# HELP firewall_daemon_config_reloads_total Total configuration reloads\n"
        "# TYPE firewall_daemon_config_reloads_total counter\n"
        "firewall_daemon_config_reloads_total %lu\n"
        "\n"
        "# HELP firewall_daemon_inotify_events_total Total inotify events received\n"
        "# TYPE firewall_daemon_inotify_events_total counter\n"
        "firewall_daemon_inotify_events_total %lu\n"
        "\n"
        "# HELP firewall_daemon_log_rotations_total Total log rotation events detected\n"
        "# TYPE firewall_daemon_log_rotations_total counter\n"
        "firewall_daemon_log_rotations_total %lu\n"
        "\n"
        "# HELP firewall_daemon_lines_skipped_total Total log lines skipped (too long or invalid)\n"
        "# TYPE firewall_daemon_lines_skipped_total counter\n"
        "firewall_daemon_lines_skipped_total %lu\n"
        "\n"
        "# HELP firewall_daemon_regex_matches_total Total regex pattern matches across all jails\n"
        "# TYPE firewall_daemon_regex_matches_total counter\n"
        "firewall_daemon_regex_matches_total %lu\n"
        "\n"
        "# HELP firewall_daemon_uptime_seconds Daemon uptime in seconds\n"
        "# TYPE firewall_daemon_uptime_seconds gauge\n"
        "firewall_daemon_uptime_seconds %ld\n"
        "\n",
        kernel_banned,
        kernel_total_bans,
        kernel_total_unbans,
        kernel_whitelist_count,
        d_lines_parsed,
        d_ips_extracted,
        d_ips_banned,
        d_failed_attempts,
        d_config_reloads,
        d_inotify_events,
        d_log_rotations,
        d_lines_skipped,
        d_regex_matches,
        (long)uptime
    );
}

/* ============================================================================
 * libmicrohttpd 请求处理器
 * ========================================================================== */

static enum MHD_Result answer_to_connection(void *cls, struct MHD_Connection *connection,
                                            const char *url, const char *method,
                                            const char *version, const char *upload_data,
                                            size_t *upload_data_size, void **con_cls)
{
    const char *page;
    struct MHD_Response *response;
    int ret;
    char metrics_buf[EXPORTER_BUFFER_SIZE];
    int len;

    /* 忽略未使用参数的警告 */
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    (void)con_cls;

    /* 仅接受 GET 请求 */
    if (strcmp(method, "GET") != 0) {
        page = "405 Method Not Allowed\r\n";
        response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
        if (!response)
            return MHD_NO;
        ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret == MHD_YES ? MHD_YES : MHD_NO;
    }

    /* 路由请求 */
    if (strcmp(url, "/metrics") == 0) {
        len = generate_metrics(metrics_buf, sizeof(metrics_buf));
        if (len < 0 || (size_t)len >= sizeof(metrics_buf)) {
            exporter_log_err("Metrics buffer overflow");
            page = "500 Internal Server Error\r\n";
            response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
            if (!response)
                return MHD_NO;
            ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, response);
            MHD_destroy_response(response);
            return ret == MHD_YES ? MHD_YES : MHD_NO;
        }

        response = MHD_create_response_from_buffer(len, metrics_buf, MHD_RESPMEM_MUST_COPY);
        if (!response)
            return MHD_NO;
        MHD_add_response_header(response, "Content-Type", "text/plain; version=0.0.4; charset=utf-8");
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret == MHD_YES ? MHD_YES : MHD_NO;

    } else if (strcmp(url, "/health") == 0 || strcmp(url, "/healthz") == 0) {
        const char *health_body = "{\"status\":\"ok\"}\n";
        response = MHD_create_response_from_buffer(strlen(health_body), (void *)health_body, MHD_RESPMEM_PERSISTENT);
        if (!response)
            return MHD_NO;
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return ret == MHD_YES ? MHD_YES : MHD_NO;

    } else {
        page = "404 Not Found\r\n";
        response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
        if (!response)
            return MHD_NO;
        ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        MHD_destroy_response(response);
        return ret == MHD_YES ? MHD_YES : MHD_NO;
    }
}

/* ============================================================================
 * HTTP 服务器主循环
 * ========================================================================== */

/**
 * start_http_exporter - 启动 Prometheus HTTP 导出器线程
 * @port: 监听的端口号（以 void* 传递以保持 pthread 兼容性）
 *
 * 该函数在独立的线程中运行，使用 libmicrohttpd 提供轻量级 HTTP 服务器
 * 用于 Prometheus 指标收集。
 *
 * 返回值：NULL（pthread 约定）
 */
void *start_http_exporter(void *port)
{
    int listen_port = port ? (int)(long)port : EXPORTER_DEFAULT_PORT;
    struct MHD_Daemon *daemon;
    const char *bind_address = "127.0.0.1";  /* 修复 P1-5：默认绑定 localhost */
    struct sockaddr_in bind_addr;

    /* 修复 P1-5：从全局配置读取绑定地址 */
    pthread_rwlock_rdlock(&config_rwlock);
    if (cfg.metrics_bind_address && strlen(cfg.metrics_bind_address) > 0) {
        bind_address = cfg.metrics_bind_address;
    }
    pthread_rwlock_unlock(&config_rwlock);

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

    /* 修复 P1-5：使用 MHD_OPTION_SOCK_ADDR 绑定到指定地址 */
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons((uint16_t)listen_port);
    if (inet_pton(AF_INET, bind_address, &bind_addr.sin_addr) != 1) {
        exporter_log_err("Invalid bind address: %s, falling back to 127.0.0.1", bind_address);
        inet_pton(AF_INET, "127.0.0.1", &bind_addr.sin_addr);
    }

    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_ERROR_LOG,
                              (uint16_t)listen_port,
                              NULL, NULL,
                              &answer_to_connection, NULL,
                              MHD_OPTION_CONNECTION_LIMIT, EXPORTER_MAX_CONNECTIONS,
                              MHD_OPTION_CONNECTION_TIMEOUT, EXPORTER_CONNECTION_TIMEOUT,
                              MHD_OPTION_SOCK_ADDR, &bind_addr,
                              MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL,
                              MHD_OPTION_END);

    if (daemon == NULL) {
        exporter_log_err("Failed to start HTTP daemon on %s:%d: %s",
                         bind_address, listen_port, strerror(errno));
        exporter_log_info("Prometheus exporter disabled (port may be in use)");
        atomic_store(&http_exporter_running, false);
        return NULL;
    }

    exporter_log_info("Prometheus exporter listening on %s:%d (libmicrohttpd)", bind_address, listen_port);

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
void stop_http_exporter(void)
{
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
