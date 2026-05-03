/*
 * http-exporter.c - Prometheus HTTP exporter for firewall daemon
 *
 * Uses libmicrohttpd for RFC-compliant HTTP server implementation.
 * Provides /metrics and /health endpoints for Prometheus monitoring.
 * Runs in a separate pthread.
 *
 * Features:
 *   - libmicrohttpd-based HTTP server (RFC compliant)
 *   - Prometheus text format output
 *   - Reads kernel stats from /proc/firewall/stats
 *   - Reads daemon stats from shared daemon_stats structure
 *   - Listens on 0.0.0.0:9119 by default
 *   - Built-in rate limiting via MHD_OPTION_CONNECTION_LIMIT
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
#include <microhttpd.h>

/* ============================================================================
 * Configuration
 * ========================================================================== */
#define EXPORTER_DEFAULT_PORT 9119
#define EXPORTER_BUFFER_SIZE  8192
#define EXPORTER_MAX_CONNECTIONS 10
#define EXPORTER_CONNECTION_TIMEOUT 5

/* Procfs paths */
#define PROCFS_STATS_PATH "/proc/firewall/stats"

/* ============================================================================
 * External reference to daemon_stats (defined in firewall-daemon.c)
 * ========================================================================== */
extern struct daemon_stats {
    atomic_ulong lines_parsed;
    atomic_ulong ips_extracted;
    atomic_ulong ips_banned;
    atomic_ulong failed_attempts;
    atomic_ulong config_reloads;
    atomic_ulong inotify_events;
    atomic_ulong log_rotations;
    atomic_ulong lines_skipped;
    atomic_ulong regex_matches_sshd;
    time_t start_time;
} daemon_stats;

/* ============================================================================
 * Logging helpers
 * ========================================================================== */
#define exporter_log_err(fmt, ...) \
    fprintf(stderr, "firewall[exporter]: ERROR: " fmt "\n", ##__VA_ARGS__)
#define exporter_log_warn(fmt, ...) \
    fprintf(stderr, "firewall[exporter]: WARN: " fmt "\n", ##__VA_ARGS__)
#define exporter_log_info(fmt, ...) \
    fprintf(stderr, "firewall[exporter]: " fmt "\n", ##__VA_ARGS__)

/* ============================================================================
 * Kernel stats reader
 * ========================================================================== */

/* Read a single integer value from a procfs file */
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

/* Read a specific integer value from /proc/firewall/stats by key name */
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
 * Metrics generation
 * ========================================================================== */

/* Generate Prometheus metrics text */
static int generate_metrics(char *buf, size_t buf_size)
{
    unsigned long kernel_banned = 0;
    unsigned long kernel_total_bans = 0;
    unsigned long kernel_total_unbans = 0;
    unsigned long kernel_whitelist_count = 0;
    unsigned long kernel_current_bans = 0;
    time_t uptime;

    /* Read kernel stats from procfs */
    read_procfs_stats_key("current_bans", &kernel_current_bans);
    read_procfs_stats_key("total_bans", &kernel_total_bans);
    read_procfs_stats_key("total_unbans", &kernel_total_unbans);
    read_procfs_stats_key("current_whitelist", &kernel_whitelist_count);
    kernel_banned = kernel_current_bans;

    /* Read daemon stats */
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
 * libmicrohttpd request handler
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

    /* Suppress unused parameter warnings */
    (void)cls;
    (void)version;
    (void)upload_data;
    (void)upload_data_size;
    (void)con_cls;

    /* Only accept GET requests */
    if (strcmp(method, "GET") != 0) {
        page = "405 Method Not Allowed\r\n";
        response = MHD_create_response_from_buffer(strlen(page), (void *)page, MHD_RESPMEM_PERSISTENT);
        if (!response)
            return MHD_NO;
        ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret == MHD_YES ? MHD_YES : MHD_NO;
    }

    /* Route requests */
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
 * HTTP server main loop
 * ========================================================================== */

/**
 * start_http_exporter - Start Prometheus HTTP exporter thread
 * @port: Port number to listen on (passed as void* for pthread compatibility)
 *
 * This function runs in a separate thread and provides a lightweight HTTP
 * server for Prometheus metrics collection using libmicrohttpd.
 *
 * Returns: NULL (pthread convention)
 */
void *start_http_exporter(void *port)
{
    int listen_port = port ? (int)(long)port : EXPORTER_DEFAULT_PORT;
    struct MHD_Daemon *daemon;

    /* Start libmicrohttpd daemon */
    daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY | MHD_USE_ERROR_LOG,
                              (uint16_t)listen_port,
                              NULL, NULL,
                              &answer_to_connection, NULL,
                              MHD_OPTION_CONNECTION_LIMIT, EXPORTER_MAX_CONNECTIONS,
                              MHD_OPTION_CONNECTION_TIMEOUT, EXPORTER_CONNECTION_TIMEOUT,
                              MHD_OPTION_NOTIFY_COMPLETED, NULL, NULL,
                              MHD_OPTION_END);

    if (daemon == NULL) {
        exporter_log_err("Failed to start HTTP daemon on port %d: %s",
                         listen_port, strerror(errno));
        exporter_log_info("Prometheus exporter disabled (port may be in use)");
        return NULL;
    }

    exporter_log_info("Prometheus exporter listening on 0.0.0.0:%d (libmicrohttpd)", listen_port);

    /* Block until thread is cancelled or daemon stops */
    while (1) {
        sleep(1);
    }

    MHD_stop_daemon(daemon);
    exporter_log_info("Prometheus exporter stopped");
    return NULL;
}
