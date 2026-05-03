/*
 * http-exporter.c - Prometheus HTTP exporter for firewall daemon
 *
 * Lightweight HTTP server providing /metrics and /health endpoints
 * for Prometheus monitoring. Runs in a separate pthread.
 *
 * Features:
 *   - Single-threaded, select() based I/O multiplexing
 *   - Prometheus text format output
 *   - Reads kernel stats from /proc/firewall/stats
 *   - Reads daemon stats from shared daemon_stats structure
 *   - Listens on 0.0.0.0:9119 by default
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>

/* ============================================================================
 * Configuration
 * ========================================================================== */
#define EXPORTER_DEFAULT_PORT 9119
#define EXPORTER_MAX_BACKLOG  5
#define EXPORTER_BUFFER_SIZE  8192
#define EXPORTER_TIMEOUT_SEC  5

/* Rate limiting */
#define EXPORTER_RATE_LIMIT_MAX_IPS 64    /* Track up to 64 unique IPs */
#define EXPORTER_RATE_LIMIT_REQ_SEC 10   /* Max requests per second per IP */

/* Procfs paths */
#define PROCFS_STATS_PATH "/proc/firewall/stats"

/* ============================================================================
 * Rate Limiting
 * ========================================================================== */
struct rate_limit_entry {
    uint32_t ip;
    time_t last_request;
    unsigned int request_count;
    time_t window_start;
};

static struct rate_limit_entry rate_limit_table[EXPORTER_RATE_LIMIT_MAX_IPS];
static int rate_limit_count = 0;

/*
 * check_rate_limit - Check if request from IP is within rate limit
 * @ip: Client IP in network byte order
 *
 * Returns: 0 if allowed, -1 if rate limited
 */
static int check_rate_limit(uint32_t ip)
{
    time_t now = time(NULL);
    struct rate_limit_entry *entry = NULL;

    /* Find existing entry */
    for (int i = 0; i < rate_limit_count; i++) {
        if (rate_limit_table[i].ip == ip) {
            entry = &rate_limit_table[i];
            break;
        }
    }

    /* Create new entry if not found */
    if (!entry) {
        if (rate_limit_count >= EXPORTER_RATE_LIMIT_MAX_IPS) {
            /* Table full - evict oldest entry */
            rate_limit_table[0].ip = ip;
            rate_limit_table[0].last_request = now;
            rate_limit_table[0].request_count = 1;
            rate_limit_table[0].window_start = now;
            return 0;
        }
        entry = &rate_limit_table[rate_limit_count++];
        entry->ip = ip;
        entry->last_request = now;
        entry->request_count = 1;
        entry->window_start = now;
        return 0;
    }

    /* Reset window if expired */
    if (now - entry->window_start >= 1) {
        entry->request_count = 0;
        entry->window_start = now;
    }

    entry->request_count++;
    entry->last_request = now;

    if (entry->request_count > EXPORTER_RATE_LIMIT_REQ_SEC) {
        return -1; /* Rate limited */
    }

    return 0;
}

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
 * Logging helpers (use stderr since syslog may not be available in thread)
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
        /* Try to parse as "key: value" or just "value" */
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

/* ============================================================================
 * HTTP response helpers
 * ========================================================================== */

static const char *http_200_ok =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char *http_200_json =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: application/json\r\n"
    "Connection: close\r\n"
    "\r\n";

static const char *http_404 =
    "HTTP/1.1 404 Not Found\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n"
    "\r\n"
    "404 Not Found\r\n";

static const char *http_400 =
    "HTTP/1.1 400 Bad Request\r\n"
    "Content-Type: text/plain\r\n"
    "Connection: close\r\n"
    "\r\n"
    "400 Bad Request\r\n";

/* Send a complete HTTP response with body */
static int send_response(int sockfd, const char *headers, const char *body)
{
    size_t headers_len = strlen(headers);
    size_t body_len = body ? strlen(body) : 0;
    size_t total = headers_len + body_len;
    char *response;
    ssize_t sent;
    size_t total_sent = 0;

    response = malloc(total + 1);
    if (!response) {
        exporter_log_err("Out of memory allocating response buffer");
        return -1;
    }

    memcpy(response, headers, headers_len);
    if (body)
        memcpy(response + headers_len, body, body_len);
    response[total] = '\0';

    while (total_sent < total) {
        sent = send(sockfd, response + total_sent, total - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            exporter_log_err("Failed to send response: %s", strerror(errno));
            free(response);
            return -1;
        }
        total_sent += (size_t)sent;
    }

    free(response);
    return 0;
}

/* ============================================================================
 * Metrics generation
 * ========================================================================== */

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

/* Generate Prometheus metrics text */
static int generate_metrics(char *buf, size_t buf_size)
{
    unsigned long kernel_banned = 0;
    unsigned long kernel_total_bans = 0;
    unsigned long kernel_total_unbans = 0;
    unsigned long kernel_whitelist_count = 0;
    unsigned long kernel_current_bans = 0;  /* Current active bans from stats */
    time_t uptime;

    /* Read kernel stats from procfs - parse specific keys from /proc/firewall/stats */
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
 * Request handler
 * ========================================================================== */

/* Parse HTTP request and handle accordingly */
static int handle_request(int sockfd)
{
    char buffer[1024];
    ssize_t bytes_read;
    char method[16] = {0};
    char uri[256] = {0};
    char http_version[32] = {0};

    /* Set receive timeout */
    struct timeval tv;
    tv.tv_sec = EXPORTER_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Read HTTP request line */
    bytes_read = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    if (bytes_read <= 0) {
        if (bytes_read < 0 && errno == EAGAIN)
            exporter_log_err("Request read timeout");
        return -1;
    }
    buffer[bytes_read] = '\0';

    /* Check if request was truncated */
    if (bytes_read >= (ssize_t)sizeof(buffer) - 1) {
        exporter_log_warn("Request too large, possible attack");
        send_response(sockfd, http_400, NULL);
        return -1;
    }

    /* Parse method, URI and HTTP version */
    if (sscanf(buffer, "%15s %255s %31s", method, uri, http_version) < 2) {
        send_response(sockfd, http_400, NULL);
        return -1;
    }

    /* Validate URI doesn't contain path traversal */
    if (strstr(uri, "..") != NULL || strcasestr(uri, "%2e") != NULL || strcasestr(uri, "%2f") != NULL) {
        exporter_log_warn("Path traversal attempt in URI: %s", uri);
        send_response(sockfd, http_400, NULL);
        return -1;
    }

    /* Only handle GET requests */
    if (strcmp(method, "GET") != 0) {
        send_response(sockfd, http_400, NULL);
        return -1;
    }

    /* Route requests */
    if (strcmp(uri, "/metrics") == 0) {
        char metrics_buf[EXPORTER_BUFFER_SIZE];
        int len = generate_metrics(metrics_buf, sizeof(metrics_buf));

        if (len < 0 || (size_t)len >= sizeof(metrics_buf)) {
            exporter_log_err("Metrics buffer overflow");
            send_response(sockfd, http_400, NULL);
            return -1;
        }

        send_response(sockfd, http_200_ok, metrics_buf);
    } else if (strcmp(uri, "/health") == 0 || strcmp(uri, "/healthz") == 0) {
        const char *health_body = "{\"status\":\"ok\"}\n";
        send_response(sockfd, http_200_json, health_body);
    } else {
        send_response(sockfd, http_404, NULL);
    }

    return 0;
}

/* ============================================================================
 * HTTP server main loop
 * ========================================================================== */

/**
 * start_http_exporter - Start Prometheus HTTP exporter thread
 * @port: Port number to listen on (passed as void* for pthread compatibility)
 *
 * This function runs in a separate thread and provides a lightweight HTTP
 * server for Prometheus metrics collection.
 *
 * Returns: NULL (pthread convention)
 */
void *start_http_exporter(void *port)
{
    int server_fd;
    int listen_port = port ? (int)(long)port : EXPORTER_DEFAULT_PORT;
    struct sockaddr_in addr;
    int optval = 1;

    /* Ignore SIGPIPE to prevent crash on broken connections */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    /* Create socket */
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        exporter_log_err("Failed to create socket: %s", strerror(errno));
        return NULL;
    }

    /* Set socket options */
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        exporter_log_err("Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    /* Bind to address */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)listen_port);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        exporter_log_err("Failed to bind to port %d: %s", listen_port, strerror(errno));
        exporter_log_info("Prometheus exporter disabled (port may be in use)");
        close(server_fd);
        return NULL;
    }

    /* Listen for connections */
    if (listen(server_fd, EXPORTER_MAX_BACKLOG) < 0) {
        exporter_log_err("Failed to listen on port %d: %s", listen_port, strerror(errno));
        close(server_fd);
        return NULL;
    }

    /* Set non-blocking for select() */
    int flags = fcntl(server_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(server_fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        exporter_log_err("Failed to set non-blocking: %s", strerror(errno));
        close(server_fd);
        return NULL;
    }

    exporter_log_info("Prometheus exporter listening on 0.0.0.0:%d", listen_port);

    /* Main accept loop with select() */
    while (1) {
        fd_set readfds;
        struct timeval tv;
        int maxfd;

        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        maxfd = server_fd;

        /* Wait for connections with timeout */
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int activity = select(maxfd + 1, &readfds, NULL, NULL, &tv);
        if (activity < 0) {
            if (errno == EINTR)
                continue;
            exporter_log_err("select error: %s", strerror(errno));
            break;
        }

        if (activity == 0) {
            /* Timeout, continue */
            continue;
        }

        /* Accept connection */
        if (FD_ISSET(server_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);

            if (client_fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    exporter_log_err("Failed to accept connection: %s", strerror(errno));
                }
                continue;
            }

            /* Rate limiting check */
            if (check_rate_limit(client_addr.sin_addr.s_addr) < 0) {
                exporter_log_info("Rate limited connection from %s", inet_ntoa(client_addr.sin_addr));
                const char *rate_limit_response =
                    "HTTP/1.1 429 Too Many Requests\r\n"
                    "Content-Type: text/plain\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "429 Too Many Requests\r\n";
                send(client_fd, rate_limit_response, strlen(rate_limit_response), MSG_NOSIGNAL);
                close(client_fd);
                continue;
            }

            exporter_log_info("Connection from %s", inet_ntoa(client_addr.sin_addr));

            /* Handle request (blocking with timeout) */
            handle_request(client_fd);

            /* Close connection */
            close(client_fd);
        }
    }

    close(server_fd);
    exporter_log_info("Prometheus exporter stopped");
    return NULL;
}
