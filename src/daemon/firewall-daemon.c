/*
 * firewall-daemon.c - User-space daemon for firewall kernel module
 *
 * Monitors log files for failed login attempts and automatically bans
 * offending IPs via the firewall kernel module procfs interface.
 *
 * Usage:
 *   sudo ./firewall-daemon [--daemonize] [--max-retries N] [--findtime SECS]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <syslog.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <time.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <regex.h>
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <ctype.h>

/* Procfs paths */
#define PROCFS_DIR "/proc/firewall"
#define ADD_BAN_PATH PROCFS_DIR "/add_ban"
#define REMOVE_BAN_PATH PROCFS_DIR "/remove_ban"
#define BAN_LIST_PATH PROCFS_DIR "/ban_list"

/* Default configuration */
#define DEFAULT_MAX_RETRIES 3
#define DEFAULT_FINDTIME 600      /* 10 minutes */
#define DEFAULT_BAN_TIME 600      /* 10 minutes */
#define DEFAULT_INTERVAL 1        /* Check interval in seconds */

/* Maximum failed attempts to track per IP */
#define MAX_FAILED_TIMESTAMPS 100

/* Maximum number of log files to monitor */
#define MAX_LOG_FILES 10

/* Event buffer size for inotify */
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

/* File state tracking for log rotation detection */
struct file_state {
    char path[512];
    off_t offset;
    ino_t inode;
    int wd;  /* inotify watch descriptor */
};

/* Global running flag */
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_config = 0;

/* Configuration structure */
struct config {
    unsigned int max_retries;
    unsigned int findtime;
    unsigned int ban_time;
    int daemonize;
    int interval;
    char *log_files[MAX_LOG_FILES];
    int log_count;
    char *config_file;  /* Path to configuration file for runtime updates */
};

/* Failed attempt tracker */
struct failed_entry {
    char ip[16];
    time_t timestamps[MAX_FAILED_TIMESTAMPS];
    unsigned int count;
    struct failed_entry *next;
    struct failed_entry *next_in_hash;  /* Next entry in hash bucket */
};

/* 配置互斥锁 - 保护 cfg 全局变量的多线程访问 */
static pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Global state */
static struct config cfg;
static struct failed_entry *failed_table = NULL;
static int inotify_fd = -1;
static struct file_state file_states[MAX_LOG_FILES];

/* Precompiled regex patterns for log parsing */
static regex_t sshd_regex;
static regex_t vsftpd_regex;
static regex_t nginx_regex;
static int regex_compiled = 0;

/* Helper function for case-insensitive substring search */
static int strcasestr_custom(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    size_t haystack_len = strlen(haystack);

    if (needle_len == 0) return 1;  /* Empty needle should match */
    if (haystack_len < needle_len) return 0;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (strncasecmp(haystack + i, needle, needle_len) == 0) {
            return 1;  /* Found match */
        }
    }
    return 0;  /* No match */
}

/* Function prototypes */
static void setup_signals(void);
static int parse_config_file(const char *config_path);
static int parse_config(int argc, char *argv[]);
static int extract_ip(const char *line, char *ip_out, size_t ip_size);
static int parse_log_line(const char *line, char *ip_out, size_t ip_size);
static struct failed_entry *find_entry(const char *ip);
static struct failed_entry *create_entry(const char *ip);
static void remove_entry(const char *ip);
static unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries);
static void handle_failed_attempt(const char *ip, unsigned int max_retries, unsigned int findtime);
static int ban_ip(const char *ip);
static int unban_ip(const char *ip);
static void cleanup_expired_bans(void);
static void cleanup_partial_line_buffer(void);
static void daemonize_process(void);
static int setup_inotify(void);
static void process_new_lines(int idx);
static void monitor_loop(void);
static void cleanup(void);
static void handle_log_rotation(int idx);
static int init_log_patterns(void);
static void free_log_patterns(void);
static int validate_and_normalize_path(const char *input_path);

/* Signal handler - only sets flag, no async-unsafe calls */
static void signal_handler(int sig)
{
    switch(sig) {
        case SIGTERM:
        case SIGINT:
            running = 0;
            break;
        case SIGHUP:
            reload_config = 1;  /* Reload configuration on SIGHUP */
            break;
    }
}

/* Parse configuration file */
static int parse_config_file(const char *config_path)
{
    FILE *file;
    char line[1024];
    char *key, *value;

    /* 修复 #5: 保存旧配置的深拷贝，用于解析失败时恢复 */
    char *old_log_files[MAX_LOG_FILES];
    int old_log_count = 0;
    unsigned int old_max_retries = cfg.max_retries;
    unsigned int old_findtime = cfg.findtime;
    unsigned int old_ban_time = cfg.ban_time;
    int old_interval = cfg.interval;

    for (int i = 0; i < cfg.log_count; i++) {
        old_log_files[i] = cfg.log_files[i] ? strdup(cfg.log_files[i]) : NULL;
        if (cfg.log_files[i] && !old_log_files[i]) {
            /* 深拷贝失败，释放已分配的内存 */
            for (int j = 0; j < i; j++) {
                free(old_log_files[j]);
            }
            syslog(LOG_ERR, "firewall: Out of memory saving old config for rollback");
            return -1;
        }
    }
    old_log_count = cfg.log_count;

    /* 获取配置锁 - 防止与 monitor_loop() 并发访问 */
    pthread_mutex_lock(&config_mutex);

    /* Clean up old inotify watches to prevent watch leak on config reload (SIGHUP) */
    for (int i = 0; i < cfg.log_count; i++) {
        if (file_states[i].wd >= 0 && inotify_fd >= 0) {
            inotify_rm_watch(inotify_fd, file_states[i].wd);
            file_states[i].wd = -1;
        }
        /* Also clear the rest of the state to avoid stale data */
        file_states[i].offset = 0;
        file_states[i].inode = 0;
        file_states[i].path[0] = '\0';
    }

    /* Free old log_files to prevent memory leak on config reload (SIGHUP) */
    for (int i = 0; i < cfg.log_count; i++) {
        if (cfg.log_files[i]) {
            free(cfg.log_files[i]);
            cfg.log_files[i] = NULL;
        }
    }
    cfg.log_count = 0;

    file = fopen(config_path, "r");
    if (!file) {
        syslog(LOG_WARNING, "firewall: Cannot open config file: %s", config_path);
        goto restore_old_config;
    }

    syslog(LOG_INFO, "firewall: Reading config file: %s", config_path);

    while (fgets(line, sizeof(line), file)) {
        /* Remove leading/trailing whitespace and comments */
        size_t len = strlen(line);

        /* Remove trailing newline */
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
            len--;
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#' || line[0] == ';') {
            continue;
        }

        /* Find the '=' separator */
        char *sep = strchr(line, '=');
        if (!sep) {
            syslog(LOG_WARNING, "firewall: Invalid config line: %s", line);
            continue;
        }

        /* Split into key and value */
        *sep = '\0';
        key = line;
        value = sep + 1;

        /* Trim leading whitespace from key */
        while (*key == ' ' || *key == '\t') {
            key++;
        }

        /* Trim trailing whitespace from key */
        char *end = key + strlen(key) - 1;
        while (end > key && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }

        /* Trim leading whitespace from value */
        while (*value == ' ' || *value == '\t') {
            value++;
        }

        /* Process configuration key-value pairs */
        if (strcmp(key, "max_retries") == 0) {
            char *endptr;
            errno = 0;
            long val = strtol(value, &endptr, 10);

            if (errno != 0 || *endptr != '\0' || val < 1 || val > 100 || val > INT_MAX) {
                syslog(LOG_WARNING, "firewall: Invalid max_retries value in config: %s", value);
            } else {
                cfg.max_retries = (unsigned int)val;
                syslog(LOG_INFO, "firewall: Config max_retries set to %u", cfg.max_retries);
            }
        } else if (strcmp(key, "findtime") == 0) {
            char *endptr;
            errno = 0;
            long val = strtol(value, &endptr, 10);

            if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600 || val > INT_MAX) {
                syslog(LOG_WARNING, "firewall: Invalid findtime value in config: %s", value);
            } else {
                cfg.findtime = (unsigned int)val;
                syslog(LOG_INFO, "firewall: Config findtime set to %u", cfg.findtime);
            }
        } else if (strcmp(key, "ban_time") == 0) {
            char *endptr;
            errno = 0;
            long val = strtol(value, &endptr, 10);

            if (errno != 0 || *endptr != '\0' || val < 1 || val > 86400 || val > INT_MAX) {
                syslog(LOG_WARNING, "firewall: Invalid ban_time value in config: %s", value);
            } else {
                cfg.ban_time = (unsigned int)val;
                syslog(LOG_INFO, "firewall: Config ban_time set to %u", cfg.ban_time);
            }
        } else if (strcmp(key, "interval") == 0) {
            char *endptr;
            errno = 0;
            long val = strtol(value, &endptr, 10);

            if (errno != 0 || *endptr != '\0' || val < 1 || val > 60 || val > INT_MAX) {
                syslog(LOG_WARNING, "firewall: Invalid interval value in config: %s", value);
            } else {
                cfg.interval = (int)val;
                syslog(LOG_INFO, "firewall: Config interval set to %d", cfg.interval);
            }
        } else if (strcmp(key, "log_file") == 0) {
            if (cfg.log_count >= MAX_LOG_FILES) {
                syslog(LOG_WARNING, "firewall: Too many log files in config (max %d)", MAX_LOG_FILES);
            } else {
                /* Validate the path to prevent path traversal attacks */
                if (validate_and_normalize_path(value) < 0) {
                    syslog(LOG_WARNING, "firewall: Invalid log file path in config: %s", value);
                } else {
                    cfg.log_files[cfg.log_count] = strdup(value);
                    if (!cfg.log_files[cfg.log_count]) {
                        syslog(LOG_ERR, "firewall: Out of memory allocating log file path");
                        /* Free any previously allocated log file paths */
                        for (int j = 0; j < cfg.log_count; j++) {
                            if (cfg.log_files[j]) {
                                free(cfg.log_files[j]);
                                cfg.log_files[j] = NULL;
                            }
                        }
                        fclose(file);
                        goto restore_old_config;
                    } else {
                        syslog(LOG_INFO, "firewall: Added log file from config: %s", cfg.log_files[cfg.log_count]);
                        cfg.log_count++;
                    }
                }
            }
        } else if (strcmp(key, "daemonize") == 0) {
            if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0) {
                cfg.daemonize = 1;
                syslog(LOG_INFO, "firewall: Config daemonize set to true");
            } else if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0) {
                cfg.daemonize = 0;
                syslog(LOG_INFO, "firewall: Config daemonize set to false");
            } else {
                syslog(LOG_WARNING, "firewall: Invalid daemonize value in config: %s", value);
            }
        } else {
            syslog(LOG_WARNING, "firewall: Unknown config key: %s", key);
        }
    }

    fclose(file);
    pthread_mutex_unlock(&config_mutex);

    /* 解析成功，释放旧配置的深拷贝 */
    for (int i = 0; i < old_log_count; i++) {
        free(old_log_files[i]);
    }
    return 0;

restore_old_config:
    /* 解析失败，恢复旧配置 */
    syslog(LOG_WARNING, "firewall: Config parsing failed, restoring old configuration");

    /* 释放新分配的资源（如果有） */
    for (int i = 0; i < cfg.log_count; i++) {
        free(cfg.log_files[i]);
        cfg.log_files[i] = NULL;
    }

    /* 恢复旧配置 */
    cfg.log_count = 0;
    for (int i = 0; i < old_log_count; i++) {
        if (old_log_files[i]) {
            cfg.log_files[cfg.log_count] = old_log_files[i];
            cfg.log_count++;
        }
    }
    cfg.max_retries = old_max_retries;
    cfg.findtime = old_findtime;
    cfg.ban_time = old_ban_time;
    cfg.interval = old_interval;

    pthread_mutex_unlock(&config_mutex);
    return -1;
}

/* Setup signal handlers using sigaction */
static void setup_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        syslog(LOG_ERR, "firewall: Failed to setup SIGTERM handler: %s",
               strerror(errno));
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        syslog(LOG_ERR, "firewall: Failed to setup SIGINT handler: %s",
               strerror(errno));
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        syslog(LOG_ERR, "firewall: Failed to setup SIGHUP handler: %s",
               strerror(errno));
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        syslog(LOG_ERR, "firewall: Failed to ignore SIGPIPE: %s",
               strerror(errno));
    }
}

/* Parse command line arguments */
static int parse_config(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},  /* New config file option */
        {"daemonize",  no_argument,       0, 'd'},
        {"max-retries", required_argument, 0, 'm'},
        {"findtime",   required_argument, 0, 'f'},
        {"ban-time",   required_argument, 0, 'b'},
        {"interval",   required_argument, 0, 'i'},
        {"log",        required_argument, 0, 'l'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Set defaults */
    cfg.max_retries = DEFAULT_MAX_RETRIES;
    cfg.findtime = DEFAULT_FINDTIME;
    cfg.ban_time = DEFAULT_BAN_TIME;
    cfg.daemonize = 0;
    cfg.interval = DEFAULT_INTERVAL;
    cfg.log_count = 0;
    cfg.config_file = NULL;  /* Initialize config file to NULL */

    /* Initialize log files array to NULL */
    for (int i = 0; i < MAX_LOG_FILES; i++) {
        cfg.log_files[i] = NULL;
    }

    /* First, check for config file option */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--config") == 0 || strncmp(argv[i], "--config=", 9) == 0 ||
            strcmp(argv[i], "-c") == 0) {
            char *config_path = NULL;

            if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0) {
                /* Config file path is the next argument */
                if (i + 1 < argc) {
                    config_path = argv[i + 1];
                }
            } else if (strncmp(argv[i], "--config=", 9) == 0) {
                /* Config file path is part of the same argument */
                config_path = argv[i] + 9;
            }

            if (config_path) {
                /* Store config file path for later reloads */
                if (cfg.config_file) {
                    free(cfg.config_file);  // Free any previously allocated config file path
                }
                cfg.config_file = strdup(config_path);
                if (!cfg.config_file) {
                    fprintf(stderr, "Error: out of memory allocating config file path\n");
                    return -1;
                }

                /* Parse config file */
                if (parse_config_file(config_path) < 0) {
                    fprintf(stderr, "Error: failed to parse config file: %s\n", config_path);
                    free(cfg.config_file);
                    cfg.config_file = NULL;
                    return -1;
                }
                break;
            }
        }
    }

    /* Now parse command line options (they override config file values) */
    while ((opt = getopt_long(argc, argv, "c:dm:f:b:i:l:h", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':  /* Config file - already handled above, but keep for completeness */
            break;
        case 'd':
            cfg.daemonize = 1;
            break;
        case 'm':
            {
                char *endptr;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);

                /* Check for conversion errors */
                if (errno != 0 || *endptr != '\0') {
                    fprintf(stderr, "Error: invalid max-retries value '%s'\n", optarg);
                    return -1;
                }

                /* Enhanced validation with stricter limits */
                if (val < 1 || val > 100 || val > INT_MAX) {  /* Reduced upper limit from MAX_FAILED_TIMESTAMPS to 100 */
                    fprintf(stderr, "Error: max-retries must be between 1 and 100\n");
                    return -1;
                }

                cfg.max_retries = (unsigned int)val;
            }
            break;
        case 'f':
            {
                char *endptr;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);

                /* Check for conversion errors */
                if (errno != 0 || *endptr != '\0') {
                    fprintf(stderr, "Error: invalid findtime value '%s'\n", optarg);
                    return -1;
                }

                /* Additional validation */
                if (val < 1 || val > 3600 || val > INT_MAX) {
                    fprintf(stderr, "Error: findtime must be between 1 and 3600 seconds\n");
                    return -1;
                }

                cfg.findtime = (unsigned int)val;
            }
            break;
        case 'b':
            {
                char *endptr;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);

                /* Check for conversion errors */
                if (errno != 0 || *endptr != '\0') {
                    fprintf(stderr, "Error: invalid ban-time value '%s'\n", optarg);
                    return -1;
                }

                /* Additional validation */
                if (val < 1 || val > 86400 || val > INT_MAX) {
                    fprintf(stderr, "Error: ban-time must be between 1 and 86400 seconds\n");
                    return -1;
                }

                cfg.ban_time = (unsigned int)val;
            }
            break;
        case 'i':
            {
                char *endptr;
                errno = 0;
                long val = strtol(optarg, &endptr, 10);

                /* Check for conversion errors */
                if (errno != 0 || *endptr != '\0') {
                    fprintf(stderr, "Error: invalid interval value '%s'\n", optarg);
                    return -1;
                }

                /* Additional validation */
                if (val < 1 || val > 60 || val > INT_MAX) {
                    fprintf(stderr, "Error: interval must be between 1 and 60 seconds\n");
                    return -1;
                }

                cfg.interval = (int)val;
            }
            break;
        case 'l':
            if (cfg.log_count >= MAX_LOG_FILES) {
                fprintf(stderr, "Error: too many log files (max %d)\n", MAX_LOG_FILES);
                return -1;
            }

            /* Enhanced security: Strict path validation to prevent path traversal attacks */
            if (validate_and_normalize_path(optarg) < 0) {
                fprintf(stderr, "Error: invalid log file path '%s'\n", optarg);
                return -1;
            }

            cfg.log_files[cfg.log_count] = strdup(optarg);
            if (!cfg.log_files[cfg.log_count]) {
                fprintf(stderr, "Error: out of memory\n");
                // Free any previously allocated log file paths
                for (int j = 0; j < cfg.log_count; j++) {
                    if (cfg.log_files[j]) {
                        free(cfg.log_files[j]);
                        cfg.log_files[j] = NULL;
                    }
                }
                if (cfg.config_file) {  // Also free config file if allocated
                    free(cfg.config_file);
                    cfg.config_file = NULL;
                }
                return -1;
            }
            cfg.log_count++;
            break;
        case 'h':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -c, --config FILE      Configuration file path\n");
            printf("  -d, --daemonize        Run as daemon\n");
            printf("  -m, --max-retries N    Max failed attempts before ban (default: %d)\n", DEFAULT_MAX_RETRIES);
            printf("  -f, --findtime SECS    Time window for failures (default: %d)\n", DEFAULT_FINDTIME);
            printf("  -b, --ban-time SECS    Ban duration (default: %d)\n", DEFAULT_BAN_TIME);
            printf("  -i, --interval SECS    Check interval (default: %d)\n", DEFAULT_INTERVAL);
            printf("  -l, --log FILE         Log file to monitor (can be specified multiple times)\n");
            printf("  -h, --help             Show this help\n");
            return 1;
        case '?':
            /* getopt_long already printed an error message */
            return -1;
        default:
            return -1;
        }
    }

    /* Default log files if none specified */
    if (cfg.log_count == 0) {
        const char *default_logs[] = {
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/vsftpd.log",
            "/var/log/nginx/error.log"
        };
        int num_defaults = sizeof(default_logs) / sizeof(default_logs[0]);

        for (int i = 0; i < num_defaults; i++) {
            /* Apply the same path validation to default log files */
            if (validate_and_normalize_path(default_logs[i]) < 0) {
                syslog(LOG_WARNING, "firewall: Skipping invalid default log path: %s", default_logs[i]);
                continue;
            }

            if (access(default_logs[i], R_OK) == 0) {
                cfg.log_files[cfg.log_count] = strdup(default_logs[i]);
                if (!cfg.log_files[cfg.log_count]) {
                    fprintf(stderr, "Error: out of memory\n");
                    // Free any previously allocated log file paths
                    for (int j = 0; j < cfg.log_count; j++) {
                        if (cfg.log_files[j]) {
                            free(cfg.log_files[j]);
                            cfg.log_files[j] = NULL;
                        }
                    }
                    if (cfg.config_file) {  // Also free config file if allocated
                        free(cfg.config_file);
                        cfg.config_file = NULL;
                    }
                    return -1;
                }
                cfg.log_count++;
            }
        }
    }

    return 0;
}

/* Extract IPv4 address from log line (fallback for non-regex mode) */
static int extract_ipv4(const char *line, char *ip_out, size_t ip_size)
{
    const char *ptr = line;
    int octets[4];

    /* Search for pattern: digits.digits.digits.digits */
    while (*ptr) {
        if (sscanf(ptr, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            /* Validate octets */
            if (octets[0] >= 0 && octets[0] <= 255 &&
                octets[1] >= 0 && octets[1] <= 255 &&
                octets[2] >= 0 && octets[2] <= 255 &&
                octets[3] >= 0 && octets[3] <= 255) {

                snprintf(ip_out, ip_size, "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                /* Validate with inet_pton */
                unsigned char buf[4];
                if (inet_pton(AF_INET, ip_out, buf) == 1) {
                    // Additional validation: reject invalid IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
                    unsigned int ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
                    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
                        octets[0] == 127 ||  // 127.x.x.x
                        (octets[0] >= 224 && octets[0] <= 239)) {  // 224.0.0.0/4 (multicast)
                        /* Skip invalid IPs: advance past the entire IP-like pattern */
                        while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
                        continue;
                    }

                    return 1;
                }
            }
        }
        /* sscanf didn't match or octets invalid: skip past digits and dots to avoid re-scanning */
        if (isdigit((unsigned char)*ptr) || *ptr == '.') {
            while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
        } else {
            ptr++;
        }
    }

    return 0;
}

/* Extract IP address from log line (IPv4 only) */
static int extract_ip(const char *line, char *ip_out, size_t ip_size)
{
    return extract_ipv4(line, ip_out, ip_size);
}

/* Helper function to extract and validate IP from a log line.
 * Returns 1 if a valid IP was extracted, 0 otherwise.
 * Consolidates duplicated IP extraction/validation logic from sshd/vsftpd/nginx branches. */
static int extract_and_validate_ip(const char *log_line, char *ip_out, size_t ip_size)
{
    char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr4;

    if (!parse_log_line(log_line, ip_buf, sizeof(ip_buf))) {
        return 0;
    }

    /* Validate IPv4 */
    if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
        unsigned int ip_num = ntohl(addr4.s_addr);
        /* Reject invalid/reserved IPv4 addresses */
        if (ip_num == 0 ||                                  /* 0.0.0.0 */
            ip_num == 0xFFFFFFFF ||                         /* 255.255.255.255 */
            ((ip_num >> 24) & 0xFF) == 127 ||              /* 127.x.x.x (loopback) */
            (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) { /* multicast */
            return 0;
        }
        size_t copy_len = strlen(ip_buf);
        if (copy_len >= ip_size) copy_len = ip_size - 1;
        memcpy(ip_out, ip_buf, copy_len);
        ip_out[copy_len] = '\0';
        return 1;
    }

    return 0;
}

/* Parse log line and extract IP if it's a failed login */
static int parse_log_line(const char *line, char *ip_out, size_t ip_size)
{
    regmatch_t matches[4];
    const char *ip_start;
    size_t ip_len;

    /* Length validation to prevent extremely long log lines */
    size_t line_len = strlen(line);
    if (line_len > 8192) {
        syslog(LOG_WARNING, "firewall: Log line too long (%zu bytes), skipping", line_len);
        return 0;
    }

    /* Check for sshd failed password using precompiled regex */
    if (regex_compiled) {
        int regex_result = regexec(&sshd_regex, line, 4, matches, 0);
        if (regex_result == 0) {
            /* Capture group 2: IP address */
            if (matches[2].rm_so >= 0 && matches[2].rm_eo > matches[2].rm_so) {
                ip_start = line + matches[2].rm_so;
                ip_len = matches[2].rm_eo - matches[2].rm_so;

                if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                    syslog(LOG_WARNING, "firewall: Invalid IP length in sshd log: %zu", ip_len);
                    return 0;
                }

                char ip_buf[INET_ADDRSTRLEN];
                memcpy(ip_buf, ip_start, ip_len);
                ip_buf[ip_len] = '\0';
                strncpy(ip_out, ip_buf, ip_size - 1);
                ip_out[ip_size - 1] = '\0';
                return 1;
            }
        } else if (regex_result != REG_NOMATCH) {
            char errbuf[256];
            regerror(regex_result, &sshd_regex, errbuf, sizeof(errbuf));
            syslog(LOG_WARNING, "firewall: Regex error in sshd pattern: %s", errbuf);
        }
    }

    /* Check for vsftpd failed login using precompiled regex */
    if (regex_compiled) {
        int regex_result = regexec(&vsftpd_regex, line, 4, matches, 0);
        if (regex_result == 0) {
            /* Capture group 1: IP address */
            if (matches[1].rm_so >= 0 && matches[1].rm_eo > matches[1].rm_so) {
                ip_start = line + matches[1].rm_so;
                ip_len = matches[1].rm_eo - matches[1].rm_so;

                if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                    syslog(LOG_WARNING, "firewall: Invalid IP length in vsftpd log: %zu", ip_len);
                    return 0;
                }

                char ip_buf[INET_ADDRSTRLEN];
                memcpy(ip_buf, ip_start, ip_len);
                ip_buf[ip_len] = '\0';
                strncpy(ip_out, ip_buf, ip_size - 1);
                ip_out[ip_size - 1] = '\0';
                return 1;
            }
        } else if (regex_result != REG_NOMATCH) {
            char errbuf[256];
            regerror(regex_result, &vsftpd_regex, errbuf, sizeof(errbuf));
            syslog(LOG_WARNING, "firewall: Regex error in vsftpd pattern: %s", errbuf);
        }
    }

    /* Check for nginx 401 Unauthorized using precompiled regex */
    if (regex_compiled) {
        int regex_result = regexec(&nginx_regex, line, 4, matches, 0);
        if (regex_result == 0) {
            /* Capture group 1: IP address */
            if (matches[1].rm_so >= 0 && matches[1].rm_eo > matches[1].rm_so) {
                ip_start = line + matches[1].rm_so;
                ip_len = matches[1].rm_eo - matches[1].rm_so;

                if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                    syslog(LOG_WARNING, "firewall: Invalid IP length in nginx log: %zu", ip_len);
                    return 0;
                }

                char ip_buf[INET_ADDRSTRLEN];
                memcpy(ip_buf, ip_start, ip_len);
                ip_buf[ip_len] = '\0';
                strncpy(ip_out, ip_buf, ip_size - 1);
                ip_out[ip_size - 1] = '\0';
                return 1;
            }
        } else if (regex_result != REG_NOMATCH) {
            char errbuf[256];
            regerror(regex_result, &nginx_regex, errbuf, sizeof(errbuf));
            syslog(LOG_WARNING, "firewall: Regex error in nginx pattern: %s", errbuf);
        }
    }

    /* Fallback: simple string matching (if regex not compiled) */
    if (!regex_compiled) {
        if (strstr(line, "Failed password for") ||
            strstr(line, "authentication failure") ||
            strstr(line, "FAIL LOGIN") ||
            strstr(line, "401 Unauthorized")) {
            return extract_ip(line, ip_out, ip_size);
        }
    }

    return 0;
}

/* Hash table for faster lookup of failed entries */
#define FAILED_ENTRY_HASH_SIZE 256
static struct failed_entry *failed_hash_table[FAILED_ENTRY_HASH_SIZE];

/* Simple hash function for IP addresses */
static unsigned int hash_ip(const char *ip)
{
    unsigned int hash = 5381;
    int c;

    while ((c = *ip++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash % FAILED_ENTRY_HASH_SIZE;
}

/* Find failed entry by IP - optimized with hash table */
static struct failed_entry *find_entry(const char *ip)
{
    unsigned int hash = hash_ip(ip);
    struct failed_entry *entry = failed_hash_table[hash];

    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            return entry;
        }
        entry = entry->next_in_hash;
    }

    return NULL;
}

/* Create new failed entry */
static struct failed_entry *create_entry(const char *ip)
{
    struct failed_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        syslog(LOG_ERR, "firewall: Failed to allocate memory for entry");
        return NULL;
    }

    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->count = 0;

    /* Add to linked list */
    entry->next = failed_table;
    failed_table = entry;

    /* Add to hash table */
    unsigned int hash = hash_ip(ip);
    entry->next_in_hash = failed_hash_table[hash];
    failed_hash_table[hash] = entry;

    return entry;
}

/* Remove failed entry */
static void remove_entry(const char *ip)
{
    struct failed_entry *prev = NULL;
    struct failed_entry *entry = failed_table;

    /* Find in main linked list */
    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            /* Remove from main linked list */
            if (prev) {
                prev->next = entry->next;
            } else {
                failed_table = entry->next;
            }

            /* Remove from hash table */
            unsigned int hash = hash_ip(ip);
            struct failed_entry *hash_prev = NULL;
            struct failed_entry *hash_entry = failed_hash_table[hash];

            while (hash_entry) {
                if (hash_entry == entry) {
                    if (hash_prev) {
                        hash_prev->next_in_hash = hash_entry->next_in_hash;
                    } else {
                        failed_hash_table[hash] = hash_entry->next_in_hash;
                    }
                    break;
                }
                hash_prev = hash_entry;
                hash_entry = hash_entry->next_in_hash;
            }

            free(entry);
            return;
        }
        prev = entry;
        entry = entry->next;
    }
}

/* Count recent failures within time window */
static unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries)
{
    time_t now = time(NULL);
    unsigned int count = 0;

    /* Validate parameters to prevent potential issues */
    if (!entry || window <= 0) {
        syslog(LOG_DEBUG, "firewall: Invalid parameters to count_recent");
        return 0;
    }

    for (unsigned int i = 0; i < entry->count; i++) {
        /* Prevent integer underflow if timestamp is in the future */
        if (now >= entry->timestamps[i]) {
            time_t diff = now - entry->timestamps[i];
            /* Additional check to prevent potential integer overflow in comparison */
            if (diff <= window) {
                count++;
            }
        }
        /* Limit processing to avoid excessive CPU usage if there are many timestamps */
        if (count > max_retries) {
            /* Early exit if we've already exceeded the threshold */
            break;
        }
    }

    return count;
}

/* Handle a failed login attempt - 线程安全版本 */
static void handle_failed_attempt(const char *ip, unsigned int max_retries, unsigned int findtime)
{
    struct failed_entry *entry = find_entry(ip);
    time_t now = time(NULL);

    /* Validate IP before processing */
    if (!ip || strlen(ip) == 0) {
        syslog(LOG_ERR, "firewall: Invalid IP address provided to handle_failed_attempt");
        return;
    }

    if (!entry) {
        entry = create_entry(ip);
        if (!entry) {
            syslog(LOG_ERR, "firewall: Failed to create entry for IP %s", ip);
            return;
        }
    }

    /* Add timestamp */
    if (entry->count < MAX_FAILED_TIMESTAMPS) {
        entry->timestamps[entry->count++] = now;
    } else {
        /* Shift timestamps to make room for the new one */
        memmove(entry->timestamps, entry->timestamps + 1,
                (MAX_FAILED_TIMESTAMPS - 1) * sizeof(time_t));
        entry->timestamps[MAX_FAILED_TIMESTAMPS - 1] = now;

        /* After shifting, check if oldest timestamp is too old to keep */
        time_t oldest_valid = now - findtime;
        int new_count = 0;
        for (int i = 0; i < MAX_FAILED_TIMESTAMPS; i++) {
            if (entry->timestamps[i] >= oldest_valid) {
                if (new_count != i) {
                    entry->timestamps[new_count] = entry->timestamps[i];
                }
                new_count++;
            }
        }
        entry->count = new_count;
    }

    /* Check if exceeded threshold - 使用传入参数而非全局 cfg */
    unsigned int recent_fails = count_recent(entry, findtime, max_retries);
    if (recent_fails >= max_retries) {
        syslog(LOG_WARNING, "firewall: IP %s exceeded %d failures in %d seconds, banning",
               ip, recent_fails, findtime);
        if (ban_ip(ip) == 0) {
            remove_entry(ip);
            syslog(LOG_INFO, "firewall: Successfully banned IP %s after %d failed attempts",
                   ip, recent_fails);
        } else {
            syslog(LOG_ERR, "firewall: Failed to ban IP %s after %d failed attempts, keeping entry for retry",
                   ip, recent_fails);
        }
    } else {
        syslog(LOG_DEBUG, "firewall: IP %s has %d failed attempts in %d seconds",
               ip, recent_fails, findtime);
    }
}

/* Secure procfs file operation helper */
static int secure_procfs_write(const char *path, const char *data, size_t data_len) {
    int fd;
    ssize_t written;
    size_t total_written = 0;

    // Validate inputs
    if (!path || !data || data_len == 0) {
        syslog(LOG_ERR, "firewall: Invalid parameters to secure_procfs_write");
        return -1;
    }

    // Check data length to prevent excessively long writes
    if (data_len > 256) {  // Reasonable limit for IP addresses
        syslog(LOG_ERR, "firewall: Data too long for procfs write (%zu bytes)", data_len);
        return -1;
    }

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "firewall: Failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    // Write data in a controlled manner
    while (total_written < data_len) {
        written = write(fd, data + total_written, data_len - total_written);
        if (written < 0) {
            if (errno == EINTR) {
                continue;  // Interrupted, try again
            } else {
                syslog(LOG_ERR, "firewall: Failed to write to %s: %s", path, strerror(errno));
                close(fd);
                return -1;
            }
        }
        total_written += written;
    }

    // Close file descriptor
    if (close(fd) < 0) {
        syslog(LOG_WARNING, "firewall: Failed to close %s: %s", path, strerror(errno));
        return -1;  // Note: Still return success since write succeeded
    }

    return 0;
}

/* Ban IP via procfs (IPv4 only) */
static int ban_ip(const char *ip)
{
    struct in_addr addr4;
    size_t ip_len;
    char ip_with_newline[INET_ADDRSTRLEN + 2];  // +1 for \n, +1 for \0

    // Validate input IP format before attempting to ban
    if (!ip) {
        syslog(LOG_ERR, "firewall: NULL IP address provided to ban_ip");
        return -1;
    }

    ip_len = strlen(ip);
    if (ip_len == 0 || ip_len >= INET_ADDRSTRLEN) {
        syslog(LOG_ERR, "firewall: Invalid IP length %zu in ban_ip", ip_len);
        return -1;
    }

    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        syslog(LOG_ERR, "firewall: Invalid IPv4 address format: %s", ip);
        return -1;
    }

    // Additional validation: reject invalid IPv4 IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4 (multicast)
        syslog(LOG_ERR, "firewall: Attempt to ban invalid IPv4: %s", ip);
        return -1;
    }

    // Prepare data with newline for writing
    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", ip);

    // Use secure write function
    if (secure_procfs_write(ADD_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
        syslog(LOG_ERR, "firewall: Failed to write to %s", ADD_BAN_PATH);
        return -1;
    }

    syslog(LOG_INFO, "firewall: Banned IP %s", ip);
    return 0;
}

/* Unban IP via procfs (used for manual unban) (IPv4 only) */
__attribute__((unused))
static int unban_ip(const char *ip)
{
    struct in_addr addr4;
    char ip_with_newline[INET_ADDRSTRLEN + 2];  // +1 for \n, +1 for \0

    // Validate input IP format before attempting to unban
    if (!ip) {
        syslog(LOG_ERR, "firewall: NULL IP address provided to unban_ip");
        return -1;
    }

    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        syslog(LOG_ERR, "firewall: Invalid IPv4 address format: %s", ip);
        return -1;
    }

    // Additional validation: reject invalid IPv4 IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4 (multicast)
        syslog(LOG_ERR, "firewall: Attempt to unban invalid IPv4: %s", ip);
        return -1;
    }

    // Prepare data with newline for writing
    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", ip);

    // Use secure write function
    if (secure_procfs_write(REMOVE_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
        syslog(LOG_ERR, "firewall: Failed to write to %s", REMOVE_BAN_PATH);
        return -1;
    }

    syslog(LOG_INFO, "firewall: Unbanned IP %s", ip);
    return 0;
}

/* Cleanup expired bans and partial line buffer (optional, kernel handles this) */
static void cleanup_expired_bans(void)
{
    /* Kernel module handles automatic cleanup via timer */
    /* This function is placeholder for future sync logic */

    /* Also clean up the partial line buffer periodically to prevent accumulation */
    cleanup_partial_line_buffer();
}

/* Daemonize process */
static void daemonize_process(void)
{
    pid_t pid;

    /* First fork */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* Parent exits - use _exit to avoid flushing stdio buffers in forked child */
        _exit(EXIT_SUCCESS);
    }

    /* Create new session */
    if (setsid() < 0) {
        perror("setsid");
        exit(EXIT_FAILURE);
    }

    /* Temporarily ignore SIGHUP during daemonization to prevent accidental reloads */
    struct sigaction sa_ignore;
    memset(&sa_ignore, 0, sizeof(sa_ignore));
    sa_ignore.sa_handler = SIG_IGN;
    sigemptyset(&sa_ignore.sa_mask);
    sa_ignore.sa_flags = 0;
    sigaction(SIGHUP, &sa_ignore, NULL);

    /* Second fork */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        /* First child exits - use _exit to avoid flushing stdio buffers in forked child */
        _exit(EXIT_SUCCESS);
    }

    /* Re-enable SIGHUP handler after daemonization is complete, so config reload works */
    struct sigaction sa_restore;
    memset(&sa_restore, 0, sizeof(sa_restore));
    sa_restore.sa_handler = signal_handler;
    sigemptyset(&sa_restore.sa_mask);
    sa_restore.sa_flags = 0;
    sigaction(SIGHUP, &sa_restore, NULL);

    /* Change working directory */
    if (chdir("/") < 0) {
        perror("chdir");
    }

    /* Redirect standard file descriptors to /dev/null */
    int devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO) {
            close(devnull);
        }
    }
}

/* Setup inotify monitoring */
static int setup_inotify(void)
{
    inotify_fd = inotify_init1(IN_CLOEXEC);  /* Use IN_CLOEXEC to prevent fd leak to child processes */
    if (inotify_fd < 0) {
        syslog(LOG_ERR, "firewall: Failed to initialize inotify: %s",
               strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(inotify_fd, F_GETFL);
    if (flags == -1) {
        syslog(LOG_ERR, "firewall: Failed to get fcntl flags for inotify: %s",
               strerror(errno));
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }
    if (fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        syslog(LOG_ERR, "firewall: Failed to set inotify non-blocking: %s",
               strerror(errno));
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }

    /* Add watches for each log file */
    for (int i = 0; i < cfg.log_count; i++) {
        struct stat st;

        /* Initialize file state - use explicit initialization instead of memset
         * to preserve wd field (which should be -1 before adding watch) */
        file_states[i].path[0] = '\0';
        file_states[i].offset = 0;
        file_states[i].inode = 0;
        file_states[i].wd = -1;  /* Mark as not watching yet */

        strncpy(file_states[i].path, cfg.log_files[i], sizeof(file_states[i].path) - 1);
        file_states[i].path[sizeof(file_states[i].path) - 1] = '\0';  /* Ensure null termination */

        /* Get initial inode */
        if (stat(cfg.log_files[i], &st) == 0) {
            file_states[i].inode = st.st_ino;
            file_states[i].offset = st.st_size;
            syslog(LOG_INFO, "firewall: Initial offset for %s: %ld bytes",
                   cfg.log_files[i], (long)file_states[i].offset);
        }

        /* Watch for modifications, moves, deletes */
        file_states[i].wd = inotify_add_watch(inotify_fd, cfg.log_files[i],
            IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
        if (file_states[i].wd < 0) {
            syslog(LOG_WARNING, "firewall: Failed to watch %s: %s",
                   cfg.log_files[i], strerror(errno));

            /* Roll back: remove previously added watches */
            for (int j = 0; j < i; j++) {
                if (file_states[j].wd >= 0) {
                    inotify_rm_watch(inotify_fd, file_states[j].wd);
                    file_states[j].wd = -1;
                }
            }
            /* Close inotify_fd to prevent leak */
            close(inotify_fd);
            inotify_fd = -1;
            return -1;
        } else {
            syslog(LOG_INFO, "firewall: Watching %s (wd=%d)", cfg.log_files[i], file_states[i].wd);
        }
    }

    return 0;
}

/* Static buffer for storing partial lines between reads */
static char partial_line_buffer[8192];  /* Increased buffer size to handle longer lines */
static size_t partial_line_len = 0;
static pthread_mutex_t partial_line_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper: Process a single complete log line.
 * Extracts IP and handles failed login attempt.
 * Called with null-terminated line in `line`. */
static void process_single_line(const char *line, const char *log_path,
                                unsigned int max_retries, unsigned int findtime)
{
    if (!line || strlen(line) == 0)
        return;

    /* Skip extremely long lines */
    size_t len = strlen(line);
    if (len >= 8192) {
        syslog(LOG_WARNING, "firewall: Line too long (%zu bytes) in %s, skipping", len, log_path);
        return;
    }

    char ip[INET_ADDRSTRLEN];
    if (extract_and_validate_ip(line, ip, sizeof(ip))) {
        handle_failed_attempt(ip, max_retries, findtime);
    }
}

/* Helper: Process all complete lines in a buffer.
 * `data` points to the buffer, `len` is the data length.
 * Updates `*consumed` to the number of bytes consumed (up to and including last newline).
 * Any remaining data after the last newline is left for the caller to handle as partial.
 * NOTE: This function may temporarily modify `data` to null-terminate lines. */
static void process_lines_in_buffer(char *data, size_t len, const char *log_path, size_t *consumed,
                                    unsigned int max_retries, unsigned int findtime)
{
    char *line_start = data;
    char *line_end;
    size_t remaining = len;

    *consumed = 0;

    while (remaining > 0 && (line_end = memchr(line_start, '\n', remaining)) != NULL) {
        size_t line_len = line_end - line_start;

        if (line_len >= 8192) {
            syslog(LOG_WARNING, "firewall: Extremely long line (%zu bytes) in %s, skipping",
                   line_len, log_path);
        } else {
            /* Temporarily null-terminate for processing */
            char saved = *line_end;
            /* Safe: line_len < 8192, and data is within caller's buffer */
            *line_end = '\0';
            process_single_line(line_start, log_path, max_retries, findtime);
            *line_end = saved;
        }

        /* Move past this line */
        size_t advance = line_len + 1;  /* +1 for newline */
        line_start += advance;
        remaining -= advance;
    }

    *consumed = len - remaining;
}

/* Helper: Store remaining data as partial line (thread-safe).
 * If partial buffer would overflow, processes accumulated data and resets. */
static void store_partial_line(const char *data, size_t len, const char *log_path,
                               unsigned int max_retries, unsigned int findtime)
{
    if (len == 0)
        return;

    if (len >= sizeof(partial_line_buffer)) {
        syslog(LOG_WARNING, "firewall: Partial line too long (%zu bytes) in %s, discarding",
               len, log_path);
        pthread_mutex_lock(&partial_line_mutex);
        partial_line_len = 0;
        pthread_mutex_unlock(&partial_line_mutex);
        return;
    }

    pthread_mutex_lock(&partial_line_mutex);

    /* Check if adding this data would overflow */
    if (partial_line_len + len >= sizeof(partial_line_buffer)) {
        /* Buffer would overflow - process accumulated data and replace with new data */
        size_t old_len = partial_line_len;
        char temp[sizeof(partial_line_buffer)];

        if (old_len > 0 && old_len < sizeof(temp)) {
            memcpy(temp, partial_line_buffer, old_len);
            temp[old_len] = '\0';
            process_single_line(temp, log_path, max_retries, findtime);
        }

        /* Store new data */
        memcpy(partial_line_buffer, data, len);
        partial_line_len = len;
    } else {
        /* Safe to append */
        memcpy(partial_line_buffer + partial_line_len, data, len);
        partial_line_len += len;
    }

    /* Ensure null termination */
    if (partial_line_len < sizeof(partial_line_buffer)) {
        partial_line_buffer[partial_line_len] = '\0';
    }

    pthread_mutex_unlock(&partial_line_mutex);
}

/* Helper: Process accumulated partial line buffer (thread-safe).
 * Drains the partial buffer and processes its content. */
static void flush_partial_line(const char *log_path, unsigned int max_retries, unsigned int findtime)
{
    size_t old_len = 0;
    char temp[sizeof(partial_line_buffer)];

    pthread_mutex_lock(&partial_line_mutex);
    if (partial_line_len > 0) {
        old_len = partial_line_len;
        if (old_len >= sizeof(temp))
            old_len = sizeof(temp) - 1;
        memcpy(temp, partial_line_buffer, old_len);
        temp[old_len] = '\0';
        partial_line_len = 0;
    }
    pthread_mutex_unlock(&partial_line_mutex);

    if (old_len > 0) {
        syslog(LOG_DEBUG, "firewall: Flushing partial line buffer with %zu bytes from %s", old_len, log_path);
        process_single_line(temp, log_path, max_retries, findtime);
    }
}

/* Process new lines from log file starting from tracked offset */
static void process_new_lines(int idx)
{
    int fd = -1;
    struct stat st;
    off_t current_offset;
    char buffer[8192];
    ssize_t bytes_read;
    int ret = 0;
    const char *log_path;
    /* 在函数入口处读取配置 - 避免在数据处理路径中访问全局 cfg */
    unsigned int max_retries, findtime;
    pthread_mutex_lock(&config_mutex);
    max_retries = cfg.max_retries;
    findtime = cfg.findtime;
    pthread_mutex_unlock(&config_mutex);

    /* Validate idx parameter */
    if (idx < 0 || idx >= MAX_LOG_FILES) {
        syslog(LOG_ERR, "firewall: Invalid index %d to process_new_lines", idx);
        return;
    }

    log_path = file_states[idx].path;

    fd = open(log_path, O_RDONLY);
    if (fd < 0) {
        syslog(LOG_ERR, "firewall: Failed to open %s: %s", log_path, strerror(errno));
        goto cleanup;
    }

    /* Check if file was rotated (inode changed or size decreased) */
    if (fstat(fd, &st) == 0) {
        if (file_states[idx].inode != 0 && st.st_ino != file_states[idx].inode) {
            syslog(LOG_INFO, "firewall: Log file rotated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            flush_partial_line(log_path, max_retries, findtime);
        } else if (st.st_size < file_states[idx].offset) {
            syslog(LOG_INFO, "firewall: Log file truncated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            flush_partial_line(log_path, max_retries, findtime);
        }
    }

    /* Seek to last known offset */
    if (file_states[idx].offset > 0) {
        if (lseek(fd, file_states[idx].offset, SEEK_SET) == (off_t)-1) {
            syslog(LOG_ERR, "firewall: Failed to seek in %s: %s", log_path, strerror(errno));
            ret = -1;
            goto cleanup;
        }
    }

    /* Read and process data in chunks */
    current_offset = file_states[idx].offset;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  /* Ensure null termination for safety */

        /* 修复问题3和问题5：使用堆分配代替栈分配，并在锁内复制数据 */
        size_t partial_len = 0;
        char *local_partial = NULL;
        char *combined = NULL;

        /* 先在锁内复制 partial line 数据 */
        pthread_mutex_lock(&partial_line_mutex);
        partial_len = partial_line_len;
        if (partial_len > 0 && partial_len < sizeof(partial_line_buffer)) {
            local_partial = malloc(partial_len + 1);
            if (local_partial) {
                memcpy(local_partial, partial_line_buffer, partial_len);
                local_partial[partial_len] = '\0';
            }
        }
        pthread_mutex_unlock(&partial_line_mutex);

        /* 在锁外处理数据 - 避免长时间持有锁 */
        if (local_partial && partial_len > 0) {
            /* 有 partial line 数据，需要合并处理 */
            /* 修复问题3：使用堆分配避免大栈帧 */
            combined = malloc(partial_len + (size_t)bytes_read + 1);
            if (!combined) {
                syslog(LOG_ERR, "firewall: Out of memory allocating combined buffer");
                free(local_partial);
                /* 丢弃 partial 数据，直接处理新数据 */
                size_t consumed = 0;
                process_lines_in_buffer(buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);
                if (consumed < (size_t)bytes_read) {
                    store_partial_line(buffer + consumed, (size_t)bytes_read - consumed, log_path, max_retries, findtime);
                }
                current_offset += bytes_read;
                continue;
            }

            memcpy(combined, local_partial, partial_len);
            memcpy(combined + partial_len, buffer, bytes_read);
            combined[partial_len + (size_t)bytes_read] = '\0';
            free(local_partial);

            size_t total_len = partial_len + (size_t)bytes_read;

            /* 清除已消费的 partial line */
            pthread_mutex_lock(&partial_line_mutex);
            partial_line_len = 0;
            pthread_mutex_unlock(&partial_line_mutex);

            /* Process complete lines */
            size_t consumed = 0;
            process_lines_in_buffer(combined, total_len, log_path, &consumed, max_retries, findtime);

            /* Store any remaining data as new partial line */
            if (consumed < total_len) {
                store_partial_line(combined + consumed, total_len - consumed, log_path, max_retries, findtime);
            }

            free(combined);
        } else {
            /* No partial line - process buffer directly */
            if (local_partial) free(local_partial);

            size_t consumed = 0;
            process_lines_in_buffer(buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);

            if (consumed < (size_t)bytes_read) {
                store_partial_line(buffer + consumed, (size_t)bytes_read - consumed, log_path, max_retries, findtime);
            }
        }

        /* Prevent integer overflow when updating offset */
        if (current_offset > SSIZE_MAX - bytes_read) {
            syslog(LOG_ERR, "firewall: Integer overflow in file offset calculation");
            ret = -1;
            goto cleanup;
        }
        current_offset += bytes_read;
    }

    if (bytes_read < 0) {
        syslog(LOG_WARNING, "firewall: Read error in %s: %s", log_path, strerror(errno));
        ret = -1;
        goto cleanup;
    }

    /* Update offset */
    file_states[idx].offset = current_offset;

cleanup:
    if (fd >= 0) {
        close(fd);
        fd = -1;
    }
    if (ret < 0) {
        syslog(LOG_ERR, "firewall: Failed to process %s", log_path);
    }
}

/* Function to periodically clean up partial line buffer to prevent accumulation */
static void cleanup_partial_line_buffer(void)
{
    /* 使用默认配置值进行清理 - 这些值仅在清理时使用，不影响实际封禁逻辑 */
    flush_partial_line("periodic_cleanup", DEFAULT_MAX_RETRIES, DEFAULT_FINDTIME);
}

/* Handle log file rotation */
static void handle_log_rotation(int idx)
{
    struct stat st;
    /* 读取配置 - 避免直接访问全局 cfg */
    unsigned int max_retries, findtime;
    pthread_mutex_lock(&config_mutex);
    max_retries = cfg.max_retries;
    findtime = cfg.findtime;
    pthread_mutex_unlock(&config_mutex);

    /* Check if file still exists */
    if (stat(file_states[idx].path, &st) != 0) {
        syslog(LOG_WARNING, "firewall: Log file disappeared: %s",
               file_states[idx].path);
        file_states[idx].offset = 0;
        flush_partial_line(file_states[idx].path, max_retries, findtime);
        return;
    }

    /* Check if inode changed (file was rotated) */
    if (st.st_ino != file_states[idx].inode) {
        syslog(LOG_INFO, "firewall: Log file rotated: %s", file_states[idx].path);
        file_states[idx].inode = st.st_ino;
        file_states[idx].offset = 0;

        /* Clean up partial line buffer on rotation */
        flush_partial_line(file_states[idx].path, max_retries, findtime);

        /* Re-add watch if needed */
        if (file_states[idx].wd >= 0) {
            inotify_rm_watch(inotify_fd, file_states[idx].wd);
        }
        file_states[idx].wd = inotify_add_watch(inotify_fd, file_states[idx].path,
            IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
        if (file_states[idx].wd < 0) {
            syslog(LOG_ERR, "firewall: Failed to re-add watch for %s: %s",
                   file_states[idx].path, strerror(errno));
            file_states[idx].wd = -1;
        } else {
            syslog(LOG_INFO, "firewall: Re-added watch for %s (wd=%d)",
                   file_states[idx].path, file_states[idx].wd);
        }
    }
}

/* Main monitoring loop */
static void monitor_loop(void)
{
    char buffer[EVENT_BUF_LEN];

    syslog(LOG_INFO, "firewall: Starting monitoring loop");

    while (running) {
        fd_set read_fds;
        struct timeval tv;
        int current_interval;

        /* 读取配置需要加锁 - 防止与 SIGHUP 配置重载并发 */
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
            syslog(LOG_ERR, "firewall: select error: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* Timeout - periodic cleanup */
            cleanup_expired_bans();

            /* Check if config reload was requested */
            if (reload_config) {
                syslog(LOG_INFO, "firewall: Reloading configuration...");
                reload_config = 0;

                if (cfg.config_file) {
                    unsigned int old_max_retries, old_findtime, old_ban_time;
                    int old_interval;

                    /* 保存旧配置的关键值用于变更检测（parse_config_file 已内部处理回滚） */
                    pthread_mutex_lock(&config_mutex);
                    old_max_retries = cfg.max_retries;
                    old_findtime = cfg.findtime;
                    old_ban_time = cfg.ban_time;
                    old_interval = cfg.interval;
                    pthread_mutex_unlock(&config_mutex);

                    /* 解析配置文件（parse_config_file 内部处理失败回滚） */
                    if (parse_config_file(cfg.config_file) < 0) {
                        syslog(LOG_ERR, "firewall: Failed to reload configuration from %s", cfg.config_file);
                    } else {
                        /* Configuration successfully reloaded */
                        syslog(LOG_INFO, "firewall: Configuration reloaded successfully");

                        /* 修复问题2：重新设置 inotify watches */
                        if (inotify_fd >= 0) {
                            /* 移除旧 watches */
                            for (int i = 0; i < cfg.log_count; i++) {
                                if (file_states[i].wd >= 0) {
                                    inotify_rm_watch(inotify_fd, file_states[i].wd);
                                    file_states[i].wd = -1;
                                }
                                /* 重置文件状态 */
                                file_states[i].offset = 0;
                                file_states[i].inode = 0;
                                file_states[i].path[0] = '\0';
                            }
                            close(inotify_fd);
                            inotify_fd = -1;
                        }

                        /* 重置文件状态 */
                        for (int i = 0; i < cfg.log_count; i++) {
                            file_states[i].wd = -1;
                            file_states[i].offset = 0;
                            file_states[i].inode = 0;
                            file_states[i].path[0] = '\0';
                        }

                        /* 重新设置 inotify */
                        if (setup_inotify() < 0) {
                            syslog(LOG_ERR, "firewall: Failed to re-setup inotify after config reload");
                            running = 0;  /* 安全退出 */
                        }

                        /* Check for changes and apply them */
                        pthread_mutex_lock(&config_mutex);
                        if (old_max_retries != cfg.max_retries) {
                            syslog(LOG_INFO, "firewall: max_retries changed from %u to %u",
                                   old_max_retries, cfg.max_retries);
                        }
                        if (old_findtime != cfg.findtime) {
                            syslog(LOG_INFO, "firewall: findtime changed from %u to %u",
                                   old_findtime, cfg.findtime);
                        }
                        if (old_ban_time != cfg.ban_time) {
                            syslog(LOG_INFO, "firewall: ban_time changed from %u to %u",
                                   old_ban_time, cfg.ban_time);
                        }
                        if (old_interval != cfg.interval) {
                            syslog(LOG_INFO, "firewall: interval changed from %d to %d",
                                   old_interval, cfg.interval);
                        }
                        pthread_mutex_unlock(&config_mutex);
                    }
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
                syslog(LOG_ERR, "firewall: inotify read error: %s",
                       strerror(errno));
            }
            continue;
        }

        /* Process events */
        size_t i = 0;
        while (i < (size_t)len) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            /* Validate event structure size and prevent integer overflow */
            if (sizeof(struct inotify_event) > (size_t)len - i) {
                syslog(LOG_ERR, "firewall: Invalid inotify event structure size");
                break;
            }

            /* Additional boundary check: ensure event->len is within reasonable bounds */
            if (event->len > EVENT_BUF_LEN) {
                syslog(LOG_WARNING, "firewall: inotify event length too large, skipping (len=%u, max=%d)",
                       event->len, (int)EVENT_BUF_LEN);
                break;
            }

            /* Verify event->len doesn't cause buffer overflow */
            if (sizeof(struct inotify_event) + event->len > (size_t)(len - i)) {
                syslog(LOG_WARNING, "firewall: inotify event too large for remaining buffer, skipping");
                break;
            }

            /* Additional safety check: ensure we don't have an unexpectedly large event length */
            if (event->len > 1024) {  /* Most inotify events have small names */
                syslog(LOG_WARNING, "firewall: Suspiciously large inotify event length, skipping (len=%u)", event->len);
                /* Calculate next position safely even with large event->len */
                size_t next_pos = i + sizeof(struct inotify_event) + event->len;
                if (next_pos < i) {  // Overflow check
                    syslog(LOG_ERR, "firewall: Integer overflow detected in inotify processing");
                    break;
                }
                i = next_pos;
                continue;  // Skip processing this suspicious event but continue with others
            }

            if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                /* File was modified or created - find matching file */
                pthread_mutex_lock(&config_mutex);
                for (int j = 0; j < cfg.log_count; j++) {
                    if (event->wd == file_states[j].wd) {
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
                for (int j = 0; j < cfg.log_count; j++) {
                    if (event->wd == file_states[j].wd) {
                        syslog(LOG_INFO, "firewall: Log file removed: %s", file_states[j].path);
                        file_states[j].wd = -1;
                        break;
                    }
                }
                pthread_mutex_unlock(&config_mutex);
            }

            /* Advance position with overflow check */
            size_t next_pos = i + sizeof(struct inotify_event) + event->len;
            if (next_pos < i) {  // Overflow check
                syslog(LOG_ERR, "firewall: Integer overflow detected in inotify processing");
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

/* Cleanup resources */
static void cleanup(void)
{
    syslog(LOG_INFO, "firewall: Cleaning up");

    /* Free regex patterns */
    free_log_patterns();

    /* Remove inotify watches */
    if (inotify_fd >= 0) {
        for (int i = 0; i < cfg.log_count; i++) {
            if (file_states[i].wd >= 0) {
                /* Only try to remove watch if the inotify_fd is still valid */
                if (inotify_rm_watch(inotify_fd, file_states[i].wd) < 0) {
                    syslog(LOG_WARNING, "firewall: Failed to remove watch for %s: %s",
                           file_states[i].path, strerror(errno));
                }
                file_states[i].wd = -1;  /* Mark as removed */
            }
        }
        if (close(inotify_fd) < 0) {
            syslog(LOG_WARNING, "firewall: Failed to close inotify fd: %s", strerror(errno));
        }
        inotify_fd = -1;
    }

    /* Free config */
    for (int i = 0; i < cfg.log_count; i++) {
        if (cfg.log_files[i]) {
            free(cfg.log_files[i]);
            cfg.log_files[i] = NULL;  /* Prevent double-free */
        }
    }

    /* Free failed table and hash table */
    struct failed_entry *entry = failed_table;
    while (entry) {
        struct failed_entry *next = entry->next;
        free(entry);
        entry = next;
    }

    /* Clear hash table pointers */
    memset(failed_hash_table, 0, sizeof(failed_hash_table));

    /* Destroy mutex for partial line buffer */
    pthread_mutex_destroy(&partial_line_mutex);

    closelog();
}

/* Initialize precompiled regex patterns for log parsing */
static int init_log_patterns(void)
{
    int ret;

    /*
     * SSH failed password pattern - with improved security
     * Capture groups:
     *   [0] = full match
     *   [1] = "invalid user " (optional)
     *   [2] = IP address  ← we use this
     * Example: "Failed password for invalid user admin from 192.168.1.100"
     * Fixed: Added bounded repetition to prevent catastrophic backtracking
     */
    memset(&sshd_regex, 0, sizeof(sshd_regex));  // Initialize to zero to prevent undefined behavior
    ret = regcomp(&sshd_regex,
        "^Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
        REG_EXTENDED);  // REG_NOSUB removed: we need capture groups to extract IP addresses
    if (ret) {
        char errbuf[256];
        regerror(ret, &sshd_regex, errbuf, sizeof(errbuf));
        syslog(LOG_ERR, "firewall: Failed to compile sshd regex: %s", errbuf);
        return -1;
    }

    /*
     * vsftpd FAIL LOGIN pattern - with improved security
     * Capture groups:
     *   [0] = full match
     *   [1] = IP address  ← we use this
     * Example: "FAIL LOGIN: client=192.168.1.100"
     * Fixed: Added bounded repetition to prevent catastrophic backtracking
     */
    memset(&vsftpd_regex, 0, sizeof(vsftpd_regex));  // Initialize to zero to prevent undefined behavior
    ret = regcomp(&vsftpd_regex,
        "^FAIL LOGIN: client=([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
        REG_EXTENDED);  // REG_NOSUB removed: we need capture groups to extract IP addresses
    if (ret) {
        char errbuf[256];
        regerror(ret, &vsftpd_regex, errbuf, sizeof(errbuf));
        syslog(LOG_ERR, "firewall: Failed to compile vsftpd regex: %s", errbuf);
        regfree(&sshd_regex);
        return -1;
    }

    /*
     * nginx 401 Unauthorized pattern - with improved security
     * Capture groups:
     *   [0] = full match
     *   [1] = IP address  ← we use this
     * Example: "192.168.1.100 - - [01/Jan/2024:00:00:00] ... 401 Unauthorized"
     * Fixed: Replaced problematic patterns with safer alternatives to prevent backtracking
     */
    memset(&nginx_regex, 0, sizeof(nginx_regex));  // Initialize to zero to prevent undefined behavior
    ret = regcomp(&nginx_regex,
        "^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}) [^ ]{1,64} [^ ]{1,64} \\[[^\\]]{1,64}\\] \"[^\"]{1,256}\" 401",
        REG_EXTENDED);  // REG_NOSUB removed: we need capture groups to extract IP addresses
    if (ret) {
        char errbuf[256];
        regerror(ret, &nginx_regex, errbuf, sizeof(errbuf));
        syslog(LOG_ERR, "firewall: Failed to compile nginx regex: %s", errbuf);
        regfree(&sshd_regex);
        regfree(&vsftpd_regex);
        return -1;
    }

    regex_compiled = 1;
    syslog(LOG_INFO, "firewall: Log patterns compiled successfully");
    return 0;
}

/* Free precompiled regex patterns */
static void free_log_patterns(void)
{
    if (regex_compiled) {
        regfree(&sshd_regex);
        regfree(&vsftpd_regex);
        regfree(&nginx_regex);
        regex_compiled = 0;
    }
}

/* Enhanced path validation function to prevent path traversal attacks */
static int validate_and_normalize_path(const char *input_path) {
    /* Basic checks */
    if (!input_path || strlen(input_path) == 0) {
        return -1;
    }

    /* Length check to prevent buffer overflow attacks */
    size_t input_len = strlen(input_path);
    if (input_len >= 512) {
        return -1;
    }

    /* Check for null bytes and other dangerous characters */
    for (size_t i = 0; i < input_len; i++) {
        if (input_path[i] == '\0') {
            return -1; /* embedded null byte */
        }
        /* Allow only alphanumeric, common path separators, and punctuation */
        if ((unsigned char)input_path[i] < 32) {
            return -1; /* control characters */
        }
        /* Reject certain characters that could be used in path traversal or command injection */
        if (input_path[i] == '|' || input_path[i] == ';' ||
            input_path[i] == '&' || input_path[i] == '`' ||
            input_path[i] == '$' || input_path[i] == '(' ||
            input_path[i] == ')' || input_path[i] == '{' ||
            input_path[i] == '}') {
            return -1; /* dangerous shell metacharacters */
        }
    }

    /* Path must start with / to be considered a valid absolute path */
    if (input_path[0] != '/') {
        return -1;
    }

    /* Check for obvious path traversal attempts */
    if (strstr(input_path, "../") ||
        strstr(input_path, "..\\") ||
        strstr(input_path, "/.." ) ||
        strstr(input_path, "..%00") ||  /* Null byte injection */
        strcasestr_custom(input_path, "%2e%2e%2f") ||  /* URL encoded ../ */
        strcasestr_custom(input_path, "%2e%2e%5c") ||  /* URL encoded ..\ */
        strstr(input_path, ".\\.") ||  /* Alternative Windows style */
        strstr(input_path, "..%2f") || /* Another URL encoded variant */
        strstr(input_path, "..%5c") || /* Another URL encoded variant */
        strstr(input_path, "%2e%2e%2e") || /* URL encoded ... */
        strstr(input_path, "%252e%252e%252f")) { /* Double-encoded ../ */
        return -1;
    }

    /* Additional check for double slashes that might be used in attacks */
    if (strstr(input_path, "//")) {
        /* Allow double slash only in protocol specifications like http:// */
        if (strstr(input_path, "://") == NULL) {
            return -1;
        }
    }

    /* 修复问题4：只拒绝真正的路径遍历攻击模式，允许合法的带点文件名 */
    /* 原来的检查 strstr(input_path, "/.") 会错误拒绝 /var/log/auth.log.1 等合法路径 */
    if (strstr(input_path, "/../") || strstr(input_path, "/..\\") ||
        (input_path[0] == '.' && input_path[1] == '.') ||
        strcmp(input_path, "..") == 0) {
        return -1;
    }

    /* 删除了过度严格的检查：
     * if (strstr(input_path, "./") ||
     *     strstr(input_path, "/.") ||
     *     strstr(input_path, "...")) {
     *     return -1;
     * }
     */

    /* More robust path traversal check: normalize the path */
    char normalized_path[512];
    strncpy(normalized_path, input_path, sizeof(normalized_path) - 1);
    normalized_path[sizeof(normalized_path) - 1] = '\0';

    /* Additional normalization to detect path traversal patterns */
    char *tmp = normalized_path;
    int depth = 0;
    while ((tmp = strchr(tmp, '/'))) {
        tmp++; // Move past the current slash
        if (tmp - normalized_path >= (ptrdiff_t)sizeof(normalized_path) - 1) {
            break; // Safety check to prevent pointer arithmetic issues
        }

        if (tmp - normalized_path >= 2 && strncmp(tmp - 2, "/../", 4) == 0) {
            return -1; // Pattern like "/../" detected
        }

        if (strncmp(tmp, "..", 2) == 0 &&
            (tmp[2] == '/' || tmp[2] == '\0' || tmp[2] == '\\')) {
            depth--; // Going up a directory level
            if (depth < 0) {
                return -1; // Attempt to go above root
            }
        } else if (tmp > normalized_path + 1 && *(tmp-2) != '.') { // Not part of ".." sequence
            depth++;
        }
    }

    /* Final check: ensure path resolves to a safe location */
    if (depth < 0) {
        return -1;
    }

    return 0;
}

/* Main entry point */
int main(int argc, char *argv[])
{
    int ret;

    /* Initialize file_states array with -1 for wd to distinguish from valid watch descriptors */
    for (int i = 0; i < MAX_LOG_FILES; i++) {
        file_states[i].wd = -1;
    }

    /* Parse configuration */
    ret = parse_config(argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Error: invalid configuration\n");
        return EXIT_FAILURE;
    }
    if (ret > 0) {
        /* Help was displayed */
        return EXIT_SUCCESS;
    }

    /* Initialize hash table */
    memset(failed_hash_table, 0, sizeof(failed_hash_table));

    /* Open syslog */
    openlog("firewall", LOG_PID | LOG_CONS, LOG_DAEMON);

    /* Check if procfs interfaces exist before proceeding */
    if (access(PROCFS_DIR, F_OK) != 0) {
        syslog(LOG_ERR, "firewall: Procfs directory %s does not exist. Is the kernel module loaded?",
               PROCFS_DIR);
        fprintf(stderr, "Error: Procfs directory %s does not exist. Is the kernel module loaded?\n",
                PROCFS_DIR);
        return EXIT_FAILURE;
    }

    if (access(ADD_BAN_PATH, F_OK) != 0) {
        syslog(LOG_ERR, "firewall: Add ban procfs interface %s does not exist", ADD_BAN_PATH);
        fprintf(stderr, "Error: Add ban procfs interface %s does not exist\n", ADD_BAN_PATH);
        return EXIT_FAILURE;
    }

    if (access(REMOVE_BAN_PATH, F_OK) != 0) {
        syslog(LOG_ERR, "firewall: Remove ban procfs interface %s does not exist", REMOVE_BAN_PATH);
        fprintf(stderr, "Error: Remove ban procfs interface %s does not exist\n", REMOVE_BAN_PATH);
        return EXIT_FAILURE;
    }

    if (access(BAN_LIST_PATH, F_OK) != 0) {
        syslog(LOG_ERR, "firewall: Ban list procfs interface %s does not exist", BAN_LIST_PATH);
        fprintf(stderr, "Error: Ban list procfs interface %s does not exist\n", BAN_LIST_PATH);
        return EXIT_FAILURE;
    }

    /* Initialize log patterns */
    if (init_log_patterns() < 0) {
        syslog(LOG_ERR, "firewall: Failed to initialize log patterns");
        cleanup();
        return EXIT_FAILURE;
    }

    /* Setup signal handlers */
    setup_signals();

    syslog(LOG_INFO, "firewall: Daemon starting up");
    syslog(LOG_INFO, "firewall: max_retries=%u, findtime=%u, ban_time=%u",
           cfg.max_retries, cfg.findtime, cfg.ban_time);

    /* Daemonize if requested */
    if (cfg.daemonize) {
        daemonize_process();
    }

    /* Setup inotify */
    if (setup_inotify() < 0) {
        syslog(LOG_ERR, "firewall: Failed to setup inotify");
        cleanup();
        return EXIT_FAILURE;
    }

    /* Run monitoring loop */
    monitor_loop();

    /* Cleanup */
    cleanup();
    syslog(LOG_INFO, "firewall: Daemon stopped");

    return EXIT_SUCCESS;
}