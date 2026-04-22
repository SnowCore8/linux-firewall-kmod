/*
 * firewall-daemon.c - User-space daemon for firewall kernel module
 *
 * Monitors log files for failed login attempts and automatically bans
 * offending IPs via the firewall kernel module procfs interface.
 *
 * Note: max_retries, findtime, and ban_time are configured via YAML config file.
 * the log analysis logic (how many failures within what time window trigger
 * a ban). These are NOT kernel module parameters - the kernel module only
 * handles the actual IP blocking based on its ban_table.
 *
 * Usage:
 *   sudo ./firewall-daemon [-c config.yaml] [-C config-dir] [--daemonize]
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
#include <stdatomic.h>
#include <stdbool.h>
#include <yaml.h>
#include <dirent.h>
#include <sys/stat.h>
#include "sqlite-persistent.h"

/* ============================================================================
 * Unified Logging System for Daemon
 * ============================================================================
 * All daemon logs use syslog with consistent "firewall: " prefix.
 * Standard error output is only used before syslog is initialized.
 * ========================================================================== */
#define daemon_log_err(fmt, ...) \
    syslog(LOG_ERR, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_warn(fmt, ...) \
    syslog(LOG_WARNING, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_info(fmt, ...) \
    syslog(LOG_INFO, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_debug(fmt, ...) \
    syslog(LOG_DEBUG, "firewall: " fmt, ##__VA_ARGS__)

/* Procfs paths */
#define PROCFS_DIR "/proc/firewall"
#define ADD_BAN_PATH PROCFS_DIR "/add_ban"
#define REMOVE_BAN_PATH PROCFS_DIR "/remove_ban"
#define PERMANENT_ADD_BAN_PATH PROCFS_DIR "/permanent_add_ban"
#define PERMANENT_REMOVE_BAN_PATH PROCFS_DIR "/permanent_remove_ban"
#define BAN_LIST_PATH PROCFS_DIR "/ban_list"

/* Default configuration */
#define DEFAULT_MAX_RETRIES 3
#define DEFAULT_FINDTIME 600      /* 10 minutes */
#define DEFAULT_BAN_TIME 600      /* 10 minutes */
#define DEFAULT_INTERVAL 1        /* Check interval in seconds */
#define DEFAULT_METRICS_PORT 9119  /* Prometheus metrics port */

/* Maximum failed attempts to track per IP */
#define MAX_FAILED_TIMESTAMPS 100

/* Maximum number of log files to monitor per jail */
#define MAX_LOG_FILES 10

/* Maximum number of jails */
#define MAX_JAILS 16

/* Event buffer size for inotify */
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

/* File state tracking for log rotation detection */
struct file_state {
    char path[512];
    off_t offset;
    ino_t inode;
    int wd;  /* inotify watch descriptor */
    int jail_idx;  /* Which jail this file belongs to */
};

/* Jail structure - isolated monitoring unit */
struct jail {
    char name[64];                    /* Jail name (sshd, nginx, etc.) */
    bool enabled;                     /* Whether this jail is active */
    char *log_files[MAX_LOG_FILES];   /* Log files for this jail */
    int log_count;                    /* Number of log files */
    char *regex_pattern;              /* Custom regex pattern (NULL = builtin) */
    regex_t compiled_regex;           /* Compiled regex */
    int regex_compiled;               /* Whether regex is compiled */
    unsigned int max_retries;         /* Max failures before ban */
    unsigned int findtime;            /* Time window for counting failures */
    unsigned int ban_time;            /* Ban duration */
    struct failed_entry *failed_table;/* Per-jail failed attempts */
    /* Hash table for faster lookup */
    struct failed_entry *failed_hash_table[256];
};

/* Global running flag */
static volatile sig_atomic_t running = 1;
static volatile sig_atomic_t reload_config = 0;  /* SIGHUP flag */

/* Global default configuration */
struct config {
    unsigned int default_max_retries; /* Default for new jails */
    unsigned int default_findtime;
    unsigned int default_ban_time;
    int daemonize;
    int interval;
    int metrics_port;       /* Prometheus metrics port (0 = disabled) */
    char *config_file;      /* Path to single configuration file for runtime updates */
    char *config_dir;       /* Path to configuration directory (auto-loads all .yaml/.yml) */
    char *permanent_db_path; /* SQLite database path for permanent bans (NULL = disabled) */
    int permanent_ban_enabled; /* Whether permanent bans are enabled */
    struct jail jails[MAX_JAILS]; /* All jails */
    int jail_count;
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
static int inotify_fd = -1;
/* File states array - sized for all jails' log files */
static struct file_state file_states[MAX_JAILS * MAX_LOG_FILES];

/* SQLite persistent banlist */
static sqlite_db_t *sqlite_db = NULL;

/* ============================================================================
 * Jail Management Functions
 * ============================================================================ */

/* Initialize jail with default values from global config */
static void init_jail_defaults(struct jail *j)
{
    j->enabled = true;
    j->log_count = 0;
    j->regex_pattern = NULL;
    j->regex_compiled = 0;
    memset(&j->compiled_regex, 0, sizeof(j->compiled_regex));
    j->max_retries = cfg.default_max_retries;
    j->findtime = cfg.default_findtime;
    j->ban_time = cfg.default_ban_time;
    j->failed_table = NULL;
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));

    for (int i = 0; i < MAX_LOG_FILES; i++) {
        j->log_files[i] = NULL;
    }
}

/* Free jail regex */
static void free_jail_regex(struct jail *j)
{
    if (j && j->regex_compiled) {
        regfree(&j->compiled_regex);
        j->regex_compiled = 0;
    }
}

/* Find existing jail or create new one */
static struct jail *find_or_create_jail(const char *name)
{
    /* Find existing jail */
    for (int i = 0; i < cfg.jail_count; i++) {
        if (strcmp(cfg.jails[i].name, name) == 0) {
            return &cfg.jails[i];
        }
    }

    /* Create new jail */
    if (cfg.jail_count >= MAX_JAILS) {
        daemon_log_warn("Max jails reached (%d), cannot create jail '%s'", MAX_JAILS, name);
        return NULL;
    }

    struct jail *j = &cfg.jails[cfg.jail_count++];
    init_jail_defaults(j);
    strncpy(j->name, name, sizeof(j->name) - 1);
    j->name[sizeof(j->name) - 1] = '\0';

    daemon_log_info("Created new jail: %s", name);
    return j;
}

/* Destroy a jail and free its resources */
static void destroy_jail(struct jail *j)
{
    if (!j) return;

    /* Free log files */
    for (int i = 0; i < j->log_count; i++) {
        if (j->log_files[i]) {
            free(j->log_files[i]);
            j->log_files[i] = NULL;
        }
    }
    j->log_count = 0;

    /* Free regex */
    free_jail_regex(j);
    if (j->regex_pattern) {
        free(j->regex_pattern);
        j->regex_pattern = NULL;
    }

    /* Free failed table */
    if (j->failed_table) {
        struct failed_entry *entry = j->failed_table;
        while (entry) {
            struct failed_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        j->failed_table = NULL;
    }

    /* Clear hash table */
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));

    daemon_log_info("Destroyed jail: %s", j->name);
}

/* Compile regex for a jail */
static int compile_jail_regex(struct jail *j)
{
    if (!j) return -1;

    /* Free existing regex if compiled */
    if (j->regex_compiled) {
        regfree(&j->compiled_regex);
        j->regex_compiled = 0;
    }

    /* Use jail's custom regex or built-in default */
    const char *pattern = (j->regex_pattern && strlen(j->regex_pattern) > 0) ?
        j->regex_pattern :
        "Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";

    int ret = regcomp(&j->compiled_regex, pattern, REG_EXTENDED);
    if (ret != 0) {
        char errbuf[256];
        regerror(ret, &j->compiled_regex, errbuf, sizeof(errbuf));
        daemon_log_err("Failed to compile regex for jail '%s': %s", j->name, errbuf);
        return -1;
    }

    j->regex_compiled = 1;
    daemon_log_debug("Compiled regex for jail '%s'", j->name);
    return 0;
}

/* Get global file_states index for a jail's log file */

static int get_global_file_state_index(int jail_idx, int file_idx)
{
    if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
        daemon_log_err("Invalid jail index: %d", jail_idx);
        return -1;
    }
    if (file_idx < 0 || file_idx >= cfg.jails[jail_idx].log_count) {
        daemon_log_err("Invalid file index for jail %d: %d", jail_idx, file_idx);
        return -1;
    }

    int global_idx = 0;
    for (int j = 0; j < jail_idx; j++) {
        global_idx += cfg.jails[j].log_count;
    }
    global_idx += file_idx;

    if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
        daemon_log_err("Global file index out of bounds: %d", global_idx);
        return -1;
    }

    return global_idx;
}

/* ============================================================================
 * Prometheus Statistics
 * ============================================================================
 * Thread-safe counters using atomic operations for monitoring and metrics.
 * ========================================================================== */
struct daemon_stats {
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

/* Cleanup all jail resources before config reload
 *
 * NOTE: failed_table and failed_hash_table share the same objects.
 * failed_table is the head of a linked list, while failed_hash_table
 * contains pointers to the same objects for O(1) lookup.
 * We iterate failed_table to free all objects exactly once, then
 * zero out failed_hash_table (which only contains dangling pointers
 * after the frees, but no ownership).
 * This is safe as long as we always add the same object to both structures.
 */
static void cleanup_all_jails(void)
{
    int old_count = cfg.jail_count;
    for (int i = 0; i < old_count; i++) {
        destroy_jail(&cfg.jails[i]);
        memset(&cfg.jails[i], 0, sizeof(struct jail));
    }
    cfg.jail_count = 0;
    daemon_log_info("All jails resources cleaned up");
}

/* Comparison function for qsort - sorting config file names */
static int compare_config_files(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* Function prototypes */
static void setup_signals(void);
static int parse_config_file(const char *config_path);
static int load_config_directory(const char *config_dir);
static int parse_config(int argc, char *argv[]);
static int extract_ip(const char *line, char *ip_out, size_t ip_size);
static int parse_log_line(struct jail *j, const char *line, char *ip_out, size_t ip_size);
static struct jail *find_or_create_jail(const char *name);
static void destroy_jail(struct jail *j);
static void init_jail_defaults(struct jail *j);
static int compile_jail_regex(struct jail *j);
static void free_jail_regex(struct jail *j);
static int get_global_file_state_index(int jail_idx, int file_idx);
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

/* HTTP exporter (defined in http-exporter.c) */
extern void *start_http_exporter(void *port);

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
            atomic_fetch_add(&daemon_stats.config_reloads, 1);
            break;
    }
}

/* Parse configuration file using libyaml - supports jail-based YAML format */
static int parse_config_file(const char *config_path)
{
    FILE *file;
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    int error = 0;

    /* Track parsing state for jail-based YAML */
    struct jail *current_jail = NULL;
    int in_jails_section = 0;
    int in_defaults_section = 0;
    int in_log_files_array = 0;
    char *current_key = NULL;
    char *current_jail_name = NULL;

    /* Extract config file directory for resolving relative paths */
    char config_dir[1024];
    strncpy(config_dir, config_path, sizeof(config_dir) - 1);
    config_dir[sizeof(config_dir) - 1] = '\0';
    char *last_slash = strrchr(config_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(config_dir, ".");
    }

    /* 获取配置锁 */
    pthread_mutex_lock(&config_mutex);

    /* Open config file */
    file = fopen(config_path, "r");
    if (!file) {
        daemon_log_warn("Cannot open config file: %s", config_path);
        pthread_mutex_unlock(&config_mutex);
        return -1;
    }

    daemon_log_info("Reading config file: %s", config_path);

    /* Initialize YAML parser */
    if (!yaml_parser_initialize(&parser)) {
        daemon_log_err("Failed to initialize YAML parser");
        fclose(file);
        pthread_mutex_unlock(&config_mutex);
        return -1;
    }

    yaml_parser_set_input_file(&parser, file);

    /* Parse YAML events */
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            daemon_log_err("YAML parse error: %s", parser.problem ? parser.problem : "unknown");
            error = 1;
            break;
        }

        switch (event.type) {
        case YAML_STREAM_START_EVENT:
        case YAML_DOCUMENT_START_EVENT:
            break;

        case YAML_STREAM_END_EVENT:
        case YAML_DOCUMENT_END_EVENT:
            done = 1;
            break;

        case YAML_SCALAR_EVENT: {
            char *value = (char *)event.data.scalar.value;

            if (in_defaults_section && current_key) {
                /* Parsing defaults section - set global defaults */
                if (strcmp(current_key, "max_retries") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 100) {
                        daemon_log_warn("Invalid default max_retries: %s", value);
                    } else {
                        cfg.default_max_retries = (unsigned int)val;
                        daemon_log_info("Default max_retries set to %u", cfg.default_max_retries);
                    }
                } else if (strcmp(current_key, "findtime") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                        daemon_log_warn("Invalid default findtime: %s", value);
                    } else {
                        cfg.default_findtime = (unsigned int)val;
                        daemon_log_info("Default findtime set to %u", cfg.default_findtime);
                    }
                } else if (strcmp(current_key, "ban_time") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 86400) {
                        daemon_log_warn("Invalid default ban_time: %s", value);
                    } else {
                        cfg.default_ban_time = (unsigned int)val;
                        daemon_log_info("Default ban_time set to %u", cfg.default_ban_time);
                    }
                } else if (strcmp(current_key, "interval") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 60) {
                        daemon_log_warn("Invalid default interval: %s", value);
                    } else {
                        cfg.interval = (int)val;
                        daemon_log_info("Default interval set to %d", cfg.interval);
                    }
                } else if (strcmp(current_key, "metrics_port") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 0 || val > 65535) {
                        daemon_log_warn("Invalid default metrics_port: %s", value);
                    } else {
                        cfg.metrics_port = (int)val;
                        daemon_log_info("Default metrics_port set to %d", cfg.metrics_port);
                    }
                } else if (strcmp(current_key, "daemonize") == 0) {
                    if (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0) {
                        cfg.daemonize = 1;
                    } else {
                        cfg.daemonize = 0;
                    }
                } else if (strcmp(current_key, "permanent_db_path") == 0) {
                    if (strlen(value) > 0) {
                        if (cfg.permanent_db_path) free(cfg.permanent_db_path);
                        /* Resolve relative path against config file directory */
                        if (value[0] == '/') {
                            cfg.permanent_db_path = strdup(value);
                        } else {
                            char full_path[1024];
                            snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, value);
                            cfg.permanent_db_path = strdup(full_path);
                        }
                        if (cfg.permanent_db_path) {
                            cfg.permanent_ban_enabled = 1;
                            daemon_log_info("Default permanent_db_path set to: %s", cfg.permanent_db_path);
                        }
                    }
                } else if (strcmp(current_key, "permanent_ban_enabled") == 0) {
                    cfg.permanent_ban_enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                }
                free(current_key);
                current_key = NULL;
            } else if (in_jails_section && current_jail_name && !in_log_files_array) {
                /* We're in a jail section - either this is a jail key or a jail property */
                if (!current_key) {
                    /* This is a property key for the current jail */
                    current_key = strdup(value);
                } else {
                    /* We have key-value pair for jail property */
                    /* Find or create jail if not already created */
                    if (!current_jail) {
                        current_jail = find_or_create_jail(current_jail_name);
                        if (!current_jail) {
                            daemon_log_warn("Failed to create jail '%s'", current_jail_name);
                            free(current_key);
                            current_key = NULL;
                            break;
                        }
                    }

                    if (strcmp(current_key, "enabled") == 0) {
                        current_jail->enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                        daemon_log_info("Jail '%s' enabled: %s", current_jail->name, value);
                    } else if (strcmp(current_key, "max_retries") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 100) {
                            daemon_log_warn("Invalid max_retries for jail '%s': %s", current_jail->name, value);
                        } else {
                            current_jail->max_retries = (unsigned int)val;
                            daemon_log_info("Jail '%s' max_retries set to %u", current_jail->name, current_jail->max_retries);
                        }
                    } else if (strcmp(current_key, "findtime") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                            daemon_log_warn("Invalid findtime for jail '%s': %s", current_jail->name, value);
                        } else {
                            current_jail->findtime = (unsigned int)val;
                            daemon_log_info("Jail '%s' findtime set to %u", current_jail->name, current_jail->findtime);
                        }
                    } else if (strcmp(current_key, "ban_time") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 86400) {
                            daemon_log_warn("Invalid ban_time for jail '%s': %s", current_jail->name, value);
                        } else {
                            current_jail->ban_time = (unsigned int)val;
                            daemon_log_info("Jail '%s' ban_time set to %u", current_jail->name, current_jail->ban_time);
                        }
                    } else if (strcmp(current_key, "regex") == 0) {
                        if (current_jail->regex_pattern) free(current_jail->regex_pattern);
                        current_jail->regex_pattern = strdup(value);
                        daemon_log_info("Jail '%s' regex set to: %s", current_jail->name, value);
                    }
                    free(current_key);
                    current_key = NULL;
                }
            } else if (in_log_files_array && current_jail) {
                /* Parsing log_files array for current jail */
                if (current_jail->log_count >= MAX_LOG_FILES) {
                    daemon_log_warn("Too many log files for jail '%s' (max %d)", current_jail->name, MAX_LOG_FILES);
                } else if (validate_and_normalize_path(value) < 0) {
                    daemon_log_warn("Invalid log file path for jail '%s': %s", current_jail->name, value);
                } else {
                    current_jail->log_files[current_jail->log_count] = strdup(value);
                    if (!current_jail->log_files[current_jail->log_count]) {
                        daemon_log_err("Out of memory allocating log file path");
                        error = 1;
                    } else {
                        daemon_log_info("Jail '%s' added log file: %s", current_jail->name, current_jail->log_files[current_jail->log_count]);
                        current_jail->log_count++;
                    }
                }
            } else if (current_key) {
                /* Top-level key-value pair (not in jails or defaults) */
                if (strcmp(current_key, "max_retries") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 100) {
                        cfg.default_max_retries = (unsigned int)val;
                        daemon_log_info("Config max_retries set to %u", cfg.default_max_retries);
                    }
                } else if (strcmp(current_key, "findtime") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 3600) {
                        cfg.default_findtime = (unsigned int)val;
                        daemon_log_info("Config findtime set to %u", cfg.default_findtime);
                    }
                } else if (strcmp(current_key, "ban_time") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 86400) {
                        cfg.default_ban_time = (unsigned int)val;
                        daemon_log_info("Config ban_time set to %u", cfg.default_ban_time);
                    }
                } else if (strcmp(current_key, "interval") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 60) {
                        cfg.interval = (int)val;
                        daemon_log_info("Config interval set to %d", cfg.interval);
                    }
                } else if (strcmp(current_key, "metrics_port") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 0 && val <= 65535) {
                        cfg.metrics_port = (int)val;
                        daemon_log_info("Config metrics_port set to %d", cfg.metrics_port);
                    }
                } else if (strcmp(current_key, "daemonize") == 0) {
                    cfg.daemonize = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                } else if (strcmp(current_key, "permanent_db_path") == 0) {
                    if (strlen(value) > 0) {
                        if (cfg.permanent_db_path) free(cfg.permanent_db_path);
                        /* Resolve relative path against config file directory */
                        if (value[0] == '/') {
                            cfg.permanent_db_path = strdup(value);
                        } else {
                            char full_path[1024];
                            snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, value);
                            cfg.permanent_db_path = strdup(full_path);
                        }
                        if (cfg.permanent_db_path) cfg.permanent_ban_enabled = 1;
                    }
                } else if (strcmp(current_key, "permanent_ban_enabled") == 0) {
                    cfg.permanent_ban_enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                } else {
                    daemon_log_warn("Ignoring unsupported top-level key: %s (jail format required)", current_key);
                }
                free(current_key);
                current_key = NULL;
            } else {
                /* This is a key without value yet */
                current_key = strdup(value);
            }
            break;
        }

        case YAML_SEQUENCE_START_EVENT: {
            if (current_key && strcmp(current_key, "log_files") == 0) {
                in_log_files_array = 1;
                free(current_key);
                current_key = NULL;
            }
            break;
        }

        case YAML_SEQUENCE_END_EVENT:
            in_log_files_array = 0;
            break;

        case YAML_MAPPING_START_EVENT: {
            if (current_key && strcmp(current_key, "jails") == 0) {
                in_jails_section = 1;
                free(current_key);
                current_key = NULL;
            } else if (current_key && strcmp(current_key, "defaults") == 0) {
                in_defaults_section = 1;
                free(current_key);
                current_key = NULL;
            } else if (in_jails_section && current_key) {
                /* Starting a new jail mapping */
                if (current_jail_name) free(current_jail_name);
                current_jail_name = current_key;
                current_jail = NULL;  /* Will be created when properties are parsed */
                current_key = NULL;
            }
            break;
        }

        case YAML_MAPPING_END_EVENT: {
            if (in_jails_section && !in_log_files_array) {
                /* End of a jail section - compile regex if pattern exists */
                if (current_jail_name && current_jail) {
                    if (current_jail->regex_pattern && strlen(current_jail->regex_pattern) > 0) {
                        compile_jail_regex(current_jail);
                    }
                    daemon_log_info("Finished parsing jail '%s': enabled=%d, log_count=%d, max_retries=%u",
                        current_jail->name, current_jail->enabled, current_jail->log_count, current_jail->max_retries);
                }
                if (current_jail_name) {
                    free(current_jail_name);
                    current_jail_name = NULL;
                }
                current_jail = NULL;
            } else if (in_defaults_section) {
                in_defaults_section = 0;
            }
            break;
        }

        case YAML_ALIAS_EVENT:
        case YAML_NO_EVENT:
            break;
        }

        yaml_event_delete(&event);

        if (error) break;
    }

    yaml_parser_delete(&parser);
    fclose(file);
    pthread_mutex_unlock(&config_mutex);

    /* Cleanup */
    if (current_key) free(current_key);
    if (current_jail_name) free(current_jail_name);

    return 0;
}

/* Load all .yaml/.yml files from a configuration directory
 * Files are loaded in alphabetical order, later files override earlier ones
 * for scalar values, and arrays are appended. */
static int load_config_directory(const char *config_dir)
{
    DIR *dir;
    struct dirent *entry;
    char **file_list = NULL;
    int file_count = 0;
    int file_capacity = 16;
    int ret = 0;
    const int MAX_CONFIG_FILES = 50;  /* Limit to prevent excessive file loading */

    dir = opendir(config_dir);
    if (!dir) {
        daemon_log_warn("Cannot open config directory: %s", config_dir);
        return -1;
    }

    daemon_log_info("Loading configuration directory: %s", config_dir);

    /* Allocate file list */
    file_list = malloc(file_capacity * sizeof(char *));
    if (!file_list) {
        daemon_log_err("Out of memory allocating file list");
        closedir(dir);
        return -1;
    }

    /* Collect all .yaml and .yml files */
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);

        /* Check for .yaml or .yml extension */
        if ((len > 5 && strcmp(name + len - 5, ".yaml") == 0) ||
            (len > 4 && strcmp(name + len - 4, ".yml") == 0)) {
            
            /* Enforce file limit */
            if (file_count >= MAX_CONFIG_FILES) {
                daemon_log_warn("Config file limit reached (%d), skipping: %s", MAX_CONFIG_FILES, name);
                continue;
            }
            
            /* Expand list if needed */
            if (file_count >= file_capacity) {
                file_capacity *= 2;
                char **new_list = realloc(file_list, file_capacity * sizeof(char *));
                if (!new_list) {
                    daemon_log_err("Out of memory expanding file list");
                    for (int i = 0; i < file_count; i++) free(file_list[i]);
                    free(file_list);
                    closedir(dir);
                    return -1;
                }
                file_list = new_list;
            }

            file_list[file_count] = strdup(name);
            if (!file_list[file_count]) {
                daemon_log_err("Out of memory allocating file name");
                for (int i = 0; i < file_count; i++) free(file_list[i]);
                free(file_list);
                closedir(dir);
                return -1;
            }
            file_count++;
        }
    }
    closedir(dir);

    if (file_count == 0) {
        daemon_log_warn("No .yaml/.yml files found in: %s", config_dir);
        free(file_list);
        return 0;
    }

    /* Sort files alphabet using qsort for better performance */
    qsort(file_list, (size_t)file_count, sizeof(char *), compare_config_files);

    /* Load each configuration file - each file can define independent jails */
    for (int i = 0; i < file_count; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, file_list[i]);

        daemon_log_info("Loading config file [%d/%d]: %s", i + 1, file_count, full_path);

        if (parse_config_file(full_path) < 0) {
            daemon_log_warn("Failed to load config file: %s (continuing with others)", full_path);
            /* Continue loading other files instead of failing completely */
        }
    }

    /* Log summary of loaded jails */
    pthread_mutex_lock(&config_mutex);
    daemon_log_info("Loaded %d jails from directory: %s", cfg.jail_count, config_dir);
    for (int i = 0; i < cfg.jail_count; i++) {
        daemon_log_info("  Jail[%d]: %s (enabled=%d, log_count=%d, max_retries=%u)",
            i, cfg.jails[i].name, cfg.jails[i].enabled, cfg.jails[i].log_count, cfg.jails[i].max_retries);
    }
    pthread_mutex_unlock(&config_mutex);

    /* Cleanup */
    for (int i = 0; i < file_count; i++) {
        free(file_list[i]);
    }
    free(file_list);

    return ret;
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
        daemon_log_err("Failed to setup SIGTERM handler: %s", strerror(errno));
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        daemon_log_err("Failed to setup SIGINT handler: %s", strerror(errno));
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        daemon_log_err("Failed to setup SIGHUP handler: %s", strerror(errno));
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        daemon_log_err("Failed to ignore SIGPIPE: %s", strerror(errno));
    }
}

/* Parse command line arguments */
static int parse_config(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},  /* Single config file */
        {"config-dir", required_argument, 0, 'C'},  /* Config directory (auto-loads all .yaml) */
        {"daemonize",  no_argument,       0, 'd'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Set defaults */
    cfg.default_max_retries = DEFAULT_MAX_RETRIES;
    cfg.default_findtime = DEFAULT_FINDTIME;
    cfg.default_ban_time = DEFAULT_BAN_TIME;
    cfg.daemonize = 0;
    cfg.interval = DEFAULT_INTERVAL;
    cfg.metrics_port = DEFAULT_METRICS_PORT;
    cfg.jail_count = 0;
    cfg.config_file = NULL;
    cfg.config_dir = NULL;
    cfg.permanent_db_path = NULL;
    cfg.permanent_ban_enabled = 0;

    /* Initialize jails */
    for (int i = 0; i < MAX_JAILS; i++) {
        cfg.jails[i].name[0] = '\0';
        cfg.jails[i].enabled = false;
        cfg.jails[i].log_count = 0;
        cfg.jails[i].regex_pattern = NULL;
        cfg.jails[i].regex_compiled = 0;
        cfg.jails[i].failed_table = NULL;
        memset(cfg.jails[i].failed_hash_table, 0, sizeof(cfg.jails[i].failed_hash_table));
        for (int j = 0; j < MAX_LOG_FILES; j++) {
            cfg.jails[i].log_files[j] = NULL;
        }
    }

    /* Default config directory: ./config/ relative to executable or /etc/firewall/config/ */
    const char *default_config_dirs[] = {
        "./config",
        "/etc/firewall/config",
        NULL
    };

    /* First pass: check for explicit config file or directory options */
    for (int i = 1; i < argc; i++) {
        /* Check for --config or -c (single file) */
        if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0) {
            char *config_path = (i + 1 < argc) ? argv[i + 1] : NULL;
            if (config_path) {
                cfg.config_file = strdup(config_path);
                if (!cfg.config_file) {
                    fprintf(stderr, "Error: out of memory allocating config file path\n");
                    return -1;
                }
                if (parse_config_file(config_path) < 0) {
                    fprintf(stderr, "Error: failed to parse config file: %s\n", config_path);
                    free(cfg.config_file);
                    cfg.config_file = NULL;
                    return -1;
                }
                break;
            }
        } else if (strncmp(argv[i], "--config=", 9) == 0) {
            const char *config_path = argv[i] + 9;
            cfg.config_file = strdup(config_path);
            if (!cfg.config_file) {
                fprintf(stderr, "Error: out of memory allocating config file path\n");
                return -1;
            }
            if (parse_config_file(config_path) < 0) {
                fprintf(stderr, "Error: failed to parse config file: %s\n", config_path);
                free(cfg.config_file);
                cfg.config_file = NULL;
                return -1;
            }
        }
        /* Check for --config-dir or -C (directory) */
        else if (strcmp(argv[i], "--config-dir") == 0 || strcmp(argv[i], "-C") == 0) {
            char *dir_path = (i + 1 < argc) ? argv[i + 1] : NULL;
            if (dir_path) {
                cfg.config_dir = strdup(dir_path);
                if (!cfg.config_dir) {
                    fprintf(stderr, "Error: out of memory allocating config dir path\n");
                    return -1;
                }
                if (load_config_directory(dir_path) < 0) {
                    fprintf(stderr, "Warning: failed to load config directory: %s\n", dir_path);
                    /* Non-fatal: continue without config */
                }
                break;
            }
        } else if (strncmp(argv[i], "--config-dir=", 13) == 0) {
            const char *dir_path = argv[i] + 13;
            cfg.config_dir = strdup(dir_path);
            if (!cfg.config_dir) {
                fprintf(stderr, "Error: out of memory allocating config dir path\n");
                return -1;
            }
            if (load_config_directory(dir_path) < 0) {
                fprintf(stderr, "Warning: failed to load config directory: %s\n", dir_path);
            }
        }
    }

    /* If no explicit config was provided, try default config directories */
    if (!cfg.config_file && !cfg.config_dir) {
        for (int i = 0; default_config_dirs[i] != NULL; i++) {
            if (access(default_config_dirs[i], F_OK) == 0) {
                cfg.config_dir = strdup(default_config_dirs[i]);
                if (!cfg.config_dir) {
                    fprintf(stderr, "Error: out of memory allocating config dir path\n");
                    return -1;
                }
                if (load_config_directory(default_config_dirs[i]) < 0) {
                    daemon_log_warn("No config files found in: %s", default_config_dirs[i]);
                    free(cfg.config_dir);
                    cfg.config_dir = NULL;
                } else {
                    daemon_log_info("Using default config directory: %s", default_config_dirs[i]);
                    break;
                }
            }
        }
    }

    /* Now parse command line options (they override config file values) */
    while ((opt = getopt_long(argc, argv, "c:C:dh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':  /* Config file - already handled above */
            break;
        case 'C':  /* Config directory - already handled above */
            break;
        case 'd':
            cfg.daemonize = 1;
            break;
        case 'h':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -c, --config FILE      Single configuration file path\n");
            printf("  -C, --config-dir DIR   Configuration directory (auto-loads all .yaml/.yml files)\n");
            printf("                         Default: ./config/ or /etc/firewall/config/\n");
            printf("  -d, --daemonize        Run as daemon\n");
            printf("  -h, --help             Show this help\n");
            printf("\nConfig file format:\n");
            printf("  defaults:\n");
            printf("    max_retries: 5\n");
            printf("    findtime: 600\n");
            printf("    ban_time: 900\n");
            printf("  jails:\n");
            printf("    sshd:\n");
            printf("      enabled: true\n");
            printf("      log_files:\n");
            printf("        - /var/log/auth.log\n");
            return 1;
        case '?':
            /* getopt_long already printed an error message */
            return -1;
        default:
            return -1;
        }
    }

    /* Default log files if none specified - require jail format in config */
    int total_log_files = 0;
    for (int i = 0; i < cfg.jail_count; i++) {
        total_log_files += cfg.jails[i].log_count;
    }

    if (total_log_files == 0) {
        fprintf(stderr, "Error: no jails configured. Use jails: section in config file.\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  jails:\n");
        fprintf(stderr, "    sshd:\n");
        fprintf(stderr, "      enabled: true\n");
        fprintf(stderr, "      log_files:\n");
        fprintf(stderr, "        - /var/log/auth.log\n");
        return -1;
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

                    /* Boundary check: ensure next char is not digit or dot (word boundary) */
                    const char *ip_end = ptr;
                    while (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) ip_end++;
                    if (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) {
                        /* More digits/dots follow - not a complete IP, skip */
                        ptr = ip_end;
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
 * Uses jail's regex for parsing. */
static int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out, size_t ip_size)
{
    char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr4;

    if (!parse_log_line(j, log_line, ip_buf, sizeof(ip_buf))) {
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
        atomic_fetch_add(&daemon_stats.ips_extracted, 1);
        size_t copy_len = strlen(ip_buf);
        if (copy_len >= ip_size) copy_len = ip_size - 1;
        memcpy(ip_out, ip_buf, copy_len);
        ip_out[copy_len] = '\0';
        return 1;
    }

    return 0;
}

/* Parse log line and extract IP if it's a failed login - uses jail's regex */
static int parse_log_line(struct jail *j, const char *line, char *ip_out, size_t ip_size)
{
    regmatch_t matches[4];
    const char *ip_start;
    size_t ip_len;

    /* Length validation to prevent extremely long log lines */
    size_t line_len = strlen(line);
    if (line_len > 8192) {
        daemon_log_warn("Log line too long (%zu bytes), skipping", line_len);
        return 0;
    }

    /* Check for failed login using jail's compiled regex */
    if (j && j->regex_compiled) {
        int regex_result = regexec(&j->compiled_regex, line, 4, matches, 0);
        if (regex_result == 0) {
            /* Dynamically find the IP capture group - search from last to first */
            int ip_group = -1;
            for (int g = 3; g >= 1; g--) {
                if (matches[g].rm_so >= 0 && matches[g].rm_eo > matches[g].rm_so) {
                    /* Validate this capture group contains an IP-like pattern */
                    size_t capture_len = matches[g].rm_eo - matches[g].rm_so;
                    if (capture_len >= 7 && capture_len < INET_ADDRSTRLEN) {  /* Min: "1.1.1.1" */
                        /* Quick validation: first char should be digit */
                        const char *capture_start = line + matches[g].rm_so;
                        if (capture_start[0] >= '0' && capture_start[0] <= '9') {
                            ip_group = g;
                            break;
                        }
                    }
                }
            }

            if (ip_group < 0) {
                daemon_log_warn("No valid IP capture group found in regex match for jail '%s'", j->name);
                return 0;
            }

            /* Add boundary checks to prevent out-of-bounds reads */
            if ((size_t)matches[ip_group].rm_eo > line_len) {
                daemon_log_warn("Regex match exceeds line length in jail '%s'", j->name);
                return 0;
            }
            ip_start = line + matches[ip_group].rm_so;
            ip_len = matches[ip_group].rm_eo - matches[ip_group].rm_so;

            if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                daemon_log_warn("Invalid IP length in jail '%s' log: %zu", j->name, ip_len);
                return 0;
            }

            char ip_buf[INET_ADDRSTRLEN];
            memcpy(ip_buf, ip_start, ip_len);
            ip_buf[ip_len] = '\0';
            strncpy(ip_out, ip_buf, ip_size - 1);
            ip_out[ip_size - 1] = '\0';
            return 1;
        } else if (regex_result != REG_NOMATCH) {
            char errbuf[256];
            regerror(regex_result, &j->compiled_regex, errbuf, sizeof(errbuf));
            daemon_log_warn("Regex error in jail '%s' pattern: %s", j->name, errbuf);
        }
    }

    /* Fallback: simple string matching (if regex not compiled) */
    if (!j || !j->regex_compiled) {
        if (strstr(line, "Failed password for") ||
            strstr(line, "authentication failure")) {
            return extract_ip(line, ip_out, ip_size);
        }
    }

    return 0;
}

/* ============================================================================
 * Per-Jail Failed Entry Functions
 * These are the primary functions used by the jail system
 * ========================================================================== */

/* Hash function for IP addresses */
static unsigned int hash_ip(const char *ip)
{
    unsigned int hash = 0;
    while (*ip) {
        hash = hash * 31 + (unsigned char)(*ip);
        ip++;
    }
    return hash % 256;
}

/* Find failed entry by IP in a specific jail */
static struct failed_entry *find_entry_for_jail(struct jail *j, const char *ip)
{
    if (!j || !ip) return NULL;

    /* Use hash table for faster lookup */
    unsigned int h = hash_ip(ip);
    struct failed_entry *entry = j->failed_hash_table[h];

    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            return entry;
        }
        entry = entry->next_in_hash;
    }
    return NULL;
}

/* Create new failed entry in a specific jail */
static struct failed_entry *create_entry_for_jail(struct jail *j, const char *ip)
{
    if (!j || !ip) return NULL;

    struct failed_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        daemon_log_err("Failed to allocate memory for failed entry");
        return NULL;
    }

    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->count = 0;

    /* Add to jail's linked list */
    entry->next = j->failed_table;
    j->failed_table = entry;

    /* Add to jail's hash table */
    unsigned int hash = hash_ip(ip);
    entry->next_in_hash = j->failed_hash_table[hash];
    j->failed_hash_table[hash] = entry;

    return entry;
}

/* Remove failed entry (per-jail) */
static void remove_entry_for_jail(struct jail *j, const char *ip)
{
    struct failed_entry *prev = NULL;
    struct failed_entry *entry = j->failed_table;

    /* Find in main linked list */
    while (entry) {
        if (strcmp(entry->ip, ip) == 0) {
            /* Remove from main linked list */
            if (prev) {
                prev->next = entry->next;
            } else {
                j->failed_table = entry->next;
            }

            /* Remove from hash table */
            unsigned int hash = hash_ip(ip);
            struct failed_entry *hash_prev = NULL;
            struct failed_entry *hash_entry = j->failed_hash_table[hash];

            while (hash_entry) {
                if (hash_entry == entry) {
                    if (hash_prev) {
                        hash_prev->next_in_hash = hash_entry->next_in_hash;
                    } else {
                        j->failed_hash_table[hash] = hash_entry->next_in_hash;
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

/* ============================================================================
 * Global failed entry functions - kept for potential legacy usage
 * These are not used in jail system but preserved for backward compatibility
 * ========================================================================== */

/* Find failed entry by IP - searches all jails */

static struct failed_entry *find_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    struct failed_entry *result = NULL;
    for (int j = 0; j < cfg.jail_count; j++) {
        struct failed_entry *entry = find_entry_for_jail(&cfg.jails[j], ip);
        if (entry) {
            result = entry;
            break;
        }
    }
    
    pthread_mutex_unlock(&config_mutex);
    return result;
}

/* Create new failed entry - creates in first jail (default behavior) */

static struct failed_entry *create_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    struct failed_entry *result = NULL;
    if (cfg.jail_count > 0) {
        result = create_entry_for_jail(&cfg.jails[0], ip);
    }
    
    pthread_mutex_unlock(&config_mutex);
    return result;
}

/* Remove failed entry - searches all jails */

static void remove_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    for (int j = 0; j < cfg.jail_count; j++) {
        struct failed_entry *entry = find_entry_for_jail(&cfg.jails[j], ip);
        if (entry) {
            remove_entry_for_jail(&cfg.jails[j], ip);
            break;
        }
    }
    
    pthread_mutex_unlock(&config_mutex);
}


/* Count recent failures within time window */

static unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries)
{
    time_t now = time(NULL);
    unsigned int count = 0;

    /* Validate parameters to prevent potential issues */
    if (!entry || window <= 0) {
        daemon_log_debug("Invalid parameters to count_recent");
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

/* Handle a failed login attempt - jail-aware version */
static void handle_failed_attempt_for_jail(struct jail *j, const char *ip, unsigned int max_retries, unsigned int findtime)
{
    struct failed_entry *entry = find_entry_for_jail(j, ip);
    time_t now = time(NULL);

    atomic_fetch_add(&daemon_stats.failed_attempts, 1);

    /* Validate IP before processing */
    if (!ip || strlen(ip) == 0) {
        daemon_log_err("Invalid IP address provided to handle_failed_attempt");
        return;
    }

    if (!entry) {
        entry = create_entry_for_jail(j, ip);
        if (!entry) {
            daemon_log_err("Failed to create entry for IP %s", ip);
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

    /* Check if exceeded threshold */
    unsigned int recent_fails = count_recent(entry, findtime, max_retries);
    if (recent_fails >= max_retries) {
        daemon_log_warn("IP %s exceeded %d failures in %d seconds in jail '%s', banning", ip, recent_fails, findtime, j->name);
        if (ban_ip(ip) == 0) {
            remove_entry_for_jail(j, ip);
            daemon_log_info("Successfully banned IP %s after %d failed attempts in jail '%s'", ip, recent_fails, j->name);
        } else {
            daemon_log_err("Failed to ban IP %s after %d failed attempts in jail '%s', keeping entry for retry", ip, recent_fails, j->name);
        }
    } else {
        daemon_log_debug("IP %s has %d failed attempts in %d seconds in jail '%s'", ip, recent_fails, findtime, j->name);
    }
}

/* Handle a failed login attempt - thread-safe version (backward compatible) */

static void handle_failed_attempt(const char *ip, unsigned int max_retries, unsigned int findtime)
{
    struct failed_entry *entry = find_entry(ip);
    time_t now = time(NULL);

    atomic_fetch_add(&daemon_stats.failed_attempts, 1);

    /* Validate IP before processing */
    if (!ip || strlen(ip) == 0) {
        daemon_log_err("Invalid IP address provided to handle_failed_attempt");
        return;
    }

    if (!entry) {
        entry = create_entry(ip);
        if (!entry) {
            daemon_log_err("Failed to create entry for IP %s", ip);
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
        daemon_log_warn("IP %s exceeded %d failures in %d seconds, banning", ip, recent_fails, findtime);
        if (ban_ip(ip) == 0) {
            remove_entry(ip);
            daemon_log_info("Successfully banned IP %s after %d failed attempts", ip, recent_fails);
        } else {
            daemon_log_err("Failed to ban IP %s after %d failed attempts, keeping entry for retry", ip, recent_fails);
        }
    } else {
        daemon_log_debug("IP %s has %d failed attempts in %d seconds", ip, recent_fails, findtime);
    }
}

/* Secure procfs file operation helper */
static int secure_procfs_write(const char *path, const char *data, size_t data_len) {
    int fd;
    ssize_t written;
    size_t total_written = 0;

    // Validate inputs
    if (!path || !data || data_len == 0) {
        daemon_log_err("Invalid parameters to secure_procfs_write");
        return -1;
    }

    // Check data length to prevent excessively long writes
    if (data_len > 256) {  // Reasonable limit for IP addresses
        daemon_log_err("Data too long for procfs write (%zu bytes)", data_len);
        return -1;
    }

    fd = open(path, O_WRONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", path, strerror(errno));
        return -1;
    }

    // Write data in a controlled manner
    while (total_written < data_len) {
        written = write(fd, data + total_written, data_len - total_written);
        if (written < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;  // Interrupted or resource temporarily unavailable, try again
            } else {
                daemon_log_err("Failed to write to %s: %s", path, strerror(errno));
                close(fd);
                return -1;
            }
        }
        total_written += written;
    }

    // Close file descriptor
    if (close(fd) < 0) {
        daemon_log_warn("Failed to close %s: %s", path, strerror(errno));
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
        daemon_log_err("NULL IP address provided to ban_ip");
        return -1;
    }

    ip_len = strlen(ip);
    if (ip_len == 0 || ip_len >= INET_ADDRSTRLEN) {
        daemon_log_err("Invalid IP length %zu in ban_ip", ip_len);
        return -1;
    }

    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        daemon_log_err("Invalid IPv4 address format: %s", ip);
        return -1;
    }

    // Additional validation: reject invalid IPv4 IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4 (multicast)
        daemon_log_err("Attempt to ban invalid IPv4: %s", ip);
        return -1;
    }

    // Prepare data with newline for writing
    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", ip);

    // Write to kernel module (temporary ban)
    if (secure_procfs_write(ADD_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
        daemon_log_err("Failed to write to %s", ADD_BAN_PATH);
        return -1;
    }

    /* Note: Automatic bans from log parsing are temporary only.
     * Permanent bans should only be added via explicit ban_ip_permanent() call.
     * This prevents accidental permanent blocking from false positives. */

    atomic_fetch_add(&daemon_stats.ips_banned, 1);
    daemon_log_info("Banned IP %s", ip);
    return 0;
}

/*
 * ban_ip_permanent - Ban IP permanently via procfs and SQLite
 */

static int ban_ip_permanent(const char *ip)
{
    struct in_addr addr4;
    size_t ip_len;
    char ip_with_newline[INET_ADDRSTRLEN + 2];

    if (!ip) {
        daemon_log_err("NULL IP address provided to ban_ip_permanent");
        return -1;
    }

    ip_len = strlen(ip);
    if (ip_len == 0 || ip_len >= INET_ADDRSTRLEN) {
        daemon_log_err("Invalid IP length %zu in ban_ip_permanent", ip_len);
        return -1;
    }

    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        daemon_log_err("Invalid IPv4 address format: %s", ip);
        return -1;
    }

    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", ip);

    /* Write to kernel module permanent ban endpoint */
    if (secure_procfs_write(PERMANENT_ADD_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
        daemon_log_err("Failed to write to %s", PERMANENT_ADD_BAN_PATH);
        return -1;
    }

    /* Also add to SQLite for persistence */
    if (sqlite_db) {
        uint32_t ip_num = addr4.s_addr;
        int rc = sqlite_add_permanent_ban(sqlite_db, ip, ip_num, "manual permanent ban", "manual");
        if (rc == 0) {
            daemon_log_info("IP %s permanently banned and saved to SQLite", ip);
        } else if (rc == -2) {
            daemon_log_debug("IP %s already in permanent banlist", ip);
        } else {
            daemon_log_warn("Failed to save permanent ban to SQLite: %s", ip);
        }
    }

    atomic_fetch_add(&daemon_stats.ips_banned, 1);
    daemon_log_info("Permanently banned IP %s", ip);
    return 0;
}

/* Unban IP via procfs (used for manual unban) (IPv4 only) */

static int unban_ip(const char *ip)
{
    struct in_addr addr4;
    char ip_with_newline[INET_ADDRSTRLEN + 2];  // +1 for \n, +1 for \0

    // Validate input IP format before attempting to unban
    if (!ip) {
        daemon_log_err("NULL IP address provided to unban_ip");
        return -1;
    }

    // Check if it's a valid IPv4 address
    if (inet_pton(AF_INET, ip, &addr4) != 1) {
        daemon_log_err("Invalid IPv4 address format: %s", ip);
        return -1;
    }

    // Additional validation: reject invalid IPv4 IPs like 0.0.0.0, 127.x.x.x, multicast, etc.
    unsigned int ip_num = ntohl(addr4.s_addr);
    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
        ((ip_num >> 24) & 0xFF) == 127 ||  // 127.x.x.x
        (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) {  // 224.0.0.0/4 (multicast)
        daemon_log_err("Attempt to unban invalid IPv4: %s", ip);
        return -1;
    }

    // Prepare data with newline for writing
    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", ip);

    // Use secure write function
    if (secure_procfs_write(REMOVE_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
        daemon_log_err("Failed to write to %s", REMOVE_BAN_PATH);
        return -1;
    }

    daemon_log_info("Unbanned IP %s", ip);
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

    /* Write PID file for systemd Type=forking support */
    FILE *pidfile = fopen("/var/run/firewall-daemon.pid", "w");
    if (pidfile) {
        fprintf(pidfile, "%d\n", getpid());
        fclose(pidfile);
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
        daemon_log_err("Failed to initialize inotify: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    int flags = fcntl(inotify_fd, F_GETFL);
    if (flags == -1) {
        daemon_log_err("Failed to get fcntl flags for inotify: %s", strerror(errno));
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }
    if (fcntl(inotify_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        daemon_log_err("Failed to set inotify non-blocking: %s", strerror(errno));
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }

    /* Add watches for each log file in each jail */
    int global_idx = 0;
    for (int j = 0; j < cfg.jail_count; j++) {
        struct jail *jail = &cfg.jails[j];

        if (!jail->enabled) {
            daemon_log_info("Skipping disabled jail: %s", jail->name);
            continue;
        }

        for (int i = 0; i < jail->log_count; i++) {
            struct stat st;

            /* Initialize file state */
            file_states[global_idx].path[0] = '\0';
            file_states[global_idx].offset = 0;
            file_states[global_idx].inode = 0;
            file_states[global_idx].wd = -1;  /* Mark as not watching yet */
            file_states[global_idx].jail_idx = j;  /* Record which jail this file belongs to */

            strncpy(file_states[global_idx].path, jail->log_files[i], sizeof(file_states[global_idx].path) - 1);
            file_states[global_idx].path[sizeof(file_states[global_idx].path) - 1] = '\0';

            /* Get initial inode */
            if (stat(jail->log_files[i], &st) == 0) {
                file_states[global_idx].inode = st.st_ino;
                file_states[global_idx].offset = st.st_size;
                daemon_log_info("Initial offset for %s (jail=%s): %ld bytes", jail->log_files[i], jail->name, (long)file_states[global_idx].offset);
            }

            /* Watch for modifications, moves, deletes */
            file_states[global_idx].wd = inotify_add_watch(inotify_fd, jail->log_files[i],
                IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
            if (file_states[global_idx].wd < 0) {
                daemon_log_warn("Failed to watch %s (jail=%s): %s (skipping)", jail->log_files[i], jail->name, strerror(errno));
                file_states[global_idx].wd = -1;
                /* Continue with other log files instead of failing entirely */
            } else {
                daemon_log_info("Watching %s (jail=%s, wd=%d)", jail->log_files[i], jail->name, file_states[global_idx].wd);
            }

            global_idx++;
            if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
                daemon_log_warn("Maximum file states reached (%d), stopping watch addition", MAX_JAILS * MAX_LOG_FILES);
                goto watch_summary;
            }
        }
    }

watch_summary:
    /* Check if at least one file is being watched */
    int watched_count = 0;
    int total_files = 0;
    for (int j = 0; j < cfg.jail_count; j++) {
        if (cfg.jails[j].enabled) {
            total_files += cfg.jails[j].log_count;
        }
    }
    for (int i = 0; i < global_idx; i++) {
        if (file_states[i].wd >= 0) watched_count++;
    }
    if (watched_count == 0) {
        daemon_log_err("No log files could be watched");
        close(inotify_fd);
        inotify_fd = -1;
        return -1;
    }
    daemon_log_info("Watching %d/%d log files across %d jails", watched_count, total_files, cfg.jail_count);

    return 0;
}

/* Static buffer for storing partial lines between reads */
static char partial_line_buffer[8192];  /* Increased buffer size to handle longer lines */
static size_t partial_line_len = 0;
static pthread_mutex_t partial_line_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Helper: Process a single complete log line.
 * Extracts IP and handles failed login attempt.
 * Called with null-terminated line in `line`. */
static void process_single_line(struct jail *j, const char *line, const char *log_path,
                                unsigned int max_retries, unsigned int findtime)
{
    if (!line || strlen(line) == 0)
        return;

    /* Skip extremely long lines */
    size_t len = strlen(line);
    if (len >= 8192) {
        daemon_log_warn("Line too long (%zu bytes) in %s, skipping", len, log_path);
        atomic_fetch_add(&daemon_stats.lines_skipped, 1);
        return;
    }

    atomic_fetch_add(&daemon_stats.lines_parsed, 1);

    char ip[INET_ADDRSTRLEN];
    if (extract_and_validate_ip(j, line, ip, sizeof(ip))) {
        handle_failed_attempt_for_jail(j, ip, max_retries, findtime);
    }
}

/* Helper: Process all complete lines in a buffer.
 * `data` points to the buffer, `len` is the data length.
 * Updates `*consumed` to the number of bytes consumed (up to and including last newline).
 * Any remaining data after the last newline is left for the caller to handle as partial.
 * NOTE: This function may temporarily modify `data` to null-terminate lines. */
static void process_lines_in_buffer(struct jail *j, char *data, size_t len, const char *log_path, size_t *consumed,
                                    unsigned int max_retries, unsigned int findtime)
{
    char *line_start = data;
    char *line_end;
    size_t remaining = len;

    *consumed = 0;

    while (remaining > 0 && (line_end = memchr(line_start, '\n', remaining)) != NULL) {
        size_t line_len = line_end - line_start;

        if (line_len >= 8192) {
            daemon_log_warn("Extremely long line (%zu bytes) in %s, skipping", line_len, log_path);
        } else {
            /* Temporarily null-terminate for processing */
            char saved = *line_end;
            /* Safe: line_len < 8192, and data is within caller's buffer */
            *line_end = '\0';
            process_single_line(j, line_start, log_path, max_retries, findtime);
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
static void store_partial_line(struct jail *j, const char *data, size_t len, const char *log_path,
                               unsigned int max_retries, unsigned int findtime)
{
    if (len == 0)
        return;

    if (len >= sizeof(partial_line_buffer)) {
        daemon_log_warn("Partial line too long (%zu bytes) in %s, discarding", len, log_path);
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
            process_single_line(j, temp, log_path, max_retries, findtime);
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
static void flush_partial_line(struct jail *j, const char *log_path, unsigned int max_retries, unsigned int findtime)
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
        daemon_log_debug("Flushing partial line buffer with %zu bytes from %s", old_len, log_path);
        process_single_line(j, temp, log_path, max_retries, findtime);
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
    struct jail *j = NULL;
    unsigned int max_retries, findtime;

    /* Validate idx parameter */
    if (idx < 0 || idx >= MAX_JAILS * MAX_LOG_FILES) {
        daemon_log_err("Invalid index %d to process_new_lines", idx);
        return;
    }

    log_path = file_states[idx].path;
    int jail_idx = file_states[idx].jail_idx;

    /* Get jail reference and configuration under lock protection */
    if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
        daemon_log_err("Invalid jail index %d in process_new_lines", jail_idx);
        return;
    }
    
    /* Lock to safely copy jail configuration values */
    pthread_mutex_lock(&config_mutex);
    j = &cfg.jails[jail_idx];
    max_retries = j->max_retries;
    findtime = j->findtime;
    pthread_mutex_unlock(&config_mutex);

    fd = open(log_path, O_RDONLY);
    if (fd < 0) {
        daemon_log_err("Failed to open %s: %s", log_path, strerror(errno));
        goto cleanup;
    }

    /* Check if file was rotated (inode changed or size decreased) */
    if (fstat(fd, &st) == 0) {
        if (file_states[idx].inode != 0 && st.st_ino != file_states[idx].inode) {
            daemon_log_info("Log file rotated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            flush_partial_line(j, log_path, max_retries, findtime);
        } else if (st.st_size < file_states[idx].offset) {
            daemon_log_info("Log file truncated: %s", log_path);
            file_states[idx].inode = st.st_ino;
            file_states[idx].offset = 0;
            flush_partial_line(j, log_path, max_retries, findtime);
        }
    }

    /* Seek to last known offset */
    if (file_states[idx].offset > 0) {
        if (lseek(fd, file_states[idx].offset, SEEK_SET) == (off_t)-1) {
            daemon_log_err("Failed to seek in %s: %s", log_path, strerror(errno));
            ret = -1;
            goto cleanup;
        }
    }

    /* Read and process data in chunks */
    current_offset = file_states[idx].offset;

    /* Move allocations outside the loop for easier cleanup */
    char *local_partial = NULL;
    char *combined = NULL;

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  /* Ensure null termination for safety */

        /* Use heap allocation instead of stack allocation for partial line data */
        size_t partial_len = 0;

        /* Copy partial line data under lock */
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

        /* Process data outside the lock */
        if (local_partial && partial_len > 0) {
            /* Has partial line data, need to merge and process */
            combined = malloc(partial_len + (size_t)bytes_read + 1);
            if (!combined) {
                daemon_log_err("Out of memory allocating combined buffer");
                free(local_partial);
                local_partial = NULL;
                /* Discard partial data, process new data directly */
                size_t consumed = 0;
                process_lines_in_buffer(j, buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);
                if (consumed < (size_t)bytes_read) {
                    store_partial_line(j, buffer + consumed, (size_t)bytes_read - consumed, log_path, max_retries, findtime);
                }
                current_offset += bytes_read;
                continue;
            }

            memcpy(combined, local_partial, partial_len);
            memcpy(combined + partial_len, buffer, bytes_read);
            combined[partial_len + (size_t)bytes_read] = '\0';
            free(local_partial);
            local_partial = NULL;  /* Prevent double-free */

            size_t total_len = partial_len + (size_t)bytes_read;

            /* Clear consumed partial line */
            pthread_mutex_lock(&partial_line_mutex);
            partial_line_len = 0;
            pthread_mutex_unlock(&partial_line_mutex);

            /* Process complete lines */
            size_t consumed = 0;
            process_lines_in_buffer(j, combined, total_len, log_path, &consumed, max_retries, findtime);

            /* Store any remaining data as new partial line */
            if (consumed < total_len) {
                store_partial_line(j, combined + consumed, total_len - consumed, log_path, max_retries, findtime);
            }

            free(combined);
            combined = NULL;  /* Prevent double-free */
        } else {
            /* No partial line - process buffer directly */
            if (local_partial) {
                free(local_partial);
                local_partial = NULL;
            }

            size_t consumed = 0;
            process_lines_in_buffer(j, buffer, (size_t)bytes_read, log_path, &consumed, max_retries, findtime);

            if (consumed < (size_t)bytes_read) {
                store_partial_line(j, buffer + consumed, (size_t)bytes_read - consumed, log_path, max_retries, findtime);
            }
        }

        /* Prevent integer overflow when updating offset */
        if (current_offset > SSIZE_MAX - bytes_read) {
            daemon_log_err("Integer overflow in file offset calculation");
            /* Free allocated memory before exiting loop */
            free(local_partial);
            free(combined);
            ret = -1;
            goto cleanup;
        }
        current_offset += bytes_read;
        
        /* Free any remaining allocations for next iteration */
        free(local_partial);
        local_partial = NULL;
        free(combined);
        combined = NULL;
    }

    if (bytes_read < 0) {
        daemon_log_warn("Read error in %s: %s", log_path, strerror(errno));
        /* Free allocated memory before cleanup */
        free(local_partial);
        free(combined);
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
        daemon_log_err("Failed to process %s", log_path);
    }
}

/* Function to periodically clean up partial line buffer to prevent accumulation */
static void cleanup_partial_line_buffer(void)
{
    /* Iterate through all jails for cleanup */
    pthread_mutex_lock(&config_mutex);
    for (int i = 0; i < cfg.jail_count; i++) {
        flush_partial_line(&cfg.jails[i], "periodic_cleanup", DEFAULT_MAX_RETRIES, DEFAULT_FINDTIME);
    }
    pthread_mutex_unlock(&config_mutex);
}

/* Handle log file rotation */
static void handle_log_rotation(int idx)
{
    struct stat st;
    int jail_idx = file_states[idx].jail_idx;
    struct jail *j = NULL;
    unsigned int max_retries, findtime;

    if (jail_idx >= 0 && jail_idx < cfg.jail_count) {
        j = &cfg.jails[jail_idx];
        max_retries = j->max_retries;
        findtime = j->findtime;
    } else {
        max_retries = DEFAULT_MAX_RETRIES;
        findtime = DEFAULT_FINDTIME;
    }

    atomic_fetch_add(&daemon_stats.log_rotations, 1);

    /* Check if file still exists */
    if (stat(file_states[idx].path, &st) != 0) {
        daemon_log_warn("Log file disappeared: %s", file_states[idx].path);
        file_states[idx].offset = 0;
        if (j) flush_partial_line(j, file_states[idx].path, max_retries, findtime);
        return;
    }

    /* Check if inode changed (file was rotated) */
    if (st.st_ino != file_states[idx].inode) {
        daemon_log_info("Log file rotated: %s", file_states[idx].path);
        file_states[idx].inode = st.st_ino;
        file_states[idx].offset = 0;

        /* Clean up partial line buffer on rotation */
        if (j) flush_partial_line(j, file_states[idx].path, max_retries, findtime);

        /* Re-add watch if needed */
        if (file_states[idx].wd >= 0) {
            inotify_rm_watch(inotify_fd, file_states[idx].wd);
        }
        file_states[idx].wd = inotify_add_watch(inotify_fd, file_states[idx].path,
            IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE | IN_CREATE);
        if (file_states[idx].wd < 0) {
            daemon_log_err("Failed to re-add watch for %s: %s", file_states[idx].path, strerror(errno));
            file_states[idx].wd = -1;
        } else {
            daemon_log_info("Re-added watch for %s (wd=%d)", file_states[idx].path, file_states[idx].wd);
        }
    }
}

/* Main monitoring loop */
static void monitor_loop(void)
{
    char buffer[EVENT_BUF_LEN];

        daemon_log_info("Starting monitoring loop");

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
            daemon_log_err("select error: %s", strerror(errno));
            break;
        }

        if (ret == 0) {
            /* Timeout - periodic cleanup */
            cleanup_expired_bans();

            /* Check if config reload was requested - use atomic exchange to prevent lost signals */
            if (__atomic_exchange_n(&reload_config, 0, __ATOMIC_SEQ_CST)) {
        daemon_log_info("Reloading configuration...");

                unsigned int old_max_retries, old_findtime, old_ban_time;
                int old_interval, old_metrics_port;

                /* 保存旧配置的关键值用于变更检测 */
                pthread_mutex_lock(&config_mutex);
                old_max_retries = cfg.default_max_retries;
                old_findtime = cfg.default_findtime;
                old_ban_time = cfg.default_ban_time;
                old_interval = cfg.interval;
                old_metrics_port = cfg.metrics_port;
                pthread_mutex_unlock(&config_mutex);

                /* 根据配置类型选择重载方式 */
                int reload_ok = 0;
                
                /* Clean up old jails resources before reloading */
                pthread_mutex_lock(&config_mutex);
                /* Clean up partial line buffers for all jails before config change */
                for (int i = 0; i < cfg.jail_count; i++) {
                    flush_partial_line(&cfg.jails[i], "config_reload_cleanup", DEFAULT_MAX_RETRIES, DEFAULT_FINDTIME);
                }
                cleanup_all_jails();
                pthread_mutex_unlock(&config_mutex);
                
                if (cfg.config_dir) {
                    /* 配置目录模式：重新加载整个目录 */
                    daemon_log_info("Reloading config directory: %s", cfg.config_dir);
                    if (load_config_directory(cfg.config_dir) < 0) {
                        daemon_log_warn("Failed to reload config directory, keeping old config");
                        /* Restore jail count since reload failed */
                    } else {
                        reload_ok = 1;
                        daemon_log_info("Config directory reloaded successfully");
                    }
                } else if (cfg.config_file) {
                    /* 单文件模式：重新加载单个文件 */
                    if (parse_config_file(cfg.config_file) < 0) {
                        daemon_log_err("Failed to reload configuration from %s", cfg.config_file);
                    } else {
                        reload_ok = 1;
                        daemon_log_info("Configuration reloaded successfully");
                    }
                } else {
                    daemon_log_warn("No config file or directory specified, cannot reload");
                }

                if (reload_ok) {
                    /* Re-setup inotify watches after config reload */
                    if (inotify_fd >= 0) {
                        /* Remove old watches - iterate through all possible file states */
                        int max_states = MAX_JAILS * MAX_LOG_FILES;
                        for (int i = 0; i < max_states; i++) {
                            if (file_states[i].wd >= 0) {
                                inotify_rm_watch(inotify_fd, file_states[i].wd);
                                file_states[i].wd = -1;
                            }
                            /* Reset file state */
                            file_states[i].offset = 0;
                            file_states[i].inode = 0;
                            file_states[i].path[0] = '\0';
                            file_states[i].jail_idx = -1;
                        }
                        close(inotify_fd);
                        inotify_fd = -1;
                    }

                    /* Re-setup inotify */
                    if (setup_inotify() < 0) {
                        daemon_log_err("Failed to re-setup inotify after config reload");
                        running = 0;  /* Safe exit */
                    }

                    /* Check changes and output logs */
                    pthread_mutex_lock(&config_mutex);
                    if (old_max_retries != cfg.default_max_retries) {
                        daemon_log_info("default_max_retries changed from %u to %u", old_max_retries, cfg.default_max_retries);
                    }
                    if (old_findtime != cfg.default_findtime) {
                        daemon_log_info("default_findtime changed from %u to %u", old_findtime, cfg.default_findtime);
                    }
                    if (old_ban_time != cfg.default_ban_time) {
                        daemon_log_info("default_ban_time changed from %u to %u", old_ban_time, cfg.default_ban_time);
                    }
                    if (old_interval != cfg.interval) {
                        daemon_log_info("interval changed from %d to %d", old_interval, cfg.interval);
                    }
                    if (old_metrics_port != cfg.metrics_port) {
                        daemon_log_info("metrics_port changed from %d to %d", old_metrics_port, cfg.metrics_port);
                    }
                    pthread_mutex_unlock(&config_mutex);
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
                daemon_log_err("inotify read error: %s", strerror(errno));
            }
            continue;
        }

        if (len > 0) {
            atomic_fetch_add(&daemon_stats.inotify_events, 1);
        }

        /* Process events */
        size_t i = 0;
        while (i < (size_t)len) {
            struct inotify_event *event = (struct inotify_event *)&buffer[i];

            /* Validate event structure size and prevent integer overflow */
            if (sizeof(struct inotify_event) > (size_t)len - i) {
        daemon_log_err("Invalid inotify event structure size");
                break;
            }

            /* Additional boundary check: ensure event->len is within reasonable bounds */
            if (event->len > EVENT_BUF_LEN) {
                daemon_log_warn("inotify event length too large, skipping (len=%u, max=%d)", event->len, (int)EVENT_BUF_LEN);
                break;
            }

            /* Verify event->len doesn't cause buffer overflow */
            if (sizeof(struct inotify_event) + event->len > (size_t)(len - i)) {
        daemon_log_warn("inotify event too large for remaining buffer, skipping");
                break;
            }

            /* Additional safety check: ensure we don't have an unexpectedly large event length */
            if (event->len > 1024) {  /* Most inotify events have small names */
                daemon_log_warn("Suspiciously large inotify event length, skipping (len=%u)", event->len);
                /* Calculate next position safely even with large event->len */
                size_t next_pos = i + sizeof(struct inotify_event) + event->len;
                if (next_pos < i) {  // Overflow check
        daemon_log_err("Integer overflow detected in inotify processing");
                    break;
                }
                i = next_pos;
                continue;  // Skip processing this suspicious event but continue with others
            }

            if (event->mask & (IN_MODIFY | IN_MOVED_TO)) {
                /* File was modified or created - find matching file */
                pthread_mutex_lock(&config_mutex);
                int max_states = MAX_JAILS * MAX_LOG_FILES;
                for (int j = 0; j < max_states; j++) {
                    if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
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
                int max_states = MAX_JAILS * MAX_LOG_FILES;
                for (int j = 0; j < max_states; j++) {
                    if (file_states[j].wd >= 0 && event->wd == file_states[j].wd) {
                        daemon_log_info("Log file removed: %s", file_states[j].path);
                        file_states[j].wd = -1;
                        break;
                    }
                }
                pthread_mutex_unlock(&config_mutex);
            }

            /* Advance position with overflow check */
            size_t next_pos = i + sizeof(struct inotify_event) + event->len;
            if (next_pos < i) {  // Overflow check
        daemon_log_err("Integer overflow detected in inotify processing");
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
    daemon_log_info("Cleaning up");

    /* Remove inotify watches */
    if (inotify_fd >= 0) {
        int max_states = MAX_JAILS * MAX_LOG_FILES;
        for (int i = 0; i < max_states; i++) {
            if (file_states[i].wd >= 0) {
                /* Only try to remove watch if the inotify_fd is still valid */
                if (inotify_rm_watch(inotify_fd, file_states[i].wd) < 0) {
                    daemon_log_warn("Failed to remove watch for %s: %s", file_states[i].path, strerror(errno));
                }
                file_states[i].wd = -1;  /* Mark as removed */
            }
        }
        if (close(inotify_fd) < 0) {
            daemon_log_warn("Failed to close inotify fd: %s", strerror(errno));
        }
        inotify_fd = -1;
    }

    /* Free all jails and their resources */
    for (int j = 0; j < cfg.jail_count; j++) {
        struct jail *jail = &cfg.jails[j];

        /* Free log files */
        for (int i = 0; i < jail->log_count; i++) {
            if (jail->log_files[i]) {
                free(jail->log_files[i]);
                jail->log_files[i] = NULL;
            }
        }
        jail->log_count = 0;

        /* Free regex */
        free_jail_regex(jail);
        if (jail->regex_pattern) {
            free(jail->regex_pattern);
            jail->regex_pattern = NULL;
        }

        /* Free failed table and hash table */
        if (jail->failed_table) {
            struct failed_entry *entry = jail->failed_table;
            while (entry) {
                struct failed_entry *next = entry->next;
                free(entry);
                entry = next;
            }
            jail->failed_table = NULL;
        }

        /* Clear hash table pointers */
        memset(jail->failed_hash_table, 0, sizeof(jail->failed_hash_table));

        daemon_log_info("Cleaned up jail: %s", jail->name);
    }
    cfg.jail_count = 0;

    /* Free global config strings */
    if (cfg.config_file) {
        free(cfg.config_file);
        cfg.config_file = NULL;
    }
    if (cfg.config_dir) {
        free(cfg.config_dir);
        cfg.config_dir = NULL;
    }
    if (cfg.permanent_db_path) {
        free(cfg.permanent_db_path);
        cfg.permanent_db_path = NULL;
    }

    /* Close SQLite database */
    if (sqlite_db) {
        sqlite_close(sqlite_db);
        sqlite_db = NULL;
        daemon_log_info("SQLite database closed");
    }

    /* Destroy mutex for partial line buffer */
    pthread_mutex_destroy(&partial_line_mutex);

    closelog();
}

/* Initialize precompiled regex patterns for all jails */
static int init_log_patterns(void)
{
    int ret = 0;

    /* Compile regex for each jail that has a pattern */
    for (int i = 0; i < cfg.jail_count; i++) {
        struct jail *jail = &cfg.jails[i];

        if (!jail->enabled) {
            daemon_log_debug("Skipping disabled jail '%s' for regex compilation", jail->name);
            continue;
        }

        if (jail->regex_pattern && strlen(jail->regex_pattern) > 0) {
            if (compile_jail_regex(jail) < 0) {
                daemon_log_warn("Failed to compile regex for jail '%s'", jail->name);
                ret = -1;
                /* Continue compiling for other jails */
            } else {
                daemon_log_info("Compiled regex for jail '%s'", jail->name);
            }
        } else {
            /* Jail will use built-in default pattern */
            daemon_log_info("Jail '%s' will use built-in default regex pattern", jail->name);
        }
    }

    if (ret == 0) {
        daemon_log_info("All jail regex patterns compiled successfully");
    }

    return ret;
}


/* Free precompiled regex patterns - no longer needed as regex is per-jail */
static void free_log_patterns(void)
{
    /* Regex is now managed per-jail, so no global patterns to free */
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
        strcasestr(input_path, "%2e%2e%2f") ||  /* URL encoded ../ */
        strcasestr(input_path, "%2e%2e%5c") ||  /* URL encoded ..\ */
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

    /* Initialize file_states array with -1 for wd and jail_idx to distinguish from valid watch descriptors */
    for (int i = 0; i < MAX_JAILS * MAX_LOG_FILES; i++) {
        file_states[i].wd = -1;
        file_states[i].jail_idx = -1;
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

    /* Open syslog */
    openlog("firewall", LOG_PID | LOG_CONS, LOG_DAEMON);

    /* Check if procfs interfaces exist before proceeding */
    if (access(PROCFS_DIR, F_OK) != 0) {
        daemon_log_err("Procfs directory %s does not exist. Is the kernel module loaded?", PROCFS_DIR);
        fprintf(stderr, "Error: Procfs directory %s does not exist. Is the kernel module loaded?\n",
                PROCFS_DIR);
        return EXIT_FAILURE;
    }

    if (access(ADD_BAN_PATH, F_OK) != 0) {
        daemon_log_err("Add ban procfs interface %s does not exist", ADD_BAN_PATH);
        fprintf(stderr, "Error: Add ban procfs interface %s does not exist\n", ADD_BAN_PATH);
        return EXIT_FAILURE;
    }

    if (access(REMOVE_BAN_PATH, F_OK) != 0) {
        daemon_log_err("Remove ban procfs interface %s does not exist", REMOVE_BAN_PATH);
        fprintf(stderr, "Error: Remove ban procfs interface %s does not exist\n", REMOVE_BAN_PATH);
        return EXIT_FAILURE;
    }

    if (access(BAN_LIST_PATH, F_OK) != 0) {
        daemon_log_err("Ban list procfs interface %s does not exist", BAN_LIST_PATH);
        fprintf(stderr, "Error: Ban list procfs interface %s does not exist\n", BAN_LIST_PATH);
        return EXIT_FAILURE;
    }

    /* Initialize log patterns */
    if (init_log_patterns() < 0) {
        daemon_log_err("Failed to initialize log patterns");
        cleanup();
        return EXIT_FAILURE;
    }

    /* Initialize statistics */
    daemon_stats.start_time = time(NULL);

    /* Initialize SQLite database for permanent bans if configured */
    if (cfg.permanent_ban_enabled && cfg.permanent_db_path) {
        sqlite_db = sqlite_init(cfg.permanent_db_path);
        if (!sqlite_db) {
            daemon_log_warn("Failed to initialize SQLite database for permanent bans at %s", cfg.permanent_db_path);
            daemon_log_warn("Permanent bans will not be available");
        } else {
            daemon_log_info("SQLite database initialized for permanent bans at %s", cfg.permanent_db_path);
            
            /* Load permanent bans from SQLite and apply to kernel module */
            struct permanent_ban_entry *entries = NULL;
            int count = 0;
            if (sqlite_load_all_permanent_bans(sqlite_db, &entries, &count) == 0 && count > 0) {
                daemon_log_info("Loading %d permanent bans from SQLite database", count);
                for (int i = 0; i < count; i++) {
                    char ip_with_newline[INET_ADDRSTRLEN + 2];
                    snprintf(ip_with_newline, sizeof(ip_with_newline), "%s\n", entries[i].ip);
                    
                    if (secure_procfs_write(PERMANENT_ADD_BAN_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
                        daemon_log_warn("Failed to restore permanent ban for %s to kernel", entries[i].ip);
                    } else {
                        daemon_log_info("Restored permanent ban for %s (reason: %s)", entries[i].ip, entries[i].reason);
                    }
                }
                free(entries);
            } else if (count == 0) {
                daemon_log_info("No permanent bans found in SQLite database");
            } else {
                daemon_log_warn("Failed to load permanent bans from SQLite database");
            }
        }
    }

    /* Setup signal handlers */
    setup_signals();

    daemon_log_info("Daemon starting up");
    daemon_log_info("Loaded %d jails", cfg.jail_count);
    for (int i = 0; i < cfg.jail_count; i++) {
        if (cfg.jails[i].enabled) {
            daemon_log_info("  Jail[%d]: %s (enabled=%d, log_count=%d, max_retries=%u, findtime=%u, ban_time=%u)",
                i, cfg.jails[i].name, cfg.jails[i].enabled, cfg.jails[i].log_count,
                cfg.jails[i].max_retries, cfg.jails[i].findtime, cfg.jails[i].ban_time);
        }
    }
    daemon_log_info("Global defaults: max_retries=%u, findtime=%u, ban_time=%u",
        cfg.default_max_retries, cfg.default_findtime, cfg.default_ban_time);

    /* Daemonize if requested */
    if (cfg.daemonize) {
        daemonize_process();
    }

    /* Setup inotify */
    if (setup_inotify() < 0) {
        daemon_log_err("Failed to setup inotify");
        cleanup();
        return EXIT_FAILURE;
    }

    /* Run monitoring loop */

    /* Start Prometheus HTTP exporter */
    pthread_t exporter_thread;
    if (cfg.metrics_port > 0) {
        if (pthread_create(&exporter_thread, NULL, start_http_exporter, (void *)(long)cfg.metrics_port) != 0) {
            daemon_log_warn("Failed to start Prometheus exporter thread");
        } else {
            daemon_log_info("Prometheus exporter started on port %d", cfg.metrics_port);
            pthread_detach(exporter_thread);
        }
    } else {
        daemon_log_info("Prometheus exporter disabled (metrics_port=0)");
    }

    monitor_loop();

    /* Cleanup */
    cleanup();
        daemon_log_info("Daemon stopped");

    return EXIT_SUCCESS;
}