/*
 * firewall-daemon.h - Shared header for firewall daemon modules
 *
 * Contains all shared constants, structures, enums, and extern declarations
 * used across the various daemon modules.
 */

#ifndef FIREWALL_DAEMON_H
#define FIREWALL_DAEMON_H

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
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <ctype.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <yaml.h>
#include <dirent.h>
#include <libgen.h>
#include "khash.h"
#include "sqlite-persistent.h"

/* Hash table for failed entries per jail */
KHASH_MAP_INIT_STR(ip_map, struct failed_entry*)

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

/* Procfs paths - unified bans interface */
#define PROCFS_DIR "/proc/firewall"
#define BANS_PATH PROCFS_DIR "/bans"

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
    pcre2_code *compiled_regex;       /* Compiled regex (PCRE2) */
    pcre2_match_data *match_data;     /* PCRE2 match data buffer */
    int regex_compiled;               /* Whether regex is compiled */
    unsigned int max_retries;         /* Max failures before ban */
    unsigned int findtime;            /* Time window for counting failures */
    unsigned int ban_time;            /* Ban duration */
    struct failed_entry *failed_table;/* Per-jail failed attempts (linked list) */
    struct failed_entry *failed_hash_table[256]; /* Manual hash table */
    khash_t(ip_map) *failed_hash;     /* khash for O(1) lookup */
    char partial_line_buffer[8192];   /* Buffer for incomplete log lines */
    size_t partial_line_len;          /* Current length of partial line */
};

/* Global running flag */
extern volatile sig_atomic_t running;
extern volatile sig_atomic_t reload_config;

/* Global default configuration */
struct config {
    unsigned int default_max_retries; /* Default for new jails */
    unsigned int default_findtime;
    unsigned int default_ban_time;
    int daemon;
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

/* Configuration mutex - protect multithreaded access to cfg global variable */
extern pthread_mutex_t config_mutex;

/* Global state */
extern struct config cfg;
extern struct daemon_stats daemon_stats;
extern int inotify_fd;
extern struct file_state file_states[MAX_JAILS * MAX_LOG_FILES];
extern sqlite_db_t *sqlite_db;

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
};

/* ============================================================================
 * Ban/Unban Action Types
 * ========================================================================== */
typedef enum {
    BAN_ACTION_TEMP,        /* Temporary ban (default duration) */
    BAN_ACTION_PERMANENT,   /* Permanent ban */
    BAN_ACTION_UNBAN,       /* Unban IP */
    BAN_ACTION_UNBAN_PERM   /* Remove permanent ban */
} ban_action_t;

/* Structure to hold validated IP information */
typedef struct {
    struct in_addr addr;
    uint32_t ip_num;  /* network byte order */
} validated_ip_t;

/* External function declarations */
extern void signal_handler(int sig);
extern void daemonize_process(void);
extern void cleanup(void);
extern void *start_http_exporter(void *port);
extern void stop_http_exporter(void);

/* Function declarations for inter-module calls */
extern int ban_ip(const char *ip);
extern void cleanup_partial_line_buffer(void);
extern void cleanup_expired_bans(void);
extern int parse_config_file(const char *config_path);
extern int load_config_directory(const char *config_dir);

#endif /* FIREWALL_DAEMON_H */