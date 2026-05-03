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
 *   sudo ./firewall-daemon [-c config.yaml] [-C config-dir] [--daemon]
 */

#include "firewall-daemon.h"
#include "jail-manager.h"
#include "config-parser.h"
#include "log-parser.h"
#include "failed-tracker.h"
#include "ban-manager.h"
#include "file-monitor.h"

/* Global running flag */
volatile sig_atomic_t running = 1;
volatile sig_atomic_t reload_config = 0;  /* SIGHUP flag */

/* Configuration mutex - protect multithreaded access to cfg global variable */
pthread_mutex_t config_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Global state */
struct config cfg;
int inotify_fd = -1;
/* File states array - sized for all jails' log files */
struct file_state file_states[MAX_JAILS * MAX_LOG_FILES];

/* SQLite persistent banlist */
sqlite_db_t *sqlite_db = NULL;

/* Prometheus statistics */
struct daemon_stats daemon_stats;

/* Signal handler - only sets flag, no async-unsafe calls */
void signal_handler(int sig)
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

/* Daemonize process */
void daemonize_process(void)
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
    FILE *pidfile = fopen("/run/firewall-daemon.pid", "w");
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

/* Cleanup resources */
void cleanup(void)
{
    daemon_log_info("Cleaning up");

    /* Stop HTTP exporter thread gracefully */
    stop_http_exporter();

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

        /* Free failed entries from linked list (each entry freed once) */
        if (jail->failed_table) {
            struct failed_entry *entry = jail->failed_table;
            while (entry) {
                struct failed_entry *next = entry->next;
                free(entry);
                entry = next;
            }
            jail->failed_table = NULL;
        }
        memset(jail->failed_hash_table, 0, sizeof(jail->failed_hash_table));

        /* Free khash table */
        if (jail->failed_hash) {
            /* Free heap-allocated keys before destroying hash table */
            khint_t k;
            for (k = kh_begin(jail->failed_hash); k != kh_end(jail->failed_hash); ++k) {
                if (kh_exist(jail->failed_hash, k)) {
                    free((char *)kh_key(jail->failed_hash, k));
                }
            }
            kh_destroy(ip_map, jail->failed_hash);
            jail->failed_hash = NULL;
        }

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

    closelog();
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

    if (access(BANS_PATH, F_OK) != 0) {
        daemon_log_err("Bans procfs interface %s does not exist", BANS_PATH);
        fprintf(stderr, "Error: Bans procfs interface %s does not exist\n", BANS_PATH);
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
                    char ip_with_newline[INET_ADDRSTRLEN + 20];  // +20 for "permanent " prefix
                    snprintf(ip_with_newline, sizeof(ip_with_newline), "permanent %s\n", entries[i].ip);

                    if (secure_procfs_write(BANS_PATH, ip_with_newline, strlen(ip_with_newline)) < 0) {
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
    if (cfg.daemon) {
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