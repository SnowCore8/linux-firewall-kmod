/*
 * firewall-daemon.c - 防火墙内核模块的用户空间守护进程
 *
 * 监控日志文件中的失败登录尝试，并通过防火墙内核模块的 procfs 接口
 * 自动封禁违规 IP。
 *
 * 注意：max_retries、findtime 和 ban_time 通过 YAML 配置文件设置。
 * 日志分析逻辑（在多长时间内多少次失败触发封禁）。这些不是内核模块参数——
 * 内核模块仅根据其 ban_table 处理实际的 IP 封禁。
 *
 * 用法：
 *   sudo ./firewall-daemon [-c config.yaml] [-C config-dir] [--daemon]
 */

#include "firewall-daemon.h"
#include "ban-manager.h"
#include "config-parser.h"
#include "failed-tracker.h"
#include "file-monitor.h"
#include "jail-manager.h"
#include "log-parser.h"

/* 全局运行标志 */
volatile sig_atomic_t running = 1;
volatile sig_atomic_t reload_config = 0; /* SIGHUP 标志 */

/* 配置严格模式标志（默认开启） */
int config_strict_mode = 1;

/* 配置读写锁 - 保护多线程对 cfg 全局变量的访问
 * 使用读写锁允许多个读者并发访问，写者独占访问 */
pthread_rwlock_t config_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/* 全局状态 */
struct config cfg;
int inotify_fd = -1;
/* 文件状态数组 - 大小为所有 jail 的日志文件数量 */
struct file_state file_states[MAX_JAILS * MAX_LOG_FILES];

/* SQLite 持久化封禁列表 */
sqlite_db_t *sqlite_db = NULL;

/* Prometheus 统计信息 */
struct daemon_stats daemon_stats;

/* 信号处理函数 - 仅设置标志，不进行异步不安全调用 */
void signal_handler(int sig) {
  switch (sig) {
  case SIGTERM:
    /* fall-through: SIGTERM and SIGINT both set running=0 */
  case SIGINT:
    running = 0;
    break;
  case SIGHUP:
    reload_config = 1; /* 收到 SIGHUP 时重新加载配置 */
    break;
  }
}

/* 将进程守护进程化 */
void daemonize_process(void) {
  pid_t pid;

  /* 第一次 fork */
  pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    /* 父进程退出 - 使用 _exit 避免在 fork 的子进程中刷新 stdio 缓冲区 */
    _exit(EXIT_SUCCESS);
  }

  /* 创建新会话 */
  if (setsid() < 0) {
    perror("setsid");
    exit(EXIT_FAILURE);
  }

  /* 在守护进程化期间临时忽略 SIGHUP，防止意外重新加载 */
  struct sigaction sa_ignore;
  memset(&sa_ignore, 0, sizeof(sa_ignore));
  sa_ignore.sa_handler = SIG_IGN;
  sigemptyset(&sa_ignore.sa_mask);
  sa_ignore.sa_flags = 0;
  sigaction(SIGHUP, &sa_ignore, NULL);

  /* 第二次 fork */
  pid = fork();
  if (pid < 0) {
    perror("fork");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    /* 第一个子进程退出 - 使用 _exit 避免在 fork 的子进程中刷新 stdio 缓冲区 */
    _exit(EXIT_SUCCESS);
  }

  /* 守护进程化完成后重新启用 SIGHUP 处理函数，使配置重新加载生效 */
  struct sigaction sa_restore;
  memset(&sa_restore, 0, sizeof(sa_restore));
  sa_restore.sa_handler = signal_handler;
  sigemptyset(&sa_restore.sa_mask);
  sa_restore.sa_flags = 0;
  sigaction(SIGHUP, &sa_restore, NULL);

  /* 切换工作目录 */
  if (chdir("/") < 0) {
    perror("chdir");
  }

  /* 写入 PID 文件以支持 systemd Type=forking */
  FILE *pidfile = fopen("/run/firewall-daemon.pid", "w");
  if (pidfile) {
    fprintf(pidfile, "%d\n", getpid());
    fclose(pidfile);
  }

  /* 将标准文件描述符重定向到 /dev/null */
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

/* 清理资源 */
void cleanup(void) {
  daemon_log_info("Cleaning up");

  /* 优雅地停止 HTTP 导出器线程 */
  stop_http_exporter();

  /* 移除 inotify 监视 */
  if (inotify_fd >= 0) {
    int max_states = MAX_JAILS * MAX_LOG_FILES;
    for (int i = 0; i < max_states; i++) {
      if (file_states[i].wd >= 0) {
        /* 仅在 inotify_fd 仍然有效时尝试移除监视 */
        if (inotify_rm_watch(inotify_fd, file_states[i].wd) < 0) {
          daemon_log_warn("Failed to remove watch for %s: %s",
                          file_states[i].path, strerror(errno));
        }
        file_states[i].wd = -1; /* 标记为已移除 */
      }
    }
    if (close(inotify_fd) < 0) {
      daemon_log_warn("Failed to close inotify fd: %s", strerror(errno));
    }
    inotify_fd = -1;
  }

  /* 修复 R3-3：使用写锁保护对全局 cfg 的访问，防止与 SIGHUP 重载竞态 */
  pthread_rwlock_wrlock(&config_rwlock);

  /* 释放所有 jail 及其资源 */
  for (int j = 0; j < cfg.jail_count; j++) {
    struct jail *jail = &cfg.jails[j];

    /* 释放日志文件 */
    for (int i = 0; i < jail->log_count; i++) {
      if (jail->log_files[i]) {
        free(jail->log_files[i]);
        jail->log_files[i] = NULL;
      }
    }
    jail->log_count = 0;

    /* 释放正则表达式 */
    free_jail_regex(jail);
    if (jail->regex_pattern) {
      free(jail->regex_pattern);
      jail->regex_pattern = NULL;
    }

    /* 修复 2.3：删除废弃的 failed_table 清理代码（仅使用 khash） */
    memset(jail->failed_hash_table, 0, sizeof(jail->failed_hash_table));

    /* 释放 khash 表 */
    if (jail->failed_hash) {
      /* 在销毁哈希表之前释放堆分配的键 */
      khint_t k;
      for (k = kh_begin(jail->failed_hash); k != kh_end(jail->failed_hash);
           ++k) {
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

  /* 释放全局配置字符串 */
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

  pthread_rwlock_unlock(&config_rwlock);

  /* 关闭 SQLite 数据库 */
  if (sqlite_db) {
    sqlite_close(sqlite_db);
    sqlite_db = NULL;
    daemon_log_info("SQLite database closed");
  }

  closelog();
}

/* 主入口点 */
int main(int argc, char *argv[]) {
  int ret;

  /* 初始化 file_states 数组，将 wd 和 jail_idx 设为
   * -1，以区别于有效的监视描述符 */
  for (int i = 0; i < MAX_JAILS * MAX_LOG_FILES; i++) {
    file_states[i].wd = -1;
    file_states[i].jail_idx = -1;
  }

  /* 解析配置 */
  ret = parse_config(argc, argv);
  if (ret < 0) {
    fprintf(stderr, "Error: invalid configuration\n");
    return EXIT_FAILURE;
  }
  if (ret > 0) {
    /* 已显示帮助信息 */
    return EXIT_SUCCESS;
  }

  /* 打开 syslog */
  openlog("firewall", LOG_PID | LOG_CONS, LOG_DAEMON);

  /* 在继续之前检查 procfs 接口是否存在 */
  if (access(PROCFS_DIR, F_OK) != 0) {
    daemon_log_err(
        "Procfs directory %s does not exist. Is the kernel module loaded?",
        PROCFS_DIR);
    fprintf(stderr,
            "Error: Procfs directory %s does not exist. Is the kernel module "
            "loaded?\n",
            PROCFS_DIR);
    return EXIT_FAILURE;
  }

  if (access(BANS_PATH, F_OK) != 0) {
    daemon_log_err("Bans procfs interface %s does not exist", BANS_PATH);
    fprintf(stderr, "Error: Bans procfs interface %s does not exist\n",
            BANS_PATH);
    return EXIT_FAILURE;
  }

  /* 初始化日志模式 */
  if (init_log_patterns() < 0) {
    daemon_log_err("Failed to initialize log patterns");
    cleanup();
    return EXIT_FAILURE;
  }

  /* 初始化统计信息 */
  daemon_stats.start_time = time(NULL);

  /* 如果已配置，初始化用于永久封禁的 SQLite 数据库 */
  if (cfg.permanent_ban_enabled && cfg.permanent_db_path) {
    sqlite_db = sqlite_init(cfg.permanent_db_path);
    if (!sqlite_db) {
      daemon_log_warn(
          "Failed to initialize SQLite database for permanent bans at %s",
          cfg.permanent_db_path);
      daemon_log_warn("Permanent bans will not be available");
    } else {
      daemon_log_info("SQLite database initialized for permanent bans at %s",
                      cfg.permanent_db_path);

      /* 从 SQLite 加载永久封禁并应用到内核模块 */
      struct permanent_ban_entry *entries = NULL;
      int count = 0;
      if (sqlite_load_all_permanent_bans(sqlite_db, &entries, &count) == 0 &&
          count > 0) {
        daemon_log_info("Loading %d permanent bans from SQLite database",
                        count);
        for (int i = 0; i < count; i++) {
          char ip_with_newline[64]; /* 足够容纳 IPv6 地址 + "permanent " 前缀 +
                                       换行 */
          snprintf(ip_with_newline, sizeof(ip_with_newline), "permanent %s\n",
                   entries[i].ip);

          if (secure_procfs_write(BANS_PATH, ip_with_newline,
                                  strlen(ip_with_newline)) < 0) {
            daemon_log_warn("Failed to restore permanent ban for %s to kernel",
                            entries[i].ip);
          } else {
            daemon_log_info("Restored permanent ban for %s (reason: %s)",
                            entries[i].ip, entries[i].reason);
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

  /* 设置信号处理函数 */
  setup_signals();

  daemon_log_info("Daemon starting up");
  daemon_log_info("Loaded %d jails", cfg.jail_count);
  for (int i = 0; i < cfg.jail_count; i++) {
    if (cfg.jails[i].enabled) {
      daemon_log_info("  Jail[%d]: %s (enabled=%d, log_count=%d, "
                      "max_retries=%u, findtime=%u, ban_time=%u)",
                      i, cfg.jails[i].name, cfg.jails[i].enabled,
                      cfg.jails[i].log_count, cfg.jails[i].max_retries,
                      cfg.jails[i].findtime, cfg.jails[i].ban_time);
    }
  }
  daemon_log_info("Global defaults: max_retries=%u, findtime=%u, ban_time=%u",
                  cfg.default_max_retries, cfg.default_findtime,
                  cfg.default_ban_time);

  /* 如果请求则守护进程化 */
  if (cfg.daemon) {
    daemonize_process();
  }

  /* 设置 inotify */
  if (setup_inotify() < 0) {
    daemon_log_err("Failed to setup inotify");
    cleanup();
    return EXIT_FAILURE;
  }

  /* 运行监控循环 */

  /* 启动 Prometheus HTTP 导出器 */
  pthread_t exporter_thread;
  if (cfg.metrics_port > 0) {
    if (pthread_create(&exporter_thread, NULL, start_http_exporter,
                       (void *)(long)cfg.metrics_port) != 0) {
      daemon_log_warn("Failed to start Prometheus exporter thread");
    } else {
      daemon_log_info("Prometheus exporter started on port %d",
                      cfg.metrics_port);
      /* 不 detach 线程，由 stop_http_exporter 负责 join 清理 */
    }
  } else {
    daemon_log_info("Prometheus exporter disabled (metrics_port=0)");
  }

  monitor_loop();

  /* 清理 */
  cleanup();
  daemon_log_info("Daemon stopped");

  return EXIT_SUCCESS;
}