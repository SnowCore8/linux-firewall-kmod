/*
 * firewall-daemon.h - 防火墙守护进程模块共享头文件
 *
 * 包含各个守护进程模块使用的共享常量、结构体、枚举和外部声明。
 */

#ifndef FIREWALL_DAEMON_H
#define FIREWALL_DAEMON_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include "khash.h"
#include "sqlite-persistent.h"
#include <ctype.h>
#include <dirent.h>
#include <libgen.h>
#include <limits.h>
#include <pcre2.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <yaml.h>

/* 每个 jail 的失败条目哈希表 */
KHASH_MAP_INIT_STR(ip_map, struct failed_entry *)

/* ============================================================================
 * 守护进程统一日志系统
 * ============================================================================
 * 所有守护进程日志使用 syslog，带有统一的 "firewall: " 前缀。
 * 标准错误输出仅在 syslog 初始化之前使用。
 * ========================================================================== */
#define daemon_log_err(fmt, ...) \
  syslog(LOG_ERR, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_warn(fmt, ...) \
  syslog(LOG_WARNING, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_info(fmt, ...) \
  syslog(LOG_INFO, "firewall: " fmt, ##__VA_ARGS__)
#define daemon_log_debug(fmt, ...) \
  syslog(LOG_DEBUG, "firewall: " fmt, ##__VA_ARGS__)

/* Procfs 路径 - 统一 bans 接口 */
#define PROCFS_DIR "/proc/firewall"
#define BANS_PATH PROCFS_DIR "/bans"

/* 默认配置 */
#define DEFAULT_MAX_RETRIES 3
#define DEFAULT_FINDTIME 600      /* 10 分钟 */
#define DEFAULT_BAN_TIME 600      /* 10 分钟 */
#define DEFAULT_INTERVAL 1        /* 检查间隔（秒） */
#define DEFAULT_METRICS_PORT 9119 /* Prometheus 指标端口 */

/* 每个 IP 最多跟踪的失败尝试次数 */
#define MAX_FAILED_TIMESTAMPS 100

/* 每个 jail 最多监控的日志文件数 */
#define MAX_LOG_FILES 10

/* 每个 jail 最多支持的正则表达式数量 */
#define MAX_REGEX_PATTERNS 10

/* 正则表达式名称最大长度 */
#define MAX_REGEX_NAME_LEN 64

/* 最大 jail 数量 */
#define MAX_JAILS 16

/* inotify 事件缓冲区大小 */
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

/* 用于检测日志轮转的文件状态跟踪 */
struct file_state {
  char path[512];
  off_t offset;
  ino_t inode;
  int wd;       /* inotify 监视描述符 */
  int jail_idx; /* 此文件所属的 jail */
  bool symlink_detected; /* 修复：标记文件是否为符号链接，防止重复处理 */
};

/* 命名正则表达式结构 */
struct regex_info {
  char name[MAX_REGEX_NAME_LEN]; /* 正则表达式名称（如 invalid_user） */
  char *pattern;                 /* 正则表达式模式 */
  pcre2_code *compiled;          /* 编译后的 PCRE2 对象 */
  pcre2_match_data *match_data; /* PCRE2 匹配数据 */
};

/* Jail 结构体 - 独立的监控单元 */
struct jail {
  char name[64];                  /* Jail 名称（sshd、nginx 等） */
  bool enabled;                   /* 此 jail 是否处于活动状态 */
  char *log_files[MAX_LOG_FILES]; /* 此 jail 的日志文件 */
  int log_count;                  /* 日志文件数量 */
  /* 多正则表达式支持 */
  struct regex_info regexes[MAX_REGEX_PATTERNS]; /* 命名正则表达式数组 */
  int regex_count;                               /* 正则表达式数量 */
  int regex_compiled;                            /* 是否已编译 */
  unsigned int max_retries; /* 封禁前的最大失败次数 */
  unsigned int findtime;    /* 统计失败次数的时间窗口 */
  unsigned int ban_time;    /* 封禁持续时间 */
  bool _max_retries_set;    /* 用户是否显式配置了 max_retries */
  bool _findtime_set;       /* 用户是否显式配置了 findtime */
  bool _ban_time_set;       /* 用户是否显式配置了 ban_time */
  struct failed_entry *failed_hash_table[256]; /* 手动哈希表（废弃） */
  khash_t(ip_map) * failed_hash;               /* khash 用于 O(1) 查找 */
  char partial_line_buffer[8192]; /* 不完整日志行的缓冲区 */
  atomic_size_t partial_line_len; /* 修复 P2-7：使用原子类型，允许无锁读取和原子清零 */
};

/* 全局运行标志 - 修复：统一使用 _Atomic(int) 替代 volatile sig_atomic_t */
extern _Atomic(int) running;
extern _Atomic(int) reload_config;

/* 配置严格模式标志 */
extern int config_strict_mode;

/* 全局默认配置 */
struct config {
  unsigned int default_max_retries; /* 新 jail 的默认值 */
  unsigned int default_findtime;
  unsigned int default_ban_time;
  int daemon;
  int interval;
  int metrics_port;           /* Prometheus 指标端口（0 = 禁用） */
  char *metrics_bind_address; /* Prometheus 指标绑定地址（默认 127.0.0.1） */
  char *metrics_username; /* Prometheus 指标 Basic Auth 用户名 */
  char *metrics_password; /* Prometheus 指标 Basic Auth 密码 */
  char *config_file;      /* 运行时更新的单个配置文件路径 */
  char *config_dir; /* 配置目录路径（自动加载所有 .yaml/.yml） */
  char *permanent_db_path; /* 永久封禁的 SQLite 数据库路径（NULL = 禁用） */
  int permanent_ban_enabled;    /* 是否启用永久封禁 */
  struct jail jails[MAX_JAILS]; /* 所有 jails */
  int jail_count;
};

/* 失败尝试跟踪器 */
struct failed_entry {
  char ip[INET6_ADDRSTRLEN + 1]; /* +1 用于 null 终止符 */
  time_t timestamps[MAX_FAILED_TIMESTAMPS];
  unsigned int count;
  /* H2 修复：将 recent_head 改为原子类型，防止多线程并发更新时的竞态条件 */
  _Atomic(unsigned int) recent_head; /* R9-7: 滑动窗口起始索引，O(1) 计数优化 */
  struct failed_entry *next;
  struct failed_entry *next_in_hash; /* 哈希桶中的下一个条目 */
};

/* 配置读写锁 - 保护 cfg 全局变量的多线程访问
 * 使用读写锁允许多个读者并发访问，写者独占访问 */
extern pthread_rwlock_t config_rwlock;

/* 全局状态 */
extern struct config cfg;
extern struct daemon_stats daemon_stats;
extern int inotify_fd;
extern struct file_state file_states[MAX_JAILS * MAX_LOG_FILES];
extern sqlite_db_t *sqlite_db;

/* ============================================================================
 * Prometheus 统计
 * ============================================================================
 * 使用原子操作的线程安全计数器，用于监控和指标。
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
  atomic_ulong regex_matches; /* Total regex matches across all jails */
  time_t start_time;
};

/* ============================================================================
 * 封禁/解封操作类型
 * ========================================================================== */
typedef enum {
  BAN_ACTION_TEMP,      /* 临时封禁（默认持续时间） */
  BAN_ACTION_PERMANENT, /* 永久封禁 */
  BAN_ACTION_UNBAN,     /* 解封 IP */
  BAN_ACTION_UNBAN_PERM /* 移除永久封禁 */
} ban_action_t;

/* 保存已验证 IP 信息的结构体 (支持 IPv4/IPv6) */
typedef struct {
  int af; /* AF_INET 或 AF_INET6 */
  union {
    struct in_addr addr4;
    struct in6_addr addr6;
  } addr;
  uint32_t ip_num; /* 网络字节序 (仅 IPv4 有效) */
} validated_ip_t;

/* 外部函数声明 */
extern void signal_handler(int sig);
extern void daemonize_process(void);
extern void cleanup(void);
extern void *start_http_exporter(void *port);
extern void stop_http_exporter(void);

/* 模块间调用的函数声明 */
extern int ban_ip(const char *ip);
extern void cleanup_partial_line_buffer(void);
extern void cleanup_expired_bans(void);
extern int parse_config_file(const char *config_path);
extern int load_config_directory(const char *config_dir);

#endif /* FIREWALL_DAEMON_H */