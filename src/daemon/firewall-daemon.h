/*
 * firewall-daemon.h - 防火墙守护进程模块共享头文件
 *
 * 包含各个守护进程模块使用的共享常量、结构体、枚举和外部声明。
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

/* 每个 jail 的失败条目哈希表 */
KHASH_MAP_INIT_STR(ip_map, struct failed_entry*)

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
#define DEFAULT_METRICS_PORT 9119  /* Prometheus 指标端口 */

/* 每个 IP 最多跟踪的失败尝试次数 */
#define MAX_FAILED_TIMESTAMPS 100

/* 每个 jail 最多监控的日志文件数 */
#define MAX_LOG_FILES 10

/* 最大 jail 数量 */
#define MAX_JAILS 16

/* inotify 事件缓冲区大小 */
#define EVENT_BUF_LEN (1024 * (sizeof(struct inotify_event) + 16))

/* 用于检测日志轮转的文件状态跟踪 */
struct file_state {
    char path[512];
    off_t offset;
    ino_t inode;
    int wd;  /* inotify 监视描述符 */
    int jail_idx;  /* 此文件所属的 jail */
};

/* Jail 结构体 - 独立的监控单元 */
struct jail {
    char name[64];                    /* Jail 名称（sshd、nginx 等） */
    bool enabled;                     /* 此 jail 是否处于活动状态 */
    char *log_files[MAX_LOG_FILES];   /* 此 jail 的日志文件 */
    int log_count;                    /* 日志文件数量 */
    char *regex_pattern;              /* 自定义正则表达式模式（NULL = 内置） */
    pcre2_code *compiled_regex;       /* 编译后的正则表达式（PCRE2） */
    pcre2_match_data *match_data;     /* PCRE2 匹配数据缓冲区 */
    int regex_compiled;               /* 正则表达式是否已编译 */
    unsigned int max_retries;         /* 封禁前的最大失败次数 */
    unsigned int findtime;            /* 统计失败次数的时间窗口 */
    unsigned int ban_time;            /* 封禁持续时间 */
    struct failed_entry *failed_table;/* 每个 jail 的失败尝试（链表） */
    struct failed_entry *failed_hash_table[256]; /* 手动哈希表 */
    khash_t(ip_map) *failed_hash;     /* khash 用于 O(1) 查找 */
    char partial_line_buffer[8192];   /* 不完整日志行的缓冲区 */
    size_t partial_line_len;          /* 当前不完整行的长度 */
};

/* 全局运行标志 */
extern volatile sig_atomic_t running;
extern volatile sig_atomic_t reload_config;

/* 全局默认配置 */
struct config {
    unsigned int default_max_retries; /* 新 jail 的默认值 */
    unsigned int default_findtime;
    unsigned int default_ban_time;
    int daemon;
    int interval;
    int metrics_port;       /* Prometheus 指标端口（0 = 禁用） */
    char *config_file;      /* 运行时更新的单个配置文件路径 */
    char *config_dir;       /* 配置目录路径（自动加载所有 .yaml/.yml） */
    char *permanent_db_path; /* 永久封禁的 SQLite 数据库路径（NULL = 禁用） */
    int permanent_ban_enabled; /* 是否启用永久封禁 */
    struct jail jails[MAX_JAILS]; /* 所有 jails */
    int jail_count;
};

/* 失败尝试跟踪器 */
struct failed_entry {
    char ip[16];
    time_t timestamps[MAX_FAILED_TIMESTAMPS];
    unsigned int count;
    struct failed_entry *next;
    struct failed_entry *next_in_hash;  /* 哈希桶中的下一个条目 */
};

/* 配置互斥锁 - 保护 cfg 全局变量的多线程访问 */
extern pthread_mutex_t config_mutex;

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
    atomic_ulong regex_matches_sshd;
    time_t start_time;
};

/* ============================================================================
 * 封禁/解封操作类型
 * ========================================================================== */
typedef enum {
    BAN_ACTION_TEMP,        /* 临时封禁（默认持续时间） */
    BAN_ACTION_PERMANENT,   /* 永久封禁 */
    BAN_ACTION_UNBAN,       /* 解封 IP */
    BAN_ACTION_UNBAN_PERM   /* 移除永久封禁 */
} ban_action_t;

/* 保存已验证 IP 信息的结构体 */
typedef struct {
    struct in_addr addr;
    uint32_t ip_num;  /* 网络字节序 */
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