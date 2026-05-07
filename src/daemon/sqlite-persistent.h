#ifndef SQLITE_PERSISTENT_H
#define SQLITE_PERSISTENT_H

#include <arpa/inet.h>
#include <stdint.h>
#include <time.h>

/* 永久封禁条目 (支持 IPv4/IPv6) */
struct permanent_ban_entry {
  int id;                    /* 数据库自增 ID */
  char ip[INET6_ADDRSTRLEN]; /* IP 地址（字符串，支持 IPv4/IPv6） */
  uint32_t ip_num;     /* IP 数字（网络字节序，仅 IPv4 有效） */
  int af;              /* 地址族: AF_INET 或 AF_INET6 */
  char reason[256];    /* 封禁原因 */
  time_t created_at;   /* 创建时间 */
  char created_by[32]; /* 触发来源（auto/manual/api） */
  int hit_count;       /* 匹配次数 */
  time_t last_hit_at;  /* 最后匹配时间 */
  int is_active;       /* 是否活跃（0=已删除但记录保留） */
};

/* 数据库句柄（对外不透明） */
typedef struct sqlite_db sqlite_db_t;

/**
 * 初始化 SQLite 数据库
 * @param db_path 数据库文件路径
 * @return 数据库句柄，失败返回 NULL
 */
sqlite_db_t *sqlite_init(const char *db_path);

/**
 * 关闭 SQLite 数据库
 * @param db 数据库句柄
 */
void sqlite_close(sqlite_db_t *db);

/**
 * 添加永久封禁条目
 * @param db 数据库句柄
 * @param ip IP 地址（字符串，支持 IPv4/IPv6）
 * @param ip_num IP 数字（网络字节序，仅 IPv4 有效，IPv6 时为 0）
 * @param reason 封禁原因
 * @param created_by 触发来源
 * @return 0 成功，-1 失败，-2 已存在
 */
int sqlite_add_permanent_ban(sqlite_db_t *db, const char *ip, uint32_t ip_num,
                             const char *reason, const char *created_by);

/**
 * 检查 IP 是否在永久黑名单中
 * @param db 数据库句柄
 * @param ip_num IP 数字（仅 IPv4）
 * @return 1 在黑名单中，0 不在，-1 查询失败
 */
int sqlite_is_permanent_banned(sqlite_db_t *db, uint32_t ip_num);

/**
 * 检查 IP 是否在永久黑名单中 (IPv6)
 * @param db 数据库句柄
 * @param ip IP 地址字符串
 * @return 1 在黑名单中，0 不在，-1 查询失败
 */
int sqlite_is_permanent_banned_ipv6(sqlite_db_t *db, const char *ip);

/**
 * 移除永久封禁条目（软删除）
 * @param db 数据库句柄
 * @param ip IP 地址
 * @return 0 成功，-1 失败，-2 不存在
 */
int sqlite_remove_permanent_ban(sqlite_db_t *db, const char *ip);

/**
 * 加载所有活跃的永久封禁条目
 * @param db 数据库句柄
 * @param entries 输出数组（调用者负责释放）
 * @param count 输出条目数量
 * @return 0 成功，-1 失败
 */
int sqlite_load_all_permanent_bans(sqlite_db_t *db,
                                   struct permanent_ban_entry **entries,
                                   int *count);

/**
 * 更新命中统计
 * @param db 数据库句柄
 * @param ip_num IP 数字（仅 IPv4）
 * @return 0 成功，-1 失败
 */
int sqlite_update_hit_stats(sqlite_db_t *db, uint32_t ip_num);

/**
 * 获取数据库统计信息
 * @param db 数据库句柄
 * @param total_count 总记录数（输出）
 * @param active_count 活跃记录数（输出）
 * @return 0 成功，-1 失败
 */
int sqlite_get_stats(sqlite_db_t *db, int *total_count, int *active_count);

/**
 * 清理已删除记录（可选维护操作）
 * @param db 数据库句柄
 * @param days 保留天数（0=清理所有已删除记录）
 * @return 清理的记录数，-1 失败
 */
int sqlite_purge_deleted(sqlite_db_t *db, int days);

#endif /* SQLITE_PERSISTENT_H */
