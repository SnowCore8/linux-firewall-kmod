/*
 * sqlite-persistent.c - SQLite 持久化永久黑名单模块
 * 提供永久黑名单的存储、加载和查询函数
 * 使用 SQLite 数据库实现持久化存储
 */

#include "sqlite-persistent.h"
#include <errno.h>
#include <libgen.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>

/* 日志辅助宏 - 使用 syslog 与守护进程日志系统集成 */
#define sqlite_log_err(fmt, ...)                                               \
  syslog(LOG_ERR, "firewall[sqlite]: ERROR: " fmt, ##__VA_ARGS__)
#define sqlite_log_warn(fmt, ...)                                              \
  syslog(LOG_WARNING, "firewall[sqlite]: WARN: " fmt, ##__VA_ARGS__)
#define sqlite_log_info(fmt, ...)                                              \
  syslog(LOG_INFO, "firewall[sqlite]: " fmt, ##__VA_ARGS__)

/* 数据库句柄结构 */
struct sqlite_db {
  sqlite3 *conn;        /* SQLite 连接句柄 */
  char db_path[512];    /* 数据库文件路径 */
  pthread_mutex_t lock; /* 线程安全互斥锁 */

  /* 缓存的 prepared statements，避免高频操作时重复编译 SQL */
  sqlite3_stmt *stmt_add_ban;      /* INSERT 永久封禁 */
  sqlite3_stmt *stmt_remove_ban;   /* UPDATE is_active=0 软删除 */
  sqlite3_stmt *stmt_check_ban;    /* SELECT 1 检查是否存在 */
  sqlite3_stmt *stmt_update_stats; /* UPDATE hit_count 命中统计 */
  sqlite3_stmt *stmt_load_all;     /* SELECT 加载所有活跃条目 */
  sqlite3_stmt *stmt_stats_total;  /* COUNT(*) 总记录数 */
  sqlite3_stmt *stmt_stats_active; /* COUNT(*) 活跃记录数 */
  sqlite3_stmt *stmt_purge_days;   /* DELETE 按天数清理 */
  sqlite3_stmt *stmt_purge_all;    /* DELETE 所有已删除 */
};

/* ============================================================================
 * 内部辅助函数
 * ========================================================================== */

/**
 * 确保数据库目录存在
 */
static int ensure_db_dir(const char *db_path) {
  char *path_copy = strdup(db_path);
  if (!path_copy) {
    sqlite_log_err("Out of memory ensuring database directory");
    return -1;
  }

  char *dir = dirname(path_copy);
  struct stat st;

  /* 验证目录不在敏感位置 */
  if (strcmp(dir, "/") == 0 || strcmp(dir, "/etc") == 0 ||
      strcmp(dir, "/usr") == 0 || strcmp(dir, "/bin") == 0 ||
      strcmp(dir, "/sbin") == 0) {
    sqlite_log_err("Unsafe database directory path: %s", dir);
    free(path_copy);
    return -1;
  }

  if (stat(dir, &st) != 0) {
    /* 目录不存在，尝试创建 */
    if (mkdir(dir, 0700) != 0) {
      sqlite_log_err("Failed to create database directory %s: %s", dir,
                     strerror(errno));
      free(path_copy);
      return -1;
    }
  } else if (!S_ISDIR(st.st_mode)) {
    sqlite_log_err("Database path %s is not a directory", dir);
    free(path_copy);
    return -1;
  }

  free(path_copy);
  return 0;
}

/**
 * 准备所有缓存的 prepared statements
 * 成功返回 0，失败返回 -1
 */
static int prepare_cached_statements(sqlite_db_t *db) {
  int rc;

  /* INSERT 永久封禁 */
  rc = sqlite3_prepare_v2(
      db->conn,
      "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, "
      "created_by, hit_count, last_hit_at, is_active) "
      "VALUES (?, ?, ?, ?, ?, 0, 0, 1);",
      -1, &db->stmt_add_ban, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare INSERT statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* UPDATE is_active=0 软删除 */
  rc = sqlite3_prepare_v2(db->conn,
                          "UPDATE permanent_banlist SET is_active = 0 WHERE ip "
                          "= ? AND is_active = 1;",
                          -1, &db->stmt_remove_ban, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare REMOVE statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* SELECT 1 检查是否存在 */
  rc = sqlite3_prepare_v2(db->conn,
                          "SELECT 1 FROM permanent_banlist WHERE ip_num = ? "
                          "AND is_active = 1 LIMIT 1;",
                          -1, &db->stmt_check_ban, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare CHECK statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* UPDATE hit_count 命中统计 */
  rc = sqlite3_prepare_v2(
      db->conn,
      "UPDATE permanent_banlist SET hit_count = hit_count + 1, last_hit_at = ? "
      "WHERE ip_num = ? AND is_active = 1;",
      -1, &db->stmt_update_stats, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare UPDATE_STATS statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* SELECT 加载所有活跃条目 */
  rc = sqlite3_prepare_v2(
      db->conn,
      "SELECT id, ip, ip_num, reason, created_at, created_by, hit_count, "
      "last_hit_at, is_active "
      "FROM permanent_banlist WHERE is_active = 1 ORDER BY created_at;",
      -1, &db->stmt_load_all, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare LOAD_ALL statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* COUNT(*) 总记录数 */
  rc = sqlite3_prepare_v2(db->conn, "SELECT COUNT(*) FROM permanent_banlist;",
                          -1, &db->stmt_stats_total, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare STATS_TOTAL statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* COUNT(*) 活跃记录数 */
  rc = sqlite3_prepare_v2(
      db->conn, "SELECT COUNT(*) FROM permanent_banlist WHERE is_active = 1;",
      -1, &db->stmt_stats_active, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare STATS_ACTIVE statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* DELETE 按天数清理 */
  rc = sqlite3_prepare_v2(
      db->conn,
      "DELETE FROM permanent_banlist WHERE is_active = 0 AND last_hit_at < ?;",
      -1, &db->stmt_purge_days, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare PURGE_DAYS statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  /* DELETE 所有已删除 */
  rc = sqlite3_prepare_v2(db->conn,
                          "DELETE FROM permanent_banlist WHERE is_active = 0;",
                          -1, &db->stmt_purge_all, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to prepare PURGE_ALL statement: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  return 0;
}

/**
 * 释放所有缓存的 prepared statements
 */
static void finalize_cached_statements(sqlite_db_t *db) {
  if (db->stmt_add_ban) {
    sqlite3_finalize(db->stmt_add_ban);
    db->stmt_add_ban = NULL;
  }
  if (db->stmt_remove_ban) {
    sqlite3_finalize(db->stmt_remove_ban);
    db->stmt_remove_ban = NULL;
  }
  if (db->stmt_check_ban) {
    sqlite3_finalize(db->stmt_check_ban);
    db->stmt_check_ban = NULL;
  }
  if (db->stmt_update_stats) {
    sqlite3_finalize(db->stmt_update_stats);
    db->stmt_update_stats = NULL;
  }
  if (db->stmt_load_all) {
    sqlite3_finalize(db->stmt_load_all);
    db->stmt_load_all = NULL;
  }
  if (db->stmt_stats_total) {
    sqlite3_finalize(db->stmt_stats_total);
    db->stmt_stats_total = NULL;
  }
  if (db->stmt_stats_active) {
    sqlite3_finalize(db->stmt_stats_active);
    db->stmt_stats_active = NULL;
  }
  if (db->stmt_purge_days) {
    sqlite3_finalize(db->stmt_purge_days);
    db->stmt_purge_days = NULL;
  }
  if (db->stmt_purge_all) {
    sqlite3_finalize(db->stmt_purge_all);
    db->stmt_purge_all = NULL;
  }
}

/**
 * 初始化数据库表结构
 * 包含迁移逻辑：将缺少 UNIQUE 约束的旧表升级到新结构。
 *
 * 迁移策略：
 * 1. 创建新表 permanent_banlist_new（含 UNIQUE(ip)）
 * 2. 检测旧表是否存在数据 → 需要迁移
 * 3. 去重后复制到新表（保留最早的记录）
 * 4. 原子替换：删除旧表，重命名新表
 * 5. 创建索引
 */
static int init_db_schema(sqlite3 *conn) {
  char *err_msg = NULL;
  int rc;

  /* 新表结构：ip 列添加 UNIQUE 约束，保证所有地址（含 IPv6）唯一 */
  const char *create_new_table_sql =
      "CREATE TABLE IF NOT EXISTS permanent_banlist_new (\n"
      "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
      "    ip TEXT NOT NULL UNIQUE,\n"
      "    ip_num INTEGER NOT NULL DEFAULT 0,\n"
      "    reason TEXT DEFAULT 'auto-ban',\n"
      "    created_at INTEGER NOT NULL,\n"
      "    created_by TEXT DEFAULT 'auto',\n"
      "    hit_count INTEGER DEFAULT 0,\n"
      "    last_hit_at INTEGER,\n"
      "    is_active INTEGER DEFAULT 1\n"
      ");";

  /* 第一步：创建新表 */
  rc = sqlite3_exec(conn, create_new_table_sql, NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to create permanent_banlist_new table: %s", err_msg);
    sqlite3_free(err_msg);
    return -1;
  }

  /* 第二步：检查新表是否为空（刚创建），且旧表存在数据 → 需要迁移 */
  int new_table_empty = 1;
  sqlite3_stmt *check_stmt = NULL;
  rc = sqlite3_prepare_v2(conn, "SELECT COUNT(*) FROM permanent_banlist_new;",
                          -1, &check_stmt, NULL);
  if (rc == SQLITE_OK) {
    if (sqlite3_step(check_stmt) == SQLITE_ROW) {
      new_table_empty = (sqlite3_column_int(check_stmt, 0) == 0);
    }
    sqlite3_finalize(check_stmt);
  }

  /* 检查旧表是否存在 */
  int old_table_exists = 0;
  rc = sqlite3_prepare_v2(
      conn,
      "SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
      "AND name='permanent_banlist';",
      -1, &check_stmt, NULL);
  if (rc == SQLITE_OK) {
    if (sqlite3_step(check_stmt) == SQLITE_ROW) {
      old_table_exists = (sqlite3_column_int(check_stmt, 0) > 0);
    }
    sqlite3_finalize(check_stmt);
  }

  if (new_table_empty && old_table_exists) {
    /* 需要迁移：从旧表去重后复制到新表 */
    syslog(LOG_INFO,
           "firewall: SQLite 迁移：检测到旧表结构，开始去重迁移到 UNIQUE(ip)");

    /* 用事务包裹整个迁移流程，确保原子性 */
    rc = sqlite3_exec(conn, "BEGIN TRANSACTION;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      sqlite_log_err("Failed to begin migration transaction: %s", err_msg);
      sqlite3_free(err_msg);
      return -1;
    }

    /* 清理所有重复记录（不限 ip_num），保留 rowid 最小（最早）的一条 */
    rc = sqlite3_exec(conn,
                      "DELETE FROM permanent_banlist WHERE rowid NOT IN ("
                      "  SELECT MIN(rowid) FROM permanent_banlist "
                      "  GROUP BY ip"
                      ");",
                      NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      sqlite_log_err("Failed to clean duplicate records: %s", err_msg);
      sqlite3_free(err_msg);
      sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
      return -1;
    }

    /* 复制旧表数据到新表 */
    rc = sqlite3_exec(
        conn,
        "INSERT OR IGNORE INTO permanent_banlist_new "
        "(ip, ip_num, reason, created_at, created_by, hit_count, "
        "last_hit_at, is_active) "
        "SELECT ip, ip_num, reason, created_at, created_by, hit_count, "
        "last_hit_at, is_active FROM permanent_banlist;",
        NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      sqlite_log_err("Failed to migrate data to new table: %s", err_msg);
      sqlite3_free(err_msg);
      sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
      sqlite3_exec(conn, "DROP TABLE IF EXISTS permanent_banlist_new;", NULL,
                   NULL, NULL);
      return -1;
    }

    /* 原子替换：删除旧表，重命名新表 */
    rc = sqlite3_exec(
        conn,
        "DROP TABLE IF EXISTS permanent_banlist;"
        "ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      sqlite_log_err("Failed to replace old table: %s", err_msg);
      sqlite3_free(err_msg);
      sqlite3_exec(conn, "ROLLBACK;", NULL, NULL, NULL);
      return -1;
    }

    /* 提交事务 */
    rc = sqlite3_exec(conn, "COMMIT;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
      sqlite_log_err("Failed to commit migration transaction: %s", err_msg);
      sqlite3_free(err_msg);
      /* COMMIT 失败后事务自动回滚 */
      return -1;
    }

    syslog(LOG_INFO, "firewall: SQLite 迁移完成");
  } else if (!new_table_empty) {
    /* 新表已有数据（迁移已完成过的二次启动），清理临时表 */
    sqlite3_exec(conn, "DROP TABLE IF EXISTS permanent_banlist_new;", NULL,
                 NULL, NULL);
  } else {
    /* 旧表不存在且新表为空：纯新库，只需重命名新表 */
    sqlite3_exec(
        conn,
        "DROP TABLE IF EXISTS permanent_banlist;"
        "ALTER TABLE permanent_banlist_new RENAME TO permanent_banlist;",
        NULL, NULL, NULL);
  }

  /* 删除旧的部分唯一索引（如果存在），UNIQUE(ip) 已覆盖所有情况 */
  sqlite3_exec(conn, "DROP INDEX IF EXISTS idx_ip_num_unique;", NULL, NULL,
               NULL);

  /* 在最终表 permanent_banlist 上创建索引 */
  const char *create_index1_sql =
      "CREATE INDEX IF NOT EXISTS idx_ip_num ON permanent_banlist(ip_num);";
  const char *create_index2_sql = "CREATE INDEX IF NOT EXISTS idx_is_active ON "
                                  "permanent_banlist(is_active);";

  rc = sqlite3_exec(conn, create_index1_sql, NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to create idx_ip_num index: %s", err_msg);
    sqlite3_free(err_msg);
    return -1;
  }

  rc = sqlite3_exec(conn, create_index2_sql, NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to create idx_is_active index: %s", err_msg);
    sqlite3_free(err_msg);
    return -1;
  }

  return 0;
}

/**
 * 启用 WAL 模式以提高并发性能
 */
static int enable_wal_mode(sqlite3 *conn) {
  char *err_msg = NULL;
  int rc;

  rc = sqlite3_exec(conn, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to enable WAL mode: %s",
                   err_msg ? err_msg : "未知错误");
    sqlite3_free(err_msg);
    return -1;
  }

  rc = sqlite3_exec(conn, "PRAGMA synchronous=FULL;", NULL, NULL, &err_msg);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to set synchronous=FULL: %s",
                   err_msg ? err_msg : "unknown error");
    sqlite3_free(err_msg);
    return -1;
  }

  return 0;
}

/* ============================================================================
 * 公共接口实现
 * ========================================================================== */

/**
 * 初始化 SQLite 数据库
 */
sqlite_db_t *sqlite_init(const char *db_path) {
  if (!db_path) {
    sqlite_log_err("sqlite_init: db_path is NULL");
    return NULL;
  }

  sqlite_db_t *db = calloc(1, sizeof(sqlite_db_t));
  if (!db) {
    sqlite_log_err("Failed to allocate sqlite_db_t");
    return NULL;
  }

  strncpy(db->db_path, db_path, sizeof(db->db_path) - 1);
  db->db_path[sizeof(db->db_path) - 1] = '\0';

  /* 初始化互斥锁 */
  pthread_mutex_init(&db->lock, NULL);

  /* 确保目录存在 */
  if (ensure_db_dir(db_path) != 0) {
    pthread_mutex_destroy(&db->lock);
    free(db);
    return NULL;
  }

  /* 打开数据库连接 */
  int rc = sqlite3_open(db_path, &db->conn);
  if (rc != SQLITE_OK) {
    sqlite_log_err("Failed to open SQLite database %s: %s", db_path,
                   sqlite3_errmsg(db->conn));
    sqlite3_close(db->conn);
    pthread_mutex_destroy(&db->lock);
    free(db);
    return NULL;
  }

  /* 启用 WAL 模式 */
  if (enable_wal_mode(db->conn) != 0) {
    sqlite_log_warn("WAL mode not enabled");
  }

  /* 初始化表结构 */
  if (init_db_schema(db->conn) != 0) {
    sqlite_log_err("Failed to initialize database schema");
    sqlite3_close(db->conn);
    pthread_mutex_destroy(&db->lock);
    free(db);
    return NULL;
  }

  /* 准备缓存的 prepared statements，避免高频操作时重复编译 SQL */
  if (prepare_cached_statements(db) != 0) {
    sqlite_log_err("Failed to prepare cached statements");
    sqlite3_close(db->conn);
    pthread_mutex_destroy(&db->lock);
    free(db);
    return NULL;
  }

  syslog(LOG_INFO, "firewall: SQLite 持久化黑名单初始化：%s", db_path);
  return db;
}

/**
 * 关闭 SQLite 数据库
 */
void sqlite_close(sqlite_db_t *db) {
  if (!db)
    return;

  /* 释放缓存的 prepared statements */
  finalize_cached_statements(db);

  if (db->conn) {
    sqlite3_close(db->conn);
  }
  pthread_mutex_destroy(&db->lock);
  free(db);
}

/**
 * 添加永久黑名单条目
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_add_permanent_ban(sqlite_db_t *db, const char *ip, uint32_t ip_num,
                             const char *reason, const char *created_by) {
  if (!db || !ip || !reason || !created_by) {
    sqlite_log_err("sqlite_add_permanent_ban: invalid parameter");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  int rc;

  /* 重置缓存语句以清除之前的绑定 */
  sqlite3_reset(db->stmt_add_ban);
  sqlite3_clear_bindings(db->stmt_add_ban);

  sqlite3_bind_text(db->stmt_add_ban, 1, ip, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(db->stmt_add_ban, 2, (sqlite3_int64)ip_num);
  sqlite3_bind_text(db->stmt_add_ban, 3, reason, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int64(db->stmt_add_ban, 4, (sqlite3_int64)time(NULL));
  sqlite3_bind_text(db->stmt_add_ban, 5, created_by, -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(db->stmt_add_ban);

  pthread_mutex_unlock(&db->lock);

  if (rc == SQLITE_DONE) {
    return 0; /* 成功 */
  } else if (rc == SQLITE_CONSTRAINT) {
    return -2; /* 已存在 */
  } else {
    sqlite_log_err("Failed to insert permanent ban: %s",
                   sqlite3_errmsg(db->conn));
    return -1;
  }
}

/**
 * 批量添加永久黑名单条目（使用事务优化性能）
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_add_permanent_bans_batch(sqlite_db_t *db, const char **ips,
                                    const uint32_t *ip_nums,
                                    const char **reasons,
                                    const char **created_bys, int count) {
  if (!db || !ips || !ip_nums || !reasons || !created_bys || count <= 0) {
    sqlite_log_err(
        "firewall: sqlite_add_permanent_bans_batch: invalid parameter\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  int rc;
  int success_count = 0;

  /* 开始事务 */
  rc = sqlite3_exec(db->conn, "BEGIN TRANSACTION;", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("firewall: 开始事务失败：%s\n", sqlite3_errmsg(db->conn));
    pthread_mutex_unlock(&db->lock);
    return -1;
  }

  for (int i = 0; i < count; i++) {
    /* 重置缓存语句以清除之前的绑定 */
    sqlite3_reset(db->stmt_add_ban);
    sqlite3_clear_bindings(db->stmt_add_ban);

    sqlite3_bind_text(db->stmt_add_ban, 1, ips[i], -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(db->stmt_add_ban, 2, (sqlite3_int64)ip_nums[i]);
    sqlite3_bind_text(db->stmt_add_ban, 3, reasons[i], -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(db->stmt_add_ban, 4, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(db->stmt_add_ban, 5, created_bys[i], -1,
                      SQLITE_TRANSIENT);

    rc = sqlite3_step(db->stmt_add_ban);

    if (rc == SQLITE_DONE) {
      success_count++;
    } else if (rc == SQLITE_CONSTRAINT) {
      /* 修复 S2-4：约束错误（如重复 IP）是预期的，显式重置语句后安全跳过 */
      sqlite3_clear_bindings(db->stmt_add_ban);
      sqlite3_reset(db->stmt_add_ban);
      continue;
    } else {
      /* 修复 P1-3：遇到非约束错误时立即回滚事务，防止部分提交 */
      sqlite_log_err("firewall: Failed to insert permanent ban %d: %s\n", i,
                     sqlite3_errmsg(db->conn));
      sqlite3_exec(db->conn, "ROLLBACK;", NULL, NULL, NULL);
      pthread_mutex_unlock(&db->lock);
      return -1;
    }
  }

  /* 提交事务 */
  rc = sqlite3_exec(db->conn, "COMMIT;", NULL, NULL, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("firewall: 提交事务失败：%s\n", sqlite3_errmsg(db->conn));
    /* COMMIT 失败后事务自动回滚，无需显式 ROLLBACK */
    pthread_mutex_unlock(&db->lock);
    return -1;
  }

  pthread_mutex_unlock(&db->lock);

  return success_count;
}

/**
 * 移除永久黑名单条目（软删除）
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_remove_permanent_ban(sqlite_db_t *db, const char *ip) {
  if (!db || !ip) {
    sqlite_log_err(
        "firewall: sqlite_remove_permanent_ban: invalid parameter\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  /* 重置缓存语句以清除之前的绑定 */
  sqlite3_reset(db->stmt_remove_ban);
  sqlite3_clear_bindings(db->stmt_remove_ban);

  sqlite3_bind_text(db->stmt_remove_ban, 1, ip, -1, SQLITE_TRANSIENT);
  int rc = sqlite3_step(db->stmt_remove_ban);

  pthread_mutex_unlock(&db->lock);

  if (rc == SQLITE_DONE) {
    int changes = sqlite3_changes(db->conn);
    if (changes > 0) {
      return 0; /* 成功 */
    } else {
      return -2; /* 不存在 */
    }
  } else {
    sqlite_log_err("firewall: 移除永久封禁失败：%s\n",
                   sqlite3_errmsg(db->conn));
    return -1;
  }
}

/**
 * 检查 IP 是否在永久黑名单中
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_is_permanent_banned(sqlite_db_t *db, uint32_t ip_num) {
  if (!db) {
    sqlite_log_err("firewall: sqlite_is_permanent_banned: db is NULL\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  /* 重置缓存语句以清除之前的绑定 */
  sqlite3_reset(db->stmt_check_ban);
  sqlite3_clear_bindings(db->stmt_check_ban);

  sqlite3_bind_int64(db->stmt_check_ban, 1, (sqlite3_int64)ip_num);
  int rc = sqlite3_step(db->stmt_check_ban);

  pthread_mutex_unlock(&db->lock);

  if (rc == SQLITE_ROW) {
    return 1; /* 在黑名单中 */
  } else if (rc == SQLITE_DONE) {
    return 0; /* 不在 */
  } else {
    sqlite_log_err("firewall: 查询永久封禁失败：%s\n",
                   sqlite3_errmsg(db->conn));
    return -1;
  }
}

/**
 * 检查 IP 是否在永久黑名单中 (IPv6)
 * 使用 ip TEXT 字段进行查找
 */
int sqlite_is_permanent_banned_ipv6(sqlite_db_t *db, const char *ip) {
  if (!db || !ip) {
    sqlite_log_err(
        "firewall: sqlite_is_permanent_banned_ipv6: invalid parameter\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db->conn,
                              "SELECT 1 FROM permanent_banlist WHERE ip = ? "
                              "AND is_active = 1 LIMIT 1;",
                              -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    sqlite_log_err("firewall: 准备 IPv6 CHECK 语句失败：%s\n",
                   sqlite3_errmsg(db->conn));
    pthread_mutex_unlock(&db->lock);
    return -1;
  }

  sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);

  sqlite3_finalize(stmt);
  pthread_mutex_unlock(&db->lock);

  if (rc == SQLITE_ROW) {
    return 1;
  } else if (rc == SQLITE_DONE) {
    return 0;
  } else {
    sqlite_log_err("firewall: 查询 IPv6 永久封禁失败：%s\n",
                   sqlite3_errmsg(db->conn));
    return -1;
  }
}

/**
 * 加载所有活动的永久黑名单条目
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_load_all_permanent_bans(sqlite_db_t *db,
                                   struct permanent_ban_entry **entries,
                                   int *count) {
  if (!db || !entries || !count) {
    sqlite_log_err(
        "firewall: sqlite_load_all_permanent_bans: invalid parameter\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  *entries = NULL;
  *count = 0;

  /* 重置缓存语句 */
  sqlite3_reset(db->stmt_load_all);
  sqlite3_clear_bindings(db->stmt_load_all);

  /* 先计数 */
  int rc;
  int n = 0;
  while ((rc = sqlite3_step(db->stmt_load_all)) == SQLITE_ROW) {
    n++;
  }
  sqlite3_reset(db->stmt_load_all);

  if (n == 0) {
    pthread_mutex_unlock(&db->lock);
    return 0; /* 无记录 */
  }

  /* 分配内存 */
  *entries = calloc(n, sizeof(struct permanent_ban_entry));
  if (!*entries) {
    sqlite_log_err("firewall: Out of memory allocating ban entries\n");
    pthread_mutex_unlock(&db->lock);
    return -1;
  }

  /* 读取数据 */
  int i = 0;
  while ((rc = sqlite3_step(db->stmt_load_all)) == SQLITE_ROW && i < n) {
    struct permanent_ban_entry *e = &(*entries)[i];
    e->id = sqlite3_column_int(db->stmt_load_all, 0);

    const unsigned char *ip_text = sqlite3_column_text(db->stmt_load_all, 1);
    if (ip_text) {
      strncpy(e->ip, (const char *)ip_text, sizeof(e->ip) - 1);
      e->ip[sizeof(e->ip) - 1] = '\0';
    }

    e->ip_num = (uint32_t)sqlite3_column_int64(db->stmt_load_all, 2);

    const unsigned char *reason = sqlite3_column_text(db->stmt_load_all, 3);
    if (reason) {
      strncpy(e->reason, (const char *)reason, sizeof(e->reason) - 1);
      e->reason[sizeof(e->reason) - 1] = '\0';
    }

    e->created_at = (time_t)sqlite3_column_int64(db->stmt_load_all, 4);

    const unsigned char *created_by = sqlite3_column_text(db->stmt_load_all, 5);
    if (created_by) {
      strncpy(e->created_by, (const char *)created_by,
              sizeof(e->created_by) - 1);
      e->created_by[sizeof(e->created_by) - 1] = '\0';
    }

    e->hit_count = sqlite3_column_int(db->stmt_load_all, 6);
    e->last_hit_at = (time_t)sqlite3_column_int64(db->stmt_load_all, 7);
    e->is_active = sqlite3_column_int(db->stmt_load_all, 8);

    i++;
  }

  *count = i;

  pthread_mutex_unlock(&db->lock);

  if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
    sqlite_log_err("firewall: Error reading permanent ban list: %s\n",
                   sqlite3_errmsg(db->conn));
    free(*entries);
    *entries = NULL;
    *count = 0;
    return -1;
  }

  return 0;
}

/**
 * 更新命中统计信息
 * 使用缓存的 prepared statement，避免重复编译 SQL
 */
int sqlite_update_hit_stats(sqlite_db_t *db, uint32_t ip_num) {
  if (!db) {
    sqlite_log_err("firewall: sqlite_update_hit_stats: db is NULL\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  /* 重置缓存语句以清除之前的绑定 */
  sqlite3_reset(db->stmt_update_stats);
  sqlite3_clear_bindings(db->stmt_update_stats);

  sqlite3_bind_int64(db->stmt_update_stats, 1, (sqlite3_int64)time(NULL));
  sqlite3_bind_int64(db->stmt_update_stats, 2, (sqlite3_int64)ip_num);
  int rc = sqlite3_step(db->stmt_update_stats);

  pthread_mutex_unlock(&db->lock);

  if (rc != SQLITE_DONE) {
    sqlite_log_err("firewall: Failed to update hit stats: %s\n",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  return 0;
}

/**
 * 获取数据库统计信息
 * 使用缓存的 prepared statements，避免重复编译 SQL
 */
int sqlite_get_stats(sqlite_db_t *db, int *total_count, int *active_count) {
  if (!db) {
    sqlite_log_err("firewall: sqlite_get_stats: db is NULL\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  /* 总记录数 */
  sqlite3_reset(db->stmt_stats_total);
  sqlite3_clear_bindings(db->stmt_stats_total);
  if (sqlite3_step(db->stmt_stats_total) == SQLITE_ROW) {
    *total_count = sqlite3_column_int(db->stmt_stats_total, 0);
  } else {
    *total_count = 0;
  }

  /* 活跃记录数 */
  sqlite3_reset(db->stmt_stats_active);
  sqlite3_clear_bindings(db->stmt_stats_active);
  if (sqlite3_step(db->stmt_stats_active) == SQLITE_ROW) {
    *active_count = sqlite3_column_int(db->stmt_stats_active, 0);
  } else {
    *active_count = 0;
  }

  pthread_mutex_unlock(&db->lock);

  return 0;
}

/**
 * 清理旧的已删除记录
 * 使用缓存的 prepared statements，避免重复编译 SQL
 */
int sqlite_purge_deleted(sqlite_db_t *db, int days) {
  if (!db) {
    sqlite_log_err("firewall: sqlite_purge_deleted: db is NULL\n");
    return -1;
  }

  pthread_mutex_lock(&db->lock);

  sqlite3_stmt *stmt;
  int rc;

  if (days > 0) {
    stmt = db->stmt_purge_days;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    time_t cutoff = time(NULL) - ((time_t)days * 86400);
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff);
  } else {
    stmt = db->stmt_purge_all;
    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
  }

  rc = sqlite3_step(stmt);
  int changes = sqlite3_changes(db->conn);

  pthread_mutex_unlock(&db->lock);

  if (rc != SQLITE_DONE) {
    sqlite_log_err("firewall: Failed to purge deleted records: %s\n",
                   sqlite3_errmsg(db->conn));
    return -1;
  }

  return changes;
}
