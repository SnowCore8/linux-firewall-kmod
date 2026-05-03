/*
 * sqlite-persistent.c - SQLite 持久化永久黑名单模块
 *
 * 提供永久黑名单的存储、加载、查询功能
 * 使用 SQLite 数据库实现持久化存储
 */

#include "sqlite-persistent.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <libgen.h>

/* 数据库句柄结构 */
struct sqlite_db {
    sqlite3 *conn;              /* SQLite 连接句柄 */
    char db_path[512];          /* 数据库文件路径 */
};

/* ============================================================================
 * 内部辅助函数
 * ========================================================================== */

/**
 * 确保数据库目录存在
 */
static int ensure_db_dir(const char *db_path)
{
    char *path_copy = strdup(db_path);
    if (!path_copy) {
        fprintf(stderr, "firewall: Out of memory ensuring db directory\n");
        return -1;
    }

    char *dir = dirname(path_copy);
    struct stat st;

    if (stat(dir, &st) != 0) {
        /* 目录不存在，尝试创建 */
        if (mkdir(dir, 0750) != 0) {
            fprintf(stderr, "firewall: Failed to create db directory %s: %s\n",
                    dir, strerror(errno));
            free(path_copy);
            return -1;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        fprintf(stderr, "firewall: db path %s is not a directory\n", dir);
        free(path_copy);
        return -1;
    }

    free(path_copy);
    return 0;
}

/**
 * 初始化数据库表结构
 */
static int init_db_schema(sqlite3 *conn)
{
    const char *create_table_sql = 
        "CREATE TABLE IF NOT EXISTS permanent_banlist (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    ip TEXT NOT NULL UNIQUE,\n"
        "    ip_num INTEGER NOT NULL UNIQUE,\n"
        "    reason TEXT DEFAULT 'auto-ban',\n"
        "    created_at INTEGER NOT NULL,\n"
        "    created_by TEXT DEFAULT 'auto',\n"
        "    hit_count INTEGER DEFAULT 0,\n"
        "    last_hit_at INTEGER,\n"
        "    is_active INTEGER DEFAULT 1\n"
        ");";

    const char *create_index1_sql = 
        "CREATE INDEX IF NOT EXISTS idx_ip_num ON permanent_banlist(ip_num);";

    const char *create_index2_sql = 
        "CREATE INDEX IF NOT EXISTS idx_is_active ON permanent_banlist(is_active);";

    char *err_msg = NULL;
    int rc;

    rc = sqlite3_exec(conn, create_table_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to create permanent_banlist table: %s\n",
                err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    rc = sqlite3_exec(conn, create_index1_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to create idx_ip_num index: %s\n",
                err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    rc = sqlite3_exec(conn, create_index2_sql, NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to create idx_is_active index: %s\n",
                err_msg);
        sqlite3_free(err_msg);
        return -1;
    }

    return 0;
}

/**
 * 启用 WAL 模式提升并发性能
 */
static int enable_wal_mode(sqlite3 *conn)
{
    char *err_msg = NULL;
    int rc;

    rc = sqlite3_exec(conn, "PRAGMA journal_mode=WAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to enable WAL mode: %s\n",
                err_msg ? err_msg : "unknown error");
        sqlite3_free(err_msg);
        return -1;
    }

    rc = sqlite3_exec(conn, "PRAGMA synchronous=NORMAL;", NULL, NULL, &err_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to set synchronous=NORMAL: %s\n",
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
sqlite_db_t *sqlite_init(const char *db_path)
{
    if (!db_path) {
        fprintf(stderr, "firewall: sqlite_init: db_path is NULL\n");
        return NULL;
    }

    sqlite_db_t *db = calloc(1, sizeof(sqlite_db_t));
    if (!db) {
        fprintf(stderr, "firewall: Out of memory allocating sqlite_db_t\n");
        return NULL;
    }

    strncpy(db->db_path, db_path, sizeof(db->db_path) - 1);
    db->db_path[sizeof(db->db_path) - 1] = '\0';

    /* 确保目录存在 */
    if (ensure_db_dir(db_path) != 0) {
        free(db);
        return NULL;
    }

    /* 打开数据库连接 */
    int rc = sqlite3_open(db_path, &db->conn);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Cannot open SQLite database %s: %s\n",
                db_path, sqlite3_errmsg(db->conn));
        sqlite3_close(db->conn);
        free(db);
        return NULL;
    }

    /* 启用 WAL 模式 */
    if (enable_wal_mode(db->conn) != 0) {
        fprintf(stderr, "firewall: Warning: WAL mode not enabled\n");
    }

    /* 初始化表结构 */
    if (init_db_schema(db->conn) != 0) {
        fprintf(stderr, "firewall: Failed to initialize database schema\n");
        sqlite3_close(db->conn);
        free(db);
        return NULL;
    }

    syslog(LOG_INFO, "firewall: SQLite persistent banlist initialized: %s", db_path);
    return db;
}

/**
 * 关闭 SQLite 数据库
 */
void sqlite_close(sqlite_db_t *db)
{
    if (!db) return;

    if (db->conn) {
        sqlite3_close(db->conn);
    }
    free(db);
}

/**
 * 添加永久黑名单条目
 */
int sqlite_add_permanent_ban(sqlite_db_t *db, const char *ip, uint32_t ip_num,
                             const char *reason, const char *created_by)
{
    if (!db || !ip || !reason || !created_by) {
        fprintf(stderr, "firewall: sqlite_add_permanent_ban: invalid parameter\n");
        return -1;
    }

    const char *sql =
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, 1);";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ip_num);
    sqlite3_bind_text(stmt, 3, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 5, created_by, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        return 0;  /* 成功 */
    } else if (rc == SQLITE_CONSTRAINT) {
        return -2;  /* 已存在 */
    } else {
        fprintf(stderr, "firewall: Failed to insert permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
 * 批量添加永久黑名单条目（使用事务优化性能）
 */
int sqlite_add_permanent_bans_batch(sqlite_db_t *db,
                                    const char **ips,
                                    const uint32_t *ip_nums,
                                    const char **reasons,
                                    const char **created_bys,
                                    int count)
{
    if (!db || !ips || !ip_nums || !reasons || !created_bys || count <= 0) {
        fprintf(stderr, "firewall: sqlite_add_permanent_bans_batch: invalid parameter\n");
        return -1;
    }

    const char *sql =
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, 1);";

    sqlite3_stmt *stmt;
    int rc;
    int success_count = 0;

    /* 开始事务 */
    rc = sqlite3_exec(db->conn, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to begin transaction: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        sqlite3_exec(db->conn, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    for (int i = 0; i < count; i++) {
        sqlite3_bind_text(stmt, 1, ips[i], -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ip_nums[i]);
        sqlite3_bind_text(stmt, 3, reasons[i], -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
        sqlite3_bind_text(stmt, 5, created_bys[i], -1, SQLITE_TRANSIENT);

        rc = sqlite3_step(stmt);
        sqlite3_reset(stmt);

        if (rc == SQLITE_DONE) {
            success_count++;
        } else if (rc != SQLITE_CONSTRAINT) {
            fprintf(stderr, "firewall: Failed to insert permanent ban %d: %s\n",
                    i, sqlite3_errmsg(db->conn));
        }
    }

    sqlite3_finalize(stmt);

    /* 提交事务 */
    rc = sqlite3_exec(db->conn, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to commit transaction: %s\n",
                sqlite3_errmsg(db->conn));
        /* COMMIT 失败后事务已自动回滚，无需显式 ROLLBACK */
        return -1;
    }

    return success_count;
}

/**
 * 移除永久黑名单条目 (软删除)
 */
int sqlite_remove_permanent_ban(sqlite_db_t *db, const char *ip)
{
    if (!db || !ip) {
        fprintf(stderr, "firewall: sqlite_remove_permanent_ban: invalid parameter\n");
        return -1;
    }

    const char *sql = 
        "UPDATE permanent_banlist SET is_active = 0 WHERE ip = ? AND is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_DONE) {
        int changes = sqlite3_changes(db->conn);
        if (changes > 0) {
            return 0;  /* 成功 */
        } else {
            return -2;  /* 不存在 */
        }
    } else {
        fprintf(stderr, "firewall: Failed to remove permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
 * 检查 IP 是否在永久黑名单中
 */
int sqlite_is_permanent_banned(sqlite_db_t *db, uint32_t ip_num)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_is_permanent_banned: db is NULL\n");
        return -1;
    }

    const char *sql = 
        "SELECT 1 FROM permanent_banlist WHERE ip_num = ? AND is_active = 1 LIMIT 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)ip_num);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc == SQLITE_ROW) {
        return 1;  /* 在黑名单中 */
    } else if (rc == SQLITE_DONE) {
        return 0;  /* 不在 */
    } else {
        fprintf(stderr, "firewall: Failed to query permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
 * 加载所有活跃的永久黑名单条目
 */
int sqlite_load_all_permanent_bans(sqlite_db_t *db, 
                                   struct permanent_ban_entry **entries,
                                   int *count)
{
    if (!db || !entries || !count) {
        fprintf(stderr, "firewall: sqlite_load_all_permanent_bans: invalid parameter\n");
        return -1;
    }

    *entries = NULL;
    *count = 0;

    const char *sql = 
        "SELECT id, ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active "
        "FROM permanent_banlist WHERE is_active = 1 ORDER BY created_at;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    /* 先计数 */
    int n = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        n++;
    }
    sqlite3_reset(stmt);

    if (n == 0) {
        sqlite3_finalize(stmt);
        return 0;  /* 没有记录 */
    }

    /* 分配内存 */
    *entries = calloc(n, sizeof(struct permanent_ban_entry));
    if (!*entries) {
        fprintf(stderr, "firewall: Out of memory allocating ban entries\n");
        sqlite3_finalize(stmt);
        return -1;
    }

    /* 读取数据 */
    int i = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW && i < n) {
        struct permanent_ban_entry *e = &(*entries)[i];
        e->id = sqlite3_column_int(stmt, 0);
        
        const unsigned char *ip_text = sqlite3_column_text(stmt, 1);
        if (ip_text) {
            strncpy(e->ip, (const char *)ip_text, sizeof(e->ip) - 1);
            e->ip[sizeof(e->ip) - 1] = '\0';
        }

        e->ip_num = (uint32_t)sqlite3_column_int64(stmt, 2);

        const unsigned char *reason = sqlite3_column_text(stmt, 3);
        if (reason) {
            strncpy(e->reason, (const char *)reason, sizeof(e->reason) - 1);
            e->reason[sizeof(e->reason) - 1] = '\0';
        }

        e->created_at = (time_t)sqlite3_column_int64(stmt, 4);

        const unsigned char *created_by = sqlite3_column_text(stmt, 5);
        if (created_by) {
            strncpy(e->created_by, (const char *)created_by, sizeof(e->created_by) - 1);
            e->created_by[sizeof(e->created_by) - 1] = '\0';
        }

        e->hit_count = sqlite3_column_int(stmt, 6);
        e->last_hit_at = (time_t)sqlite3_column_int64(stmt, 7);
        e->is_active = sqlite3_column_int(stmt, 8);

        i++;
    }

    sqlite3_finalize(stmt);
    *count = i;

    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        fprintf(stderr, "firewall: Error reading permanent ban list: %s\n",
                sqlite3_errmsg(db->conn));
        free(*entries);
        *entries = NULL;
        *count = 0;
        return -1;
    }

    return 0;
}

/**
 * 更新命中统计
 */
int sqlite_update_hit_stats(sqlite_db_t *db, uint32_t ip_num)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_update_hit_stats: db is NULL\n");
        return -1;
    }

    const char *sql = 
        "UPDATE permanent_banlist SET hit_count = hit_count + 1, last_hit_at = ? "
        "WHERE ip_num = ? AND is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ip_num);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "firewall: Failed to update hit stats: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    return 0;
}

/**
 * 获取数据库统计信息
 */
int sqlite_get_stats(sqlite_db_t *db, int *total_count, int *active_count)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_get_stats: db is NULL\n");
        return -1;
    }

    const char *sql_total = "SELECT COUNT(*) FROM permanent_banlist;";
    const char *sql_active = "SELECT COUNT(*) FROM permanent_banlist WHERE is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    /* 总记录数 */
    rc = sqlite3_prepare_v2(db->conn, sql_total, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_count = sqlite3_column_int(stmt, 0);
    } else {
        *total_count = 0;
    }
    sqlite3_finalize(stmt);

    /* 活跃记录数 */
    rc = sqlite3_prepare_v2(db->conn, sql_active, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *active_count = sqlite3_column_int(stmt, 0);
    } else {
        *active_count = 0;
    }
    sqlite3_finalize(stmt);

    return 0;
}

/**
 * 清理已删除的旧记录
 */
int sqlite_purge_deleted(sqlite_db_t *db, int days)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_purge_deleted: db is NULL\n");
        return -1;
    }

    const char *sql;
    sqlite3_stmt *stmt;
    int rc;

    if (days > 0) {
        sql = "DELETE FROM permanent_banlist WHERE is_active = 0 AND last_hit_at < ?;";
        rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                    sqlite3_errmsg(db->conn));
            return -1;
        }
        time_t cutoff = time(NULL) - (days * 86400);
        sqlite3_bind_int64(stmt, 1, (sqlite3_int64)cutoff);
    } else {
        sql = "DELETE FROM permanent_banlist WHERE is_active = 0;";
        rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                    sqlite3_errmsg(db->conn));
            return -1;
        }
    }

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->conn);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "firewall: Failed to purge deleted records: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    return changes;
}
