/*
 * sqlite-persistent.c - SQLite persistent permanent blacklist module
 * Provides storage, loading, and query functions for permanent blacklists
 * Implements persistent storage using SQLite database
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
#include <pthread.h>

/* Database handle structure */
struct sqlite_db {
    sqlite3 *conn;              /* SQLite connection handle */
    char db_path[512];          /* Database file path */
    pthread_mutex_t lock;       /* Thread-safe mutex lock */
};

/* ============================================================================
 * Internal helper functions
 * ========================================================================== */

/**
 * Ensure database directory exists
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
        /* Directory does not exist, try to create */
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
* Initialize database table schema
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
* Enable WAL mode to improve concurrent performance
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
 * Public interface implementation
 * ========================================================================== */

/**
* Initialize SQLite database
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

    /* Initialize mutex lock */
    pthread_mutex_init(&db->lock, NULL);

    /* Ensure directory exists */
    if (ensure_db_dir(db_path) != 0) {
        free(db);
        return NULL;
    }

    /* Open database connection */
    int rc = sqlite3_open(db_path, &db->conn);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Cannot open SQLite database %s: %s\n",
                db_path, sqlite3_errmsg(db->conn));
        sqlite3_close(db->conn);
        free(db);
        return NULL;
    }

    /* Enable WAL mode */
    if (enable_wal_mode(db->conn) != 0) {
        fprintf(stderr, "firewall: Warning: WAL mode not enabled\n");
    }

    /* Initialize table schema */
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
* Close SQLite database
*/
void sqlite_close(sqlite_db_t *db)
{
    if (!db) return;

    if (db->conn) {
        sqlite3_close(db->conn);
    }
    pthread_mutex_destroy(&db->lock);
    free(db);
}

/**
* Add permanent blacklist entry
*/
int sqlite_add_permanent_ban(sqlite_db_t *db, const char *ip, uint32_t ip_num,
                             const char *reason, const char *created_by)
{
    if (!db || !ip || !reason || !created_by) {
        fprintf(stderr, "firewall: sqlite_add_permanent_ban: invalid parameter\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql =
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, 1);";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ip_num);
    sqlite3_bind_text(stmt, 3, reason, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 5, created_by, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    if (rc == SQLITE_DONE) {
           return 0;  /* Success */
    } else if (rc == SQLITE_CONSTRAINT) {
        return -2;  /* Already exists */
    } else {
        fprintf(stderr, "firewall: Failed to insert permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
* Batch add permanent blacklist entries (optimize performance with transactions)
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

    pthread_mutex_lock(&db->lock);

    const char *sql =
        "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by, hit_count, last_hit_at, is_active) "
        "VALUES (?, ?, ?, ?, ?, 0, 0, 1);";

    sqlite3_stmt *stmt;
    int rc;
    int success_count = 0;

    /* Begin transaction */
    rc = sqlite3_exec(db->conn, "BEGIN TRANSACTION;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to begin transaction: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        sqlite3_exec(db->conn, "ROLLBACK;", NULL, NULL, NULL);
        pthread_mutex_unlock(&db->lock);
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

    /* Commit transaction */
    rc = sqlite3_exec(db->conn, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to commit transaction: %s\n",
                sqlite3_errmsg(db->conn));
        /* Transaction automatically rolls back after COMMIT failure, no explicit ROLLBACK needed */
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    pthread_mutex_unlock(&db->lock);

    return success_count;
}

/**
* Remove permanent blacklist entry (soft delete)
*/
int sqlite_remove_permanent_ban(sqlite_db_t *db, const char *ip)
{
    if (!db || !ip) {
        fprintf(stderr, "firewall: sqlite_remove_permanent_ban: invalid parameter\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql = 
        "UPDATE permanent_banlist SET is_active = 0 WHERE ip = ? AND is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    sqlite3_bind_text(stmt, 1, ip, -1, SQLITE_TRANSIENT);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    if (rc == SQLITE_DONE) {
        int changes = sqlite3_changes(db->conn);
        if (changes > 0) {
       return 0;  /* Success */
        } else {
            return -2;  /* Does not exist */
        }
    } else {
        fprintf(stderr, "firewall: Failed to remove permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
* Check if IP is in permanent blacklist
*/
int sqlite_is_permanent_banned(sqlite_db_t *db, uint32_t ip_num)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_is_permanent_banned: db is NULL\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql = 
        "SELECT 1 FROM permanent_banlist WHERE ip_num = ? AND is_active = 1 LIMIT 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)ip_num);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    if (rc == SQLITE_ROW) {
        return 1;  /* In blacklist */
    } else if (rc == SQLITE_DONE) {
        return 0;  /* Not in */
    } else {
        fprintf(stderr, "firewall: Failed to query permanent ban: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }
}

/**
* Load all active permanent blacklist entries
*/
int sqlite_load_all_permanent_bans(sqlite_db_t *db, 
                                   struct permanent_ban_entry **entries,
                                   int *count)
{
    if (!db || !entries || !count) {
        fprintf(stderr, "firewall: sqlite_load_all_permanent_bans: invalid parameter\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

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
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    /* Count first */
    int n = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        n++;
    }
    sqlite3_reset(stmt);

    if (n == 0) {
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db->lock);
        return 0;  /* No records */
    }

    /* Allocate memory */
    *entries = calloc(n, sizeof(struct permanent_ban_entry));
    if (!*entries) {
        fprintf(stderr, "firewall: Out of memory allocating ban entries\n");
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    /* Read data */
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

    pthread_mutex_unlock(&db->lock);

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
* Update hit statistics
*/
int sqlite_update_hit_stats(sqlite_db_t *db, uint32_t ip_num)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_update_hit_stats: db is NULL\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql = 
        "UPDATE permanent_banlist SET hit_count = hit_count + 1, last_hit_at = ? "
        "WHERE ip_num = ? AND is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)ip_num);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "firewall: Failed to update hit stats: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    return 0;
}

/**
* Get database statistics
*/
int sqlite_get_stats(sqlite_db_t *db, int *total_count, int *active_count)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_get_stats: db is NULL\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql_total = "SELECT COUNT(*) FROM permanent_banlist;";
    const char *sql_active = "SELECT COUNT(*) FROM permanent_banlist WHERE is_active = 1;";

    sqlite3_stmt *stmt;
    int rc;

    /* Total record count */
    rc = sqlite3_prepare_v2(db->conn, sql_total, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *total_count = sqlite3_column_int(stmt, 0);
    } else {
        *total_count = 0;
    }
    sqlite3_finalize(stmt);

    /* Active record count */
    rc = sqlite3_prepare_v2(db->conn, sql_active, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                sqlite3_errmsg(db->conn));
        pthread_mutex_unlock(&db->lock);
        return -1;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *active_count = sqlite3_column_int(stmt, 0);
    } else {
        *active_count = 0;
    }
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    return 0;
}

/**
* Clean up old deleted records
*/
int sqlite_purge_deleted(sqlite_db_t *db, int days)
{
    if (!db) {
        fprintf(stderr, "firewall: sqlite_purge_deleted: db is NULL\n");
        return -1;
    }

    pthread_mutex_lock(&db->lock);

    const char *sql;
    sqlite3_stmt *stmt;
    int rc;

    if (days > 0) {
        sql = "DELETE FROM permanent_banlist WHERE is_active = 0 AND last_hit_at < ?;";
        rc = sqlite3_prepare_v2(db->conn, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "firewall: Failed to prepare statement: %s\n",
                    sqlite3_errmsg(db->conn));
            pthread_mutex_unlock(&db->lock);
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
            pthread_mutex_unlock(&db->lock);
            return -1;
        }
    }

    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db->conn);
    sqlite3_finalize(stmt);

    pthread_mutex_unlock(&db->lock);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "firewall: Failed to purge deleted records: %s\n",
                sqlite3_errmsg(db->conn));
        return -1;
    }

    return changes;
}
