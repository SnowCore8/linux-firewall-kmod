#ifndef SQLITE_PERSISTENT_H
#define SQLITE_PERSISTENT_H

#include <stdint.h>
#include <time.h>

/* SQLite persistent blacklist module
 * Provides storage, loading, and query functions for permanent blacklists
 * Implements persistent storage using SQLite database
 */

/* Permanent blacklist entry */
struct permanent_ban_entry {
    int id;                     /* Database auto-increment ID */
    char ip[16];                /* IP address (dotted decimal) */
    uint32_t ip_num;            /* IP number (network byte order) */
    char reason[256];           /* Ban reason */
    time_t created_at;          /* Creation time */
    char created_by[32];        /* Trigger source (auto/manual/api) */
    int hit_count;              /* Match count */
    time_t last_hit_at;         /* Last match time */
    int is_active;              /* Whether active (0=deleted but record preserved) */
};

/* Database handle (opaque to external) */
typedef struct sqlite_db sqlite_db_t;

/**
 * Initialize SQLite database
 * @param db_path database file path
 * @return database handle, NULL on failure
 */
sqlite_db_t *sqlite_init(const char *db_path);

/**
 * Close SQLite database
 * @param db database handle
 */
void sqlite_close(sqlite_db_t *db);

/**
 * Add permanent blacklist entry
 * @param db database handle
 * @param ip IP address (dotted decimal)
 * @param ip_num IP number (network byte order)
 * @param reason ban reason
 * @param created_by trigger source
 * @return 0 success, -1 failure, -2 already exists
 */
int sqlite_add_permanent_ban(sqlite_db_t *db, const char *ip, uint32_t ip_num,
                             const char *reason, const char *created_by);

/**
 * Remove permanent blacklist entry (soft delete)
 * @param db database handle
 * @param ip IP address
 * @return 0 success, -1 failure, -2 does not exist
 */
int sqlite_remove_permanent_ban(sqlite_db_t *db, const char *ip);

/**
 * Check if IP is in permanent blacklist
 * @param db database handle
 * @param ip_num IP number
 * @return 1 in blacklist, 0 not in, -1 query failed
 */
int sqlite_is_permanent_banned(sqlite_db_t *db, uint32_t ip_num);

/**
 * Load all active permanent blacklist entries
 * @param db database handle
 * @param entries output array (caller responsible for free)
 * @param count output entry count
 * @return 0 success, -1 failure
 */
int sqlite_load_all_permanent_bans(sqlite_db_t *db, 
                                   struct permanent_ban_entry **entries,
                                   int *count);

/**
 * Update hit statistics
 * @param db database handle
 * @param ip_num IP number
 * @return 0 success, -1 failure
 */
int sqlite_update_hit_stats(sqlite_db_t *db, uint32_t ip_num);

/**
 * Get database statistics
 * @param db database handle
 * @param total_count total record count (output)
 * @param active_count active record count (output)
 * @return 0 success, -1 failure
 */
int sqlite_get_stats(sqlite_db_t *db, int *total_count, int *active_count);

/**
 * Clean up old deleted records (optional maintenance operation)
 * @param db database handle
 * @param days retention days (0=clean all deleted records)
 * @return cleaned record count, -1 failure
 */
int sqlite_purge_deleted(sqlite_db_t *db, int days);

#endif /* SQLITE_PERSISTENT_H */
