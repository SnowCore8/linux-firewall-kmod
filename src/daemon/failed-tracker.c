/*
 * failed-tracker.c - Failed attempt tracking functions
 */

#include "firewall-daemon.h"
#include "jail-manager.h"
#include "ban-manager.h"
#include "failed-tracker.h"

/* Find failed entry by IP in a specific jail */
struct failed_entry *find_entry_for_jail(struct jail *j, const char *ip)
{
    if (!j || !j->failed_hash || !ip) return NULL;
    
    khint_t k = kh_get(ip_map, j->failed_hash, ip);
    if (k != kh_end(j->failed_hash)) {
        return kh_value(j->failed_hash, k);
    }
    return NULL;
}

/* Create new failed entry in a specific jail */
struct failed_entry *create_entry_for_jail(struct jail *j, const char *ip)
{
    if (!j || !ip) return NULL;
    
    /* Initialize hash table if needed */
    if (!j->failed_hash) {
        j->failed_hash = kh_init(ip_map);
        if (!j->failed_hash) {
            daemon_log_err("Failed to initialize hash table for jail '%s'", j->name);
            return NULL;
        }
    }
    
    /* Check if entry already exists */
    int ret;
    khint_t k = kh_put(ip_map, j->failed_hash, ip, &ret);
    if (ret == 0) {
        return kh_value(j->failed_hash, k);  /* Already exists */
    }
    
    /* Key ownership: replace stack pointer with heap-allocated copy */
    char *key_copy = strdup(ip);
    if (!key_copy) {
        daemon_log_err("Failed to allocate memory for hash key");
        kh_del(ip_map, j->failed_hash, k);  /* Remove empty slot */
        return NULL;
    }
    kh_key(j->failed_hash, k) = key_copy;
    
    /* Create new entry */
    struct failed_entry *entry = calloc(1, sizeof(*entry));
    if (!entry) {
        daemon_log_err("Failed to allocate memory for failed entry");
        free(key_copy);
        kh_del(ip_map, j->failed_hash, k);  /* Remove empty slot */
        return NULL;
    }
    
    strncpy(entry->ip, ip, sizeof(entry->ip) - 1);
    entry->ip[sizeof(entry->ip) - 1] = '\0';
    entry->count = 0;
    
    kh_value(j->failed_hash, k) = entry;
    return entry;
}

/* Remove failed entry (per-jail) */
void remove_entry_for_jail(struct jail *j, const char *ip)
{
    if (!j || !j->failed_hash || !ip) return;
    
    khint_t k = kh_get(ip_map, j->failed_hash, ip);
    if (k != kh_end(j->failed_hash)) {
        free(kh_value(j->failed_hash, k));
        free((char *)kh_key(j->failed_hash, k));  /* Free heap-allocated key */
        kh_del(ip_map, j->failed_hash, k);
    }
}

/* Count recent failures within time window */
unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries)
{
    time_t now = time(NULL);
    unsigned int count = 0;

    /* Validate parameters to prevent potential issues */
    if (!entry || window <= 0) {
        daemon_log_debug("Invalid parameters to count_recent");
        return 0;
    }

    for (unsigned int i = 0; i < entry->count; i++) {
        /* Prevent integer underflow if timestamp is in the future */
        if (now >= entry->timestamps[i]) {
            time_t diff = now - entry->timestamps[i];
            /* Additional check to prevent potential integer overflow in comparison */
            if (diff <= window) {
                count++;
            }
        }
        /* Limit processing to avoid excessive CPU usage if there are many timestamps */
        if (count > max_retries) {
            /* Early exit if we've already exceeded the threshold */
            break;
        }
    }

    return count;
}

/*
 * process_failed_timestamps - Add timestamp and manage buffer overflow
 * @entry: Failed entry to update
 * @now: Current timestamp
 * @findtime: Time window for counting failures
 */
void process_failed_timestamps(struct failed_entry *entry, time_t now, time_t findtime)
{
    if (entry->count < MAX_FAILED_TIMESTAMPS) {
        entry->timestamps[entry->count++] = now;
    } else {
        /* Shift timestamps to make room for the new one */
        memmove(entry->timestamps, entry->timestamps + 1,
                (MAX_FAILED_TIMESTAMPS - 1) * sizeof(time_t));
        entry->timestamps[MAX_FAILED_TIMESTAMPS - 1] = now;

        /* Filter out expired timestamps */
        time_t oldest_valid = now - findtime;
        int new_count = 0;
        for (int i = 0; i < MAX_FAILED_TIMESTAMPS; i++) {
            if (entry->timestamps[i] >= oldest_valid) {
                if (new_count != i) {
                    entry->timestamps[new_count] = entry->timestamps[i];
                }
                new_count++;
            }
        }
        entry->count = new_count;
    }
}

/*
 * check_and_ban - Check threshold and ban if exceeded
 * @entry: Failed entry to check
 * @ip: IP address string
 * @max_retries: Maximum allowed failures
 * @findtime: Time window for counting failures
 * @jail_name: Jail name for logging (NULL for global)
 */
void check_and_ban(struct failed_entry *entry, const char *ip,
                   unsigned int max_retries, unsigned int findtime,
                   const char *jail_name)
{
    unsigned int recent_fails = count_recent(entry, findtime, max_retries);

    if (recent_fails >= max_retries) {
        if (jail_name) {
            daemon_log_warn("IP %s exceeded %d failures in %d seconds in jail '%s', banning",
                           ip, recent_fails, findtime, jail_name);
        } else {
            daemon_log_warn("IP %s exceeded %d failures in %d seconds, banning",
                           ip, recent_fails, findtime);
        }

        if (ban_ip(ip) == 0) {
            if (jail_name) {
                daemon_log_info("Successfully banned IP %s after %d failed attempts in jail '%s'",
                               ip, recent_fails, jail_name);
            } else {
                daemon_log_info("Successfully banned IP %s after %d failed attempts",
                               ip, recent_fails);
            }
        } else {
            if (jail_name) {
                daemon_log_err("Failed to ban IP %s after %d failed attempts in jail '%s', keeping entry for retry",
                              ip, recent_fails, jail_name);
            } else {
                daemon_log_err("Failed to ban IP %s after %d failed attempts, keeping entry for retry",
                              ip, recent_fails);
            }
        }
    } else {
        if (jail_name) {
            daemon_log_debug("IP %s has %d failed attempts in %d seconds in jail '%s'",
                            ip, recent_fails, findtime, jail_name);
        } else {
            daemon_log_debug("IP %s has %d failed attempts in %d seconds",
                            ip, recent_fails, findtime);
        }
    }
}

/* Handle a failed login attempt - jail-aware version */
void handle_failed_attempt_for_jail(struct jail *j, const char *ip,
                                   unsigned int max_retries, unsigned int findtime)
{
    struct failed_entry *entry;
    time_t now;

    if (!ip || !*ip) {
        daemon_log_err("Invalid IP address provided to handle_failed_attempt_for_jail");
        return;
    }

    atomic_fetch_add(&daemon_stats.failed_attempts, 1);

    entry = find_entry_for_jail(j, ip);
    if (!entry) {
        entry = create_entry_for_jail(j, ip);
        if (!entry) {
            daemon_log_err("Failed to create entry for IP %s", ip);
            return;
        }
    }

    now = time(NULL);
    process_failed_timestamps(entry, now, findtime);
    check_and_ban(entry, ip, max_retries, findtime, j->name);

    /* Remove entry after successful ban */
    if (count_recent(entry, findtime, max_retries) >= max_retries) {
        remove_entry_for_jail(j, ip);
    }
}

/* Handle a failed login attempt - global version (backward compatible) */
void handle_failed_attempt(const char *ip, unsigned int max_retries, unsigned int findtime)
{
    struct failed_entry *entry;
    time_t now;

    if (!ip || !*ip) {
        daemon_log_err("Invalid IP address provided to handle_failed_attempt");
        return;
    }

    atomic_fetch_add(&daemon_stats.failed_attempts, 1);

    entry = find_entry(ip);
    if (!entry) {
        entry = create_entry(ip);
        if (!entry) {
            daemon_log_err("Failed to create entry for IP %s", ip);
            return;
        }
    }

    now = time(NULL);
    process_failed_timestamps(entry, now, findtime);
    check_and_ban(entry, ip, max_retries, findtime, NULL);

    /* Remove entry after successful ban */
    if (count_recent(entry, findtime, max_retries) >= max_retries) {
        remove_entry(ip);
    }
}

/* Find failed entry by IP - searches all jails */
struct failed_entry *find_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    struct failed_entry *result = NULL;
    for (int j = 0; j < cfg.jail_count; j++) {
        struct failed_entry *entry = find_entry_for_jail(&cfg.jails[j], ip);
        if (entry) {
            result = entry;
            break;
        }
    }
    
    pthread_mutex_unlock(&config_mutex);
    return result;
}

/* Create new failed entry - creates in first jail (default behavior) */
struct failed_entry *create_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    struct failed_entry *result = NULL;
    if (cfg.jail_count > 0) {
        result = create_entry_for_jail(&cfg.jails[0], ip);
    }
    
    pthread_mutex_unlock(&config_mutex);
    return result;
}

/* Remove failed entry - searches all jails */
void remove_entry(const char *ip)
{
    pthread_mutex_lock(&config_mutex);
    
    for (int j = 0; j < cfg.jail_count; j++) {
        struct failed_entry *entry = find_entry_for_jail(&cfg.jails[j], ip);
        if (entry) {
            remove_entry_for_jail(&cfg.jails[j], ip);
            break;
        }
    }
    
    pthread_mutex_unlock(&config_mutex);
}