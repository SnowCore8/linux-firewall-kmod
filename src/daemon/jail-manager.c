/*
 * jail-manager.c - Jail management functions
 */

#include "firewall-daemon.h"
#include "jail-manager.h"

/* Initialize jail with default values from global config */
void init_jail_defaults(struct jail *j)
{
    j->enabled = true;
    j->log_count = 0;
    j->regex_pattern = NULL;
    j->regex_compiled = 0;
    memset(&j->compiled_regex, 0, sizeof(j->compiled_regex));
    j->max_retries = cfg.default_max_retries;
    j->findtime = cfg.default_findtime;
    j->ban_time = cfg.default_ban_time;
    j->failed_table = NULL;
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));
    j->failed_hash = NULL;
    j->partial_line_len = 0;
    j->partial_line_buffer[0] = '\0';

    for (int i = 0; i < MAX_LOG_FILES; i++) {
        j->log_files[i] = NULL;
    }
}

/* Free jail regex */
void free_jail_regex(struct jail *j)
{
    if (j && j->regex_compiled) {
        if (j->compiled_regex)
            pcre2_code_free(j->compiled_regex);
        if (j->match_data)
            pcre2_match_data_free(j->match_data);
        j->compiled_regex = NULL;
        j->match_data = NULL;
        j->regex_compiled = 0;
    }
}

/* Find existing jail or create new one */
struct jail *find_or_create_jail(const char *name)
{
    /* Find existing jail */
    for (int i = 0; i < cfg.jail_count; i++) {
        if (strcmp(cfg.jails[i].name, name) == 0) {
            return &cfg.jails[i];
        }
    }

    /* Create new jail */
    if (cfg.jail_count >= MAX_JAILS) {
        daemon_log_warn("Max jails reached (%d), cannot create jail '%s'", MAX_JAILS, name);
        return NULL;
    }

    struct jail *j = &cfg.jails[cfg.jail_count++];
    init_jail_defaults(j);
    strncpy(j->name, name, sizeof(j->name) - 1);
    j->name[sizeof(j->name) - 1] = '\0';

    daemon_log_info("Created new jail: %s", name);
    return j;
}

/* Destroy a jail and free its resources */
void destroy_jail(struct jail *j)
{
    if (!j) return;

    /* Free log files */
    for (int i = 0; i < j->log_count; i++) {
        if (j->log_files[i]) {
            free(j->log_files[i]);
            j->log_files[i] = NULL;
        }
    }
    j->log_count = 0;

    /* Free regex */
    free_jail_regex(j);
    if (j->regex_pattern) {
        free(j->regex_pattern);
        j->regex_pattern = NULL;
    }

    /* Free failed table */
    if (j->failed_table) {
        struct failed_entry *entry = j->failed_table;
        while (entry) {
            struct failed_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        j->failed_table = NULL;
    }

    /* Clear hash table */
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));

    /* Free khash table keys (heap-allocated strings) before destroying */
    if (j->failed_hash) {
        khint_t k;
        for (k = kh_begin(j->failed_hash); k != kh_end(j->failed_hash); ++k) {
            if (kh_exist(j->failed_hash, k)) {
                free((char *)kh_key(j->failed_hash, k));
            }
        }
        kh_destroy(ip_map, j->failed_hash);
        j->failed_hash = NULL;
    }

    daemon_log_info("Destroyed jail: %s", j->name);
}

/* Compile regex for a jail using PCRE2 */
int compile_jail_regex(struct jail *j)
{
    if (!j) return -1;

    /* Free existing regex if compiled */
    if (j->regex_compiled) {
        if (j->compiled_regex)
            pcre2_code_free(j->compiled_regex);
        if (j->match_data)
            pcre2_match_data_free(j->match_data);
        j->compiled_regex = NULL;
        j->match_data = NULL;
        j->regex_compiled = 0;
    }

    /* Use jail's custom regex or built-in default */
    const char *pattern = (j->regex_pattern && strlen(j->regex_pattern) > 0) ?
        j->regex_pattern :
        "Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";

    /* Validate regex pattern to prevent ReDoS attacks */
    if (j->regex_pattern && strlen(j->regex_pattern) > 0) {
        /* Reject nested quantifiers that can cause catastrophic backtracking */
        if (strstr(pattern, ")+") || strstr(pattern, ")*") ||
            strstr(pattern, "){") || strstr(pattern, "}?") ||
            strstr(pattern, "++") || strstr(pattern, "*+")) {
            daemon_log_err("Rejected unsafe regex for jail '%s': nested quantifiers detected", j->name);
            return -1;
        }

        /* Reject excessive alternation (a|b|c|... patterns) */
        int pipe_count = 0;
        for (const char *p = pattern; *p; p++) {
            if (*p == '|') pipe_count++;
        }
        if (pipe_count > 50) {
            daemon_log_err("Rejected unsafe regex for jail '%s': too many alternations (%d)", j->name, pipe_count);
            return -1;
        }

        /* Reject patterns that are too long */
        if (strlen(pattern) > 1024) {
            daemon_log_err("Rejected unsafe regex for jail '%s': pattern too long (%zu bytes)", j->name, strlen(pattern));
            return -1;
        }
    }

    /* Compile with PCRE2 */
    int error_number;
    PCRE2_SIZE error_offset;
    j->compiled_regex = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                       PCRE2_NO_UTF_CHECK, &error_number, &error_offset, NULL);
    if (!j->compiled_regex) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(error_number, buffer, sizeof(buffer));
        daemon_log_err("Failed to compile regex for jail '%s' at offset %d: %s",
                       j->name, (int)error_offset, buffer);
        return -1;
    }

    /* Create match data buffer */
    j->match_data = pcre2_match_data_create_from_pattern(j->compiled_regex, NULL);
    if (!j->match_data) {
        daemon_log_err("Failed to create match data for jail '%s'", j->name);
        pcre2_code_free(j->compiled_regex);
        j->compiled_regex = NULL;
        return -1;
    }

    j->regex_compiled = 1;
    daemon_log_debug("Compiled regex for jail '%s'", j->name);
    return 0;
}

/* Get global file_states index for a jail's log file */

int get_global_file_state_index(int jail_idx, int file_idx)
{
    if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
        daemon_log_err("Invalid jail index: %d", jail_idx);
        return -1;
    }
    if (file_idx < 0 || file_idx >= cfg.jails[jail_idx].log_count) {
        daemon_log_err("Invalid file index for jail %d: %d", jail_idx, file_idx);
        return -1;
    }

    int global_idx = 0;
    for (int j = 0; j < jail_idx; j++) {
        global_idx += cfg.jails[j].log_count;
    }
    global_idx += file_idx;

    if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
        daemon_log_err("Global file index out of bounds: %d", global_idx);
        return -1;
    }

    return global_idx;
}

/* Cleanup all jail resources before config reload
 *
 * NOTE: failed_table and failed_hash_table share the same objects.
 * failed_table is the head of a linked list, while failed_hash_table
 * contains pointers to the same objects for O(1) lookup.
 * We iterate failed_table to free all objects exactly once, then
 * zero out failed_hash_table (which only contains dangling pointers
 * after the frees, but no ownership).
 * This is safe as long as we always add the same object to both structures.
 */
void cleanup_all_jails(void)
{
    int old_count = cfg.jail_count;
    for (int i = 0; i < old_count; i++) {
        destroy_jail(&cfg.jails[i]);
        memset(&cfg.jails[i], 0, sizeof(struct jail));
    }
    cfg.jail_count = 0;
    daemon_log_info("All jails resources cleaned up");
}

/* Find or create jail in a specific config (for double-buffer reload) */
struct jail *find_or_create_jail_in_cfg(const char *name, struct config *target_cfg)
{
    for (int i = 0; i < target_cfg->jail_count; i++) {
        if (strcmp(target_cfg->jails[i].name, name) == 0) {
            return &target_cfg->jails[i];
        }
    }

    if (target_cfg->jail_count >= MAX_JAILS) {
        daemon_log_warn("Max jails reached (%d), cannot create jail '%s'", MAX_JAILS, name);
        return NULL;
    }

    struct jail *j = &target_cfg->jails[target_cfg->jail_count++];
    j->enabled = true;
    j->log_count = 0;
    j->regex_pattern = NULL;
    memset(&j->compiled_regex, 0, sizeof(j->compiled_regex));
    j->regex_compiled = 0;
    j->max_retries = target_cfg->default_max_retries;
    j->findtime = target_cfg->default_findtime;
    j->ban_time = target_cfg->default_ban_time;
    j->failed_table = NULL;
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));
    j->failed_hash = NULL;
    j->partial_line_len = 0;
    j->partial_line_buffer[0] = '\0';

    for (int i = 0; i < MAX_LOG_FILES; i++) {
        j->log_files[i] = NULL;
    }

    strncpy(j->name, name, sizeof(j->name) - 1);
    j->name[sizeof(j->name) - 1] = '\0';

    daemon_log_info("Created new jail: %s", name);
    return j;
}

/* Clone a single jail (deep copy, excludes runtime state) */
int clone_jail(struct jail *dst, const struct jail *src)
{
    memcpy(dst, src, sizeof(*dst));

    dst->log_count = 0;
    for (int i = 0; i < src->log_count; i++) {
        if (src->log_files[i]) {
            dst->log_files[i] = strdup(src->log_files[i]);
            if (!dst->log_files[i]) {
                for (int j = 0; j < dst->log_count; j++) {
                    free(dst->log_files[j]);
                }
                return -1;
            }
            dst->log_count++;
        }
    }

    dst->regex_pattern = NULL;
    if (src->regex_pattern) {
        dst->regex_pattern = strdup(src->regex_pattern);
        if (!dst->regex_pattern) {
            for (int j = 0; j < dst->log_count; j++) {
                free(dst->log_files[j]);
            }
            return -1;
        }
    }

    /* Don't clone compiled regex - will be recompiled */
    memset(&dst->compiled_regex, 0, sizeof(dst->compiled_regex));
    dst->regex_compiled = 0;

    /* Don't clone runtime state */
    dst->failed_table = NULL;
    memset(dst->failed_hash_table, 0, sizeof(dst->failed_hash_table));
    dst->failed_hash = NULL;
    dst->partial_line_len = 0;
    dst->partial_line_buffer[0] = '\0';

    return 0;
}

/* Clone entire config (excludes runtime state) */
struct config *config_clone(const struct config *src)
{
    struct config *dst = calloc(1, sizeof(*dst));
    if (!dst) return NULL;

    dst->default_max_retries = src->default_max_retries;
    dst->default_findtime = src->default_findtime;
    dst->default_ban_time = src->default_ban_time;
    dst->daemon = src->daemon;
    dst->interval = src->interval;
    dst->metrics_port = src->metrics_port;
    dst->permanent_ban_enabled = src->permanent_ban_enabled;

    if (src->config_file) {
        dst->config_file = strdup(src->config_file);
        if (!dst->config_file) goto fail;
    }
    if (src->config_dir) {
        dst->config_dir = strdup(src->config_dir);
        if (!dst->config_dir) goto fail;
    }
    if (src->permanent_db_path) {
        dst->permanent_db_path = strdup(src->permanent_db_path);
        if (!dst->permanent_db_path) goto fail;
    }

    dst->jail_count = src->jail_count;
    for (int i = 0; i < src->jail_count; i++) {
        if (clone_jail(&dst->jails[i], &src->jails[i]) < 0) {
            goto fail;
        }
    }

    return dst;

fail:
    if (dst->config_file) free(dst->config_file);
    if (dst->config_dir) free(dst->config_dir);
    if (dst->permanent_db_path) free(dst->permanent_db_path);
    for (int i = 0; i < dst->jail_count; i++) {
        for (int j = 0; j < dst->jails[i].log_count; j++) {
            free(dst->jails[i].log_files[j]);
        }
        if (dst->jails[i].regex_pattern) free(dst->jails[i].regex_pattern);
    }
    free(dst);
    return NULL;
}

/* Validate configuration integrity */
int config_validate(const struct config *cfg)
{
    if (!cfg) return -1;
    if (cfg->jail_count <= 0 || cfg->jail_count > MAX_JAILS) return -1;
    if (cfg->interval <= 0 || cfg->interval > 60) return -1;
    if (cfg->metrics_port < 0 || cfg->metrics_port > 65535) return -1;
    if (cfg->default_max_retries == 0) return -1;
    if (cfg->default_findtime == 0) return -1;
    if (cfg->default_ban_time == 0) return -1;

    for (int i = 0; i < cfg->jail_count; i++) {
        const struct jail *j = &cfg->jails[i];
        if (!j->enabled) continue;
        if (j->log_count == 0) {
            daemon_log_err("Jail '%s' has no log files", j->name);
            return -1;
        }
        if (j->max_retries == 0) {
            daemon_log_err("Jail '%s' has max_retries=0", j->name);
            return -1;
        }
        if (j->findtime == 0) {
            daemon_log_err("Jail '%s' has findtime=0", j->name);
            return -1;
        }
        if (j->ban_time == 0) {
            daemon_log_err("Jail '%s' has ban_time=0", j->name);
            return -1;
        }
    }

    return 0;
}

/* Migrate failed entries from old config to new config */
void migrate_failed_entries(struct config *old, struct config *new)
{
    for (int i = 0; i < old->jail_count; i++) {
        struct jail *old_jail = &old->jails[i];
        if (!old_jail->failed_hash) continue;

        for (int j = 0; j < new->jail_count; j++) {
            struct jail *new_jail = &new->jails[j];
            if (strcmp(old_jail->name, new_jail->name) == 0) {
                new_jail->failed_hash = old_jail->failed_hash;
                old_jail->failed_hash = NULL;
                daemon_log_debug("Migrated failed entries for jail '%s'", new_jail->name);
                break;
            }
        }
    }
}

/* Free config without runtime state (already migrated) */
void free_config_partial(struct config *cfg)
{
    if (!cfg) return;

    for (int i = 0; i < cfg->jail_count; i++) {
        struct jail *jail = &cfg->jails[i];

        for (int j = 0; j < jail->log_count; j++) {
            free(jail->log_files[j]);
        }

        if (jail->regex_compiled) {
            if (jail->compiled_regex)
                pcre2_code_free(jail->compiled_regex);
            if (jail->match_data)
                pcre2_match_data_free(jail->match_data);
            jail->compiled_regex = NULL;
            jail->match_data = NULL;
            jail->regex_compiled = 0;
        }
        if (jail->regex_pattern) {
            free(jail->regex_pattern);
        }

        /* failed_hash already migrated, skip */
    }

    if (cfg->config_file) free(cfg->config_file);
    if (cfg->config_dir) free(cfg->config_dir);
    if (cfg->permanent_db_path) free(cfg->permanent_db_path);
}

/* Comparison function for qsort - sorting config file names */
int compare_config_files(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* Initialize precompiled regex patterns for all jails */
int init_log_patterns(void)
{
    int ret = 0;

    /* Compile regex for each jail that has a pattern */
    for (int i = 0; i < cfg.jail_count; i++) {
        struct jail *jail = &cfg.jails[i];

        if (!jail->enabled) {
            daemon_log_debug("Skipping disabled jail '%s' for regex compilation", jail->name);
            continue;
        }

        if (jail->regex_pattern && strlen(jail->regex_pattern) > 0) {
            if (compile_jail_regex(jail) < 0) {
                daemon_log_warn("Failed to compile regex for jail '%s'", jail->name);
                ret = -1;
                /* Continue compiling for other jails */
            } else {
                daemon_log_info("Compiled regex for jail '%s'", jail->name);
            }
        } else {
            /* Jail will use built-in default pattern */
            daemon_log_info("Jail '%s' will use built-in default regex pattern", jail->name);
        }
    }

    if (ret == 0) {
        daemon_log_info("All jail regex patterns compiled successfully");
    }

    return ret;
}


/* Free precompiled regex patterns - no longer needed as regex is per-jail */
void free_log_patterns(void)
{
    /* Regex is now managed per-jail, so no global patterns to free */
}