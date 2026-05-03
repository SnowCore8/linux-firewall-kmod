/*
 * jail-manager.h - Header for jail management functions
 */

#ifndef JAIL_MANAGER_H
#define JAIL_MANAGER_H

#include "firewall-daemon.h"

/* Initialize jail with default values from global config */
void init_jail_defaults(struct jail *j);

/* Free jail regex */
void free_jail_regex(struct jail *j);

/* Find existing jail or create new one */
struct jail *find_or_create_jail(const char *name);

/* Destroy a jail and free its resources */
void destroy_jail(struct jail *j);

/* Compile regex for a jail using PCRE2 */
int compile_jail_regex(struct jail *j);

/* Get global file_states index for a jail's log file */
int get_global_file_state_index(int jail_idx, int file_idx);

/* Cleanup all jail resources before config reload */
void cleanup_all_jails(void);

/* Find or create jail in a specific config (for double-buffer reload) */
struct jail *find_or_create_jail_in_cfg(const char *name, struct config *target_cfg);

/* Clone a single jail (deep copy, excludes runtime state) */
int clone_jail(struct jail *dst, const struct jail *src);

/* Clone entire config (excludes runtime state) */
struct config *config_clone(const struct config *src);

/* Validate configuration integrity */
int config_validate(const struct config *cfg);

/* Migrate failed entries from old config to new config */
void migrate_failed_entries(struct config *old, struct config *new);

/* Free config without runtime state (already migrated) */
void free_config_partial(struct config *cfg);

/* Compare config file names for sorting */
int compare_config_files(const void *a, const void *b);

/* Initialize precompiled regex patterns for all jails */
int init_log_patterns(void);

/* Free precompiled regex patterns */
void free_log_patterns(void);

#endif /* JAIL_MANAGER_H */