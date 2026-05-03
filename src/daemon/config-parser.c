/*
 * config-parser.c - Configuration parsing functions
 */

#include "firewall-daemon.h"
#include "jail-manager.h"
#include "config-parser.h"

/* YAML parsing context for double-buffer config reload */
struct yaml_parse_ctx {
    struct jail *current_jail;
    int in_jails_section;
    int in_defaults_section;
    int in_log_files_array;
    char *current_key;
    char *current_jail_name;
};

/* Parse YAML file into a target config (no lock held).
 * This is the core parsing logic extracted from parse_config_file.
 * Returns 0 on success, -1 on error. */
static int parse_yaml_into(const char *config_path, struct config *target)
{
    FILE *file;
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    int error = 0;

    struct yaml_parse_ctx ctx = {0};

    /* Extract config file directory for resolving relative paths */
    char config_dir[1024];
    strncpy(config_dir, config_path, sizeof(config_dir) - 1);
    config_dir[sizeof(config_dir) - 1] = '\0';
    char *last_slash = strrchr(config_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(config_dir, ".");
    }

    /* Open config file */
    file = fopen(config_path, "r");
    if (!file) {
        daemon_log_warn("Cannot open config file: %s", config_path);
        return -1;
    }

    daemon_log_info("Reading config file: %s", config_path);

    /* Initialize YAML parser */
    if (!yaml_parser_initialize(&parser)) {
        daemon_log_err("Failed to initialize YAML parser");
        fclose(file);
        return -1;
    }

    yaml_parser_set_input_file(&parser, file);

    /* Parse YAML events */
    while (!done) {
        if (!yaml_parser_parse(&parser, &event)) {
            daemon_log_err("YAML parse error: %s", parser.problem ? parser.problem : "unknown");
            error = 1;
            break;
        }

        switch (event.type) {
        case YAML_STREAM_START_EVENT:
        case YAML_DOCUMENT_START_EVENT:
            break;

        case YAML_STREAM_END_EVENT:
        case YAML_DOCUMENT_END_EVENT:
            done = 1;
            break;

        case YAML_SCALAR_EVENT: {
            char *value = (char *)event.data.scalar.value;

            /* Reject excessively long values to prevent memory exhaustion */
            if (strlen(value) > 1024) {
                daemon_log_warn("YAML value too long (%zu bytes), rejecting", strlen(value));
                error = 1;
                break;
            }

            if (ctx.in_defaults_section && ctx.current_key) {
                /* Parsing defaults section - set global defaults */
                if (strcmp(ctx.current_key, "max_retries") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 100) {
                        daemon_log_warn("Invalid default max_retries: %s", value);
                    } else {
                        target->default_max_retries = (unsigned int)val;
                        daemon_log_info("Default max_retries set to %u", target->default_max_retries);
                    }
                } else if (strcmp(ctx.current_key, "findtime") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                        daemon_log_warn("Invalid default findtime: %s", value);
                    } else {
                        target->default_findtime = (unsigned int)val;
                        daemon_log_info("Default findtime set to %u", target->default_findtime);
                    }
                } else if (strcmp(ctx.current_key, "ban_time") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 86400) {
                        daemon_log_warn("Invalid default ban_time: %s", value);
                    } else {
                        target->default_ban_time = (unsigned int)val;
                        daemon_log_info("Default ban_time set to %u", target->default_ban_time);
                    }
                } else if (strcmp(ctx.current_key, "interval") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 60) {
                        daemon_log_warn("Invalid default interval: %s", value);
                    } else {
                        target->interval = (int)val;
                        daemon_log_info("Default interval set to %d", target->interval);
                    }
                } else if (strcmp(ctx.current_key, "metrics_port") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 0 || val > 65535) {
                        daemon_log_warn("Invalid default metrics_port: %s", value);
                    } else {
                        target->metrics_port = (int)val;
                        daemon_log_info("Default metrics_port set to %d", target->metrics_port);
                    }
                } else if (strcmp(ctx.current_key, "daemon") == 0) {
                    if (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0) {
                        target->daemon = 1;
                    } else {
                        target->daemon = 0;
                    }
                } else if (strcmp(ctx.current_key, "permanent_db_path") == 0) {
                    if (strlen(value) > 0) {
                        if (target->permanent_db_path) free(target->permanent_db_path);
                        /* Resolve relative path against config file directory */
                        if (value[0] == '/') {
                            target->permanent_db_path = strdup(value);
                        } else {
                            char full_path[1024];
                            snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, value);
                            target->permanent_db_path = strdup(full_path);
                        }
                        if (target->permanent_db_path) {
                            target->permanent_ban_enabled = 1;
                            daemon_log_info("Default permanent_db_path set to: %s", target->permanent_db_path);
                        }
                    }
                } else if (strcmp(ctx.current_key, "permanent_ban_enabled") == 0) {
                    target->permanent_ban_enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                }
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else if (ctx.in_jails_section && ctx.current_jail_name && !ctx.in_log_files_array) {
                /* We're in a jail section - either this is a jail key or a jail property */
                if (!ctx.current_key) {
                    /* This is a property key for the current jail */
                    ctx.current_key = strdup(value);
                } else {
                    /* We have key-value pair for jail property */
                    /* Find or create jail if not already created */
                    if (!ctx.current_jail) {
                        ctx.current_jail = find_or_create_jail_in_cfg(ctx.current_jail_name, target);
                        if (!ctx.current_jail) {
                            daemon_log_warn("Failed to create jail '%s'", ctx.current_jail_name);
                            free(ctx.current_key);
                            ctx.current_key = NULL;
                            break;
                        }
                    }

                    if (strcmp(ctx.current_key, "enabled") == 0) {
                        ctx.current_jail->enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                        daemon_log_info("Jail '%s' enabled: %s", ctx.current_jail->name, value);
                    } else if (strcmp(ctx.current_key, "max_retries") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 100) {
                            daemon_log_warn("Invalid max_retries for jail '%s': %s", ctx.current_jail->name, value);
                        } else {
                            ctx.current_jail->max_retries = (unsigned int)val;
                            daemon_log_info("Jail '%s' max_retries set to %u", ctx.current_jail->name, ctx.current_jail->max_retries);
                        }
                    } else if (strcmp(ctx.current_key, "findtime") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                            daemon_log_warn("Invalid findtime for jail '%s': %s", ctx.current_jail->name, value);
                        } else {
                            ctx.current_jail->findtime = (unsigned int)val;
                            daemon_log_info("Jail '%s' findtime set to %u", ctx.current_jail->name, ctx.current_jail->findtime);
                        }
                    } else if (strcmp(ctx.current_key, "ban_time") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 86400) {
                            daemon_log_warn("Invalid ban_time for jail '%s': %s", ctx.current_jail->name, value);
                        } else {
                            ctx.current_jail->ban_time = (unsigned int)val;
                            daemon_log_info("Jail '%s' ban_time set to %u", ctx.current_jail->name, ctx.current_jail->ban_time);
                        }
                    } else if (strcmp(ctx.current_key, "regex") == 0) {
                        if (ctx.current_jail->regex_pattern) free(ctx.current_jail->regex_pattern);
                        ctx.current_jail->regex_pattern = strdup(value);
                        daemon_log_info("Jail '%s' regex set to: %s", ctx.current_jail->name, value);
                    }
                    free(ctx.current_key);
                    ctx.current_key = NULL;
                }
            } else if (ctx.in_log_files_array && ctx.current_jail) {
                /* Parsing log_files array for current jail */
                if (ctx.current_jail->log_count >= MAX_LOG_FILES) {
                    daemon_log_warn("Too many log files for jail '%s' (max %d)", ctx.current_jail->name, MAX_LOG_FILES);
                } else if (validate_and_normalize_path(value) < 0) {
                    daemon_log_warn("Invalid log file path for jail '%s': %s", ctx.current_jail->name, value);
                } else {
                    ctx.current_jail->log_files[ctx.current_jail->log_count] = strdup(value);
                    if (!ctx.current_jail->log_files[ctx.current_jail->log_count]) {
                        daemon_log_err("Out of memory allocating log file path");
                        error = 1;
                    } else {
                        daemon_log_info("Jail '%s' added log file: %s", ctx.current_jail->name, ctx.current_jail->log_files[ctx.current_jail->log_count]);
                        ctx.current_jail->log_count++;
                    }
                }
            } else if (ctx.current_key) {
                /* Top-level key-value pair (not in jails or defaults) */
                if (strcmp(ctx.current_key, "max_retries") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 100) {
                        target->default_max_retries = (unsigned int)val;
                        daemon_log_info("Config max_retries set to %u", target->default_max_retries);
                    }
                } else if (strcmp(ctx.current_key, "findtime") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 3600) {
                        target->default_findtime = (unsigned int)val;
                        daemon_log_info("Config findtime set to %u", target->default_findtime);
                    }
                } else if (strcmp(ctx.current_key, "ban_time") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 86400) {
                        target->default_ban_time = (unsigned int)val;
                        daemon_log_info("Config ban_time set to %u", target->default_ban_time);
                    }
                } else if (strcmp(ctx.current_key, "interval") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 1 && val <= 60) {
                        target->interval = (int)val;
                        daemon_log_info("Config interval set to %d", target->interval);
                    }
                } else if (strcmp(ctx.current_key, "metrics_port") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno == 0 && *endptr == '\0' && val >= 0 && val <= 65535) {
                        target->metrics_port = (int)val;
                        daemon_log_info("Config metrics_port set to %d", target->metrics_port);
                    }
                } else if (strcmp(ctx.current_key, "daemon") == 0) {
                    target->daemon = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                } else if (strcmp(ctx.current_key, "permanent_db_path") == 0) {
                    if (strlen(value) > 0) {
                        if (target->permanent_db_path) free(target->permanent_db_path);
                        /* Resolve relative path against config file directory */
                        if (value[0] == '/') {
                            target->permanent_db_path = strdup(value);
                        } else {
                            char full_path[1024];
                            snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, value);
                            target->permanent_db_path = strdup(full_path);
                        }
                        if (target->permanent_db_path) target->permanent_ban_enabled = 1;
                    }
                } else if (strcmp(ctx.current_key, "permanent_ban_enabled") == 0) {
                    target->permanent_ban_enabled = (strcmp(value, "true") == 0 || strcmp(value, "True") == 0 || strcmp(value, "1") == 0);
                } else {
                    daemon_log_warn("Ignoring unsupported top-level key: %s (jail format required)", ctx.current_key);
                }
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else {
                /* This is a key without value yet */
                ctx.current_key = strdup(value);
            }
            break;
        }

        case YAML_SEQUENCE_START_EVENT: {
            if (ctx.current_key && strcmp(ctx.current_key, "log_files") == 0) {
                ctx.in_log_files_array = 1;
                free(ctx.current_key);
                ctx.current_key = NULL;
            }
            break;
        }

        case YAML_SEQUENCE_END_EVENT:
            ctx.in_log_files_array = 0;
            break;

        case YAML_MAPPING_START_EVENT: {
            if (ctx.current_key && strcmp(ctx.current_key, "jails") == 0) {
                ctx.in_jails_section = 1;
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else if (ctx.current_key && strcmp(ctx.current_key, "defaults") == 0) {
                ctx.in_defaults_section = 1;
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else if (ctx.in_jails_section && ctx.current_key) {
                /* Starting a new jail mapping */
                if (ctx.current_jail_name) free(ctx.current_jail_name);
                ctx.current_jail_name = ctx.current_key;
                ctx.current_jail = NULL;  /* Will be created when properties are parsed */
                ctx.current_key = NULL;
            }
        }
        break;

        case YAML_MAPPING_END_EVENT: {
            if (ctx.in_jails_section && !ctx.in_log_files_array) {
                /* End of a jail section - compile regex if pattern exists */
                if (ctx.current_jail_name && ctx.current_jail) {
                    if (ctx.current_jail->regex_pattern && strlen(ctx.current_jail->regex_pattern) > 0) {
                        compile_jail_regex(ctx.current_jail);
                    }
                    daemon_log_info("Finished parsing jail '%s': enabled=%d, log_count=%d, max_retries=%u",
                        ctx.current_jail->name, ctx.current_jail->enabled, ctx.current_jail->log_count, ctx.current_jail->max_retries);
                }
                if (ctx.current_jail_name) {
                    free(ctx.current_jail_name);
                    ctx.current_jail_name = NULL;
                }
                ctx.current_jail = NULL;
            } else if (ctx.in_defaults_section) {
                ctx.in_defaults_section = 0;
            }
            break;
        }

        case YAML_ALIAS_EVENT:
        case YAML_NO_EVENT:
            break;
        }

        yaml_event_delete(&event);

        if (error) break;
    }

    yaml_parser_delete(&parser);
    fclose(file);

    /* Cleanup */
    if (ctx.current_key) free(ctx.current_key);
    if (ctx.current_jail_name) free(ctx.current_jail_name);

    return error ? -1 : 0;
}

/* Parse configuration file using libyaml - supports jail-based YAML format.
 * Uses double-buffer pattern: parses into temporary config without holding lock,
 * then briefly locks to swap configs and migrate runtime state. */
int parse_config_file(const char *config_path)
{
    struct config *new_cfg;
    struct config *old_cfg_snapshot = NULL;
    int parse_rc;

    /* Allocate temporary config */
    new_cfg = calloc(1, sizeof(*new_cfg));
    if (!new_cfg) {
        daemon_log_err("Out of memory allocating temporary config");
        return -1;
    }

    /* Copy path strings to new_cfg (needed for relative path resolution) */
    if (cfg.config_file) {
        new_cfg->config_file = strdup(cfg.config_file);
    }
    if (cfg.config_dir) {
        new_cfg->config_dir = strdup(cfg.config_dir);
    }
    if (cfg.permanent_db_path) {
        new_cfg->permanent_db_path = strdup(cfg.permanent_db_path);
        new_cfg->permanent_ban_enabled = cfg.permanent_ban_enabled;
    }

    /* Copy current defaults as baseline */
    pthread_mutex_lock(&config_mutex);
    new_cfg->default_max_retries = cfg.default_max_retries;
    new_cfg->default_findtime = cfg.default_findtime;
    new_cfg->default_ban_time = cfg.default_ban_time;
    new_cfg->daemon = cfg.daemon;
    new_cfg->interval = cfg.interval;
    new_cfg->metrics_port = cfg.metrics_port;
    new_cfg->jail_count = 0;
    pthread_mutex_unlock(&config_mutex);

    /* Parse YAML into new_cfg WITHOUT holding the lock */
    parse_rc = parse_yaml_into(config_path, new_cfg);
    if (parse_rc < 0) {
        daemon_log_warn("Failed to parse config file: %s", config_path);
        /* Free new_cfg's allocated strings */
        if (new_cfg->config_file) free(new_cfg->config_file);
        if (new_cfg->config_dir) free(new_cfg->config_dir);
        if (new_cfg->permanent_db_path) free(new_cfg->permanent_db_path);
        for (int i = 0; i < new_cfg->jail_count; i++) {
            for (int j = 0; j < new_cfg->jails[i].log_count; j++) {
                free(new_cfg->jails[i].log_files[j]);
            }
            if (new_cfg->jails[i].regex_pattern) free(new_cfg->jails[i].regex_pattern);
            if (new_cfg->jails[i].regex_compiled) {
                if (new_cfg->jails[i].compiled_regex) pcre2_code_free(new_cfg->jails[i].compiled_regex);
                if (new_cfg->jails[i].match_data) pcre2_match_data_free(new_cfg->jails[i].match_data);
            }
        }
        free(new_cfg);
        return -1;
    }

    /* Validate new config */
    if (config_validate(new_cfg) < 0) {
        daemon_log_warn("Config validation failed for: %s", config_path);
        /* Free new_cfg */
        if (new_cfg->config_file) free(new_cfg->config_file);
        if (new_cfg->config_dir) free(new_cfg->config_dir);
        if (new_cfg->permanent_db_path) free(new_cfg->permanent_db_path);
        for (int i = 0; i < new_cfg->jail_count; i++) {
            for (int j = 0; j < new_cfg->jails[i].log_count; j++) {
                free(new_cfg->jails[i].log_files[j]);
            }
            if (new_cfg->jails[i].regex_pattern) free(new_cfg->jails[i].regex_pattern);
            if (new_cfg->jails[i].regex_compiled) {
                if (new_cfg->jails[i].compiled_regex) pcre2_code_free(new_cfg->jails[i].compiled_regex);
                if (new_cfg->jails[i].match_data) pcre2_match_data_free(new_cfg->jails[i].match_data);
            }
        }
        free(new_cfg);
        return -1;
    }

    /* Briefly lock to swap configs and migrate runtime state */
    pthread_mutex_lock(&config_mutex);

    /* Snapshot old config for migration and cleanup */
    old_cfg_snapshot = config_clone(&cfg);

    /* Copy new config values to global cfg */
    cfg.default_max_retries = new_cfg->default_max_retries;
    cfg.default_findtime = new_cfg->default_findtime;
    cfg.default_ban_time = new_cfg->default_ban_time;
    cfg.daemon = new_cfg->daemon;
    cfg.interval = new_cfg->interval;
    cfg.metrics_port = new_cfg->metrics_port;

    /* Migrate runtime state (failed_hash) from old jails to new jails */
    if (old_cfg_snapshot) {
        for (int i = 0; i < old_cfg_snapshot->jail_count; i++) {
            struct jail *old_jail = &old_cfg_snapshot->jails[i];
            if (!old_jail->failed_hash) continue;

            for (int j = 0; j < new_cfg->jail_count; j++) {
                struct jail *new_jail = &new_cfg->jails[j];
                if (strcmp(old_jail->name, new_jail->name) == 0) {
                    new_jail->failed_hash = old_jail->failed_hash;
                    old_jail->failed_hash = NULL;
                    daemon_log_debug("Migrated failed entries for jail '%s'", new_jail->name);
                    break;
                }
            }
        }
    }

    /* Clean up old jails (failed_hash already migrated) */
    for (int i = 0; i < cfg.jail_count; i++) {
        struct jail *old_jail = &cfg.jails[i];
        for (int j = 0; j < old_jail->log_count; j++) {
            free(old_jail->log_files[j]);
        }
        if (old_jail->regex_compiled) {
            if (old_jail->compiled_regex) pcre2_code_free(old_jail->compiled_regex);
            if (old_jail->match_data) pcre2_match_data_free(old_jail->match_data);
        }
        if (old_jail->regex_pattern) free(old_jail->regex_pattern);
        /* failed_hash already migrated, skip */
        memset(old_jail, 0, sizeof(struct jail));
    }
    cfg.jail_count = 0;

    /* Copy new jails to global cfg */
    cfg.jail_count = new_cfg->jail_count;
    for (int i = 0; i < new_cfg->jail_count; i++) {
        memcpy(&cfg.jails[i], &new_cfg->jails[i], sizeof(struct jail));
        /* Clear source to prevent double-free */
        memset(&new_cfg->jails[i], 0, sizeof(struct jail));
    }
    new_cfg->jail_count = 0;

    /* Update path strings */
    if (new_cfg->config_file) {
        if (cfg.config_file) free(cfg.config_file);
        cfg.config_file = new_cfg->config_file;
        new_cfg->config_file = NULL;
    }
    if (new_cfg->config_dir) {
        if (cfg.config_dir) free(cfg.config_dir);
        cfg.config_dir = new_cfg->config_dir;
        new_cfg->config_dir = NULL;
    }
    if (new_cfg->permanent_db_path) {
        if (cfg.permanent_db_path) free(cfg.permanent_db_path);
        cfg.permanent_db_path = new_cfg->permanent_db_path;
        new_cfg->permanent_db_path = NULL;
        cfg.permanent_ban_enabled = new_cfg->permanent_ban_enabled;
    }

    pthread_mutex_unlock(&config_mutex);

    /* Free new_cfg (jails already moved, paths already moved) */
    if (new_cfg->config_file) free(new_cfg->config_file);
    if (new_cfg->config_dir) free(new_cfg->config_dir);
    if (new_cfg->permanent_db_path) free(new_cfg->permanent_db_path);
    free(new_cfg);

    /* Free old config snapshot (runtime state already migrated) */
    if (old_cfg_snapshot) {
        free_config_partial(old_cfg_snapshot);
        free(old_cfg_snapshot);
    }

    daemon_log_info("Configuration loaded successfully from: %s", config_path);
    return 0;
}

/* Load all .yaml/.yml files from a configuration directory
 * Files are loaded in alphabetical order, later files override earlier ones
 * for scalar values, and arrays are appended. */
int load_config_directory(const char *config_dir)
{
    DIR *dir;
    struct dirent *entry;
    char **file_list = NULL;
    int file_count = 0;
    int file_capacity = 16;
    int ret = 0;
    const int MAX_CONFIG_FILES = 50;  /* Limit to prevent excessive file loading */

    dir = opendir(config_dir);
    if (!dir) {
        daemon_log_warn("Cannot open config directory: %s", config_dir);
        return -1;
    }

    daemon_log_info("Loading configuration directory: %s", config_dir);

    /* Allocate file list */
    file_list = malloc(file_capacity * sizeof(char *));
    if (!file_list) {
        daemon_log_err("Out of memory allocating file list");
        closedir(dir);
        return -1;
    }

    /* Collect all .yaml and .yml files */
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);

        /* Check for .yaml or .yml extension */
        if ((len > 5 && strcmp(name + len - 5, ".yaml") == 0) ||
            (len > 4 && strcmp(name + len - 4, ".yml") == 0)) {
            
            /* Enforce file limit */
            if (file_count >= MAX_CONFIG_FILES) {
                daemon_log_warn("Config file limit reached (%d), skipping: %s", MAX_CONFIG_FILES, name);
                continue;
            }
            

            /* Expand list if needed */
            if (file_count >= file_capacity) {
                file_capacity *= 2;
                char **new_list = realloc(file_list, file_capacity * sizeof(char *));
                if (!new_list) {
                    daemon_log_err("Out of memory expanding file list");
                    for (int i = 0; i < file_count; i++) free(file_list[i]);
                    free(file_list);
                    closedir(dir);
                    return -1;
                }
                file_list = new_list;
            }

            file_list[file_count] = strdup(name);
            if (!file_list[file_count]) {
                daemon_log_err("Out of memory allocating file name");
                for (int i = 0; i < file_count; i++) free(file_list[i]);
                free(file_list);
                closedir(dir);
                return -1;
            }
            file_count++;
        }
    }
    closedir(dir);

    if (file_count == 0) {
        daemon_log_warn("No .yaml/.yml files found in: %s", config_dir);
        free(file_list);
        return 0;
    }

    /* Sort files alphabet using qsort for better performance */
    qsort(file_list, (size_t)file_count, sizeof(char *), compare_config_files);

    /* Load each configuration file - each file can define independent jails */
    for (int i = 0; i < file_count; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, file_list[i]);

        daemon_log_info("Loading config file [%d/%d]: %s", i + 1, file_count, full_path);

        if (parse_config_file(full_path) < 0) {
            daemon_log_warn("Failed to load config file: %s (continuing with others)", full_path);
            /* Continue loading other files instead of failing completely */
        }
    }

    /* Log summary of loaded jails */
    pthread_mutex_lock(&config_mutex);
    daemon_log_info("Loaded %d jails from directory: %s", cfg.jail_count, config_dir);
    for (int i = 0; i < cfg.jail_count; i++) {
        daemon_log_info("  Jail[%d]: %s (enabled=%d, log_count=%d, max_retries=%u)",
            i, cfg.jails[i].name, cfg.jails[i].enabled, cfg.jails[i].log_count, cfg.jails[i].max_retries);
    }
    pthread_mutex_unlock(&config_mutex);

    /* Cleanup */
    for (int i = 0; i < file_count; i++) {
        free(file_list[i]);
    }
    free(file_list);

    return ret;
}

/* Setup signal handlers using sigaction */
void setup_signals(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGTERM, &sa, NULL) == -1) {
        daemon_log_err("Failed to setup SIGTERM handler: %s", strerror(errno));
    }
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        daemon_log_err("Failed to setup SIGINT handler: %s", strerror(errno));
    }
    if (sigaction(SIGHUP, &sa, NULL) == -1) {
        daemon_log_err("Failed to setup SIGHUP handler: %s", strerror(errno));
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        daemon_log_err("Failed to ignore SIGPIPE: %s", strerror(errno));
    }
}

/* Parse command line arguments */
int parse_config(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},  /* Single config file */
        {"config-dir", required_argument, 0, 'C'},  /* Config directory (auto-loads all .yaml) */
        {"daemon",     no_argument,       0, 'd'},
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* Set defaults */
    cfg.default_max_retries = DEFAULT_MAX_RETRIES;
    cfg.default_findtime = DEFAULT_FINDTIME;
    cfg.default_ban_time = DEFAULT_BAN_TIME;
    cfg.daemon = 0;
    cfg.interval = DEFAULT_INTERVAL;
    cfg.metrics_port = DEFAULT_METRICS_PORT;
    cfg.jail_count = 0;
    cfg.config_file = NULL;
    cfg.config_dir = NULL;
    cfg.permanent_db_path = NULL;
    cfg.permanent_ban_enabled = 0;

    /* Initialize jails */
    for (int i = 0; i < MAX_JAILS; i++) {
        cfg.jails[i].name[0] = '\0';
        cfg.jails[i].enabled = false;
        cfg.jails[i].log_count = 0;
        cfg.jails[i].regex_pattern = NULL;
        cfg.jails[i].regex_compiled = 0;
        cfg.jails[i].failed_hash = NULL;
        for (int j = 0; j < MAX_LOG_FILES; j++) {
            cfg.jails[i].log_files[j] = NULL;
        }
    }

    /* Default config directory: /etc/firewall/ (FHS compliant) */
    const char *default_config_dirs[] = {
        "/etc/firewall",
        NULL
    };

    /* First pass: check for explicit config file or directory options */
    for (int i = 1; i < argc; i++) {
        /* Check for --config or -c (single file) */
        if (strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-c") == 0) {
            char *config_path = (i + 1 < argc) ? argv[i + 1] : NULL;
            if (config_path) {
                cfg.config_file = strdup(config_path);
                if (!cfg.config_file) {
                    fprintf(stderr, "Error: out of memory allocating config file path\n");
                    return -1;
                }
                if (parse_config_file(config_path) < 0) {
                    fprintf(stderr, "Error: failed to parse config file: %s\n", config_path);
                    free(cfg.config_file);
                    cfg.config_file = NULL;
                    return -1;
                }
                break;
            }
        } else if (strncmp(argv[i], "--config=", 9) == 0) {
            const char *config_path = argv[i] + 9;
            cfg.config_file = strdup(config_path);
            if (!cfg.config_file) {
                fprintf(stderr, "Error: out of memory allocating config file path\n");
                return -1;
            }
            if (parse_config_file(config_path) < 0) {
                fprintf(stderr, "Error: failed to parse config file: %s\n", config_path);
                free(cfg.config_file);
                cfg.config_file = NULL;
                return -1;
            }
        }
        /* Check for --config-dir or -C (directory) */
        else if (strcmp(argv[i], "--config-dir") == 0 || strcmp(argv[i], "-C") == 0) {
            char *dir_path = (i + 1 < argc) ? argv[i + 1] : NULL;
            if (dir_path) {
                cfg.config_dir = strdup(dir_path);
                if (!cfg.config_dir) {
                    fprintf(stderr, "Error: out of memory allocating config dir path\n");
                    return -1;
                }
                if (load_config_directory(dir_path) < 0) {
                    fprintf(stderr, "Warning: failed to load config directory: %s\n", dir_path);
                    /* Non-fatal: continue without config */
                }
                break;
            }
        } else if (strncmp(argv[i], "--config-dir=", 13) == 0) {
            const char *dir_path = argv[i] + 13;
            cfg.config_dir = strdup(dir_path);
            if (!cfg.config_dir) {
                fprintf(stderr, "Error: out of memory allocating config dir path\n");
                return -1;
            }
            if (load_config_directory(dir_path) < 0) {
                fprintf(stderr, "Warning: failed to load config directory: %s\n", dir_path);
            }
        }
    }

    /* If no explicit config was provided, try default config directories */
    if (!cfg.config_file && !cfg.config_dir) {
        for (int i = 0; default_config_dirs[i] != NULL; i++) {
            if (access(default_config_dirs[i], F_OK) == 0) {
                cfg.config_dir = strdup(default_config_dirs[i]);
                if (!cfg.config_dir) {
                    fprintf(stderr, "Error: out of memory allocating config dir path\n");
                    return -1;
                }
                if (load_config_directory(default_config_dirs[i]) < 0) {
                    daemon_log_warn("No config files found in: %s", default_config_dirs[i]);
                    free(cfg.config_dir);
                    cfg.config_dir = NULL;
                } else {
                    daemon_log_info("Using default config directory: %s", default_config_dirs[i]);
                    break;
                }
            }
        }
    }

    /* Now parse command line options (they override config file values) */
    while ((opt = getopt_long(argc, argv, "c:C:dh", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':  /* Config file - already handled above */
            break;
        case 'C':  /* Config directory - already handled above */
            break;
        case 'd':
            cfg.daemon = 1;
            break;
        case 'h':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -c, --config FILE      Single configuration file path\n");
            printf("  -C, --config-dir DIR   Configuration directory (auto-loads all .yaml/.yml files)\n");
            printf("                         Default: /etc/firewall/\n");
            printf("  -d, --daemon           Run as daemon\n");
            printf("  -h, --help             Show this help\n");
            printf("\nConfig file format:\n");
            printf("  defaults:\n");
            printf("    max_retries: 5\n");
            printf("    findtime: 600\n");
            printf("    ban_time: 900\n");
            printf("  jails:\n");
            printf("    sshd:\n");
            printf("      enabled: true\n");
            printf("      log_files:\n");
            printf("        - /var/log/auth.log\n");
            return 1;
        case '?':
            /* getopt_long already printed an error message */
            return -1;
        default:
            return -1;
        }
    }

    /* Default log files if none specified - require jail format in config */
    int total_log_files = 0;
    for (int i = 0; i < cfg.jail_count; i++) {
        total_log_files += cfg.jails[i].log_count;
    }

    if (total_log_files == 0) {
        fprintf(stderr, "Error: no jails configured. Use jails: section in config file.\n");
        fprintf(stderr, "Example:\n");
        fprintf(stderr, "  jails:\n");
        fprintf(stderr, "    sshd:\n");
        fprintf(stderr, "      enabled: true\n");
        fprintf(stderr, "      log_files:\n");
        fprintf(stderr, "        - /var/log/auth.log\n");
        return -1;
    }

    return 0;
}

/*
 * validate_and_normalize_path - Validate log file path for security
 * @input_path: Path to validate
 *
 * Uses realpath() for robust path normalization and traversal detection.
 * Rejects paths with shell metacharacters, control characters, or
 * that resolve outside expected locations.
 *
 * Returns: 0 if valid, -1 if invalid
 */
int validate_and_normalize_path(const char *input_path) {
    char resolved[PATH_MAX];
    size_t input_len;

    if (!input_path) {
        return -1;
    }

    input_len = strlen(input_path);
    if (input_len == 0 || input_len >= PATH_MAX) {
        return -1;
    }

    /* Must be absolute path */
    if (input_path[0] != '/') {
        return -1;
    }

    /* Reject control characters */
    for (size_t i = 0; i < input_len; i++) {
        if ((unsigned char)input_path[i] < 32) {
            return -1;
        }
    }

    /* Reject shell metacharacters that could enable injection */
    if (strpbrk(input_path, "|;&`$(){}<>!~*?[]") != NULL) {
        return -1;
    }

    /* Reject URL-encoded traversal attempts */
    if (strcasestr(input_path, "%2e") != NULL || strcasestr(input_path, "%2f") != NULL) {
        return -1;
    }

    /* Reject obvious path traversal patterns */
    if (strstr(input_path, "..") != NULL) {
        return -1;
    }

    /* Use realpath() for final normalization and validation.
     * realpath() requires the path to exist, so we use it only for
     * the directory component. If the file doesn't exist yet, we
     * validate the parent directory instead. */
    char *path_copy = strdup(input_path);
    if (!path_copy) {
        return -1;
    }

    char *dir = dirname(path_copy);
    if (realpath(dir, resolved) == NULL) {
        /* Directory doesn't exist - allow if path looks safe */
        free(path_copy);
        return (strstr(input_path, "//") == NULL) ? 0 : -1;
    }

    free(path_copy);

    /* Verify resolved path doesn't escape expected locations.
     * Log files should be under /var/log or similar standard locations.
     * Note: /root/ is excluded as systemd ProtectHome=yes blocks access. */
    if (strncmp(resolved, "/var/log", 8) != 0 &&
        strncmp(resolved, "/etc/", 5) != 0 &&
        strncmp(resolved, "/home/", 6) != 0 &&
        strncmp(resolved, "/srv/", 5) != 0) {
        /* Reject paths outside standard locations */
        return -1;
    }

    return 0;
}