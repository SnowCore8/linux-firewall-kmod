/*
 * config-parser.c - 配置解析函数
 */

#include "firewall-daemon.h"
#include "jail-manager.h"
#include "config-parser.h"

/* 引用全局严格模式标志 */
extern int config_strict_mode;

/* 用于双缓冲配置重新加载的 YAML 解析上下文 */
struct yaml_parse_ctx {
    struct jail *current_jail;
    int in_jails_section;
    int in_defaults_section;
    int in_log_files_array;
    char *current_key;
    char *current_jail_name;
    int strict_mode;          /* 1=严格模式，0=兼容模式 */
    int has_error;            /* 错误累积标志 */
    const char *config_file;  /* 配置文件路径（用于错误提示） */
};

/* 校验 defaults 部分的参数名是否有效 */
static int is_valid_defaults_key(const char *key)
{
    const char *valid_keys[] = {
        "max_retries", "findtime", "ban_time", "interval",
        "metrics_port", "daemon", "permanent_db_path",
        "permanent_ban_enabled", NULL
    };
    for (int i = 0; valid_keys[i]; i++) {
        if (strcmp(key, valid_keys[i]) == 0) return 1;
    }
    return 0;
}

/* 校验 jail 部分的参数名是否有效 */
static int is_valid_jail_key(const char *key)
{
    const char *valid_keys[] = {
        "enabled", "log_files", "max_retries", "findtime",
        "ban_time", "regex", NULL
    };
    for (int i = 0; valid_keys[i]; i++) {
        if (strcmp(key, valid_keys[i]) == 0) return 1;
    }
    return 0;
}

/* 将 YAML 文件解析到目标配置（不持有锁）。
 * 这是从 parse_config_file 中提取的核心解析逻辑。
 * 成功返回 0，错误返回 -1。 */
static int parse_yaml_into(const char *config_path, struct config *target)
{
    FILE *file;
    yaml_parser_t parser;
    yaml_event_t event;
    int done = 0;
    int error = 0;

    struct yaml_parse_ctx ctx = {0};
    ctx.strict_mode = config_strict_mode;  /* 使用全局严格模式设置 */
    ctx.config_file = config_path;

    /* 提取配置文件目录以解析相对路径 */
    char config_dir[1024];
    strncpy(config_dir, config_path, sizeof(config_dir) - 1);
    config_dir[sizeof(config_dir) - 1] = '\0';
    char *last_slash = strrchr(config_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(config_dir, ".");
    }

    /* 打开配置文件 */
    file = fopen(config_path, "r");
    if (!file) {
        daemon_log_warn("Cannot open config file: %s", config_path);
        return -1;
    }

    daemon_log_info("Reading config file: %s", config_path);

    /* 初始化 YAML 解析器 */
    if (!yaml_parser_initialize(&parser)) {
        daemon_log_err("Failed to initialize YAML parser");
        fclose(file);
        return -1;
    }

    yaml_parser_set_input_file(&parser, file);

    /* 解析 YAML 事件 */
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

            /* 拒绝过长的值以防止内存耗尽 */
            if (strlen(value) > 1024) {
                daemon_log_warn("YAML value too long (%zu bytes), rejecting", strlen(value));
                error = 1;
                break;
            }

            if (ctx.in_defaults_section && ctx.current_key) {
                /* 解析 defaults 部分 - 设置全局默认值 */
                if (strcmp(ctx.current_key, "max_retries") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 100) {
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid value for 'max_retries': '%s' (must be integer between 1 and 100) in %s",
                                           value, ctx.config_file ? ctx.config_file : "unknown");
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Invalid default max_retries: %s", value);
                        }
                    } else {
                        target->default_max_retries = (unsigned int)val;
                        daemon_log_info("Default max_retries set to %u", target->default_max_retries);
                    }
                } else if (strcmp(ctx.current_key, "findtime") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid value for 'findtime': '%s' (must be integer between 1 and 3600) in %s",
                                           value, ctx.config_file ? ctx.config_file : "unknown");
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Invalid default findtime: %s", value);
                        }
                    } else {
                        target->default_findtime = (unsigned int)val;
                        daemon_log_info("Default findtime set to %u", target->default_findtime);
                    }
                } else if (strcmp(ctx.current_key, "ban_time") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || (val != 0 && (val < 1 || val > 86400))) {
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid value for 'ban_time': '%s' (must be 0 or integer between 1 and 86400) in %s",
                                           value, ctx.config_file ? ctx.config_file : "unknown");
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Invalid default ban_time: %s", value);
                        }
                    } else {
                        target->default_ban_time = (unsigned int)val;
                        daemon_log_info("Default ban_time set to %u", target->default_ban_time);
                    }
                } else if (strcmp(ctx.current_key, "interval") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 1 || val > 60) {
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid value for 'interval': '%s' (must be integer between 1 and 60) in %s",
                                           value, ctx.config_file ? ctx.config_file : "unknown");
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Invalid default interval: %s", value);
                        }
                    } else {
                        target->interval = (int)val;
                        daemon_log_info("Default interval set to %d", target->interval);
                    }
                } else if (strcmp(ctx.current_key, "metrics_port") == 0) {
                    char *endptr;
                    errno = 0;
                    long val = strtol(value, &endptr, 10);
                    if (errno != 0 || *endptr != '\0' || val < 0 || val > 65535) {
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid value for 'metrics_port': '%s' (must be integer between 0 and 65535) in %s",
                                           value, ctx.config_file ? ctx.config_file : "unknown");
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Invalid default metrics_port: %s", value);
                        }
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
                        /* 相对于配置文件目录解析相对路径 */
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
                } else {
                    /* 未知参数处理 */
                    if (ctx.strict_mode) {
                        daemon_log_err("Invalid config parameter '%s' with value '%s' in [defaults] of %s",
                                       ctx.current_key, value, ctx.config_file ? ctx.config_file : "unknown");
                        ctx.has_error = 1;
                    } else {
                        daemon_log_warn("Ignoring unknown parameter in [defaults]: %s = %s",
                                        ctx.current_key, value);
                    }
                }
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else if (ctx.in_jails_section && ctx.current_jail_name && !ctx.in_log_files_array) {
                /* 在 jail 部分中 - 这可能是 jail 键或 jail 属性 */
                if (!ctx.current_key) {
                    /* 这是当前 jail 的属性键 */
                    ctx.current_key = strdup(value);
                } else {
                    /* 我们有了 jail 属性的键值对 */
                    /* 如果尚未创建则查找或创建 jail */
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
                            if (ctx.strict_mode) {
                                daemon_log_err("Invalid value for 'max_retries': '%s' in jail '%s' of %s (must be integer between 1 and 100)",
                                               value, ctx.current_jail->name, ctx.config_file);
                                ctx.has_error = 1;
                            } else {
                                daemon_log_warn("Invalid max_retries for jail '%s': %s", ctx.current_jail->name, value);
                            }
                        } else {
                            ctx.current_jail->max_retries = (unsigned int)val;
                            ctx.current_jail->_max_retries_set = true;
                            daemon_log_info("Jail '%s' max_retries set to %u", ctx.current_jail->name, ctx.current_jail->max_retries);
                        }
                    } else if (strcmp(ctx.current_key, "findtime") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || val < 1 || val > 3600) {
                            if (ctx.strict_mode) {
                                daemon_log_err("Invalid value for 'findtime': '%s' in jail '%s' of %s (must be integer between 1 and 3600)",
                                               value, ctx.current_jail->name, ctx.config_file);
                                ctx.has_error = 1;
                            } else {
                                daemon_log_warn("Invalid findtime for jail '%s': %s", ctx.current_jail->name, value);
                            }
                        } else {
                            ctx.current_jail->findtime = (unsigned int)val;
                            ctx.current_jail->_findtime_set = true;
                            daemon_log_info("Jail '%s' findtime set to %u", ctx.current_jail->name, ctx.current_jail->findtime);
                        }
                    } else if (strcmp(ctx.current_key, "ban_time") == 0) {
                        char *endptr;
                        errno = 0;
                        long val = strtol(value, &endptr, 10);
                        if (errno != 0 || *endptr != '\0' || (val != 0 && (val < 1 || val > 86400))) {
                            if (ctx.strict_mode) {
                                daemon_log_err("Invalid value for 'ban_time': '%s' in jail '%s' of %s (must be 0 or integer between 1 and 86400)",
                                               value, ctx.current_jail->name, ctx.config_file);
                                ctx.has_error = 1;
                            } else {
                                daemon_log_warn("Invalid ban_time for jail '%s': %s", ctx.current_jail->name, value);
                            }
                        } else {
                            ctx.current_jail->ban_time = (unsigned int)val;
                            ctx.current_jail->_ban_time_set = true;
                            daemon_log_info("Jail '%s' ban_time set to %u", ctx.current_jail->name, ctx.current_jail->ban_time);
                        }
                    } else if (strcmp(ctx.current_key, "regex") == 0) {
                        if (ctx.current_jail->regex_pattern) free(ctx.current_jail->regex_pattern);
                        ctx.current_jail->regex_pattern = strdup(value);
                        daemon_log_info("Jail '%s' regex set to: %s", ctx.current_jail->name, value);
                    } else {
                        /* 未知 jail 参数 */
                        if (ctx.strict_mode) {
                            daemon_log_err("Invalid config parameter '%s' with value '%s' in jail '%s' of %s",
                                           ctx.current_key, value, ctx.current_jail->name, ctx.config_file);
                            ctx.has_error = 1;
                        } else {
                            daemon_log_warn("Ignoring unknown parameter in jail '%s': %s = %s",
                                            ctx.current_jail->name, ctx.current_key, value);
                        }
                    }
                    free(ctx.current_key);
                    ctx.current_key = NULL;
                }
            } else if (ctx.in_log_files_array && ctx.current_jail) {
                /* 解析当前 jail 的 log_files 数组 */
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
                /* 顶层键值对（不在 jails 或 defaults 中） */
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
                        /* 相对于配置文件目录解析相对路径 */
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
                    if (ctx.strict_mode) {
                        daemon_log_err("Invalid config parameter '%s' with value '%s' at top-level of %s (jail format required)",
                                       ctx.current_key, value, ctx.config_file);
                        ctx.has_error = 1;
                    } else {
                        daemon_log_warn("Ignoring unsupported top-level key: %s (jail format required)", ctx.current_key);
                    }
                }
                free(ctx.current_key);
                ctx.current_key = NULL;
            } else {
                /* 这是一个还没有值的键 */
                ctx.current_key = strdup(value);
            }
            break;
        }

        case YAML_SEQUENCE_START_EVENT: {
            if (ctx.current_key && strcmp(ctx.current_key, "log_files") == 0) {
                ctx.in_log_files_array = 1;
            }
            /* 无论是否匹配，都需要释放 current_key */
            if (ctx.current_key) {
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
                /* 开始一个新的 jail 映射 */
                if (ctx.current_jail_name) free(ctx.current_jail_name);
                ctx.current_jail_name = ctx.current_key;
                ctx.current_jail = NULL;  /* 将在解析属性时创建 */
                ctx.current_key = NULL;
            } else if (ctx.current_key) {
                /* 意外映射，释放 key */
                free(ctx.current_key);
                ctx.current_key = NULL;
            }
        }
        break;

        case YAML_MAPPING_END_EVENT: {
            if (ctx.in_jails_section && !ctx.in_log_files_array) {
                /* jail 部分结束 - 如果存在模式则编译正则表达式 */
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

    /* 清理 */
    if (ctx.current_key) free(ctx.current_key);
    if (ctx.current_jail_name) free(ctx.current_jail_name);

    /* 严格模式下如果有任何错误则返回失败 */
    if (ctx.has_error && ctx.strict_mode) {
        daemon_log_err("Config loading failed due to invalid parameters in %s", config_path);
        return -1;
    }

    if (error) return -1;

    /* 解析成功后应用智能推断参数（仅对未显式配置的参数） */
    apply_smart_defaults_to_all(target);

    return 0;
}

/* 使用 libyaml 解析配置文件 - 支持基于 jail 的 YAML 格式。
 * 使用双缓冲模式：在不持有锁的情况下解析到临时配置，
 * 然后短暂加锁以交换配置并迁移运行时状态。 */
int parse_config_file(const char *config_path)
{
    struct config *new_cfg;
    struct config *old_cfg_snapshot = NULL;
    int parse_rc;

    /* 分配临时配置 */
    new_cfg = calloc(1, sizeof(*new_cfg));
    if (!new_cfg) {
        daemon_log_err("Out of memory allocating temporary config");
        return -1;
    }

    /* 将路径字符串复制到 new_cfg（解析相对路径所需）
     * 在持有读锁的情况下复制以防止并发修改 */
    pthread_rwlock_rdlock(&config_rwlock);
    if (cfg.config_file) {
        new_cfg->config_file = strdup(cfg.config_file);
        if (!new_cfg->config_file) { pthread_rwlock_unlock(&config_rwlock); free(new_cfg); return -1; }
    }
    if (cfg.config_dir) {
        new_cfg->config_dir = strdup(cfg.config_dir);
        if (!new_cfg->config_dir) {
            free(new_cfg->config_file); pthread_rwlock_unlock(&config_rwlock); free(new_cfg); return -1;
        }
    }
    if (cfg.permanent_db_path) {
        new_cfg->permanent_db_path = strdup(cfg.permanent_db_path);
        if (!new_cfg->permanent_db_path) {
            free(new_cfg->config_file); free(new_cfg->config_dir); pthread_rwlock_unlock(&config_rwlock); free(new_cfg); return -1;
        }
        new_cfg->permanent_ban_enabled = cfg.permanent_ban_enabled;
    }
    pthread_rwlock_unlock(&config_rwlock);

    /* 复制当前默认值作为基准 */
    pthread_rwlock_rdlock(&config_rwlock);
    new_cfg->default_max_retries = cfg.default_max_retries;
    new_cfg->default_findtime = cfg.default_findtime;
    new_cfg->default_ban_time = cfg.default_ban_time;
    new_cfg->daemon = cfg.daemon;
    new_cfg->interval = cfg.interval;
    new_cfg->metrics_port = cfg.metrics_port;
    new_cfg->jail_count = 0;
    pthread_rwlock_unlock(&config_rwlock);

    /* 在不持有锁的情况下将 YAML 解析到 new_cfg */
    parse_rc = parse_yaml_into(config_path, new_cfg);
    if (parse_rc < 0) {
        daemon_log_warn("Failed to parse config file: %s", config_path);
        /* 释放 new_cfg 分配的字符串 */
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

    /* 验证新配置 */
    if (config_validate(new_cfg) < 0) {
        daemon_log_warn("Config validation failed for: %s", config_path);
        /* 释放 new_cfg */
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

    /* 短暂加写锁以交换配置并迁移运行时状态 */
    pthread_rwlock_wrlock(&config_rwlock);

    /* 快照旧配置以进行迁移和清理 */
    old_cfg_snapshot = config_clone(&cfg);

    /* 将新配置值复制到全局 cfg */
    cfg.default_max_retries = new_cfg->default_max_retries;
    cfg.default_findtime = new_cfg->default_findtime;
    cfg.default_ban_time = new_cfg->default_ban_time;
    cfg.daemon = new_cfg->daemon;
    cfg.interval = new_cfg->interval;
    cfg.metrics_port = new_cfg->metrics_port;

    /* 将运行时状态（failed_hash）从旧 jail 迁移到新 jail。
     * 注意：old_cfg_snapshot 是通过 config_clone() 创建的，clone_jail() 显式设置 failed_hash = NULL，
     * 所以必须从原始 cfg 获取 failed_hash。*/
    if (old_cfg_snapshot) {
        for (int i = 0; i < old_cfg_snapshot->jail_count; i++) {
            struct jail *old_jail = &old_cfg_snapshot->jails[i];
            struct jail *real_old_jail = &cfg.jails[i];  /* 从原始 cfg 获取 failed_hash */
            if (!real_old_jail->failed_hash) continue;

            for (int j = 0; j < new_cfg->jail_count; j++) {
                struct jail *new_jail = &new_cfg->jails[j];
                if (strcmp(old_jail->name, new_jail->name) == 0) {
                    new_jail->failed_hash = real_old_jail->failed_hash;
                    real_old_jail->failed_hash = NULL;  /* 防止后续清理时泄漏 */
                    daemon_log_debug("Migrated failed entries for jail '%s'", new_jail->name);
                    break;
                }
            }
        }
    }

    /* 清理旧 jail（failed_hash 已迁移） */
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
        /* 释放 failed_table 链表 */
        if (old_jail->failed_table) {
            struct failed_entry *entry = old_jail->failed_table;
            while (entry) {
                struct failed_entry *next = entry->next;
                free(entry);
                entry = next;
            }
        }
        /* failed_hash 已迁移，跳过 */
        memset(old_jail, 0, sizeof(struct jail));
    }
    cfg.jail_count = 0;

    /* 将新 jail 复制到全局 cfg */
    cfg.jail_count = new_cfg->jail_count;
    for (int i = 0; i < new_cfg->jail_count; i++) {
        memcpy(&cfg.jails[i], &new_cfg->jails[i], sizeof(struct jail));
        /* 清空源以防止重复释放 */
        memset(&new_cfg->jails[i], 0, sizeof(struct jail));
    }
    new_cfg->jail_count = 0;

    /* 更新路径字符串 */
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

    pthread_rwlock_unlock(&config_rwlock);

    /* 释放 new_cfg（jail 已移动，路径已移动） */
    if (new_cfg->config_file) free(new_cfg->config_file);
    if (new_cfg->config_dir) free(new_cfg->config_dir);
    if (new_cfg->permanent_db_path) free(new_cfg->permanent_db_path);
    free(new_cfg);

    /* 释放旧配置快照（运行时状态已迁移） */
    if (old_cfg_snapshot) {
        free_config_partial(old_cfg_snapshot);
        free(old_cfg_snapshot);
    }

    daemon_log_info("Configuration loaded successfully from: %s", config_path);
    return 0;
}

/* 从配置目录加载所有 .yaml/.yml 文件
 * 文件按字母顺序加载，后面的文件会覆盖前面的标量值，
 * 数组则会追加。 */
int load_config_directory(const char *config_dir)
{
    DIR *dir;
    struct dirent *entry;
    char **file_list = NULL;
    int file_count = 0;
    int file_capacity = 16;
    int ret = 0;
    const int MAX_CONFIG_FILES = 50;  /* 限制数量以防止加载过多文件 */

    dir = opendir(config_dir);
    if (!dir) {
        daemon_log_warn("Cannot open config directory: %s", config_dir);
        return -1;
    }

    daemon_log_info("Loading configuration directory: %s", config_dir);

    /* 分配文件列表 */
    file_list = malloc(file_capacity * sizeof(char *));
    if (!file_list) {
        daemon_log_err("Out of memory allocating file list");
        closedir(dir);
        return -1;
    }

    /* 收集所有 .yaml 和 .yml 文件 */
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        size_t len = strlen(name);

        /* 检查 .yaml 或 .yml 扩展名 */
        if ((len > 5 && strcmp(name + len - 5, ".yaml") == 0) ||
            (len > 4 && strcmp(name + len - 4, ".yml") == 0)) {
            
            /* 强制执行文件数量限制 */
            if (file_count >= MAX_CONFIG_FILES) {
                daemon_log_warn("Config file limit reached (%d), skipping: %s", MAX_CONFIG_FILES, name);
                continue;
            }
            

            /* 如果需要则扩展列表 */
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

    /* 使用 qsort 按字母顺序对文件排序以提高性能 */
    qsort(file_list, (size_t)file_count, sizeof(char *), compare_config_files);

    /* 加载每个配置文件 - 每个文件可以定义独立的 jail */
    for (int i = 0; i < file_count; i++) {
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", config_dir, file_list[i]);

        daemon_log_info("Loading config file [%d/%d]: %s", i + 1, file_count, full_path);

        if (parse_config_file(full_path) < 0) {
            daemon_log_warn("Failed to load config file: %s (continuing with others)", full_path);
            /* 继续加载其他文件而不是完全失败 */
        }
    }

    /* 记录已加载 jail 的摘要 */
    pthread_rwlock_rdlock(&config_rwlock);
    daemon_log_info("Loaded %d jails from directory: %s", cfg.jail_count, config_dir);
    for (int i = 0; i < cfg.jail_count; i++) {
        daemon_log_info("  Jail[%d]: %s (enabled=%d, log_count=%d, max_retries=%u)",
            i, cfg.jails[i].name, cfg.jails[i].enabled, cfg.jails[i].log_count, cfg.jails[i].max_retries);
    }
    pthread_rwlock_unlock(&config_rwlock);

    /* 清理 */
    for (int i = 0; i < file_count; i++) {
        free(file_list[i]);
    }
    free(file_list);

    return ret;
}

/* 使用 sigaction 设置信号处理函数 */
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

    /* 忽略 SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        daemon_log_err("Failed to ignore SIGPIPE: %s", strerror(errno));
    }
}

/* 解析命令行参数 */
int parse_config(int argc, char *argv[])
{
    int opt;
    static struct option long_options[] = {
        {"config",     required_argument, 0, 'c'},  /* 单个配置文件 */
        {"config-dir", required_argument, 0, 'C'},  /* 配置目录（自动加载所有 .yaml） */
        {"daemon",     no_argument,       0, 'd'},
        {"strict",     no_argument,       0, 's'},  /* 严格模式（默认） */
        {"permissive", no_argument,       0, 'p'},  /* 宽松模式 */
        {"help",       no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    /* 设置默认值 */
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

    /* 初始化 jails */
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

    /* 默认配置目录：/etc/firewall/（符合 FHS 标准） */
    const char *default_config_dirs[] = {
        "/etc/firewall",
        NULL
    };

    /* 第一遍：检查显式的配置文件或目录选项 */
    for (int i = 1; i < argc; i++) {
        /* 检查 --config 或 -c（单个文件） */
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
        /* 检查 --config-dir 或 -C（目录） */
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
                    /* 非致命错误：在没有配置的情况下继续 */
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
        /* 检查 --strict 或 -s（严格模式） */
        else if (strcmp(argv[i], "--strict") == 0 || strcmp(argv[i], "-s") == 0) {
            config_strict_mode = 1;
        }
        /* 检查 --permissive 或 -p（宽松模式） */
        else if (strcmp(argv[i], "--permissive") == 0 || strcmp(argv[i], "-p") == 0) {
            config_strict_mode = 0;
        }
    }

    /* 如果未提供显式配置，尝试默认配置目录 */
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

    /* 现在解析命令行选项（它们会覆盖配置文件中的值） */
    while ((opt = getopt_long(argc, argv, "c:C:dsph", long_options, NULL)) != -1) {
        switch (opt) {
        case 'c':  /* 配置文件 - 已在上面处理 */
            break;
        case 'C':  /* 配置目录 - 已在上面处理 */
            break;
        case 'd':
            cfg.daemon = 1;
            break;
        case 's':
            config_strict_mode = 1;
            fprintf(stderr, "Strict mode enabled: invalid config parameters will cause loading failure\n");
            break;
        case 'p':
            config_strict_mode = 0;
            fprintf(stderr, "Permissive mode enabled: invalid config parameters will be ignored with warnings\n");
            break;
        case 'h':
            printf("Usage: %s [OPTIONS]\n", argv[0]);
            printf("\nOptions:\n");
            printf("  -c, --config FILE      Single configuration file path\n");
            printf("  -C, --config-dir DIR   Configuration directory (auto-loads all .yaml/.yml files)\n");
            printf("                         Default: /etc/firewall/\n");
            printf("  -d, --daemon           Run as daemon\n");
            printf("  -s, --strict           Enable strict config validation (default)\n");
            printf("  -p, --permissive       Allow unknown parameters with warnings\n");
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
            /* getopt_long 已打印错误信息 */
            return -1;
        default:
            return -1;
        }
    }

    /* 如果未指定默认日志文件 - 需要在配置中使用 jail 格式 */
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
 * validate_and_normalize_path - 验证日志文件路径的安全性
 * @input_path: 要验证的路径
 *
 * 使用 realpath() 进行可靠的路径规范化和遍历检测。
 * 拒绝包含 shell 元字符、控制字符或
 * 解析到预期位置之外的路径。
 *
 * 返回值：有效返回 0，无效返回 -1
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

    /* 必须是绝对路径 */
    if (input_path[0] != '/') {
        return -1;
    }

    /* 拒绝控制字符 */
    for (size_t i = 0; i < input_len; i++) {
        if ((unsigned char)input_path[i] < 32) {
            return -1;
        }
    }

    /* 拒绝可能导致注入的 shell 元字符 */
    if (strpbrk(input_path, "|;&`$(){}<>!~*?[]") != NULL) {
        return -1;
    }

    /* 拒绝 URL 编码的遍历尝试 */
    if (strcasestr(input_path, "%2e") != NULL || strcasestr(input_path, "%2f") != NULL) {
        return -1;
    }

    /* 拒绝明显的路径遍历模式 */
    if (strstr(input_path, "..") != NULL) {
        return -1;
    }

    /* 使用 realpath() 进行最终的规范化和验证。
     * realpath() 要求路径存在，因此我们仅将其用于
     * 目录部分。如果文件尚不存在，我们
     * 改为验证父目录。 */
    char *path_copy = strdup(input_path);
    if (!path_copy) {
        return -1;
    }

    char *dir = dirname(path_copy);
    if (realpath(dir, resolved) == NULL) {
        /* 目录不存在 - 如果路径看起来安全则允许 */
        free(path_copy);
        return (strstr(input_path, "//") == NULL) ? 0 : -1;
    }

    free(path_copy);

    /* 验证解析后的路径不会逃逸到预期位置之外。
     * 日志文件应位于 /var/log 或类似的标准位置。
     * 注意：/root/ 被排除，因为 systemd ProtectHome=yes 会阻止访问。 */
    if (strncmp(resolved, "/var/log", 8) != 0 &&
        strncmp(resolved, "/etc/", 5) != 0 &&
        strncmp(resolved, "/home/", 6) != 0 &&
        strncmp(resolved, "/srv/", 5) != 0) {
        /* 拒绝不在标准位置的路径 */
        return -1;
    }

    return 0;
}