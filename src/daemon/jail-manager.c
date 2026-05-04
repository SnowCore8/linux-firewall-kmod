/*
 * jail-manager.c - jail 管理函数
 */

#include "firewall-daemon.h"
#include "jail-manager.h"

/* 根据服务名称智能推断推荐参数 */
static void apply_smart_defaults(struct jail *j, const char *name)
{
    /* SSH 服务 - 暴力破解防护 */
    if (strstr(name, "ssh") || strstr(name, "sshd")) {
        j->max_retries = 5;
        j->findtime = 600;      /* 10 分钟窗口 */
        j->ban_time = 900;      /* 15 分钟封禁 */
        daemon_log_info("Jail '%s': applying SSH smart defaults (retries=5, findtime=600, ban=900)", name);
    }
    /* Nginx/Apache 服务 - Web 攻击防护 */
    else if (strstr(name, "nginx") || strstr(name, "apache") || strstr(name, "http")) {
        j->max_retries = 10;
        j->findtime = 300;      /* 5 分钟窗口 */
        j->ban_time = 1800;     /* 30 分钟封禁 */
        daemon_log_info("Jail '%s': applying WEB smart defaults (retries=10, findtime=300, ban=1800)", name);
    }
    /* FTP 服务 */
    else if (strstr(name, "ftp") || strstr(name, "vsftpd") || strstr(name, "proftpd")) {
        j->max_retries = 5;
        j->findtime = 600;
        j->ban_time = 1800;
        daemon_log_info("Jail '%s': applying FTP smart defaults (retries=5, findtime=600, ban=1800)", name);
    }
    /* 邮件服务 */
    else if (strstr(name, "postfix") || strstr(name, "dovecot") || strstr(name, "mail")) {
        j->max_retries = 5;
        j->findtime = 300;
        j->ban_time = 1800;
        daemon_log_info("Jail '%s': applying MAIL smart defaults (retries=5, findtime=300, ban=1800)", name);
    }
    /* FRP 服务 */
    else if (strstr(name, "frp")) {
        j->max_retries = 10;
        j->findtime = 300;
        j->ban_time = 1800;
        daemon_log_info("Jail '%s': applying FRP smart defaults (retries=10, findtime=300, ban=1800)", name);
    }
    /* 数据库服务 */
    else if (strstr(name, "mysql") || strstr(name, "mariadb") || strstr(name, "postgres")) {
        j->max_retries = 3;
        j->findtime = 300;
        j->ban_time = 3600;     /* 1 小时封禁 */
        daemon_log_info("Jail '%s': applying DB smart defaults (retries=3, findtime=300, ban=3600)", name);
    }
    /* 默认使用全局 defaults */
    else {
        j->max_retries = cfg.default_max_retries;
        j->findtime = cfg.default_findtime;
        j->ban_time = cfg.default_ban_time;
        daemon_log_info("Jail '%s': using global defaults (retries=%u, findtime=%u, ban=%u)",
                       name, j->max_retries, j->findtime, j->ban_time);
    }
}

/* 使用全局配置的默认值初始化 jail */
void init_jail_defaults(struct jail *j)
{
    j->enabled = true;
    j->log_count = 0;
    j->regex_pattern = NULL;
    j->regex_compiled = 0;
    memset(&j->compiled_regex, 0, sizeof(j->compiled_regex));
    /* 注意：max_retries/findtime/ban_time 将在 apply_smart_defaults 中设置 */
    j->failed_table = NULL;
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));
    j->failed_hash = NULL;
    j->partial_line_len = 0;
    j->partial_line_buffer[0] = '\0';

    for (int i = 0; i < MAX_LOG_FILES; i++) {
        j->log_files[i] = NULL;
    }
}

/* 释放 jail 正则表达式 */
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

/* 查找现有 jail 或创建新的 */
struct jail *find_or_create_jail(const char *name)
{
    /* 查找现有 jail */
    for (int i = 0; i < cfg.jail_count; i++) {
        if (strcmp(cfg.jails[i].name, name) == 0) {
            return &cfg.jails[i];
        }
    }

    /* 创建新 jail */
    if (cfg.jail_count >= MAX_JAILS) {
        daemon_log_warn("Max jails reached (%d), cannot create jail '%s'", MAX_JAILS, name);
        return NULL;
    }

    struct jail *j = &cfg.jails[cfg.jail_count++];
    init_jail_defaults(j);
    strncpy(j->name, name, sizeof(j->name) - 1);
    j->name[sizeof(j->name) - 1] = '\0';

    /* 应用智能推断参数 */
    apply_smart_defaults(j, name);

    daemon_log_info("Created new jail: %s", name);
    return j;
}

/* 销毁 jail 并释放其资源 */
void destroy_jail(struct jail *j)
{
    if (!j) return;

    /* 释放日志文件 */
    for (int i = 0; i < j->log_count; i++) {
        if (j->log_files[i]) {
            free(j->log_files[i]);
            j->log_files[i] = NULL;
        }
    }
    j->log_count = 0;

    /* 释放正则表达式 */
    free_jail_regex(j);
    if (j->regex_pattern) {
        free(j->regex_pattern);
        j->regex_pattern = NULL;
    }

    /* 释放失败记录表 */
    if (j->failed_table) {
        struct failed_entry *entry = j->failed_table;
        while (entry) {
            struct failed_entry *next = entry->next;
            free(entry);
            entry = next;
        }
        j->failed_table = NULL;
    }

    /* 清空哈希表 */
    memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));

    /* 在销毁之前释放 khash 表的键（堆分配的字符串） */
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

/* 使用 PCRE2 编译 jail 的正则表达式 */
int compile_jail_regex(struct jail *j)
{
    if (!j) return -1;

    /* 如果已编译则释放现有正则表达式 */
    if (j->regex_compiled) {
        if (j->compiled_regex)
            pcre2_code_free(j->compiled_regex);
        if (j->match_data)
            pcre2_match_data_free(j->match_data);
        j->compiled_regex = NULL;
        j->match_data = NULL;
        j->regex_compiled = 0;
    }

    /* 使用 jail 的自定义正则表达式或内置默认值 */
    const char *pattern = (j->regex_pattern && strlen(j->regex_pattern) > 0) ?
        j->regex_pattern :
        "Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";

    /* 验证正则表达式模式以防止 ReDoS 攻击 */
    if (j->regex_pattern && strlen(j->regex_pattern) > 0) {
        size_t pattern_len = strlen(pattern);

        /* 拒绝过长的模式（在嵌套量词检测之前先做长度检查） */
        if (pattern_len > 1024) {
            daemon_log_err("Rejected unsafe regex for jail '%s': pattern too long (%zu bytes, max 1024)",
                           j->name, pattern_len);
            return -1;
        }

        /* 拒绝真正的嵌套量词模式: 遍历检测 ) 后紧跟 + 或 * 的情况
         * 注意: (text)? 是合法的可选捕获组，不应被拒绝
         *       只有 )+  )* 才是危险的嵌套量词（如 (a+)+ (a*)*）
         * 保留 ++ 和 *+ 的检测（占有量词） */
        int has_nested_quantifier = 0;
        for (const char *p = pattern; *p; p++) {
            if (p[0] == ')') {
                char next = p[1];
                if (next == '+' || next == '*') {
                    has_nested_quantifier = 1;
                    daemon_log_err("Rejected unsafe regex for jail '%s': nested quantifiers detected "
                                   "(pattern like (a+)+ or (a*)* at offset %ld)", j->name, (long)(p - pattern));
                    return -1;
                }
            }
        }
        (void)has_nested_quantifier;

        if (strstr(pattern, "++") || strstr(pattern, "*+")) {
            daemon_log_err("Rejected unsafe regex for jail '%s': possessive quantifiers detected "
                           "(patterns like ++  *+ are not allowed)", j->name);
            return -1;
        }

        /* 拒绝 (? 后直接跟量词的模式: (?+  (?*  (?{  (?? */
        for (const char *p = pattern; *p; p++) {
            if (p[0] == '(' && p[1] == '?') {
                char next = p[2];
                if (next == '+' || next == '*' || next == '{' || next == '?') {
                    daemon_log_err("Rejected unsafe regex for jail '%s': invalid quantifier after "
                                   "'(?' at offset %ld", j->name, (long)(p - pattern));
                    return -1;
                }
            }
        }

        /* 拒绝过多的分支选择（a|b|c|... 模式） */
        int pipe_count = 0;
        for (const char *p = pattern; *p; p++) {
            if (*p == '|') pipe_count++;
        }
        if (pipe_count > 50) {
            daemon_log_err("Rejected unsafe regex for jail '%s': too many alternations (%d, max 50)",
                           j->name, pipe_count);
            return -1;
        }
    }

    /* 使用 PCRE2 编译 */
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

    /* 创建匹配数据缓冲区 */
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

/* 获取 jail 日志文件的全局 file_states 索引 */

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

/* 在重新加载配置之前清理所有 jail 资源
 *
 * 注意：failed_table 和 failed_hash_table 共享相同的对象。
 * failed_table 是链表的头节点，而 failed_hash_table
 * 包含指向相同对象的指针以实现 O(1) 查找。
 * 我们遍历 failed_table 来精确释放每个对象一次，然后
 * 将 failed_hash_table 清零（释放后它只包含悬空指针，
 * 但不拥有所有权）。
 * 只要我们始终将同一个对象添加到两个结构中，这就是安全的。
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

/* 在特定配置中查找或创建 jail（用于双缓冲重新加载） */
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

/* 克隆单个 jail（深拷贝，不包含运行时状态） */
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

    /* 不克隆已编译的正则表达式 - 将重新编译 */
    memset(&dst->compiled_regex, 0, sizeof(dst->compiled_regex));
    dst->regex_compiled = 0;

    /* 不克隆运行时状态 */
    dst->failed_table = NULL;
    memset(dst->failed_hash_table, 0, sizeof(dst->failed_hash_table));
    dst->failed_hash = NULL;
    dst->partial_line_len = 0;
    dst->partial_line_buffer[0] = '\0';

    return 0;
}

/* 克隆整个配置（不包含运行时状态） */
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

/* 验证配置完整性 */
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

/* 将失败记录从旧配置迁移到新配置 */
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

/* 释放不含运行时状态的配置（已迁移） */
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

        /* failed_hash 已迁移，跳过 */
    }

    if (cfg->config_file) free(cfg->config_file);
    if (cfg->config_dir) free(cfg->config_dir);
    if (cfg->permanent_db_path) free(cfg->permanent_db_path);
}

/* qsort 的比较函数 - 对配置文件名排序 */
int compare_config_files(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* 初始化所有 jail 的预编译正则表达式模式 */
int init_log_patterns(void)
{
    int ret = 0;

    /* 为每个有模式的 jail 编译正则表达式 */
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
                /* 继续为其他 jail 编译 */
            } else {
                daemon_log_info("Compiled regex for jail '%s'", jail->name);
            }
        } else {
            /* Jail 将使用内置默认模式 */
            daemon_log_info("Jail '%s' will use built-in default regex pattern", jail->name);
        }
    }

    if (ret == 0) {
        daemon_log_info("All jail regex patterns compiled successfully");
    }

    return ret;
}


/* 释放预编译正则表达式模式 - 由于正则表达式按 jail 管理，不再需要 */
void free_log_patterns(void)
{
    /* 正则表达式现在按 jail 管理，因此没有全局模式需要释放 */
}