/*
 * jail-manager.c - jail 管理函数
 */

#include "jail-manager.h"
#include "firewall-daemon.h"

/* 服务名称匹配辅助函数 */

/**
 * is_service_name_match - 检查服务名称是否匹配指定模式
 * @name: 服务名称
 * @patterns: 模式数组（以 NULL 结尾）
 * 返回: 1 表示匹配，0 表示不匹配
 *
 * 匹配规则：
 * 1. 精确匹配（如 "sshd" == "sshd"）
 * 2. 前缀匹配（如 "sshd-custom" 以 "sshd" 开头）
 * 3. 后缀匹配（如 "custom-sshd" 以 "sshd" 结尾）
 */
static int is_service_name_match(const char *name, const char *const *patterns) {
  for (int i = 0; patterns[i] != NULL; i++) {
    const char *pattern = patterns[i];
    size_t name_len = strlen(name);
    size_t pattern_len = strlen(pattern);

    /* 精确匹配 */
    if (strcmp(name, pattern) == 0)
      return 1;

    /* 前缀匹配：服务名以模式开头，且后面紧跟 - 或结束 */
    if (name_len > pattern_len && strncmp(name, pattern, pattern_len) == 0 &&
        name[pattern_len] == '-')
      return 1;

    /* 后缀匹配：服务名以模式结尾，且前面紧跟 - 或开始 */
    if (name_len > pattern_len && strcmp(name + name_len - pattern_len, pattern) == 0 &&
        name[name_len - pattern_len - 1] == '-')
      return 1;

    /* 包含匹配：模式作为独立词出现在服务名中（前后都是 -） */
    {
      const char *pos = strstr(name, pattern);
      if (pos) {
        int at_start = (pos == name);
        int at_end = (pos + pattern_len == name + name_len);
        int char_before_ok = at_start || (pos[-1] == '-');
        int char_after_ok = at_end || (pos[pattern_len] == '-');

        if (char_before_ok && char_after_ok)
          return 1;
      }
    }
  }
  return 0;
}

/* 服务名称模式定义 */
static const char *const ssh_patterns[] = { "ssh", "sshd", NULL };
static const char *const web_patterns[] = { "nginx", "apache", "http", NULL };
static const char *const ftp_patterns[] = { "ftp", "vsftpd", "proftpd", NULL };
static const char *const mail_patterns[] = { "postfix", "dovecot", "mail", NULL };
static const char *const frp_patterns[] = { "frp", NULL };
static const char *const db_patterns[] = { "mysql", "mariadb", "postgres", NULL };

/* 根据服务名称应用智能默认参数 */

/**
 * apply_service_defaults - 应用特定服务的默认参数
 * @j: jail结构
 * @name: 服务名称
 * @service_type: 服务类型标识
 * @retries: 推荐的最大重试次数
 * @findtime: 推荐的查找时间（秒）
 * @ban_time: 推荐的封禁时间（秒）
 */
static void apply_service_defaults(struct jail *j, const char *name,
                                   const char *service_type, unsigned int retries,
                                   unsigned int findtime, unsigned int ban_time) {
  if (!j->_max_retries_set)
    j->max_retries = retries;
  if (!j->_findtime_set)
    j->findtime = findtime;
  if (!j->_ban_time_set)
    j->ban_time = ban_time;

  daemon_log_info("Jail '%s': applying %s smart defaults (retries=%u, "
                  "findtime=%u, ban=%u)",
                  name, service_type, j->max_retries, j->findtime, j->ban_time);
}

/* 根据服务名称智能推断推荐参数（仅当用户未显式配置时应用） */
static void apply_smart_defaults_single(struct jail *j, const char *name,
                                        struct config *target_cfg) {
  /* SSH 服务 - 暴力破解防护 */
  if (is_service_name_match(name, ssh_patterns)) {
    apply_service_defaults(j, name, "SSH", 5, 600, 900);
  }
  /* Nginx/Apache 服务 - Web 攻击防护 */
  else if (is_service_name_match(name, web_patterns)) {
    apply_service_defaults(j, name, "WEB", 10, 300, 1800);
  }
  /* FTP 服务 */
  else if (is_service_name_match(name, ftp_patterns)) {
    apply_service_defaults(j, name, "FTP", 5, 600, 1800);
  }
  /* 邮件服务 */
  else if (is_service_name_match(name, mail_patterns)) {
    apply_service_defaults(j, name, "MAIL", 5, 300, 1800);
  }
  /* FRP 服务 */
  else if (is_service_name_match(name, frp_patterns)) {
    apply_service_defaults(j, name, "FRP", 10, 300, 1800);
  }
  /* 数据库服务 */
  else if (is_service_name_match(name, db_patterns)) {
    apply_service_defaults(j, name, "DB", 3, 300, 3600);
  }
  /* 默认使用全局 defaults */
  else {
    if (!j->_max_retries_set)
      j->max_retries = target_cfg->default_max_retries;
    if (!j->_findtime_set)
      j->findtime = target_cfg->default_findtime;
    if (!j->_ban_time_set)
      j->ban_time = target_cfg->default_ban_time;
    daemon_log_info("Jail '%s': using global defaults (retries=%u, findtime=%u, ban=%u)",
                    name, j->max_retries, j->findtime, j->ban_time);
  }
}

/* 为所有未显式配置的 jail 应用智能推断参数 */
void apply_smart_defaults_to_all(struct config *target_cfg) {
  for (int i = 0; i < target_cfg->jail_count; i++) {
    apply_smart_defaults_single(&target_cfg->jails[i], target_cfg->jails[i].name, target_cfg);
  }
}

/* 使用全局配置的默认值初始化 jail */
void init_jail_defaults(struct jail *j) {
  j->enabled = true;
  j->log_count = 0;
  j->regex_count = 0;
  j->regex_compiled = 0;
  memset(j->regexes, 0, sizeof(j->regexes));
  /* 注意：max_retries/findtime/ban_time 将在 apply_smart_defaults 中设置 */
  j->_max_retries_set = false;
  j->_findtime_set = false;
  j->_ban_time_set = false;
  memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));
  j->failed_hash = NULL;
  atomic_store(&j->partial_line_len, 0);
  j->partial_line_buffer[0] = '\0';

  for (int i = 0; i < MAX_LOG_FILES; i++) {
    j->log_files[i] = NULL;
  }
}

/* 释放 jail 正则表达式 - 仅释放编译对象，保留 pattern */
void free_jail_regex(struct jail *j) {
  if (!j)
    return;
  for (int i = 0; i < j->regex_count; i++) {
    if (j->regexes[i].compiled) {
      pcre2_code_free(j->regexes[i].compiled);
      j->regexes[i].compiled = NULL;
    }
    if (j->regexes[i].match_data) {
      pcre2_match_data_free(j->regexes[i].match_data);
      j->regexes[i].match_data = NULL;
    }
  }
  j->regex_compiled = 0;
}

/* 完全释放 jail 正则表达式 - 释放 pattern 和编译对象 */
void free_jail_regex_full(struct jail *j) {
  if (!j)
    return;
  for (int i = 0; i < j->regex_count; i++) {
    free(j->regexes[i].pattern);
    j->regexes[i].pattern = NULL;
    if (j->regexes[i].compiled) {
      pcre2_code_free(j->regexes[i].compiled);
      j->regexes[i].compiled = NULL;
    }
    if (j->regexes[i].match_data) {
      pcre2_match_data_free(j->regexes[i].match_data);
      j->regexes[i].match_data = NULL;
    }
  }
  j->regex_count = 0;
  j->regex_compiled = 0;
}

/* 查找现有 jail 或创建新的 */
struct jail *find_or_create_jail(const char *name) {
  pthread_rwlock_wrlock(&config_rwlock);

  /* 查找现有 jail */
  for (int i = 0; i < cfg.jail_count; i++) {
    if (strcmp(cfg.jails[i].name, name) == 0) {
      struct jail *j = &cfg.jails[i];
      pthread_rwlock_unlock(&config_rwlock);
      return j;
    }
  }

  /* 创建新 jail */
  if (cfg.jail_count >= MAX_JAILS) {
    pthread_rwlock_unlock(&config_rwlock);
    daemon_log_warn("Max jails reached (%d), cannot create jail '%s'", MAX_JAILS, name);
    return NULL;
  }

  struct jail *j = &cfg.jails[cfg.jail_count++];
  init_jail_defaults(j);
  strncpy(j->name, name, sizeof(j->name) - 1);
  j->name[sizeof(j->name) - 1] = '\0';

  pthread_rwlock_unlock(&config_rwlock);
  daemon_log_info("Created new jail: %s", name);
  return j;
}

/* 销毁 jail 并释放其资源 */
void destroy_jail(struct jail *j) {
  if (!j)
    return;

  /* 释放日志文件 */
  for (int i = 0; i < j->log_count; i++) {
    if (j->log_files[i]) {
      free(j->log_files[i]);
      j->log_files[i] = NULL;
    }
  }
  j->log_count = 0;

  /* 释放正则表达式（完全释放，包括 pattern） */
  free_jail_regex_full(j);

  /* 修复 2.3：删除废弃的 failed_table 清理代码（仅使用 khash） */
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

/**
 * validate_regex_safety - 验证正则表达式模式以防止 ReDoS 攻击
 * @j: jail结构
 * @pattern: 正则表达式模式
 * 返回: 0 表示安全，-1 表示不安全
 */
static int validate_regex_safety(struct jail *j, const char *pattern) {
  size_t pattern_len;
  int pipe_count = 0;

  if (!pattern || strlen(pattern) == 0)
    return 0; /* 空模式跳过验证 */

  pattern_len = strlen(pattern);

  /* 拒绝过长的模式 */
  if (pattern_len > 1024) {
    daemon_log_err("Rejected unsafe regex for jail '%s': pattern too long "
                   "(%zu bytes, max 1024)",
                   j->name, pattern_len);
    return -1;
  }

  /* 拒绝嵌套量词模式: )+ 或 )* */
  for (const char *p = pattern; *p; p++) {
    if (p[0] == ')') {
      char next = p[1];
      if (next == '+' || next == '*') {
        daemon_log_err("Rejected unsafe regex for jail '%s': nested "
                       "quantifiers detected "
                       "(pattern like (a+)+ or (a*)* at offset %ld)",
                       j->name, (long)(p - pattern));
        return -1;
      }
    }
  }

  /* 拒绝占有量词: ++ 或 *+ */
  if (strstr(pattern, "++") || strstr(pattern, "*+")) {
    daemon_log_err("Rejected unsafe regex for jail '%s': possessive "
                   "quantifiers detected "
                   "(patterns like ++  *+ are not allowed)",
                   j->name);
    return -1;
  }

  /* 拒绝 (? 后直接跟量词的模式 */
  for (const char *p = pattern; *p; p++) {
    if (p[0] == '(' && p[1] == '?') {
      char next = p[2];
      if (next == '+' || next == '*' || next == '{' || next == '?') {
        daemon_log_err("Rejected unsafe regex for jail '%s': invalid quantifier after "
                       "'(?' at offset %ld",
                       j->name, (long)(p - pattern));
        return -1;
      }
    }
  }

  /* 拒绝过多的分支选择 */
  for (const char *p = pattern; *p; p++) {
    if (*p == '|')
      pipe_count++;
  }
  if (pipe_count > 50) {
    daemon_log_err("Rejected unsafe regex for jail '%s': too many "
                   "alternations (%d, max 50)",
                   j->name, pipe_count);
    return -1;
  }

  /* 拒绝量化的交替组：如 (a|aa)+ 导致指数级回溯 */
  {
    int paren_depth = 0;
    bool has_alternation_in_group = false;
    for (const char *p = pattern; *p; p++) {
      if (*p == '(' && p[1] != '?') {
        paren_depth++;
        has_alternation_in_group = false;
      } else if (*p == ')') {
        if (has_alternation_in_group) {
          /* 检查右括号后是否紧跟量词 */
          char next = p[1];
          if (next == '+' || next == '*' || next == '{' || next == '?') {
            daemon_log_err("Rejected unsafe regex for jail '%s': alternation inside "
                           "quantified group detected (pattern like (a|aa)+ at offset "
                           "%ld)",
                           j->name, (long)(p - pattern));
            return -1;
          }
        }
        paren_depth--;
        if (paren_depth < 0)
          paren_depth = 0;
      } else if (*p == '|' && paren_depth > 0) {
        has_alternation_in_group = true;
      }
    }
  }

  return 0;
}

/**
 * compile_pcre2_pattern - 编译PCRE2正则表达式并创建匹配数据
 * @j: jail结构
 * @pattern: 正则表达式模式
 * @out_re: 输出参数，编译后的正则表达式
 * @out_md: 输出参数，匹配数据
 * 返回: 0 表示成功，-1 表示失败
 */
static int compile_pcre2_pattern(struct jail *j, const char *pattern,
                                 pcre2_code **out_re, pcre2_match_data **out_md) {
  int error_number;
  PCRE2_SIZE error_offset;
  pcre2_code *re;
  pcre2_match_data *md;

  /* 编译正则表达式 */
  re = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                     PCRE2_NO_UTF_CHECK, &error_number, &error_offset, NULL);
  if (!re) {
    PCRE2_UCHAR buffer[256];
    pcre2_get_error_message(error_number, buffer, sizeof(buffer));
    daemon_log_err("Failed to compile regex for jail '%s' at offset %d: %s",
                   j->name, (int)error_offset, buffer);
    return -1;
  }

  /* 创建匹配数据缓冲区 */
  md = pcre2_match_data_create_from_pattern(re, NULL);
  if (!md) {
    daemon_log_err("Failed to create match data for jail '%s'", j->name);
    pcre2_code_free(re);
    return -1;
  }

  *out_re = re;
  *out_md = md;
  return 0;
}

/* 使用 PCRE2 编译 jail 的所有正则表达式 */
int compile_jail_regex(struct jail *j) {
  if (!j)
    return -1;

  /* 如果已编译则释放现有正则表达式的编译对象（保留 pattern） */
  free_jail_regex(j);

  /* 如果没有配置正则表达式，使用内置默认值 */
  if (j->regex_count == 0) {
    const char *default_pattern = "Failed password for (invalid user )?[a-zA-Z0-9_.-]{1,64} from "
                                  "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
    j->regexes[0].name[0] = '\0';
    strncat(j->regexes[0].name, "default", MAX_REGEX_NAME_LEN - 1);
    j->regexes[0].pattern = strdup(default_pattern);
    if (!j->regexes[0].pattern)
      return -1;
    j->regex_count = 1;
  }

  /* 编译所有正则表达式 */
  int compiled_count = 0;
  for (int i = 0; i < j->regex_count; i++) {
    if (!j->regexes[i].pattern || strlen(j->regexes[i].pattern) == 0)
      continue;

    /* 验证正则表达式模式以防止 ReDoS 攻击 */
    if (validate_regex_safety(j, j->regexes[i].pattern) < 0)
      continue;

    pcre2_code *re = NULL;
    pcre2_match_data *md = NULL;

    if (compile_pcre2_pattern(j, j->regexes[i].pattern, &re, &md) < 0)
      continue;

    /* 编译成功，存储到结构体 */
    j->regexes[i].compiled = re;
    j->regexes[i].match_data = md;
    compiled_count++;
    daemon_log_info("Compiled regex '%s' for jail '%s': %s", j->regexes[i].name,
                    j->name, j->regexes[i].pattern);
  }

  j->regex_compiled = (compiled_count > 0) ? 1 : 0;
  daemon_log_info("Compiled %d regex pattern(s) for jail '%s'", compiled_count, j->name);
  return (compiled_count > 0) ? 0 : -1;
}

/* 获取 jail 日志文件的全局 file_states 索引 */

int get_global_file_state_index(int jail_idx, int file_idx) {
  pthread_rwlock_rdlock(&config_rwlock);

  if (jail_idx < 0 || jail_idx >= cfg.jail_count) {
    pthread_rwlock_unlock(&config_rwlock);
    daemon_log_err("Invalid jail index: %d", jail_idx);
    return -1;
  }
  if (file_idx < 0 || file_idx >= cfg.jails[jail_idx].log_count) {
    pthread_rwlock_unlock(&config_rwlock);
    daemon_log_err("Invalid file index for jail %d: %d", jail_idx, file_idx);
    return -1;
  }

  int global_idx = 0;
  for (int j = 0; j < jail_idx; j++) {
    global_idx += cfg.jails[j].log_count;
  }
  global_idx += file_idx;

  pthread_rwlock_unlock(&config_rwlock);

  if (global_idx >= MAX_JAILS * MAX_LOG_FILES) {
    daemon_log_err("Global file index out of bounds: %d", global_idx);
    return -1;
  }

  return global_idx;
}

/* 在重新加载配置之前清理所有 jail 资源 */
void cleanup_all_jails(void) {
  pthread_rwlock_wrlock(&config_rwlock);
  int old_count = cfg.jail_count;
  for (int i = 0; i < old_count; i++) {
    destroy_jail(&cfg.jails[i]);
    memset(&cfg.jails[i], 0, sizeof(struct jail));
  }
  cfg.jail_count = 0;
  pthread_rwlock_unlock(&config_rwlock);
  daemon_log_info("All jails resources cleaned up");
}

/* 在特定配置中查找或创建 jail（用于双缓冲重新加载） */
struct jail *find_or_create_jail_in_cfg(const char *name, struct config *target_cfg) {
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
  j->regex_count = 0;
  j->regex_compiled = 0;
  memset(j->regexes, 0, sizeof(j->regexes));
  /* 注意：max_retries/findtime/ban_time 保持为 0，等待
   * apply_smart_defaults_to_all() 设置 */
  j->max_retries = 0;
  j->findtime = 0;
  j->ban_time = 0;
  j->_max_retries_set = false;
  j->_findtime_set = false;
  j->_ban_time_set = false;
  memset(j->failed_hash_table, 0, sizeof(j->failed_hash_table));
  j->failed_hash = NULL;
  atomic_store(&j->partial_line_len, 0);
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
int clone_jail(struct jail *dst, const struct jail *src) {
  memcpy(dst, src, sizeof(*dst));

  /* 清零指针以防止 memcpy 后残留源指针导致 double-free */
  dst->regex_count = 0;
  dst->regex_compiled = 0;
  for (int i = 0; i < src->regex_count; i++) {
    dst->regexes[i].pattern = NULL;
    dst->regexes[i].compiled = NULL;
    dst->regexes[i].match_data = NULL;
  }
  dst->failed_hash = NULL;

  dst->log_count = 0;
  for (int i = 0; i < MAX_LOG_FILES; i++) {
    dst->log_files[i] = NULL;
  }
  for (int i = 0; i < src->log_count; i++) {
    if (src->log_files[i]) {
      dst->log_files[i] = strdup(src->log_files[i]);
      if (!dst->log_files[i]) {
        for (int j = 0; j < dst->log_count; j++) {
          free(dst->log_files[j]);
        }
        dst->log_count = 0; /* 清零防止 config_clone 失败路径 double-free */
        return -1;
      }
      dst->log_count++;
    }
  }

  /* 克隆正则表达式字符串 */
  for (int i = 0; i < src->regex_count; i++) {
    if (src->regexes[i].pattern) {
      dst->regexes[i].pattern = strdup(src->regexes[i].pattern);
      if (!dst->regexes[i].pattern) {
        for (int j = 0; j < dst->log_count; j++) {
          free(dst->log_files[j]);
          dst->log_files[j] = NULL;
        }
        for (int j = 0; j < i; j++) {
          free(dst->regexes[j].pattern);
        }
        dst->log_count = 0;
        dst->regex_count = 0;
        return -1;
      }
      strncpy(dst->regexes[i].name, src->regexes[i].name, MAX_REGEX_NAME_LEN - 1);
      dst->regexes[i].name[MAX_REGEX_NAME_LEN - 1] = '\0';
      dst->regex_count++;
    }
  }

  /* 不克隆已编译的正则表达式 - 将重新编译（已在函数开头清零） */

  /* M6 修复：不克隆运行时状态，确保新 jail 的 failed_hash_table 和
   * failed_hash 被正确清零，防止克隆后的 jail 误用源 jail 的运行时状态 */
  memset(dst->failed_hash_table, 0, sizeof(dst->failed_hash_table));
  dst->failed_hash = NULL; /* 已在函数开头设置，此处显式注释说明 */
  atomic_store(&dst->partial_line_len, 0);
  dst->partial_line_buffer[0] = '\0';

  return 0;
}

/* 克隆整个配置（不包含运行时状态） */
struct config *config_clone(const struct config *src) {
  struct config *dst = calloc(1, sizeof(*dst));
  if (!dst)
    return NULL;

  dst->default_max_retries = src->default_max_retries;
  dst->default_findtime = src->default_findtime;
  dst->default_ban_time = src->default_ban_time;
  dst->daemon = src->daemon;
  dst->interval = src->interval;
  dst->metrics_port = src->metrics_port;
  dst->permanent_ban_enabled = src->permanent_ban_enabled;

  if (src->config_file) {
    dst->config_file = strdup(src->config_file);
    if (!dst->config_file)
      goto fail;
  }
  if (src->config_dir) {
    dst->config_dir = strdup(src->config_dir);
    if (!dst->config_dir)
      goto fail;
  }
  if (src->permanent_db_path) {
    dst->permanent_db_path = strdup(src->permanent_db_path);
    if (!dst->permanent_db_path)
      goto fail;
  }
  if (src->metrics_username) {
    dst->metrics_username = strdup(src->metrics_username);
    if (!dst->metrics_username)
      goto fail;
  }
  if (src->metrics_password) {
    dst->metrics_password = strdup(src->metrics_password);
    if (!dst->metrics_password)
      goto fail;
  }
  if (src->metrics_bind_address) {
    dst->metrics_bind_address = strdup(src->metrics_bind_address);
    if (!dst->metrics_bind_address)
      goto fail;
  }

  dst->jail_count = 0;
  for (int i = 0; i < src->jail_count; i++) {
    if (clone_jail(&dst->jails[i], &src->jails[i]) < 0) {
      goto fail;
    }
    dst->jail_count++; /* 克隆成功才递增 */
  }

  return dst;

fail:
  if (dst->config_file)
    free(dst->config_file);
  if (dst->config_dir)
    free(dst->config_dir);
  if (dst->permanent_db_path)
    free(dst->permanent_db_path);
  if (dst->metrics_username)
    free(dst->metrics_username);
  if (dst->metrics_password)
    free(dst->metrics_password);
  if (dst->metrics_bind_address)
    free(dst->metrics_bind_address);
  for (int i = 0; i < dst->jail_count; i++) {
    for (int j = 0; j < dst->jails[i].log_count; j++) {
      free(dst->jails[i].log_files[j]);
    }
    for (int j = 0; j < dst->jails[i].regex_count; j++) {
      free(dst->jails[i].regexes[j].pattern);
    }
  }
  free(dst);
  return NULL;
}

/* 验证配置完整性 */
int config_validate(const struct config *cfg) {
  if (!cfg) {
    daemon_log_err("Config validation failed: cfg is NULL");
    return -1;
  }
  if (cfg->jail_count <= 0 || cfg->jail_count > MAX_JAILS) {
    daemon_log_err("Config validation failed: invalid jail_count=%d (must be 1..%d)",
                   cfg->jail_count, MAX_JAILS);
    return -1;
  }
  if (cfg->interval <= 0 || cfg->interval > 60) {
    daemon_log_err("Config validation failed: invalid interval=%d (must be 1..60)",
                   cfg->interval);
    return -1;
  }
  if (cfg->metrics_port < 0 || cfg->metrics_port > 65535) {
    daemon_log_err("Config validation failed: invalid metrics_port=%d (must be 0..65535)",
                   cfg->metrics_port);
    return -1;
  }
  if (cfg->default_max_retries == 0) {
    daemon_log_err("Config validation failed: default_max_retries is 0");
    return -1;
  }
  if (cfg->default_findtime == 0) {
    daemon_log_err("Config validation failed: default_findtime is 0");
    return -1;
  }
  /* ban_time=0 表示永久封禁，config-parser.c 中已允许此值 */
  /* default_ban_time 可以为 0（永久封禁），不做拒绝检查 */

  for (int i = 0; i < cfg->jail_count; i++) {
    const struct jail *j = &cfg->jails[i];
    if (!j->enabled)
      continue;
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
    /* ban_time=0 表示永久封禁，config-parser.c 中已允许此值 */
    if (j->ban_time == 0) {
      daemon_log_debug("Jail '%s' ban_time=0 (permanent ban)", j->name);
    }
  }

  return 0;
}

/* 将失败记录从旧配置迁移到新配置 */
void migrate_failed_entries(struct config *old, struct config *new) {
  for (int i = 0; i < old->jail_count; i++) {
    struct jail *old_jail = &old->jails[i];
    if (!old_jail->failed_hash)
      continue;

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
void free_config_partial(struct config *cfg) {
  if (!cfg)
    return;

  for (int i = 0; i < cfg->jail_count; i++) {
    struct jail *jail = &cfg->jails[i];

    for (int j = 0; j < jail->log_count; j++) {
      free(jail->log_files[j]);
    }

    /* 释放正则表达式 */
    for (int j = 0; j < jail->regex_count; j++) {
      free(jail->regexes[j].pattern);
      jail->regexes[j].pattern = NULL;
      if (jail->regexes[j].compiled) {
        pcre2_code_free(jail->regexes[j].compiled);
        jail->regexes[j].compiled = NULL;
      }
      if (jail->regexes[j].match_data) {
        pcre2_match_data_free(jail->regexes[j].match_data);
        jail->regexes[j].match_data = NULL;
      }
    }
    jail->regex_count = 0;
    jail->regex_compiled = 0;

    /* 防御性清理：如果 failed_hash 未被迁移（如错误路径），释放防止泄漏 */
    if (jail->failed_hash) {
      khint_t k;
      for (k = kh_begin(jail->failed_hash); k != kh_end(jail->failed_hash); ++k) {
        if (kh_exist(jail->failed_hash, k)) {
          free((char *)kh_key(jail->failed_hash, k));
        }
      }
      kh_destroy(ip_map, jail->failed_hash);
      jail->failed_hash = NULL;
    }
  }

  if (cfg->config_file)
    free(cfg->config_file);
  if (cfg->config_dir)
    free(cfg->config_dir);
  if (cfg->permanent_db_path)
    free(cfg->permanent_db_path);
  if (cfg->metrics_bind_address)
    free(cfg->metrics_bind_address);
  if (cfg->metrics_username)
    free(cfg->metrics_username);
  if (cfg->metrics_password)
    free(cfg->metrics_password);
}

/* qsort 的比较函数 - 对配置文件名排序 */
int compare_config_files(const void *a, const void *b) {
  return strcmp(*(const char **)a, *(const char **)b);
}

/* 初始化所有 jail 的预编译正则表达式模式 */
int init_log_patterns(void) {
  int ret = 0;

  /* 为每个有模式的 jail 编译正则表达式 */
  for (int i = 0; i < cfg.jail_count; i++) {
    struct jail *jail = &cfg.jails[i];

    if (!jail->enabled) {
      daemon_log_debug("Skipping disabled jail '%s' for regex compilation", jail->name);
      continue;
    }

    if (jail->regex_count > 0) {
      if (compile_jail_regex(jail) < 0) {
        daemon_log_warn("Failed to compile regex for jail '%s'", jail->name);
        ret = -1;
        /* 继续为其他 jail 编译 */
      } else {
        daemon_log_info("Compiled %d regex pattern(s) for jail '%s'",
                        jail->regex_count, jail->name);
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
void free_log_patterns(void) {
  /* 正则表达式现在按 jail 管理，因此没有全局模式需要释放 */
}