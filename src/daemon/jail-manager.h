/*
 * jail-manager.h - jail 管理函数头文件
 */

#ifndef JAIL_MANAGER_H
#define JAIL_MANAGER_H

#include "firewall-daemon.h"

/* 使用全局配置的默认值初始化 jail */
void init_jail_defaults(struct jail *j);

/* 释放 jail 正则表达式 */
void free_jail_regex(struct jail *j);

/* 查找现有 jail 或创建新的 */
struct jail *find_or_create_jail(const char *name);

/* 销毁 jail 并释放其资源 */
void destroy_jail(struct jail *j);

/* 使用 PCRE2 编译 jail 的正则表达式 */
int compile_jail_regex(struct jail *j);

/* 获取 jail 日志文件的全局 file_states 索引 */
int get_global_file_state_index(int jail_idx, int file_idx);

/* 在配置重载前清理所有 jail 资源 */
void cleanup_all_jails(void);

/* 在特定配置中查找或创建 jail（用于双缓冲重载） */
struct jail *find_or_create_jail_in_cfg(const char *name, struct config *target_cfg);

/* 克隆单个 jail（深拷贝，不包含运行时状态） */
int clone_jail(struct jail *dst, const struct jail *src);

/* 克隆整个配置（不包含运行时状态） */
struct config *config_clone(const struct config *src);

/* 验证配置完整性 */
int config_validate(const struct config *cfg);

/* 将失败条目从旧配置迁移到新配置 */
void migrate_failed_entries(struct config *old, struct config *new);

/* 释放配置（不包含已迁移的运行时状态） */
void free_config_partial(struct config *cfg);

/* 比较配置文件名用于排序 */
int compare_config_files(const void *a, const void *b);

/* 为所有 jail 初始化预编译正则表达式模式 */
int init_log_patterns(void);

/* 释放预编译正则表达式模式 */
void free_log_patterns(void);

/* 为所有未显式配置的 jail 应用智能推断参数 */
void apply_smart_defaults_to_all(struct config *target_cfg);

#endif /* JAIL_MANAGER_H */