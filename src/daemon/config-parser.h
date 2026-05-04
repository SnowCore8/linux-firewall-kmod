/*
 * config-parser.h - 配置解析函数头文件
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "firewall-daemon.h"

/* 使用 libyaml 解析配置文件 - 支持基于 jail 的 YAML 格式 */
int parse_config_file(const char *config_path);

/* 从配置目录加载所有 .yaml/.yml 文件 */
int load_config_directory(const char *config_dir);

/* 解析命令行参数 */
int parse_config(int argc, char *argv[]);

/* 设置信号处理函数 */
void setup_signals(void);

/* 验证并规范化日志文件路径以确保安全 */
int validate_and_normalize_path(const char *input_path);

#endif /* CONFIG_PARSER_H */