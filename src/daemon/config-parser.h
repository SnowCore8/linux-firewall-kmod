/*
 * config-parser.h - Header for configuration parsing functions
 */

#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include "firewall-daemon.h"

/* Parse configuration file using libyaml - supports jail-based YAML format */
int parse_config_file(const char *config_path);

/* Load all .yaml/.yml files from a configuration directory */
int load_config_directory(const char *config_dir);

/* Parse command line arguments */
int parse_config(int argc, char *argv[]);

/* Setup signal handlers */
void setup_signals(void);

/* Validate and normalize log file path for security */
int validate_and_normalize_path(const char *input_path);

#endif /* CONFIG_PARSER_H */