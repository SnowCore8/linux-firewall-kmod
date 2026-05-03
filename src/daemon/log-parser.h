/*
 * log-parser.h - Header for log parsing and IP extraction functions
 */

#ifndef LOG_PARSER_H
#define LOG_PARSER_H

#include "firewall-daemon.h"

/* Extract IPv4 address from log line (fallback for non-regex mode) */
int extract_ipv4(const char *line, char *ip_out, size_t ip_size);

/* Extract IP address from log line (IPv4 only) */
int extract_ip(const char *line, char *ip_out, size_t ip_size);

/* Helper function to extract and validate IP from a log line */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out, size_t ip_size);

/* Parse log line and extract IP if it's a failed login - uses jail's PCRE2 regex */
int parse_log_line(struct jail *j, const char *line, char *ip_out, size_t ip_size);

#endif /* LOG_PARSER_H */