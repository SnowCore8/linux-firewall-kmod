/*
 * log-parser.c - Log parsing and IP extraction functions
 */

#include "firewall-daemon.h"
#include "log-parser.h"

/* Extract IPv4 address from log line (fallback for non-regex mode) */
int extract_ipv4(const char *line, char *ip_out, size_t ip_size)
{
    const char *ptr = line;
    int octets[4];

    /* Search for pattern: digits.digits.digits.digits */
    while (*ptr) {
        if (sscanf(ptr, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
            /* Validate octets */
            if (octets[0] >= 0 && octets[0] <= 255 &&
                octets[1] >= 0 && octets[1] <= 255 &&
                octets[2] >= 0 && octets[2] <= 255 &&
                octets[3] >= 0 && octets[3] <= 255) {

                snprintf(ip_out, ip_size, "%d.%d.%d.%d",
                        octets[0], octets[1], octets[2], octets[3]);
                /* Validate with inet_pton */
                unsigned char buf[4];
                if (inet_pton(AF_INET, ip_out, buf) == 1) {
                    /* Additional validation: reject invalid IPs like 0.0.0.0, 127.x.x.x, multicast, etc. */
                    unsigned int ip_num = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
                    if (ip_num == 0 || ip_num == 0xFFFFFFFF ||
                        octets[0] == 127 ||  // 127.x.x.x
                        (octets[0] >= 224 && octets[0] <= 239)) {  // 224.0.0.0/4 (multicast)
                        /* Skip invalid IPs: advance past the entire IP-like pattern */
                        while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
                        continue;
                    }

                    /* Boundary check: ensure next char is not digit or dot (word boundary) */
                    const char *ip_end = ptr;
                    while (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) ip_end++;
                    if (*ip_end && (isdigit((unsigned char)*ip_end) || *ip_end == '.')) {
                        /* More digits/dots follow - not a complete IP, skip */
                        ptr = ip_end;
                        continue;
                    }

                    return 1;
                }
            }
        }
        /* sscanf didn't match or octets invalid: skip past digits and dots to avoid re-scanning */
        if (isdigit((unsigned char)*ptr) || *ptr == '.') {
            while (*ptr && (isdigit((unsigned char)*ptr) || *ptr == '.')) ptr++;
        } else {
            ptr++;
        }
    }

    return 0;
}

/* Extract IP address from log line (IPv4 only) */
int extract_ip(const char *line, char *ip_out, size_t ip_size)
{
    return extract_ipv4(line, ip_out, ip_size);
}

/* Helper function to extract and validate IP from a log line.
 * Returns 1 if a valid IP was extracted, 0 otherwise.
 * Uses jail's regex for parsing. */
int extract_and_validate_ip(struct jail *j, const char *log_line, char *ip_out, size_t ip_size)
{
    char ip_buf[INET_ADDRSTRLEN];
    struct in_addr addr4;

    if (!parse_log_line(j, log_line, ip_buf, sizeof(ip_buf))) {
        return 0;
    }

    /* Validate IPv4 */
    if (inet_pton(AF_INET, ip_buf, &addr4) == 1) {
        unsigned int ip_num = ntohl(addr4.s_addr);
        /* Reject invalid/reserved IPv4 addresses */
        if (ip_num == 0 ||                                  /* 0.0.0.0 */
            ip_num == 0xFFFFFFFF ||                         /* 255.255.255.255 */
            ((ip_num >> 24) & 0xFF) == 127 ||              /* 127.x.x.x (loopback) */
            (((ip_num >> 24) & 0xFF) >= 224 && ((ip_num >> 24) & 0xFF) <= 239)) { /* multicast */
            return 0;
        }
        atomic_fetch_add(&daemon_stats.ips_extracted, 1);
        size_t copy_len = strlen(ip_buf);
        if (copy_len >= ip_size) copy_len = ip_size - 1;
        memcpy(ip_out, ip_buf, copy_len);
        ip_out[copy_len] = '\0';
        return 1;
    }

    return 0;
}

/* Parse log line and extract IP if it's a failed login - uses jail's PCRE2 regex */
int parse_log_line(struct jail *j, const char *line, char *ip_out, size_t ip_size)
{
    const char *ip_start;
    size_t ip_len;

    /* Length validation to prevent extremely long log lines */
    size_t line_len = strlen(line);
    if (line_len > 8192) {
        daemon_log_warn("Log line too long (%zu bytes), skipping", line_len);
        return 0;
    }

    /* Check for failed login using jail's compiled PCRE2 regex */
    if (j && j->regex_compiled && j->compiled_regex && j->match_data) {
        int regex_result = pcre2_match(j->compiled_regex, (PCRE2_SPTR)line,
                                        (PCRE2_SIZE)line_len, 0, 0,
                                        j->match_data, NULL);
        if (regex_result >= 0) {
            /* Get captured substrings */
            PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(j->match_data);
            int num_groups = regex_result;

            /* Dynamically find the IP capture group - search from last to first */
            int ip_group = -1;
            for (int g = num_groups - 1; g >= 1; g--) {
                if (ovector[g * 2] != PCRE2_UNSET && ovector[g * 2 + 1] > ovector[g * 2]) {
                    /* Validate this capture group contains an IP-like pattern */
                    size_t capture_len = ovector[g * 2 + 1] - ovector[g * 2];
                    if (capture_len >= 7 && capture_len < INET_ADDRSTRLEN) {  /* Min: "1.1.1.1" */
                        /* Quick validation: first char should be digit */
                        const char *capture_start = line + ovector[g * 2];
                        if (capture_start[0] >= '0' && capture_start[0] <= '9') {
                            ip_group = g;
                            break;
                        }
                    }
                }
            }

            if (ip_group < 0) {
                daemon_log_warn("No valid IP capture group found in regex match for jail '%s'", j->name);
                return 0;
            }

            /* Add boundary checks to prevent out-of-bounds reads */
            if ((size_t)ovector[ip_group * 2 + 1] > line_len) {
                daemon_log_warn("Regex match exceeds line length in jail '%s'", j->name);
                return 0;
            }
            ip_start = line + ovector[ip_group * 2];
            ip_len = ovector[ip_group * 2 + 1] - ovector[ip_group * 2];

            if (ip_len >= INET_ADDRSTRLEN || ip_len == 0) {
                daemon_log_warn("Invalid IP length in jail '%s' log: %zu", j->name, ip_len);
                return 0;
            }

            char ip_buf[INET_ADDRSTRLEN];
            memcpy(ip_buf, ip_start, ip_len);
            ip_buf[ip_len] = '\0';
            strncpy(ip_out, ip_buf, ip_size - 1);
            ip_out[ip_size - 1] = '\0';
            return 1;
        } else if (regex_result != PCRE2_ERROR_NOMATCH) {
            PCRE2_UCHAR errbuf[256];
            pcre2_get_error_message(regex_result, errbuf, sizeof(errbuf));
            daemon_log_warn("Regex error in jail '%s' pattern: %s", j->name, errbuf);
        }
    }

    /* Fallback: simple string matching (if regex not compiled) */
    if (!j || !j->regex_compiled) {
        if (strstr(line, "Failed password for") ||
            strstr(line, "authentication failure")) {
            return extract_ip(line, ip_out, ip_size);
        }
    }

    return 0;
}