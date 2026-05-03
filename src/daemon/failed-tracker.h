/*
 * failed-tracker.h - Header for failed attempt tracking functions
 */

#ifndef FAILED_TRACKER_H
#define FAILED_TRACKER_H

#include "firewall-daemon.h"

/* Find failed entry by IP in a specific jail */
struct failed_entry *find_entry_for_jail(struct jail *j, const char *ip);

/* Create new failed entry in a specific jail */
struct failed_entry *create_entry_for_jail(struct jail *j, const char *ip);

/* Remove failed entry (per-jail) */
void remove_entry_for_jail(struct jail *j, const char *ip);

/* Count recent failures within time window */
unsigned int count_recent(struct failed_entry *entry, time_t window, unsigned int max_retries);

/* Process failed timestamps - Add timestamp and manage buffer overflow */
void process_failed_timestamps(struct failed_entry *entry, time_t now, time_t findtime);

/* Check threshold and ban if exceeded */
void check_and_ban(struct failed_entry *entry, const char *ip,
                   unsigned int max_retries, unsigned int findtime,
                   const char *jail_name);

/* Handle a failed login attempt - jail-aware version */
void handle_failed_attempt_for_jail(struct jail *j, const char *ip,
                                   unsigned int max_retries, unsigned int findtime);

/* Handle a failed login attempt - global version (backward compatible) */
void handle_failed_attempt(const char *ip, unsigned int max_retries, unsigned int findtime);

/* Find failed entry by IP - searches all jails (legacy function) */
struct failed_entry *find_entry(const char *ip);

/* Create new failed entry - creates in first jail (legacy function) */
struct failed_entry *create_entry(const char *ip);

/* Remove failed entry - searches all jails (legacy function) */
void remove_entry(const char *ip);

#endif /* FAILED_TRACKER_H */