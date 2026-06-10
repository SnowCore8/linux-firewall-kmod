# Userspace Daemon

This document describes the design and implementation of the userspace daemon `fwctl`.

## Overview

The daemon `fwctl` runs in userspace and is responsible for:

- Monitoring log file changes
- Matching ban patterns using PCRE2 regex
- Counting failures and triggering bans
- Managing ban persistence
- Exposing Prometheus metrics

## Technology Stack

| Component | Purpose |
|-----------|---------|
| C Language | Primary programming language |
| libyaml | YAML configuration parsing |
| libpcre2 | Regular expression compilation and matching |
| libsqlite3 | Ban record persistent storage |
| libmicrohttpd | Prometheus HTTP metrics server |
| inotify | Linux file change monitoring |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    fwctl Daemon                       │
│                                                      │
│  ┌─────────────────────────────────────────────┐    │
│  │               Main Loop (epoll)              │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  │    │
│  │  │ inotify  │  │  Timer   │  │  Signal  │  │    │
│  │  │  Events  │  │  Events  │  │  Events  │  │    │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  │    │
│  │       │              │              │        │    │
│  └───────┼──────────────┼──────────────┼────────┘    │
│          │              │              │             │
│  ┌───────▼──────────────┴──────────────┴────────┐   │
│  │                Event Handler                  │   │
│  │  ┌─────────────┐  ┌───────────────────────┐  │   │
│  │  │  Log Read   │  │  Scheduled Tasks       │  │   │
│  │  │  & PCRE2    │  │  - Expired cleanup     │  │   │
│  │  │  Match      │  │  - Persistence sync    │  │   │
│  │  └──────┬──────┘  └───────────────────────┘  │   │
│  │         │                                     │   │
│  └─────────┼─────────────────────────────────────┘   │
│            │                                          │
│  ┌─────────▼─────────────────────────────────────┐  │
│  │              Jail Manager                       │  │
│  │  ┌───────────┐  ┌───────────┐  ┌──────────┐  │  │
│  │  │ Failure   │  │ Ban       │  │ Whitelist│  │  │
│  │  │ Counters  │  │ Trigger   │  │ Manager  │  │  │
│  │  └───────────┘  └───────────┘  └──────────┘  │  │
│  └────────────────────┬──────────────────────────┘  │
│                       │                              │
│  ┌────────────────────┼──────────────────────────┐  │
│  │              Output Interfaces                 │  │
│  │  ┌──────────┐  ┌──────────┐  ┌────────────┐  │  │
│  │  │  ProcFS  │  │  SQLite  │  │ Prometheus │  │  │
│  │  │ (Kernel) │  │ (Persist)│  │  (:9119)   │  │  │
│  │  └──────────┘  └──────────┘  └────────────┘  │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Startup Flow

```
main()
    │
    ├── Parse command-line arguments
    │
    ├── Read YAML configuration
    │
    ├── Initialize logging
    │
    ├── Initialize SQLite database
    │   └── Restore unexpired ban records
    │
    ├── Compile PCRE2 regexes
    │   └── Compile regex for each jail
    │
    ├── Register inotify watches
    │   └── Add watch for each jail's log_path
    │
    ├── Start Prometheus HTTP server (:9119)
    │
    ├── Restore bans to kernel
    │   └── Write to kernel module via ProcFS
    │
    └── Enter epoll main loop
```

## Log Monitoring

### inotify Events

```c
int fd = inotify_init();
inotify_add_watch(fd, "/var/log/auth.log", IN_MODIFY);
```

| Event | Description |
|-------|-------------|
| `IN_MODIFY` | File was modified (new log written) |
| `IN_CLOSE_WRITE` | File was closed after writing |
| `IN_MOVED_TO` | File was moved in (log rotation) |

### Log Rotation Handling

The daemon detects log rotation and re-registers inotify watches:

```c
if (event->mask & IN_IGNORED) {
    // Log file was rotated, re-watch
    inotify_add_watch(fd, log_path, IN_MODIFY);
}
```

## PCRE2 Regex Matching

### Regex Compilation

```c
pcre2_code *re = pcre2_compile(
    (PCRE2_SPTR)pattern,
    PCRE2_ZERO_TERMINATED,
    PCRE2_UTF | PCRE2_NO_UTF_CHECK,
    &error_code,
    &error_offset,
    NULL
);
```

### `<HOST>` Expansion

The `<HOST>` placeholder in configuration is replaced with an IP matching regex:

```c
#define HOST_PATTERN \
    "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}" \
    "(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

// Replace <HOST> with HOST_PATTERN
char *expanded = replace_all(regex, "<HOST>", HOST_PATTERN);
```

### Matching Flow

```
New Log Line
    │
    ▼
┌──────────────┐
│ PCRE2 Match  │
└──────┬───────┘
       │
       ├── Match Success
       │      │
       │      ▼
       │  Extract IP Address
       │      │
       │      ▼
       │  Update Counter
       │      │
       │      ▼
       │  Check Threshold ──► Reached ──► Trigger Ban
       │
       └── No Match
              │
              ▼
           Ignore Line
```

## Jail Manager

### Failure Counters

Each jail maintains an `(ip, count)` mapping:

```c
struct failure_counter {
    uint32_t ip;              // IP address
    uint32_t count;           // Current count
    time_t first_seen;        // First appearance time
    time_t last_seen;         // Last appearance time
};
```

### Ban Trigger

```
Counter Updated
    │
    ▼
Check: count >= max_retries?
    │
    ├── Yes ──► Check if within find_time window
    │              │
    │              ├── Yes ──► Trigger Ban
    │              │            │
    │              │            ├── Write to kernel (ProcFS)
    │              │            ├── Record to SQLite
    │              │            └── Update metrics
    │              │
    │              └── No ──► Reset counter
    │
    └── No ──► Continue monitoring
```

### find_time Window

```
find_time = 600s

t=0          t=300        t=600        t=900
│            │            │            │
├──── window ─────────────┤
             ├──────────── window ─────┤

Fail 1 ───► Fail 2 ───► Fail 3 ──► Fail 1 expires
```

## SQLite Persistence

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    jail TEXT NOT NULL,
    ban_time INTEGER NOT NULL,
    expire_time INTEGER NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
CREATE INDEX IF NOT EXISTS idx_bans_expire ON bans(expire_time);
```

### Operations

| Operation | Description |
|-----------|-------------|
| Startup restore | Read records where `expire_time > now` |
| Ban record | INSERT new record |
| Unban record | DELETE expired record |
| Periodic sync | Clean expired records every 60 seconds |

## Prometheus Metrics

### Endpoint

```
http://<host>:9119/metrics
```

### Available Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `fw_fire_banned_ips_total` | gauge | Current number of banned IPs |
| `fw_fire_ban_events_total` | counter | Total ban events since startup |
| `fw_fire_unban_events_total` | counter | Total unban events since startup |
| `fw_fire_packets_dropped_total` | counter | Total packets dropped |
| `fw_fire_packets_passed_total` | counter | Total packets passed |
| `fw_fire_jail_failures_total{jail="sshd"}` | counter | Failures per jail |
| `fw_fire_whitelist_entries_total` | gauge | Whitelist entry count |
| `fw_fire_hash_table_usage` | gauge | Hash table usage (0-1) |

### Example Output

```
# HELP fw_fire_banned_ips_total Current number of banned IPs
# TYPE fw_fire_banned_ips_total gauge
fw_fire_banned_ips_total 15

# HELP fw_fire_ban_events_total Total ban events since startup
# TYPE fw_fire_ban_events_total counter
fw_fire_ban_events_total 125

# HELP fw_fire_packets_dropped_total Total packets dropped by the firewall
# TYPE fw_fire_packets_dropped_total counter
fw_fire_packets_dropped_total 45230
```

## Signal Handling

| Signal | Behavior |
|--------|----------|
| `SIGTERM` | Graceful exit, save state |
| `SIGINT` | Graceful exit, save state |
| `SIGHUP` | Reload configuration |
| `SIGUSR1` | Output current status to log |

## Configuration Hot-Reload

Triggered by `SIGHUP` signal:

```
Received SIGHUP
    │
    ▼
Re-read YAML config
    │
    ▼
Compare old and new config
    │
    ├── New jail ──► Initialize and register inotify
    │
    ├── Removed jail ──► Remove inotify watch
    │
    ├── Modified regex ──► Recompile PCRE2
    │
    └── Modified whitelist ──► Update kernel whitelist
```