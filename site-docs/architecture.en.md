# Architecture Design Document

**Version**: v2.0

## 1. Overall Architecture

Firewall adopts a **dual-layer architecture**, moving fail2ban's core functionality from userspace to kernelspace:

```
┌─────────────────────────────────────────────────────────────────┐
│                        Userspace (Daemon)                        │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ inotify     │  │ PCRE2       │  │ Jail        │             │
│  │ File Watch  │→ │ Regex Parse │→ │ Manager     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                                    │                  │
│         ▼                                    ▼                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ Failure     │  │ Ban         │  │ Prometheus  │             │
│  │ Tracking    │→ │ Management  │  │ Metrics     │             │
│  │ (khash)     │  │ (procfs)    │  │ Export      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │ procfs write
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Kernelspace (Module)                      │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Netfilter PRE_ROUTING Hook                   │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │   │
│  │  │ Ban Table   │    │ Whitelist   │    │ Statistics  │  │   │
│  │  │ (1024 cap)  │    │ (64 cap)    │    │             │  │   │
│  │  └─────────────┘    └─────────────┘    └─────────────┘  │   │
│  │              RCU Concurrency + spinlock                  │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ procfs      │  │ Timer       │  │ Net Device  │             │
│  │ Interface   │  │ (Expiry)    │  │ (IP Disc.)  │             │
│  │ (bans/stats)│  │             │  │             │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 2. Data Flow

```
Attacker brute-force
    ↓
System logs (/var/log/auth.log, etc.)
    ↓ inotify event-driven (millisecond-level)
Daemon (userspace)
    ├─ PCRE2 regex log parsing
    ├─ khash O(1) failure tracking
    └─ Threshold reached → /proc/firewall/bans
    ↓ procfs write
Kernel module (kernelspace)
    ├─ Netfilter hook (NF_INET_PRE_ROUTING)
    ├─ RCU lock-free read + spinlock write
    └─ Subsequent packets → NF_DROP (microsecond-level)
```

## 3. Kernel Module Design

### 3.1 File Structure

| File | Lines | Responsibility |
|------|-------|----------------|
| `firewall.c` | ~200 | Module entry, parameter definitions, init/cleanup |
| `firewall.h` | ~225 | Data structures, macros, function declarations |
| `ban-manager.c` | ~375 | Ban/unban management, hash table operations |
| `whitelist.c` | ~180 | Whitelist management, system IP auto-discovery |
| `cleanup.c` | ~150 | Expiry cleanup, timer callbacks |
| `netdev.c` | ~320 | Network device notifier, IP auto-discovery |
| `procfs.c` | ~770 | procfs interface implementation |
| `netfilter.c` | ~150 | Netfilter hook, packet filtering |
| `state-persist.c` | ~445 | State persistence (save/restore) |

### 3.2 Core Data Structures

```c
/* Ban entry */
struct ban_entry {
    __be32 ip;              /* IP address */
    unsigned long ban_time; /* Ban time (jiffies) */
    unsigned long unban_time; /* Unban time (jiffies) */
    bool is_permanent;      /* Whether permanent ban */
    struct hlist_node hash; /* Hash table node */
    struct rcu_head rcu_head; /* RCU release head */
};

/* Whitelist entry */
struct whitelist_entry {
    __be32 ip;              /* Subnet address */
    __be32 mask;            /* Subnet mask */
    char dev_name[IFNAMSIZ]; /* Device name */
    struct hlist_node hash; /* Hash table node */
    struct rcu_head rcu_head; /* RCU release head */
};

/* Firewall global state */
struct firewall_info {
    DECLARE_HASHTABLE(ban_table, BAN_HASH_BITS);     /* Ban hash table */
    DECLARE_HASHTABLE(whitelist_table, WL_HASH_BITS); /* Whitelist hash table */
    spinlock_t lock;          /* Write lock */
    atomic_t ban_count;       /* Current ban count */
    atomic_t total_ban_count; /* Total ban count */
    atomic_t total_unban_count; /* Total unban count */
    struct timer_list cleanup_timer; /* Cleanup timer */
    struct delayed_work sync_work;   /* Sync work */
    struct notifier_block netdev_nb; /* Network device notifier */
};
```

### 3.3 Concurrency Model

```
Read Path (Netfilter Hook)       Write Path (procfs Write)
─────────────────────────        ─────────────────────────
rcu_read_lock()                  spin_lock(&fw->lock)
  hash_for_each_possible_rcu()     hash_add_rcu()
  READ_ONCE(entry->field)          hlist_del_rcu()
rcu_read_unlock()                spin_unlock(&fw->lock)
                                 call_rcu(&entry->rcu_head, free)
```

**Key Design**:
- Read path uses RCU for lock-free high performance
- Write path uses spinlock + RCU-safe deletion
- Field reads/writes use `READ_ONCE`/`WRITE_ONCE` to prevent compiler reordering

### 3.4 Module Parameters

| Parameter | Type | Default | Permission | Description |
|-----------|------|---------|------------|-------------|
| `fw_ban_time` | int | 600 | 0644 | Default ban duration (seconds) |
| `fw_max_bans_per_second` | int | 200 | 0444 | Max bans per second (flood protection) |
| `state_file` | charp | NULL | 0444 | State file path (read-only) |

### 3.5 procfs Interface

The kernel module provides a userspace interaction interface through the `/proc/firewall/` directory, including ban management, whitelist management, runtime configuration, and statistics.

For detailed interface operations, command examples, and limitations, refer to the [Operations Manual → procfs Interface](operations.md#2-procfs-interface).

## 4. Daemon Design

### 4.1 File Structure

| File | Responsibility |
|------|----------------|
| `firewall-daemon.c/h` | Main entry, signal handling, daemonization, CLI parsing |
| `jail-manager.c/h` | Jail lifecycle management: create/destroy/reload |
| `config-parser.c/h` | YAML config parsing: global defaults + jail config |
| `log-parser.c/h` | PCRE2 regex log parsing: JIT compilation, IP extraction |
| `failed-tracker.c/h` | Failure tracking: khash hash table, time window counting |
| `ban-manager.c/h` | Ban management: send ban commands to kernel via procfs |
| `file-monitor.c/h` | inotify log file monitoring: event listening, rotation detection |
| `http-exporter.c` | Prometheus metrics export: HTTP server, metrics collection |
| `sqlite-persistent.c/h` | SQLite permanent ban persistence: table operations, batch inserts |
| `khash.h` | Third-party hash library (header-only) |

### 4.2 Configuration System

**Dual-layer configuration structure**:

```yaml
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  max_retries: 5      # Override default
  findtime: 600       # Override default
  ban_time: 900       # Override default
  regex: ""           # Use built-in pattern
```

**Configuration Loading Process**:
1. Parse `defaults` block → global defaults
2. Parse each jail block → service-specific config
3. Smart inference: auto-match built-in patterns based on jail name
4. Strict validation: unknown params/invalid values → reject (default)
5. Double-buffer reload: SIGHUP → parse to temp structure → atomic swap

### 4.3 Core Component Interaction

```
main()
  ├─ config_parse()          # Load configuration
  ├─ jail_manager_init()     # Initialize jails
  │   ├─ log_parser_compile()  # Compile PCRE2 regex
  │   └─ failed_tracker_init() # Initialize khash table
  ├─ file_monitor_start()    # Start inotify monitoring
  │   └─ monitor_loop()        # Event loop
  │       ├─ process_new_lines() # Process new log lines
  │       │   ├─ log_parser_match() # Regex matching
  │       │   └─ failed_tracker_add() # Record failure
  │       └─ execute_ban_action() # Trigger ban
  ├─ http_exporter_start()   # Start Prometheus export
  └─ sqlite_persistent_init() # Initialize SQLite
```

## 5. Module Dependency Graph

```
firewall.c (entry)
  ├── ban-manager.c
  ├── whitelist.c
  ├── cleanup.c
  ├── netdev.c
  ├── procfs.c
  ├── netfilter.c
  └── state-persist.c

firewall-daemon.c (entry)
  ├── jail-manager.c
  │   ├── config-parser.c
  │   ├── log-parser.c
  │   └── failed-tracker.c
  ├── ban-manager.c
  ├── file-monitor.c
  ├── http-exporter.c
  └── sqlite-persistent.c
```

## 6. Performance Characteristics

| Operation | Complexity | Description |
|-----------|------------|-------------|
| Ban Lookup | O(1) | Hash table lookup |
| Ban Insertion | O(1) | Pre-allocation outside lock + insertion inside lock |
| Whitelist Exact Match | O(1) | Hash lookup /32 entries |
| Whitelist Subnet Match | O(n) | Full table traversal (with iteration limit) |
| Expiry Cleanup | Incremental | Process partial buckets each time, avoid long lock hold |
| Log Parsing | JIT | PCRE2 JIT compilation acceleration |
| Failure Tracking | O(1) | khash hash table |

## 7. Security Design

| Layer | Measures |
|-------|----------|
| Build Security | `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`, `-Wl,-z,relro,-z,now` |
| Input Validation | IP format check, path traversal protection, URL encoding detection |
| Concurrency Safety | RCU + spinlock + READ_ONCE/WRITE_ONCE |
| Memory Safety | Pre-allocation outside lock, call_rcu async release, TOCTOU protection |
| Regex Safety | ReDoS protection (nested quantifier detection, possessive quantifier rejection) |
| Path Safety | Whitelist directory check, realpath verification, `O_NOFOLLOW` |
