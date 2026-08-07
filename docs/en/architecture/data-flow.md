# Data Flow

This document describes the packet flow and event flow in the Linux Firewall Kernel Module.

## Packet Processing Flow

### Inbound Packet Flow

```mermaid
graph TB
    A[Network Interface] --> B[NIC Driver]
    B --> C[IP Layer Input]
    C --> D[Netfilter: PREROUTING Hook]
    D --> E{In Whitelist?}
    E -->|Yes| F[ACCEPT]
    E -->|No| G{In Ban Table?}
    G -->|Yes| H[DROP]
    G -->|No| I[ACCEPT]
```

### Ban Decision Tree

```mermaid
graph TB
    A["Packet (src_ip, dst_port, protocol)"] --> B{src_ip in whitelist?}
    B -->|Yes| C[ACCEPT]
    B -->|No| D{"(ip,port,proto) in ban table?"}
    D -->|Yes| E[DROP]
    D -->|No| F[ACCEPT]
```

## Ban Event Flow

### Complete Ban Flow

```mermaid
graph TB
    A[Log File] -->|inotify notification| B[Daemon reads new lines]
    B -->|regex match| C{Regex match successful?}
    C -->|No| D[Ignore]
    C -->|Yes| E[Extract IP]
    E --> F[Update Counter]
    F --> G{count >= max?}
    G -->|No| H[Ignore]
    G -->|Yes| I{IP in whitelist?}
    I -->|Yes| J[Ignore ban]
    I -->|No| K[Send netlink BAN command]
    K --> L[Kernel adds to hash table]
    L --> M[Kernel returns response/statistics]
    M --> N[Daemon updates Prometheus metrics]
    N --> O[Ban Active]
```

## Unban Event Flow

### Automatic Unban

```mermaid
graph TB
    A["ban_entry.expire_timer fires"] --> B["ban_entry_expire_callback"]
    B --> C{"Unlinked / renewed?"}
    C -->|Unlinked| D["Return"]
    C -->|Renewed| E["Re-arm mod_timer"]
    C -->|Expire| F["Remove from hash / active_bans_list"]
    F --> G["netlink BanStateChange expired"]
    G --> H["Daemon updates cache and metrics"]
```

### Manual Unban

```mermaid
graph TB
    A["echo unban ip via ProcFS<br/>or daemon netlink UnbanIp"] --> B["timer_delete + unlink under bucket lock"]
    B --> C["call_rcu free"]
    C --> D["netlink / metrics update"]
```

## Inter-Component Communication

### Userspace -> Kernel

| Method | Interface | Purpose |
|--------|-----------|---------|
| netlink | Kernel-module protocol | Daemon bans, unbans, whitelist changes, and configuration |
| ProcFS write | `/proc/firewall/bans` | Manual user ban / unban (`unban <ip>`) |
| ProcFS write | `/proc/firewall/whitelist` | Manual user whitelist changes |

> `/proc/firewall/config` and `/proc/firewall/stats` are read-only.
> The module does not provide a "clear all" command — unban one by one
> or reload the module. Daemon-to-kernel traffic uses netlink; ProcFS
> remains available for users and compatibility.

### Kernel -> Userspace

| Method | Interface | Purpose |
|--------|-----------|---------|
| netlink | Kernel-module protocol | Command responses, statistics, state snapshots, and DDoS events |
| ProcFS read | `/proc/firewall/config` | Get ban_time, current ban/whitelist counts |
| ProcFS read | `/proc/firewall/bans` | Get banned IP list |
| ProcFS read | `/proc/firewall/whitelist` | Get whitelist |
| ProcFS read | `/proc/firewall/stats` | Get counters |

### Internal Communication

| Component | Communication | Data |
|-----------|---------------|------|
| Daemon -> HTTP clients | HTTP (axum) | Web UI, JSON API, SSE, health checks, and Prometheus metrics |
| Daemon -> Log | File I/O | Operation logs |

## Sequence Diagrams

### Ban Sequence

```mermaid
sequenceDiagram
    participant L as LogFile
    participant D as Daemon
    participant K as Kernel
    participant P as Prometheus

    L->>D: IN_MODIFY
    D->>L: read line
    L-->>D: new line
    D->>D: regex match
    D->>D: count+1
    D->>D: check thresh
    D->>K: netlink BAN 1.2.3.4
    K->>K: add ban
    K-->>D: netlink response/statistics
    D->>P: update metrics
```

### Packet Processing Sequence

```mermaid
sequenceDiagram
    participant N as Network
    participant K as Kernel
    participant W as Whitelist
    participant H as Hash Table

    N->>K: packet
    K->>W: check whitelist
    W-->>K: not whitelisted
    K->>H: lookup hash
    H-->>K: not found
    K-->>N: NF_ACCEPT
    N->>K: packet
    K->>H: lookup hash
    H-->>K: found
    K-->>N: NF_DROP
```

## Performance Characteristics

### Packet Processing Latency

| Scenario | Latency |
|----------|---------|
| Whitelist match | ~50ns |
| Hash lookup (miss) | ~100ns |
| Hash lookup (hit) | ~100ns |
| Total (normal traffic) | ~150ns |

### Throughput

| Configuration | Performance |
|---------------|-------------|
| Empty table | Line rate (10Gbps+) |
| Full table (4096) | Line rate (10Gbps+) |
| Whitelist (64) | Line rate (10Gbps+) |

### Bottleneck Analysis

| Component | Bottleneck | Optimization |
|-----------|------------|--------------|
| Netfilter Hook | None | RCU read, zero lock contention |
| Hash lookup | Hash collisions | jhash uniform distribution |
| Whitelist lookup | Linear scan | Small capacity (64), negligible impact |
