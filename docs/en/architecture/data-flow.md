# Data Flow

This document describes the packet flow and event flow in the Linux Firewall Kernel Module.

## Packet Processing Flow

### Inbound Packet Flow

```
                    Network Interface
                           │
                           ▼
                   ┌───────────────┐
                   │  NIC Driver    │
                   └───────┬───────┘
                           │
                           ▼
                   ┌───────────────┐
                   │  IP Layer Input│
                   └───────┬───────┘
                           │
                           ▼
               ╔═══════════════════════╗
               ║  Netfilter:           ║
               ║  PREROUTING Hook     ║
               ║  ┌─────────────────┐  ║
               ║  │ firewall_hook()  │  ║
               ║  └────────┬────────┘  ║
               ╚═══════════╪═══════════╝
                           │
                  ┌────────┴────────┐
                  ▼                 ▼
            ┌──────────┐      ┌──────────┐
            │ In        │  Yes  │          │
            │ Whitelist?│──────►│ ACCEPT   │
            └────┬─────┘      └──────────┘
                 │ No
                 ▼
            ┌──────────┐
            │ In Ban    │─── Yes ──► DROP
            │ Table?    │
            └────┬─────┘
                 │ No
                 ▼
            ┌──────────┐
            │ ACCEPT    │
            └──────────┘
```

### Ban Decision Tree

```
Packet (src_ip, dst_port, protocol)
            │
            ▼
    ┌───────────────┐
    │ src_ip in      │
    │ whitelist?     │
    └───┬───────┬───┘
        │ Yes    │ No
        ▼       ▼
    ACCEPT  ┌───────────────┐
            │ (ip,port,proto)│
            │ in ban table?  │
            └───┬───────┬───┘
                │ Yes    │ No
                ▼       ▼
            DROP    ACCEPT
```

## Ban Event Flow

### Complete Ban Flow

```
        Log File
            │
            ▼ inotify notification
    ┌───────────────┐
    │ Daemon reads   │
    │ new lines      │
    └───────┬───────┘
            │
            ▼ PCRE2 match
    ┌───────────────┐
    │ Regex match    │
    │ successful?    │
    └───┬───────┬───┘
        │ No     │ Yes
        │       ▼
        │  ┌───────────────┐
        │  │ Extract IP     │
        │  └───────┬───────┘
        │          │
        │          ▼
        │  ┌───────────────┐
        │  │ Update Counter │
        │  └───────┬───────┘
        │          │
        │          ▼
        │  ┌───────────────┐
        │  │ count >= max? │
        │  └───┬───────┬───┘
        │      │ No     │ Yes
        │      │       ▼
        │      │  ┌───────────────┐
        │      │  │ IP in          │
        │      │  │ whitelist?     │
        │      │  └───┬───────┬───┘
        │      │      │ Yes    │ No
        │      │      │       ▼
        │      │      │  ┌───────────────┐
        │      │      │  │ Write to Kernel│
        │      │      │  │ /proc/.../config│
        │      │      │  └───────┬───────┘
        │      │      │          │
        │      │      │          ▼
        │      │      │  ┌───────────────┐
        │      │      │  │ Kernel adds to │
        │      │      │  │ hash table     │
        │      │      │  └───────┬───────┘
        │      │      │          │
        │      │      │          ▼
        │      │      │  ┌───────────────┐
        │      │      │  │ Record to SQLite│
        │      │      │  └───────┬───────┘
        │      │      │          │
        │      │      │          ▼
        │      │      │  ┌───────────────┐
        │      │      │  │ Update Prometheus│
        │      │      │  │ metrics         │
        │      │      │  └───────────────┘
        │      │      │
        ▼      ▼      ▼
     Ignore Ignore  Ban Active
```

## Unban Event Flow

### Automatic Unban

```
    Kernel Cleanup Thread (30s)
            │
            ▼
    ┌───────────────┐
    │ Iterate Hash   │
    │ Table          │
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ expire_time   │
    │ < current?    │
    └───┬───────┬───┘
        │ No     │ Yes
        │       ▼
        │  ┌───────────────┐
        │  │ Remove from    │
        │  │ hash table     │
        │  └───────┬───────┘
        │          │
        │          ▼
        │  ┌───────────────┐
        │  │ Delete from    │
        │  │ SQLite         │
        │  └───────┬───────┘
        │          │
        │          ▼
        │  ┌───────────────┐
        │  │ Update Metrics │
        │  └───────────────┘
        │
        ▼
      Retain
```

### Manual Unban

```
    echo "unban <ip>" | sudo tee /proc/firewall/bans
            │
            ▼
    ┌───────────────┐
    │ Write to ProcFS│
    │ echo "unban"  │
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ Kernel removes │
    │ from hash table│
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ Delete from    │
    │ SQLite         │
    └───────┬───────┘
            │
            ▼
    ┌───────────────┐
    │ Update Metrics │
    └───────────────┘
```

## Inter-Component Communication

### Userspace → Kernel

| Method | Path | Purpose |
|--------|------|---------|
| ProcFS write | `/proc/firewall/bans` | Ban / unban (`unban <ip>`) |
| ProcFS write | `/proc/firewall/whitelist` | Add / remove whitelist entries |

> `/proc/firewall/config` and `/proc/firewall/stats` are read-only.
> The module does not provide a "clear all" command — unban one by one
> or reload the module.

### Kernel → Userspace

| Method | Path | Purpose |
|--------|------|---------|
| ProcFS read | `/proc/firewall/config` | Get ban_time, current ban/whitelist counts |
| ProcFS read | `/proc/firewall/bans` | Get banned IP list |
| ProcFS read | `/proc/firewall/whitelist` | Get whitelist |
| ProcFS read | `/proc/firewall/stats` | Get counters |

### Internal Communication

| Component | Communication | Data |
|-----------|---------------|------|
| Daemon → SQLite | File I/O | Ban records |
| Daemon → Prometheus | HTTP (libmicrohttpd) | Metrics data |
| Daemon → Log | File I/O | Operation logs |

## Sequence Diagrams

### Ban Sequence

```
LogFile    Daemon          Kernel        SQLite      Prometheus
   │           │              │              │            │
   │──IN_MODIFY─►              │              │            │
   │           │──read line───►│              │            │
   │           │◄──new line─── │              │            │
   │           │                │              │            │
   │           │──PCRE2 match──►│              │            │
   │           │                │              │            │
   │           │──count+1      │              │            │
   │           │──check thresh │              │            │
   │           │                │              │            │
   │           │──ban 1.2.3.4──►│              │            │
   │           │  (ProcFS)     │              │            │
   │           │                │──add ban     │            │
   │           │                │──►INSERT─────►            │
   │           │                │              │            │
   │           │                │              │◄─update metrics
   │           │                │              │            │
   ▼           ▼                ▼              ▼            ▼
```

### Packet Processing Sequence

```
Network       Kernel          Whitelist    Hash Table
   │              │                │            │
   │──packet──────►│                │            │
   │              │──check whitelist─►            │
   │              │◄──not whitelisted│            │
   │              │                │            │
   │              │──lookup hash─────┼───────────►│
   │              │◄────────────────┼──not found──│
   │              │                │            │
   │◄──NF_ACCEPT──│                │            │
   │              │                │            │
   │──packet──────►│                │            │
   │              │──lookup hash─────┼───────────►│
   │              │◄────────────────┼──found──────│
   │              │                │            │
   │◄──NF_DROP────│                │            │
   ▼              ▼                ▼            ▼
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