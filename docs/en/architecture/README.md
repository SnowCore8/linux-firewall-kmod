# Architecture

This section describes the overall architecture and core components of the Linux Firewall Kernel Module.

## Overall Architecture

The system consists of two main components:

```
┌──────────────────────────────────────────────────────┐
│                    Userspace                           │
│  ┌────────────────────────────────────────────────┐  │
│  │              firewall-daemon Daemon                       │  │
│  │  ┌─────────┐  ┌──────────┐  ┌──────────────┐  │  │
│  │  │ inotify │  │  PCRE2   │  │ SQLite/HTTP  │  │  │
│  │  │ Monitor │  │  Regex   │  │ Persist/Metrics│ │  │
│  │  └────┬────┘  └────┬─────┘  └──────┬───────┘  │  │
│  │       │             │               │          │  │
│  │       └─────────────┼───────────────┘          │  │
│  │                     ▼                          │  │
│  │              Config Dispatch (ProcFS)           │  │
│  └────────────────────┬───────────────────────────┘  │
└───────────────────────┼──────────────────────────────┘
                        │
┌───────────────────────┼──────────────────────────────┐
│                    Kernel Space │                      │
│  ┌────────────────────┴───────────────────────────┐  │
│  │            Linux Firewall Module               │  │
│  │  ┌────────────────────────────────────────┐   │  │
│  │  │        Netfilter Hook (PREROUTING)     │   │  │
│  │  │         │                              │   │  │
│  │  │    ┌────┴─────┐                        │   │  │
│  │  │    ▼          ▼                        │   │  │
│  │  │  Whitelist   Hash Table                │   │  │
│  │  │  (64)       (4096)                     │   │  │
│  │  │    │          │                        │   │  │
│  │  │    ▼          ▼                        │   │  │
│  │  │  ACCEPT     DROP                        │   │  │
│  │  └────────────────────────────────────────┘   │  │
│  │  ┌────────────────────────────────────────┐   │  │
│  │  │           ProcFS Interface             │   │  │
│  │  │      /proc/firewall/*                   │   │  │
│  │  └────────────────────────────────────────┘   │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

## Core Design Principles

| Principle | Implementation |
|-----------|----------------|
| High Performance | Netfilter Hook direct processing, no iptables rule traversal |
| Low Latency | O(1) hash lookup, RCU lock-free reads |
| High Availability | SQLite persistence, ban state recovery on reboot |
| Security | Whitelist protection, prevents banning critical services |
| Observability | Dual monitoring via ProcFS + Prometheus |

## Key Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Hash Table Capacity | 4096 | Maximum banned IP count |
| Whitelist Capacity | 64 | Maximum whitelist IP count |
| Prometheus Port | 9119 | Metrics exposure port |

## Concurrency Model

```
CPU 0          CPU 1          CPU 2          CPU 3
  │              │              │              │
  ├─ RCU Read ───┤              ├─ RCU Read ───┤
  │              │              │              │
  │              ├─ RCU Write ──┤              │
  │              │              │              │
  ├─ RCU Read ───┤              ├─ RCU Read ───┤
  │              │              │              │
```

- **Read operations**: RCU protected, completely lock-free, multi-CPU parallel
- **Write operations**: RCU synchronized, ensuring consistency
- **Packet processing**: Pure read operations, extremely low latency

## Component Relationships

| Component | Space | Responsibility |
|-----------|-------|----------------|
| Kernel Module | Kernel | Packet filtering, IP ban management |
| Daemon | Userspace | Log monitoring, regex matching, config dispatch |
| ProcFS | Kernel/Userspace | Configuration interface, status queries |
| SQLite | Userspace | Ban record persistence |
| libmicrohttpd | Userspace | Prometheus metrics server |