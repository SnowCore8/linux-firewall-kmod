# Architecture

This section describes the overall architecture and core components of the Linux Firewall Kernel Module.

## Overall Architecture

The system consists of two main components:

```mermaid
graph TB
    subgraph UserSpace["Userspace"]
        subgraph Daemon["firewall-daemon Daemon"]
            Inotify["inotify Monitor"]
            Regex["Regex Engine"]
            ProcFS_Client["Config Dispatch ProcFS"]

            Inotify --> ProcFS_Client
            Regex --> ProcFS_Client
        end
    end

    subgraph KernelSpace["Kernel Space"]
        subgraph Firewall["Linux Firewall Module"]
            Netfilter["Netfilter Hook PREROUTING"]
            Whitelist["Whitelist 64 entries"]
            HashTable["Hash Table 4096 entries"]
            Accept["ACCEPT"]
            Drop["DROP"]
            ProcFS_Server["ProcFS Interface"]
            
            Netfilter --> Whitelist
            Netfilter --> HashTable
            Whitelist --> Accept
            HashTable --> Accept
            HashTable --> Drop
        end
    end

    ProcFS_Client -->|"write"| ProcFS_Server
```

## Core Design Principles

| Principle | Implementation |
|-----------|----------------|
| High Performance | Netfilter Hook direct processing, no iptables rule traversal |
| Low Latency | O(1) hash lookup, RCU lock-free reads |
| High Availability | In-memory cache, bans lost on reboot |
| Security | Whitelist protection, prevents banning critical services |
| Observability | Dual monitoring via ProcFS + Prometheus |

## Key Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Hash Table Capacity | 4096 | Maximum banned IP count |
| Whitelist Capacity | 64 | Maximum whitelist IP count |
| Prometheus Port | 9119 | Metrics exposure port |

## Concurrency Model

```mermaid
sequenceDiagram
    participant CPU0 as CPU 0
    participant CPU1 as CPU 1
    participant CPU2 as CPU 2
    participant CPU3 as CPU 3

    CPU0->>CPU0: RCU Read
    CPU2->>CPU2: RCU Read
    CPU1->>CPU1: RCU Write
    CPU0->>CPU0: RCU Read
    CPU3->>CPU3: RCU Read
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
| Memory Cache | Userspace | Runtime ban tracking |