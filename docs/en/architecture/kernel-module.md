# Kernel Module

This document describes the implementation details of the Linux Firewall kernel module.

## Module Overview

The kernel module `firewall.ko` is the core of the system, responsible for intercepting and filtering packets at the network stack level.

### Module Information

| Attribute | Value |
|-----------|-------|
| Module Name | `firewall` |
| Source File | `src/kernel-module/firewall-main.c` |
| License | MIT |
| Load Path | `/lib/modules/$(uname -r)/extra/firewall.ko` |

## Netfilter Hook

### Hook Registration Point

The module registers a hook on the `NF_INET_PRE_ROUTING` chain, one of the earliest processing points after packets enter the network stack.

```c
struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook     = nf_hook_func_ipv4,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

struct nf_hook_ops nf_ops_ipv6 __read_mostly = {
    .hook     = nf_hook_func_ipv6,
    .pf       = NFPROTO_IPV6,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};
```

### Hook Function Flow

```mermaid
graph TB
    A[Network Packet Arrives] --> B[nf_hook_func_ipv4 / nf_hook_func_ipv6]
    B --> C{Check Whitelist}
    C -->|Matched| D[NF_ACCEPT]
    C -->|Not Matched| E{Lookup Hash}
    E -->|In Ban Table| F[NF_DROP]
    E -->|Not Banned| G[NF_ACCEPT]
```

### Return Values

| Return Value | Description |
|--------------|-------------|
| `NF_ACCEPT` | Allow packet to pass |
| `NF_DROP` | Drop the packet |

## Hash Table

### Data Structure

The kernel uses a hash table to store banned IP addresses with a capacity of 4096.

```c
#define HASH_TABLE_SIZE 4096

struct banned_ip {
    __be32 ip;                // IPv4 address
    u32 port;                 // Port
    u8 protocol;              // Protocol
    ktime_t ban_time;         // Ban time
    ktime_t expire_time;      // Expiration time
    char jail_name[64];       // Jail name
    struct hlist_node node;   // Hash list node
};
```

### Hash Function

```c
static inline u32 hash_ip(__be32 ip, u32 port)
{
    return jhash_2words((__force u32)ip, port, HASH_SEED) % HASH_TABLE_SIZE;
}
```

### Operation Complexity

| Operation | Complexity | Description |
|-----------|------------|-------------|
| Lookup | O(1) average | Hash lookup |
| Insert | O(1) average | Head insertion |
| Delete | O(1) average | List deletion |

## RCU Concurrency Control

### Read Operations

The packet processing path uses RCU read locks, ensuring multi-CPU concurrency safety without lock contention:

```c
rcu_read_lock();
entry = firewall_lookup(ip, port);
rcu_read_unlock();
```

### Write Operations

Adding/removing bans uses RCU write synchronization:

```c
spin_lock(&hash_lock);
hlist_add_head_rcu(&entry->node, &hash_table[hash]);
spin_unlock(&hash_lock);
synchronize_rcu();
```

### Advantages

| Feature | Description |
|---------|-------------|
| Lock-free reads | Packet processing path has no locks, extremely low latency |
| Multi-CPU | Supports all CPU cores processing in parallel |
| Safe | Guarantees readers see consistent data |

## Whitelist

### Data Structure

The whitelist uses a fixed-size array with a capacity of 64.

```c
#define WHITELIST_SIZE 64

struct whitelist_entry {
    __be32 ip;          // IP address
    __be32 mask;        // Subnet mask
    bool active;        // Whether active
};
```

### Matching Logic

Whitelist check is performed before hash table lookup, ensuring whitelisted IPs are never banned:

```c
if (is_whitelisted(ip)) {
    return NF_ACCEPT;
}
```

### CIDR Support

The whitelist supports CIDR notation, matching via subnet mask:

```c
/* Real implementation in src/kernel-module/whitelist.c */
bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip)
{
    struct whitelist_entry *entry;
    /* Two-stage matching: exact match (O(1) hash bucket) first,
     * then walk CIDR subnets. */
    ...
}
```

## Auto-Expiry Cleanup

### Cleanup Thread

The kernel module uses a timer to periodically clean up expired ban
entries (see `src/kernel-module/cleanup.c`):

```c
/* Real implementation in src/kernel-module/cleanup.c */
void cleanup_timer_callback(struct timer_list *t)
{
    struct firewall_info *fw = container_of(t, struct firewall_info, cleanup_timer);
    cleanup_expired_bans(fw);  /* remove expired bans */
    /* Reschedule next cleanup */
    mod_timer(&fw->cleanup_timer, jiffies + CLEANUP_INTERVAL);
}
```

### Cleanup Strategy

| Parameter | Default | Description |
|-----------|---------|-------------|
| Cleanup interval | 30 seconds | Frequency to check expired entries |
| Batch processing | 100 entries | Maximum entries processed per cycle |

### Cleanup Flow

```mermaid
graph TB
    A[Cleanup Thread Wakes] --> B[Iterate Hash Table]
    B --> C{Check expire_time < now}
    C -->|Yes| D[Remove Entry]
    D --> E[Notify Userspace]
    C -->|No| F[Continue]
```

## ProcFS Interface

### Registration

```c
static int __init firewall_proc_init(void)
{
    proc_create("firewall/bans", 0200, NULL, &bans_fops);
    proc_create("firewall/whitelist", 0200, NULL, &whitelist_fops);
    proc_create("firewall/config", 0444, NULL, &config_fops);
    proc_create("firewall/stats", 0444, NULL, &stats_fops);
    return 0;
}
```

### File Operations

| File | Permission | Operation |
|------|------------|-----------|
| `bans` | 0200 | Write-only, ban/unban IP addresses |
| `whitelist` | 0200 | Write-only, add/remove whitelist entries |
| `config` | 0444 | Read-only, returns current configuration |
| `stats` | 0444 | Read-only, returns statistics |

## Module Lifecycle

### Initialization

```mermaid
graph TB
    A[module_init] --> B[Register Netfilter Hook]
    A --> C[Initialize hash table]
    A --> D[Initialize whitelist]
    A --> E[Create ProcFS interface]
    A --> F[Start cleanup thread]
```

### Exit

```mermaid
graph TB
    A[module_exit] --> B[Stop cleanup thread]
    A --> C[Remove ProcFS interface]
    A --> D[Unregister Netfilter Hook]
    A --> E[Free hash table memory]
    A --> F[Free whitelist memory]
```

## Kernel Logging

Uses `pr_*` macros for logging:

```c
pr_info("firewall: module loaded\n");
pr_warn("firewall: hash table full\n");
pr_err("firewall: failed to register hook\n");
```

Debug level is controlled via compile-time macro:

```bash
make debug DL=2    # Enable debug level 2
```