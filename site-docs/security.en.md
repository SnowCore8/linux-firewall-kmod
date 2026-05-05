# Security Features Technical Document

**Version**: v2.0

## 1. Build Security

### 1.1 Security Compilation Flags

| Flag | Purpose |
|------|---------|
| `-Wall -Wextra` | Enable all common warnings |
| `-Werror=format-security` | Format string security errors |
| `-O2` | Optimization level 2 |
| `-D_FORTIFY_SOURCE=2` | Buffer overflow detection |
| `-fstack-protector-strong` | Stack overflow protection |
| `-fPIE -pie` | PIE executable (works with ASLR) |
| `-Wl,-z,relro,-z,now` | Full RELRO (delayed binding protection) |

### 1.2 Verify Build Security

```bash
# Check PIE
file build/daemon/firewall-daemon     # Output should contain: pie executable

# Check RELRO
readelf -l build/daemon/firewall-daemon | grep GNU_RELRO

# Check BIND_NOW
readelf -d build/daemon/firewall-daemon | grep FLAGS  # Output should contain: BIND_NOW
```

## 2. Runtime Security

### 2.1 systemd Service Hardening

Security restrictions enabled in `firewall-daemon.service`:

```ini
[Service]
ProtectSystem=strict        # Protect system directories
ProtectHome=yes             # Restrict access to /home
NoNewPrivileges=yes         # Prevent privilege escalation
PrivateTmp=yes              # Private /tmp
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH  # Minimal capabilities
```

### 2.2 Principle of Least Privilege

| Component | Privileges | Description |
|-----------|------------|-------------|
| Kernel Module | ring 0 | Required (kernelspace) |
| Daemon | root + capabilities | Only necessary capabilities retained |
| Config Files | 600 root:root | Read/write by root only |
| State Directory | 700 root:root | Accessible by root only |

## 3. Input Validation

### 3.1 IP Address Validation

- Strict IPv4 format checking
- Reject loopback addresses (`127.0.0.0/8`), multicast addresses (`224.0.0.0/4`), broadcast addresses, and `0.0.0.0`

### 3.2 Path Traversal Protection

- Whitelist directories: only `/var/log/`, `/etc/`, `/home/`, `/srv/` allowed
- `realpath` resolution validation, reject `//` consecutive slashes and `..` path traversal

### 3.3 URL Encoding Detection

procfs interface detects encoding bypass attempts: `%2e` → `.`, `%2f` → `/`, `%2e%2e` → `..`

## 4. Concurrency Safety

### 4.1 RCU Mechanism

```
Read Path (Lock-free)              Write Path (spinlock)
─────────────────                  ─────────────────
rcu_read_lock()                    spin_lock()
  READ_ONCE()                        Modify data
rcu_read_unlock()                  spin_unlock()
                                   call_rcu() → Delayed release
```

**Key Guarantees**: Readers never block on writers; writers wait for RCU grace period before freeing memory; field reads/writes use `READ_ONCE`/`WRITE_ONCE` to prevent compiler reordering.

### 4.2 Lock Design

```
firewall_info.lock
  ├── ban_table (hash table)
  └── whitelist_table (hash table)
```

Single-lock design, no deadlock risk.

## 5. Memory Safety

### 5.1 Pre-allocation Strategy

```c
// Pre-allocate outside lock (GFP_KERNEL), only check and insert inside lock
entry = kmalloc(sizeof(*entry), GFP_KERNEL);
spin_lock(&fw->lock);
if (duplicate) { kfree(entry); return 0; }
hash_add_rcu(fw->ban_table, &entry->hash, ip);
spin_unlock(&fw->lock);
```

### 5.2 RCU Safe Release

```c
hlist_del_rcu(&entry->hash);
call_rcu(&entry->rcu_head, free_ban_entry_rcu);  // kfree executed after grace period
```

### 5.3 TOCTOU Protection

State file operations use `O_NOFOLLOW` + inode consistency validation:

```c
vfs_getattr(&path, &saved_stat);   // Record inode before opening
// ... write operation ...
vfs_getattr(&path, &close_stat);   // Verify after writing
if (close_stat.ino != saved_stat.ino)
    return -EACCES;                // TOCTOU attack detected
```

## 6. Regex Safety

### 6.1 ReDoS Protection

Detect the following dangerous patterns before compilation:

| Pattern | Example | Risk |
|---------|---------|------|
| Nested Quantifiers | `(a+)+` | Exponential backtracking |
| Possessive Quantifiers | `a++` | Non-backtrackable |
| Excessive Alternation | `(a\|b\|c\|...){10,}` | Combinatorial explosion |

### 6.2 Regex Limits

- Maximum length: 1024 bytes
- JIT compilation acceleration with match timeout protection

## 7. Monitoring Metrics

Prometheus metrics (port 9119):

| Metric | Description |
|--------|-------------|
| `firewall_kernel_banned_ips_current` | Current ban count |
| `firewall_kernel_total_bans_total` | Cumulative ban count |
| `firewall_daemon_ips_banned_total` | Daemon ban count |

## 8. Security Fix History

| Version | Fix Content |
|---------|-------------|
| v2.0 | RCU safety fixes (`hash_add_rcu`, `READ_ONCE`/`WRITE_ONCE`) |
| v2.0 | TOCTOU race condition fix (`O_NOFOLLOW` + inode validation) |
| v2.0 | Buffer overflow fix (dedicated parsing buffer) |
| v2.0 | Path validation enhancement (whitelist directory rejection) |
| v1.9 | SQLite thread safety protection (`pthread_mutex_t`) |
| v1.9 | State save/restore `is_permanent` fix |
| v1.8 | libmicrohttpd replacement (security update) |
| v1.7 | PCRE2 replacement (ReDoS protection) |
