# YAML Configuration

This document details all options in the `/etc/firewall/default.yaml` configuration file.

## Configuration Overview

The current design uses **smart inference**: you only need to configure `log_files` and `regexes`; other parameters use sensible defaults.

```yaml
# Global defaults
defaults:
  max_retries: 5
  findtime: 600         # 10 minutes
  ban_time: 900         # 15 minutes
  interval: 1           # Check interval (seconds)
  metrics_port: 9119    # Prometheus metrics port

# Jail definitions
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retries: 3
    findtime: 600
    ban_time: 1800
    regexes:
      failed_password:
        pattern: "Failed password for (?:invalid user )?.+ from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

# Persistence
permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

## Global Defaults (defaults)

The `defaults` block defines default behavior for all jails. Individual jails can override these values.

```yaml
defaults:
  max_retries: 5
  findtime: 600         # 10 minutes
  ban_time: 900         # 15 minutes
  interval: 1           # Check interval (seconds)
  metrics_port: 9119    # Prometheus metrics port
```

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `max_retries` | int | `5` | 1-100 | Maximum failures before a ban is triggered |
| `findtime` | int | `600` | 1-3600 | Time window (seconds) over which failures are counted |
| `ban_time` | int | `900` | 0 or 1-86400 | Ban duration (seconds); 0 = permanent |
| `interval` | int | `1` | 1-60 | Log file check interval (seconds) |
| `metrics_port` | int | `9119` | 1024-65535 | Prometheus metrics port |

### Time Parameter Relationship

```
findtime (600s)
├── Failure count accumulates within this window
│
max_retries (5)
├── Ban triggers when count reaches this
│
ban_time (900s)
├── Ban lasts for this duration
└── Auto-unban after expiry
```

## Jail Configuration

Each jail defines an independent log monitoring and ban rule.

### Jail Structure

```yaml
jails:
  sshd:                           # Jail name (key name = name)
    enabled: true                 # Whether enabled
    log_files:                    # Log files to monitor
      - /var/log/auth.log
      - /var/log/secure
    max_retries: 3                # Override defaults
    findtime: 600                 # Override defaults
    ban_time: 1800                # Override defaults
    regexes:                      # Named regex patterns
      failed_password:
        pattern: "..."
      invalid_user:
        pattern: "..."
```

### Jail Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `<name>` (key) | string | Yes | - | Jail name, globally unique |
| `enabled` | bool | No | `true` | Whether this jail is active |
| `log_files` | list | Yes | - | List of log file paths to monitor |
| `max_retries` | int | No | Inherited from `defaults` | Max failures before ban |
| `findtime` | int | No | Inherited from `defaults` | Time window (seconds) |
| `ban_time` | int | No | Inherited from `defaults` | Ban duration (seconds) |
| `regexes` | map | Yes | - | Named regex pattern collection |

### Regex Configuration (regexes)

```yaml
regexes:
  failed_password:                          # Pattern name
    pattern: "Failed password for (?:invalid user )?.+ from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
  invalid_user:
    pattern: "Invalid user [a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `<name>` (key) | string | Yes | Pattern name, used for log identification |
| `pattern` | string | Yes | PCRE2 regex; use capture group `()` to extract IP |

### PCRE2 Regex Syntax

The current version **no longer uses the `<HOST>` placeholder**. Write the full regex directly in `pattern`.

| Feature | Example | Description |
|---------|---------|-------------|
| Capture group | `([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})` | Extract IP address |
| Non-capture group | `(?:pattern)` | Group without capturing |
| Character class | `[a-zA-Z0-9_.-]` | Character range |
| Quantifiers | `*`, `+`, `?`, `{n,m}` | Repetition |
| Anchors | `^`, `$` | Line start/end |

> **YAML Escaping Note**: In YAML, backslashes must be doubled `\\.` instead of `\.`, or wrap the value in double quotes.

## Whitelist Configuration (whitelist)

```yaml
whitelist:
  - 127.0.0.1
  - 192.168.1.0/24
  - 10.0.0.1
  - 172.16.0.0/16
```

| Format | Example | Description |
|--------|---------|-------------|
| Single IP | `192.168.1.100` | Skip this IP when banning |
| CIDR range | `192.168.1.0/24` | Skip all IPs in this subnet |

> **Limit**: Maximum 64 whitelist entries. Excess entries are ignored with a warning.

### Built-in Whitelist

The following IP is always protected, no manual configuration needed:

- `127.0.0.1` - Loopback address

## Persistence Configuration

```yaml
permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `permanent_db_path` | string | `/var/lib/firewall/bans.db` | SQLite database path |
| `permanent_ban_enabled` | bool | `true` | Enable permanent ban persistence |

## Complete Configuration Example

```yaml
# /etc/firewall/default.yaml

# ============================================================
# Global defaults - applied to all jails unless overridden
# ============================================================
defaults:
  max_retries: 5
  findtime: 600         # 10 minutes
  ban_time: 900         # 15 minutes
  interval: 1           # Check interval (seconds)
  metrics_port: 9119    # Prometheus metrics port

# ============================================================
# Jail definitions - each service monitored independently
# ============================================================
jails:
  # SSH protection
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log       # Debian/Ubuntu
      - /var/log/secure         # RHEL/CentOS
    max_retries: 3
    findtime: 600               # 10 minutes
    ban_time: 1800              # 30 minutes
    regexes:
      invalid_user:
        pattern: "Invalid user [a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
      failed_password:
        pattern: "Failed password for (?:invalid user )?[a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
      connection_closed:
        pattern: "Connection closed by invalid user [a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

  # Nginx auth protection
  nginx-auth:
    enabled: true
    log_files:
      - /var/log/nginx/error.log
    max_retries: 10
    findtime: 300               # 5 minutes
    ban_time: 1800              # 30 minutes
    regexes:
      no_auth:
        pattern: "no user/password was provided for basic authentication.*client: ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

# ============================================================
# Permanent ban persistence (SQLite)
# ============================================================
permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

## Multi-Config Loading

The daemon supports `-C <dir>` to load all YAML files in a directory:

```bash
sudo firewall-daemon -C /etc/firewall
```

Loading order:

1. Files loaded in **alphabetical order**
2. Jails are **accumulated** (later configs do not overwrite earlier ones)
3. Duplicate jail names use **last-wins** strategy

Example directory structure:

```
/etc/firewall/
├── default.yaml      # Base configuration
├── nginx.yaml        # Additional nginx protection
├── mysql.yaml        # Additional mysql protection
└── ...
```
