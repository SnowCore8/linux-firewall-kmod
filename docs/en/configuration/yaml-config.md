# YAML Configuration

This document details all options in the `/etc/fw_fire/fw_fire.yaml` configuration file.

## Global Configuration (global)

```yaml
global:
  log_level: info
  log_file: /var/log/fw_fire.log
  db_path: /var/lib/fw_fire/bans.db
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `log_level` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `log_file` | string | `/var/log/fw_fire.log` | Log file path |
| `db_path` | string | `/var/lib/fw_fire/bans.db` | SQLite database path |

### Log Levels

| Level | Description |
|-------|-------------|
| `debug` | Debug information, including all detailed operation logs |
| `info` | General information, ban/unban events |
| `warn` | Warnings, configuration issues, resource limits |
| `error` | Errors, module load failures, database errors |

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

> **Limit**: The whitelist supports up to 64 entries. Excess entries are ignored with a warning.

### Built-in Whitelist

The following IPs are always whitelisted and do not need manual configuration:

- `127.0.0.1` - Loopback address

## Jail Configuration

Each jail defines an independent monitoring and banning rule.

### Complete Example

```yaml
jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 22
    protocol: tcp
```

### Basic Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | string | Yes | - | Jail name, globally unique |
| `enabled` | bool | No | `true` | Whether the jail is enabled |
| `log_path` | string | Yes | - | Log file path to monitor |
| `port` | int | Yes | - | Target port to monitor |
| `protocol` | string | Yes | - | Protocol: `tcp`, `udp`, `all` |

### Filter Configuration (filter)

```yaml
filter:
  regex: 'Failed password for .* from <HOST>'
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `regex` | string | Yes | PCRE2 regex, uses `<HOST>` placeholder to match IPs |

### Regular Expression Syntax

Uses the PCRE2 engine, supporting:

| Feature | Example | Description |
|---------|---------|-------------|
| `<HOST>` placeholder | `from <HOST>` | Matches IPv4/IPv6 addresses |
| Capture groups | `(?:pattern)` | Non-capturing group |
| Character classes | `[a-z]` | Character range |
| Quantifiers | `*`, `+`, `?` | Repetition |
| Anchors | `^`, `$` | Start/end of line |

### `<HOST>` Placeholder

`<HOST>` is a special placeholder that automatically matches IP addresses:

```
# Equivalent regex
<HOST> => (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```

### Action Configuration (action)

```yaml
action:
  ban_time: 3600
  find_time: 600
  max_retries: 5
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `ban_time` | int | No | `3600` | Ban duration (seconds), 0 = permanent |
| `find_time` | int | No | `600` | Time window (seconds) for counting |
| `max_retries` | int | No | `5` | Maximum failures before ban |

### Time Parameter Relationship

```
find_time (600s)
├── Count failures within this window
│
max_retries (5)
├── Trigger ban when this count is reached
│
ban_time (3600s)
├── Ban lasts for this duration
└── Auto-unban when expired
```

## Complete Configuration Example

```yaml
# /etc/fw_fire/fw_fire.yaml

global:
  log_level: info
  log_file: /var/log/fw_fire.log
  db_path: /var/lib/fw_fire/bans.db

whitelist:
  - 127.0.0.1
  - 192.168.1.0/24
  - 10.0.0.1

jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 22
    protocol: tcp

  - name: nginx-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp

  - name: dovecot
    enabled: false
    log_path: /var/log/mail.log
    filter:
      regex: 'auth failed.*rip=<HOST>'
    action:
      ban_time: 7200
      find_time: 600
      max_retries: 3
    port: 143
    protocol: tcp
```