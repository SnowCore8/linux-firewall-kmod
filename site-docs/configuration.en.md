# Configuration Guide

**Version**: v2.0

## 1. Configuration File Structure

Firewall uses YAML configuration files and supports two loading methods:

```bash
# Load a single configuration file
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# Load all YAML files in a directory
sudo ./build/daemon/firewall-daemon -C /etc/firewall/
```

### 1.1 File Locations

| Location | Description |
|----------|-------------|
| `/etc/firewall/` | Production environment configuration directory |
| `config/` | Built-in configuration templates |

### 1.2 Configuration Structure

```yaml
# Global default settings
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

# Jail configuration (one block per service)
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
    - /var/log/secure
  max_retries: 5
  findtime: 600
  ban_time: 900
  regex: ""
```

## 2. Global Default Settings (defaults)

The `defaults` block defines baseline values for all jails. Individual jails can override these values.

| Parameter | Type | Default | Description | Valid Range |
|-----------|------|---------|-------------|-------------|
| `max_retries` | integer | `5` | Number of failures to trigger a ban | 1 ~ 100 |
| `findtime` | integer | `600` | Time window for failure tracking (seconds) | 1 ~ 3600 |
| `ban_time` | integer | `900` | Ban duration (seconds), 0 = permanent | 0 or 1 ~ 86400 |
| `interval` | integer | `1` | Log check interval (seconds) | 1 ~ 60 |
| `metrics_port` | integer | `9119` | Prometheus metrics export port | 0 ~ 65535 |

**Example**:

```yaml
defaults:
  max_retries: 5        # Ban after 5 failures
  findtime: 600         # 10-minute window
  ban_time: 900         # 15-minute ban
  interval: 1           # Check every second
  metrics_port: 9119    # Prometheus port
```

## 3. Jail Configuration

Each jail represents a service's protection configuration.

| Parameter | Type | Default | Description | Limit |
|-----------|------|---------|-------------|-------|
| `enabled` | boolean | `true` | Whether to enable this jail | - |
| `log_files` | array | `[]` | List of log file paths to monitor | Max 10 files |
| `max_retries` | integer | Inherited from defaults | Override default max_retries | 1 ~ 100 |
| `findtime` | integer | Inherited from defaults | Override default findtime | 1 ~ 3600 |
| `ban_time` | integer | Inherited from defaults | Override default ban_time, 0 = permanent | 0 or 1 ~ 86400 |
| `regex` | string | `""` | Custom PCRE2 regex pattern | Max 1024 bytes |

**Example**:

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  max_retries: 5
  findtime: 600
  ban_time: 900
  regex: ""  # Use built-in SSHD pattern
```

## 4. Preset Service Templates

The project provides 12 preset service templates:

| File | Jail Name | Service Type | Default Log Path |
|------|-----------|--------------|------------------|
| `default.yaml` | sshd | SSH | `/var/log/auth.log` |
| `nginx.yaml` | nginx | Web Server | `/var/log/nginx/error.log` |
| `apache.yaml` | apache | Web Server | `/var/log/apache2/error.log` |
| `dovecot.yaml` | dovecot | Mail Service | `/var/log/mail.log` |
| `postfix.yaml` | postfix | Mail Service | `/var/log/mail.log` |
| `mysql.yaml` | mysql | Database | `/var/log/mysql/error.log` |
| `vsftpd.yaml` | vsftpd | FTP Service | `/var/log/vsftpd.log` |
| `wordpress.yaml` | wordpress | Web Application | `/var/log/nginx/error.log` |
| `redis.yaml` | redis | Database | `/var/log/redis/redis-server.log` |
| `docker.yaml` | docker | Container Platform | `/var/log/docker.log` |
| `traefik.yaml` | traefik | Reverse Proxy | `/var/log/traefik/traefik.log` |
| `frp.yaml` | frp | Intranet Penetration | `/var/log/frp/frp.log` |

## 5. Smart Inference

When a jail name matches a known service, the system automatically infers the configuration:

| Jail Name Keyword | Inferred Service | Built-in Regex |
|-------------------|------------------|----------------|
| `ssh` | SSHD | `Failed password for .* from <IP>` |
| `nginx` | Nginx | `access forbidden by rule, client: <IP>` |
| `apache` | Apache | `client denied by server configuration: ...` |
| `mysql` | MySQL | `Access denied for user .* from <IP>` |
| `redis` | Redis | `Invalid password from <IP>` |
| `vsftpd` | vsftpd | `FAIL LOGIN: Client "<IP>"` |
| `docker` | Docker | `TLS handshake error from <IP>` |
| `frp` | FRP | `remoteAddr: <IP>` |

## 6. Strict / Permissive Mode

### 6.1 Strict Mode (Default)

Unknown parameters or invalid values cause the configuration to be rejected:

```bash
sudo ./build/daemon/firewall-daemon --strict
```

### 6.2 Permissive Mode

Allows unknown parameters with warnings:

```bash
sudo ./build/daemon/firewall-daemon --permissive
```

## 7. Hot Config Reload

Send a SIGHUP signal to reload the configuration:

```bash
sudo kill -HUP $(cat /run/firewall-daemon.pid)
```

**Reload Process**:
1. Parse new configuration into a temporary structure
2. Validate configuration
3. Atomically swap the configuration pointer
4. Free old configuration memory

## 8. Custom Regex

### 8.1 Using Built-in Patterns

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  regex: ""  # Use built-in SSHD pattern
```

### 8.2 Custom PCRE2 Regex

```yaml
custom-app:
  enabled: true
  log_files:
    - /var/log/custom.log
  regex: "Authentication failure.*from\s+<IP>"
```

**Requirements**:
- Regex must include the `<IP>` placeholder for IP extraction
- Use PCRE2 syntax
- Maximum 1024 bytes

### 8.3 ReDoS Protection

The system automatically detects the following dangerous patterns:
- Nested quantifiers: `(a+)+`
- Possessive quantifiers: `a++`
- Excessive alternation: `(a|b|c|...){10,}`

Dangerous patterns are rejected with an error.

## 9. Configuration Validation Rules

### 9.1 Parameter Whitelist

**Defaults section** only accepts the following parameters:
- `max_retries`, `findtime`, `ban_time`, `interval`, `metrics_port`

**Jail section** only accepts the following parameters:
- `enabled`, `log_files`, `max_retries`, `findtime`, `ban_time`
- `regex`

### 9.2 Value Range Checks

| Parameter | Min Value | Max Value |
|-----------|-----------|-----------|
| `max_retries` | 1 | 100 |
| `findtime` | 1 | 3600 |
| `ban_time` | 0 (permanent) | 86400 (24 hours) |
| `interval` | 1 | 60 |
| `metrics_port` | 0 | 65535 |

### 9.3 Path Validation

Log file paths must:
- Exist under `/var/log/`, `/etc/`, `/home/`, or `/srv/` directories
- Not contain `//` consecutive slashes
- Remain within whitelisted directories after `realpath` resolution
