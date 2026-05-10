# Quick Start

This guide will help you configure and run your first jail rule in 5 minutes.

## Prerequisites

Ensure you have completed [Installation](installation.md) and verified the module is working.

## Step 1: Configuration File

Edit the main configuration file `/etc/fw_fire/fw_fire.yaml`:

```bash
sudo vim /etc/fw_fire/fw_fire.yaml
```

### Basic Configuration

```yaml
# Global settings
global:
  log_level: info
  log_file: /var/log/fw_fire.log
  db_path: /var/lib/fw_fire/bans.db

# SSH Protection Jail
jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for .* from <HOST>'
    action:
      ban_time: 3600        # Ban for 1 hour
      find_time: 600        # Within 10 minutes
      max_retries: 5        # Ban after 5 failures
    port: 22
    protocol: tcp
```

### Configuration Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `name` | Jail name | `sshd` |
| `enabled` | Whether enabled | `true` |
| `log_path` | Log file to monitor | `/var/log/auth.log` |
| `regex` | Regex for matching failures | `Failed password for .* from <HOST>` |
| `ban_time` | Ban duration (seconds) | `3600` |
| `find_time` | Counting window (seconds) | `600` |
| `max_retries` | Maximum retry count | `5` |
| `port` | Monitored port | `22` |
| `protocol` | Protocol type | `tcp` |

## Step 2: Add Whitelist

Add your admin IP to the whitelist to prevent accidental banning:

```yaml
# Add to configuration file
whitelist:
  - 192.168.1.0/24
  - 10.0.0.1
```

> **Note**: The whitelist supports up to 64 entries.

## Step 3: Start the Service

```bash
# Reload configuration and start
sudo systemctl restart fw_fire

# Check status
sudo systemctl status fw_fire
```

## Step 4: Verify Banning

### Method 1: Check ProcFS

```bash
cat /proc/fw_fire/banned_ips
```

### Method 2: Using fwctl

```bash
# View banned list
fwctl banned

# View statistics
fwctl stats
```

### Method 3: Manual Test

```bash
# Manually ban a test IP
fwctl ban 192.168.1.100 3600

# Confirm banned
fwctl banned

# Unban
fwctl unban 192.168.1.100
```

## Step 5: Monitoring

### View Prometheus Metrics

```bash
curl http://localhost:9119/metrics
```

Key metrics:

```
# TYPE fw_fire_banned_ips_total gauge
fw_fire_banned_ips_total 5

# TYPE fw_fire_ban_events_total counter
fw_fire_ban_events_total 12

# TYPE fw_fire_unban_events_total counter
fw_fire_unban_events_total 7
```

### View Logs

```bash
sudo tail -f /var/log/fw_fire.log
```

## Configuring More Jails

### Nginx Brute Force Protection

```yaml
  - name: nginx-http-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password was provided for basic authentication.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp
```

### Postfix Protection

```yaml
  - name: postfix
    enabled: true
    log_path: /var/log/mail.log
    filter:
      regex: 'warning: .*\[<HOST>\]: SASL .+ authentication failed'
    action:
      ban_time: 7200
      find_time: 600
      max_retries: 3
    port: 25
    protocol: tcp
```

## Next Steps

- Read [YAML Configuration](../configuration/yaml-config.md) for all configuration options
- Check [Configuration Examples](../configuration/examples.md) for more templates
- Learn about [Architecture](../architecture/) to understand how it works

---

[中文版本](../../zh/getting-started/quick-start.md)
