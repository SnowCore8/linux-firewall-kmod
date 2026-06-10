# Quick Start

This guide will help you configure and run your first jail rule in 5 minutes.

## Prerequisites

Ensure you have completed [Installation](installation.md) and verified the module is working.

## Step 1: Configuration File

Edit the main configuration file `/etc/firewall/default.yaml`:

```bash
sudo vim /etc/firewall/default.yaml
```

### Basic Configuration

```yaml
# Global settings
global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db

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
sudo systemctl restart firewall

# Check status
sudo systemctl status firewall
```

## Step 4: Verify Banning

### Method 1: Check ProcFS

```bash
cat /proc/firewall/bans
```

### Method 2: Using firewall-daemon

```bash
# View banned list
cat /proc/firewall/bans

# View statistics
cat /proc/firewall/stats
```

### Method 3: Manual Test

```bash
# Manually ban a test IP
echo "192.168.1.100 3600" | sudo tee /proc/firewall/bans

# Confirm banned
cat /proc/firewall/bans

# Unban
echo "unban 192.168.1.100" | sudo tee /proc/firewall/bans
```

## Step 5: Monitoring

### View Prometheus Metrics

```bash
curl http://localhost:9119/metrics
```

Key metrics:

```
# TYPE firewall_kernel_banned_ips_current gauge
firewall_kernel_banned_ips_current 5

# TYPE firewall_kernel_bans_total counter
firewall_kernel_bans_total 12

# TYPE firewall_kernel_unbans_total counter
firewall_kernel_unbans_total 7
```

### View Logs

```bash
sudo tail -f /var/log/firewall.log
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