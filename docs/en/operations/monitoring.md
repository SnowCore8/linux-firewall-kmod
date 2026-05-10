# Monitoring

This document describes how to monitor the Linux Firewall Kernel Module's operational status.

## Prometheus Monitoring

### Configure Prometheus

Add a job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'fw_fire'
    static_configs:
      - targets: ['localhost:9119']
    scrape_interval: 15s
```

### Available Metrics

#### General Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `fw_fire_banned_ips_total` | gauge | Current number of banned IPs |
| `fw_fire_ban_events_total` | counter | Total ban events |
| `fw_fire_unban_events_total` | counter | Total unban events |
| `fw_fire_packets_dropped_total` | counter | Total dropped packets |
| `fw_fire_packets_passed_total` | counter | Total passed packets |

#### Capacity Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `fw_fire_whitelist_entries_total` | gauge | Current whitelist entries |
| `fw_fire_hash_table_usage` | gauge | Hash table usage (0.0-1.0) |
| `fw_fire_hash_table_capacity` | gauge | Hash table capacity (4096) |
| `fw_fire_whitelist_capacity` | gauge | Whitelist capacity (64) |

#### Jail Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `fw_fire_jail_failures_total` | counter | `jail` | Failure matches per jail |
| `fw_fire_jail_bans_total` | counter | `jail` | Bans triggered per jail |
| `fw_fire_jail_active` | gauge | `jail` | Whether jail is enabled (0/1) |

### Query Examples

```promql
# Current banned IP count
fw_fire_banned_ips_total

# Ban rate over last 5 minutes
rate(fw_fire_ban_events_total[5m])

# Bans by jail
sum by (jail) (fw_fire_jail_bans_total)

# Hash table usage percentage
fw_fire_hash_table_usage * 100

# Packet drop rate
rate(fw_fire_packets_dropped_total[5m])
```

## Grafana Dashboard

### Import Dashboard

1. Open Grafana
2. Click `+` → `Import`
3. Enter dashboard JSON or upload file

### Recommended Panels

#### Ban Overview

```
Title: Current Banned IPs
Panel: Stat
Query: fw_fire_banned_ips_total
Thresholds: 100 (warning), 1000 (critical)
```

#### Ban Trend

```
Title: Ban Events Rate
Panel: Time Series
Query: rate(fw_fire_ban_events_total[5m])
```

#### Jail Distribution

```
Title: Bans by Jail
Panel: Pie Chart
Query: sum by (jail) (fw_fire_jail_bans_total)
```

#### Packet Statistics

```
Title: Packets Processed
Panel: Time Series
Query: 
  rate(fw_fire_packets_dropped_total[5m])  # Dropped
  rate(fw_fire_packets_passed_total[5m])   # Passed
```

## Log Monitoring

### Log Format

```
[2024-01-15 10:30:45] [INFO] [sshd] Banned 192.168.1.100 (5 failures in 600s)
[2024-01-15 10:30:45] [INFO] Kernel: Added 192.168.1.100 to hash table
[2024-01-15 11:30:45] [INFO] [sshd] Unbanned 192.168.1.100 (expired)
[2024-01-15 12:00:00] [WARN] Hash table 75% full
```

### Log Levels

| Level | Description | Example |
|-------|-------------|---------|
| `DEBUG` | Debug information | Detailed matching process |
| `INFO` | General information | Ban/unban events |
| `WARN` | Warnings | Resources approaching limit |
| `ERROR` | Errors | Operation failures |

### Log Rotation

Configure logrotate:

```
/etc/logrotate.d/fw_fire

/var/log/fw_fire.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload fw_fire > /dev/null 2>&1 || true
    endscript
}
```

### Log Analysis Commands

```bash
# Count today's bans
grep "$(date +%Y-%m-%d)" /var/log/fw_fire.log | grep "Banned" | wc -l

# Most frequently banned IPs
grep "Banned" /var/log/fw_fire.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -20

# Bans per jail
grep "Banned" /var/log/fw_fire.log | grep -oP '\[\w+\]' | sort | uniq -c | sort -rn

# Last 10 bans
grep "Banned" /var/log/fw_fire.log | tail -10
```

## Alert Rules

### Prometheus AlertManager

```yaml
groups:
  - name: fw_fire
    rules:
      - alert: HighBanRate
        expr: rate(fw_fire_ban_events_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High ban rate detected"
          description: "Ban rate is {{ $value }} per second"

      - alert: HashTableNearlyFull
        expr: fw_fire_hash_table_usage > 0.8
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Hash table nearly full"
          description: "Usage is {{ $value | humanizePercentage }}"

      - alert: FirewallDown
        expr: fw_fire_banned_ips_total == -1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Firewall module is not responding"

      - alert: HighDropRate
        expr: rate(fw_fire_packets_dropped_total[5m]) > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate"
          description: "Drop rate is {{ $value }} per second"
```

## Health Checks

### Local Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/fw_fire-health.sh

# Check kernel module
if ! lsmod | grep -q fw_fire; then
    echo "CRITICAL: Kernel module not loaded"
    exit 2
fi

# Check daemon
if ! systemctl is-active --quiet fw_fire; then
    echo "CRITICAL: Daemon not running"
    exit 2
fi

# Check ProcFS
if [ ! -f /proc/fw_fire/status ]; then
    echo "CRITICAL: ProcFS interface not available"
    exit 2
fi

# Check Prometheus port
if ! curl -s http://localhost:9119/metrics > /dev/null 2>&1; then
    echo "WARNING: Prometheus metrics not available"
    exit 1
fi

echo "OK: All checks passed"
exit 0
```

### systemd Integration

```ini
# /etc/systemd/system/fw_fire-health.service
[Unit]
Description=Linux Firewall Health Check
After=fw_fire.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fw_fire-health.sh

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

---

[中文版本](../../zh/operations/monitoring.md)
