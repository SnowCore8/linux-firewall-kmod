# Monitoring

This document describes how to monitor the Linux Firewall Kernel Module's operational status.

## Prometheus Monitoring

### Configure Prometheus

Add a job to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'firewall'
    static_configs:
      - targets: ['localhost:9119']
    scrape_interval: 15s
```

### Available Metrics

> The 14 metrics below are actually exposed by
> `src/daemon/http-exporter.c`. Earlier drafts listed
> `firewall_ban_events_total` / `firewall_packets_dropped_total` /
> `firewall_hash_table_*` / `firewall_jail_*` — none of which exist in
> the source — and have been removed.

#### Kernel-side (from `/proc/firewall/stats`)

The full 12-field stats interface maps to the following kernel-level
counters. Refer to `docs/configuration/procfs.md` for the exact
key names and the conservation law.

| Metric | Type | Description |
|--------|------|-------------|
| `firewall_kernel_banned_ips_current` | gauge | Currently banned IPs (`current_bans`) |
| `firewall_kernel_bans_total` | counter | Cumulative ban operations (`total_bans`) |
| `firewall_kernel_unbans_total` | counter | Cumulative unban operations (`total_unbans`) |
| `firewall_kernel_whitelist_count` | gauge | Current whitelist entries (`current_whitelist`) |
| `firewall_kernel_whitelist_rejects_total` | counter | Whitelist-rejected ban attempts |
| `firewall_kernel_ban_table_full_rejects_total` | counter | Rejected due to full ban table |
| `firewall_kernel_alloc_failures_total` | counter | `kmalloc` failures for ban entries |
| `firewall_kernel_packets_dropped_total` | counter | Packets dropped due to ban match |
| `firewall_kernel_packets_accepted_total` | counter | Packets accepted by netfilter hook |
| `firewall_kernel_cleanup_cycles_total` | counter | Cleanup timer cycles |
| `firewall_kernel_cleanup_expired_total` | counter | Entries removed by cleanup timer |
| `firewall_kernel_recent_additions` | gauge | Bans within the 1-second flood window |

**Invariant**: `total_bans == current_bans + total_unbans + cleanup_expired_total`

#### Daemon-side

| Metric | Type | Description |
|--------|------|-------------|
| `firewall_daemon_uptime_seconds` | counter | Daemon uptime |
| `firewall_daemon_config_reloads_total` | counter | SIGHUP-triggered config reloads |
| `firewall_daemon_inotify_events_total` | counter | inotify events received |
| `firewall_daemon_log_rotations_total` | counter | Log rotation events |
| `firewall_daemon_lines_parsed_total` | counter | Log lines parsed |
| `firewall_daemon_lines_skipped_total` | counter | Log lines skipped (unparseable) |
| `firewall_daemon_regex_matches_total` | counter | PCRE2 regex matches |
| `firewall_daemon_ips_extracted_total` | counter | IPs extracted from logs |
| `firewall_daemon_ips_banned_total` | counter | IPs that triggered a kernel ban |
| `firewall_daemon_failed_attempts_total` | counter | Ban failures (e.g. table full) |

### Query Examples

```promql
# Current banned IP count
firewall_kernel_banned_ips_current

# 5-minute ban rate (kernel-side)
rate(firewall_kernel_bans_total[5m])

# 5-minute IP extraction rate
rate(firewall_daemon_ips_extracted_total[5m])

# Pending: extracted but not yet banned (within find_time window)
rate(firewall_daemon_ips_extracted_total[5m])
  - rate(firewall_daemon_ips_banned_total[5m])

# Daemon uptime in hours
firewall_daemon_uptime_seconds / 3600

# Parsing-vs-match ratio (health indicator)
rate(firewall_daemon_regex_matches_total[5m])
  / rate(firewall_daemon_lines_parsed_total[5m])
```

## Grafana Dashboard

### Import Dashboard

1. Open Grafana
2. Click `+` → `Import`
3. Enter dashboard JSON or upload file

### Recommended Panels

#### Current Banned IPs

```
Title: Current Banned IPs
Panel: Stat
Query: firewall_kernel_banned_ips_current
Thresholds: 100 (warning), 1000 (critical)
```

#### Ban Rate Trend

```
Title: Ban Rate (kernel)
Panel: Time Series
Query: rate(firewall_kernel_bans_total[5m])
```

#### Unban Rate Trend

```
Title: Unban Rate (kernel)
Panel: Time Series
Query: rate(firewall_kernel_unbans_total[5m])
```

#### Daemon Health

```
Title: Daemon Health
Panel: Time Series
Queries:
  - rate(firewall_daemon_lines_parsed_total[5m])    # parsed
  - rate(firewall_daemon_regex_matches_total[5m])   # matched
  - rate(firewall_daemon_lines_skipped_total[5m])   # skipped
  - rate(firewall_daemon_failed_attempts_total[5m])  # failed
```

#### Capacity Usage

```
Title: Whitelist Capacity
Panel: Gauge
Query: firewall_kernel_whitelist_count
Thresholds: 50 (warning), 60 (critical)
Max: 64
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
/etc/logrotate.d/firewall

/var/log/firewall.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload firewall > /dev/null 2>&1 || true
    endscript
}
```

### Log Analysis Commands

```bash
# Count today's bans
grep "$(date +%Y-%m-%d)" /var/log/firewall.log | grep "Banned" | wc -l

# Most frequently banned IPs
grep "Banned" /var/log/firewall.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -20

# Bans per jail
grep "Banned" /var/log/firewall.log | grep -oP '\[\w+\]' | sort | uniq -c | sort -rn

# Last 10 bans
grep "Banned" /var/log/firewall.log | tail -10
```

## Alert Rules

### Prometheus AlertManager

```yaml
groups:
  - name: firewall
    rules:
      - alert: HighBanRate
        expr: rate(firewall_kernel_bans_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High kernel ban rate detected"
          description: "Ban rate is {{ $value }} per second"

      - alert: WhitelistNearlyFull
        expr: firewall_kernel_whitelist_count > 50
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Whitelist nearing 64-entry cap"
          description: "{{ $value }} entries used (max 64)"

      - alert: DaemonDown
        # When the daemon crashes or is not running, the uptime
        # counter stops advancing.
        expr: rate(firewall_daemon_uptime_seconds[5m]) == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "firewall-daemon not running"
          description: "Daemon uptime counter not advancing"

      - alert: DaemonFailingExtraction
        expr: rate(firewall_daemon_failed_attempts_total[5m]) > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High daemon failure rate"
          description: "Failure rate is {{ $value }} per second"
```

## Health Checks

### Local Health Check Script

```bash
#!/bin/bash
# /usr/local/bin/firewall-health.sh

# Check kernel module
if ! lsmod | grep -q firewall; then
    echo "CRITICAL: Kernel module not loaded"
    exit 2
fi

# Check daemon
if ! systemctl is-active --quiet firewall; then
    echo "CRITICAL: Daemon not running"
    exit 2
fi

# Check ProcFS
if [ ! -f /proc/firewall/config ]; then
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
# /etc/systemd/system/firewall-health.service
[Unit]
Description=Linux Firewall Health Check
After=firewall-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall-health.sh

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```