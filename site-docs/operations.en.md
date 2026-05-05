# Firewall Operations Manual

**Version**: v2.0  
**Last Updated**: 2026-05-05

## 1. Installation & Deployment

### 1.1 System Requirements

| Item | Requirement |
|------|-------------|
| Operating System | Linux (Kernel 5.15+) |
| Architecture | x86_64 |
| Dependencies | libyaml, libsqlite3, libmicrohttpd, libpcre2-8 |
| Privileges | root (for loading kernel module) |

### 1.2 Build & Install

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev

# Build
make

# Install
sudo make install
```

### 1.3 Manual Installation

```bash
# 1. Install kernel module
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a
sudo modprobe firewall

# 2. Install daemon
sudo cp build/daemon/firewall-daemon /usr/local/sbin/

# 3. Install configuration
sudo mkdir -p /etc/firewall
sudo cp config/*.yaml /etc/firewall/

# 4. Install systemd service
sudo cp firewall-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-daemon
```

## 2. procfs Interface

> **Architecture Note**: For internal implementation and design principles of the procfs interface, refer to the [Architecture Document → procfs Interface](architecture.md#35-procfs-interface).

All operations go through the `/proc/firewall/` directory and require root privileges.

### 2.1 Interface List

| Path | Permissions | Function |
|------|-------------|----------|
| `/proc/firewall/bans` | 0600 | Ban list management |
| `/proc/firewall/whitelist` | 0600 | Whitelist management |
| `/proc/firewall/config` | 0600 | Runtime configuration |
| `/proc/firewall/stats` | 0400 | Statistics |

### 2.2 Ban Operations

| Operation | Format | Example |
|-----------|--------|---------|
| Read | `cat` | `cat /proc/firewall/bans` |
| Default Ban | `IP` | `echo "1.2.3.4" \| sudo tee /proc/firewall/bans` |
| Custom Duration | `IP seconds` | `echo "1.2.3.4 7200" \| sudo tee /proc/firewall/bans` |
| Permanent Ban | `IP 0` | `echo "1.2.3.4 0" \| sudo tee /proc/firewall/bans` |
| Unban | `unban IP` | `echo "unban 1.2.3.4" \| sudo tee /proc/firewall/bans` |

**Limits**: Maximum 1024 IPs, ban_time range 30 seconds ~ 31,536,000 seconds (1 year).

### 2.3 Whitelist Operations

| Operation | Format | Example |
|-----------|--------|---------|
| Read | `cat` | `cat /proc/firewall/whitelist` |
| Add Subnet | `subnet/prefix` | `echo "10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |
| Remove Subnet | `remove subnet/prefix` | `echo "remove 10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |

**Limits**: Maximum 64 whitelist entries.

### 2.4 Statistics

```bash
cat /proc/firewall/stats
```

Example output:
```
current_bans: 15
total_bans: 1234
total_unbans: 1200
packets_dropped: 56789
packets_accepted: 1234567
whitelist_entries: 5
```

## 3. Command-Line Arguments

```bash
sudo ./build/daemon/firewall-daemon --help
```

Options:
| Option | Description |
|--------|-------------|
| `-c, --config FILE` | Single configuration file path |
| `-C, --config-dir DIR` | Configuration directory (auto-loads all .yaml/.yml files) |
| `-f, --foreground` | Run in foreground (no daemonization) |
| `-v, --verbose` | Verbose log output |
| `-s, --strict` | Enable strict config validation (default) |
| `-p, --permissive` | Allow unknown parameters with warnings |
| `-h, --help` | Display help information |

## 4. systemd Service Management

### 4.1 Basic Operations

```bash
# Start service
sudo systemctl start firewall-daemon

# Stop service
sudo systemctl stop firewall-daemon

# Restart service
sudo systemctl restart firewall-daemon

# Check status
sudo systemctl status firewall-daemon

# View logs
sudo journalctl -u firewall-daemon -f
```

### 4.2 Enable at Boot

```bash
sudo systemctl enable firewall-daemon
```

### 4.3 Service Hardening

The `firewall-daemon.service` includes the following security hardening:
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH`

## 5. Monitoring & Observability

### 5.1 Logs

```bash
# Kernel logs
dmesg | grep firewall

# Daemon logs
sudo journalctl -u firewall-daemon -n 100
```

### 5.2 Prometheus Metrics

```bash
curl http://localhost:9119/metrics   # Metrics endpoint
curl http://localhost:9119/health    # Health check
curl http://localhost:9119/healthz   # Health check (K8s compatible)
```

#### Kernel Module Metrics (4 items)

| Metric | Type | Description |
|--------|------|-------------|
| `firewall_kernel_banned_ips_current` | gauge | Current active bans |
| `firewall_kernel_total_bans_total` | counter | Total cumulative bans |
| `firewall_kernel_total_unbans_total` | counter | Total cumulative unbans |
| `firewall_kernel_whitelist_count` | gauge | Whitelist entry count |

#### Daemon Metrics (10 items)

| Metric | Type | Description |
|--------|------|-------------|
| `firewall_daemon_lines_parsed_total` | counter | Total parsed log lines |
| `firewall_daemon_ips_extracted_total` | counter | Total extracted IP addresses |
| `firewall_daemon_ips_banned_total` | counter | Total banned IPs |
| `firewall_daemon_failed_attempts_total` | counter | Total failed attempts |
| `firewall_daemon_config_reloads_total` | counter | Config reload count |
| `firewall_daemon_inotify_events_total` | counter | Total inotify events |
| `firewall_daemon_log_rotations_total` | counter | Log rotation detections |
| `firewall_daemon_lines_skipped_total` | counter | Total skipped log lines |
| `firewall_daemon_regex_matches_total` | counter | Successful regex matches |
| `firewall_daemon_uptime_seconds` | gauge | Daemon uptime (seconds) |

### 5.3 Grafana Dashboard

Prometheus configuration example:
```yaml
scrape_configs:
  - job_name: 'firewall'
    static_configs:
      - targets: ['localhost:9119']
```

## 6. Troubleshooting

### 6.1 Module Load Failure

```bash
# Check kernel version
uname -r

# Check module dependencies
modinfo build/kernel-module/firewall.ko

# View kernel logs
dmesg | tail -20
```

### 6.2 Daemon Startup Failure

```bash
# Check configuration file
sudo ./build/daemon/firewall-daemon -c config/default.yaml --strict

# Check logs
sudo journalctl -u firewall-daemon -n 50 --no-pager

# Check port usage
sudo ss -tlnp | grep 9119
```

### 6.3 Bans Not Taking Effect

```bash
# Check if module is loaded
lsmod | grep firewall

# Check procfs interface
cat /proc/firewall/bans

# Check statistics
cat /proc/firewall/stats

# Check kernel logs
dmesg | grep firewall
```

### 6.4 Performance Issues

```bash
# Check ban table usage
cat /proc/firewall/stats | grep current_bans

# Check Prometheus metrics
curl -s http://localhost:9119/metrics | grep firewall

# Check system load
top -p $(pgrep firewall-daemon)
```

## 7. Maintenance Operations

### 7.1 Hot Config Reload

```bash
# Reload after modifying configuration
sudo kill -HUP $(cat /run/firewall-daemon.pid)

# Or use systemctl
sudo systemctl reload firewall-daemon
```

### 7.2 State Save/Restore

```bash
# Manually save state
echo "save /var/lib/firewall/state.bin" | sudo tee /proc/firewall/config

# Manually restore state
echo "restore /var/lib/firewall/state.bin" | sudo tee /proc/firewall/config
```

### 7.3 Clean Expired Bans

Expired bans are automatically cleaned by kernel timers — no manual intervention required.

## 8. Known Limitations

| Limitation | Description |
|------------|-------------|
| Ban Capacity | Maximum 1024 IPs |
| Whitelist Capacity | Maximum 64 entries |
| IPv6 Support | IPv4 only |
| Fragmented Packets | Cannot inspect fragmented packets, forwarded directly |
| Kernel Version | Requires 5.15+ kernel |

## 9. Performance Benchmarks

| Operation | Latency | Description |
|-----------|---------|-------------|
| Ban Lookup | <1 μs | O(1) hash lookup |
| Packet Filtering | <0.5 μs | Netfilter hook |
| Log Parsing | ~10 μs | PCRE2 JIT accelerated |
| Failure Tracking | <1 μs | khash O(1) insertion |
