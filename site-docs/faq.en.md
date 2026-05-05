# Frequently Asked Questions (FAQ)

**Version**: v2.0  
**Last Updated**: 2026-05-05

---

## General Questions

### What is Firewall?

Firewall is a **Linux kernel module version of fail2ban** that moves IP banning logic from userspace to kernelspace. It uses Netfilter hooks for real-time IP banning at the packet level, achieving lower latency and higher performance than traditional fail2ban.

The core architecture is a **dual-layer design**:
- **Kernelspace module** (C language): Performs packet filtering via Netfilter `NF_INET_PRE_ROUTING` hook, using hash tables for O(1) lookups
- **Userspace daemon** (C language): Monitors log files via inotify, performs regex parsing with PCRE2, and communicates with the kernel module via procfs interface

### How is it different from fail2ban?

| Aspect | fail2ban | Firewall |
|--------|----------|----------|
| Ban Location | iptables/nftables (userspace rules) | Netfilter kernel hooks |
| Response Latency | Seconds | Milliseconds |
| Language | Python | C (kernel module + daemon) |
| Lookup Performance | Linear rule traversal | Hash table O(1) lookup |
| Config Format | INI | YAML |
| Config Validation | Permissive | Strict (default) |
| Persistence | Filesystem | SQLite database |
| Ban Capacity | No hard limit | 1024 IPs |
| Metrics | No built-in | Prometheus export (port 9119) |

> For detailed comparison, refer to the [Migration Guide from fail2ban](migration.md).

### What scenarios is this project suitable for?

| Recommended | Not Recommended |
|-------------|-----------------|
| Personal VPS / Cloud server protection | Production DDoS protection |
| SSH brute-force protection | Enterprise environments requiring audit compliance |
| Development / testing environments | Large-scale distributed deployments |
| Web service (Nginx/Apache) protection | Environments requiring IPv6 support |
| Database (MySQL/Redis) protection | Scenarios with more than 1024 banned IPs |

### Is IPv6 supported?

**No.** The current version only supports IPv4 address banning and whitelist management. IPv6 support is planned — please watch for future releases.

---

## Installation & Configuration

### What are the system requirements?

| Item | Requirement |
|------|-------------|
| Operating System | Linux |
| Kernel Version | 5.15+ |
| CPU Architecture | x86_64 |
| Privileges | root (for loading kernel module and managing procfs) |
| Disk Space | ~5MB (including build artifacts) |
| Memory | ~10MB (kernel module + daemon) |

### How do I install dependencies?

**Debian / Ubuntu:**

```bash
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev
```

**RHEL / CentOS / AlmaLinux:**

```bash
sudo dnf install -y gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel
```

> If `libmicrohttpd-dev` or `libpcre2-dev` is not available in your package manager, you may need to enable the EPEL repository or compile from source.

### Where are the configuration files?

| Location | Description |
|----------|-------------|
| `config/` | Built-in configuration templates (12 preset services) |
| `/etc/firewall/` | Production environment configuration directory (after installation) |

After installation, all configuration files are copied to `/etc/firewall/`:

```bash
ls /etc/firewall/
# default.yaml  nginx.yaml  apache.yaml  mysql.yaml  ...
```

### How do I add custom service protection?

Create a new YAML configuration file in the `/etc/firewall/` directory, for example `myapp.yaml`:

```yaml
myapp:
  enabled: true
  log_files:
    - /var/log/myapp/access.log
  max_retries: 3
  findtime: 300
  ban_time: 1800
  regex: "Authentication failure.*from\s+<IP>"
```

> **Note**: The regex expression must include the `<IP>` placeholder for IP extraction.

Apply changes via hot config reload:

```bash
sudo kill -HUP $(cat /run/firewall-daemon.pid)
```

Or restart the service:

```bash
sudo systemctl restart firewall-daemon
```

---

## Running & Usage

### How do I view currently banned IPs?

**Method 1: Via procfs interface**

```bash
cat /proc/firewall/bans
```

Example output:
```
192.168.1.100    expires: 2026-05-05 12:30:00    permanent: no
10.0.0.50        expires: permanent              permanent: yes
```

**Method 2: Via Prometheus metrics**

```bash
curl -s http://localhost:9119/metrics | grep firewall_kernel_banned_ips_current
# firewall_kernel_banned_ips_current 15
```

**Method 3: Via statistics**

```bash
cat /proc/firewall/stats
```

### How do I manually ban/unban an IP?

**Ban an IP (default duration):**

```bash
echo "1.2.3.4" | sudo tee /proc/firewall/bans
```

**Ban an IP (custom duration, in seconds):**

```bash
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans  # Ban for 1 hour
```

**Permanent ban:**

```bash
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans
```

> Permanent bans are saved to the SQLite database (if `permanent_ban_enabled` is enabled) and persist across restarts.

**Unban an IP:**

```bash
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
```

### How do I whitelist an IP/subnet?

**Add to whitelist:**

```bash
# Single IP
echo "192.168.1.1/32" | sudo tee /proc/firewall/whitelist

# Entire subnet
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist
echo "172.16.0.0/12" | sudo tee /proc/firewall/whitelist
```

**View whitelist:**

```bash
cat /proc/firewall/whitelist
```

**Remove from whitelist:**

```bash
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

> The whitelist limit is 64 entries. System IPs are automatically discovered and added to the whitelist to prevent accidental self-banning.

### What is the ban limit? What happens when it's full?

| Item | Limit |
|------|-------|
| Banned IPs | 1024 |
| Whitelist Entries | 64 |

**Behavior when ban table is full:**
- New ban requests are **rejected**, the kernel module returns an error
- The daemon log records a `ban table full` warning

**Solutions:**

1. **Wait for expired bans to be automatically cleaned**: Kernel timers periodically clean expired entries
2. **Manually unban unnecessary IPs**:
   ```bash
   echo "unban <old_ip>" | sudo tee /proc/firewall/bans
   ```
3. **Shorten ban duration**: Reduce the `ban_time` value in configuration to let bans expire faster
4. **Use permanent ban filtering**: Only set confirmed attackers to permanent ban (`ban_time: 0`)

---

## Troubleshooting

### What should I do if the module fails to load?

**Step 1: Check kernel version**

```bash
uname -r
# Requires 5.15+ kernel
```

**Step 2: Check if kernel headers are installed**

```bash
ls /lib/modules/$(uname -r)/build/Makefile
# If not found, install the corresponding kernel headers
```

**Step 3: View kernel logs**

```bash
dmesg | tail -20
dmesg | grep firewall
```

**Step 4: Check module information**

```bash
modinfo build/kernel-module/firewall.ko
```

**Step 5: Manually load and observe errors**

```bash
sudo insmod build/kernel-module/firewall.ko
# Observe error output
```

**Common issues:**
- `Invalid module format`: Kernel version mismatch with build environment, recompile needed
- `Unknown symbol`: Kernel API changes, need to adapt to current kernel version

### What should I do if the daemon fails to start?

**Step 1: Check configuration file syntax**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml --strict
# Observe config parsing error output
```

**Step 2: Check systemd logs**

```bash
sudo journalctl -u firewall-daemon -n 50 --no-pager
```

**Step 3: Check port usage**

```bash
sudo ss -tlnp | grep 9119
# If port is occupied, change metrics_port in configuration
```

**Step 4: Check if kernel module is loaded**

```bash
lsmod | grep firewall
# If not loaded, load the module first:
sudo insmod build/kernel-module/firewall.ko
```

**Step 5: Debug in foreground mode**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
# Run in foreground with verbose output
```

### What should I do if bans are not taking effect?

**Step 1: Confirm kernel module is loaded**

```bash
lsmod | grep firewall
```

**Step 2: Confirm procfs interface exists**

```bash
ls -la /proc/firewall/
# Should include bans, whitelist, config, stats
```

**Step 3: Manually test banning**

```bash
echo "1.2.3.4" | sudo tee /proc/firewall/bans
cat /proc/firewall/bans  # Confirm ban was added
```

**Step 4: Check statistics**

```bash
cat /proc/firewall/stats
```

Pay attention to whether the `packets_dropped` counter is increasing:
- If `packets_dropped` is not changing, banned packets are not reaching the kernel module
- If `packets_dropped` is increasing, bans are working

**Step 5: Check kernel logs**

```bash
dmesg | grep firewall
```

**Step 6: Confirm IP is not in the whitelist**

```bash
cat /proc/firewall/whitelist
# If the target IP is in the whitelist, the ban will not take effect
```

### How do I view logs?

**Kernel module logs:**

```bash
# Real-time viewing
dmesg -w | grep firewall

# View last 100 entries
dmesg | grep firewall | tail -100
```

**Daemon logs (systemd):**

```bash
# Real-time follow
sudo journalctl -u firewall-daemon -f

# View last 100 entries
sudo journalctl -u firewall-daemon -n 100 --no-pager

# View today's logs
sudo journalctl -u firewall-daemon --since today
```

**Daemon logs (foreground mode):**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
```

> Use the `-v` (verbose) parameter for more detailed debug information.

---

## Performance & Limitations

### How is the performance? How much faster than fail2ban?

| Operation | Firewall | fail2ban | Description |
|-----------|----------|----------|-------------|
| Ban Lookup | <1 μs | ~10-100 μs | O(1) hash vs linear traversal |
| Packet Filtering | <0.5 μs | ~1-5 ms | Kernel Netfilter vs iptables userspace rules |
| Ban Response | Milliseconds | Seconds | Direct kernel write vs calling iptables command |
| Log Parsing | ~10 μs | ~50-100 μs | PCRE2 JIT vs Python re |
| Failure Tracking | <1 μs | ~5-10 μs | khash O(1) vs Python dict |
| Memory Usage | ~10 MB | ~50-100 MB | Lightweight C vs Python runtime |

**Summary**: In terms of ban response speed and resource usage, Firewall is **1-2 orders of magnitude** faster than fail2ban.

### What are the known limitations?

| Limitation | Description | Impact |
|------------|-------------|--------|
| Ban Capacity | Maximum 1024 IPs | May not be sufficient for large-scale attacks |
| Whitelist Capacity | Maximum 64 entries | Large networks require careful subnet planning |
| IPv6 Support | IPv4 only | Cannot be used in pure IPv6 environments |
| Fragmented Packet Handling | Cannot inspect fragmented packets | Fragmented packets are forwarded directly |
| Kernel Version | Requires 5.15+ | Old kernels (e.g., CentOS 7's 3.10) are incompatible |
| Config Hot Reload | Requires SIGHUP signal | Some config changes require restart |
| Log Format | Depends on regex matching | Non-standard log formats require custom regex |

### Can it be used in production?

**Yes, but consider the following factors:**

**Scenarios suitable for production:**
- Personal VPS / small server protection
- SSH brute-force protection
- Basic web service protection
- Scenarios with < 1024 banned IPs

**Scenarios requiring careful evaluation:**
- Large-scale DDoS protection (use dedicated hardware firewalls)
- Enterprise environments requiring audit compliance (need additional logging solutions)
- Pure IPv6 networks (currently not supported)
- High-traffic scenarios with more than 1024 banned IPs

**Production recommendations:**
1. Enable permanent ban feature (`permanent_ban_enabled: true`)
2. Configure Prometheus monitoring and alerting
3. Regularly back up the SQLite database
4. Use systemd service management (with security hardening)
5. Keep fail2ban as a temporary rollback option

---

## Migration

### How do I migrate from fail2ban?

Refer to the [Migration Guide from fail2ban](migration.md) for complete migration steps.

**Quick migration overview:**

1. **Stop fail2ban**:
   ```bash
   sudo systemctl stop fail2ban
   sudo systemctl disable fail2ban
   ```

2. **Backup configuration**:
   ```bash
   sudo cp -r /etc/fail2ban /etc/fail2ban.backup
   ```

3. **Install Firewall**:
   ```bash
   make && sudo make install
   ```

4. **Migrate configuration**: Convert fail2ban jail configuration to YAML format (refer to migration guide)

5. **Start Firewall**:
   ```bash
   sudo systemctl start firewall-daemon
   ```

### Can it run alongside fail2ban?

**Not recommended.** Reasons:

| Issue | Description |
|-------|-------------|
| Port Conflicts | Both may monitor the same log files, causing duplicate bans |
| Rule Conflicts | fail2ban uses iptables, Firewall uses Netfilter hooks, which may conflict |
| Resource Waste | Dual monitoring of the same log files wastes system resources |
| Management Confusion | Unclear ban sources, difficult troubleshooting |

**Recommended approach:**
1. Completely stop and disable fail2ban
2. Migrate configuration to Firewall
3. Verify Firewall is working correctly
4. Keep fail2ban as a rollback option (not started)

If you must coexist during a transition period, ensure:
- fail2ban and Firewall monitor **different log files**
- fail2ban uses a different ban chain (custom iptables chain)
- Closely monitor for conflicts between the two
