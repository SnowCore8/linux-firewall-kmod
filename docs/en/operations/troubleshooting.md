# Troubleshooting

This document describes common issues and solutions for the Linux Firewall Kernel Module.

## Diagnostic Tools

### Quick Diagnostic Script

```bash
#!/bin/bash
# firewall-diagnose.sh

echo "=== Linux Firewall Diagnosis ==="
echo ""

# 1. Kernel module
echo "1. Kernel Module"
echo "   Loaded: $(lsmod | grep -c firewall)"
lsmod | grep firewall
echo ""

# 2. Daemon
echo "2. Daemon"
systemctl status firewall --no-pager
echo ""

# 3. ProcFS
echo "3. ProcFS"
cat /proc/firewall/config
echo ""

# 4. Ban statistics
echo "4. Statistics"
cat /proc/firewall/stats
echo ""

# 5. Kernel log
echo "5. Kernel Log (last 20 lines)"
dmesg | grep firewall | tail -20
echo ""

# 6. Daemon log
echo "6. Daemon Log (last 20 lines)"
tail -20 /var/log/firewall.log
echo ""

# 7. Prometheus
echo "7. Prometheus Metrics"
curl -s http://localhost:9119/metrics | head -20
```

## Common Issues

### Module Cannot Load

**Symptoms**:

```
modprobe: ERROR: could not insert 'firewall': Operation not permitted
```

**Causes and Solutions**:

| Cause | Solution |
|-------|----------|
| Not root user | Use `sudo modprobe firewall` |
| Secure Boot enabled | Sign module or disable Secure Boot |
| Kernel version mismatch | Recompile: `make clean && make` |
| Missing kernel headers | Install: `apt install linux-headers-$(uname -r)` |

### Daemon Cannot Start

**Symptoms**:

```
Job for firewall-daemon.service failed because the control process exited with error code.
```

**Troubleshooting Steps**:

```bash
# View detailed errors
journalctl -u firewall -n 50

# Check configuration file
firewall-daemon check-config

# Check port usage
ss -tlnp | grep 9119

# Check dependency libraries
ldd /usr/local/sbin/firewall-daemon
```

**Common Causes**:

| Cause | Solution |
|-------|----------|
| Config syntax error | Fix YAML format |
| Port in use | Change config or stop occupying process |
| Missing library | Install missing library |
| Log directory missing | `mkdir -p /var/lib/firewall` |
| Database directory permissions | `chown root:root /var/lib/firewall` |

### IP Not Being Banned

**Symptoms**: Log shows match success, but IP can still access.

**Troubleshooting Steps**:

```bash
# 1. Check if kernel module is loaded
lsmod | grep firewall

# 2. Check if IP is in whitelist
cat /proc/firewall/whitelist

# 3. Check if ban was written successfully
cat /proc/firewall/bans

# 4. Check kernel log
dmesg | grep firewall

# 5. Verify packets go through Hook
# Add pr_info debug output in module
```

**Common Causes**:

| Cause | Solution |
|-------|----------|
| IP in whitelist | Remove IP from whitelist |
| Module not loaded | `sudo modprobe firewall` |
| Port mismatch | Check jail's port config |
| Protocol mismatch | Check jail's protocol config |
| Hash table full | Clear expired bans or increase capacity |

### Regex Match Failures

**Symptoms**: Log contains matching content but no ban is triggered.

**Troubleshooting Steps**:

```bash
# 1. Enable debug mode
sudo systemctl stop firewall
sudo firewall-daemon -d start

# 2. View match logs
tail -f /var/log/firewall.log | grep "match"

# 3. Test regex
echo "Failed password for root from 192.168.1.100" | \
    grep -P 'Failed password for (?:invalid user )?.+ from \d+\.\d+\.\d+\.\d+'
```

**Common Causes**:

| Cause | Solution |
|-------|----------|
| Regex syntax error | Test PCRE2 with online tools |
| `<HOST>` not replaced | Check spelling in config |
| Log format changed | Update regex expression |
| inotify not triggered | Check file permissions and rotation |

### Performance Issues

**Symptoms**: Increased network latency or high CPU usage.

**Troubleshooting Steps**:

```bash
# 1. Check ban count
cat /proc/firewall/stats

# 2. Check hash table usage
curl -s http://localhost:9119/metrics | grep hash_table

# 3. Check packet drop rate
curl -s http://localhost:9119/metrics | grep dropped

# 4. Check kernel CPU usage
top -b -n 1 | head -20
```

**Optimization Suggestions**:

| Problem | Solution |
|---------|----------|
| Too many bans | Reduce `find_time` or increase `max_retries` |
| Large log file | Configure log rotation |
| Database bloat | Manually clean expired records |

### Log File Monitoring Failure

**Symptoms**: inotify events lost or new logs not detected.

**Troubleshooting Steps**:

```bash
# Check inotify limits
cat /proc/sys/fs/inotify/max_user_watches
cat /proc/sys/fs/inotify/max_queued_events

# Increase limits
echo 524288 | sudo tee /proc/sys/fs/inotify/max_user_watches
```

**Persistent Configuration**:

```
# /etc/sysctl.d/99-inotify.conf
fs.inotify.max_user_watches = 524288
fs.inotify.max_queued_events = 32768
```

### Bans Lost After Reboot

**Symptoms**: All ban records lost after server restart.

**Troubleshooting Steps**:

```bash
# Check SQLite database
ls -la /var/lib/firewall/bans.db

# Check database content
sqlite3 /var/lib/firewall/bans.db "SELECT COUNT(*) FROM bans;"

# Check daemon startup log
journalctl -u firewall | grep -i "restore\|recover"
```

**Common Causes**:

| Cause | Solution |
|-------|----------|
| Wrong database path | Check `db_path` config |
| Database permissions | `chmod 644 /var/lib/firewall/bans.db` |
| SQLite corruption | Backup and rebuild database |

## Kernel Debugging

### Enable Debug Output

```bash
# Compile debug version
make debug DL=2

# Reinstall
sudo make install
sudo modprobe -r firewall
sudo modprobe firewall

# View kernel log
dmesg -w | grep firewall
```

### Debug Levels

```bash
# Modify in source code
#define DEBUG_LEVEL 2  # 0=off, 1=basic, 2=verbose, 3=all
```

### RCU Debugging

```bash
# Check RCU status
cat /sys/kernel/debug/rcu/rcudata

# Check RCU callbacks
cat /sys/kernel/debug/rcu/rcu_pending
```

## Getting Help

### Collect Diagnostic Information

```bash
# Collect full diagnostic package
sudo firewall-daemon diagnose > firewall-diag-$(date +%Y%m%d).txt
```

### Report Issues

When submitting an Issue on GitHub, please include:

1. Diagnostic output
2. Configuration file (sanitized)
3. Kernel version: `uname -r`
4. Distribution: `cat /etc/os-release`
5. Steps to reproduce

### Community Support

- GitHub Issues: https://github.com/SnowCore8/linux-firewall-kmod/issues
- Documentation: This GitBook