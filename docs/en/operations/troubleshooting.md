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

# Validate config syntax
sudo firewall-daemon -c /etc/firewall/default.yaml
# or with yamllint
yamllint /etc/firewall/

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

# Rebuild kernel module with debug symbols
make clean && make debug DL=2
sudo rmmod firewall 2>/dev/null
sudo modprobe firewall fw_ban_time=600
# Also set global.log_level: debug in /etc/firewall/default.yaml
sudo systemctl restart firewall-daemon

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

### Permanent ban SQLite not created

**Symptoms**:

- Daemon is running but `/var/lib/firewall/bans.db` does not exist
- Prometheus `firewall_daemon_*` metrics are working normally
- `journalctl -u firewall-daemon` does not contain "SQLite database initialized"

**Diagnosis**:

1. Check the actual value of `cfg.permanent_ban_enabled`. If it is `false`, the daemon skips SQLite initialization entirely.
2. Check the location of `permanent_ban_enabled` and `permanent_db_path` in `/etc/firewall/default.yaml`.
3. If those fields are at the top level (after `jails:`), the Rust parser silently ignores them — any field outside the `defaults:` block never makes it into the `Config` struct.

**Fix**:

```yaml
# Wrong (fields at top level, silently ignored):
jails:
  sshd: ...
permanent_ban_enabled: true        # ← top level, parser can't see it
permanent_db_path: "/var/lib/firewall/bans.db"

# Correct (fields must live inside defaults:):
defaults:
  ...
  permanent_ban_enabled: true      # ← inside defaults:
  permanent_db_path: "/var/lib/firewall/bans.db"
jails:
  sshd: ...
```

### Daemon cannot open /var/log/firewall.log

**Symptoms**: At startup the log shows:

```
WARN  Failed to open log file /var/log/firewall.log: Read-only file system (os error 30) (falling back to syslog-only)
```

**Cause**: The systemd unit's `ProtectSystem=strict` makes `/var/log` read-only from the daemon's point of view. `/var/log` is owned by the `system` namespace, and the daemon has no write access.

**Fix (not recommended)**: Add `ReadWritePaths=/var/log` to the systemd unit:

```bash
sudo systemctl edit firewall-daemon
# Add:
# [Service]
# ReadWritePaths=/var/log
```

But this is the deliberate "secure default" — the daemon should not have permission to write anywhere, and falling back to syslog-only is a sensible choice. `journalctl -u firewall-daemon` still shows all log output.

**Alternative**: Point `log_file` at a `/var/log/firewall/` subdirectory, then grant write access to that subdirectory only (much narrower than opening all of `/var/log`):

```yaml
# /etc/firewall/default.yaml
log_file: /var/log/firewall/firewall.log
```

```bash
sudo mkdir -p /var/log/firewall
sudo chown root:root /var/log/firewall
sudo chmod 755 /var/log/firewall
sudo systemctl edit firewall-daemon
# [Service]
# ReadWritePaths=/var/lib/firewall /var/log/firewall
sudo systemctl restart firewall-daemon
```

### Tests report "bans.db not found"

**Symptoms**: `make test` running `tests/suites/12_permanent_ban.sh` fails with "bans.db not found" or "no such file or directory".

**Cause**: Same root cause as [Permanent ban SQLite not created](#permanent-ban-sqlite-not-created) — `permanent_ban_enabled: true` was not placed inside `defaults:`, so the daemon skipped SQLite initialization.

**Fix**: Move `permanent_ban_enabled` and `permanent_db_path` into the `defaults:` block, then:

```bash
sudo systemctl restart firewall-daemon
ls -la /var/lib/firewall/bans.db   # should now exist
make test
```

### `make deb` reports "no rule to make target"

**Symptoms**:

```
make: *** No rule to make target 'deb'.  Stop.
```

**Cause**: Older Makefiles (pre-v2.2.0) did not have a `deb:` rule. Fixed in v2.2.1 onwards (`make help` also lists `deb`).

**Fix**:

- Upgrade to v2.2.1+:
  ```bash
  git pull origin main
  make deb
  ```
- Or invoke `./build-deb.sh` directly (bypasses `make`):
  ```bash
  ./build-deb.sh
  ```

### `cargo: not found` under sudo

**Symptoms**: `sudo ./tests/run_tests.sh` reports:

```
make: cargo: No such file or directory
make: *** [Makefile:100: daemon] Error 127
```

**Cause**: `sudo`'s default `secure_path` does not include `~/.cargo/bin`, but rustup installs `cargo` there.

**Fix**:

- `source ~/.cargo/env` before invoking sudo:
  ```bash
  source ~/.cargo/env
  sudo -E ./tests/run_tests.sh
  ```
- Or use `sudo -E` to preserve the current PATH (still requires `source` first):
  ```bash
  source ~/.cargo/env
  sudo -E make test
  ```
- v2.2.1 onwards `tests/run_tests.sh` auto-sources `~/.cargo/env` (see `tests/run_tests.sh:134-139`), so re-running should just work.

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
journalctl -u firewall-daemon --since "1 day ago" > firewall-diag-journal.txt
dmesg | grep -i firewall > firewall-diag-dmesg.txt
cat /proc/firewall/bans /proc/firewall/whitelist /proc/firewall/config /proc/firewall/stats \
    > firewall-diag-procfs.txt
echo "# Captured $(date)" > firewall-diag-$(date +%Y%m%d).txt
cat firewall-diag-journal.txt firewall-diag-dmesg.txt firewall-diag-procfs.txt \
    >> firewall-diag-$(date +%Y%m%d).txt
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