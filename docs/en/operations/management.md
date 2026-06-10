# Management Commands

This page lists the real commands for day-to-day management of Linux
Firewall. All runtime operations are performed through `/proc/firewall/`
(see [ProcFS Interface](../configuration/procfs.md)) and systemd — the
project does not provide a separate CLI wrapper.

## Service Management

| Action | Command |
|--------|---------|
| Start daemon | `sudo systemctl start firewall-daemon` |
| Stop daemon | `sudo systemctl stop firewall-daemon` |
| Restart daemon | `sudo systemctl restart firewall-daemon` |
| Check service status | `systemctl status firewall-daemon` |
| Enable at boot | `sudo systemctl enable firewall-daemon` |
| Reload YAML config (no interruption) | `sudo systemctl reload firewall-daemon` |
| Validate config syntax | `sudo firewall-daemon -c /etc/firewall/default.yaml` (runs in foreground so errors are visible) |

`firewall-daemon` accepts only these options:

| Option | Meaning |
|--------|---------|
| `-c <file>` | Load a single YAML config file |
| `-C <dir>` | Load all YAML files in the directory (alphabetical order) |
| `--daemon` | Daemonize (fork into background) |

## Kernel Module

| Action | Command |
|--------|---------|
| Load module | `sudo modprobe firewall` |
| Load with parameters | `sudo modprobe firewall fw_ban_time=600 fw_max_bans=4096` |
| Check if loaded | `lsmod \| grep firewall` |
| Unload module | `sudo rmmod firewall` |
| Module metadata | `modinfo firewall` |

## Ban Management

```bash
# Ban (default duration fw_ban_time)
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# Ban (specific seconds)
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans

# Permanent ban
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# Unban
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# Batch ban from file (one IP per line)
while read ip; do echo "$ip" | sudo tee -a /proc/firewall/bans; done < ip_list.txt

# Clear all bans (no built-in command — see below)
```

Clear all bans: the module does not provide a one-shot "clear" command.
Unban each IP in a loop:

```bash
while read -r line; do
  ip=$(echo "$line" | awk '/^[0-9]/ {print $1}')
  [ -n "$ip" ] && echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null
done < <(cat /proc/firewall/bans)
```

Or reload the module to fully reset kernel state (warning: also wipes
non-persistent bans):

```bash
sudo rmmod firewall && sudo modprobe firewall fw_ban_time=600
```

## Whitelist Management

```bash
# View
cat /proc/firewall/whitelist

# Add IP / CIDR
echo "10.0.0.1" | sudo tee /proc/firewall/whitelist
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist

# Remove
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

> Whitelist is capped at 64 entries. Entries declared in
> `/etc/firewall/*.yaml` are pushed by the daemon on
> `systemctl restart firewall-daemon`.

## Status and Statistics

```bash
# Runtime configuration (ban_time, current entry counts)
cat /proc/firewall/config

# Counters (total_bans, total_unbans, packets_dropped, etc.)
cat /proc/firewall/stats

# Prometheus metrics (default :9119)
curl http://localhost:9119/metrics
```

Jail-level statistics are exposed through Prometheus metrics
(`firewall_kernel_*`) and the daemon log. The procfs interface does not
provide a per-jail table directly.

## Logs

```bash
# Daemon log
tail -f /var/log/firewall.log

# Kernel log (module output)
sudo dmesg --follow | grep -i firewall

# By severity
sudo dmesg --level=err,warn | grep -i firewall
```

To change the daemon log level, edit `global.log_level` in
`/etc/firewall/default.yaml` and `systemctl reload firewall-daemon`.

## Configuration

| Action | Command |
|--------|---------|
| Validate YAML syntax | `yamllint /etc/firewall/` |
| Dry-run (foreground; see startup log without staying resident) | `sudo firewall-daemon -c /etc/firewall/default.yaml` |
| Apply config (hot reload) | `sudo systemctl reload firewall-daemon` |
| View current runtime config | `cat /proc/firewall/config` (runtime fields only) |

> Field reference and examples: see
> [Configuration — YAML Config](../configuration/yaml-config.md).

## Command Quick Reference

| Purpose | Command |
|---------|---------|
| Start | `sudo systemctl start firewall-daemon` |
| Stop | `sudo systemctl stop firewall-daemon` |
| Restart | `sudo systemctl restart firewall-daemon` |
| Reload config | `sudo systemctl reload firewall-daemon` |
| Load module | `sudo modprobe firewall` |
| Unload module | `sudo rmmod firewall` |
| View bans | `cat /proc/firewall/bans` |
| Ban IP | `echo "<ip> [<seconds>]" \| sudo tee /proc/firewall/bans` |
| Unban IP | `echo "unban <ip>" \| sudo tee /proc/firewall/bans` |
| View whitelist | `cat /proc/firewall/whitelist` |
| Add whitelist | `echo "<ip-or-cidr>" \| sudo tee /proc/firewall/whitelist` |
| Remove whitelist | `echo "remove <ip-or-cidr>" \| sudo tee /proc/firewall/whitelist` |
| View runtime config | `cat /proc/firewall/config` |
| View counters | `cat /proc/firewall/stats` |
| Daemon log | `tail -f /var/log/firewall.log` |
| Kernel log | `sudo dmesg \| grep -i firewall` |
| Prometheus metrics | `curl http://localhost:9119/metrics` |
