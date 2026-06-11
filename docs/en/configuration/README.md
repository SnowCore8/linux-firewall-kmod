# Configuration

This section describes the configuration methods and options for the Linux Firewall Kernel Module.

## Configuration File Locations

| File | Path | Purpose |
|------|------|---------|
| Main config | `/etc/firewall/default.yaml` | Global settings and jail definitions |
| Database | `/var/lib/firewall/bans.db` | SQLite persistent ban records |
| Log file | `/var/log/firewall.log` | Daemon log (independent of syslog) |

## Configuration Hierarchy

```mermaid
graph TD
    ROOT["default.yaml"]

    subgraph GLOBAL["global Global settings"]
        G1[log_level]
        G2[log_file]
        G3[db_path]
    end

    subgraph WHITELIST["whitelist IP whitelist entries"]
        W1["<IP/CIDR>"]
    end

    subgraph JAILS["jails Jail definitions"]
        J_NAME[name]
        J1[enabled]
        J2[log_path]
        J_FILTER[filter]
        J_REGEX[regex]
        J_ACTION[action]
        J_BAN[ban_time]
        J_FIND[find_time]
        J_MAX[max_retries]
        J_PORT[port]
        J_PROTO[protocol]
    end

    ROOT --> GLOBAL
    GLOBAL --> G1
    GLOBAL --> G2
    GLOBAL --> G3

    ROOT --> WHITELIST
    WHITELIST --> W1

    ROOT --> JAILS
    JAILS --> J_NAME
    J_NAME --> J1
    J_NAME --> J2
    J_NAME --> J_FILTER
    J_FILTER --> J_REGEX
    J_NAME --> J_ACTION
    J_ACTION --> J_BAN
    J_ACTION --> J_FIND
    J_ACTION --> J_MAX
    J_NAME --> J_PORT
    J_NAME --> J_PROTO
```

## Global Configuration Reference

### `log_file` (Independent log file)

- **Type**: string path
- **Default**: `/var/log/firewall.log` (pre-created by debian package)
- **Description**: The daemon tees logs to this file in addition to syslog. File uses `O_APPEND` mode for atomic appends, with `fflush` after each write.
- **Typical usage**: `grep Banned /var/log/firewall.log | tail -10` to analyze ban records
- **Leave empty**: syslog-only, no file is created
- **Path restriction**: must be under `/var/log`, `/etc`, `/home`, or `/srv` (security whitelist)
- **Hot reload**: sending SIGHUP while `log_file` changes will close the old file and open the new one without restart

### `log_level` (Runtime log level)

- **Type**: integer (0..4)
- **Default**: `3` (INFO)
- **Description**: Runtime filter threshold; logs above this level are discarded
- **Allowed values**:
  - `0` = NONE (no logs at all)
  - `1` = ERR (errors only)
  - `2` = WARN (errors + warnings)
  - `3` = INFO (default, day-to-day operations)
  - `4` = DEBUG (all levels, including development debugging)
- **Hot reload**: SIGHUP-triggered config reload applies `log_level` change immediately

### Example

```yaml
defaults:
  # ... other defaults ...
  log_file: /var/log/firewall.log
  log_level: 3
```

## Configuration Loading Order

1. Reads `/etc/firewall/default.yaml` on system startup
2. Parses global configuration
3. Loads whitelist into kernel (up to 64 entries)
4. Initializes each enabled jail
5. Registers inotify watches for log files
6. Restores unexpired bans from SQLite

## Runtime Modifications

Configuration can be modified at runtime via:

| Method | Description | Persists After Restart |
|--------|-------------|----------------------|
| ProcFS interface | Write directly to `/proc/firewall/` | No |
| Edit YAML + restart | `systemctl restart firewall` | Yes |
| firewall-daemon commands | Dynamic management | Partial (depends on operation) |

## Configuration Validation

After modifying the configuration, verify it is correct:

```bash
# Check YAML syntax
cat /etc/firewall/default.yaml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"

# Reload and check status
sudo systemctl restart firewall
sudo systemctl status firewall
```