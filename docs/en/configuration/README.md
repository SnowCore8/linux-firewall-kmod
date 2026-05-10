# Configuration

This section describes the configuration methods and options for the Linux Firewall Kernel Module.

## Table of Contents

- [YAML Config](yaml-config.md) - Configuration file reference
- [Examples](examples.md) - Common scenario templates
- [ProcFS Interface](procfs.md) - Runtime configuration interface

## Configuration File Locations

| File | Path | Purpose |
|------|------|---------|
| Main config | `/etc/fw_fire/fw_fire.yaml` | Global settings and jail definitions |
| Database | `/var/lib/fw_fire/bans.db` | SQLite persistent ban records |
| Log file | `/var/log/fw_fire.log` | Daemon log |

## Configuration Hierarchy

```
fw_fire.yaml
├── global          # Global settings
│   ├── log_level
│   ├── log_file
│   └── db_path
├── whitelist       # IP whitelist entries
│   └[]- <IP/CIDR>
└── jails           # Jail definitions
    └[]- name
        ├── enabled
        ├── log_path
        ├── filter
        │   └── regex
        ├── action
        │   ├── ban_time
        │   ├── find_time
        │   └── max_retries
        ├── port
        └── protocol
```

## Configuration Loading Order

1. Reads `/etc/fw_fire/fw_fire.yaml` on system startup
2. Parses global configuration
3. Loads whitelist into kernel (up to 64 entries)
4. Initializes each enabled jail
5. Registers inotify watches for log files
6. Restores unexpired bans from SQLite

## Runtime Modifications

Configuration can be modified at runtime via:

| Method | Description | Persists After Restart |
|--------|-------------|----------------------|
| ProcFS interface | Write directly to `/proc/fw_fire/` | No |
| Edit YAML + restart | `systemctl restart fw_fire` | Yes |
| fwctl commands | Dynamic management | Partial (depends on operation) |

## Configuration Validation

After modifying the configuration, verify it is correct:

```bash
# Check YAML syntax
cat /etc/fw_fire/fw_fire.yaml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"

# Reload and check status
sudo systemctl restart fw_fire
sudo systemctl status fw_fire
```

---

[中文版本](../../zh/configuration/README.md)
