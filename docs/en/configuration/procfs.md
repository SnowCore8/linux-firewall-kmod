# ProcFS Interface

The Linux Firewall Kernel Module provides runtime management and monitoring through the `/proc/fw_fire/` directory.

## Interface Overview

```
/proc/fw_fire/
├── status          # Module status
├── banned_ips      # Currently banned IP list
├── whitelist       # Current whitelist IP list
├── stats           # Statistics
├── config          # Runtime configuration (write)
├── clear           # Clear banned list (write triggers)
└── version         # Module version
```

## Read Interfaces

### Module Status

```bash
cat /proc/fw_fire/status
```

Output:

```
Firewall Module Status
======================
Module: loaded
Version: 1.0.0
State: active
Banned IPs: 15 / 4096
Whitelisted IPs: 3 / 64
```

| Field | Description |
|-------|-------------|
| `Module` | Module load status |
| `Version` | Module version |
| `State` | Running state: `active`, `inactive` |
| `Banned IPs` | Current bans / total capacity |
| `Whitelisted IPs` | Current whitelist / total capacity |

### Banned IP List

```bash
cat /proc/fw_fire/banned_ips
```

Output:

```
Banned IP List
==============
IP              Jail      Remaining(s)  Protocol  Port
192.168.1.100   sshd      3452          tcp       22
10.0.0.50       nginx     1200          tcp       80
172.16.0.1      postfix   5800          tcp       25
```

| Field | Description |
|-------|-------------|
| `IP` | Banned IP address |
| `Jail` | Jail that triggered the ban |
| `Remaining(s)` | Remaining ban time (seconds) |
| `Protocol` | Banned protocol |
| `Port` | Banned port |

### Whitelist

```bash
cat /proc/fw_fire/whitelist
```

Output:

```
Whitelist
=========
IP/Range
127.0.0.1
192.168.1.0/24
10.0.0.1
```

### Statistics

```bash
cat /proc/fw_fire/stats
```

Output:

```
Statistics
==========
Total ban events:     125
Total unban events:   98
Total packets dropped: 45230
Total packets passed:  1250340
Current banned:       15
```

| Field | Description |
|-------|-------------|
| `Total ban events` | Cumulative ban count |
| `Total unban events` | Cumulative unban count |
| `Total packets dropped` | Cumulative dropped packets |
| `Total packets passed` | Cumulative passed packets |
| `Current banned` | Currently banned IP count |

### Module Version

```bash
cat /proc/fw_fire/version
```

Output:

```
1.0.0
```

## Write Interfaces

### Add Ban

Write ban command to `config`:

```bash
echo "ban 192.168.1.100 3600 tcp 22 sshd" | sudo tee /proc/fw_fire/config
```

Format: `ban <ip> <duration> <protocol> <port> <jail>`

| Parameter | Description |
|-----------|-------------|
| `ip` | IP address to ban |
| `duration` | Ban duration (seconds), 0 = permanent |
| `protocol` | `tcp`, `udp`, `all` |
| `port` | Target port |
| `jail` | Jail name (optional) |

### Remove Ban

```bash
echo "unban 192.168.1.100" | sudo tee /proc/fw_fire/config
```

Format: `unban <ip>`

### Add to Whitelist

```bash
echo "whitelist 192.168.1.50" | sudo tee /proc/fw_fire/config
```

Format: `whitelist <ip>`

> **Limit**: Maximum 64 whitelist entries.

### Remove from Whitelist

```bash
echo "unwhitelist 192.168.1.50" | sudo tee /proc/fw_fire/config
```

Format: `unwhitelist <ip>`

### Clear All Bans

```bash
echo "clear" | sudo tee /proc/fw_fire/clear
```

Or write to `config`:

```bash
echo "clear" | sudo tee /proc/fw_fire/config
```

### Enable/Disable Module

```bash
# Disable (stop processing packets)
echo "disable" | sudo tee /proc/fw_fire/config

# Enable
echo "enable" | sudo tee /proc/fw_fire/config
```

## Access via fwctl

The `fwctl` tool wraps ProcFS operations:

| fwctl Command | ProcFS Operation |
|---------------|-----------------|
| `fwctl status` | Read `/proc/fw_fire/status` |
| `fwctl banned` | Read `/proc/fw_fire/banned_ips` |
| `fwctl whitelist` | Read `/proc/fw_fire/whitelist` |
| `fwctl stats` | Read `/proc/fw_fire/stats` |
| `fwctl ban <ip> <time>` | Write `/proc/fw_fire/config` |
| `fwctl unban <ip>` | Write `/proc/fw_fire/config` |
| `fwctl clear` | Write `/proc/fw_fire/clear` |

## Permission Requirements

| Operation | Permission |
|-----------|------------|
| Read | Root or `fw_fire` group |
| Write | Root |

```bash
# Create fw_fire group
sudo groupadd fw_fire

# Add user to group
sudo usermod -aG fw_fire $USER

# Modify ProcFS file permissions (requires udev rule)
```

## Debugging

### Enable Debug Log

Compile with debug level:

```bash
make debug DL=2
```

View kernel log:

```bash
sudo dmesg | grep fw_fire
```

### Debug Levels

| Level | Description |
|-------|-------------|
| `DL=0` | No debug output |
| `DL=1` | Critical debug info |
| `DL=2` | Verbose debug info |
| `DL=3` | All debug info |

---

[中文版本](../../zh/configuration/procfs.md)
