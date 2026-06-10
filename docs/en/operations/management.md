# Management Commands

This document describes all commands available in the `fwctl` command-line tool.

## fwctl Overview

`fwctl` is the userspace management tool for Linux Firewall, providing a complete command-line interface for managing bans, whitelists, and viewing status.

### Syntax

```bash
fwctl <command> [arguments]
```

### Global Options

| Option | Description |
|--------|-------------|
| `-c, --config <path>` | Specify config file path (default `/etc/firewall/default.yaml`) |
| `-h, --help` | Show help information |
| `-v, --version` | Show version information |
| `-d, --debug` | Enable debug mode |

## Service Management

### Start

```bash
fwctl start
```

Start the daemon and load the kernel module.

### Stop

```bash
fwctl stop
```

Stop the daemon and unload the kernel module.

### Restart

```bash
fwctl restart
```

Restart the daemon.

### Status

```bash
fwctl status
```

Example output:

```
firewall Status
==============
Daemon:     running (PID: 12345)
Module:     loaded
Banned:     15 IPs
Whitelisted: 3 IPs
Uptime:     2d 5h 30m
```

### Reload Configuration

```bash
fwctl reload
```

Sends SIGHUP signal to the daemon to reload YAML configuration without interrupting service.

## Ban Management

### View Banned List

```bash
fwctl banned
```

Example output:

```
Banned IPs (15)
================
IP              Jail      Remaining   Protocol  Port
192.168.1.100   sshd      3452s       tcp       22
10.0.0.50       nginx     1200s       tcp       80
172.16.0.1      postfix   5800s       tcp       25
```

### Ban IP

```bash
fwctl ban <ip> [duration] [protocol] [port]
```

Examples:

```bash
# Ban for 1 hour
fwctl ban 192.168.1.100 3600

# Ban for 30 minutes, TCP port 80
fwctl ban 192.168.1.100 1800 tcp 80

# Permanent ban, all ports
fwctl ban 192.168.1.100 0 all 0
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `duration` | 3600 | Ban duration (seconds), 0 = permanent |
| `protocol` | tcp | `tcp`, `udp`, `all` |
| `port` | 0 | Port, 0 = all ports |

### Unban IP

```bash
fwctl unban <ip>
```

Example:

```bash
fwctl unban 192.168.1.100
```

### Bulk Ban

```bash
fwctl ban-file <file>
```

File format (one IP per line):

```
192.168.1.100
10.0.0.50
172.16.0.1
```

### Clear All Bans

```bash
fwctl clear
```

Confirmation prompt:

```
Are you sure you want to unban all IPs? [y/N]
```

Force clear (no prompt):

```bash
fwctl clear --force
```

## Whitelist Management

### View Whitelist

```bash
fwctl whitelist
```

Example output:

```
Whitelist (3/64)
================
127.0.0.1
192.168.1.0/24
10.0.0.1
```

### Add to Whitelist

```bash
fwctl whitelist-add <ip[/cidr]>
```

Examples:

```bash
fwctl whitelist-add 192.168.1.50
fwctl whitelist-add 10.0.0.0/8
```

### Remove from Whitelist

```bash
fwctl whitelist-remove <ip[/cidr]>
```

Example:

```bash
fwctl whitelist-remove 192.168.1.50
```

## Statistics

### View Statistics

```bash
fwctl stats
```

Example output:

```
Statistics
==========
Total ban events:       125
Total unban events:     98
Total packets dropped:  45230
Total packets passed:   1250340
Current banned:         15
Hash table usage:       0.37%
```

### View Jail Statistics

```bash
fwctl jail-stats
```

Example output:

```
Jail Statistics
===============
Jail        Enabled  Failures  Bans
sshd        yes      523       15
nginx       yes      1250      45
postfix     yes      89        3
```

### Real-time Statistics

```bash
watch -n 1 fwctl stats
```

## Logging

### View Daemon Log

```bash
fwctl log
```

Equivalent to:

```bash
tail -f /var/log/firewall.log
```

### View Kernel Log

```bash
fwctl dmesg
```

Equivalent to:

```bash
dmesg | grep firewall
```

## Configuration

### Validate Configuration

```bash
fwctl check-config
```

Checks YAML configuration file syntax and validity.

### Show Current Configuration

```bash
fwctl show-config
```

Displays the parsed current configuration.

## Command Quick Reference

| Command | Description |
|---------|-------------|
| `fwctl start` | Start service |
| `fwctl stop` | Stop service |
| `fwctl restart` | Restart service |
| `fwctl status` | View status |
| `fwctl reload` | Reload configuration |
| `fwctl banned` | View banned list |
| `fwctl ban <ip>` | Ban IP |
| `fwctl unban <ip>` | Unban IP |
| `fwctl clear` | Clear all bans |
| `fwctl whitelist` | View whitelist |
| `fwctl whitelist-add <ip>` | Add to whitelist |
| `fwctl whitelist-remove <ip>` | Remove from whitelist |
| `fwctl stats` | View statistics |
| `fwctl jail-stats` | View jail statistics |
| `fwctl log` | View log |
| `fwctl dmesg` | View kernel log |
| `fwctl check-config` | Validate configuration |
| `fwctl show-config` | Show configuration |