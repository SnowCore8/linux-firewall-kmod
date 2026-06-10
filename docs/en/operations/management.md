# Management Commands

This document describes all commands available in the `firewall-daemon` command-line tool.

## firewall-daemon Overview

`firewall-daemon` is the userspace management tool for Linux Firewall, providing a complete command-line interface for managing bans, whitelists, and viewing status.

### Syntax

```bash
firewall-daemon <command> [arguments]
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
firewall-daemon start
```

Start the daemon and load the kernel module.

### Stop

```bash
firewall-daemon stop
```

Stop the daemon and unload the kernel module.

### Restart

```bash
firewall-daemon restart
```

Restart the daemon.

### Status

```bash
cat /proc/firewall/config
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
firewall-daemon reload
```

Sends SIGHUP signal to the daemon to reload YAML configuration without interrupting service.

## Ban Management

### View Banned List

```bash
cat /proc/firewall/bans
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
firewall-daemon ban <ip> [duration] [protocol] [port]
```

Examples:

```bash
# Ban for 1 hour
echo "192.168.1.100 3600" | sudo tee /proc/firewall/bans

# Ban for 30 minutes, TCP port 80
firewall-daemon ban 192.168.1.100 1800 tcp 80

# Permanent ban, all ports
firewall-daemon ban 192.168.1.100 0 all 0
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `duration` | 3600 | Ban duration (seconds), 0 = permanent |
| `protocol` | tcp | `tcp`, `udp`, `all` |
| `port` | 0 | Port, 0 = all ports |

### Unban IP

```bash
echo "unban <ip>" | sudo tee /proc/firewall/bans
```

Example:

```bash
echo "unban 192.168.1.100" | sudo tee /proc/firewall/bans
```

### Bulk Ban

```bash
firewall-daemon ban-file <file>
```

File format (one IP per line):

```
192.168.1.100
10.0.0.50
172.16.0.1
```

### Clear All Bans

```bash
firewall-daemon clear
```

Confirmation prompt:

```
Are you sure you want to unban all IPs? [y/N]
```

Force clear (no prompt):

```bash
firewall-daemon clear --force
```

## Whitelist Management

### View Whitelist

```bash
cat /proc/firewall/whitelist
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
firewall-daemon whitelist-add <ip[/cidr]>
```

Examples:

```bash
firewall-daemon whitelist-add 192.168.1.50
firewall-daemon whitelist-add 10.0.0.0/8
```

### Remove from Whitelist

```bash
firewall-daemon whitelist-remove <ip[/cidr]>
```

Example:

```bash
firewall-daemon whitelist-remove 192.168.1.50
```

## Statistics

### View Statistics

```bash
cat /proc/firewall/stats
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
firewall-daemon jail-stats
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
watch -n 1 firewall-daemon stats
```

## Logging

### View Daemon Log

```bash
firewall-daemon log
```

Equivalent to:

```bash
tail -f /var/log/firewall.log
```

### View Kernel Log

```bash
firewall-daemon dmesg
```

Equivalent to:

```bash
dmesg | grep firewall
```

## Configuration

### Validate Configuration

```bash
firewall-daemon check-config
```

Checks YAML configuration file syntax and validity.

### Show Current Configuration

```bash
firewall-daemon show-config
```

Displays the parsed current configuration.

## Command Quick Reference

| Command | Description |
|---------|-------------|
| `firewall-daemon start` | Start service |
| `firewall-daemon stop` | Stop service |
| `firewall-daemon restart` | Restart service |
| `cat /proc/firewall/config` | View status |
| `firewall-daemon reload` | Reload configuration |
| `cat /proc/firewall/bans` | View banned list |
| `echo "<ip>" | sudo tee /proc/firewall/bans` | Ban IP |
| `echo "unban <ip>" | sudo tee /proc/firewall/bans` | Unban IP |
| `sudo rmmod firewall && sudo insmod firewall.ko` | Clear all bans |
| `cat /proc/firewall/whitelist` | View whitelist |
| `firewall-daemon whitelist-add <ip>` | Add to whitelist |
| `firewall-daemon whitelist-remove <ip>` | Remove from whitelist |
| `cat /proc/firewall/stats` | View statistics |
| `firewall-daemon jail-stats` | View jail statistics |
| `firewall-daemon log` | View log |
| `firewall-daemon dmesg` | View kernel log |
| `firewall-daemon check-config` | Validate configuration |
| `firewall-daemon show-config` | Show configuration |