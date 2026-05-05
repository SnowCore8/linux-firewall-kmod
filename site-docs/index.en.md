---
hide:
  - navigation
  - toc
---

# linux-firewall-kmod

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/kernel-5.15%2B-orange.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%2B%20YAML-green.svg)]()
[![Build](https://img.shields.io/badge/build-make-success.svg)]()

**A Linux kernel module version of fail2ban — moving IP banning from userspace to kernelspace.**

</div>

---

## Overview

**linux-firewall-kmod** is a high-performance alternative to fail2ban that implements IP banning logic directly in the Linux kernel. By leveraging Netfilter hooks and kernel-space hash tables, it achieves microsecond-level packet filtering with O(1) lookup performance — significantly faster than traditional userspace solutions.

The project features a dual-layer architecture: a kernel module for real-time packet filtering and a userspace daemon for log monitoring, pattern matching, and ban management.

## Why Choose This Over fail2ban?

| Feature | fail2ban | linux-firewall-kmod |
|---------|----------|---------------------|
| Ban Location | iptables/nftables (userspace rules) | Netfilter kernel hooks |
| Response Latency | Seconds | Milliseconds |
| Language | Python | C (kernel module + daemon) |
| Lookup Performance | Linear rule traversal | Hash table O(1) lookup |
| Config Format | INI | YAML |
| Config Validation | Permissive | Strict (default) |
| Persistence | Filesystem | SQLite database |
| Ban Capacity | No hard limit | 1024 IPs |
| Metrics | No built-in | Prometheus export (port 9119) |

## Core Features

1. **Kernel-space Filtering** — Netfilter `NF_INET_PRE_ROUTING` hook for real-time packet dropping
2. **O(1) Ban Lookup** — Kernel hash table with RCU concurrent protection
3. **Event-driven Log Monitoring** — inotify-based file watching with millisecond response
4. **PCRE2 Regex Engine** — JIT-compiled pattern matching with ReDoS protection
5. **YAML Configuration** — Clean, validated config with strict mode by default
6. **12 Preset Service Templates** — SSH, Nginx, Apache, MySQL, Redis, Docker, and more
7. **Prometheus Metrics** — 14 built-in metrics for monitoring and alerting
8. **SQLite Persistence** — Permanent ban storage surviving daemon restarts
9. **Hot Config Reload** — SIGHUP-triggered atomic config swap without downtime
10. **Auto IP Discovery** — Automatic system IP detection and whitelisting
11. **systemd Hardening** — Sandboxed service with minimal capabilities
12. **Comprehensive Logging** — Kernel dmesg + systemd journal integration

## Quick Start

### Build

```bash
# Install dependencies (Debian/Ubuntu)
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev

# Build
make

# Install
sudo make install
```

### Load Kernel Module

```bash
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a
sudo modprobe firewall
```

### Basic Operations

```bash
# View banned IPs
cat /proc/firewall/bans

# Ban an IP (default duration)
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# Ban with custom duration (seconds)
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans

# Unban an IP
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# View statistics
cat /proc/firewall/stats
```

### Start the Daemon

```bash
# Copy configuration
sudo mkdir -p /etc/firewall
sudo cp config/*.yaml /etc/firewall/

# Start with systemd
sudo systemctl enable --now firewall-daemon

# Or run in foreground for debugging
sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
```

## Use Cases

| Scenario | Recommended | Notes |
|----------|-------------|-------|
| Personal VPS / Cloud Server | Yes | Ideal for SSH brute-force protection |
| Web Service (Nginx/Apache) | Yes | Built-in regex patterns included |
| Database (MySQL/Redis) | Yes | Protect against unauthorized access |
| Enterprise DDoS Protection | No | Use dedicated hardware firewalls |
| IPv6-only Environment | No | IPv6 support is planned |
| Ban Count > 1024 IPs | No | Consider enterprise solutions |

## License & Contributing

This project is licensed under the [MIT License](LICENSE). We welcome contributions of all kinds — bug fixes, feature additions, documentation improvements, and translations.

See the [Contributing Guide](contributing.md) for development setup and workflow details.

---

> **Documentation**: [Configuration](configuration.md) | [Operations](operations.md) | [Architecture](architecture.md) | [Security](security.md) | [FAQ](faq.md)
