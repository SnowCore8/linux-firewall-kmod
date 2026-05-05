# Firewall

**Linux Kernel Module Version of fail2ban — Real-time IP Ban Protection**

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.1-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x-orange.svg)]()

> 🌍 [中文文档](README.md)

## Overview

Firewall is a Linux kernel module version of fail2ban, moving the ban logic from userspace to kernelspace using the netfilter framework for real-time IP banning at the packet level with lower latency and higher performance.

## Why This Project

| Feature | fail2ban (Userspace) | Firewall (Kernelspace) |
|---------|---------------------|----------------------|
| Ban Location | iptables/nftables userspace | netfilter kernel hooks |
| Response Time | Seconds | Milliseconds |
| Resource Usage | Python runtime + dependencies | Lightweight C daemon |
| Lookup Performance | Linear rule scan | Hash table O(1) lookup |

## Core Features

- ✅ **Kernel-space IP banning** — netfilter hooks for higher efficiency
- ✅ **Jail system** — multi-service isolation like fail2ban
- ✅ **Hash table storage** — 4096 capacity, O(1) lookup performance
- ✅ **Auto-expire cleanup** — periodic cleanup of expired bans
- ✅ **IP whitelist protection** — auto-discovery + manual entries (64 capacity)
- ✅ **procfs interface** — ban/unban/whitelist/config operations
- ✅ **C language daemon** — no Python dependency, lightweight
- ✅ **PCRE2 regex parsing** — JIT accelerated, ReDoS protected
- ✅ **RCU concurrency safety** — spinlock protected, high-concurrency safe
- ✅ **Strict config validation** — unknown params rejected by default
- ✅ **State persistence** — SQLite for permanent ban recovery
- ✅ **Prometheus metrics** — exported on port 9119
- ✅ **Security Hardening** — Integer overflow protection, Use-After-Free fix, RCU consistency
- ✅ **Performance Optimization** — Hash table capacity 4096, SQLite statement cache, whitelist two-stage matching
- ✅ **Code Quality** — Unified goto cleanup pattern, extracted common config parsing functions

## Quick Start

### Build

```bash
make                    # Build all
make kernel-module      # Kernel module only
make daemon             # Daemon only
make clean              # Clean
```

### Load Module

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
cat /proc/firewall/config
sudo rmmod firewall
```

### Basic Operations

```bash
# Ban (default / custom duration / permanent)
echo "1.2.3.4"       | sudo tee /proc/firewall/bans
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans

# Unban / Whitelist
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist
```

### Start Daemon

```bash
sudo ./build/daemon/firewall-daemon                         # Default config
sudo ./build/daemon/firewall-daemon -c config/default.yaml  # Custom config
sudo ./build/daemon/firewall-daemon --help                  # Help
```

> 📖 Full procfs interface: [docs/OPERATIONS.md](docs/OPERATIONS.md)

## 📚 Documentation Navigation

| Document | Description | For |
|----------|-------------|-----|
| [CONFIGURATION.md](docs/CONFIGURATION.md) | YAML Jail format, parameters, hot-reload | Configuration |
| [OPERATIONS.md](docs/OPERATIONS.md) | Deployment, procfs API, troubleshooting | Operations |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Kernel design, data flow, components | Developers |
| [TESTING.md](docs/TESTING.md) | 105 tests, how to run/write | Testers |
| [SECURITY.md](docs/SECURITY.md) | Build options, systemd hardening | Security |
| [PERMANENT_BAN_GUIDE.md](docs/PERMANENT_BAN_GUIDE.md) | SQLite persistence, DB schema | Advanced users |
| [FAQ.md](docs/FAQ.md) | Frequently asked questions | All users |
| [MIGRATION.md](docs/MIGRATION.md) | Migration guide from fail2ban | Migrating users |
| [CHANGELOG.md](CHANGELOG.md) | v1.0 to v2.1 changelog | All users |

## Use Cases

| ✅ Recommended | ❌ Not Recommended |
|----------------|-------------------|
| Personal VPS protection | Production DDoS protection |
| Dev/test environments | Audit compliance scenarios |
| Small-scale SSH brute-force protection | Large-scale distributed deployment |

## License & Contributing

- **License**: [MIT License](LICENSE)
- **Contribute**: [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) | [PRs](https://github.com/SnowCore8/linux-firewall-kmod/pulls)
- **Author**: [SnowCore8](https://github.com/SnowCore8) — Built with [OpenCode](https://opencode.ai)
