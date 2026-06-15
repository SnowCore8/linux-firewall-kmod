# Firewall

**Linux Kernel Module Version of fail2ban — Real-time IP Ban Protection**

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.2.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-Rust%20%2B%20C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x-orange.svg)]()

> 🌍 [中文文档](README.md)

## Overview

Firewall is a Linux kernel module version of fail2ban, moving the ban logic from userspace to kernelspace using the netfilter framework for real-time IP banning at the packet level with lower latency and higher performance. The userspace daemon is now written in Rust (translated from C in v2.2.0), producing a 3.8MB stripped binary; 111 integration tests pass with `RUST=1`.

## Why This Project

| Feature | fail2ban (Userspace) | Firewall (Kernelspace) |
|---------|---------------------|----------------------|
| Ban Location | iptables/nftables userspace | netfilter kernel hooks |
| Response Time | Seconds | Milliseconds |
| Resource Usage | Python interpreter + full dep chain | Single-file 3.8MB Rust binary |
| Lookup Performance | Linear rule scan | Hash table O(1) lookup |
| Permanent Ban | Config file | SQLite WAL + soft-delete + startup restore |

## Core Features

- ✅ **Kernel-space IP banning** — netfilter hooks for higher efficiency
- ✅ **Jail system** — multi-service isolation like fail2ban
- ✅ **Hash table storage** — 4096 capacity, O(1) lookup performance
- ✅ **Auto-expire cleanup** — periodic cleanup of expired bans
- ✅ **IP whitelist protection** — auto-discovery + manual entries (64 capacity)
- ✅ **procfs interface** — ban/unban/whitelist/config operations
- ✅ **Rust daemon (v2.2.0+)** — 12 modules / 7000 lines, 3.8MB stripped binary, behaviorally equivalent to the C version
- ✅ **Regex parsing** — named capture groups for IP extraction
- ✅ **RCU concurrency safety** — spinlock protected, high-concurrency safe
- ✅ **Strict config validation** — unknown params rejected by default
- ✅ **State persistence** — SQLite WAL + soft-delete for permanent ban recovery
- ✅ **Prometheus metrics** — 14 metrics on port 9119 (4 kernel + 10 user-space)
- ✅ **Independent log file** — `cfg.log_file` default `/var/log/firewall.log`, falls back to syslog-only on open failure
- ✅ **Security hardening** — Integer overflow protection, UAF fix, RCU consistency, 19 `unsafe` blocks all with `// SAFETY:` comments
- ✅ **Performance optimization** — Hash table 4096, SQLite statement cache, whitelist two-stage match, LTO compilation
- ✅ **Code quality** — 108 unit tests + 1 real-running doctest + 115 integration tests 100% pass, CI three jobs all green

## Quick Start

### Build

```bash
make                    # Build kernel module + Rust daemon
make kernel-module      # Kernel module only
make daemon             # Rust daemon only (cargo build --release)
make clean              # Clean
make build-quick        # Quick build (skip format check)
```


### Install

```bash
# Method 1: One-click install (auto-build + verify)
sudo env "PATH=$PATH" make install

# Method 2: Build first, then install
make build
sudo env "PATH=$PATH" make install

# Uninstall
sudo make uninstall
```

> 💡 **Tip**: `make install` automatically builds, installs, verifies, and starts the systemd service. Use `sudo env "PATH=$PATH"` to ensure cargo is in PATH.

### Load Module (manual)

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

### Build .deb Package

```bash
make deb                 # Calls ./build-deb.sh
                         # Output: build/deb/linux-firewall-kmod-2.2.0.deb (1.5MB)
sudo dpkg -i build/deb/linux-firewall-kmod-2.2.0.deb  # Install (DKMS auto-builds + systemd start)
```

> 📖 Docs: [中文](docs/zh/) | [English](docs/en/) | [Online Viewer](https://snowcore8.github.io/linux-firewall-kmod/)

## 📚 Documentation Navigation

Browse the full documentation via the sidebar. Quick links:

- [Getting Started](docs/en/getting-started/README.md) - Install, build, first use
- [Configuration](docs/en/configuration/README.md) - YAML Jail format, parameters
- [Architecture](docs/en/architecture/README.md) - Kernel module & daemon design
- [Operations](docs/en/operations/README.md) - Management, monitoring
  - [Troubleshooting](docs/en/operations/troubleshooting.md)
- [Development](docs/en/development/README.md) - Build, contribution
  - [Testing](docs/en/development/testing.md)
- [Migration](docs/en/migration/from-fail2ban.md) - From fail2ban
- [CHANGELOG.md](CHANGELOG.md) - v1.0 to v2.2 changelog

## Use Cases

| ✅ Recommended | ❌ Not Recommended |
|----------------|-------------------|
| Personal VPS protection | Production DDoS protection |
| Dev/test environments | Audit compliance scenarios |
| Small-scale SSH brute-force protection | Large-scale distributed deployment |

## License & Contributing

- **License**: [MIT License](LICENSE)
- **Contribute**: [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) | [PRs](https://github.com/SnowCore8/linux-firewall-kmod/pulls)
- **Author**: [SnowCore8](https://github.com/SnowCore8) — Built with [Code CLI](https://github.com/github/code-cli)
