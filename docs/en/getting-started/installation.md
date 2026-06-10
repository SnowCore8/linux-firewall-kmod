# Installation

This document describes how to install the Linux Firewall Kernel Module and its userspace daemon.

## System Requirements

| Item | Minimum | Recommended |
|------|---------|-------------|
| Kernel Version | Linux 5.x | Linux 6.x LTS |
| CPU Architecture | x86_64 | x86_64 |
| Memory | 256 MB | 512 MB+ |
| Disk Space | 50 MB | 100 MB+ |
| Compiler | GCC 10+ | GCC 12+ |

### Supported Distributions

| Distribution | Status |
|--------------|--------|
| Ubuntu 20.04+ | Fully Supported |
| Debian 11+ | Fully Supported |
| CentOS 8+ | Fully Supported |
| RHEL 8+ | Fully Supported |
| Arch Linux | Community Support |
| Fedora 35+ | Community Support |

## Installing Dependencies

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    libyaml-dev \
    libsqlite3-dev \
    libmicrohttpd-dev \
    libpcre2-dev \
    pkg-config
```

### CentOS / RHEL

```bash
sudo dnf install -y \
    gcc gcc-c++ make \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r) \
    libyaml-devel \
    sqlite-devel \
    libmicrohttpd-devel \
    pcre2-devel \
    pkg-config
```

### Arch Linux

```bash
sudo pacman -S --needed \
    base-devel \
    linux-headers \
    libyaml \
    sqlite \
    libmicrohttpd \
    pcre2 \
    pkg-config
```

## Build and Install

### 1. Clone the Repository

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod
```

### 2. Build

Build the complete project (kernel module + daemon):

```bash
make
```

Build only the kernel module:

```bash
make kernel-module
```

Build only the daemon:

```bash
make daemon
```

### 3. Install

```bash
sudo make install
```

After installation:

- Kernel module `firewall.ko` is installed to `/lib/modules/$(uname -r)/extra/`
- Daemon `fwctl` is installed to `/usr/local/sbin/`
- Configuration file is installed to `/etc/firewall/default.yaml`
- systemd service file is installed to `/etc/systemd/system/`

### 4. Load the Kernel Module

```bash
sudo modprobe firewall
```

Verify the module is loaded:

```bash
lsmod | grep firewall
```

### 5. Start the Daemon

```bash
sudo systemctl enable firewall
sudo systemctl start firewall
```

Check service status:

```bash
sudo systemctl status firewall
```

## Verifying Installation

### Check Kernel Module

```bash
cat /proc/firewall/status
```

Expected output:

```
Firewall Module Status
======================
Module: loaded
Version: 1.0.0
Banned IPs: 0
Whitelisted IPs: 0
Hash table capacity: 4096
Whitelist capacity: 64
```

### Check Daemon

```bash
fwctl status
```

### Check Prometheus Metrics

```bash
curl http://localhost:9119/metrics
```

## Uninstallation

```bash
sudo systemctl stop firewall
sudo systemctl disable firewall
sudo make uninstall
```

Uninstallation removes:

- Kernel module (automatically unloaded)
- Daemon binary
- Configuration files (optional, user configs preserved)
- systemd service file

## Common Issues

### Kernel Headers Not Found

```bash
# Ubuntu/Debian
sudo apt install linux-headers-$(uname -r)

# CentOS/RHEL
sudo dnf install kernel-devel-$(uname -r) kernel-headers-$(uname -r)
```

### Secure Boot Issues

If Secure Boot is enabled, you need to sign the kernel module or use MOK (Machine Owner Key):

```bash
sudo mokutil --import /path/to/signing_key.der
```

### Insufficient Permissions

Ensure you use `sudo` or run as root for installation commands.