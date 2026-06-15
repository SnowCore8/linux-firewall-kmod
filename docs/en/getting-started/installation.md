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
    pkg-config
```

### CentOS / RHEL

```bash
sudo dnf install -y \
    gcc gcc-c++ make \
    kernel-devel-$(uname -r) \
    kernel-headers-$(uname -r) \
    pkg-config
```

### Arch Linux

```bash
sudo pacman -S --needed \
    base-devel \
    linux-headers \
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

### Building .deb from source

The recommended way to build a distributable .deb package (for Debian/Ubuntu-family distributions) is `make deb`.

```bash
# Build artifacts
make                    # Compile kernel module + Rust daemon
                        # Kernel module: build/kernel-module/firewall.ko
                        # Daemon:        build/daemon/firewall-daemon (3.8MB stripped)

# Build .deb
make deb                # Output: build/deb/linux-firewall-kmod-2.2.0.deb (1.5MB)

# Install
sudo dpkg -i build/deb/linux-firewall-kmod-2.2.0.deb
# Equivalent to:
#   1. dkms add + build + install firewall/2.2.0
#   2. modprobe firewall
#   3. systemctl enable --now firewall-daemon
#   4. cp /etc/firewall/*.yaml (from /usr/share/firewall/)

# Verify
systemctl status firewall-daemon
lsmod | grep firewall
ls /proc/firewall/
```

> If `make deb` fails with `make: cargo: No such file or directory`, `cargo` is not on your `PATH`. Run `source ~/.cargo/env` and retry, or install rustup (https://rustup.rs).

### 3. Install

#### Method 1: One-click install (recommended)

```bash
sudo env "PATH=$PATH" make install
```

This command automatically:
1. Builds kernel module and daemon (if not already built)
2. Installs all components to system directories
3. Verifies installation integrity
4. Loads kernel module
5. Starts systemd service

> 💡 **Tip**: Use `sudo env "PATH=$PATH"` to ensure cargo is in PATH. Without it, sudo environment may not find cargo.

#### Method 2: Build first, then install

```bash
# Build first
make build

# Then install
sudo env "PATH=$PATH" make install
```

#### Installation process

`make install` executes in the following order:
1. **build** - Build kernel module and daemon
2. **install-kernel-module** - Install kernel module to `/lib/modules/$(uname -r)/extra/`
3. **install-daemon** - Install daemon to `/usr/local/sbin/`
4. **install-config** - Install configuration files to `/etc/firewall/`
5. **install-state** - Create state directory `/var/lib/firewall/`
6. **install-systemd** - Install systemd service unit
7. **install-start** - Load kernel module and start daemon
8. **install-verify** - Verify all components installed successfully

After installation:

- Kernel module `firewall.ko` is installed to `/lib/modules/$(uname -r)/extra/`
- Daemon `firewall-daemon` is installed to `/usr/local/sbin/`
- Configuration files are installed to `/etc/firewall/` (includes 12 jail configs)
- State data directory `/var/lib/firewall/`
- systemd service file is installed to `/etc/systemd/system/`

### 4. Verify installation

After installation, verify service status:

```bash
# Check service status
sudo systemctl status firewall-daemon

# Check kernel module
lsmod | grep firewall

# View procfs interface
ls /proc/firewall/

# View logs
journalctl -u firewall-daemon.service -f
```

### 5. Manually load kernel module (optional)

If the service didn't auto-load the kernel module:

```bash
sudo modprobe firewall
```

Verify the module is loaded:

```bash
lsmod | grep firewall
```

## Verifying Installation

### Check Kernel Module

```bash
cat /proc/firewall/config
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
cat /proc/firewall/config
```

### Check Prometheus Metrics

```bash
curl http://localhost:9119/metrics
```

## Post-install Behavior

Whether you install via `sudo make install` or `sudo dpkg -i *.deb`, the system automatically performs the following actions:

1. **systemd starts `firewall-daemon.service`**
   - Unit file lives at `/etc/systemd/system/firewall-daemon.service`
   - `enable --now` starts the daemon immediately and registers it for boot
   - The unit runs under a hardened sandbox: `ProtectSystem=strict`, `ReadOnlyPaths=/etc/firewall`, `ReadWritePaths=/var/lib/firewall`

2. **Loads the kernel module `firewall.ko`**
   - Done via `modprobe firewall` or the `install-systemd` hook
   - The module exports the following procfs files under `/proc/firewall/`: `config`, `stats`, `bans`, `whitelist`, `log_level`

3. **Daemon startup sequence**
   - Loads all YAML config files from `/etc/firewall/*.yaml` (in lexicographic order; later files override earlier ones)
   - Compiles each jail's regex patterns (`regex::Regex::new`)
   - Starts the Prometheus HTTP exporter on `:9119/metrics`
   - Starts inotify watches on the `log_path` files
   - Enters the main monitoring loop: regex match → failure counter → threshold check → write to procfs to trigger a ban

4. **First-boot observation**
   ```bash
   journalctl -u firewall-daemon -f
   # Expected output:
   #   Loaded config: /etc/firewall/default.yaml
   #   Compiled regex for jail 'sshd' (12 patterns)
   #   Prometheus exporter listening on 0.0.0.0:9119
   #   inotify watching /var/log/auth.log
   #   Daemon ready
   ```

> Note: if the daemon fails to open `log_file: /var/log/firewall.log` at startup, it logs a warning "Failed to open log file ... (falling back to syslog-only)". This is by design — the systemd unit's `ProtectSystem=strict` makes `/var/log` read-only for the daemon. See [Troubleshooting - Daemon cannot open /var/log/firewall.log](../operations/troubleshooting.md#daemon-cannot-open-varlogfirewalllog).

## Uninstallation

```bash
sudo systemctl stop firewall-daemon
sudo systemctl disable firewall-daemon
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