# Building

This document describes the build system and compilation options for the Linux Firewall Kernel Module.

## Makefile Targets

### Primary Targets

| Target | Description |
|--------|-------------|
| `make` | Build all (kernel module + daemon) |
| `make kernel-module` | Build only the kernel module |
| `make daemon` | Build only the daemon |
| `make install` | Install to system |
| `make uninstall` | Uninstall from system |
| `make clean` | Clean build artifacts |

### Debug Targets

| Target | Description |
|--------|-------------|
| `make debug` | Build debug version |
| `make debug DL=2` | Build debug version (level 2) |
| `make asan` | Build AddressSanitizer version |

### Test Targets

| Target | Description |
|--------|-------------|
| `make test` | Run all tests |
| `make test-unit` | Run unit tests |
| `make test-integration` | Run integration tests |

## Building the Kernel Module

### Standard Build

```bash
make kernel-module
```

Output:

```
make -C /lib/modules/$(uname -r)/build M=$(PWD) modules
make[1]: Entering directory '/usr/src/linux-headers-...'
  CC [M]  /path/to/src/kernel/fw_fire.o
  LD [M]  /path/to/fw_fire.ko
  MODPOST /path/to/Module.symvers
make[1]: Leaving directory '/usr/src/linux-headers-...'
```

### Debug Build

```bash
make debug DL=2
```

Debug level descriptions:

| DL Value | Output |
|----------|--------|
| 0 | No debug output |
| 1 | Critical events (module load/unload) |
| 2 | Verbose events (ban/unban operations) |
| 3 | All events (including packet processing) |

## Building the Daemon

### Standard Build

```bash
make daemon
```

Output:

```
gcc -Wall -Wextra -O2 -o fwctl \
    src/daemon/main.c \
    src/daemon/config.c \
    src/daemon/jail.c \
    src/daemon/monitor.c \
    src/daemon/regex.c \
    src/daemon/database.c \
    src/daemon/metrics.c \
    src/daemon/procfs.c \
    -lyaml -lsqlite3 -lmicrohttpd -lpcre2-8
```

### AddressSanitizer Build

```bash
make asan
```

For detecting memory errors:

- Buffer overflows
- Use-after-free
- Memory leaks

Usage:

```bash
sudo ./fwctl asan
# Run for a while and check output
```

## Full Build

```bash
# Clean previous build
make clean

# Build all
make

# Install
sudo make install
```

## Cross Compilation

### Build for Target Architecture

```bash
export ARCH=x86_64
export CROSS_COMPILE=x86_64-linux-gnu-

make kernel-module
```

### Specify Kernel Source Path

```bash
make kernel-module KDIR=/path/to/kernel/source
```

## Compiler Flags

### Kernel Module Flags

| Flag | Description |
|------|-------------|
| `-Wall` | Enable all warnings |
| `-Wextra` | Enable extra warnings |
| `-Werror` | Treat warnings as errors |
| `-O2` | Optimization level 2 |
| `-DLINUX_VERSION_CODE` | Kernel version detection |

### Daemon Flags

| Flag | Description |
|------|-------------|
| `-Wall -Wextra` | Enable warnings |
| `-O2` | Release mode optimization |
| `-O0 -g` | Debug mode |
| `-fsanitize=address` | AddressSanitizer |
| `-DDEBUG` | Enable debug code |

## Dependency Checking

### Automatic Check

The build system checks dependencies automatically:

```bash
make
```

If dependencies are missing:

```
Checking dependencies...
  linux-headers: OK
  libyaml:       NOT FOUND
  libsqlite3:    OK
  libmicrohttpd: OK
  libpcre2:      OK

Error: Missing dependencies. Install:
  sudo apt install libyaml-dev
```

### Manual Check

```bash
# Check kernel headers
ls /lib/modules/$(uname -r)/build

# Check libraries
pkg-config --libs libyaml
pkg-config --libs sqlite3
pkg-config --libs libmicrohttpd
pkg-config --libs libpcre2
```

## Build Artifacts

### Kernel Module

| File | Description |
|------|-------------|
| `fw_fire.ko` | Kernel module |
| `fw_fire.mod.c` | Module metadata |
| `Module.symvers` | Symbol versions |
| `modules.order` | Module order |

### Daemon

| File | Description |
|------|-------------|
| `fwctl` | Daemon binary |

### Installation Locations

| File | Install Path |
|------|-------------|
| `fw_fire.ko` | `/lib/modules/$(uname -r)/extra/` |
| `fwctl` | `/usr/local/sbin/` |
| `fw_fire.yaml` | `/etc/fw_fire/` |
| `fw_fire.service` | `/etc/systemd/system/` |

## Build Troubleshooting

### Kernel Header Mismatch

```
ERROR: Kernel configuration is invalid.
```

Solution:

```bash
sudo apt install --reinstall linux-headers-$(uname -r)
```

### Library Version Incompatibility

```
undefined reference to `pcre2_compile_8'
```

Solution:

```bash
sudo apt install --reinstall libpcre2-dev
```

### Insufficient Permissions

```
make install: Permission denied
```

Solution:

```bash
sudo make install
```

---

[中文版本](../../zh/development/building.md)
