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
make -C /lib/modules/$(uname -r)/build M=$(PWD)/src/kernel-module modules
make[1]: Entering directory '/usr/src/linux-headers-...'
  CC [M]  src/kernel-module/firewall-main.o
  LD [M]  src/kernel-module/firewall.ko
  MODPOST modules
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

The actual build is driven by the Makefile; this gcc invocation is
illustrative only (the source list was refactored in v2.x):

```
gcc -Wall -Wextra -O2 -o firewall-daemon \
    src/daemon/firewall-daemon.c \
    src/daemon/jail-manager.c \
    src/daemon/config-parser.c \
    src/daemon/log-parser.c \
    src/daemon/failed-tracker.c \
    src/daemon/ban-manager.c \
    src/daemon/file-monitor.c \
    src/daemon/http-exporter.c \
    src/daemon/sqlite-persistent.c \
    -lpthread -lyaml -lsqlite3 -lmicrohttpd -lpcre2-8
```

> For actual builds, use `make daemon` — the Makefile drives the
> object list and flags. The command above is conceptual.

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
sudo ./firewall-daemon asan
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
| `firewall.ko` | Kernel module |
| `firewall.mod.c` | Module metadata |
| `Module.symvers` | Symbol versions |
| `modules.order` | Module order |

### Daemon

| File | Description |
|------|-------------|
| `firewall-daemon` | Daemon binary |

### Installation Locations

| File | Install Path |
|------|-------------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` |
| `firewall-daemon` | `/usr/local/sbin/` |
| `default.yaml` | `/etc/firewall/` |
| `firewall-daemon.service` | `/etc/systemd/system/` |

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