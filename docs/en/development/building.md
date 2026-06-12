# Building

This document describes the build system and compilation options for the Linux Firewall Kernel Module.

## Makefile Targets

> Aligned 1:1 with `make help`. The default `make` is equivalent to
> `make all` (runs clang-format check first).

### Primary Targets

| Target | Description |
|--------|-------------|
| `make` / `make all` / `make build` | Build everything (kernel module + daemon; runs clang-format check by default) |
| `make build-quick` | Same as above, skipping format check (faster for iterative CI) |
| `make kernel-module` | Build only the kernel module |
| `make daemon` | Build only the daemon |
| `make install` | Install to system |
| `make uninstall` | Uninstall from system |
| `make help` | Show full help |

### Debug / Sanitizer Targets

| Target | Description |
|--------|-------------|
| `make debug` | Build debug version (`DL=1`) |
| `make debug DL=2` | Build debug version (level 2, more verbose) |
| `make asan` | Build AddressSanitizer version |
| `make deb [VERSION=x.x.x]` | Build Debian package (VERSION inferred from CHANGELOG if omitted) |

### Maintenance Targets

| Target | Description |
|--------|-------------|
| `make format` | Auto-format all C code (applies clang-format) |
| `make format-check` | Check C code formatting (default CI gate; fails on violation) |
| `make clean` | Clean `build/` artifacts |
| `make distclean` | Clean all generated files (incl. kernel module `.ko` / `.o` / `Module.symvers`) |

### Test and CI Targets

| Target | Description |
|--------|-------------|
| `make test` | Run all tests (`sudo ./tests/run_tests.sh`) |
| `make ci` | Full CI build: format-check + build + test |

> The Makefile exposes only `make test`. To filter by suite or
> category, call `./tests/run_tests.sh --suite NN` /
> `--category X` / `--report` directly. See [Testing](testing.md).

### Skipping the Format Check

The format check (clang-format) may take a while on first build while
it downloads the toolchain. Two ways to skip:

```bash
# Via target
make build-quick

# Via variable
make SKIP_FORMAT_CHECK=1 all
```

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

The daemon is written in Rust and built via `cargo build`. The Makefile drives the build:

```bash
cargo build --release --bin firewall-daemon
```

> For actual builds, use `make daemon` — the Makefile drives the
> cargo build and links required libraries.

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

If dependencies are missing, the build will report which packages are required.

### Manual Check

```bash
# Check kernel headers
ls /lib/modules/$(uname -r)/build

# Check Rust toolchain
rustc --version
cargo --version

# Check libraries
pkg-config --libs sqlite3
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

### Rust Build Issues

```
error[E0432]: unresolved import `regex`
```

Solution:

```bash
cargo build
```

Cargo will automatically fetch required dependencies from `Cargo.toml`.

### Insufficient Permissions

```
make install: Permission denied
```

Solution:

```bash
sudo make install
```