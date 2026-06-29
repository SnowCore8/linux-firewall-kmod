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
| `make deb` | Build Debian package (invokes `./build-deb.sh`, output in `build/deb/`) |

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

The daemon (since v2.2.0) has been ported to Rust and is built via
`cargo`. The `make daemon` target runs:

```bash
cargo build --release
cp target/release/firewall-daemon build/daemon/firewall-daemon
```

### Rust release profile (`Cargo.toml`)

`Cargo.toml` pre-defines three profiles, each tuned for a different
use case:

| Profile | Size | Purpose | Build command |
|---------|------|---------|---------------|
| `release` (default) | **6.2MB stripped** | Production deployment | `cargo build --release` |
| `dev-with-debug` | 32MB (with DWARF + symbols) | Field crash analysis; use `addr2line` to unwind stacks | `cargo build --release --profile dev-with-debug` |
| `asan` | (with ASAN runtime) | Memory-safety checks, requires nightly | `cargo +nightly build --profile asan` |

#### release (default)

```toml
[profile.release]
opt-level = 2
lto = true            # link-time optimization
codegen-units = 1     # single codegen unit → better inlining
debug = false
strip = true
panic = "abort"       # smaller binary, no unwinding tables
```

Produces a 6.2MB stripped binary — the default for `make deb` /
`make install`.

#### dev-with-debug

```toml
[profile.dev-with-debug]
inherits = "release"
debug = true
strip = false
```

Inherits all of `release`'s optimizations (`opt-level=2` + `lto=true`)
but **retains DWARF + symbol tables**. Production-equivalent speed,
crash-locatable:

```bash
cargo build --profile dev-with-debug
addr2line -e build/daemon/firewall-daemon 0x401a23
```

#### asan (nightly opt-in)

```toml
[profile.asan]
inherits = "dev"
opt-level = 1
debug = true
lto = false
```

**Requires the nightly toolchain** (`rustup install nightly`); runs
AddressSanitizer memory-safety checks. The `make asan` target selects
this profile automatically.

## Full Build

```bash
# Clean previous build
make clean

# Build all
make

# Install
sudo make install
```

## Building the Debian Package

`make deb` depends on the `build` target (it first compiles the kernel
module and daemon), then calls `./build-deb.sh` to produce a `.deb`:

```bash
make deb
# Output: build/deb/linux-firewall-kmod-<VERSION>.deb
ls -lh build/deb/
```

Package layout (the `build-deb.sh` staging directory, DKMS mode):

| Path | Contents |
|------|----------|
| `/usr/sbin/firewall-daemon` | Daemon binary (already `strip`-ed, ~6.2MB) |
| `/usr/src/linux-firewall-kmod-<VERSION>/` | DKMS source tree (compiled by dkms on first install) |
| `/etc/firewall/*.yaml` | YAML config files |
| `/etc/systemd/system/firewall-daemon.service` | systemd unit |
| `/var/log/firewall.log` | Daemon log file (`logrotate` keeps 30 days) |
| `/var/lib/firewall/` | Runtime state directory |

### Version-number behavior

- **No argument**: `build-deb.sh` auto-extracts from the first
  `## v` entry in `CHANGELOG.md` (e.g. `## v2.2.0` → `2.2.0`); falls
  back to a hard-coded default if not found
- **Positional argument**: `./build-deb.sh 2.2.0` to override explicitly
- **The `VERSION=` env-var form is NOT accepted** — `build-deb.sh`
  parses only `$1` and does not read the `VERSION` env var. Running
  `make deb VERSION=2.2.0` will NOT change the output version

> The daemon in the .deb installs to `/usr/sbin/`, whereas
> `make install` defaults to `PREFIX=/usr/local` →
> `/usr/local/sbin/`. The two paths differ because the .deb follows
> system-package convention (`/usr/sbin/`) while `make install`
> follows FHS-style compatibility. To make `make install` also land
> in `/usr/sbin/`:
> `sudo make install PREFIX=/usr`

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

### Daemon (Rust) profile

The daemon has no C-flag knobs anymore; build behavior is fully
controlled by the `[profile.*]` sections in `Cargo.toml`. See
[Building the Daemon → Rust release profile](#rust-release-profile-cargotoml)
for the full profile matrix.

- `release`: `lto=true` + `strip=true` + `debug=false` + `panic="abort"`
  → 6.2MB stripped
- `dev-with-debug`: inherits release, keeps DWARF + symbols → 32MB
- `asan`: nightly opt-in, bundles the ASAN runtime

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
| `build/daemon/firewall-daemon` | Daemon binary (**6.2MB stripped**, default `release` profile) |
| `target/release/firewall-daemon` | `cargo`'s original output location (`make daemon` copies it to `build/daemon/`) |
| `build/daemon/firewall-daemon-asan` | ASAN build (`make asan` output; larger, includes ASAN runtime) |

> The `dev-with-debug` profile's output is NOT copied to
> `build/daemon/` by `make daemon`; pick it up manually from
> `target/dev-with-debug/`.

### Installation Locations

| File | Install Path |
|------|-------------|
| `firewall.ko` | `/lib/modules/$(uname -r)/extra/` |
| `firewall-daemon` (from `make deb`) | `/usr/sbin/firewall-daemon` |
| `firewall-daemon` (from `make install`) | `/usr/local/sbin/firewall-daemon` (default `PREFIX=/usr/local`) |
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

### `cargo: not found` under sudo

`sudo`'s default `secure_path` does not include `~/.cargo/bin`, which
is the standard location when Rust is installed via rustup. `make test`
already calls `sudo ./tests/run_tests.sh` and the test runner's entry
point does `source ~/.cargo/env` plus
`export PATH=$HOME/.cargo/bin:$PATH`, so this is handled automatically.
But calling `sudo make daemon` directly will fail:

```
sudo make daemon
make: cargo: Command not found
make: *** [Makefile:101: daemon] Error 127
```

Solutions (any of the three):

```bash
# 1) Source the cargo env before sudo
source ~/.cargo/env
sudo make daemon

# 2) Preserve PATH explicitly through sudo
sudo --preserve-env=PATH make daemon

# 3) Install cargo into a system path (not recommended; breaks
#    the user-isolation that rustup is built around)
sudo cp ~/.cargo/bin/cargo /usr/local/bin/
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