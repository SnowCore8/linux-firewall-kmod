# Building

This document describes the build system and compilation options for the Linux Firewall Kernel Module.

## Makefile Targets

> Aligned 1:1 with `make help`. The default `make` is equivalent to
> `make all` (runs clang-format check first).

### Primary Targets

| Target | Description |
|--------|-------------|
| `make` / `make all` / `make build` | Build everything (frontend + kernel module + daemon; runs clang-format check by default) |
| `make build-quick` | Same as above, skipping format check (faster for iterative CI) |
| `make kernel-module` | Build only the kernel module |
| `make daemon` | Build only the daemon (runs `make frontend` first) |
| `make frontend` | Build only the frontend (`npm ci` + `vite build`), output to `src/daemon/web_ui/static/` |
| `make frontend-typecheck` | Type-check the frontend only (`tsc --noEmit`), no build artifacts |
| `make install` | Install to system |
| `make uninstall` | Uninstall from system |
| `make help` | Show full help |

> The frontend is React 19 + TypeScript + Vite + antd-mobile 5
> (mobile-first, hash routing, PWA support) and requires **Node.js ≥ 20 + npm**
> to build. `make frontend` installs dependencies with `npm ci`; the lockfile
> `frontend/package-lock.json` is committed for reproducibility. The daemon
> embeds `index.html` / `app.js` / `style.css` / `sw.js` / `manifest.webmanifest`
> / `icons/` into the binary via `rust-embed`, so Node.js is not needed at runtime.

### Frontend and PWA

- **Fixed artifact names**: vite emits `app.js` / `style.css` (no content hash
  in the filename), so the Service Worker must use a "cache-first + background
  refresh" strategy; otherwise a daemon upgrade would serve old JS alongside new
  HTML and blank the page
- **`/api/*` is never cached**: the Service Worker does not intercept `/api/*`
  at all, so ban lists and statistics always come from the network
- **PWA install is limited to secure contexts**: a Service Worker only registers
  in a secure context (HTTPS or `localhost`). When accessed over a LAN via
  `http://<ip>:9119`, Chrome **silently refuses** to register the SW — the UI
  still works, but "Add to Home Screen" is unavailable; use HTTPS or a local
  `localhost` visit when PWA installability is required

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
| `make test` | Run all tests (`sudo python3 -m pytest tests/ -v`) |
| `make ci` | Full CI build: format-check + build + test |

> The Makefile exposes only `make test`. To filter by suite or
> category, call `python3 -m pytest tests/test_NN_*.py -v` /
> `-k "keyword"` directly. See [Testing](testing.md).

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
  CC [M]  src/kernel-module/fw_main.o
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

`Cargo.toml` pre-defines `release` / `dev` / `dev-with-debug` / `asan` and
other profiles, each tuned for a different use case:

| Profile | Build artifact | Purpose | Build command |
|---------|----------------|---------|---------------|
| `release` (default) | Compact `strip`-ed binary | Production deployment | `cargo build --release` |
| `dev-with-debug` | Unstripped, with DWARF + symbols | Field crash analysis; use `addr2line` to unwind stacks | `cargo build --release --profile dev-with-debug` |
| `asan` | With ASAN runtime | Memory-safety checks, requires nightly | `cargo +nightly build --profile asan` |

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

Produces a compact `strip`-ed binary (with the frontend artifacts embedded; the
exact size varies with the frontend bundle — measure it with
`stat -c %s build/daemon/firewall-daemon`) — the default for `make deb` /
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
| `/usr/sbin/firewall-daemon` | Daemon binary (already `strip`-ed, with embedded frontend artifacts) |
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
  → compact `strip`-ed binary
- `dev-with-debug`: inherits release, keeps DWARF + symbols
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
| `build/daemon/firewall-daemon` | Daemon binary (`strip`-ed, with embedded frontend artifacts, default `release` profile; measure size with `stat -c %s build/daemon/firewall-daemon`) |
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
already calls `sudo python3 -m pytest tests/ -v` and the pytest
environment inherits the current PATH (including `~/.cargo/bin`),
so this is handled automatically.
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