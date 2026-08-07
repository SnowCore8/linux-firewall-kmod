# Development Guide

This section covers how to develop, build, and test the Linux Firewall Kernel Module.

## Development Environment

### Recommended Configuration

| Item | Requirement |
|------|-------------|
| OS | Ubuntu 22.04+ / Debian 12+ |
| GCC | 12+ |
| Make | 4.0+ |
| Git | 2.30+ |

### Install Development Dependencies

```bash
# Ubuntu/Debian
sudo apt install -y \
    build-essential \
    linux-headers-$(uname -r) \
    pkg-config \
    valgrind \
    clang \
    cmake
```

## Project Structure

```mermaid
graph LR
    ROOT["linux-firewall-kmod/"]
    KERNEL["src/kernel-module/<br/>C kernel module"]
    DAEMON["src/daemon/<br/>Rust daemon"]
    FRONTEND["frontend/<br/>Leptos WASM frontend"]
    STATIC["src/daemon/web_ui/static/<br/>compiled static assets"]
    SUPPORT["config/ · tests/ · docs/<br/>scripts/ · debian/ · grafana/"]

    ROOT --> KERNEL
    ROOT --> DAEMON
    ROOT --> FRONTEND
    ROOT --> SUPPORT
    FRONTEND -->|"trunk build"| STATIC
    STATIC -->|"rust-embed"| DAEMON
    DAEMON <-->|"netlink"| KERNEL
```

### Three Runtime Components

| Component | Entry point | Responsibility |
|-----------|-------------|----------------|
| Kernel module | `src/kernel-module/firewall-main.c` | Registers netfilter hooks, maintains bans and whitelists, and makes packet-path decisions |
| Daemon | `src/daemon/main.rs`, `src/daemon/lib.rs` | Parses configuration and logs, applies ban policy, persists state, and serves HTTP |
| Web frontend | `frontend/src/main.rs` | Leptos management UI; embedded in the daemon binary rather than deployed separately |

### Build Pipeline

`make daemon` first runs `make frontend`. Trunk follows
`frontend/Trunk.toml` and writes the frontend bundle to
`src/daemon/web_ui/static/`; `rust-embed` then compiles those assets into
`firewall-daemon`.

The remaining top-level directories contain YAML configuration (`config/`),
integration tests (`tests/`), published documentation (`docs/`), helper scripts
(`scripts/`), Debian packaging metadata (`debian/`), and Grafana resources
(`grafana/`).

## Code Standards

### C Language Standards

- Use C99 standard
- 4-space indentation
- Function names use `snake_case`
- Constants use `UPPER_CASE`
- Structs use `snake_case` with `_t` suffix

### Kernel Module Standards

- Follow Linux kernel coding style
- Use `pr_*` macros for logging
- Mark init/exit functions with `__init` and `__exit`
- Avoid sleeping in atomic context

### Commit Convention

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation update |
| `style` | Code formatting |
| `refactor` | Refactoring |
| `perf` | Performance optimization |
| `test` | Test related |
| `chore` | Build/toolchain |

## Contribution Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/amazing-feature`)
3. Commit changes (`git commit -m 'feat: add amazing feature'`)
4. Run tests (`make test`)
5. Push branch (`git push origin feat/amazing-feature`)
6. Create a Pull Request