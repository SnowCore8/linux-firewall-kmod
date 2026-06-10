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
    libyaml-dev \
    libsqlite3-dev \
    libmicrohttpd-dev \
    libpcre2-dev \
    pkg-config \
    valgrind \
    clang \
    cmake
```

## Project Structure

```
linux-firewall-kmod/
├── Makefile              # Main Makefile (all / kernel-module / daemon / test)
├── src/
│   ├── kernel-module/    # Kernel module source
│   │   ├── firewall-main.c   # Module entry / netfilter hook registration
│   │   ├── ban-manager.c     # Hash-table ban management
│   │   ├── whitelist.c       # Whitelist (exact + CIDR two-stage matching)
│   │   ├── netfilter.c       # Packet handling and ban decision
│   │   ├── netdev.c          # Network device helpers
│   │   ├── procfs.c          # /proc/firewall/* interface
│   │   ├── state-persist.c   # Kernel state save/restore
│   │   ├── cleanup.c         # Module exit cleanup
│   │   └── firewall.h        # Common header
│   └── daemon/           # Userspace daemon
│       ├── firewall-daemon.c   # Daemon entry
│       ├── config-parser.c     # YAML config parsing (strict mode)
│       ├── file-monitor.c      # inotify log monitoring
│       ├── failed-tracker.c    # Jail failure counter
│       ├── ban-manager.c       # Ban/unban scheduler
│       ├── metrics.c           # Prometheus exporter
│       └── *.h                 # Matching headers
├── tests/                # Tests
│   ├── run_tests.sh
│   ├── test_framework.sh
│   ├── test_config.sh
│   ├── suites/           # Test suites
│   └── reports/          # Generated reports
├── docs/                 # HonKit documentation
├── config/               # Example YAML configs
├── scripts/              # Helper scripts (build, verify, deb packaging)
└── debian/               # Debian packaging metadata
```

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