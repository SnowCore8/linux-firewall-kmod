# Development Guide

This section covers how to develop, build, and test the Linux Firewall Kernel Module.

## Table of Contents

- [Building](building.md) - Build options and process
- [Testing](testing.md) - Test framework and cases

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
├── Makefile              # Main Makefile
├── src/
│   ├── kernel/           # Kernel module source
│   │   ├── fw_fire.c
│   │   └── fw_fire.h
│   ├── daemon/           # Daemon source
│   │   ├── main.c
│   │   ├── config.c      # YAML config parsing
│   │   ├── jail.c        # Jail management
│   │   ├── monitor.c     # Log monitoring (inotify)
│   │   ├── regex.c       # PCRE2 matching
│   │   ├── database.c    # SQLite persistence
│   │   ├── metrics.c     # Prometheus metrics
│   │   └── procfs.c      # ProcFS communication
│   └── include/          # Common headers
│       └── common.h
├── tests/                # Test files
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── docs/                 # Documentation
├── config/
│   └── fw_fire.yaml      # Example config
└── scripts/              # Helper scripts
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

---

[中文版本](../../zh/development/README.md)
