# Contributing Guide

## Welcome

Thank you for your interest in the **linux-firewall-kmod** project! Whether it's fixing bugs, adding new features, improving documentation, or suggesting ideas — every contribution makes the project better.

## Before You Start

- Read the [README.md](index.md) to understand project goals and core features
- Browse the [Documentation Index](index.md) to familiarize yourself with project docs
- Check existing [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) to avoid duplicates
- Read the [Git Workflow Guide](git-workflow.md) to understand collaboration processes

## Development Environment Setup

### System Requirements

- **Operating System**: Linux (Debian/Ubuntu or RHEL/CentOS/Fedora)
- **Kernel Version**: 4.19+ (5.10+ recommended)
- **Architecture**: x86_64

### Install Dependencies

```bash
# Debian/Ubuntu
sudo apt install build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev \
  pkg-config git

# RHEL/CentOS/Fedora
sudo dnf install gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel \
  pkg-config git
```

### Clone & Build

```bash
git clone https://github.com/SnowCore8/linux-firewall-kmod.git
cd linux-firewall-kmod

# Build kernel module + daemon
make

# Build kernel module only
make kernel-module

# Build daemon only
make daemon
```

### Run Tests

```bash
# Run all tests (12 suites, 106 tests)
make test

# Run unit tests only
make unit-test

# Run integration tests only
make integration-test
```

## Ways to Contribute

### 1. Report Bugs

Use the [Bug Report Template](https://github.com/SnowCore8/linux-firewall-kmod/blob/master/.github/ISSUE_TEMPLATE/bug_report.md) to submit an issue, including:
- Environment information (kernel version, distribution, project version)
- Problem description and reproduction steps
- Expected vs actual behavior
- Relevant log output (kernel log, daemon log)

### 2. Request New Features

Use the [Feature Request Template](https://github.com/SnowCore8/linux-firewall-kmod/blob/master/.github/ISSUE_TEMPLATE/feature_request.md) to submit an issue, describing:
- Feature description and use case
- Alternative solutions (if any)
- Reference implementation or design ideas

### 3. Submit Code Fixes

1. Comment on the issue to indicate you're working on it
2. Fork the repo and create a feature branch
3. Write code and add tests
4. Ensure all tests pass
5. Submit a Pull Request

### 4. Improve Documentation

- Fix typos or unclear expressions
- Add missing configuration explanations
- Add usage examples and best practices
- Translate documentation into other languages

### 5. Add Test Cases

- Add unit tests for uncovered code paths
- Add regression tests for edge cases
- Improve integration test scenarios

## Code Standards

### C Language Coding Standards

| Rule | Description |
|------|-------------|
| Naming | Functions/variables use `snake_case`, macros use `UPPER_CASE` |
| Indentation | 4 spaces, tabs forbidden |
| Line Width | Maximum 100 characters |
| Braces | K&R style, opening brace on same line |
| Function Length | Single function should not exceed 50 lines; complex logic should be split into sub-functions |

### Comment Standards

- **Use Chinese comments uniformly**
- Comments explain "why" not "what"
- Public functions must include docstrings (functionality, parameters, return values)
- Complex algorithms must include implementation notes

```c
/**
 * Check if IP is in the whitelist
 * @param ip IPv4 address to check (network byte order)
 * @return 1 if in whitelist, 0 if not
 * 
 * Note: Uses RCU read-side critical section, caller does not need additional locking
 */
int whitelist_check(__be32 ip);
```

### Commit Message Standards

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

| Type | Description | Example |
|------|-------------|---------|
| `feat` | New feature | `feat(rules): add CIDR range matching support` |
| `fix` | Bug fix | `fix(kernel): resolve RCU grace period deadlock` |
| `docs` | Documentation update | `docs(readme): add quick start guide` |
| `style` | Code formatting | `style: fix indentation in rule_parser.c` |
| `refactor` | Code refactoring | `refactor(hash): simplify resize logic` |
| `perf` | Performance optimization | `perf(lookup): reduce lock contention in hot path` |
| `test` | Test related | `test(rules): add edge case for empty rule file` |
| `chore` | Build/tooling | `chore(ci): add kernel 6.1 to test matrix` |

## Pull Request Process

### 1. Fork the Repository

Click "Fork" on GitHub to copy the repository to your account.

### 2. Create a Feature Branch

```bash
git clone https://github.com/<your-username>/linux-firewall-kmod.git
cd linux-firewall-kmod
git checkout main
git checkout -b feature/your-feature-name
```

### 3. Develop & Commit

```bash
# Write code...

# Ensure tests pass
make test

# Commit changes
git add <files>
git commit -m "feat(scope): your commit message"
```

### 4. Push & Create PR

```bash
git push origin feature/your-feature-name
```

Create a Pull Request on GitHub targeting the `main` branch of this repository.

### 5. Code Review

Mainters will respond within 48 hours. PRs are merged after review approval.

### 6. Merge

After the PR is merged, the feature branch can be safely deleted.

## PR Checklist

Before submitting a PR, please confirm:

- [ ] Code passes all tests (`make test`)
- [ ] Follows Conventional Commits specification
- [ ] New features have corresponding test cases
- [ ] Documentation is updated accordingly
- [ ] PR description is clear, explaining what changed and why
- [ ] No sensitive information leaked (keys, configs, etc.)

## Review Standards

| Dimension | Requirements |
|-----------|--------------|
| Correctness | Logic is correct, no known bugs |
| Performance | Kernelspace code avoids blocking operations |
| Security | Strict input validation, no memory leaks |
| Readability | Clear naming, sufficient comments |
| Testing | Covers normal paths and edge cases |

## Code of Conduct

- Respect all contributors, use friendly and inclusive language
- Accept constructive criticism, focus on issues not personalities
- Maintain community harmony, no personal attacks or discriminatory speech
- Contact project maintainers if you observe inappropriate behavior

## License

This project is open-sourced under the [MIT License](https://github.com/SnowCore8/linux-firewall-kmod/blob/master/LICENSE). By submitting code, you agree to release your code under the MIT License.

## Contact

- **GitHub**: [@SnowCore8](https://github.com/SnowCore8)
- **Email**: snowcore8@gmail.com
- **Issues**: [Submit issues or suggestions](https://github.com/SnowCore8/linux-firewall-kmod/issues)
