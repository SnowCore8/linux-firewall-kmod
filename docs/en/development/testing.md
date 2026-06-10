# Testing

This document describes the test framework and test cases for the Linux Firewall Kernel Module.

## Test Types

| Type | Location | Description |
|------|----------|-------------|
| Unit Tests | `tests/unit/` | Test individual functions and modules |
| Integration Tests | `tests/integration/` | Test inter-component interaction |
| Stress Tests | `tests/stress/` | Test performance and edge cases |

## Running Tests

### Run All Tests

```bash
make test
```

### Run Specific Tests

```bash
# Unit tests only
make test-unit

# Integration tests only
make test-integration

# Run a single test file
./tests/unit/test_hash_table
```

## Unit Tests

### Hash Table Tests

Tests kernel hash table insert, lookup, and delete operations.

```bash
./tests/unit/test_hash_table
```

Test cases:

| Case | Description |
|------|-------------|
| `test_insert` | Insert single IP |
| `test_lookup` | Lookup existing IP |
| `test_delete` | Delete IP |
| `test_duplicate` | Insert duplicate IP |
| `test_capacity` | Test 4096 capacity limit |
| `test_expiry` | Test expiry cleanup |

### Whitelist Tests

Tests whitelist add, remove, and match operations.

```bash
./tests/unit/test_whitelist
```

Test cases:

| Case | Description |
|------|-------------|
| `test_add` | Add single IP |
| `test_remove` | Remove IP |
| `test_match` | Match IP |
| `test_cidr` | CIDR subnet matching |
| `test_capacity` | Test 64 capacity limit |

### Regex Tests

Tests PCRE2 regex compilation and matching.

```bash
./tests/unit/test_regex
```

Test cases:

| Case | Description |
|------|-------------|
| `test_compile` | Compile regex expression |
| `test_host_placeholder` | `<HOST>` placeholder replacement |
| `test_match_ipv4` | Match IPv4 address |
| `test_no_match` | Non-matching cases |
| `test_invalid_regex` | Invalid regex handling |

### Configuration Parsing Tests

Tests YAML configuration file parsing.

```bash
./tests/unit/test_config
```

Test cases:

| Case | Description |
|------|-------------|
| `test_parse_global` | Parse global config |
| `test_parse_jail` | Parse jail config |
| `test_parse_whitelist` | Parse whitelist |
| `test_invalid_yaml` | Invalid YAML handling |
| `test_missing_fields` | Missing required fields handling |

## Integration Tests

### Complete Ban Flow Test

Tests the full flow from log matching to kernel banning.

```bash
sudo ./tests/integration/test_full_ban
```

Test steps:

```
1. Start test environment
2. Load kernel module
3. Start daemon
4. Write test log lines
5. Wait for inotify trigger
6. Verify PCRE2 match
7. Verify counter increment
8. Verify threshold trigger
9. Verify kernel ban
10. Verify packets are dropped
11. Clean up test environment
```

### Auto-Unban Test

Tests automatic unban when ban expires.

```bash
sudo ./tests/integration/test_auto_unban
```

Test steps:

```
1. Ban test IP (short duration)
2. Verify ban is active
3. Wait for expiry
4. Verify automatic unban
5. Verify packets pass again
```

### ProcFS Interface Test

Tests ProcFS read/write operations.

```bash
sudo ./tests/integration/test_procfs
```

Test cases:

| Case | Description |
|------|-------------|
| `test_read_status` | Read module status |
| `test_read_banned` | Read banned list |
| `test_write_ban` | Write ban command |
| `test_write_unban` | Write unban command |
| `test_write_clear` | Write clear command |

## Stress Tests

### Hash Table Stress Test

Tests performance at 4096 capacity.

```bash
sudo ./tests/stress/test_hash_table_stress
```

Test scenarios:

| Scenario | Description |
|----------|-------------|
| Full table insert | Insert 4096 IPs |
| Full table lookup | Lookup in full table |
| Full table delete | Delete from full table |
| Mixed operations | Insert/lookup/delete mix |

### Concurrency Test

Tests multi-CPU concurrent access.

```bash
sudo ./tests/stress/test_concurrent
```

Test scenarios:

| Scenario | Description |
|----------|-------------|
| Concurrent reads | Multi-CPU concurrent lookup |
| Concurrent writes | Multi-CPU concurrent insert |
| Mixed R/W | Concurrent read + write |

### Packet Stress Test

Tests performance under high traffic.

```bash
sudo ./tests/stress/test_packet_stress
```

Use `hping3` or `nping` to generate high traffic:

```bash
# Install hping3
sudo apt install hping3

# Generate test traffic
hping3 --flood -p 22 -S <target_ip>
```

## Test Coverage

### Generate Coverage Report

```bash
# Install lcov
sudo apt install lcov

# Build with coverage flags
make clean
CFLAGS="--coverage" make

# Run tests
make test

# Generate report
lcov --capture --directory . --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

### View Report

```bash
# Open in browser
xdg-open coverage-html/index.html
```

## Memory Detection

### Valgrind

Detect daemon memory issues:

```bash
# Build with debug info
make daemon CFLAGS="-g -O0"

# Run valgrind
sudo valgrind --leak-check=full --show-leak-kinds=all \
    ./fwctl start

# Run for a while then stop, check report
```

### AddressSanitizer

```bash
# Build ASan version
make asan

# Run
sudo ./fwctl asan

# Check ASan output
```

## Kernel Module Test Tools

### Using kselftest

Linux kernel self-test framework:

```bash
# Run network-related self-tests
sudo make -C tools/testing/selftests run_tests=net
```

### Using ktap

Kernel TAP testing:

```bash
sudo modprobe firewall
./tests/kernel/test_firewall.ktap
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@v3

      - name: Install dependencies
        run: |
          sudo apt update
          sudo apt install -y \
            build-essential \
            linux-headers-$(uname -r) \
            libyaml-dev \
            libsqlite3-dev \
            libmicrohttpd-dev \
            libpcre2-dev

      - name: Build
        run: make

      - name: Run tests
        run: sudo make test

      - name: Run ASan tests
        run: sudo make asan
```

## Writing New Tests

### Unit Test Template

```c
#include <stdio.h>
#include <assert.h>
#include "../src/include/common.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void test_##name(void)

#define ASSERT(cond) \
    do { \
        if (cond) { tests_passed++; } \
        else { tests_failed++; printf("FAIL: %s\n", #cond); } \
    } while(0)

TEST(my_feature) {
    // Setup
    ...

    // Execute
    ...

    // Verify
    ASSERT(result == expected);
}

int main(void) {
    printf("Running tests...\n");

    test_my_feature();

    printf("\nResults: %d passed, %d failed\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
```