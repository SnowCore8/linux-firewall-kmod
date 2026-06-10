# Testing

This document covers the test framework and test suites for the Linux
Firewall project.

## Architecture

```
tests/
├── run_tests.sh            # unified entry point
├── test_framework.sh       # assertion functions, color output, reports
├── test_config.sh          # path/parameter variables (KERNEL_MODULE_PATH, …)
├── suites/                 # numbered suites (executed in 01–12 order)
│   ├── 01_module_basic.sh
│   ├── 02_procfs_interface.sh
│   ├── 03_ban_unban.sh
│   ├── 04_whitelist.sh
│   ├── 07_concurrency.sh
│   ├── 08_stress_perf.sh
│   ├── 09_daemon_config.sh
│   ├── 10_daemon_logparse.sh
│   ├── 11_resource_mgmt.sh
│   └── 12_permanent_ban.sh
└── reports/                # generated reports (after running)
```

> Earlier versions split tests into `tests/{unit,integration,stress}/`.
> Since v1.5 they have been reorganized into numbered suites sharing a
> single framework to remove duplication.

## Running Tests

```bash
# After building, run all suites
make test
# Underlying command: sudo ./tests/run_tests.sh
```

```bash
# Call run_tests.sh directly
./tests/run_tests.sh                    # run all suites
./tests/run_tests.sh --suite 03         # only 03_ban_unban
./tests/run_tests.sh --category security   # filter by category
./tests/run_tests.sh --report           # write report to tests/reports/
./tests/run_tests.sh --help             # help
```

## Test Suites

| # | File | Coverage |
|---|------|----------|
| 01 | `01_module_basic.sh` | Module load/unload, parameter load, sysfs readable |
| 02 | `02_procfs_interface.sh` | `/proc/firewall/{bans,whitelist,config,stats}` R/W |
| 03 | `03_ban_unban.sh` | Ban, unban, temporary/permanent, expiry cleanup |
| 04 | `04_whitelist.sh` | Exact match, CIDR subnet match, capacity limit |
| 07 | `07_concurrency.sh` | Multi-process R/W, RCU correctness |
| 08 | `08_stress_perf.sh` | Full 4096-entry table operations, latency |
| 09 | `09_daemon_config.sh` | YAML loading, strict-mode validation, jail parsing |
| 10 | `10_daemon_logparse.sh` | inotify monitoring, PCRE2 matching, jail trigger |
| 11 | `11_resource_mgmt.sh` | Memory, fds, procfs resource lifecycle |
| 12 | `12_permanent_ban.sh` | SQLite permanent ban, cross-restart recovery |

> Numbering skips 05/06: those slots were used by old suites that have
> since been merged into the ones above.

## Framework Assertions

Suites use helpers from `tests/test_framework.sh`:

| Function | Purpose |
|----------|---------|
| `fw_test_header` | Print suite title |
| `fw_subsection` | Print subsection title |
| `fw_pass` / `fw_fail` | Mark a single case as passed/failed |
| `assert_success <cmd> <msg>` | Assert command exits 0 |
| `assert_true <expr> <msg>` | Assert expression is true |
| `assert_file_exists <path>` | Assert file exists |
| `assert_dir_exists <path>` | Assert directory exists |
| `warn_test <msg>` | Soft warning (not counted as failure) |

## Module-Loading Constraints

Several suites need the kernel module to be loadable. On GitHub Actions
Azure VMs the running kernel frequently does not match the installed
headers, so module loading can fail while functional tests still pass.
The CI runner automatically skips module-dependent suites when this
happens (see [ci.yml](../../../../.github/workflows/ci.yml)).

## Memory Detection

### Valgrind

```bash
make daemon CFLAGS="-g -O0"
sudo valgrind --leak-check=full --show-leak-kinds=all \
    ./firewall-daemon -c config/default.yaml
```

### AddressSanitizer

```bash
make asan
sudo ./build/daemon/firewall-daemon-asan
```

Any `ERROR:` line in the ASan output indicates a memory defect.

## Writing a New Suite

Place new tests in `tests/suites/` with the file name `NN_description.sh`
(NN being the next available number). Each suite `source`s the framework
and config, then uses the assertions above:

```bash
#!/bin/bash
# 13_my_feature.sh - new feature tests

source ../test_framework.sh
source ../test_config.sh

fw_test_header "New feature tests"

fw_subsection "Basic behavior"
assert_true "[[ 1 -eq 1 ]]" "trivial equality holds"

fw_subsection "Boundary"
assert_true "[[ -n \"$KERNEL_MODULE_PATH\" ]]" "KERNEL_MODULE_PATH is set"
```

## CI Integration

Tests are orchestrated by the `test` job in `.github/workflows/ci.yml`:

1. Reuses artifacts from the `build` job
2. Runs `sudo ./tests/run_tests.sh --report` on the runner
3. Auto-skips module-dependent suites if the module cannot load
4. Uploads the report as a CI artifact
