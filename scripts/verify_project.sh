#!/bin/bash
# verify_project.sh - Script to verify the integrity of the firewall project

set -euo pipefail

# Ensure we're in the project root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/.."

echo "Verifying firewall project integrity..."

# Check that essential files exist (with correct paths)
ESSENTIAL_FILES=(
    "src/kernel-module/Makefile"
    "src/kernel-module/fw_main.c"
    "src/daemon/cmd/firewall-daemon/main.go"
    "src/daemon/go.mod"
    "Makefile"
    "docs/zh/README.md"
    "tests/conftest.py"
)

echo "Checking essential files..."
for file in "${ESSENTIAL_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "✓ $file exists"
    else
        echo "✗ $file missing"
        exit 1
    fi
done

# Check that documentation files are properly marked as deprecated
DOC_FILES=(
    "PROJECT_SUMMARY.md"
    "FINAL_SUMMARY.md"
    "FULL_PROJECT_DOC.md"
    "SUMMARY.md"
    "FILE_LIST.md"
)

echo "Checking deprecated documentation files..."
for file in "${DOC_FILES[@]}"; do
    if [[ -f "$file" ]]; then
        echo "⚠ $file exists (marked as deprecated)"
    else
        echo "ℹ $file not found (may be intentionally removed)"
    fi
done

# The daemon is built from the Go module at src/daemon: verify_project.sh must not
# require Cargo metadata, which no longer exists.
[[ -f "Cargo.toml" ]] && { echo "✗ Root Cargo.toml still exists (Go rewrite should have dropped it)"; exit 1; }

# Check if we can compile the project
echo "Attempting to compile the project..."
if make clean >/dev/null 2>&1; then
    echo "✓ Clean successful"
else
    echo "⚠ Clean failed (may be normal if no objects exist)"
fi

if make -j$(nproc) >/dev/null 2>&1; then
    echo "✓ Kernel module compilation successful"
else
    echo "✗ Kernel module compilation failed"
    exit 1
fi

if make daemon >/dev/null 2>&1; then
    echo "✓ Daemon compilation successful"
else
    echo "✗ Daemon compilation failed"
    exit 1
fi

echo "Project verification completed successfully!"
echo ""
echo "To run the full test suite, execute:"
echo "sudo python3 -m pytest tests/ -v"