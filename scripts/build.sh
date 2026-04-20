#!/bin/bash
# build.sh - Build script for firewall project

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Check required commands
command -v make >/dev/null 2>&1 || { error "make not found in PATH"; exit 1; }
command -v gcc >/dev/null 2>&1 || { error "gcc not found in PATH"; exit 1; }

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

info() { echo -e "${GREEN}INFO:${NC} $1"; }
warn() { echo -e "${YELLOW}WARN:${NC} $1"; }
error() { echo -e "${RED}ERROR:${NC} $1"; }

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  -k, --kernel    Build kernel module only"
    echo "  -d, --daemon    Build daemon only"
    echo "  -a, --all       Build all components (default)"
    echo "  -h, --help      Show this help message"
    exit 0
}

build_kernel_module() {
    info "Building kernel module..."
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" kernel-module
}

build_daemon() {
    info "Building daemon..."
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" daemon
}

build_all() {
    info "Building all components..."
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" all-with-daemon
}

# Default to building everything
BUILD_TYPE="all"

while [[ $# -gt 0 ]]; do
    case $1 in
        -k|--kernel)
            BUILD_TYPE="kernel"
            shift
            ;;
        -d|--daemon)
            BUILD_TYPE="daemon"
            shift
            ;;
        -a|--all)
            BUILD_TYPE="all"
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            error "Unknown option: $1"
            usage
            ;;
    esac
done

case $BUILD_TYPE in
    kernel)
        build_kernel_module
        ;;
    daemon)
        build_daemon
        ;;
    all)
        build_all
        ;;
    *)
        error "Invalid build type: $BUILD_TYPE"
        usage
        ;;
esac

info "Build completed successfully!"