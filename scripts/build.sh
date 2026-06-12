#!/bin/bash
# build.sh - 防火墙项目构建脚本
# 内核模块用 gcc 编译, 守护进程用 Rust (cargo) 构建

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 检查所需命令
command -v make >/dev/null 2>&1 || { echo "make not found in PATH"; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "gcc not found in PATH"; exit 1; }
command -v cargo >/dev/null 2>&1 || { echo "cargo not found in PATH"; exit 1; }

# 颜色定义
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
    make -C "$PROJECT_ROOT" kernel-module
}

build_daemon() {
    info "Building daemon (Rust)..."
    make -C "$PROJECT_ROOT" daemon
}

build_all() {
    info "Building all components..."
    make -C "$PROJECT_ROOT" all
}

# 默认构建所有组件
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