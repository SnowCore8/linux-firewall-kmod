#!/bin/bash
# build.sh - 防火墙项目构建脚本

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 检查所需命令
command -v make >/dev/null 2>&1 || { echo "make not found in PATH"; exit 1; }
command -v gcc >/dev/null 2>&1 || { echo "gcc not found in PATH"; exit 1; }

# 检查依赖库
check_library() {
    local pkg_name=$1
    local apt_pkg=$2
    local rpm_pkg=$3
    
    if ! pkg-config --exists lib$pkg_name 2>/dev/null; then
        echo "Missing required library: lib$pkg_name-dev"
        echo "   安装命令（Debian/Ubuntu）: sudo apt install $apt_pkg"
        echo "   安装命令（RHEL/CentOS）: sudo yum install $rpm_pkg"
        exit 1
    fi
}

# Check for yaml library via pkg-config or library file existence
# P1-5: Removed sed -i that modified Makefile; use env var YAML_LIB instead
detect_yaml_library() {
    if pkg-config --exists libyaml 2>/dev/null; then
        echo "Found libyaml using pkg-config"
        echo "YAML_LIB=libyaml"
        return
    fi
    if pkg-config --exists yaml 2>/dev/null; then
        echo "Found yaml using pkg-config: yaml"
        echo "YAML_LIB=yaml"
        return
    fi
    # Check common library paths for yaml-0.1 / yaml
    if [ -f "/usr/lib/x86_64-linux-gnu/libyaml-0.so" ] || \
       [ -f "/usr/lib/x86_64-linux-gnu/libyaml.so" ] || \
       [ -f "/usr/lib64/libyaml-0.so" ] || \
       [ -f "/usr/lib64/libyaml.so" ]; then
        echo "Found yaml library directly on system"
        echo "YAML_LIB=yaml-0.1"
        return
    fi
    # Fallback: check pkg-config for yaml-0.1
    if pkg-config --exists yaml-0.1 2>/dev/null; then
        echo "Found yaml-0.1 using pkg-config"
        echo "YAML_LIB=yaml-0.1"
        return
    fi
    echo "libyaml-dev not found"
    echo "   安装命令（Debian/Ubuntu）: sudo apt install libyaml-dev"
    echo "   安装命令（RHEL/CentOS）: sudo yum install libyaml-devel"
    exit 1
}

YAML_LIB_INFO=$(detect_yaml_library)
echo "$YAML_LIB_INFO" | grep "^YAML_LIB=" | cut -d= -f2

# Check for sqlite3 library via pkg-config
detect_sqlite3_library() {
    if pkg-config --exists sqlite3 2>/dev/null; then
        echo "Found sqlite3 using pkg-config"
        return
    fi
    echo "libsqlite3-dev not found"
    echo "   安装命令（Debian/Ubuntu）: sudo apt install libsqlite3-dev"
    echo "   安装命令（RHEL/CentOS）: sudo yum install sqlite-devel"
    exit 1
}

detect_sqlite3_library

check_library microhttpd libmicrohttpd-dev libmicrohttpd-devel
check_library pcre2-8 libpcre2-dev pcre2-devel

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
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" kernel-module
}

build_daemon() {
    info "Building daemon..."
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" daemon
}

build_all() {
    info "Building all components..."
    make -C "$PROJECT_ROOT" -f "$PROJECT_ROOT/Makefile" all
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