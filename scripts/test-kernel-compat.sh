#!/bin/bash
# 测试内核兼容性检查功能
#
# 用法：
#   ./scripts/test-kernel-compat.sh          # 测试当前内核
#   ./scripts/test-kernel-compat.sh --all    # 测试所有已编译版本

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_BASE="$PROJECT_ROOT/build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_test() {
    echo -e "${BLUE}[TEST]${NC} $*"
}

# 测试单个内核版本
test_kernel_version() {
    local kernel_version="$1"
    local ko_path="$BUILD_BASE/kernel-module/$kernel_version/firewall.ko"
    
    if [ ! -f "$ko_path" ]; then
        log_error "未找到: $ko_path"
        return 1
    fi
    
    log_test "测试内核版本: $kernel_version"
    echo "  模块路径: $ko_path"
    
    # 清空 dmesg
    sudo dmesg -C >/dev/null 2>&1 || true
    
    # 加载模块
    if sudo insmod "$ko_path" 2>&1; then
        log_info "✓ 模块加载成功"
        
        # 等待日志输出
        sleep 1
        
        # 检查兼容性日志
        echo
        log_info "兼容性检查日志:"
        sudo dmesg | grep "firewall:" | grep -E "(兼容性|内核版本|API)" | sed 's/^/  /'
        echo
        
        # 卸载模块
        sudo rmmod firewall >/dev/null 2>&1 || true
        log_info "✓ 模块卸载成功"
        
        return 0
    else
        log_error "✗ 模块加载失败"
        
        # 检查错误日志
        echo
        log_error "错误日志:"
        sudo dmesg | grep "firewall:" | tail -10 | sed 's/^/  /'
        echo
        
        return 1
    fi
}

# 测试当前运行内核
test_current_kernel() {
    local current_kernel
    current_kernel=$(uname -r)
    
    log_info "当前运行内核: $current_kernel"
    echo
    
    # 查找对应的 .ko
    local ko_path="$BUILD_BASE/kernel-module/$current_kernel/firewall.ko"
    
    if [ ! -f "$ko_path" ]; then
        log_warn "未找到当前内核的编译产物: $ko_path"
        log_info "尝试编译当前内核版本..."
        
        cd "$PROJECT_ROOT"
        if ! ./scripts/build-kmod-multi-version.sh "$current_kernel"; then
            log_error "编译失败"
            return 1
        fi
        
        if [ ! -f "$ko_path" ]; then
            log_error "编译后仍未找到模块文件"
            return 1
        fi
    fi
    
    test_kernel_version "$current_kernel"
}

# 测试所有已编译版本
test_all_versions() {
    log_info "测试所有已编译的内核版本"
    echo
    
    local success=0
    local failed=0
    local total=0
    
    for ko_dir in "$BUILD_BASE"/kernel-module/*/; do
        if [ -d "$ko_dir" ]; then
            local kernel_version
            kernel_version=$(basename "$ko_dir")
            
            ((total+=1))
            
            if test_kernel_version "$kernel_version"; then
                ((success+=1))
            else
                ((failed+=1))
            fi
            
            echo
            echo "───────────────────────────────────────────────────────────"
            echo
        fi
    done
    
    if [ $total -eq 0 ]; then
        log_error "未找到任何已编译的内核模块"
        log_info "请先运行: ./scripts/build-kmod-multi-version.sh --all"
        return 1
    fi
    
    log_info "测试完成: 总计 $total, 成功 $success, 失败 $failed"
    
    if [ $failed -gt 0 ]; then
        return 1
    fi
    
    return 0
}

# 主逻辑
main() {
    cd "$PROJECT_ROOT"
    
    if [ $# -eq 0 ]; then
        # 无参数：测试当前内核
        test_current_kernel
        
    elif [ "$1" = "--all" ]; then
        # 测试所有版本
        test_all_versions
        
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "用法: $0 [选项]"
        echo
        echo "选项:"
        echo "  (无)       测试当前运行的内核"
        echo "  --all      测试所有已编译的内核版本"
        echo "  --help     显示帮助信息"
        
    else
        log_error "未知选项: $1"
        echo "使用 --help 查看帮助"
        exit 1
    fi
}

main "$@"
