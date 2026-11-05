#!/bin/bash
# 多版本内核模块编译脚本
# 自动检测已安装的内核头文件并为每个版本编译 firewall.ko
#
# 用法：
#   ./scripts/build-kmod-multi-version.sh              # 智能模式：优先编译当前运行内核
#   ./scripts/build-kmod-multi-version.sh --all        # 编译所有可用版本
#   ./scripts/build-kmod-multi-version.sh 6.8.0-147-generic  # 只编译指定版本
#   ./scripts/build-kmod-multi-version.sh --list       # 列出可用版本与兼容性
#   ./scripts/build-kmod-multi-version.sh --check      # 仅检测兼容性，不编译

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_BASE="$PROJECT_ROOT/build"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_debug() {
    echo -e "${BLUE}[DEBUG]${NC} $*"
}

# 获取当前运行的内核版本
get_running_kernel() {
    uname -r
}

# 检查指定版本的内核头文件是否存在
check_headers_available() {
    local version="$1"
    [ -d "/lib/modules/$version/build" ]
}

# 检测兼容性并显示信息
detect_compatibility() {
    local running_kernel
    running_kernel=$(get_running_kernel)
    
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}内核兼容性检测${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "当前运行内核: ${GREEN}$running_kernel${NC}"
    echo
    
    local available_versions=()
    local compatible_versions=()
    local incompatible_versions=()
    
    # 收集所有已安装的内核头文件
    for dir in /lib/modules/*/build; do
        if [ -d "$dir" ]; then
            local version
            version=$(basename "$(dirname "$dir")")
            available_versions+=("$version")
            
            # 检查兼容性（主版本和次版本匹配）
            local running_major running_minor
            local version_major version_minor
            
            running_major=$(echo "$running_kernel" | cut -d. -f1)
            running_minor=$(echo "$running_kernel" | cut -d. -f2)
            version_major=$(echo "$version" | cut -d. -f1)
            version_minor=$(echo "$version" | cut -d. -f2)
            
            if [ "$running_major" = "$version_major" ] && [ "$running_minor" = "$version_minor" ]; then
                compatible_versions+=("$version")
            else
                incompatible_versions+=("$version")
            fi
        fi
    done
    
    # 显示检测结果
    echo -e "${BLUE}已安装的内核头文件 (${#available_versions[@]} 个):${NC}"
    for version in "${available_versions[@]}"; do
        if [ "$version" = "$running_kernel" ]; then
            echo -e "  ${GREEN}✓ $version (当前运行)${NC}"
        else
            is_compatible=false
            for compat in "${compatible_versions[@]}"; do
                if [ "$version" = "$compat" ]; then
                    is_compatible=true
                    break
                fi
            done
            if $is_compatible; then
                echo -e "  ${YELLOW}~ $version (兼容，可编译)${NC}"
            else
                echo -e "  ${RED}✗ $version (不兼容，仅编译)${NC}"
            fi
        fi
    done
    echo
    
    # 显示兼容性摘要
    echo -e "${BLUE}兼容性摘要:${NC}"
    echo -e "  可直接加载测试: ${GREEN}${#compatible_versions[@]}${NC} 个版本"
    echo -e "  仅可编译: ${RED}${#incompatible_versions[@]}${NC} 个版本"
    echo
    
    # 返回当前运行内核是否有头文件
    if check_headers_available "$running_kernel"; then
        echo -e "${GREEN}✓ 当前运行内核的头文件已安装，可以直接编译和测试${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠ 当前运行内核的头文件未安装${NC}"
        echo -e "${YELLOW}  安装命令: sudo apt install linux-headers-$running_kernel${NC}"
        return 1
    fi
}

# 列出可用的内核版本与兼容性
list_available_versions() {
    detect_compatibility
}

# 编译指定版本的内核模块
build_for_version() {
    local kernel_version="$1"
    local kdir="/lib/modules/$kernel_version/build"
    local output_dir="$BUILD_BASE/kernel-module/$kernel_version"
    
    if [ ! -d "$kdir" ]; then
        log_error "内核头文件不存在: $kdir"
        log_error "安装命令: sudo apt install linux-headers-$kernel_version"
        return 1
    fi
    
    log_info "编译 firewall.ko for $kernel_version"
    
    # 创建输出目录
    mkdir -p "$output_dir"
    
    # 进入项目根目录
    cd "$PROJECT_ROOT"
    
    # 生成契约文件（如果还没有）
    if [ ! -f "contract/generated/netlink_uapi.h" ]; then
        log_info "生成契约文件..."
        make contract >/dev/null || {
            log_error "契约生成失败"
            return 1
        }
    fi
    
    # 编译内核模块
    cd src/kernel-module
    make clean >/dev/null 2>&1 || true
    
    # 使用内核构建系统编译
    make -C "$kdir" M="$PWD" modules CC="gcc" 2>&1 | \
        grep -E "(error|warning:|CC|LD|MODPOST)" || true
    
    # 检查编译结果
    if [ ! -f "firewall.ko" ]; then
        log_error "编译失败: $kernel_version"
        return 1
    fi
    
    # 复制产物
    cp firewall.ko "$output_dir/"
    log_info "✓ $kernel_version -> $output_dir/firewall.ko"
    
    # 显示模块信息
    modinfo "$output_dir/firewall.ko" | grep -E "^(filename|vermagic|srcversion)" | sed 's/^/  /'
    
    # 清理源码目录中的中间文件
    make clean >/dev/null 2>&1 || true
    
    return 0
}

# 智能编译：优先编译当前运行内核
build_smart() {
    local running_kernel
    running_kernel=$(get_running_kernel)
    
    log_info "智能模式：检测当前运行内核..."
    echo -e "当前运行内核: ${GREEN}$running_kernel${NC}"
    echo
    
    # 检查当前运行内核的头文件是否存在
    if check_headers_available "$running_kernel"; then
        log_info "当前运行内核的头文件已安装"
        detect_compatibility
        echo
        log_info "开始编译当前运行内核: $running_kernel"
        
        if build_for_version "$running_kernel"; then
            log_info "✓ 编译成功"
            echo
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}下一步操作:${NC}"
            echo -e "  加载模块: sudo insmod build/kernel-module/$running_kernel/firewall.ko"
            echo -e "  运行测试: sudo make test"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════${NC}"
            exit 0
        else
            log_error "编译失败"
            exit 1
        fi
    else
        log_warn "当前运行内核的头文件未安装"
        echo
        detect_compatibility
        echo
        
        # 查找兼容的版本
        local compatible_versions=()
        for dir in /lib/modules/*/build; do
            if [ -d "$dir" ]; then
                local version
                version=$(basename "$(dirname "$dir")")
                local running_major running_minor version_major version_minor
                running_major=$(echo "$running_kernel" | cut -d. -f1)
                running_minor=$(echo "$running_kernel" | cut -d. -f2)
                version_major=$(echo "$version" | cut -d. -f1)
                version_minor=$(echo "$version" | cut -d. -f2)
                
                if [ "$running_major" = "$version_major" ] && [ "$running_minor" = "$version_minor" ]; then
                    compatible_versions+=("$version")
                fi
            fi
        done
        
        if [ ${#compatible_versions[@]} -gt 0 ]; then
            log_info "找到 ${#compatible_versions[@]} 个兼容版本，将编译第一个"
            log_info "推荐安装当前内核头文件: sudo apt install linux-headers-$running_kernel"
            echo
            
            if build_for_version "${compatible_versions[0]}"; then
                log_info "✓ 编译成功: ${compatible_versions[0]}"
                exit 0
            else
                log_error "编译失败"
                exit 1
            fi
        else
            log_error "未找到兼容的内核头文件"
            log_error "请安装: sudo apt install linux-headers-$running_kernel"
            exit 1
        fi
    fi
}

# 编译所有可用版本
build_all() {
    log_info "编译所有可用的内核版本..."
    detect_compatibility
    echo
    
    local versions=()
    for dir in /lib/modules/*/build; do
        if [ -d "$dir" ]; then
            versions+=("$(basename "$(dirname "$dir")")")
        fi
    done
    
    if [ ${#versions[@]} -eq 0 ]; then
        log_error "未找到任何已安装的内核头文件"
        log_error "请先安装: sudo apt install linux-headers-\$(uname -r)"
        exit 1
    fi
    
    log_info "找到 ${#versions[@]} 个内核版本"
    
    local success=0
    local failed=0
    
    for version in "${versions[@]}"; do
        if build_for_version "$version"; then
            ((success++))
        else
            ((failed++))
        fi
        echo
    done
    
    log_info "编译完成: 成功 $success, 失败 $failed"
    
    if [ $failed -gt 0 ]; then
        exit 1
    fi
}

# 主逻辑
main() {
    cd "$PROJECT_ROOT"
    
    # 处理参数
    if [ $# -eq 0 ]; then
        # 无参数：智能模式，优先编译当前运行内核
        build_smart
        
    elif [ "$1" = "--all" ]; then
        # 编译所有版本
        build_all
        
    elif [ "$1" = "--list" ]; then
        # 列出可用版本与兼容性
        detect_compatibility
        
    elif [ "$1" = "--check" ]; then
        # 仅检测兼容性
        detect_compatibility
        exit $?
        
    elif [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
        echo "用法: $0 [选项] [内核版本...]"
        echo
        echo "选项:"
        echo "  (无)            智能模式：优先编译当前运行内核"
        echo "  --all           编译所有可用的内核版本"
        echo "  --list          列出已安装的内核头文件与兼容性"
        echo "  --check         仅检测兼容性，不编译"
        echo "  --help, -h      显示帮助信息"
        echo
        echo "示例:"
        echo "  $0                           # 智能模式：编译当前运行内核"
        echo "  $0 --all                     # 编译所有可用版本"
        echo "  $0 6.8.0-147-generic         # 只编译指定版本"
        echo "  $0 6.8.0-146-generic 6.8.0-147-generic  # 编译多个版本"
        echo
        echo "兼容性说明:"
        echo "  - 主版本和次版本相同的内核视为兼容（如 6.8.0-146 与 6.8.0-147）"
        echo "  - 兼容的版本编译后可以直接加载测试"
        echo "  - 不兼容的版本只能编译，加载时可能因 vermagic 不匹配而失败"
        
    else
        # 编译指定的版本
        local success=0
        local failed=0
        
        for version in "$@"; do
            if build_for_version "$version"; then
                ((success++))
            else
                ((failed++))
            fi
            echo
        done
        
        log_info "编译完成: 成功 $success, 失败 $failed"
        
        if [ $failed -gt 0 ]; then
            exit 1
        fi
    fi
}

main "$@"
