#!/bin/bash
# run_tests.sh - 统一测试入口
# 用法:
#   ./tests/run_tests.sh                  # 运行所有测试
#   ./tests/run_tests.sh --suite 03       # 运行单个测试套件
#   ./tests/run_tests.sh --category security  # 按类别运行
#   ./tests/run_tests.sh --report         # 生成报告
#   ./tests/run_tests.sh --help           # 显示帮助

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 加载测试框架和配置
source ./test_framework.sh
source ./test_config.sh

# 注册清理函数
trap fw_cleanup EXIT

# ============================================================================
# 命令行参数解析
# ============================================================================
RUN_ALL=true
RUN_SUITE=""
RUN_CATEGORY=""
GEN_REPORT=false
SHOW_HELP=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite)
            RUN_ALL=false
            RUN_SUITE="$2"
            shift 2
            ;;
        --category)
            RUN_ALL=false
            RUN_CATEGORY="$2"
            shift 2
            ;;
        --report)
            GEN_REPORT=true
            shift
            ;;
        --help|-h)
            SHOW_HELP=true
            shift
            ;;
        --debug)
            TEST_DEBUG=1
            shift
            ;;
        *)
            echo "未知参数: $1"
            echo "使用 --help 查看用法"
            exit 1
            ;;
    esac
done

if [[ "$SHOW_HELP" == true ]]; then
    cat << 'EOF'
用法: ./tests/run_tests.sh [选项]

选项:
  (无)                    运行所有测试
  --suite <编号或名称>     运行单个测试套件 (如: 03, 03_ban_unban)
  --category <类别>        按类别运行 (如: daemon, performance)
  --report                 生成测试报告
  --debug                  启用调试输出
  --help                   显示此帮助

示例:
  ./tests/run_tests.sh                    # 运行所有测试
  ./tests/run_tests.sh --suite 03         # 运行封禁/解封测试
  ./tests/run_tests.sh --suite 09         # 运行配置测试
  ./tests/run_tests.sh --report           # 运行所有测试并生成报告
  ./tests/run_tests.sh --debug            # 运行所有测试并显示调试信息
EOF
    exit 0
fi

# ============================================================================
# 预检
# ============================================================================
fw_section "测试预检"

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    fw_log_error "需要 root 权限运行测试"
    exit 1
fi
fw_log_info "Root 权限检查通过"

# 始终清理并重新编译以确保最新代码
fw_log_info "清理旧产物..."
cd "$PROJECT_ROOT" && make clean >/dev/null 2>&1
cd "$SCRIPT_DIR"

# 编译内核模块
fw_log_info "编译内核模块..."
cd "$PROJECT_ROOT" && make kernel-module 2>/tmp/fw_compile_stderr_$$.log || {
    if [[ -s /tmp/fw_compile_stderr_$$.log ]]; then
        fw_log_error "编译输出: $(cat /tmp/fw_compile_stderr_$$.log)"
    fi
    rm -f /tmp/fw_compile_stderr_$$.log
    fw_log_error "内核模块编译失败"
    exit 1
}
cd "$SCRIPT_DIR"
# 输出编译警告
if [[ -s /tmp/fw_compile_stderr_$$.log ]]; then
    while IFS= read -r line; do
        fw_log_warn "编译警告: $line"
    done < /tmp/fw_compile_stderr_$$.log
    fw_log_info "清理编译临时文件..."
fi
rm -f /tmp/fw_compile_stderr_$$.log
# 验证编译产物
if [[ ! -f "$KERNEL_MODULE_PATH" ]]; then
    fw_log_error "内核模块编译成功但产物不存在: $KERNEL_MODULE_PATH"
    exit 1
fi

# 编译守护进程
DAEMON_BIN="$PROJECT_ROOT/build/daemon/firewall-daemon"
fw_log_info "编译用户态守护进程..."
cd "$PROJECT_ROOT" && make daemon 2>/tmp/fw_compile_stderr_$$.log || {
    rm -f /tmp/fw_compile_stderr_$$.log
    fw_log_warn "守护进程编译失败（部分测试可能跳过）"
}
cd "$SCRIPT_DIR"
# 输出编译警告
if [[ -s /tmp/fw_compile_stderr_$$.log ]]; then
    while IFS= read -r line; do
        fw_log_warn "编译警告: $line"
    done < /tmp/fw_compile_stderr_$$.log
    fw_log_info "清理编译临时文件..."
fi
rm -f /tmp/fw_compile_stderr_$$.log
# 验证编译产物
if [[ -f "$DAEMON_BIN" ]]; then
    fw_log_info "守护进程编译成功"
else
    fw_log_warn "守护进程编译失败（部分测试可能跳过）"
fi

# 安全预检
fw_log_info "测试模式：仅加载/卸载模块，不安装到系统"

# 加载内核模块
fw_section "加载内核模块"
fw_log_debug "KERNEL_MODULE_PATH=$KERNEL_MODULE_PATH"
fw_log_debug "PROC_DIR=$PROC_DIR"
fw_log_debug "PROC_BANS=$PROC_BANS"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH" || {
    fw_log_error "内核模块加载失败，终止测试"
    exit 1
}

# 验证模块完全就绪（lsmod + procfs 双重检查）
fw_log_info "验证模块就绪..."
sleep 1  # 等待模块完全初始化

_module_ready=false
for i in 1 2 3; do
    _lsmod_ok=false
    _procfs_ok=false
    _bans_ok=false
    
    _lsmod_raw=$(lsmod 2>/dev/null)
    if echo "$_lsmod_raw" | grep -q "^firewall"; then
        _lsmod_ok=true
    fi
    [[ -d "$PROC_DIR" ]] && _procfs_ok=true
    [[ -w "$PROC_BANS" ]] && _bans_ok=true
    
    fw_log_debug "检查 [$i]: lsmod=$_lsmod_ok procfs=$_procfs_ok bans=$_bans_ok"
    
    if [[ "$_lsmod_ok" == true ]] && [[ "$_procfs_ok" == true ]] && [[ "$_bans_ok" == true ]]; then
        _module_ready=true
        break
    fi
    sleep 1
done

if [[ "$_module_ready" != true ]]; then
    fw_log_error "模块未完全就绪"
    exit 1
fi

fw_log_info "模块就绪：lsmod ✓ | procfs ✓ | bans 接口 ✓"

# ============================================================================
# 测试套件映射
# ============================================================================
declare -A SUITE_FILES=(
    ["01_module_basic"]="suites/01_module_basic.sh"
    ["02_procfs_interface"]="suites/02_procfs_interface.sh"
    ["03_ban_unban"]="suites/03_ban_unban.sh"
    ["04_whitelist"]="suites/04_whitelist.sh"
    ["07_concurrency"]="suites/07_concurrency.sh"
    ["08_stress_perf"]="suites/08_stress_perf.sh"
    ["09_daemon_config"]="suites/09_daemon_config.sh"
    ["10_daemon_logparse"]="suites/10_daemon_logparse.sh"
    ["11_resource_mgmt"]="suites/11_resource_mgmt.sh"
    ["12_permanent_ban"]="suites/12_permanent_ban.sh"
    ["13_frp_jail"]="suites/13_frp_jail.sh"
    ["14_ban_netfilter"]="suites/14_ban_netfilter.sh"
)

declare -A SUITE_CATEGORIES=(
    ["01_module_basic"]="module basic"
    ["02_procfs_interface"]="procfs basic"
    ["03_ban_unban"]="ban basic"
    ["04_whitelist"]="whitelist security"
    ["07_concurrency"]="concurrency performance"
    ["08_stress_perf"]="stress performance"
    ["09_daemon_config"]="daemon config"
    ["10_daemon_logparse"]="daemon logparse"
    ["11_resource_mgmt"]="resource"
    ["12_permanent_ban"]="permanent ban"
    ["13_frp_jail"]="daemon frp"
    ["14_ban_netfilter"]="ban netfilter security"
)

# ============================================================================
# 运行测试
# ============================================================================

# 模块健康检查函数 - 在每个测试套件执行前验证
check_module_ready() {
    local _lsmod_out
    _lsmod_out=$(lsmod 2>/dev/null) || true
    if ! echo "$_lsmod_out" | grep -q "^firewall"; then
        fw_log_error "模块意外卸载 (lsmod 检查失败)"
        return 1
    fi
    if [[ ! -d "$PROC_DIR" ]]; then
        fw_log_error "procfs 目录不存在: $PROC_DIR"
        return 1
    fi
    if [[ ! -w "$PROC_BANS" ]]; then
        fw_log_error "bans 接口不可写: $PROC_BANS"
        return 1
    fi
    return 0
}

run_suite() {
    local suite_key="$1"
    local suite_file="${SUITE_FILES[$suite_key]:-}"

    if [[ -z "$suite_file" ]]; then
        fw_log_error "未知测试套件: $suite_key"
        return 1
    fi

    if [[ ! -f "$suite_file" ]]; then
        fw_log_error "测试套件文件不存在: $suite_file"
        return 1
    fi

    # 执行前验证模块就绪
    fw_log_debug "执行前检查模块状态: $suite_key"
    if ! check_module_ready; then
        fw_log_warn "模块未就绪，尝试重新加载..."
        # 尝试重新加载模块
        fw_ensure_module_unloaded 2>/dev/null || true
        if fw_ensure_module_loaded "$KERNEL_MODULE_PATH"; then
            fw_log_info "模块重新加载成功，继续执行 $suite_key"
            sleep 0.5
        else
            fw_log_error "模块重新加载失败，跳过测试套件: $suite_key"
            fw_log_debug "lsmod: $(lsmod 2>/dev/null | grep firewall || echo 'not found')"
            fw_log_debug "procfs: $([ -d "$PROC_DIR" ] && echo 'exists' || echo 'missing')"
            TEST_SKIP=$((TEST_SKIP + 1))
            TEST_TOTAL=$((TEST_TOTAL + 1))
            TEST_RESULTS+=("SKIP|$suite_key|模块未就绪且重新加载失败，跳过整个套件")
            return 1
        fi
    fi

    fw_log_info "运行测试套件: $suite_key"
    source "./$suite_file"
    
    # 执行后再次检查模块状态
    fw_log_debug "执行后检查模块状态: $suite_key"
    if ! lsmod | grep -q "^firewall"; then
        fw_log_warn "测试套件 $suite_key 执行后模块已卸载"
    fi
}

if [[ "$RUN_ALL" == true ]]; then
    fw_section "运行所有测试套件"

    for suite_key in $(echo "${!SUITE_FILES[@]}" | tr ' ' '\n' | sort); do
        run_suite "$suite_key"
    done
elif [[ -n "$RUN_SUITE" ]]; then
    # 尝试匹配编号或名称
    found_suite=false
    for key in "${!SUITE_FILES[@]}"; do
        if [[ "$key" == "$RUN_SUITE"* ]]; then
            run_suite "$key"
            found_suite=true
            break
        fi
    done
    if [[ "$found_suite" == false ]]; then
        fw_log_error "未找到匹配的测试套件: $RUN_SUITE"
        exit 1
    fi
elif [[ -n "$RUN_CATEGORY" ]]; then
    fw_section "按类别运行测试: $RUN_CATEGORY"

    for key in $(echo "${!SUITE_FILES[@]}" | tr ' ' '\n' | sort); do
        cats="${SUITE_CATEGORIES[$key]:-}"
        if [[ " $cats " == *" $RUN_CATEGORY "* ]]; then
            run_suite "$key"
        fi
    done
fi

# ============================================================================
# 生成报告
# ============================================================================
if [[ "$GEN_REPORT" == true ]]; then
    fw_generate_report "reports/test_report.md"
fi

# ============================================================================
# 测试完成，卸载模块
# ============================================================================
fw_section "测试完成，卸载模块"
fw_ensure_module_unloaded || fw_log_warn "模块卸载失败（可能被占用）"

# ============================================================================
# 打印摘要
# ============================================================================
fw_print_summary

exit $TEST_FAIL
