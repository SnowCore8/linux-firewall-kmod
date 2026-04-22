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
  --category <类别>        按类别运行 (如: security, daemon, performance)
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

# 检查模块文件
if [[ ! -f "$KERNEL_MODULE_PATH" ]]; then
    fw_log_info "编译内核模块..."
    cd "$PROJECT_ROOT" && make kernel-module >/dev/null 2>&1 || {
        fw_log_error "内核模块编译失败"
        exit 1
    }
    cd "$SCRIPT_DIR"
fi
assert_file_exists "$KERNEL_MODULE_PATH" "内核模块存在"

# 安全预检
fw_log_info "测试模式：仅加载/卸载模块，不安装到系统"

# ============================================================================
# 测试套件映射
# ============================================================================
declare -A SUITE_FILES=(
    ["01_module_basic"]="suites/01_module_basic.sh"
    ["02_procfs_interface"]="suites/02_procfs_interface.sh"
    ["03_ban_unban"]="suites/03_ban_unban.sh"
    ["04_whitelist"]="suites/04_whitelist.sh"
    ["05_input_validation"]="suites/05_input_validation.sh"
    ["06_security"]="suites/06_security.sh"
    ["07_concurrency"]="suites/07_concurrency.sh"
    ["08_stress_perf"]="suites/08_stress_perf.sh"
    ["09_daemon_config"]="suites/09_daemon_config.sh"
    ["10_daemon_logparse"]="suites/10_daemon_logparse.sh"
    ["11_resource_mgmt"]="suites/11_resource_mgmt.sh"
    ["12_permanent_ban"]="suites/12_permanent_ban.sh"
    ["13_frp_jail"]="suites/13_frp_jail.sh"
)

declare -A SUITE_CATEGORIES=(
    ["01_module_basic"]="module basic"
    ["02_procfs_interface"]="procfs basic"
    ["03_ban_unban"]="ban basic"
    ["04_whitelist"]="whitelist security"
    ["05_input_validation"]="security input"
    ["06_security"]="security"
    ["07_concurrency"]="concurrency performance"
    ["08_stress_perf"]="stress performance"
    ["09_daemon_config"]="daemon config"
    ["10_daemon_logparse"]="daemon logparse"
    ["11_resource_mgmt"]="resource"
    ["12_permanent_ban"]="permanent ban"
    ["13_frp_jail"]="daemon frp"
)

# ============================================================================
# 运行测试
# ============================================================================

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

    fw_log_info "运行测试套件: $suite_key"
    source "./$suite_file"
}

if [[ "$RUN_ALL" == true ]]; then
    fw_section "运行所有测试套件"

    for suite_key in $(echo "${!SUITE_FILES[@]}" | tr ' ' '\n' | sort); do
        run_suite "$suite_key"
    done
elif [[ -n "$RUN_SUITE" ]]; then
    # 尝试匹配编号或名称
    local_found=false
    for key in "${!SUITE_FILES[@]}"; do
        if [[ "$key" == "$RUN_SUITE"* ]]; then
            run_suite "$key"
            local_found=true
            break
        fi
    done
    if [[ "$local_found" == false ]]; then
        fw_log_error "未找到匹配的测试套件: $RUN_SUITE"
        exit 1
    fi
elif [[ -n "$RUN_CATEGORY" ]]; then
    fw_section "按类别运行测试: $RUN_CATEGORY"

    for key in $(echo "${!SUITE_FILES[@]}" | tr ' ' '\n' | sort); do
        local_cats="${SUITE_CATEGORIES[$key]:-}"
        if [[ " $local_cats " == *" $RUN_CATEGORY "* ]]; then
            run_suite "$key"
        fi
    done
fi

# ============================================================================
# 生成报告
# ============================================================================
if [[ "$GEN_REPORT" == true ]]; then
    fw_generate_report "tests/reports/test_report.md"
fi

# ============================================================================
# 打印摘要
# ============================================================================
fw_print_summary

exit $TEST_FAIL
