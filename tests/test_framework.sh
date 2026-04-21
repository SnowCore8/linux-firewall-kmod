#!/bin/bash
# test_framework.sh - 测试框架核心
# 提供断言函数、彩色输出、统计汇总、测试报告生成

# ============================================================================
# 彩色输出
# ============================================================================
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; MAGENTA='\033[0;35m'; CYAN='\033[0;36m'
    BOLD='\033[1m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; BOLD=''; NC=''
fi

# ============================================================================
# 测试统计
# ============================================================================
TEST_PASS=0
TEST_FAIL=0
TEST_WARN=0
TEST_SKIP=0
TEST_TOTAL=0
CURRENT_SUITE=""

# 测试结果数组（用于报告生成）
declare -a TEST_RESULTS=()

# ============================================================================
# 日志函数
# ============================================================================
fw_log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
fw_log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
fw_log_error()   { echo -e "${RED}[ERROR]${NC} $*"; }
fw_log_debug()   { [[ "${TEST_DEBUG:-0}" == "1" ]] && echo -e "${MAGENTA}[DEBUG]${NC} $*" || true; }

fw_section() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}$*${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
}

fw_subsection() {
    echo ""
    echo -e "${BLUE}--- $* ---${NC}"
}

fw_test_header() {
    CURRENT_SUITE="$*"
    fw_section "$*"
}

# ============================================================================
# 断言函数
# ============================================================================

# 基础断言：条件为真
assert_true() {
    local condition="$1"
    local msg="${2:-断言失败}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if eval "$condition" >/dev/null 2>&1; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 基础断言：条件为假
assert_false() {
    local condition="$1"
    local msg="${2:-断言失败}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if ! eval "$condition" >/dev/null 2>&1; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 断言：命令执行成功（退出码 0）
assert_success() {
    local cmd="$1"
    local msg="${2:-命令执行失败}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    local output
    output=$(eval "$cmd" 2>&1)
    local rc=$?

    if [[ $rc -eq 0 ]]; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg (退出码: $rc)"
        fw_log_debug "输出: $output"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg (退出码: $rc)")
        return 1
    fi
}

# 断言：命令执行失败（退出码非 0）
assert_failure() {
    local cmd="$1"
    local msg="${2:-命令应失败但成功了}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    local output
    output=$(eval "$cmd" 2>&1)
    local rc=$?

    if [[ $rc -ne 0 ]]; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        fw_log_debug "输出: $output"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 断言：文件存在
assert_file_exists() {
    local file="$1"
    local msg="${2:-文件不存在: $file}"
    assert_true "[[ -f '$file' ]]" "$msg"
}

# 断言：目录存在
assert_dir_exists() {
    local dir="$1"
    local msg="${2:-目录不存在: $dir}"
    assert_true "[[ -d '$dir' ]]" "$msg"
}

# 断言：文件包含内容
assert_file_contains() {
    local file="$1"
    local pattern="$2"
    local msg="${3:-文件 $file 不包含 '$pattern'}"
    assert_true "grep -q '$pattern' '$file' 2>/dev/null" "$msg"
}

# 断言：字符串相等
assert_eq() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-期望 '$expected' 但得到 '$actual'}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if [[ "$actual" == "$expected" ]]; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 断言：数值大于等于
assert_ge() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-期望 >= $expected 但得到 $actual}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if [[ "$actual" -ge "$expected" ]] 2>/dev/null; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 断言：数值小于等于
assert_le() {
    local actual="$1"
    local expected="$2"
    local msg="${3:-期望 <= $expected 但得到 $actual}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if [[ "$actual" -le "$expected" ]] 2>/dev/null; then
        TEST_PASS=$((TEST_PASS + 1))
        echo -e "  ${GREEN}[PASS]${NC} $msg"
        TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
        return 0
    else
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
        return 1
    fi
}

# 警告（不计入失败）
warn_test() {
    local msg="$1"
    TEST_WARN=$((TEST_WARN + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${YELLOW}[WARN]${NC} $msg"
    TEST_RESULTS+=("WARN|$CURRENT_SUITE|$msg")
}

# 跳过测试
skip_test() {
    local msg="$1"
    TEST_SKIP=$((TEST_SKIP + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${CYAN}[SKIP]${NC} $msg"
    TEST_RESULTS+=("SKIP|$CURRENT_SUITE|$msg")
}

# ============================================================================
# 模块管理
# ============================================================================
fw_ensure_module_loaded() {
    local module_path="$1"
    local params="${2:-}"

    # 先卸载
    rmmod firewall 2>/dev/null || true
    sleep 0.3

    # 加载
    if [[ -n "$params" ]]; then
        insmod "$module_path" $params 2>/dev/null
    else
        insmod "$module_path" 2>/dev/null
    fi
    sleep 0.5
}

fw_ensure_module_unloaded() {
    rmmod firewall 2>/dev/null || true
    sleep 0.3
}

# ============================================================================
# 测试报告生成
# ============================================================================
fw_generate_report() {
    local report_file="${1:-tests/reports/test_report.md}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    mkdir -p "$(dirname "$report_file")"

    cat > "$report_file" << EOF
# Firewall 测试报告

**生成时间**: $timestamp
**总计**: $TEST_TOTAL | **通过**: $TEST_PASS | **失败**: $TEST_FAIL | **警告**: $TEST_WARN | **跳过**: $TEST_SKIP

## 测试结果

| 状态 | 数量 |
|------|------|
| ${GREEN}通过${NC} | $TEST_PASS |
| ${RED}失败${NC} | $TEST_FAIL |
| ${YELLOW}警告${NC} | $TEST_WARN |
| ${CYAN}跳过${NC} | $TEST_SKIP |
| **总计** | **$TEST_TOTAL** |

## 详细结果

EOF

    for result in "${TEST_RESULTS[@]}"; do
        IFS='|' read -r status suite msg <<< "$result"
        local icon
        case "$status" in
            PASS) icon="✅" ;;
            FAIL) icon="❌" ;;
            WARN) icon="⚠️" ;;
            SKIP) icon="⏭️" ;;
        esac
        echo "- $icon **[$suite]** $msg" >> "$report_file"
    done

    echo "" >> "$report_file"

    if [[ $TEST_FAIL -eq 0 ]]; then
        echo -e "${GREEN}## ✓ 所有测试通过!${NC}" >> "$report_file"
    else
        echo -e "${RED}## ✗ 存在 $TEST_FAIL 个失败项${NC}" >> "$report_file"
    fi

    echo ""
    fw_log_info "测试报告已生成: $report_file"
}

# ============================================================================
# 测试摘要
# ============================================================================
fw_print_summary() {
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}${BOLD}                      测试总结${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "  总计: $TEST_TOTAL"
    echo -e "  ${GREEN}通过: $TEST_PASS${NC}"
    echo -e "  ${RED}失败: $TEST_FAIL${NC}"
    echo -e "  ${YELLOW}警告: $TEST_WARN${NC}"
    echo -e "  ${CYAN}跳过: $TEST_SKIP${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

    if [[ $TEST_FAIL -eq 0 ]]; then
        echo -e "${GREEN}${BOLD}✓ 所有测试通过!${NC}"
    else
        echo -e "${RED}${BOLD}✗ 存在 $TEST_FAIL 个失败项，需要修复${NC}"
    fi
    echo ""
}

# ============================================================================
# 清理函数（测试结束后调用）
# ============================================================================
fw_cleanup() {
    rmmod firewall 2>/dev/null || true

    # 清理临时文件
    rm -f /tmp/fw_test_*.log /tmp/fw_test_*.tmp /tmp/fw_test_*.yaml

    # 严格检查：确保测试后没有遗留安装文件
    if [[ -f "/lib/modules/$(uname -r)/kernel/net/firewall.ko" ]]; then
        fw_log_error "测试结束后发现模块被安装到系统，立即清理"
        rm -f "/lib/modules/$(uname -r)/kernel/net/firewall.ko"
        depmod -a 2>/dev/null
    fi
    if [[ -f "/usr/local/bin/firewall-daemon" ]]; then
        fw_log_error "测试结束后发现守护进程被安装到系统，立即清理"
        rm -f "/usr/local/bin/firewall-daemon"
    fi
}
