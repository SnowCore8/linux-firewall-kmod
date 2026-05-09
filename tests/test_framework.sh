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

# 安全验证：检查条件字符串是否包含危险的命令注入模式
# 返回 0 表示安全，1 表示不安全
assert_condition_safe() {
    local cond="$1"
    # 如果条件以 [[ 开头，允许其中的 && 和 ||（它们是 [[ ]] 内的合法操作符）
    if [[ "$cond" == "[["* ]]; then
        # [[ ]] 内部：只拒绝分号（命令分隔符）和命令替换
        if [[ "$cond" =~ \; ]] || [[ "$cond" =~ \$\( ]] || [[ "$cond" =~ \` ]]; then
            fw_log_error "拒绝不安全的断言条件（包含命令注入模式）: $cond"
            return 1
        fi
    else
        # 非 [[ ]] 表达式：拒绝所有命令链式操作符和命令替换
        if [[ "$cond" =~ \; ]] || [[ "$cond" =~ \&\& ]] || [[ "$cond" =~ \|\| ]] || [[ "$cond" =~ \$\( ]] || [[ "$cond" =~ \` ]]; then
            fw_log_error "拒绝不安全的断言条件（包含命令注入模式）: $cond"
            return 1
        fi
    fi
    return 0
}

# 基础断言：条件为真
assert_true() {
    local condition="$1"
    local msg="${2:-断言失败}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if ! assert_condition_safe "$condition"; then
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg (不安全条件被拒绝)"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg (不安全条件被拒绝)")
        return 1
    fi

    # 修复：使用 [[ ]] 替代 eval 执行断言条件
    if [[ "$condition" == "[["* ]]; then
        # [[ ]] 表达式：直接执行
        if bash -c "$condition" 2>/dev/null; then
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
    else
        # 简单命令：使用 bash -c 替代 eval
        if bash -c "$condition" 2>/dev/null; then
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
    fi
}

# 基础断言：条件为假
assert_false() {
    local condition="$1"
    local msg="${2:-断言失败}"
    TEST_TOTAL=$((TEST_TOTAL + 1))

    if ! assert_condition_safe "$condition"; then
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg (不安全条件被拒绝)"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg (不安全条件被拒绝)")
        return 1
    fi

    # 修复：使用 [[ ]] 替代 eval 执行断言条件
    if [[ "$condition" == "[["* ]]; then
        if ! bash -c "$condition" 2>/dev/null; then
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
    else
        if ! bash -c "$condition" 2>/dev/null; then
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
    assert_true "grep -q \"$pattern\" \"$file\" 2>/dev/null" "$msg"
}

# 断言：字符串包含内容
assert_contains() {
    local string="$1"
    local pattern="$2"
    local msg="${3:-字符串不包含 '$pattern'}"
    assert_true "[[ \"\$string\" == *\"\$pattern\"* ]]" "$msg"
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

    # 先验证参数是否为有效整数
    if ! [[ "$actual" =~ ^-?[0-9]+$ ]] || ! [[ "$expected" =~ ^-?[0-9]+$ ]]; then
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg (错误: 参数不是有效整数)"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg (错误: 参数不是有效整数)")
        return 1
    fi

    if [[ "$actual" -ge "$expected" ]]; then
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

    # 先验证参数是否为有效整数
    if ! [[ "$actual" =~ ^-?[0-9]+$ ]] || ! [[ "$expected" =~ ^-?[0-9]+$ ]]; then
        TEST_FAIL=$((TEST_FAIL + 1))
        echo -e "  ${RED}[FAIL]${NC} $msg (错误: 参数不是有效整数)"
        TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg (错误: 参数不是有效整数)")
        return 1
    fi

    if [[ "$actual" -le "$expected" ]]; then
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
# Procfs 辅助函数
# ============================================================================

# 等待 procfs 处理完成
fw_wait_procfs() { sleep "${PROCFS_SYNC_DELAY:-0.2}"; }

# 获取 procfs 统计值
fw_get_stat() { grep "$1" "$PROC_STATS" 2>/dev/null | awk '{print $2}'; }

# 封禁列表行数
fw_count_bans() { wc -l < "$PROC_BANS" 2>/dev/null || echo 0; }

# 白名单行数
fw_count_whitelist() { wc -l < "$PROC_WHITELIST" 2>/dev/null || echo 0; }

# ============================================================================
# 封禁/解封辅助函数
# ============================================================================

# 封禁 IP（同步等待）
fw_ban() { echo "$1" > "$PROC_BANS" 2>/dev/null; fw_wait_procfs; }

# 封禁 IP 带时长（同步等待）
fw_ban_with_time() { echo "$1 $2" > "$PROC_BANS" 2>/dev/null; fw_wait_procfs; }

# 永久封禁 IP（同步等待）
fw_ban_permanent() { echo "$1 0" > "$PROC_BANS" 2>/dev/null; fw_wait_procfs; }

# 解封 IP（同步等待）
fw_unban() { echo "unban $1" > "$PROC_BANS" 2>/dev/null; fw_wait_procfs; }

# 批量封禁 IP
fw_ban_multiple() {
    for ip in "$@"; do
        echo "$ip" > "$PROC_BANS" 2>/dev/null || true
    done
    fw_wait_procfs
}

# 批量解封 IP
fw_unban_multiple() {
    for ip in "$@"; do
        echo "unban $ip" > "$PROC_BANS" 2>/dev/null || true
    done
    fw_wait_procfs
}

# 断言：IP 未被封禁（不在封禁列表中）
fw_assert_ip_not_banned() {
    local ip="$1" desc="${2:-IP $1 未进入封禁列表}"
    assert_true "! grep -q '$ip' '$PROC_BANS' 2>/dev/null" "$desc"
}

# 断言：procfs 列表计数未变化
fw_assert_list_unchanged() {
    local list_path="$1" before="$2" desc="${3:-列表未变化}"
    local after
    after=$(wc -l < "$list_path" 2>/dev/null || echo 0)
    assert_eq "$before" "$after" "$desc"
}

# 添加白名单（同步等待）
fw_whitelist_add() { echo "add $1" > "$PROC_WHITELIST" 2>/dev/null; fw_wait_procfs; }

# 移除白名单（同步等待）
fw_whitelist_remove() { echo "remove $1" > "$PROC_WHITELIST" 2>/dev/null; fw_wait_procfs; }

# ============================================================================
# 数据重置函数（测试套件之间隔离）
# ============================================================================

# 重置所有测试数据，确保每个测试套件从干净状态开始
fw_reset_all_data() {
    fw_log_debug "开始重置所有测试数据"

    # 1. 清空封禁列表：读取当前封禁，逐个解封
    if [[ -r "$PROC_BANS" ]]; then
        local banned_ips
        banned_ips=$(grep -oP '^\d+\.\d+\.\d+\.\d+' "$PROC_BANS" 2>/dev/null || true)
        if [[ -n "$banned_ips" ]]; then
            local count=0
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                echo "unban $ip" > "$PROC_BANS" 2>/dev/null || true
                count=$((count + 1))
            done <<< "$banned_ips"
            fw_log_debug "已解封 $count 个 IP"
            fw_wait_procfs
        fi
    fi

    # 2. 清空手动添加的白名单（保留系统自动发现的条目）
    if [[ -r "$PROC_WHITELIST" ]]; then
        # 提取 device_name 为 manual 或 restored 的条目
        local manual_entries
        manual_entries=$(grep -E ' on (manual|restored)$' "$PROC_WHITELIST" 2>/dev/null | grep -oP '^[^\s/]+' || true)
        if [[ -n "$manual_entries" ]]; then
            local count=0
            while IFS= read -r subnet; do
                [[ -z "$subnet" ]] && continue
                echo "remove $subnet" > "$PROC_WHITELIST" 2>/dev/null || true
                count=$((count + 1))
            done <<< "$manual_entries"
            fw_log_debug "已移除 $count 个手动白名单条目"
            fw_wait_procfs
        fi
    fi

    # 3. 清理测试创建的临时文件
    rm -f /tmp/fw_test_*.log 2>/dev/null || true
    rm -f /tmp/fw_test_*.yaml 2>/dev/null || true
    rm -f /tmp/fw_test_*.conf 2>/dev/null || true
    rm -f /tmp/fw_test_*.tmp 2>/dev/null || true

    # 4. 清理测试用 SQLite 数据库
    rm -f /tmp/fw_test_*.db 2>/dev/null || true
    rm -f /tmp/test_bans.db 2>/dev/null || true

    fw_log_debug "测试数据重置完成"
}

# ============================================================================
# 基准测试辅助函数
# ============================================================================

# 基准测试：测量命令执行时间并断言不超过阈值
# 用法: fw_benchmark "描述" 阈值_ms "命令"
fw_benchmark() {
    local desc="$1" threshold="$2" cmd="$3"
    local start end dur
    start=$(date +%s%N)
    eval "$cmd" 2>/dev/null
    end=$(date +%s%N)
    dur=$(( (end - start) / 1000000 ))
    assert_le "$dur" "$threshold" "$desc (${dur}ms)"
}

# ============================================================================
# 守护进程辅助函数
# ============================================================================

# 运行守护进程，接受 0/124/137 为正常退出码
# 用法: fw_daemon_starts_ok "完整命令字符串" "描述"
fw_daemon_starts_ok() {
    local cmd="$1" desc="$2"
    local rc=0
    eval "timeout --signal=KILL 2 $cmd" >/dev/null 2>&1 || rc=$?
    if [[ $rc -eq 0 || $rc -eq 124 || $rc -eq 137 ]]; then
        fw_pass "$desc (退出码=$rc)"
    else
        fw_fail "$desc (退出码=$rc, 预期 0/124/137)"
    fi
}

# 运行守护进程并捕获 stderr
# 用法: fw_run_daemon_captured 配置文件 [超时秒数]
fw_run_daemon_captured() {
    local config="$1" timeout_sec="${2:-5}"
    local stderr_file="/tmp/fw_daemon_stderr_$$.log"
    timeout --signal=KILL "$timeout_sec" "$DAEMON_PATH" -c "$config" 2>"$stderr_file" || true
    if [[ -s "$stderr_file" ]]; then
        fw_log_warn "守护进程 stderr: $(cat "$stderr_file")"
    fi
    rm -f "$stderr_file"
}

# ============================================================================
# 配置生成辅助函数
# ============================================================================

# 生成测试用 YAML 配置
# 用法: fw_generate_test_yaml 文件 日志文件 [max_retries] [findtime] [ban_time] [metrics_port] [jail_name]
fw_generate_test_yaml() {
    local file="$1" log_file="$2"
    local max_retries="${3:-1}" findtime="${4:-1}" ban_time="${5:-5}"
    local metrics_port="${6:-9119}" jail_name="${7:-sshd}"
    cat > "$file" << EOF
defaults:
  max_retries: $max_retries
  findtime: $findtime
  ban_time: $ban_time
  interval: 1
  metrics_port: $metrics_port

jails:
  $jail_name:
    enabled: true
    log_files:
      - $log_file
    max_retries: $max_retries
    findtime: $findtime
    ban_time: $ban_time
    regex: ""
EOF
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
    local insmod_output
    if [[ -n "$params" ]]; then
        insmod_output=$(insmod "$module_path" $params 2>&1)
        local insmod_rc=$?
        if [[ $insmod_rc -ne 0 ]]; then
            fw_log_error "模块加载失败: $module_path $params (退出码: $insmod_rc, 输出: $insmod_output)"
            return 1
        fi
    else
        insmod_output=$(insmod "$module_path" 2>&1)
        local insmod_rc=$?
        if [[ $insmod_rc -ne 0 ]]; then
            fw_log_error "模块加载失败: $module_path (退出码: $insmod_rc, 输出: $insmod_output)"
            return 1
        fi
    fi
    fw_log_debug "insmod 成功: $module_path"

    # 验证模块是否真的加载成功
    local retries=10
    while [[ $retries -gt 0 ]]; do
        local lsmod_output
        lsmod_output=$(lsmod 2>&1)
        fw_log_debug "lsmod 输出 (retries=$retries): $(echo "$lsmod_output" | grep firewall || echo 'no firewall found')"
        if echo "$lsmod_output" | grep -q "^firewall"; then
            fw_log_debug "模块验证成功"
            return 0
        fi
        sleep 0.2
        retries=$((retries - 1))
    done

    fw_log_error "模块加载后验证失败: 模块未出现在 lsmod 中"
    return 1
}

fw_ensure_module_unloaded() {
    if lsmod | grep -q "^firewall"; then
        if ! rmmod firewall 2>/dev/null; then
            fw_log_warn "模块卸载失败，可能被其他进程引用"
            return 1
        fi
    fi
    sleep 0.3
    
    # 验证卸载
    if lsmod | grep -q "^firewall"; then
        fw_log_error "模块卸载验证失败: 模块仍在运行"
        return 1
    fi
    return 0
}

# ============================================================================
# 测试报告生成
# ============================================================================
fw_generate_report() {
    local report_file="${1:-reports/test_report.md}"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    mkdir -p "$(dirname "$report_file")"
    
    # 临时保存并清空颜色变量，避免 Markdown 中出现 ANSI 代码
    local _red="$RED" _green="$GREEN" _yellow="$YELLOW" _blue="$BLUE" _cyan="$CYAN" _nc="$NC" _bold="$BOLD"
    RED="" GREEN="" YELLOW="" BLUE="" CYAN="" NC="" BOLD=""

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

    # 报告生成完成后恢复颜色变量
    RED="$_red" GREEN="$_green" YELLOW="$_yellow" BLUE="$_blue" CYAN="$_cyan" NC="$_nc" BOLD="$_bold"
    
    echo ""
    fw_log_info "测试报告已生成: $report_file"
}

# ============================================================================
# 测试摘要
# ============================================================================
fw_print_summary() {
    # 一致性校验：确保 PASS+FAIL+WARN+SKIP == TOTAL
    local sum=$((TEST_PASS + TEST_FAIL + TEST_WARN + TEST_SKIP))
    if [[ $sum -ne $TEST_TOTAL ]]; then
        echo -e "${RED}[错误] 统计不一致: PASS+FAIL+WARN+SKIP=$sum != TOTAL=$TEST_TOTAL${NC}"
    fi

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

    if [[ $TEST_FAIL -gt 0 ]]; then
        echo -e "${RED}${BOLD}✗ 存在 $TEST_FAIL 个失败项，需要修复${NC}"
    elif [[ $TEST_SKIP -gt 0 ]]; then
        echo -e "${YELLOW}⚠ 存在 $TEST_SKIP 个跳过项${NC}"
        if [[ $TEST_WARN -gt 0 ]]; then
            echo -e "${YELLOW}⚠ 存在 $TEST_WARN 个警告项${NC}"
        fi
        echo -e "${GREEN}✓ 已执行的测试全部通过${NC}"
    else
        echo -e "${GREEN}${BOLD}✓ 所有测试通过!${NC}"
    fi
    echo ""
}

# ============================================================================
# 清理函数（测试结束后调用）
# ============================================================================

# 清理模块状态文件（防止模块卸载时保存的残余条目影响测试）
fw_cleanup_state() {
    rm -f /var/lib/firewall/state 2>/dev/null
}

# 测试小节清理（在 subsection 结束时调用）
fw_cleanup_section() {
    local msg="${1:-小节清理完成}"
    fw_log_debug "$msg"
}

# 跳过测试（兼容函数）
fw_skip() {
    local msg="${1:-跳过}"
    TEST_SKIP=$((TEST_SKIP + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${CYAN}[SKIP]${NC} $msg"
    TEST_RESULTS+=("SKIP|$CURRENT_SUITE|$msg")
}

# 显式标记测试通过
fw_pass() {
    local msg="${1:-测试通过}"
    TEST_PASS=$((TEST_PASS + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${GREEN}[PASS]${NC} $msg"
    TEST_RESULTS+=("PASS|$CURRENT_SUITE|$msg")
}

# 显式标记测试失败
fw_fail() {
    local msg="${1:-测试失败}"
    TEST_FAIL=$((TEST_FAIL + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${RED}[FAIL]${NC} $msg"
    TEST_RESULTS+=("FAIL|$CURRENT_SUITE|$msg")
}

# 显式标记测试警告
fw_warn() {
    local msg="${1:-测试警告}"
    TEST_WARN=$((TEST_WARN + 1))
    TEST_TOTAL=$((TEST_TOTAL + 1))
    echo -e "  ${YELLOW}[WARN]${NC} $msg"
    TEST_RESULTS+=("WARN|$CURRENT_SUITE|$msg")
}

fw_cleanup() {
    # 先重置数据（需要在模块卸载前执行，否则 procfs 操作会失败）
    fw_reset_all_data

    # 卸载内核模块（测试模式）
    if lsmod | grep -q "^firewall"; then
        rmmod firewall 2>/dev/null || true
    fi
    
    # 只清理测试创建的临时文件
    rm -f /tmp/fw_test_*.log 2>/dev/null
    rm -f /tmp/fw_test_*.yaml 2>/dev/null
    rm -f /tmp/fw_test_*.conf 2>/dev/null
    rm -f /tmp/fw_test_*.tmp 2>/dev/null
    
    # 清理编译临时文件
    rm -f /tmp/fw_compile_*.log 2>/dev/null
    rm -f /tmp/fw_test_mod_*.ko 2>/dev/null
    
    # 清理测试包装器脚本
    rm -f /tmp/fw_test_wrapper_*.sh 2>/dev/null
    rm -f /tmp/fw_suite_stderr_*.log 2>/dev/null
    
    # 注意：不再删除 /lib/modules/*/kernel/net/firewall.ko 和 /usr/local/sbin/firewall-daemon
    # 这些系统文件只能由包管理器或安装脚本管理
}

# ============================================================================
# 错误处理和恢复
# ============================================================================

# 测试套件错误处理包装器
fw_run_suite_with_error_handling() {
    local suite_name="$1"
    local suite_func="$2"
    
    fw_log_debug "开始执行测试套件: $suite_name"
    
    # 执行测试套件
    if $suite_func; then
        fw_log_debug "测试套件 $suite_name 成功完成"
        return 0
    else
        fw_log_warn "测试套件 $suite_name 执行失败"
        return 1
    fi
}

# 确保清理函数在错误时也被调用
fw_safe_cleanup() {
    local exit_code=$?
    fw_cleanup
    exit $exit_code
}
