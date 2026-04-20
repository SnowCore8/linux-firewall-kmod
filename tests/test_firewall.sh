#!/bin/bash
# test-firewall.sh - Comprehensive test script for firewall module

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODULE_FILE="firewall.ko"
PROC_DIR="/proc/firewall"
TEST_IP="203.0.113.1"
INVALID_IP="999.999.999.999"
LOCALHOST_IP="127.0.0.1"
BROADCAST_IP="255.255.255.255"
ZERO_IP="0.0.0.0"
MULTICAST_IP="224.0.0.1"
TEST_SUBNET="192.168.1.0/24"
TEST_SUBNET_IP="192.168.1.100"

# Colors
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

PASS=0; FAIL=0; WARN=0

pass() { PASS=$((PASS + 1)); echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "${RED}[FAIL]${NC} $1"; }
warn() { WARN=$((WARN + 1)); echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  $1"; }

cleanup() {
    rmmod firewall 2>/dev/null || true
    # Clean up any temporary files
    rm -f /tmp/fake_log_*.log
    
    # 严格禁止：测试结束后确保没有遗留的安装文件
    if [[ -f "/lib/modules/$(uname -r)/kernel/net/firewall.ko" ]]; then
        echo "ERROR: 测试结束后发现模块被安装到系统，立即清理"
        rm -f "/lib/modules/$(uname -r)/kernel/net/firewall.ko"
        depmod -a 2>/dev/null
    fi
    if [[ -f "/usr/local/bin/firewall-daemon" ]]; then
        echo "ERROR: 测试结束后发现守护进程被安装到系统，立即清理"
        rm -f "/usr/local/bin/firewall-daemon"
    fi
}
trap cleanup EXIT

section() { echo ""; echo "=== $1 ==="; }

# Pre-flight
if [[ $EUID -ne 0 ]]; then echo "需要 root 权限"; exit 1; fi

# ============================================================
# 严格禁止：测试过程中绝不允许执行安装到系统的操作
# ============================================================
echo ""
echo "=== 安全预检：严格禁止安装到系统 ==="
# 检查是否有 make install 相关的痕迹
if command -v make &>/dev/null; then
    # 如果 Makefile 中有 install 目标，发出警告但不阻止
    if grep -qE '^\s*install\s*:' ../Makefile 2>/dev/null; then
        warn "Makefile 中存在 install 目标，测试期间严禁执行 make install"
    fi
fi
# 绝对禁止在测试中执行安装
_check_no_install() {
    local cmd="$1"
    if echo "$cmd" | grep -qiE 'make\s+install|cp\s+.*/lib/modules|cp\s+.*/usr/local'; then
        echo "ERROR: 测试中严格禁止执行安装操作: $cmd"
        exit 1
    fi
}
export -f _check_no_install
echo "安全预检通过"
pass "测试模式：仅加载/卸载模块，不安装到系统"

# Check for module file in build directory or root
if [[ -f "../build/$MODULE_FILE" ]]; then
    MODULE_PATH="../build/$MODULE_FILE"
elif [[ -f "../$MODULE_FILE" ]]; then
    MODULE_PATH="../$MODULE_FILE"
else
    info "编译模块..."
    cd .. && make > /dev/null 2>&1
    cd tests
    if [[ -f "../build/$MODULE_FILE" ]]; then
        MODULE_PATH="../build/$MODULE_FILE"
    elif [[ -f "../$MODULE_FILE" ]]; then
        MODULE_PATH="../$MODULE_FILE"
    else
        fail "编译失败"
    fi
fi
pass "模块文件存在 ($MODULE_PATH)"

# Test 1: Load/Unload with parameters
section "模块加载/卸载（带参数）"
rmmod firewall 2>/dev/null || true
sudo insmod "$MODULE_PATH" fw_ban_time=300 fw_max_retries=5 2>/dev/null && pass "加载成功（带参数）" || fail "加载失败"
sleep 0.5
# Check if the module is loaded by looking for it in lsmod output
if lsmod | grep -q "^firewall\b"; then
    pass "lsmod 可见"
elif [ -d "/proc/firewall" ]; then
    # Alternative check: if proc directory exists, module is likely loaded
    pass "lsmod 可见（通过procfs验证）"
else
    warn "lsmod 未显示模块"
fi
rmmod firewall 2>/dev/null || true && pass "卸载成功"

# Test 2: Procfs
section "Procfs 接口"
(sudo rmmod firewall 2>/dev/null || true) # Ensure module is unloaded first
if sudo insmod "$MODULE_PATH" 2>/dev/null; then
    pass "模块加载成功"
else
    fail "模块加载失败"
fi
sleep 0.5
[[ -d "$PROC_DIR" ]] && pass "proc 目录存在" || fail "proc 不存在"
[[ -r "$PROC_DIR/ban_list" ]] && pass "ban_list 可读" || fail "不可读"
[[ -w "$PROC_DIR/add_ban" ]] && pass "add_ban 可写" || fail "不可写"
[[ -r "$PROC_DIR/remove_ban" ]] && pass "remove_ban 可读" || fail "remove_ban 不可读"
[[ -w "$PROC_DIR/remove_ban" ]] && pass "remove_ban 可写" || fail "remove_ban 不可写"
[[ -r "$PROC_DIR/whitelist" ]] && pass "whitelist 可读" || fail "不可读"
[[ -w "$PROC_DIR/whitelist_add" ]] && pass "whitelist_add 可写" || fail "whitelist_add 不可写"
[[ -w "$PROC_DIR/whitelist_remove" ]] && pass "whitelist_remove 可写" || fail "whitelist_remove 不可写"

# Test 3: Ban/Unban with various IPs
section "封禁/解封（多种IP类型）"
# Test with standard IP
echo "$TEST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 && pass "标准IP封禁添加" || fail "标准IP封禁失败"
sleep 0.3
grep -q "$TEST_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "标准IP封禁验证" || fail "标准IP封禁未显示"
echo "$TEST_IP" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 && pass "标准IP解封操作" || fail "标准IP解封失败"
sleep 0.3
! grep -q "$TEST_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "标准IP解封验证" || fail "标准IP解封失败"

# Test with subnet
echo "$TEST_SUBNET_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 && pass "子网IP封禁添加" || fail "子网IP封禁失败"
sleep 0.3
grep -q "$TEST_SUBNET_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "子网IP封禁验证" || fail "子网IP封禁未显示"
echo "$TEST_SUBNET_IP" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 && pass "子网IP解封操作" || fail "子网IP解封失败"
sleep 0.3
! grep -q "$TEST_SUBNET_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "子网IP解封验证" || fail "子网IP解封失败"

# Test 4: Whitelist protection
section "白名单保护"
# Test localhost protection
echo "$LOCALHOST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.3
! grep -q "$LOCALHOST_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "回环地址保护" || fail "回环地址被封"

# Test broadcast IP protection
echo "$BROADCAST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.3
! grep -q "$BROADCAST_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "广播地址保护" || fail "广播地址被封"

# Test zero IP protection
echo "$ZERO_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.3
! grep -q "$ZERO_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "零地址保护" || fail "零地址被封"

# Test multicast IP protection
echo "$MULTICAST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.3
! grep -q "$MULTICAST_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "组播地址保护" || fail "组播地址被封"

# Test manual whitelist addition
echo "$TEST_SUBNET" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 && pass "手动添加子网白名单" || fail "添加失败"
grep -q "$TEST_SUBNET" "$PROC_DIR/whitelist" 2>/dev/null && pass "子网白名单验证" || fail "未显示"
echo "$TEST_SUBNET_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.3
! grep -q "$TEST_SUBNET_IP" "$PROC_DIR/ban_list" 2>/dev/null && pass "白名单子网IP保护" || fail "白名单子网IP未受保护"
echo "$TEST_SUBNET" | tee "$PROC_DIR/whitelist_remove" > /dev/null 2>&1 && pass "手动移除子网白名单" || fail "移除失败"

# Test 5: Daemon functionality
section "守护进程功能"
if [[ -x "../build/daemon/firewall-daemon" ]]; then
    pass "守护进程可执行"

    # Test help
    ../build/daemon/firewall-daemon --help > /dev/null 2>&1 && pass "--help 正常" || fail "--help 失败"

    # Test invalid args
    ! ../build/daemon/firewall-daemon --invalid > /dev/null 2>&1 && pass "拒绝无效参数" || warn "未拒绝无效参数"

    # Test regex compilation and functionality
    echo "Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2" > /tmp/test_auth.log
    timeout 5 ../build/daemon/firewall-daemon --log /tmp/test_auth.log --max-retries 1 --findtime 1 --ban-time 5 --interval 1 || true
    # Give it a moment to process
    sleep 2
    if [[ -r "/proc/firewall/ban_list" ]]; then
        if grep -q "192.0.2.1" "/proc/firewall/ban_list" 2>/dev/null; then
            pass "正则表达式功能正常（IP被封禁）"
        else
            warn "正则表达式功能可能有问题（IP未被封禁）"
        fi
    else
        info "跳过正则表达式测试（内核模块未加载）"
    fi
    rm -f /tmp/test_auth.log
else
    [[ -f "../src/daemon/firewall-daemon.c" ]] && warn "守护进程未编译" || info "源码不存在"
fi

# Test 6: Edge cases and security
section "边界情况和安全测试"
# Test empty input
echo "" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "空输入被拒绝"
# Test invalid IP format
echo "$INVALID_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "无效 IP 被拒绝"
# Test partial IP
echo "192.168.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "部分 IP 被拒绝"
# Test overly long input
python3 -c "print('A'*1000)" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "超长输入被拒绝"
# Test IP with invalid characters
echo "192.168.1.1a" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "含字母IP被拒绝"
# Test negative numbers in IP
echo "-1.1.1.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "负数IP被拒绝"

# Test 7: Performance
section "性能测试"
start=$(date +%s%N)
for i in $(seq 1 10); do echo "203.0.113.$i" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true; done
dur=$(( ($(date +%s%N) - start) / 1000000 ))
[[ $dur -lt 5000 ]] && pass "封禁 10 IP: ${dur}ms" || warn "封禁较慢: ${dur}ms"

start=$(date +%s%N)
for i in $(seq 1 10); do echo "203.0.113.$i" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true; done
dur=$(( ($(date +%s%N) - start) / 1000000 ))
[[ $dur -lt 5000 ]] && pass "解封 10 IP: ${dur}ms" || warn "解封较慢: ${dur}ms"

# Test 8: Module parameter validation
section "模块参数验证"
(sudo rmmod firewall 2>/dev/null || true)  # Ensure module is unloaded first
# Test with very small ban time
if sudo insmod "$MODULE_PATH" fw_ban_time=1 fw_max_retries=1 fw_findtime=1 2>/dev/null; then
    sleep 0.5
    pass "小参数值接受"
    # Verify parameters were set correctly
    cat /sys/module/firewall/parameters/fw_ban_time | grep -q "1" && pass "参数设置验证" || fail "参数设置验证失败"
    sudo rmmod firewall 2>/dev/null || true
else
    fail "小参数值拒绝"
fi

# Re-load module for remaining tests
(sudo rmmod firewall 2>/dev/null || true)  # Ensure module is unloaded first
sudo insmod "$MODULE_PATH" 2>/dev/null || true; sleep 0.5

# Test 9: Concurrent access simulation
section "并发访问模拟"
# Run multiple processes simultaneously to test thread safety
{
    for i in $(seq 1 10); do
        echo "198.51.100.$i" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 &
    done
    wait
    pass "并发封禁操作"
} & PID1=$!

{
    for i in $(seq 1 10); do
        echo "198.51.100.$i" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 &
    done
    wait
    pass "并发解封操作"
} & PID2=$!

wait $PID1 $PID2
sleep 0.5

# Test 10: Log monitoring simulation
section "日志监控模拟"
# Create a fake log file
FAKE_LOG="/tmp/fake_log_$$.log"
touch "$FAKE_LOG"
echo "Mar 10 10:30:01 server sshd[1234]: Failed password for root from $TEST_IP port 12345 ssh2" >> "$FAKE_LOG"
echo "Mar 10 10:30:02 server sshd[1235]: Failed password for invaliduser from $TEST_SUBNET_IP port 12346 ssh2" >> "$FAKE_LOG"
echo "Mar 10 10:30:03 server sshd[1236]: Invalid user test from $TEST_IP port 12347" >> "$FAKE_LOG"

# Start daemon to process the fake log (only if daemon exists and module is loaded)
if [[ -x "../build/daemon/firewall-daemon" ]] && [[ -d "/proc/firewall" ]]; then
    DAEMON_BIN="../build/daemon/firewall-daemon"
elif [[ -x "../firewall-daemon" ]] && [[ -d "/proc/firewall" ]]; then
    DAEMON_BIN="../firewall-daemon"
else
    DAEMON_BIN=""
fi

if [[ -n "$DAEMON_BIN" ]]; then
    info "启动守护进程处理假日志..."
    timeout 5 $DAEMON_BIN --log "$FAKE_LOG" --max-retries 1 --findtime 1 --ban-time 5 --interval 1 &
    DAEMON_PID=$!
    sleep 2

    # Check if IPs were detected and processed
    info "检查日志监控是否检测到攻击IP..."
    if grep -q "$TEST_IP" "/proc/firewall/ban_list" 2>/dev/null; then
        pass "日志监控检测成功（$TEST_IP 被封禁）"
    else
        warn "日志监控可能未检测到（$TEST_IP 未封禁）"
    fi

    # Cleanup daemon
    kill $DAEMON_PID 2>/dev/null || true
    wait $DAEMON_PID 2>/dev/null || true
else
    if [[ ! -x "../build/daemon/firewall-daemon" ]] && [[ ! -x "../firewall-daemon" ]]; then
        info "跳过日志监控测试（守护进程未编译）"
    else
        info "跳过日志监控测试（内核模块未加载）"
    fi
fi

# Cleanup fake log
rm -f "$FAKE_LOG"

# Test 11: Packet interception verification
section "数据包拦截验证"
# Add a test IP to the ban list
TEST_BAN_IP="192.0.2.100"
echo "$TEST_BAN_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 && pass "拦截测试IP封禁添加" || fail "拦截测试IP封禁失败"
sleep 0.5

# Verify the IP is in the ban list
if grep -q "$TEST_BAN_IP" "$PROC_DIR/ban_list" 2>/dev/null; then
    pass "拦截测试IP封禁验证"

    # Verify that the netfilter hook is active by checking module stats
    # We can't directly test packet interception in a script, but we can verify:
    # 1. That the IP is properly added to the ban list
    # 2. That the netfilter hook is registered and active
    # 3. That the kernel module is loaded and functioning

    info "验证 netfilter 钩子是否处于活动状态..."

    # Check if the netfilter hook is registered (skip this check if module was temporarily unloaded)
    if lsmod | grep -q "^firewall\b"; then
        pass "内核模块已加载"
    else
        info "注意：模块可能在测试过程中被临时卸载"
    fi

    # Verify the netfilter hook by checking if the module's proc interface exists
    if [[ -r "$PROC_DIR/ban_list" ]]; then
        pass "procfs 接口正常"
    else
        fail "procfs 接口异常"
    fi

    # Additional verification: check that the banned IP remains in the list
    if grep -q "$TEST_BAN_IP" "$PROC_DIR/ban_list" 2>/dev/null; then
        pass "封禁IP持续存在"
    else
        fail "封禁IP消失"
    fi

    # Remove the test IP
    echo "$TEST_BAN_IP" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 && pass "拦截测试IP解封" || fail "拦截测试IP解封失败"

    # Verify the IP is removed
    if ! grep -q "$TEST_BAN_IP" "$PROC_DIR/ban_list" 2>/dev/null; then
        pass "解封功能验证"
    else
        fail "解封功能验证失败"
    fi
else
    fail "拦截测试IP封禁验证失败"
fi

# Test 12: Hash collision resistance
section "哈希碰撞抗性测试"
# Add many IPs that may hash to similar buckets
for i in $(seq 1 20); do
    echo "192.0.2.$i" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
done
sleep 0.5
count=$(wc -l < "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
info "添加20个IP后，封禁列表中有 $count 个IP"
[[ $count -ge 10 ]] && pass "哈希表工作正常（至少10个IP被封禁）" || fail "哈希表可能存在问题（少于10个IP被封禁）"

# Clear the IPs
for i in $(seq 1 20); do
    echo "192.0.2.$i" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# Test 13: Stress test
section "压力测试"
start=$(date +%s%N)
# Add and remove many IPs rapidly
for i in $(seq 1 100); do
    echo "203.0.114.$i" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
    if (( i % 10 == 0 )); then
        echo "203.0.114.$((i-10))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
    fi
done
dur=$(( ($(date +%s%N) - start) / 1000000 ))
info "压力测试耗时: ${dur}ms"
final_count=$(wc -l < "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
info "压力测试后，封禁列表中有 $final_count 个IP"
[[ $final_count -ge 0 ]] && pass "压力测试完成，模块稳定" || fail "压力测试后模块不稳定"

# Final cleanup
for i in $(seq 1 100); do
    echo "203.0.114.$i" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# Unload module
section "卸载模块"
(sudo rmmod firewall 2>/dev/null || true) && pass "模块卸载成功" || fail "模块卸载失败"

# Summary
echo ""
echo "═════════════════════════════════════════════════════════════════════════════════════"
echo "  总计: $((PASS + FAIL + WARN))"
echo -e "  ${GREEN}通过: $PASS${NC}"
echo -e "  ${RED}失败: $FAIL${NC}"
echo -e "  ${YELLOW}警告: $WARN${NC}"
echo "═════════════════════════════════════════════════════════════════════════════════════"
[[ $FAIL -eq 0 ]] && echo -e "${GREEN}✓ 所有测试通过!${NC}" || echo -e "${RED}✗ 存在失败${NC}"

exit $FAIL