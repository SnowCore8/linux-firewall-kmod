#!/bin/bash
# 15_path_traversal.sh - 路径遍历防护真实测试套件
# 测试内核模块和守护进程对路径遍历攻击的实际防护能力
# 包括：procfs 接口输入验证、配置解析路径检查、URL 编码绕过检测、符号链接攻击防护

source "$(dirname "$0")/../test_framework.sh"
source "$(dirname "$0")/../test_config.sh"

fw_test_header "路径遍历防护测试"

# ============================================================================
# 测试 1: Procfs bans 接口拒绝包含 ../ 的输入
# 内核模块在 bans_write 中检查 strstr(input, "..") 并返回 -EINVAL
# ============================================================================
fw_subsection "Procfs bans 接口拒绝路径遍历输入"

# 测试 1.1: 正常 IP 应该被成功封禁（基线测试）
echo '203.0.113.1' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_file_contains "$PROC_BANS" "203.0.113.1" "正常 IP 被封禁成功"
echo "unban 203.0.113.1" > "$PROC_BANS" 2>/dev/null || true

# 测试 1.2: 简单 ../ 路径遍历应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '../etc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "简单 ../ 路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "简单 ../ 路径遍历被拒绝（封禁列表变化了）"
fi

# 测试 1.3: 多级 ../ 路径遍历应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '../../../etc/shadow' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "多级 ../ 路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "多级 ../ 路径遍历被拒绝（封禁列表变化了）"
fi

# 测试 1.4: 以 .. 开头的输入应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '..' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "单独 .. 输入被拒绝（封禁列表未变化）"
else
    fw_fail "单独 .. 输入被拒绝（封禁列表变化了）"
fi

# 测试 1.5: 隐藏在 IP 后的路径遍历应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '192.168.1.1/../../../etc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "IP 后隐藏的路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "IP 后隐藏的路径遍历被拒绝（封禁列表变化了）"
fi

# ============================================================================
# 测试 2: Procfs bans 接口拒绝 URL 编码的路径遍历
# 内核模块将输入转为小写后检查 %2e 和 %2f
# ============================================================================
fw_subsection "Procfs bans 接口拒绝 URL 编码路径遍历"

# 测试 2.1: 小写 URL 编码 %2e%2e%2f 应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '%2e%2e%2fetc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "小写 URL 编码路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "小写 URL 编码路径遍历被拒绝（封禁列表变化了）"
fi

# 测试 2.2: 大写 URL 编码 %2E%2E%2F 应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '%2E%2E%2Fetc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "大写 URL 编码路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "大写 URL 编码路径遍历被拒绝（封禁列表变化了）"
fi

# 测试 2.3: 混合大小写 URL 编码应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '%2e%2E%2f%2E%2e%2Fetc/shadow' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "混合大小写 URL 编码被拒绝（封禁列表未变化）"
else
    fw_fail "混合大小写 URL 编码被拒绝（封禁列表变化了）"
fi

# 测试 2.4: 仅编码点号 %2e%2e 应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '%2e%2e/etc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "仅编码点号的路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "仅编码点号的路径遍历被拒绝（封禁列表变化了）"
fi

# 测试 2.5: 仅编码斜杠 %2f 应被拒绝
local_before_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '..%2fetc/passwd' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
local_after_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
if [[ "$local_before_count" -eq "$local_after_count" ]]; then
    fw_pass "仅编码斜杠的路径遍历被拒绝（封禁列表未变化）"
else
    fw_fail "仅编码斜杠的路径遍历被拒绝（封禁列表变化了）"
fi

# ============================================================================
# 测试 3: 配置解析拒绝路径遍历日志文件路径
# 守护进程 config-parser 的 validate_and_normalize_path 函数检查:
#   - strstr(input_path, "..") 拒绝包含 .. 的路径
#   - strcasestr(input_path, "%2e") / "%2f" 拒绝 URL 编码
#   - realpath() 验证解析后的路径在允许目录内
# ============================================================================
fw_subsection "配置解析拒绝路径遍历日志文件路径"

# 创建临时测试目录
TEST_DIR="/tmp/fw_test_path_traversal_$$"
mkdir -p "$TEST_DIR"

# 测试 3.1: 包含 ../ 的日志文件路径应被拒绝
cat > "$TEST_DIR/evil_traversal.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  evil_jail:
    enabled: true
    log_files:
      - "/var/log/../../../etc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/evil_traversal.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "单层 ../ 路径遍历配置被拒绝"

# 测试 3.2: 深层多级 ../ 路径遍历应被拒绝
cat > "$TEST_DIR/evil_deep_traversal.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  deep_traversal_jail:
    enabled: true
    log_files:
      - "/var/log/../../../../../../etc/passwd"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/evil_deep_traversal.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "深层多级路径遍历配置被拒绝"

# 测试 3.3: 以 .. 开头的相对路径应被拒绝
cat > "$TEST_DIR/evil_relative.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  relative_jail:
    enabled: true
    log_files:
      - "../etc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/evil_relative.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "相对路径 ../ 开头被拒绝"

# 测试 3.4: 正常 /var/log/ 路径应被接受（基线测试）
cat > "$TEST_DIR/normal_config.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  normal_jail:
    enabled: true
    log_files:
      - "/var/log/auth.log"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_success "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/normal_config.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ]" "正常 /var/log/ 路径配置被接受"

# 清理临时文件
rm -rf "$TEST_DIR"

# ============================================================================
# 测试 4: 配置解析拒绝 URL 编码的路径遍历
# validate_and_normalize_path 使用 strcasestr 检测 %2e 和 %2f
# ============================================================================
fw_subsection "配置解析拒绝 URL 编码路径遍历"

TEST_DIR="/tmp/fw_test_url_traversal_$$"
mkdir -p "$TEST_DIR"

# 测试 4.1: 小写 URL 编码 %2e%2e%2f 应被拒绝
cat > "$TEST_DIR/url_lower.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  url_lower_jail:
    enabled: true
    log_files:
      - "/var/log/%2e%2e%2f%2e%2e%2fetc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/url_lower.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "小写 URL 编码路径遍历被拒绝"

# 测试 4.2: 大写 URL 编码 %2E%2E%2F 应被拒绝
cat > "$TEST_DIR/url_upper.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  url_upper_jail:
    enabled: true
    log_files:
      - "/var/log/%2E%2E%2F%2E%2E%2Fetc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/url_upper.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "大写 URL 编码路径遍历被拒绝"

# 测试 4.3: 混合大小写 URL 编码应被拒绝
cat > "$TEST_DIR/url_mixed.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  url_mixed_jail:
    enabled: true
    log_files:
      - "/var/log/%2e%2E%2f%2E%2e%2Fetc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_failure "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/url_mixed.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -ne 0 ] && [ \$rc -ne 124 ]" "混合大小写 URL 编码被拒绝"

# 测试 4.4: 双重 URL 编码 %252e 绕过单层检测
# 注意：validate_and_normalize_path 不做 URL 解码，仅检查字面 %2e/%2f
# 因此 %252e（即编码后的 %2e）不会被直接拦截
# 但 realpath 验证目录时，/var/log 是合法目录，所以此配置会被接受
# 这是一个已知的设计限制：未对输入进行 URL 解码后再检查
cat > "$TEST_DIR/url_double.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  url_double_jail:
    enabled: true
    log_files:
      - "/var/log/%252e%252e%252fetc/shadow"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

# 双重编码路径绕过了 %2e/%2f 和 .. 的字面检查
# realpath 仅验证目录部分 /var/log 是合法的
assert_success "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/url_double.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ]" "双重 URL 编码绕过单层检测（已知限制）"

# 清理临时文件
rm -rf "$TEST_DIR"

# ============================================================================
# 测试 5: 符号链接攻击检测
# 内核模块在 restore_state_from_file 中使用 O_NOFOLLOW 打开状态文件
# 如果文件是符号链接，filp_open 返回 -ELOOP 并被拒绝
# ============================================================================
fw_subsection "符号链接攻击检测"

# 测试 5.1: 内核模块拒绝符号链接状态文件
# 创建指向 /proc/self/environ 的符号链接作为状态文件（使用临时路径）
local_state_file="/tmp/fw_test_state_$$.file"
rm -f "$local_state_file" 2>/dev/null || true
ln -sf /proc/self/environ "$local_state_file"

# 清空 dmesg 中旧的防火墙消息
dmesg -c > /dev/null 2>&1 || true

# 加载模块，模块在初始化时会尝试恢复状态文件
assert_success "insmod '$KERNEL_MODULE_PATH' 2>/dev/null" "内核模块加载成功（符号链接状态文件被跳过）"
sleep 0.5

# 验证 dmesg 中包含符号链接拒绝消息
DMESG_TMP="/tmp/fw_dmesg_check_$$"
dmesg 2>/dev/null > "$DMESG_TMP"
assert_true "grep -q 'symlink detected and rejected' '$DMESG_TMP'" "dmesg 包含符号链接拒绝消息"
rm -f "$DMESG_TMP"

# 清理符号链接
rm -f "$local_state_file" 2>/dev/null || true

# 测试 5.2: 内核模块拒绝包含 ../ 的状态文件路径
sleep 0.3

# 清空 dmesg
dmesg -c > /dev/null 2>&1 || true

# 使用包含 ../ 的状态文件路径加载模块
assert_success "insmod '$KERNEL_MODULE_PATH' state_file='/var/lib/../../../tmp/evil_state' 2>/dev/null" "模块加载成功（../ 状态文件路径被拒绝）"
sleep 0.5

# 验证 dmesg 中包含路径遍历拒绝消息
DMESG_TMP="/tmp/fw_dmesg_check_$$"
dmesg 2>/dev/null > "$DMESG_TMP"
assert_true "grep -q 'path traversal attempt rejected' '$DMESG_TMP'" "dmesg 包含状态文件路径遍历拒绝消息"
rm -f "$DMESG_TMP"

# 测试 5.3: 内核模块拒绝状态文件路径中的 ../ 模式（/.. 边界情况）
sleep 0.3

# 清空 dmesg
dmesg -c > /dev/null 2>&1 || true

# 使用 /.. 边界模式的状态文件路径加载模块
assert_success "insmod '$KERNEL_MODULE_PATH' state_file='/var/lib/firewall/..' 2>/dev/null" "模块加载成功（/.. 边界路径被拒绝）"
sleep 0.5

# 验证 dmesg 中包含路径遍历拒绝消息
DMESG_TMP="/tmp/fw_dmesg_check_$$"
dmesg 2>/dev/null > "$DMESG_TMP"
assert_true "grep -q 'path traversal attempt rejected' '$DMESG_TMP'" "dmesg 包含 /.. 边界路径遍历拒绝消息"
rm -f "$DMESG_TMP"

# ============================================================================
# 测试 6: 验证正常操作不受影响（回归测试）
# ============================================================================
fw_subsection "验证正常操作不受影响"

# 确保模块已加载
LSMOD_TMP="/tmp/fw_lsmod_check_$$"
lsmod > "$LSMOD_TMP" 2>/dev/null
rm -f "$LSMOD_TMP"

# 测试 6.1: 正常 IP 封禁仍然工作
echo '203.0.113.50' > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_file_contains "$PROC_BANS" "203.0.113.50" "正常 IP 封禁仍然工作"
echo "unban 203.0.113.50" > "$PROC_BANS" 2>/dev/null || true

# 测试 6.2: 正常守护进程配置仍然工作
TEST_DIR="/tmp/fw_test_normal_regression_$$"
mkdir -p "$TEST_DIR"

cat > "$TEST_DIR/normal_regression.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 0

jails:
  sshd:
    enabled: true
    log_files:
      - "/var/log/auth.log"
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

assert_success "timeout 2 '$DAEMON_PATH' -c '$TEST_DIR/normal_regression.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ]" "正常守护进程配置仍然工作"

# 清理
rm -rf "$TEST_DIR"

# ============================================================================
# 清理环境
# ============================================================================

echo ""
echo "路径遍历防护测试完成"
