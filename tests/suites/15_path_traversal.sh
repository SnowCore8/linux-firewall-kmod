#!/bin/bash
# Test Suite 15: Path Traversal Protection
# 路径遍历防护测试套件
# 测试内核模块和守护进程对路径遍历攻击的防护

source "$(dirname "$0")/../test_framework.sh"
source "$(dirname "$0")/../test_config.sh"

fw_test_header "路径遍历防护测试"

# 设置必要环境
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# ============================================================================
# 测试 1: Procfs bans 接口拒绝路径遍历输入
# ============================================================================
fw_subsection "Procfs bans 接口拒绝 '../' 输入"

# 测试 1.1: 正常 IP 应该被成功封禁
assert_success "echo '203.0.113.1' > '$PROC_BANS'" "正常 IP 被成功封禁"

# 测试 1.2: 包含 '../' 的路径遍历输入应被拒绝
assert_failure "echo '../etc/passwd' > '$PROC_BANS' 2>&1" "路径遍历 '../' 被拒绝"

# 测试 1.3: 包含多级 '../' 的路径遍历输入应被拒绝
assert_failure "echo '../../../etc/shadow' > '$PROC_BANS' 2>&1" "多级路径遍历被拒绝"

# 测试 1.4: 包含 '/../' 的路径遍历输入应被拒绝
assert_failure "echo '192.168.1.1/../../../etc/passwd' > '$PROC_BANS' 2>&1" "混合路径遍历被拒绝"

# ============================================================================
# 测试 2: 配置解析拒绝路径遍历日志文件
# ============================================================================
fw_subsection "配置解析拒绝路径遍历日志文件"

# 创建临时目录用于测试
TEST_DIR="/tmp/fw_test_path_$$"
mkdir -p "$TEST_DIR"

# 测试 2.1: 包含 '../' 的日志文件路径应被拒绝
cat > "$TEST_DIR/evil_traversal.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "evil_jail"
    log_files:
      - "/var/log/../../../etc/shadow"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/evil_traversal.yaml --strict 2>&1" "路径遍历配置被拒绝"

# 测试 2.2: 包含多级 '../' 的日志文件路径应被拒绝
cat > "$TEST_DIR/evil_deep_traversal.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "deep_traversal_jail"
    log_files:
      - "/var/log/../../../../../../etc/passwd"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/evil_deep_traversal.yaml --strict 2>&1" "深层路径遍历配置被拒绝"

# 清理临时文件
rm -rf "$TEST_DIR"

# ============================================================================
# 测试 3: URL 编码的路径遍历应被拒绝
# ============================================================================
fw_subsection "URL 编码的路径遍历应被拒绝"

# 创建临时目录用于测试
TEST_DIR="/tmp/fw_test_url_$$"
mkdir -p "$TEST_DIR"

# 测试 3.1: 小写 URL 编码的路径遍历
cat > "$TEST_DIR/url_encoded_lower.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "url_encoded_jail"
    log_files:
      - "/var/log/%2e%2e%2f%2e%2e%2fetc/shadow"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/url_encoded_lower.yaml --strict 2>&1" "小写 URL 编码路径遍历被拒绝"

# 测试 3.2: 大写 URL 编码的路径遍历
cat > "$TEST_DIR/url_encoded_upper.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "url_encoded_upper_jail"
    log_files:
      - "/var/log/%2E%2E%2F%2E%2E%2Fetc/shadow"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/url_encoded_upper.yaml --strict 2>&1" "大写 URL 编码路径遍历被拒绝"

# 测试 3.3: 混合大小写 URL 编码的路径遍历
cat > "$TEST_DIR/url_encoded_mixed.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "url_encoded_mixed_jail"
    log_files:
      - "/var/log/%2e%2E%2f%2E%2e%2Fetc/shadow"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/url_encoded_mixed.yaml --strict 2>&1" "混合大小写 URL 编码路径遍历被拒绝"

# 清理临时文件
rm -rf "$TEST_DIR"

# ============================================================================
# 测试 4: 符号链接攻击应被拒绝
# ============================================================================
fw_subsection "符号链接攻击应被拒绝"

# 创建临时目录用于测试
TEST_DIR="/tmp/fw_test_symlink_$$"
mkdir -p "$TEST_DIR"

# 测试 4.1: 符号链接指向敏感文件应被拒绝
# 创建一个符号链接指向 /etc/shadow
ln -sf /etc/shadow "$TEST_DIR/symlink_to_shadow"

# 创建配置文件使用符号链接
cat > "$TEST_DIR/symlink_attack.yaml" << EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "symlink_jail"
    log_files:
      - "$TEST_DIR/symlink_to_shadow"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/symlink_attack.yaml --strict 2>&1" "符号链接攻击被拒绝"

# 测试 4.2: 符号链接指向多级 ../ 的目标应被拒绝
mkdir -p "$TEST_DIR/real_dir"
ln -sf "../../../etc/passwd" "$TEST_DIR/real_dir/symlink_traversal"

cat > "$TEST_DIR/symlink_traversal_attack.yaml" << EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900

jails:
  - name: "symlink_traversal_jail"
    log_files:
      - "$TEST_DIR/real_dir/symlink_traversal"
    regex: "Failed password"
    max_retries: 5
    findtime: 600
    ban_time: 900
EOF

assert_failure "$DAEMON_PATH -c $TEST_DIR/symlink_traversal_attack.yaml --strict 2>&1" "符号链接的路径遍历目标被拒绝"

# 清理临时文件
rm -rf "$TEST_DIR"

# ============================================================================
# 测试 5: 内核模块 bans 接口拒绝 URL 编码的输入
# ============================================================================
fw_subsection "内核模块 bans 接口拒绝 URL 编码输入"

# 测试 5.1: URL 编码的路径遍历在 bans 接口应被拒绝
assert_failure "echo '%2e%2e%2fetc/passwd' > '$PROC_BANS' 2>&1" "URL 编码路径遍历在 bans 接口被拒绝"

# 测试 5.2: 大写 URL 编码的路径遍历在 bans 接口应被拒绝
assert_failure "echo '%2E%2E%2Fetc/passwd' > '$PROC_BANS' 2>&1" "大写 URL 编码路径遍历在 bans 接口被拒绝"

# ============================================================================
# 测试 6: 验证正常配置仍能工作
# ============================================================================
fw_subsection "验证正常配置仍能工作"

# 创建临时目录用于测试
TEST_DIR="/tmp/fw_test_normal_$$"
mkdir -p "$TEST_DIR"

# 测试 6.1: 正常日志文件路径应被接受
cat > "$TEST_DIR/normal_config.yaml" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  metrics_port: 0

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""
EOF

# 注意：由于 /var/log/auth.log 可能不存在，我们只测试配置解析不失败
# 使用 --permissive 模式以允许日志文件不存在的情况
# 使用 timeout 限制测试时间，防止测试超时
# 守护进程在后台运行，我们只测试配置解析是否成功
# 使用后台运行并等待守护进程启动
timeout 5 $DAEMON_PATH -c $TEST_DIR/normal_config.yaml --permissive 2>&1 &
DAEMON_PID=$!
sleep 2
if kill -0 $DAEMON_PID 2>/dev/null; then
    TEST_PASS=$((TEST_PASS + 1))
    echo -e "  ${GREEN}[PASS]${NC} 正常配置被接受"
    TEST_RESULTS+=("PASS|$CURRENT_SUITE|正常配置被接受")
    kill $DAEMON_PID 2>/dev/null || true
    sleep 1
else
    TEST_FAIL=$((TEST_FAIL + 1))
    echo -e "  ${RED}[FAIL]${NC} 正常配置被接受 (守护进程未启动)"
    TEST_RESULTS+=("FAIL|$CURRENT_SUITE|正常配置被接受 (守护进程未启动)")
fi

# 清理临时文件
rm -rf "$TEST_DIR"

# 清理临时文件
rm -rf "$TEST_DIR"

# 卸载内核模块
fw_ensure_module_unloaded

# 打印测试摘要
echo ""
echo "路径遍历防护测试完成"
echo "所有测试应通过，验证路径遍历攻击被正确防护"
