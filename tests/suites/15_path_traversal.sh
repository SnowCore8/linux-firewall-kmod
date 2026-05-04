#!/bin/bash
# Test Suite 15: Path Traversal Protection
# Tests for path validation in daemon

fw_test_header "路径遍历防护测试"

# 测试 1：有效日志路径应被接受
fw_subsection "有效日志路径"
local config_file="/tmp/test_valid_path.yaml"
cat > "$config_file" << 'EOF'
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 600
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retries: 3
    findtime: 600
    ban_time: 600
EOF
assert_success "test -f $config_file" "有效配置文件应创建成功"
rm -f "$config_file"

# 测试 2：包含 .. 的路径应被拒绝
fw_subsection ".. 路径遍历"
assert_true "echo '/var/log/../../../etc/passwd' | grep -q '\.\.'" ".. 路径应被检测到"

# 测试 3：包含 Shell 元字符的路径应被拒绝
fw_subsection "Shell 元字符"
assert_true "echo '/var/log/auth.log;rm' | grep -qE '[|;&]'" "分号注入应被检测到"
assert_true "echo '/var/log/auth.log|cat' | grep -qE '[|;&]'" "管道注入应被检测到"

# 测试 4：URL 编码的遍历应被拒绝
fw_subsection "URL 编码遍历"
assert_true "echo '/var/log/%2e%2e/etc/passwd' | grep -qiE '%2e|%2f'" "URL 编码遍历应被检测到"

# 测试 5：包含扩展元字符的路径应被拒绝
fw_subsection "扩展元字符"
assert_true "echo '/var/log/auth.log<redirect' | grep -qE '[<>!~*?]' " "重定向符应被检测到"

# 测试 6：/tmp/ 路径不应在允许列表中
fw_subsection "/tmp/ 路径拒绝"
assert_false "echo '/var/log /etc/ /home/ /root/' | grep -q '/tmp/'" "/tmp/ 不应在允许路径列表中"
