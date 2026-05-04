#!/bin/bash
# 05_input_validation.sh - 输入验证测试

fw_test_header "输入验证测试"

# 5.1 无效 IP 格式
fw_subsection "无效 IP 格式"
assert_failure "echo '$INVALID_IP' > '$PROC_BANS' 2>&1" "无效 IP (999.999.999.999) 被拒绝"
assert_failure "echo 'abc.def.ghi.jkl' > '$PROC_BANS' 2>&1" "字母 IP 被拒绝"
assert_failure "echo '192.168.1' > '$PROC_BANS' 2>&1" "不完整 IP (192.168.1) 被拒绝"
assert_failure "echo '192.168.1.1.1' > '$PROC_BANS' 2>&1" "超额 IP (192.168.1.1.1) 被拒绝"

# 5.2 含字母 IP
assert_failure "echo '192.168.1.1a' > '$PROC_BANS' 2>&1" "含字母 IP 被拒绝"
assert_failure "echo '-1.1.1.1' > '$PROC_BANS' 2>&1" "负数 IP 被拒绝"
assert_failure "echo '256.0.0.1' > '$PROC_BANS' 2>&1" "超出范围 IP (256.0.0.1) 被拒绝"

# 5.3 超长输入
fw_subsection "超长输入 (缓冲区溢出)"
assert_failure "python3 -c \"print('A'*100)\" > '$PROC_BANS' 2>&1" "100 字符输入被拒绝"
assert_failure "python3 -c \"print('A'*1000)\" > '$PROC_BANS' 2>&1" "1000 字符输入被拒绝"

# 5.4 边界值测试
fw_subsection "边界值测试"
assert_failure "echo '0.0.0.0' > '$PROC_BANS' 2>&1" "零地址被拒绝"
assert_failure "echo '255.255.255.255' > '$PROC_BANS' 2>&1" "广播地址被拒绝"
assert_failure "echo '127.0.0.1' > '$PROC_BANS' 2>&1" "回环地址被拒绝"

# 5.5 格式验证
fw_subsection "格式验证"
assert_failure "echo 'not_an_ip' > '$PROC_BANS' 2>&1" "非 IP 格式被拒绝"
assert_failure "echo '' > '$PROC_BANS' 2>&1" "空输入被拒绝"
assert_failure "echo '   ' > '$PROC_BANS' 2>&1" "空白输入被拒绝"

# 5.6 有效边界 IP
fw_subsection "有效边界 IP"
assert_success "echo '1.0.0.1' > '$PROC_BANS' 2>/dev/null" "最小有效 IP (1.0.0.1) 被封禁"
echo "unban 1.0.0.1" > "$PROC_BANS" 2>/dev/null || true

assert_success "echo '254.255.255.255' > '$PROC_BANS' 2>/dev/null" "最大有效单播 IP 被封禁"
echo "unban 254.255.255.255" > "$PROC_BANS" 2>/dev/null || true
