#!/bin/bash
# Test Suite 14: Integer Overflow Protection
# Tests for ban time overflow protection in kernel module

fw_test_header "整数溢出防护测试"

# 确保模块已加载
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 测试 1：正常封禁时间（应成功）
fw_subsection "正常封禁时间"
echo "$TEST_IP 3600" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "$TEST_IP" "正常封禁时间 (3600s) 应成功"
echo "unban $TEST_IP" > "$PROC_BANS" 2>/dev/null

# 测试 2：最大允许封禁时间（应成功）
fw_subsection "最大封禁时间"
echo "$TEST_IP2 31536000" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "$TEST_IP2" "最大封禁时间 (365天) 应成功"
echo "unban $TEST_IP2" > "$PROC_BANS" 2>/dev/null

# 测试 3：超过最大封禁时间（应失败）
fw_subsection "超限封禁时间"
# 内核应拒绝超过 MAX_BAN_TIME 的封禁时间（365 天 = 31536000 秒）
echo "$TEST_IP3 999999999" > "$PROC_BANS" 2>/dev/null
sleep 0.3
# 验证 IP 未被封禁（写入应被拒绝）
assert_true "! grep -q '$TEST_IP3' '$PROC_BANS' 2>/dev/null" "超限封禁时间应被拒绝"
echo "unban $TEST_IP3" > "$PROC_BANS" 2>/dev/null

# 测试 4：永久封禁（0 秒）仍应正常工作
fw_subsection "永久封禁"
echo "192.168.1.103 0" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.103" "永久封禁 (0s) 应成功"
echo "unban 192.168.1.103" > "$PROC_BANS" 2>/dev/null

# 测试 5：最小封禁时间（应成功）
fw_subsection "最小封禁时间"
echo "192.168.1.104 30" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.104" "最小封禁时间 (30s) 应成功"
echo "unban 192.168.1.104" > "$PROC_BANS" 2>/dev/null

# 测试 6：极小封禁时间（应成功但可能很快过期）
fw_subsection "极小封禁时间"
echo "192.168.1.105 1" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.105" "极小封禁时间 (1s) 应接受"
echo "unban 192.168.1.105" > "$PROC_BANS" 2>/dev/null
