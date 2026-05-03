#!/bin/bash
# Test Suite 14: Integer Overflow Protection
# Tests for ban time overflow protection in kernel module

fw_test_header "整数溢出防护测试"

# Ensure module is loaded
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# Test 1: Normal ban time (should succeed)
fw_subsection "正常封禁时间"
echo "$TEST_IP 3600" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "$TEST_IP" "正常封禁时间 (3600s) 应成功"
echo "unban $TEST_IP" > "$PROC_BANS" 2>/dev/null

# Test 2: Maximum allowed ban time (should succeed)
fw_subsection "最大封禁时间"
echo "$TEST_IP2 31536000" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "$TEST_IP2" "最大封禁时间 (365天) 应成功"
echo "unban $TEST_IP2" > "$PROC_BANS" 2>/dev/null

# Test 3: Ban time exceeding maximum (should fail)
fw_subsection "超限封禁时间"
# The kernel should reject ban times > MAX_BAN_TIME (365 days = 31536000s)
echo "$TEST_IP3 999999999" > "$PROC_BANS" 2>/dev/null
sleep 0.3
# Verify IP was NOT banned (write should have been rejected)
assert_true "! grep -q '$TEST_IP3' '$PROC_BANS' 2>/dev/null" "超限封禁时间应被拒绝"
echo "unban $TEST_IP3" > "$PROC_BANS" 2>/dev/null

# Test 4: Permanent ban (0 seconds) should still work
fw_subsection "永久封禁"
echo "192.168.1.103 0" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.103" "永久封禁 (0s) 应成功"
echo "unban 192.168.1.103" > "$PROC_BANS" 2>/dev/null

# Test 5: Minimum ban time (should succeed)
fw_subsection "最小封禁时间"
echo "192.168.1.104 30" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.104" "最小封禁时间 (30s) 应成功"
echo "unban 192.168.1.104" > "$PROC_BANS" 2>/dev/null

# Test 6: Very small ban time (should succeed but may expire quickly)
fw_subsection "极小封禁时间"
echo "192.168.1.105 1" > "$PROC_BANS" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BANS" "192.168.1.105" "极小封禁时间 (1s) 应接受"
echo "unban 192.168.1.105" > "$PROC_BANS" 2>/dev/null
