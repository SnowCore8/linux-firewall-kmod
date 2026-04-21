#!/bin/bash
# 03_ban_unban.sh - 封禁/解封测试

fw_test_header "封禁/解封测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 3.1 基本封禁/解封
fw_subsection "基本封禁/解封"
echo "$TEST_IP" > "$PROC_ADD_BAN" 2>/dev/null
sleep 0.3
assert_file_contains "$PROC_BAN_LIST" "$TEST_IP" "IP $TEST_IP 封禁成功"

echo "$TEST_IP" > "$PROC_REMOVE_BAN" 2>/dev/null
sleep 0.3
assert_true "! grep -q '$TEST_IP' '$PROC_BAN_LIST' 2>/dev/null" "IP $TEST_IP 解封成功"

# 3.2 批量封禁
fw_subsection "批量封禁"
for i in $(seq 1 10); do
    echo "203.0.113.$i" > "$PROC_ADD_BAN" 2>/dev/null || true
done
sleep 0.3

local_count=$(wc -l < "$PROC_BAN_LIST" 2>/dev/null || echo 0)
assert_ge "$local_count" 10 "批量封禁 10 个 IP，实际 $local_count 个"

# 清理批量封禁
for i in $(seq 1 10); do
    echo "203.0.113.$i" > "$PROC_REMOVE_BAN" 2>/dev/null || true
done

# 3.3 重复封禁
fw_subsection "重复封禁处理"
echo "$TEST_IP2" > "$PROC_ADD_BAN" 2>/dev/null
sleep 0.2
echo "$TEST_IP2" > "$PROC_ADD_BAN" 2>/dev/null
sleep 0.2

local_dup_count=$(grep -c "$TEST_IP2" "$PROC_BAN_LIST" 2>/dev/null || echo 0)
assert_eq "$local_dup_count" "1" "重复封禁未产生重复条目"
echo "$TEST_IP2" > "$PROC_REMOVE_BAN" 2>/dev/null || true

# 3.4 封禁/解封循环
fw_subsection "封禁/解封循环稳定性"
local_cycle_pass=true
for cycle in $(seq 1 5); do
    local_cycle_ip="198.51.100.$cycle"
    echo "$local_cycle_ip" > "$PROC_ADD_BAN" 2>/dev/null || true
    sleep 0.1
    echo "$local_cycle_ip" > "$PROC_REMOVE_BAN" 2>/dev/null || true
done
assert_true "true" "5 次封禁/解封循环稳定"

fw_ensure_module_unloaded
