#!/bin/bash
# 04_whitelist.sh - 白名单测试

fw_test_header "白名单测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 4.1 系统 IP 自动发现
fw_subsection "系统 IP 自动发现"
local_wl_count=$(wc -l < "$PROC_WHITELIST" 2>/dev/null || echo 0)
assert_ge "$local_wl_count" 1 "系统 IP 自动发现 ($local_wl_count 个)"

# 4.2 手动添加白名单
fw_subsection "手动添加/移除白名单"
echo "add $TEST_SUBNET" > "$PROC_WHITELIST" 2>/dev/null
sleep 0.2
assert_file_contains "$PROC_WHITELIST" "$TEST_SUBNET" "手动添加子网白名单 $TEST_SUBNET"

# 4.3 白名单保护 - 验证白名单 IP 无法被封禁
local_bans_before=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
local_write_rc=0
echo "$TEST_SUBNET_IP" > "$PROC_BANS" 2>/dev/null || local_write_rc=$?
sleep 0.2
local_bans_after=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
# 验证封禁列表没有增长（无论 procfs 拒绝写入还是内核过滤，结果都是列表不变）
assert_eq "$local_bans_before" "$local_bans_after" "白名单子网 IP 未进入封禁列表"
# 验证列表中确实不存在该 IP
assert_true "! grep -q '$TEST_SUBNET_IP' '$PROC_BANS' 2>/dev/null" "封禁列表中无白名单 IP"

# 移除白名单
echo "remove $TEST_SUBNET" > "$PROC_WHITELIST" 2>/dev/null
sleep 0.2
assert_true "! grep -q '$TEST_SUBNET' '$PROC_WHITELIST' 2>/dev/null" "白名单移除成功"

# 4.4 特殊 IP 保护
fw_subsection "特殊 IP 地址保护"
echo "$ZERO_IP" > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_true "! grep -q '$ZERO_IP' '$PROC_BANS' 2>/dev/null" "零地址 (0.0.0.0) 保护"

echo "$BROADCAST_IP" > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_true "! grep -q '$BROADCAST_IP' '$PROC_BANS' 2>/dev/null" "广播地址 (255.255.255.255) 保护"

echo "$MULTICAST_IP" > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_true "! grep -q '$MULTICAST_IP' '$PROC_BANS' 2>/dev/null" "组播地址 (224.0.0.1) 保护"

echo "$LOCALHOST_IP" > "$PROC_BANS" 2>/dev/null || true
sleep 0.2
assert_true "! grep -q '$LOCALHOST_IP' '$PROC_BANS' 2>/dev/null" "回环地址 (127.0.0.1) 保护"

# 4.5 白名单格式验证
fw_subsection "白名单格式验证"
local rc=0
echo 'add invalid_subnet' > "$PROC_WHITELIST" 2>/dev/null || rc=$?
assert_true "[[ $rc -ne 0 ]]" "无效子网格式被拒绝"

rc=0
echo 'add 999.999.999.999/32' > "$PROC_WHITELIST" 2>/dev/null || rc=$?
assert_true "[[ $rc -ne 0 ]]" "无效子网 IP 被拒绝"

rc=0
echo 'add 192.168.1.0/33' > "$PROC_WHITELIST" 2>/dev/null || rc=$?
assert_true "[[ $rc -ne 0 ]]" "无效前缀长度被拒绝"

# 4.6 白名单容量测试
fw_subsection "白名单容量测试 (上限 64)"
local_added=0
for i in $(seq 1 50); do
    if echo "add 10.$((i/255)).$((i%255)).0/24" > "$PROC_WHITELIST" 2>/dev/null; then
        local_added=$((local_added + 1))
    fi
done
sleep 0.3

local_final_count=$(wc -l < "$PROC_WHITELIST" 2>/dev/null || echo 0)
assert_le "$local_final_count" 64 "白名单数量在限制内 (64)，实际 $local_final_count"

# 清理
for i in $(seq 1 50); do
    echo "remove 10.$((i/255)).$((i%255)).0/24" > "$PROC_WHITELIST" 2>/dev/null || true
done

fw_ensure_module_unloaded
