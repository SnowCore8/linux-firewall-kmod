#!/bin/bash
# 04_whitelist.sh - 白名单测试

fw_test_header "白名单测试"

# 4.1 系统 IP 自动发现
fw_subsection "系统 IP 自动发现"
local_wl_count=$(fw_count_whitelist)
assert_ge "$local_wl_count" 1 "系统 IP 自动发现 ($local_wl_count 个)"

# 4.2 手动添加/移除白名单
fw_subsection "手动添加/移除白名单"
fw_whitelist_add "$TEST_SUBNET"
assert_file_contains "$PROC_WHITELIST" "$TEST_SUBNET" "手动添加子网白名单 $TEST_SUBNET"

# 4.3 白名单保护
fw_subsection "白名单保护"
local_bans_before=$(fw_count_bans)
echo "$TEST_SUBNET_IP" > "$PROC_BANS" 2>/dev/null || true
fw_wait_procfs
assert_eq "$(fw_count_bans)" "$local_bans_before" "白名单子网 IP 未进入封禁列表"
fw_assert_ip_not_banned "$TEST_SUBNET_IP" "封禁列表中无白名单 IP"

fw_whitelist_remove "$TEST_SUBNET"
assert_true "! grep -q '$TEST_SUBNET' '$PROC_WHITELIST' 2>/dev/null" "白名单移除成功"

# 4.4 特殊 IP 保护
fw_subsection "特殊 IP 地址保护"
for ip_info in "$ZERO_IP:零地址 (0.0.0.0)" "$BROADCAST_IP:广播地址 (255.255.255.255)" "$MULTICAST_IP:组播地址 (224.0.0.1)" "$LOCALHOST_IP:回环地址 (127.0.0.1)"; do
    ip="${ip_info%%:*}"
    desc="${ip_info##*:}"
    echo "$ip" > "$PROC_BANS" 2>/dev/null || true
    fw_wait_procfs
    fw_assert_ip_not_banned "$ip" "$desc 保护"
done

# 4.5 白名单格式验证
fw_subsection "白名单格式验证"
for invalid_input in "add invalid_subnet:无效子网格式" "add 999.999.999.999/32:无效子网 IP" "add 192.168.1.0/33:无效前缀长度"; do
    input="${invalid_input%%:*}"
    desc="${invalid_input##*:}"
    local rc=0
    echo "$input" > "$PROC_WHITELIST" 2>/dev/null || rc=$?
    assert_true "[[ $rc -ne 0 ]]" "$desc 被拒绝"
done

# 4.6 白名单容量测试
fw_subsection "白名单容量测试 (上限 64)"
local_added=0
for i in $(seq 1 50); do
    if echo "add 10.$((i/255)).$((i%255)).0/24" > "$PROC_WHITELIST" 2>/dev/null; then
        local_added=$((local_added + 1))
    fi
done
fw_wait_procfs
local wl_count=$(fw_get_stat current_whitelist)
assert_le "$wl_count" 64 "白名单数量在限制内 (64)，实际 $wl_count"

# 清理
for i in $(seq 1 50); do
    ip="10.$((i/255)).$((i%255)).0/24"
    echo "remove $ip" > "$PROC_WHITELIST" 2>/dev/null || true
done
fw_unban_multiple $(for i in $(seq 1 50); do echo "10.$((i/255)).$((i%255)).0/24"; done) 2>/dev/null || true
