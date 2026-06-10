#!/bin/bash
# 03_ban_unban.sh - 封禁/解封测试

fw_test_header "封禁/解封测试"

# 3.1 基本封禁/解封
fw_subsection "基本封禁/解封"
fw_ban "$TEST_IP"
assert_file_contains "$PROC_BANS" "$TEST_IP" "IP $TEST_IP 封禁成功"

fw_unban "$TEST_IP"
fw_assert_ip_not_banned "$TEST_IP" "IP $TEST_IP 解封成功"

# 3.2 批量封禁
fw_subsection "批量封禁"
fw_ban_multiple $(for i in $(seq 1 10); do echo "203.0.113.$i"; done)
local_count=$(fw_count_bans)
assert_ge "$local_count" 10 "批量封禁 10 个 IP，实际 $local_count 个"

# 清理批量封禁
fw_unban_multiple $(for i in $(seq 1 10); do echo "203.0.113.$i"; done)

# 3.3 重复封禁处理
fw_subsection "重复封禁处理"
fw_ban "$TEST_IP2"
fw_ban "$TEST_IP2"
local_dup_count=$(grep -c "$TEST_IP2" "$PROC_BANS" 2>/dev/null || echo 0)
assert_eq "$local_dup_count" "1" "重复封禁未产生重复条目"
fw_unban "$TEST_IP2"

# 3.4 封禁/解封循环
fw_subsection "封禁/解封循环稳定性"
for cycle in $(seq 1 5); do
    local_ip="198.51.100.$cycle"
    fw_ban "$local_ip"
    fw_unban "$local_ip"
done

local_all_unbanned=true
for cycle in $(seq 1 5); do
    if grep -q "198.51.100.$cycle" "$PROC_BANS" 2>/dev/null; then
        local_all_unbanned=false
        break
    fi
done
assert_true "[[ $local_all_unbanned == true ]]" "5 次封禁/解封循环稳定，所有 IP 已解封"

# 3.5 重复封禁不污染统计计数器 (回归: total_ban_count / ban_count 过度计数 Bug)
fw_subsection "重复封禁不污染统计计数器"
local_test_ip="203.0.113.250"
local_total_before=$(fw_get_stat "total_bans")
local_current_before=$(fw_get_stat "current_bans")
fw_ban "$local_test_ip"
fw_ban "$local_test_ip"
fw_ban "$local_test_ip"
local_total_after=$(fw_get_stat "total_bans")
local_current_after=$(fw_get_stat "current_bans")
local_total_delta=$((local_total_after - local_total_before))
local_current_delta=$((local_current_after - local_current_before))
assert_eq "$local_total_delta" "1" "重复 ban 3 次后 total_bans 仅 +1 (实际 +$local_total_delta)"
assert_eq "$local_current_delta" "1" "重复 ban 3 次后 current_bans 仅 +1 (实际 +$local_current_delta)"
fw_unban "$local_test_ip"

# 3.6 IPv6 路径同样适用 (回归覆盖: __do_ban_ip_ipv6)
fw_subsection "IPv6 重复封禁不污染统计"
local_v6_ip="2001:db8::1"
# 先确保不在表中
echo "$local_v6_ip" | grep -E "^${local_v6_ip} " "$PROC_BANS" > /dev/null 2>&1 && fw_unban "$local_v6_ip"
local_v6_total_before=$(fw_get_stat "total_bans")
local_v6_current_before=$(fw_get_stat "current_bans")
echo "$local_v6_ip" > "$PROC_BANS"
echo "$local_v6_ip" > "$PROC_BANS"
echo "$local_v6_ip" > "$PROC_BANS"
fw_wait_procfs
local_v6_total_after=$(fw_get_stat "total_bans")
local_v6_current_after=$(fw_get_stat "current_bans")
local_v6_total_delta=$((local_v6_total_after - local_v6_total_before))
local_v6_current_delta=$((local_v6_current_after - local_v6_current_before))
assert_eq "$local_v6_total_delta" "1" "IPv6 重复 ban 3 次后 total_bans 仅 +1 (实际 +$local_v6_total_delta)"
assert_eq "$local_v6_current_delta" "1" "IPv6 重复 ban 3 次后 current_bans 仅 +1 (实际 +$local_v6_current_delta)"
fw_unban "$local_v6_ip"
