#!/bin/bash
# 08_stress_perf.sh - 压力/性能测试

fw_test_header "压力/性能测试"

# 8.1 封禁性能
fw_subsection "封禁性能"
local_start=$(date +%s%N)
for i in $(seq 1 $PERF_TEST_COUNT); do
    echo "203.0.114.$i" > "$PROC_BANS" 2>/dev/null || true
done
local_dur=$(( ($(date +%s%N) - local_start) / 1000000 ))
local_avg=$(( local_dur / PERF_TEST_COUNT ))
fw_log_info "封禁 $PERF_TEST_COUNT IP 耗时: ${local_dur}ms (平均 ${local_avg}ms/IP)"
assert_le "$local_dur" "$BAN_PERF_THRESHOLD_MS" "封禁 $PERF_TEST_COUNT IP 在 ${BAN_PERF_THRESHOLD_MS}ms 内"

# 8.2 解封性能
fw_subsection "解封性能"
local_start=$(date +%s%N)
for i in $(seq 1 $PERF_TEST_COUNT); do
    echo "unban 203.0.114.$i" > "$PROC_BANS" 2>/dev/null || true
done
local_dur=$(( ($(date +%s%N) - local_start) / 1000000 ))
local_avg=$(( local_dur / PERF_TEST_COUNT ))
fw_log_info "解封 $PERF_TEST_COUNT IP 耗时: ${local_dur}ms (平均 ${local_avg}ms/IP)"
assert_le "$local_dur" "$UNBAN_PERF_THRESHOLD_MS" "解封 $PERF_TEST_COUNT IP 在 ${UNBAN_PERF_THRESHOLD_MS}ms 内"

# 8.3 压力测试
fw_subsection "压力测试 (快速大量封禁)"
local_start=$(date +%s%N)
for i in $(seq 1 $STRESS_IP_COUNT); do
    echo "172.16.$((i/255)).$((i%255))" > "$PROC_BANS" 2>/dev/null || true
done
local_dur=$(( ($(date +%s%N) - local_start) / 1000000 ))
fw_log_info "压力测试 $STRESS_IP_COUNT IP 耗时: ${local_dur}ms"
assert_le "$local_dur" "$STRESS_THRESHOLD_MS" "压力测试在 ${STRESS_THRESHOLD_MS}ms 内完成"

local_ban_count=$(fw_count_bans)
assert_le "$local_ban_count" "$MAX_BAN_CAPACITY" "封禁数量在限制内 ($MAX_BAN_CAPACITY)，实际 $local_ban_count"

# 清理压力测试 IP
for i in $(seq 1 $STRESS_IP_COUNT); do
    echo "unban 172.16.$((i/255)).$((i%255))" > "$PROC_BANS" 2>/dev/null || true
done

# 8.4 批量封禁负载测试
fw_subsection "批量封禁负载测试"
for i in $(seq 1 100); do
    echo "192.0.2.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done
sleep 0.5
local_ban_count=$(fw_count_bans)
assert_ge "$local_ban_count" 50 "批量封禁后封禁列表数据完整 (>50 IP)，实际 $local_ban_count"

# 清理批量负载测试 IP
for i in $(seq 1 100); do
    echo "unban 192.0.2.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done
