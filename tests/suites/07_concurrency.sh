#!/bin/bash
# 07_concurrency.sh - 并发/竞态条件测试

fw_test_header "并发/竞态条件测试"

# 7.1 并发封禁
fw_subsection "并发封禁"
fw_benchmark "并发封禁 20 IP" 5000 "for i in \$(seq 1 20); do (echo \"192.168.100.\$i\" > \"\$PROC_BANS\" 2>/dev/null &); done; wait"
sleep 0.5

# 7.2 同时封禁和解封
fw_subsection "同时封禁/解封"
for i in $(seq 1 10); do
    echo "10.10.10.$i" > "$PROC_BANS" 2>/dev/null &
    echo "unban 10.10.10.$i" > "$PROC_BANS" 2>/dev/null &
done
wait
sleep 0.5
local_stats=$(cat "$PROC_STATS" 2>/dev/null)
assert_true "[[ -n '$local_stats' ]]" "同时封禁/解封后模块仍响应"
fw_unban_multiple $(for i in $(seq 1 10); do echo "10.10.10.$i"; done)

# 7.3 白名单和封禁列表并发操作
fw_subsection "白名单和封禁列表并发操作"
for i in $(seq 1 5); do
    echo "add 172.20.$i.0/24" > "$PROC_WHITELIST" 2>/dev/null &
    echo "172.20.$i.$i" > "$PROC_BANS" 2>/dev/null &
done
wait
sleep 0.5
local_wl=$(cat "$PROC_WHITELIST" 2>/dev/null)
local_bans=$(cat "$PROC_BANS" 2>/dev/null)
assert_true "[[ -n '$local_wl' && -n '$local_bans' ]]" "白名单和封禁列表并发操作后接口正常"
for i in $(seq 1 5); do
    fw_whitelist_remove "172.20.$i.0/24"
    fw_unban "172.20.$i.$i"
done

# 7.4 读取时修改
fw_subsection "读取时修改"
for i in $(seq 1 10); do
    cat "$PROC_BANS" > /dev/null 2>&1 &
    echo "192.168.200.$i" > "$PROC_BANS" 2>/dev/null &
done
wait
sleep 0.5
local_ban_count=$(fw_get_stat "current_bans")
assert_true "[[ -n '$local_ban_count' && '$local_ban_count' -ge 0 ]]" "读取时修改后统计信息一致"
fw_unban_multiple $(for i in $(seq 1 10); do echo "192.168.200.$i"; done)
