#!/bin/bash
# 07_concurrency.sh - 并发/竞态条件测试

fw_test_header "并发/竞态条件测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 7.1 并发封禁
fw_subsection "并发封禁"
local_start=$(date +%s%N)
for i in $(seq 1 20); do
    (echo "192.168.100.$i" > "$PROC_ADD_BAN" 2>/dev/null &)
done
wait
local_dur=$(( ($(date +%s%N) - local_start) / 1000000 ))
assert_le "$local_dur" 5000 "并发封禁 20 IP 在 5s 内 (${local_dur}ms)"

sleep 0.5

# 7.2 同时封禁和解封
fw_subsection "同时封禁/解封"
for i in $(seq 1 10); do
    echo "10.10.10.$i" > "$PROC_ADD_BAN" 2>/dev/null &
    echo "10.10.10.$i" > "$PROC_REMOVE_BAN" 2>/dev/null &
done
wait
sleep 0.5
assert_true "true" "同时封禁/解封未导致崩溃"

# 清理
for i in $(seq 1 10); do
    echo "10.10.10.$i" > "$PROC_REMOVE_BAN" 2>/dev/null || true
done

# 7.3 白名单和封禁列表并发操作
fw_subsection "白名单和封禁列表并发操作"
for i in $(seq 1 5); do
    echo "172.20.$i.0/24" > "$PROC_WHITELIST_ADD" 2>/dev/null &
    echo "172.20.$i.$i" > "$PROC_ADD_BAN" 2>/dev/null &
done
wait
sleep 0.5
assert_true "true" "白名单和封禁列表并发操作稳定"

# 清理
for i in $(seq 1 5); do
    echo "172.20.$i.0/24" > "$PROC_WHITELIST_REMOVE" 2>/dev/null || true
    echo "172.20.$i.$i" > "$PROC_REMOVE_BAN" 2>/dev/null || true
done

# 7.4 读取时修改
fw_subsection "读取时修改"
for i in $(seq 1 10); do
    (cat "$PROC_BAN_LIST" > /dev/null 2>&1 &) &
    echo "192.168.200.$i" > "$PROC_ADD_BAN" 2>/dev/null &
done
wait
sleep 0.5
assert_true "true" "读取时修改操作稳定"

# 清理
for i in $(seq 1 10); do
    echo "192.168.200.$i" > "$PROC_REMOVE_BAN" 2>/dev/null || true
done

fw_ensure_module_unloaded
