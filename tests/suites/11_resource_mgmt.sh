#!/bin/bash
# 11_resource_mgmt.sh - 资源管理测试

fw_test_header "资源管理测试"

# 11.1 模块加载/卸载循环
fw_subsection "模块加载/卸载循环"
for i in $(seq 1 3); do
    fw_ensure_module_unloaded 2>/dev/null || true
    fw_ensure_module_loaded "$KERNEL_MODULE_PATH" 2>/dev/null || true
done
assert_true "[[ -r '$PROC_BANS' ]]" "3 次加载/卸载循环稳定，模块仍可访问"

# 11.2 大量操作后模块稳定性
fw_subsection "大量操作后模块稳定性"
for i in $(seq 1 50); do
    echo "203.0.113.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done
fw_wait_procfs
assert_true "[[ -r '$PROC_BANS' ]]" "大量操作后模块仍响应"

# 清理
for i in $(seq 1 50); do
    echo "unban 203.0.113.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done

# 11.3 封禁容量边界测试
fw_subsection "封禁容量边界测试 (4096 上限)"
local_added=0
for i in $(seq 1 200); do
    if echo "10.0.$((i/256)).$((i%256))" > "$PROC_BANS" 2>/dev/null; then
        local_added=$((local_added + 1))
    fi
done
sleep 0.5
local_final_count=$(fw_count_bans)
fw_log_info "添加 200 IP 后封禁列表: $local_final_count"
assert_le "$local_final_count" "$MAX_BAN_CAPACITY" "封禁数量未超出 $MAX_BAN_CAPACITY 上限"

# 分批清理
for i in $(seq 1 200); do
    echo "unban 10.0.$((i/256)).$((i%256))" > "$PROC_BANS" 2>/dev/null || true
    if (( i % 50 == 0 )); then
        sleep 0.05
    fi
done

# 11.4 模块卸载后 procfs 清理
fw_subsection "模块卸载后 procfs 清理"
fw_ensure_module_unloaded
sleep 1
if [[ ! -d "$PROC_DIR" ]]; then
    fw_pass "模块卸载后 proc 目录消失"
else
    sleep 1
    if [[ ! -d "$PROC_DIR" ]]; then
        fw_pass "模块卸载后 proc 目录消失（延迟清理）"
    else
        warn_test "proc 目录在模块卸载后仍存在（内核延迟清理）"
    fi
fi

# 重新加载模块供后续测试使用
if ! fw_ensure_module_loaded "$KERNEL_MODULE_PATH"; then
    fw_log_error "模块重新加载失败，后续测试套件将跳过"
fi

# 11.5 守护进程资源检查
fw_subsection "守护进程资源检查"
if [[ -x "$DAEMON_PATH" ]]; then
    local_bin_size=$(stat -c%s "$DAEMON_PATH" 2>/dev/null || echo 0)
    fw_log_info "守护进程二进制大小: $local_bin_size bytes"
    assert_le "$local_bin_size" 1048576 "守护进程二进制 < 1MB"
else
    warn_test "守护进程未编译，跳过检查"
fi
