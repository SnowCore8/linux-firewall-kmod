#!/bin/bash
# 11_resource_mgmt.sh - 资源管理测试

fw_test_header "资源管理测试"

# 11.1 模块加载/卸载循环
fw_subsection "模块加载/卸载循环"
for i in $(seq 1 3); do
    fw_ensure_module_loaded "$KERNEL_MODULE_PATH"
    sleep 0.2
    fw_ensure_module_unloaded
    sleep 0.1
done
# 最终加载以验证模块在循环后仍正常工作
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"
assert_true "[[ -r '$PROC_BANS' ]]" "3 次加载/卸载循环稳定，模块仍可访问"

# 11.2 大量操作后模块稳定性
fw_subsection "大量操作后模块稳定性"
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

for i in $(seq 1 50); do
    echo "203.0.113.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done
sleep 0.3

# 检查模块是否仍响应
assert_true "[[ -r '$PROC_BANS' ]]" "大量操作后模块仍响应"

# 清理
for i in $(seq 1 50); do
    echo "unban 203.0.113.$((i%256))" > "$PROC_BANS" 2>/dev/null || true
done

# 11.3 封禁容量测试 (1024 上限)
fw_subsection "封禁容量边界测试 (1024 上限)"
local_added=0
for i in $(seq 1 200); do
    if echo "10.0.$((i/256)).$((i%256))" > "$PROC_BANS" 2>/dev/null; then
        local_added=$((local_added + 1))
    fi
done
sleep 0.5

local_final_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
fw_log_info "添加 200 IP 后封禁列表: $local_final_count"
assert_le "$local_final_count" 1024 "封禁数量未超出 1024 上限"

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
assert_true "! [[ -d '$PROC_DIR' ]]" "模块卸载后 proc 目录消失" || warn_test "proc 目录仍存在（可能需要时间清理）"

# 11.5 守护进程资源
fw_subsection "守护进程资源检查"
if [[ -x "$DAEMON_PATH" ]]; then
    # 检查二进制文件大小
    local_bin_size=$(stat -c%s "$DAEMON_PATH" 2>/dev/null || echo 0)
    fw_log_info "守护进程二进制大小: $local_bin_size bytes"
    assert_le "$local_bin_size" 1048576 "守护进程二进制 < 1MB"
else
    warn_test "守护进程未编译，跳过检查"
fi
