#!/bin/bash
# 02_procfs_interface.sh - Procfs 接口测试

fw_test_header "Procfs 接口测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 2.1 接口存在性
fw_subsection "接口文件存在性"
assert_dir_exists "$PROC_DIR" "proc/firewall 目录存在"
assert_true "[[ -w '$PROC_BANS' ]]" "bans 接口存在且可写"
assert_true "[[ -r '$PROC_WHITELIST' ]]" "whitelist 接口存在且可读"
assert_true "[[ -w '$PROC_WHITELIST' ]]" "whitelist 接口可写"
assert_true "[[ -r '$PROC_STATS' ]]" "stats 接口存在且可读"
assert_true "[[ -r '$PROC_CONFIG' ]]" "config 接口存在且可读"
assert_true "[[ -w '$PROC_CONFIG' ]]" "config 接口可写"

# 2.2 读写权限
fw_subsection "接口权限检查"
assert_true "[[ -r '$PROC_BANS' ]]" "bans 接口可读"
assert_true "[[ -w '$PROC_BANS' ]]" "bans 接口可写"
assert_true "[[ -r '$PROC_WHITELIST' ]]" "whitelist 可读"
assert_true "[[ -w '$PROC_WHITELIST' ]]" "whitelist 可写"

# 2.3 空操作测试 - 验证空输入/空白输入被静默忽略（不添加到封禁列表）
fw_subsection "空操作测试"
local_bans_before=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
echo '' > "$PROC_BANS" 2>/dev/null || true
sleep 0.1
local_bans_after_empty=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
assert_eq "$local_bans_before" "$local_bans_after_empty" "空输入被静默忽略，封禁列表不变"

echo '   ' > "$PROC_BANS" 2>/dev/null || true
sleep 0.1
local_bans_after_blank=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
assert_eq "$local_bans_before" "$local_bans_after_blank" "空白输入被静默忽略，封禁列表不变"

# 2.4 统计信息接口
fw_subsection "统计信息接口"
assert_true "[[ -r '$PROC_STATS' ]]" "stats 接口可读"
stats_output=$(cat "$PROC_STATS" 2>&1)
assert_success "cat '$PROC_STATS'" "读取统计信息成功"
assert_contains "$stats_output" "current_bans" "统计信息包含 current_bans"
assert_contains "$stats_output" "current_whitelist" "统计信息包含 current_whitelist"

# 2.5 配置接口
fw_subsection "配置接口"
assert_true "[[ -r '$PROC_CONFIG' ]]" "config 接口可读"
assert_true "[[ -w '$PROC_CONFIG' ]]" "config 接口可写"
config_output=$(cat "$PROC_CONFIG" 2>&1)
assert_success "cat '$PROC_CONFIG'" "读取配置成功"
assert_contains "$config_output" "ban_time" "配置包含 ban_time 字段"

# 清理
fw_ensure_module_unloaded
