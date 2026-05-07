#!/bin/bash
# 02_procfs_interface.sh - Procfs 接口测试

fw_test_header "Procfs 接口测试"

# 2.1 接口存在性与权限
fw_subsection "接口文件存在性与权限"
assert_dir_exists "$PROC_DIR" "proc/firewall 目录存在"
assert_true "[[ -r '$PROC_BANS' && -w '$PROC_BANS' ]]" "bans 接口存在且可读写"
assert_true "[[ -r '$PROC_WHITELIST' && -w '$PROC_WHITELIST' ]]" "whitelist 接口存在且可读写"
assert_true "[[ -r '$PROC_STATS' ]]" "stats 接口存在且可读"
assert_true "[[ -r '$PROC_CONFIG' && -w '$PROC_CONFIG' ]]" "config 接口存在且可读写"

# 2.2 空操作测试
fw_subsection "空操作测试"
local_bans_before=$(fw_count_bans)
echo '' > "$PROC_BANS" 2>/dev/null || true
fw_wait_procfs
fw_assert_list_unchanged "$PROC_BANS" "$local_bans_before" "空输入被静默忽略"

echo '   ' > "$PROC_BANS" 2>/dev/null || true
fw_wait_procfs
fw_assert_list_unchanged "$PROC_BANS" "$local_bans_before" "空白输入被静默忽略"

# 2.3 统计信息接口
fw_subsection "统计信息接口"
stats_output=$(cat "$PROC_STATS" 2>&1)
assert_success "cat '$PROC_STATS'" "读取统计信息成功"
assert_contains "$stats_output" "current_bans" "统计信息包含 current_bans"
assert_contains "$stats_output" "current_whitelist" "统计信息包含 current_whitelist"

# 2.4 配置接口
fw_subsection "配置接口"
config_output=$(cat "$PROC_CONFIG" 2>&1)
assert_success "cat '$PROC_CONFIG'" "读取配置成功"
assert_contains "$config_output" "ban_time" "配置包含 ban_time 字段"
