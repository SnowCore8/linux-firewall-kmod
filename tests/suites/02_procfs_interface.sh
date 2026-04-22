#!/bin/bash
# 02_procfs_interface.sh - Procfs 接口测试

fw_test_header "Procfs 接口测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 2.1 接口存在性
fw_subsection "接口文件存在性"
assert_dir_exists "$PROC_DIR" "proc/firewall 目录存在"
assert_file_exists "$PROC_ADD_BAN" "add_ban 接口存在"
assert_file_exists "$PROC_REMOVE_BAN" "remove_ban 接口存在"
assert_file_exists "$PROC_BAN_LIST" "ban_list 接口存在"
assert_file_exists "$PROC_WHITELIST" "whitelist 接口存在"
assert_file_exists "$PROC_WHITELIST_ADD" "whitelist_add 接口存在"
assert_file_exists "$PROC_WHITELIST_REMOVE" "whitelist_remove 接口存在"
assert_file_exists "$PROC_PERMANENT_ADD_BAN" "permanent_add_ban 接口存在"
assert_file_exists "$PROC_PERMANENT_REMOVE_BAN" "permanent_remove_ban 接口存在"
assert_file_exists "$PROC_STATS" "stats 接口存在"

# 2.2 读写权限
fw_subsection "接口权限检查"
assert_true "[[ -r '$PROC_BAN_LIST' ]]" "ban_list 可读"
assert_true "[[ -w '$PROC_ADD_BAN' ]]" "add_ban 可写"
assert_true "[[ -w '$PROC_REMOVE_BAN' ]]" "remove_ban 可写"
assert_true "[[ -r '$PROC_WHITELIST' ]]" "whitelist 可读"
assert_true "[[ -w '$PROC_WHITELIST_ADD' ]]" "whitelist_add 可写"
assert_true "[[ -w '$PROC_WHITELIST_REMOVE' ]]" "whitelist_remove 可写"

# 2.3 空操作测试
fw_subsection "空操作测试"
assert_failure "echo '' > '$PROC_ADD_BAN' 2>&1" "空输入被封禁接口拒绝"
assert_failure "echo '   ' > '$PROC_ADD_BAN' 2>&1" "空白输入被封禁接口拒绝"

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
