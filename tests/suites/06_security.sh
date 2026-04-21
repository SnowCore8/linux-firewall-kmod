#!/bin/bash
# 06_security.sh - 安全测试（注入、溢出、权限等）

fw_test_header "安全测试"

fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 6.1 命令注入防护
fw_subsection "命令注入防护"
assert_failure "echo '8.8.8.8; touch /tmp/fw_pwned' > '$PROC_ADD_BAN' 2>&1" "分号注入被拒绝"
assert_true "! [[ -f /tmp/fw_pwned ]]" "命令注入未执行"
rm -f /tmp/fw_pwned

# 6.2 procfs 只读/只写检查
fw_subsection "procfs 权限检查"
assert_true "[[ -r '$PROC_BAN_LIST' ]]" "ban_list 只读正常"
assert_true "[[ -r '$PROC_WHITELIST' ]]" "whitelist 只读正常"
assert_true "[[ -w '$PROC_ADD_BAN' ]]" "add_ban 只写正常"

# 尝试截断只读文件（应被拒绝或无影响）
assert_success ": > '$PROC_BAN_LIST' 2>&1" "截断 ban_list 操作完成（内核处理）"

# 6.3 模块参数安全
fw_subsection "模块参数安全"
fw_ensure_module_unloaded

# 零值参数
assert_failure "insmod '$KERNEL_MODULE_PATH' fw_ban_time=0 2>/dev/null" "拒绝零值参数"

# 负数参数
assert_failure "insmod '$KERNEL_MODULE_PATH' fw_ban_time=-1 2>/dev/null" "拒绝负数参数"

# 大数值参数
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" "fw_ban_time=86400"
if [[ -f "/sys/module/firewall/parameters/fw_ban_time" ]]; then
    local_bt=$(cat /sys/module/firewall/parameters/fw_ban_time 2>/dev/null || echo "unknown")
    assert_eq "$local_bt" "86400" "大参数值加载正确"
else
    warn_test "sysfs 参数文件不可读"
fi

fw_ensure_module_unloaded
