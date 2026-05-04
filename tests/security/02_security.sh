#!/bin/bash
# 06_security.sh - 安全测试（注入、溢出、权限等）

fw_test_header "安全测试"

# 6.1 命令注入防护
fw_subsection "命令注入防护"
assert_inject_blocked "echo '8.8.8.8; touch /tmp/fw_pwned' > '$PROC_BANS' 2>&1" "分号注入被拒绝"
assert_true "! [[ -f /tmp/fw_pwned ]]" "命令注入未执行"
rm -f /tmp/fw_pwned

# 6.2 procfs 只读/只写检查
fw_subsection "procfs 权限检查"
assert_true "[[ -r '$PROC_BANS' ]]" "bans 接口可读"
assert_true "[[ -w '$PROC_BANS' ]]" "bans 接口可写"
assert_true "[[ -r '$PROC_WHITELIST' ]]" "whitelist 只读正常"
assert_true "[[ -w '$PROC_WHITELIST' ]]" "whitelist 可写正常"

# 尝试截断 bans 文件 - procfs 虚拟文件不受 shell 截断影响
local_bans_before=$(cat "$PROC_BANS" 2>/dev/null)
: > "$PROC_BANS" 2>/dev/null || true
sleep 0.1
local_bans_after=$(cat "$PROC_BANS" 2>/dev/null)
assert_eq "$local_bans_before" "$local_bans_after" "procfs bans 文件不受 shell 截断影响（内核状态不变）"

# 6.3 模块参数安全
fw_subsection "模块参数安全"

# 零值参数
assert_failure "insmod '$KERNEL_MODULE_PATH' fw_ban_time=0 2>/dev/null" "拒绝零值参数"

# 负数参数
assert_failure "insmod '$KERNEL_MODULE_PATH' fw_ban_time=-1 2>/dev/null" "拒绝负数参数"

# 大数值参数
if [[ -f "/sys/module/firewall/parameters/fw_ban_time" ]]; then
    local_bt=$(cat /sys/module/firewall/parameters/fw_ban_time 2>/dev/null || echo "unknown")
    assert_eq "$local_bt" "86400" "大参数值加载正确"
else
    warn_test "sysfs 参数文件不可读"
fi
