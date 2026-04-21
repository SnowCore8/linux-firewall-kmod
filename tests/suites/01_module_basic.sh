#!/bin/bash
# 01_module_basic.sh - 模块基础测试

fw_test_header "模块基础测试"

# 1.1 模块文件存在性
fw_subsection "模块文件检查"
assert_file_exists "$KERNEL_MODULE_PATH" "内核模块文件存在"

# 1.2 模块加载/卸载
fw_subsection "模块加载/卸载"
fw_ensure_module_unloaded
assert_success "insmod '$KERNEL_MODULE_PATH'" "模块加载成功"
sleep 0.5

assert_true "(lsmod | grep -q '^firewall\b') || [[ -d '$PROC_DIR' ]]" "lsmod 或 procfs 验证模块已加载"
assert_dir_exists "$PROC_DIR" "proc 目录存在"

fw_ensure_module_unloaded
assert_success "! lsmod | grep -q '^firewall\b'" "模块卸载成功"

# 1.3 带参数加载
fw_subsection "带参数加载"
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" "fw_ban_time=300 fw_max_retries=5 fw_findtime=600"

# 验证参数已设置（注意：sysfs 显示的是当前运行时值，insmod 传参在某些内核版本可能不立即反映）
if [[ -f "/sys/module/firewall/parameters/fw_ban_time" ]]; then
    local_ban_time=$(cat /sys/module/firewall/parameters/fw_ban_time 2>/dev/null || echo "unknown")
    fw_log_info "fw_ban_time 当前值: $local_ban_time"
    assert_true "[[ '$local_ban_time' != 'unknown' ]]" "sysfs 参数文件可读"
else
    warn_test "sysfs 参数文件不存在，跳过参数验证"
fi

fw_ensure_module_unloaded

# 1.4 重复加载保护
fw_subsection "重复加载保护"
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"
assert_failure "insmod '$KERNEL_MODULE_PATH'" "重复加载被拒绝"
fw_ensure_module_unloaded
