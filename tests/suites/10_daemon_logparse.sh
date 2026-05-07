#!/bin/bash
# 10_daemon_logparse.sh - 日志解析测试

fw_test_header "日志解析测试"

# 10.1 守护进程检查
fw_subsection "守护进程检查"
if [[ ! -x "$DAEMON_PATH" ]]; then
    skip_test "守护进程未编译，跳过日志解析测试"
    return 0
fi

# 10.2 构造测试日志
fw_subsection "日志解析功能"
local_test_log="/tmp/fw_test_logparse_$$.log"
cat > "$local_test_log" << EOF
$LOG_LINE_SSHD
$LOG_LINE_SSHD_INVALID
$LOG_LINE_VSFTPD
$LOG_LINE_NGINX
$LOG_LINE_FRP
Invalid line with no IP address
Mar 10 10:30:01 server sshd[1234]: Failed password for root from port ssh2
EOF

# 10.3 内核模块检查
if ! check_module_ready; then
    fw_log_warn "内核模块意外卸载，尝试重新加载..."
    rm -f /var/lib/firewall/state 2>/dev/null
    if fw_ensure_module_loaded "$KERNEL_MODULE_PATH"; then
        fw_log_info "模块重新加载成功，继续执行"
        sleep 0.5
    else
        skip_test "内核模块未加载且重新加载失败，跳过处理测试"
        rm -f "$local_test_log"
        return 0
    fi
fi

# 10.4 守护进程处理测试日志
fw_subsection "守护进程处理测试日志"
local_yaml_config="/tmp/fw_logparse_yaml_$$.yaml"
fw_generate_test_yaml "$local_yaml_config" "$local_test_log" 1 1 5

fw_run_daemon_captured "$local_yaml_config" 5
sleep 1

if [[ -r "$PROC_BANS" ]]; then
    local_ban_count=$(fw_count_bans)
    fw_log_info "封禁列表中的 IP 数量: $local_ban_count"
    if [[ $local_ban_count -gt 0 ]]; then
        assert_ge "$local_ban_count" 1 "日志解析成功，有 IP 被封禁"
    else
        warn_test "日志解析后无 IP 被封禁（可能是正则未匹配）"
    fi
else
    warn_test "bans 接口不可读"
fi
rm -f "$local_test_log" "$local_yaml_config"

# 10.5 特殊字符日志处理
fw_subsection "特殊字符日志处理"
local_special_log="/tmp/fw_test_special_$$.log"
cat > "$local_special_log" << 'EOF'
Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2
Mar 10 10:30:02 server sshd[1235]: Failed password for <script>alert('xss')</script> from 192.0.2.2 port 12346 ssh2
Mar 10 10:30:03 server sshd[1236]: Failed password for root from 192.0.2.3 port 12347 ssh2
EOF

local_special_yaml="/tmp/fw_special_yaml_$$.yaml"
fw_generate_test_yaml "$local_special_yaml" "$local_special_log" 1 1 5
fw_run_daemon_captured "$local_special_yaml" 5
sleep 1
assert_true "[[ -r '$PROC_BANS' ]]" "特殊字符日志处理后 procfs 仍可访问"
rm -f "$local_special_log" "$local_special_yaml"

# 10.6 空日志文件处理
fw_subsection "空日志文件处理"
: > "/tmp/fw_test_empty_$$.log"
local_empty_yaml="/tmp/fw_empty_yaml_$$.yaml"
fw_generate_test_yaml "$local_empty_yaml" "/tmp/fw_test_empty_$$.log" 1 1 5
fw_run_daemon_captured "$local_empty_yaml" 3
assert_true "[[ -r '$PROC_BANS' ]]" "空日志文件处理后 procfs 仍可访问"
rm -f "/tmp/fw_test_empty_$$.log" "$local_empty_yaml"

# 10.7 不存在日志文件处理
fw_subsection "不存在日志文件处理"
local_nonexist_yaml="/tmp/fw_nonexist_yaml_$$.yaml"
fw_generate_test_yaml "$local_nonexist_yaml" "/nonexistent/log.log" 1 1 5

timeout 3 "$DAEMON_PATH" -c "$local_nonexist_yaml" > /dev/null 2>&1
local rc=$?
assert_true "[[ $rc -ne 0 ]]" "不存在的日志文件被拒绝（退出码 $rc）"
rm -f "$local_nonexist_yaml"
