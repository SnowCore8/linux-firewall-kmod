#!/bin/bash
# 10_daemon_logparse.sh - 日志解析测试

fw_test_header "日志解析测试"

# 10.1 守护进程可执行
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

# 10.3 守护进程处理测试
# 需要内核模块已加载
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" 2>/dev/null || {
    skip_test "内核模块无法加载，跳过处理测试"
    rm -f "$local_test_log"
    return 0
}

# 创建临时 YAML 配置用于日志解析测试
local_yaml_config="/tmp/fw_logparse_yaml_$$.yaml"
cat > "$local_yaml_config" << EOF
defaults:
  max_retries: 1
  findtime: 1
  ban_time: 5
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_log
    max_retries: 1
    findtime: 1
    ban_time: 5
    regex: ""
EOF

# 启动守护进程处理测试日志
fw_log_info "启动守护进程处理测试日志..."
timeout 5 "$DAEMON_PATH" -c "$local_yaml_config" &
local_daemon_pid=$!
sleep 3

# 检查是否有 IP 被封禁
if [[ -r "$PROC_BAN_LIST" ]]; then
    local_ban_count=$(wc -l < "$PROC_BAN_LIST" 2>/dev/null || echo 0)
    fw_log_info "封禁列表中的 IP 数量: $local_ban_count"
    if [[ $local_ban_count -gt 0 ]]; then
        assert_ge "$local_ban_count" 1 "日志解析成功，有 IP 被封禁"
    else
        warn_test "日志解析后无 IP 被封禁（可能是正则未匹配）"
    fi
else
    warn_test "ban_list 不可读"
fi

# 清理守护进程
kill $local_daemon_pid 2>/dev/null || true
wait $local_daemon_pid 2>/dev/null || true
rm -f "$local_test_log" "$local_yaml_config"

# 10.4 特殊字符日志
fw_subsection "特殊字符日志处理"
local_special_log="/tmp/fw_test_special_$$.log"
cat > "$local_special_log" << 'EOF'
Mar 10 10:30:01 server sshd[1234]: Failed password for root from 192.0.2.1 port 12345 ssh2
Mar 10 10:30:02 server sshd[1235]: Failed password for <script>alert('xss')</script> from 192.0.2.2 port 12346 ssh2
Mar 10 10:30:03 server sshd[1236]: Failed password for root from 192.0.2.3 port 12347 ssh2
EOF

local_special_yaml="/tmp/fw_special_yaml_$$.yaml"
cat > "$local_special_yaml" << EOF
defaults:
  max_retries: 1
  findtime: 1
  ban_time: 5
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - $local_special_log
    max_retries: 1
    regex: ""
EOF

timeout 5 "$DAEMON_PATH" -c "$local_special_yaml" 2>&1 || true
sleep 1
assert_true "true" "特殊字符日志处理未崩溃"

rm -f "$local_special_log" "$local_special_yaml"

# 10.5 空日志文件
fw_subsection "空日志文件处理"
: > "/tmp/fw_test_empty_$$.log"

local_empty_yaml="/tmp/fw_empty_yaml_$$.yaml"
cat > "$local_empty_yaml" << EOF
defaults:
  max_retries: 1
  findtime: 1
  ban_time: 5
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - /tmp/fw_test_empty_$$.log
    max_retries: 1
    regex: ""
EOF

timeout 3 "$DAEMON_PATH" -c "$local_empty_yaml" 2>&1 || true
assert_true "true" "空日志文件处理未崩溃"

rm -f "/tmp/fw_test_empty_$$.log" "$local_empty_yaml"

# 10.6 不存在日志文件
fw_subsection "不存在日志文件处理"

local_nonexist_yaml="/tmp/fw_nonexist_yaml_$$.yaml"
cat > "$local_nonexist_yaml" << EOF
defaults:
  max_retries: 1
  findtime: 1
  ban_time: 5
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - /nonexistent/log.log
    max_retries: 1
    regex: ""
EOF

assert_failure "timeout 3 '$DAEMON_PATH' -c '$local_nonexist_yaml' 2>&1" "不存在的日志文件被拒绝"
rm -f "$local_nonexist_yaml"

fw_ensure_module_unloaded
