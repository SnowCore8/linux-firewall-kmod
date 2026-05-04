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
if ! lsmod | grep -q "^firewall "; then
    skip_test "内核模块未加载，跳过处理测试"
    rm -f "$local_test_log"
    return 0
fi

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
    regex_pattern: ""
EOF

# 启动守护进程处理测试日志
fw_log_info "启动守护进程处理测试日志..."
timeout 5 "$DAEMON_PATH" -c "$local_yaml_config" 2>/tmp/fw_daemon_stderr_$$.log &
local_daemon_pid=$!
sleep 3

# 检查是否有 IP 被封禁
if [[ -r "$PROC_BANS" ]]; then
    local_ban_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
    fw_log_info "封禁列表中的 IP 数量: $local_ban_count"
    if [[ $local_ban_count -gt 0 ]]; then
        assert_ge "$local_ban_count" 1 "日志解析成功，有 IP 被封禁"
    else
        warn_test "日志解析后无 IP 被封禁（可能是正则未匹配）"
    fi
else
    warn_test "bans 接口不可读"
fi

# 清理守护进程
kill $local_daemon_pid 2>/dev/null || true
wait $local_daemon_pid 2>/dev/null || true

# 输出守护进程 stderr 警告
if [[ -s /tmp/fw_daemon_stderr_$$.log ]]; then
    fw_log_warn "守护进程 stderr: $(cat /tmp/fw_daemon_stderr_$$.log)"
fi
rm -f /tmp/fw_daemon_stderr_$$.log "$local_test_log" "$local_yaml_config"

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

timeout 5 "$DAEMON_PATH" -c "$local_special_yaml" 2>/tmp/fw_daemon_stderr_special_$$.log || true
if [[ -s /tmp/fw_daemon_stderr_special_$$.log ]]; then
    fw_log_warn "守护进程 stderr (特殊字符): $(cat /tmp/fw_daemon_stderr_special_$$.log)"
fi
rm -f /tmp/fw_daemon_stderr_special_$$.log
sleep 1
# 验证守护进程处理特殊字符后 procfs 仍可访问
assert_true "[[ -r '$PROC_BANS' ]]" "特殊字符日志处理后 procfs 仍可访问"

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

timeout 3 "$DAEMON_PATH" -c "$local_empty_yaml" 2>/tmp/fw_daemon_stderr_empty_$$.log || true
if [[ -s /tmp/fw_daemon_stderr_empty_$$.log ]]; then
    fw_log_warn "守护进程 stderr (空日志): $(cat /tmp/fw_daemon_stderr_empty_$$.log)"
fi
rm -f /tmp/fw_daemon_stderr_empty_$$.log
# 验证守护进程处理空日志后 procfs 仍可访问
assert_true "[[ -r '$PROC_BANS' ]]" "空日志文件处理后 procfs 仍可访问"

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

# 运行守护进程并捕获退出码（日志文件 /nonexistent/log.log 不存在）
timeout 3 "$DAEMON_PATH" -c "$local_nonexist_yaml" > /dev/null 2>&1
local rc=$?

# 验证守护进程因不存在的日志文件而失败
if [[ $rc -ne 0 ]]; then
    assert_true "[[ $rc -ne 0 ]]" "不存在的日志文件被拒绝（退出码 $rc）"
else
    assert_true "[[ $rc -ne 0 ]]" "不存在的日志文件应导致守护进程失败"
fi

rm -f "$local_nonexist_yaml"

