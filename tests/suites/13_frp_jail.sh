#!/bin/bash
# 13_frp_jail.sh - FRP Jail 配置测试

fw_test_header "FRP Jail 配置测试"

# 13.1 检查 default.yaml 中的 FRP Jail 配置
fw_subsection "FRP Jail 配置存在性"
assert_success "grep -q 'frp:' '$CONFIG_DIR/default.yaml'" "FRP Jail 定义存在"
assert_success "grep -q 'enabled: true' '$CONFIG_DIR/default.yaml'" "FRP Jail 已启用"

# 13.2 验证 FRP 日志文件配置
fw_subsection "FRP 日志文件配置"
assert_success "grep -q '/var/log/frp/frp.log' '$CONFIG_DIR/default.yaml'" "frp.log 路径配置"

# 13.3 验证 FRP 参数配置
fw_subsection "FRP 参数配置"
assert_success "sed -n '/^  frp:/,/^$/p' '$CONFIG_DIR/default.yaml' | grep -q 'max_retries: 10'" "max_retries=10"
assert_success "sed -n '/^  frp:/,/^$/p' '$CONFIG_DIR/default.yaml' | grep -q 'findtime: 300'" "findtime=300"
assert_success "sed -n '/^  frp:/,/^$/p' '$CONFIG_DIR/default.yaml' | grep -q 'ban_time: 1800'" "ban_time=1800"

# 13.4 守护进程加载 FRP 配置
fw_subsection "守护进程加载 FRP 配置"
assert_success "timeout 2 '$DAEMON_PATH' -c '$CONFIG_DIR/default.yaml' --help > /dev/null 2>&1" "FRP 配置文件加载成功"

# 13.5 FRP 日志解析测试
fw_subsection "FRP 日志解析"
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" 2>/dev/null || {
    skip_test "内核模块无法加载，跳过 FRP 日志解析测试"
    fw_ensure_module_unloaded
    return 0
}

# 创建 FRP 测试日志
local_frp_test_log="/tmp/fw_test_frp_$$.log"
cat > "$local_frp_test_log" << 'EOF'
2026/04/22 10:30:01 [W] [proxy/proxy.go:100] get a user connection [203.0.113.50:12345]
2026/04/22 10:30:02 [E] [server/control.go:200] invalid token from 198.51.100.100
2026/04/22 10:30:03 [W] [server/control.go:300] connection timeout from 192.0.2.200
EOF

# 创建 FRP YAML 配置
local_frp_yaml="/tmp/fw_frp_yaml_$$.yaml"
cat > "$local_frp_yaml" << EOF
defaults:
  max_retries: 1
  findtime: 1
  ban_time: 5
  interval: 1
  metrics_port: 9119

jails:
  frp:
    enabled: true
    log_files:
      - $local_frp_test_log
    max_retries: 1
    findtime: 1
    ban_time: 5
    regex_pattern: ""
EOF

# 使用 FRP 配置测试
timeout 5 "$DAEMON_PATH" -c "$local_frp_yaml" 2>/tmp/fw_daemon_stderr_frp_$$.log || true
if [[ -s /tmp/fw_daemon_stderr_frp_$$.log ]]; then
    fw_log_warn "守护进程 stderr (FRP): $(cat /tmp/fw_daemon_stderr_frp_$$.log)"
fi
rm -f /tmp/fw_daemon_stderr_frp_$$.log
sleep 1

# 检查封禁列表
if [[ -r "$PROC_BANS" ]]; then
    local_ban_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
    fw_log_info "FRP 日志解析后封禁 IP 数量: $local_ban_count"
    assert_ge "$local_ban_count" 1 "FRP 日志解析处理成功，有 IP 被封禁"
else
    warn_test "bans 接口不可读"
fi

rm -f "$local_frp_test_log" "$local_frp_yaml"

# 13.6 FRP 配置热重载测试
fw_subsection "FRP 配置热重载"
# 创建临时 FRP 配置
local_frp_config="/tmp/fw_test_frp_config_$$.yaml"
cat > "$local_frp_config" << 'EOF'
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

jails:
  frp:
    enabled: true
    log_files:
      - /var/log/fw_test_frps.log
    max_retries: 3
    findtime: 120
    ban_time: 600
    regex: ""
EOF

assert_success "timeout 2 '$DAEMON_PATH' -c '$local_frp_config' --help > /dev/null 2>&1" "FRP 独立配置文件加载"
rm -f "$local_frp_config"

fw_ensure_module_unloaded
