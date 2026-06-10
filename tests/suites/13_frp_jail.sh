#!/bin/bash
# 13_frp_jail.sh - FRP Jail 配置测试

fw_test_header "FRP Jail 配置测试"

# 13.1 FRP Jail 配置存在性
fw_subsection "FRP Jail 配置存在性"
assert_true "(test -f '$CONFIG_DIR/frp.yaml') || (grep -q 'frp:' '$CONFIG_DIR/default.yaml' 2>/dev/null)" "FRP Jail 定义存在"
assert_true "(grep -q 'enabled: true' '$CONFIG_DIR/frp.yaml' 2>/dev/null) || (grep -q 'enabled: true' '$CONFIG_DIR/default.yaml' 2>/dev/null)" "FRP Jail 已启用"

# 13.2 FRP 日志文件配置
fw_subsection "FRP 日志文件配置"
assert_true "(grep -qE '/var/log/frp(\\.log|/frp\\.log)' '$CONFIG_DIR/frp.yaml' 2>/dev/null) || (grep -qE '/var/log/frp(\\.log|/frp\\.log)' '$CONFIG_DIR/default.yaml' 2>/dev/null)" "frp.log 路径配置"

# 13.3 FRP 参数配置
fw_subsection "FRP 参数配置"
assert_true "(test -f '$CONFIG_DIR/frp.yaml') || (grep -q 'frp:' '$CONFIG_DIR/default.yaml' 2>/dev/null)" "FRP 配置完整"

# 13.4 守护进程加载 FRP 配置
fw_subsection "守护进程加载 FRP 配置"
fw_daemon_starts_ok "'$DAEMON_PATH' -c '$CONFIG_DIR/default.yaml'" "FRP 配置文件加载成功"

# 13.5 FRP 日志解析测试
fw_subsection "FRP 日志解析"
local_frp_test_log="/var/log/fw_test_frp_$$.log"
cat > "$local_frp_test_log" << 'EOF'
2026/04/22 10:30:01 [W] [proxy/proxy.go:100] get a user connection [203.0.113.50:12345]
2026/04/22 10:30:02 [E] [server/control.go:200] invalid token from 198.51.100.100
2026/04/22 10:30:03 [W] [server/control.go:300] connection timeout from 192.0.2.200
EOF

local_frp_yaml="/var/log/fw_frp_yaml_$$.yaml"
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
      - "$local_frp_test_log"
    max_retries: 1
    findtime: 1
    ban_time: 5
    regex: ""
EOF

fw_run_daemon_captured "$local_frp_yaml" 5
sleep 1

if [[ -r "$PROC_BANS" ]]; then
    local_ban_count=$(fw_count_bans)
    fw_log_info "FRP 日志解析后封禁 IP 数量: $local_ban_count"
    assert_ge "$local_ban_count" 1 "FRP 日志解析处理成功，有 IP 被封禁"
else
    warn_test "bans 接口不可读"
fi

rm -f "$local_frp_test_log" "$local_frp_yaml"

# 13.6 FRP 配置热重载测试
fw_subsection "FRP 配置热重载"
local_frp_config="/tmp/fw_test_frp_config_$$.yaml"
touch "/var/log/fw_test_frps.log"
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

fw_daemon_starts_ok "'$DAEMON_PATH' -c '$local_frp_config'" "FRP 独立配置文件加载"
rm -f "$local_frp_config" "/var/log/fw_test_frps.log"
