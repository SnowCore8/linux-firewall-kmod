#!/bin/bash
# 09_daemon_config.sh - 守护进程配置测试（YAML）

fw_test_header "守护进程配置测试"

# 9.1 守护进程可执行
fw_subsection "守护进程检查"
assert_file_exists "$DAEMON_PATH" "守护进程可执行文件存在"
assert_success "'$DAEMON_PATH' --help > /dev/null 2>&1" "--help 正常"

# 9.2 YAML 配置文件存在性
fw_subsection "YAML 配置文件检查"
assert_dir_exists "$CONFIG_DIR" "config/ 目录存在"
assert_file_exists "$CONFIG_DIR/default.yaml" "default.yaml 存在"

# 9.3 默认配置目录加载
fw_subsection "默认配置目录加载"
# 显式指定项目配置目录（而非依赖 /etc/firewall）
assert_success "timeout --signal=KILL 2 '$DAEMON_PATH' -C '$CONFIG_DIR' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ] || [ \$rc -eq 137 ]" "默认配置目录加载"

# 9.4 指定配置目录
fw_subsection "指定配置目录 (-C)"
# 创建临时测试配置目录
local_test_config_dir="/tmp/fw_test_config_$$"
mkdir -p "$local_test_config_dir"
cat > "$local_test_config_dir/test1.yaml" << 'EOF'
defaults:
  max_retries: 7
  findtime: 120
  ban_time: 300
  interval: 2
  metrics_port: 9130

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retries: 7
    regex: ""
EOF

assert_success "timeout --signal=KILL 2 '$DAEMON_PATH' -C '$local_test_config_dir' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ] || [ \$rc -eq 137 ]" "指定配置目录加载"
rm -rf "$local_test_config_dir"

# 9.5 单个配置文件加载 (-c)
fw_subsection "单个配置文件加载 (-c)"
assert_success "timeout --signal=KILL 2 '$DAEMON_PATH' -c '$CONFIG_DIR/default.yaml' >/dev/null 2>&1; rc=\$?; [ \$rc -eq 0 ] || [ \$rc -eq 124 ] || [ \$rc -eq 137 ]" "单配置文件加载"

# 9.6 无效配置处理
fw_subsection "无效配置处理"
local_invalid_config="/tmp/fw_test_invalid_$$"
echo "invalid: [yaml: broken" > "$local_invalid_config"
# 无效 YAML 应被解析器拒绝，不应崩溃 (segfault=139, abort=134)
local rc=0
timeout --signal=KILL 2 "$DAEMON_PATH" -c "$local_invalid_config" >/dev/null 2>&1 || rc=$?
# rc=1 (config error) or rc=124 (timeout) or rc=137 (killed) are expected; rc>=128 indicates signal crash
assert_true "[[ $rc -lt 128 || $rc -eq 137 ]]" "无效 YAML 处理完成（未崩溃，退出码=$rc）"
rm -f "$local_invalid_config"

# 9.7 不存在的配置文件
local rc=0
timeout --signal=KILL 2 "$DAEMON_PATH" -c '/nonexistent/config.yaml' >/dev/null 2>&1 || rc=$?
# rc 应为 1（配置错误），不应为 0（成功）或 124（超时）或 137（被杀）
if [[ $rc -ne 0 && $rc -ne 124 && $rc -ne 137 ]]; then
    fw_pass "不存在配置文件被拒绝（退出码=$rc）"
else
    fw_fail "不存在配置文件被拒绝（退出码=$rc，预期非0且非124/137）"
fi
