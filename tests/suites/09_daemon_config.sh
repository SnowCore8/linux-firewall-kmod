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
assert_file_exists "$CONFIG_DIR/frps.yaml" "frps.yaml 存在"

# 9.3 默认配置目录加载
fw_subsection "默认配置目录加载"
assert_success "cd '$PROJECT_ROOT' && timeout 2 '$DAEMON_PATH' --help > /dev/null 2>&1" "默认配置目录加载"

# 9.4 指定配置目录
fw_subsection "指定配置目录 (-C)"
# 创建临时测试配置目录
local_test_config_dir="/tmp/fw_test_config_$$"
mkdir -p "$local_test_config_dir"
cat > "$local_test_config_dir/test1.yaml" << EOF
max_retries: 7
findtime: 120
ban_time: 300
interval: 2
daemonize: false
metrics_port: 9130
log_files:
  - /var/log/auth.log
regex_patterns:
  sshd: ""
  vsftpd: ""
  nginx: ""
  frp: ""
EOF

assert_success "timeout 2 '$DAEMON_PATH' -C '$local_test_config_dir' --help > /dev/null 2>&1" "指定配置目录加载"
rm -rf "$local_test_config_dir"

# 9.5 单个配置文件加载 (-c)
fw_subsection "单个配置文件加载 (-c)"
assert_success "timeout 2 '$DAEMON_PATH' -c '$CONFIG_DIR/default.yaml' --help > /dev/null 2>&1" "单配置文件加载"

# 9.6 无效配置处理
fw_subsection "无效配置处理"
local_invalid_config="/tmp/fw_test_invalid_$$"
echo "invalid: [yaml: broken" > "$local_invalid_config"
assert_failure "timeout 2 '$DAEMON_PATH' -c '$local_invalid_config' --help > /dev/null 2>&1" "无效 YAML 被拒绝或处理"
rm -f "$local_invalid_config"

# 9.7 不存在的配置 文件
assert_failure "timeout 2 '$DAEMON_PATH' -c '/nonexistent/config.yaml' --help > /dev/null 2>&1" "不存在配置文件被拒绝"
