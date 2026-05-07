#!/bin/bash
# 09_daemon_config.sh - 守护进程配置测试（YAML）

fw_test_header "守护进程配置测试"

# 9.1 守护进程检查
fw_subsection "守护进程检查"
assert_file_exists "$DAEMON_PATH" "守护进程可执行文件存在"
assert_success "'$DAEMON_PATH' --help > /dev/null 2>&1" "--help 正常"

# 9.2 YAML 配置文件存在性
fw_subsection "YAML 配置文件检查"
assert_dir_exists "$CONFIG_DIR" "config/ 目录存在"
assert_file_exists "$CONFIG_DIR/default.yaml" "default.yaml 存在"

# 9.3 默认配置目录加载
fw_subsection "默认配置目录加载"
fw_daemon_starts_ok "'$DAEMON_PATH' -C '$CONFIG_DIR'" "默认配置目录加载"

# 9.4 指定配置目录 (-C)
fw_subsection "指定配置目录 (-C)"
local_test_config_dir="/tmp/fw_test_config_$$"
mkdir -p "$local_test_config_dir"
fw_generate_test_yaml "$local_test_config_dir/test1.yaml" "/var/log/auth.log" 7 120 300 9130
fw_daemon_starts_ok "'$DAEMON_PATH' -C '$local_test_config_dir'" "指定配置目录加载"
rm -rf "$local_test_config_dir"

# 9.5 单个配置文件加载 (-c)
fw_subsection "单个配置文件加载 (-c)"
fw_daemon_starts_ok "'$DAEMON_PATH' -c '$CONFIG_DIR/default.yaml'" "单配置文件加载"

# 9.6 无效配置处理
fw_subsection "无效配置处理"
local_invalid_config="/tmp/fw_test_invalid_$$"
echo "invalid: [yaml: broken" > "$local_invalid_config"
local rc=0
timeout --signal=KILL 2 "$DAEMON_PATH" -c "$local_invalid_config" >/dev/null 2>&1 || rc=$?
assert_true "[[ $rc -lt 128 || $rc -eq 137 ]]" "无效 YAML 处理完成（未崩溃，退出码=$rc）"
rm -f "$local_invalid_config"

# 9.7 不存在的配置文件
fw_subsection "不存在的配置文件"
local rc=0
timeout --signal=KILL 2 "$DAEMON_PATH" -c '/nonexistent/config.yaml' >/dev/null 2>&1 || rc=$?
if [[ $rc -ne 0 && $rc -ne 124 && $rc -ne 137 ]]; then
    fw_pass "不存在配置文件被拒绝（退出码=$rc）"
else
    fw_fail "不存在配置文件被拒绝（退出码=$rc，预期非0且非124/137）"
fi
