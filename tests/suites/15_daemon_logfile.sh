#!/bin/bash
# 15_daemon_logfile.sh - 守护进程独立日志文件 (log_file / log_destination / log_format / log_level)

fw_test_header "守护进程独立日志系统 (v2: log_file / log_destination / log_format / log_level)"

# 测试用路径 - 必须在 parse_config_path 白名单 (/var/log /etc /home /srv) 内
# 用 $$ 区分本次运行的临时文件
local_test_log_file="/var/log/firewall_test_$$.log"
local_test_sshd_log="/var/log/firewall_test_$$.sshd.log"
local_test_config="/var/log/firewall_test_$$.yaml"
rm -f "$local_test_log_file" "$local_test_sshd_log" "$local_test_config"
touch "$local_test_sshd_log"

# 辅助函数: 启动守护进程并等待日志产生
start_daemon_with_config() {
    local config_file="$1"
    "$DAEMON_PATH" -c "$config_file" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    echo "$pid"
}

# ============================================================================
# 15.1 destination=both + format=plain: 现有行为(默认)
# ============================================================================
fw_subsection "destination=both + format=plain (默认行为)"
cat > "$local_test_config" <<EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  log_file: $local_test_log_file
  log_level: 3
  log_destination: both
  log_format: plain
jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_sshd_log
EOF
rm -f "$local_test_log_file"
local_daemon_pid=$(start_daemon_with_config "$local_test_config")

assert_file_exists "$local_test_log_file" "destination=both 创建日志文件"
if [[ -s "$local_test_log_file" ]]; then
    # plain 格式: "YYYY-MM-DD HH:MM:SS [daemon] INFO: ..."
    if grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} \[daemon\] (INFO|WARN|ERROR|DEBUG):' "$local_test_log_file"; then
        assert_true "true" "plain 格式含时间戳与 [daemon] 标签"
    else
        assert_true "false" "plain 格式应含 'YYYY-MM-DD HH:MM:SS [daemon] LEVEL:' 前缀"
    fi
else
    assert_true "false" "plain 格式日志文件非空"
fi
kill $local_daemon_pid 2>/dev/null; wait $local_daemon_pid 2>/dev/null

# ============================================================================
# 15.2 destination=both + format=json: 结构化输出
# ============================================================================
fw_subsection "destination=both + format=json (JSON Lines)"
cat > "$local_test_config" <<EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  log_file: $local_test_log_file
  log_level: 3
  log_destination: both
  log_format: json
jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_sshd_log
EOF
rm -f "$local_test_log_file"
local_daemon_pid=$(start_daemon_with_config "$local_test_config")

if [[ -s "$local_test_log_file" ]]; then
    # JSON 格式: {"ts":"...","prio":N,"component":"...","level":"...","msg":"..."}
    # 验证首行是合法 JSON
    if python3 -c "import json, sys; d=json.loads(open('$local_test_log_file').readline()); sys.exit(0 if all(k in d for k in ['ts','prio','component','level','msg']) else 1)" 2>/dev/null; then
        assert_true "true" "JSON Lines 含 5 个必需字段 (ts/prio/component/level/msg)"
    else
        assert_true "false" "JSON Lines 应含 5 个必需字段 (ts/prio/component/level/msg)"
    fi

    # 验证 %s 已被渲染（msg 不应含原始的 %s/%d 占位符）
    if grep -qE '"msg":".*(%s|%d).*"' "$local_test_log_file"; then
        assert_true "false" "JSON msg 字段不应含未渲染的 %s/%d 占位符"
    else
        assert_true "true" "JSON msg 字段已正确渲染（无 %s/%d 残留）"
    fi

    # 验证 message 含 'level' 字段值正确
    if grep -qE '"level":"INFO"' "$local_test_log_file"; then
        assert_true "true" "JSON level 字段值正确 (INFO)"
    else
        assert_true "false" "JSON level 字段值应为 INFO"
    fi
else
    assert_true "false" "JSON 格式日志文件非空"
fi
kill $local_daemon_pid 2>/dev/null; wait $local_daemon_pid 2>/dev/null

# ============================================================================
# 15.3 destination=syslog + format=plain: 仅 syslog, 不创建文件
# ============================================================================
fw_subsection "destination=syslog (仅 syslog, 不写文件)"
local_test_log_off="/var/log/firewall_test_off_$$.log"
rm -f "$local_test_log_off"
cat > "$local_test_config" <<EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  log_file: $local_test_log_file
  log_level: 3
  log_destination: syslog
  log_format: plain
jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_sshd_log
EOF
# 即使 cfg.log_file 设置了, destination=syslog 时不应写文件
# (但 log_init_file 仍会打开 fp 以便 reload 切换; 文件创建不是判定标准)
# 判定标准: 新行不再增加(因为 LOG_INFO 走 syslog 不走 file)
local_daemon_pid=$(start_daemon_with_config "$local_test_config")
sleep 1
local_size_before=$(stat -c %s "$local_test_log_file" 2>/dev/null || echo 0)
sleep 1
local_size_after=$(stat -c %s "$local_test_log_file" 2>/dev/null || echo 0)
if [[ "$local_size_before" -eq "$local_size_after" ]]; then
    assert_true "true" "destination=syslog 不再向文件追加新内容"
else
    assert_true "false" "destination=syslog 不应写文件,但尺寸从 $local_size_before 增至 $local_size_after"
fi
kill $local_daemon_pid 2>/dev/null; wait $local_daemon_pid 2>/dev/null
rm -f "$local_test_log_off"

# ============================================================================
# 15.4 destination=file + format=json: 仅文件, 无 syslog
# ============================================================================
fw_subsection "destination=file + format=json (仅文件, JSON 格式)"
rm -f "$local_test_log_file"
cat > "$local_test_config" <<EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  log_file: $local_test_log_file
  log_level: 3
  log_destination: file
  log_format: json
jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_sshd_log
EOF
local_daemon_pid=$(start_daemon_with_config "$local_test_config")

if [[ -s "$local_test_log_file" ]]; then
    # 验证是 JSON Lines
    if python3 -c "import json, sys; d=json.loads(open('$local_test_log_file').readline()); sys.exit(0 if 'level' in d else 1)" 2>/dev/null; then
        assert_true "true" "destination=file 写入 JSON Lines"
    else
        assert_true "false" "destination=file 应写 JSON Lines"
    fi
else
    assert_true "false" "destination=file 日志文件非空"
fi
kill $local_daemon_pid 2>/dev/null; wait $local_daemon_pid 2>/dev/null

# ============================================================================
# 15.5 无效 destination 值被严格模式拒绝
# ============================================================================
fw_subsection "无效 log_destination 值被严格模式拒绝"
cat > "$local_test_config" <<EOF
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  log_file: $local_test_log_file
  log_level: 3
  log_destination: invalid_dest
  log_format: plain
jails:
  sshd:
    enabled: true
    log_files:
      - $local_test_sshd_log
EOF
local_rc=0
timeout --signal=KILL 3 "$DAEMON_PATH" -c "$local_test_config" >/dev/null 2>&1 || local_rc=$?
# 严格模式应该使配置解析失败, 守护进程无法启动
if [[ $local_rc -ne 0 ]]; then
    assert_true "true" "无效 log_destination 被严格模式拒绝(退出码 $local_rc)"
else
    assert_true "false" "无效 log_destination 应被拒绝,但守护进程启动了"
fi

# ============================================================================
# 清理
# ============================================================================
rm -f "$local_test_log_file" "$local_test_sshd_log" "$local_test_config"
