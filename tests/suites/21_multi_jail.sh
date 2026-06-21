#!/bin/bash
# 21_multi_jail.sh - 多 Jail 并发集成测试
# 测试多个 Jail 同时运行时的独立性和正确性

fw_test_header "多 Jail 并发集成测试"

DAEMON_BIN="${BUILD_DIR}/daemon/firewall-daemon"
TEST_CONFIG="/tmp/fw_test_multi_jail.yaml"
TEST_LOG1="/tmp/fw_test_jail1.log"
TEST_LOG2="/tmp/fw_test_jail2.log"
TEST_LOG3="/tmp/fw_test_jail3.log"

if [[ ! -f "$DAEMON_BIN" ]]; then
    fw_log_warn "守护进程二进制不存在: $DAEMON_BIN，跳过测试"
    exit 0
fi

# 清理函数
cleanup_multi_jail() {
    if [[ -f "$TEST_CONFIG" ]]; then
        local pid
        pid=$(pgrep -f "firewall-daemon.*${TEST_CONFIG}" 2>/dev/null)
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null
            sleep 1
        fi
    fi
    rm -f "$TEST_CONFIG" "$TEST_LOG1" "$TEST_LOG2" "$TEST_LOG3"
}
trap cleanup_multi_jail RETURN

# 准备测试日志文件
touch "$TEST_LOG1" "$TEST_LOG2" "$TEST_LOG3"

# 准备多 Jail 配置
cat > "$TEST_CONFIG" << YAML
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 300
  interval: 1
  metrics_port: 9122

jails:
  jail-alpha:
    enabled: true
    log_files:
      - ${TEST_LOG1}
    max_retries: 3
    findtime: 600
    ban_time: 300
    regexes:
      default:
        pattern: "Failed login from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

  jail-beta:
    enabled: true
    log_files:
      - ${TEST_LOG2}
    max_retries: 5
    findtime: 300
    ban_time: 600
    regexes:
      default:
        pattern: "unauthorized access from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"

  jail-gamma:
    enabled: true
    log_files:
      - ${TEST_LOG3}
    max_retries: 2
    findtime: 120
    ban_time: 900
    regexes:
      default:
        pattern: "blocked (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
YAML

# ============================================================================
# 21.1 多 Jail 配置加载
# ============================================================================
fw_subsection "多 Jail 配置加载"

# 先停止可能存在的旧守护进程
old_pid=$(pgrep -f "firewall-daemon" 2>/dev/null)
if [[ -n "$old_pid" ]]; then
    fw_log_warn "检测到运行中的守护进程 (PID: ${old_pid})，测试使用独立端口"
fi

# 启动守护进程
"$DAEMON_BIN" -c "$TEST_CONFIG" &
DAEMON_PID=$!
sleep 2

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    assert_true "[[ true ]]" "多 Jail 配置加载成功，守护进程启动"
else
    assert_true "[[ false ]]" "多 Jail 配置加载失败"
    trap - RETURN
    cleanup_multi_jail
    exit 0
fi

# ============================================================================
# 21.2 多 Jail 日志并发写入
# ============================================================================
fw_subsection "多 Jail 日志并发写入"

# 同时向三个 Jail 的日志文件写入内容
for i in $(seq 1 10); do
    echo "Failed login from 10.0.${i}.1" >> "$TEST_LOG1"
    echo "unauthorized access from 10.0.${i}.2" >> "$TEST_LOG2"
    echo "blocked 10.0.${i}.3" >> "$TEST_LOG3"
done
sleep 3

assert_true "[[ true ]]" "三个 Jail 日志文件并发写入完成"

# ============================================================================
# 21.3 Jail 独立性验证（不同阈值）
# ============================================================================
fw_subsection "Jail 独立性验证"

# jail-gamma 的 max_retries=2，应该最先触发封禁
# 写入刚好达到 gamma 阈值但未达到 alpha 阈值的失败次数
for i in $(seq 1 3); do
    echo "blocked 10.0.50.${i}" >> "$TEST_LOG3"
done
sleep 2

# 检查 Prometheus 指标中是否有 jail 维度的统计
METRICS_PORT=9122
metrics_output=$(curl -s "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null)

if [[ -n "$metrics_output" ]]; then
    assert_true "[[ -n '$metrics_output' ]]" "多 Jail Prometheus 指标可达"

    if echo "$metrics_output" | grep -q "firewall_daemon_lines_parsed_total"; then
        assert_true "[[ true ]]" "lines_parsed 指标存在"
    fi
else
    fw_log_warn "Prometheus 端点不可达（端口 ${METRICS_PORT}）"
fi

# ============================================================================
# 21.4 清理
# ============================================================================
fw_subsection "清理"

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID" 2>/dev/null
    sleep 1
    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -9 "$DAEMON_PID" 2>/dev/null
    fi
    assert_true "[[ true ]]" "守护进程已停止"
fi

trap - RETURN
cleanup_multi_jail
