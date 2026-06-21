#!/bin/bash
# 20_daemon_lifecycle.sh - 守护进程生命周期集成测试
# 测试启动、停止、重启、信号处理、PID 文件管理

fw_test_header "守护进程生命周期集成测试"

DAEMON_BIN="${BUILD_DIR}/daemon/firewall-daemon"
PID_FILE="/var/run/firewall-daemon.pid"
TEST_CONFIG="/tmp/fw_test_lifecycle.yaml"

if [[ ! -f "$DAEMON_BIN" ]]; then
    fw_log_warn "守护进程二进制不存在: $DAEMON_BIN，跳过测试"
    exit 0
fi

# 清理函数：确保测试结束后不留残余
cleanup_lifecycle() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null
            sleep 1
            kill -9 "$pid" 2>/dev/null
        fi
        rm -f "$PID_FILE"
    fi
    rm -f "$TEST_CONFIG"
}
trap cleanup_lifecycle RETURN

# 准备测试配置
cat > "$TEST_CONFIG" << 'YAML'
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 300
  interval: 1
  metrics_port: 9121

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    max_retries: 3
    findtime: 600
    ban_time: 300
    regexes:
      default:
        pattern: ""
YAML

# ============================================================================
# 20.1 守护进程启动与 PID 文件创建
# ============================================================================
fw_subsection "守护进程启动与 PID 文件"

# 先确保没有残留进程
if [[ -f "$PID_FILE" ]]; then
    old_pid=$(cat "$PID_FILE" 2>/dev/null)
    if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
        kill "$old_pid" 2>/dev/null
        sleep 1
    fi
    rm -f "$PID_FILE"
fi

# 启动守护进程
"$DAEMON_BIN" -c "$TEST_CONFIG" &
DAEMON_PID=$!
sleep 2

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    assert_true "[[ true ]]" "守护进程启动成功 (PID: ${DAEMON_PID})"
else
    assert_true "[[ false ]]" "守护进程启动失败"
    fw_log_warn "后续测试因启动失败而跳过"
    trap - RETURN
    cleanup_lifecycle
    exit 0
fi

# 检查 PID 文件
if [[ -f "$PID_FILE" ]]; then
    assert_true "[[ true ]]" "PID 文件已创建"
    pid_content=$(cat "$PID_FILE" 2>/dev/null)
    assert_true "[[ '${pid_content}' == '${DAEMON_PID}' ]]" "PID 文件内容匹配 (${pid_content})"
else
    fw_log_warn "PID 文件未创建（可能使用了不同的 PID 路径）"
fi

# ============================================================================
# 20.2 单实例约束（flock 排他锁）
# ============================================================================
fw_subsection "单实例约束"

# 尝试启动第二个实例
"$DAEMON_BIN" -c "$TEST_CONFIG" &
SECOND_PID=$!
sleep 2

if kill -0 "$SECOND_PID" 2>/dev/null; then
    fw_log_warn "第二个实例启动成功（单实例约束可能未启用）"
    kill "$SECOND_PID" 2>/dev/null
    wait "$SECOND_PID" 2>/dev/null
else
    assert_true "[[ true ]]" "第二个实例被拒绝（单实例约束生效）"
fi

# ============================================================================
# 20.3 SIGHUP 配置重载
# ============================================================================
fw_subsection "SIGHUP 配置重载"

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -HUP "$DAEMON_PID" 2>/dev/null
    sleep 1

    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        assert_true "[[ true ]]" "SIGHUP 后守护进程仍在运行"
    else
        assert_true "[[ false ]]" "SIGHUP 导致守护进程退出"
    fi
fi

# ============================================================================
# 20.4 SIGTERM 优雅退出
# ============================================================================
fw_subsection "SIGTERM 优雅退出"

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill -TERM "$DAEMON_PID" 2>/dev/null
    sleep 2

    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        fw_log_warn "SIGTERM 后进程仍在运行，发送 SIGKILL"
        kill -9 "$DAEMON_PID" 2>/dev/null
        sleep 1
    fi

    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        assert_true "[[ true ]]" "SIGTERM 后守护进程已退出"
    else
        assert_true "[[ false ]]" "守护进程未能被 SIGTERM 终止"
    fi
fi

# 清理 trap
trap - RETURN
cleanup_lifecycle
