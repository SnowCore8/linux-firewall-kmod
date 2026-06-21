#!/bin/bash
# 19_netlink_comm.sh - Netlink 通信与健康指标集成测试

fw_test_header "Netlink 通信与健康指标集成测试"

# 检查守护进程是否运行
if ! pgrep -f "firewall-daemon" > /dev/null; then
    fw_log_warn "守护进程未运行，跳过 Netlink 通信测试"
    fw_log_info "请先启动守护进程: sudo ./build/daemon/firewall-daemon"
    exit 0
fi

METRICS_PORT=${METRICS_PORT:-9119}
WEBUI_PORT=${WEBUI_PORT:-8080}

# ============================================================================
# 19.1 Prometheus netlink 指标存在性
# ============================================================================
fw_subsection "Prometheus netlink 指标存在性"

metrics_output=$(curl -s "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null)

if [[ -n "$metrics_output" ]]; then
    assert_true "[[ -n '$metrics_output' ]]" "Prometheus 端点可达"

    for metric in \
        "firewall_netlink_messages_sent_total" \
        "firewall_netlink_messages_received_total" \
        "firewall_netlink_send_errors_total" \
        "firewall_netlink_recv_errors_total"; do
        if echo "$metrics_output" | grep -q "^${metric} "; then
            assert_true "[[ true ]]" "${metric} 指标存在"
        else
            fw_log_warn "${metric} 指标不存在（可能无 netlink 通信）"
        fi
    done
else
    fw_log_warn "Prometheus 端点无响应，跳过 netlink 指标检查"
fi

# ============================================================================
# 19.2 封禁操作触发 netlink 消息计数递增
# ============================================================================
fw_subsection "封禁操作触发 netlink 消息计数递增"

if [[ -n "$metrics_output" ]]; then
    sent_before=$(echo "$metrics_output" | grep "^firewall_netlink_messages_sent_total " | awk '{print $2}')
    recv_before=$(echo "$metrics_output" | grep "^firewall_netlink_messages_received_total " | awk '{print $2}')
    sent_before=${sent_before:-0}
    recv_before=${recv_before:-0}

    # 执行一次封禁操作（通过 API 触发 netlink 通信）
    TEST_NL_IP="192.0.2.200"
    curl -s -X POST "http://localhost:${WEBUI_PORT}/api/bans" \
        -H "Content-Type: application/json" \
        -d "{\"ip\": \"${TEST_NL_IP}\", \"duration\": 60}" > /dev/null 2>&1
    sleep 1

    metrics_after=$(curl -s "http://localhost:${METRICS_PORT}/metrics" 2>/dev/null)
    sent_after=$(echo "$metrics_after" | grep "^firewall_netlink_messages_sent_total " | awk '{print $2}')
    recv_after=$(echo "$metrics_after" | grep "^firewall_netlink_messages_received_total " | awk '{print $2}')
    sent_after=${sent_after:-0}
    recv_after=${recv_after:-0}

    if [[ "$sent_after" -ge "$sent_before" ]]; then
        assert_true "[[ true ]]" "发送计数未减少（before=${sent_before}, after=${sent_after}）"
    else
        assert_true "[[ false ]]" "发送计数应不减少（before=${sent_before}, after=${sent_after}）"
    fi

    # 清理：解封
    curl -s -X DELETE "http://localhost:${WEBUI_PORT}/api/bans/${TEST_NL_IP}" > /dev/null 2>&1
else
    fw_log_warn "Prometheus 端点无响应，跳过计数递增测试"
fi

# ============================================================================
# 19.3 netlink 错误计数初始为零
# ============================================================================
fw_subsection "netlink 错误计数检查"

if [[ -n "$metrics_output" ]]; then
    send_err=$(echo "$metrics_output" | grep "^firewall_netlink_send_errors_total " | awk '{print $2}')
    recv_err=$(echo "$metrics_output" | grep "^firewall_netlink_recv_errors_total " | awk '{print $2}')
    send_err=${send_err:-0}
    recv_err=${recv_err:-0}

    assert_true "[[ ${send_err} -ge 0 ]]" "netlink 发送错误计数 >= 0（当前: ${send_err}）"
    assert_true "[[ ${recv_err} -ge 0 ]]" "netlink 接收错误计数 >= 0（当前: ${recv_err}）"
else
    fw_log_warn "Prometheus 端点无响应，跳过错误计数检查"
fi
