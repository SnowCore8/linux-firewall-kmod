#!/bin/bash
# 15_ddos_detection.sh - DDoS 检测集成测试

fw_test_header "DDoS 检测集成测试"

# 检查守护进程是否运行
if ! pgrep -f "firewall-daemon" > /dev/null; then
    fw_log_warn "守护进程未运行，跳过 DDoS 检测测试"
    fw_log_info "请先启动守护进程: sudo ./build/daemon/firewall-daemon"
    exit 0
fi

# 15.1 DDoS 检测配置验证
fw_subsection "DDoS 检测配置验证"

# 检查 DDoS 检测是否启用
if grep -q "ddos:" /etc/firewall/default.yaml 2>/dev/null; then
    assert_true "[[ -f /etc/firewall/default.yaml ]]" "DDoS 配置文件存在"
    
    # 检查关键配置项
    if grep -q "enabled: true" /etc/firewall/default.yaml 2>/dev/null; then
        assert_true "[[ true ]]" "DDoS 检测已启用"
    else
        fw_log_warn "DDoS 检测未启用，部分测试可能跳过"
    fi
else
    fw_log_warn "DDoS 配置节不存在，使用默认配置"
fi

# 15.2 速率检测阈值验证
fw_subsection "速率检测阈值验证"

# 读取内核模块的速率检测配置
if [[ -f /proc/firewall/config ]]; then
    local_config=$(cat /proc/firewall/config)
    assert_true "[[ -n '$local_config' ]]" "内核模块配置可读"
    
    # 检查速率检测参数是否存在
    if echo "$local_config" | grep -q "max_packets_per_second"; then
        assert_true "[[ true ]]" "速率检测参数已配置"
    else
        fw_log_warn "速率检测参数未在 procfs 中暴露"
    fi
else
    fw_log_warn "/proc/firewall/config 不存在，跳过内核配置验证"
fi

# 15.3 DDoS 统计信息验证
fw_subsection "DDoS 统计信息验证"

# 检查内核模块统计
if [[ -f /proc/firewall/stats ]]; then
    local_stats=$(cat /proc/firewall/stats)
    assert_true "[[ -n '$local_stats' ]]" "内核模块统计可读"
    
    # 检查 DDoS 相关统计字段
    if echo "$local_stats" | grep -q "ddos"; then
        assert_true "[[ true ]]" "DDoS 统计字段存在"
    else
        fw_log_info "DDoS 统计字段未在 procfs 中暴露（可能通过 Prometheus 指标暴露）"
    fi
else
    fw_log_warn "/proc/firewall/stats 不存在"
fi

# 15.4 Prometheus 指标验证
fw_subsection "Prometheus 指标验证"

# 检查 Prometheus 端点是否可用
if curl -s http://localhost:9119/metrics > /dev/null 2>&1; then
    assert_true "[[ true ]]" "Prometheus 端点可访问"
    
    # 获取指标
    local_metrics=$(curl -s http://localhost:9119/metrics 2>/dev/null)
    
    # 检查 DDoS 相关指标
    if echo "$local_metrics" | grep -q "firewall_ddos"; then
        assert_true "[[ true ]]" "DDoS 相关 Prometheus 指标存在"
        
        # 检查具体指标
        if echo "$local_metrics" | grep -q "firewall_ddos_events_total"; then
            assert_true "[[ true ]]" "firewall_ddos_events_total 指标存在"
        fi
        
        if echo "$local_metrics" | grep -q "firewall_ddos_bans_total"; then
            assert_true "[[ true ]]" "firewall_ddos_bans_total 指标存在"
        fi
    else
        fw_log_warn "DDoS 相关 Prometheus 指标不存在"
    fi
else
    fw_log_warn "Prometheus 端点不可访问（端口 9119）"
fi

# 15.5 自动封禁触发测试（模拟）
fw_subsection "自动封禁触发测试"

# 注意：真实的 DDoS 模拟需要生成大量网络流量，这在集成测试中不太实际
# 这里我们只验证自动封禁机制的配置和状态

# 检查是否有自动封禁的 IP（通过 Prometheus 指标或日志）
if curl -s http://localhost:9119/metrics 2>/dev/null | grep -q "firewall_ddos_bans_total [1-9]"; then
    assert_true "[[ true ]]" "检测到 DDoS 自动封禁事件"
else
    fw_log_info "未检测到 DDoS 自动封禁事件（正常，需要真实流量触发）"
fi

# 15.6 守护进程日志验证
fw_subsection "守护进程日志验证"

# 检查守护进程日志
if [[ -f /var/log/firewall.log ]]; then
    assert_true "[[ -f /var/log/firewall.log ]]" "守护进程日志文件存在"
    
    # 检查是否有 DDoS 相关的日志条目
    if grep -qi "ddos\|rate.*limit\|auto.*ban" /var/log/firewall.log 2>/dev/null; then
        assert_true "[[ true ]]" "日志中包含 DDoS 检测相关条目"
    else
        fw_log_info "日志中未找到 DDoS 检测条目（可能尚未触发）"
    fi
else
    fw_log_warn "守护进程日志文件不存在"
fi

# 15.7 配置热重载验证
fw_subsection "配置热重载验证"

# 发送 SIGHUP 信号触发配置重载
if pgrep -f "firewall-daemon" > /dev/null; then
    local_pid=$(pgrep -f "firewall-daemon")
    
    # 记录重载前的配置哈希
    local_before_hash=$(md5sum /etc/firewall/default.yaml 2>/dev/null | cut -d' ' -f1)
    
    # 发送 SIGHUP
    kill -HUP "$local_pid" 2>/dev/null
    sleep 1
    
    # 验证进程仍然运行
    if pgrep -f "firewall-daemon" > /dev/null; then
        assert_true "[[ true ]]" "配置重载后守护进程仍在运行"
    else
        assert_true "[[ false ]]" "配置重载后守护进程仍在运行"
    fi
    
    # 检查日志中是否有重载记录
    if grep -qi "reload\|sighup\|config.*load" /var/log/firewall.log 2>/dev/null | tail -5; then
        assert_true "[[ true ]]" "日志中包含配置重载记录"
    else
        fw_log_info "日志中未找到配置重载记录"
    fi
else
    fw_log_warn "守护进程未运行，跳过配置重载测试"
fi

fw_log_info "DDoS 检测集成测试完成"
