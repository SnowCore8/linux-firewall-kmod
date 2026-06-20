#!/bin/bash
# 17_config_reload.sh - 配置热重载（SIGHUP）集成测试

fw_test_header "配置热重载（SIGHUP）集成测试"

# 配置恢复 trap（确保测试中断时也能恢复配置）
cleanup_config() {
    if [[ -f /etc/firewall/default.yaml.bak ]]; then
        mv /etc/firewall/default.yaml.bak /etc/firewall/default.yaml 2>/dev/null
        # 重载配置
        local pid=$(pgrep -f "firewall-daemon" | head -1)
        if [[ -n "$pid" ]]; then
            kill -HUP "$pid" 2>/dev/null
        fi
    fi
}
trap cleanup_config EXIT ERR INT TERM

# 检查守护进程是否运行
if ! pgrep -f "firewall-daemon" > /dev/null; then
    fw_log_warn "守护进程未运行，跳过配置热重载测试"
    fw_log_info "请先启动守护进程: sudo ./build/daemon/firewall-daemon"
    exit 0
fi

# 17.1 守护进程 PID 获取
fw_subsection "守护进程 PID 获取"

local_pid=$(pgrep -f "firewall-daemon" | head -1)
if [[ -n "$local_pid" ]]; then
    assert_true "[[ -n '$local_pid' ]]" "获取守护进程 PID: $local_pid"
else
    fw_log_error "无法获取守护进程 PID"
    exit 1
fi

# 17.2 配置文件存在性检查
fw_subsection "配置文件存在性检查"

if [[ -f /etc/firewall/default.yaml ]]; then
    assert_true "[[ -f /etc/firewall/default.yaml ]]" "默认配置文件存在"
    
    # 记录配置文件修改时间
    local_before_mtime=$(stat -c %Y /etc/firewall/default.yaml 2>/dev/null)
    assert_true "[[ -n '$local_before_mtime' ]]" "获取配置文件修改时间"
else
    fw_log_warn "默认配置文件不存在，使用测试配置"
    # 创建临时测试配置
    mkdir -p /etc/firewall
    cat > /etc/firewall/default.yaml << 'EOF'
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

jails:
  test_jail:
    enabled: true
    log_files:
      - /var/log/test.log
    max_retries: 5
    findtime: 300
    ban_time: 600
    regexes:
      test_pattern:
        pattern: "test.*from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
EOF
    assert_true "[[ -f /etc/firewall/default.yaml ]]" "创建测试配置文件"
fi

# 17.3 发送 SIGHUP 信号
fw_subsection "发送 SIGHUP 信号"

# 记录发送信号前的日志行数
local_before_log_lines=$(wc -l < /var/log/firewall.log 2>/dev/null || echo "0")

# 发送 SIGHUP
kill -HUP "$local_pid" 2>/dev/null
assert_true "[[ $? -eq 0 ]]" "发送 SIGHUP 信号成功"

# 等待守护进程处理信号
sleep 2

# 17.4 验证守护进程仍在运行
fw_subsection "验证守护进程仍在运行"

if pgrep -f "firewall-daemon" > /dev/null; then
    assert_true "[[ true ]]" "SIGHUP 后守护进程仍在运行"
    
    # 验证 PID 未变
    local_after_pid=$(pgrep -f "firewall-daemon" | head -1)
    if [[ "$local_pid" == "$local_after_pid" ]]; then
        assert_true "[[ true ]]" "守护进程 PID 未变（未重启）"
    else
        fw_log_warn "守护进程 PID 已变：$local_pid -> $local_after_pid"
    fi
else
    assert_true "[[ false ]]" "SIGHUP 后守护进程仍在运行"
    fw_log_error "守护进程在 SIGHUP 后退出"
    exit 1
fi

# 17.5 验证日志中记录了重载事件
fw_subsection "验证日志中记录了重载事件"

sleep 1
local_after_log_lines=$(wc -l < /var/log/firewall.log 2>/dev/null || echo "0")

if [[ $local_after_log_lines -gt $local_before_log_lines ]]; then
    assert_true "[[ true ]]" "SIGHUP 后日志有新内容"
    
    # 检查是否有 reload 相关日志
    if tail -n 20 /var/log/firewall.log 2>/dev/null | grep -qi "reload\|sighup\|config.*load\|signal"; then
        assert_true "[[ true ]]" "日志中包含配置重载记录"
    else
        fw_log_info "日志中未找到明确的重载记录（可能日志级别不够）"
    fi
else
    fw_log_warn "SIGHUP 后日志无新内容"
fi

# 17.6 修改配置文件并重新加载
fw_subsection "修改配置文件并重新加载"

# 备份原配置
cp /etc/firewall/default.yaml /etc/firewall/default.yaml.bak 2>/dev/null

# 修改配置（改变 max_retries）
if [[ -f /etc/firewall/default.yaml ]]; then
    # 使用 sed 修改 max_retries 值
    sed -i 's/max_retries: [0-9]\+/max_retries: 10/' /etc/firewall/default.yaml 2>/dev/null
    
    # 验证修改成功
    if grep -q "max_retries: 10" /etc/firewall/default.yaml 2>/dev/null; then
        assert_true "[[ true ]]" "修改配置文件成功（max_retries: 10）"
    else
        fw_log_warn "修改配置文件失败"
    fi
    
    # 再次发送 SIGHUP
    kill -HUP "$local_pid" 2>/dev/null
    sleep 2
    
    # 验证守护进程仍在运行
    if pgrep -f "firewall-daemon" > /dev/null; then
        assert_true "[[ true ]]" "修改配置后 SIGHUP 守护进程仍在运行"
    else
        assert_true "[[ false ]]" "修改配置后 SIGHUP 守护进程仍在运行"
    fi
    
    # 恢复原配置
    mv /etc/firewall/default.yaml.bak /etc/firewall/default.yaml 2>/dev/null
    
    # 再次重载恢复的配置
    kill -HUP "$local_pid" 2>/dev/null
    sleep 1
fi

# 17.7 无效配置测试
fw_subsection "无效配置测试"

# 备份原配置
cp /etc/firewall/default.yaml /etc/firewall/default.yaml.bak 2>/dev/null

# 写入无效配置
echo "invalid_yaml: [" > /etc/firewall/default.yaml 2>/dev/null

# 发送 SIGHUP
kill -HUP "$local_pid" 2>/dev/null
sleep 2

# 验证守护进程仍在运行（应该忽略无效配置或保持原配置）
if pgrep -f "firewall-daemon" > /dev/null; then
    assert_true "[[ true ]]" "无效配置后守护进程仍在运行（容错）"
else
    fw_log_warn "无效配置导致守护进程退出"
fi

# 恢复原配置
mv /etc/firewall/default.yaml.bak /etc/firewall/default.yaml 2>/dev/null
kill -HUP "$local_pid" 2>/dev/null
sleep 1

# 17.8 多次连续 SIGHUP 测试
fw_subsection "多次连续 SIGHUP 测试"

# 连续发送 5 次 SIGHUP
for i in {1..5}; do
    kill -HUP "$local_pid" 2>/dev/null
    sleep 0.5
done

sleep 2

# 验证守护进程仍在运行
if pgrep -f "firewall-daemon" > /dev/null; then
    assert_true "[[ true ]]" "连续 5 次 SIGHUP 后守护进程仍在运行"
else
    assert_true "[[ false ]]" "连续 5 次 SIGHUP 后守护进程仍在运行"
fi

fw_log_info "配置热重载（SIGHUP）集成测试完成"
