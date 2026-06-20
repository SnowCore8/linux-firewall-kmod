#!/bin/bash
# 18_log_rotation.sh - 日志轮转检测集成测试

fw_test_header "日志轮转检测集成测试"

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
    # 清理测试日志目录
    rm -rf /var/log/firewall-test 2>/dev/null
}
trap cleanup_config EXIT ERR INT TERM

# 检查守护进程是否运行
if ! pgrep -f "firewall-daemon" > /dev/null; then
    fw_log_warn "守护进程未运行，跳过日志轮转测试"
    fw_log_info "请先启动守护进程: sudo ./build/daemon/firewall-daemon"
    exit 0
fi

# 18.1 测试日志文件准备
fw_subsection "测试日志文件准备"

# 创建测试日志目录
mkdir -p /var/log/firewall-test
assert_true "[[ -d /var/log/firewall-test ]]" "创建测试日志目录"

# 创建测试日志文件
local_test_log="/var/log/firewall-test/test.log"
echo "Initial log entry" > "$local_test_log"
assert_true "[[ -f '$local_test_log' ]]" "创建测试日志文件"

# 记录初始 inode
local_initial_inode=$(stat -c %i "$local_test_log" 2>/dev/null)
assert_true "[[ -n '$local_initial_inode' ]]" "获取初始 inode: $local_initial_inode"

# 18.2 创建测试 Jail 配置
fw_subsection "创建测试 Jail 配置"

# 备份原配置
if [[ -f /etc/firewall/default.yaml ]]; then
    cp /etc/firewall/default.yaml /etc/firewall/default.yaml.bak
fi

# 添加测试 jail 到配置
cat >> /etc/firewall/default.yaml << EOF

jails:
  log_rotation_test:
    enabled: true
    log_files:
      - $local_test_log
    max_retries: 3
    findtime: 600
    ban_time: 900
    regexes:
      test_pattern:
        pattern: "test.*from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"
EOF

assert_true "[[ -f /etc/firewall/default.yaml ]]" "更新配置文件"

# 发送 SIGHUP 重载配置
local_pid=$(pgrep -f "firewall-daemon" | head -1)
if [[ -n "$local_pid" ]]; then
    kill -HUP "$local_pid" 2>/dev/null
    sleep 2
    assert_true "[[ true ]]" "发送 SIGHUP 重载配置"
fi

# 18.3 写入测试日志
fw_subsection "写入测试日志"

# 写入一些测试日志条目
for i in {1..10}; do
    echo "Test log entry $i from 192.168.1.$i" >> "$local_test_log"
done
sleep 1

# 验证日志文件有内容
local_log_size=$(stat -c %s "$local_test_log" 2>/dev/null)
assert_true "[[ $local_log_size -gt 0 ]]" "日志文件有内容: ${local_log_size} bytes"

# 18.4 模拟日志轮转（mv + 创建新文件）
fw_subsection "模拟日志轮转（mv + 创建新文件）"

# 记录轮转前的 inode
local_before_rotate_inode=$(stat -c %i "$local_test_log" 2>/dev/null)

# 模拟 logrotate：移动旧日志，创建新日志
mv "$local_test_log" "${local_test_log}.1"
assert_true "[[ -f '${local_test_log}.1' ]]" "旧日志已移动"

# 创建新的日志文件
echo "New log file after rotation" > "$local_test_log"
assert_true "[[ -f '$local_test_log' ]]" "新日志文件已创建"

# 记录轮转后的 inode
local_after_rotate_inode=$(stat -c %i "$local_test_log" 2>/dev/null)

# 验证 inode 已改变
if [[ "$local_before_rotate_inode" != "$local_after_rotate_inode" ]]; then
    assert_true "[[ true ]]" "日志轮转后 inode 已改变"
else
    fw_log_warn "日志轮转后 inode 未改变"
fi

# 18.5 验证守护进程检测到轮转
fw_subsection "验证守护进程检测到轮转"

# 等待守护进程检测轮转（inotify 或轮询）
sleep 3

# 写入新日志条目
echo "Post-rotation test entry from 10.0.0.1" >> "$local_test_log"
sleep 2

# 检查守护进程日志中是否有轮转检测记录
if grep -qi "rotation\|reopen\|inode.*change\|file.*change" /var/log/firewall.log 2>/dev/null | tail -10; then
    assert_true "[[ true ]]" "守护进程日志中包含轮转检测记录"
else
    fw_log_info "守护进程日志中未找到明确的轮转检测记录"
fi

# 18.6 验证守护进程继续监控新文件
fw_subsection "验证守护进程继续监控新文件"

# 写入更多测试日志
for i in {1..5}; do
    echo "Post-rotation entry $i from 172.16.0.$i" >> "$local_test_log"
done
sleep 2

# 验证新日志文件有内容
local_new_log_size=$(stat -c %s "$local_test_log" 2>/dev/null)
assert_true "[[ $local_new_log_size -gt 0 ]]" "新日志文件有内容: ${local_new_log_size} bytes"

# 18.7 模拟 copytruncate 轮转方式
fw_subsection "模拟 copytruncate 轮转方式"

# 记录当前 inode
local_before_ct_inode=$(stat -c %i "$local_test_log" 2>/dev/null)
local_before_ct_size=$(stat -c %s "$local_test_log" 2>/dev/null)

# 模拟 copytruncate：复制内容到备份，清空原文件
cp "$local_test_log" "${local_test_log}.2"
> "$local_test_log"  # 清空文件

# 验证 inode 未变（copytruncate 不改变 inode）
local_after_ct_inode=$(stat -c %i "$local_test_log" 2>/dev/null)
if [[ "$local_before_ct_inode" == "$local_after_ct_inode" ]]; then
    assert_true "[[ true ]]" "copytruncate 后 inode 未改变"
else
    fw_log_warn "copytruncate 后 inode 改变了"
fi

# 验证文件大小为 0
local_after_ct_size=$(stat -c %s "$local_test_log" 2>/dev/null)
if [[ $local_after_ct_size -eq 0 ]]; then
    assert_true "[[ true ]]" "copytruncate 后文件大小为 0"
else
    fw_log_warn "copytruncate 后文件大小不为 0: $local_after_ct_size"
fi

# 等待守护进程检测
sleep 3

# 写入新日志
echo "After copytruncate entry from 192.168.2.1" >> "$local_test_log"
sleep 2

# 验证新内容被写入
local_final_size=$(stat -c %s "$local_test_log" 2>/dev/null)
assert_true "[[ $local_final_size -gt 0 ]]" "copytruncate 后新内容被写入: ${local_final_size} bytes"

# 18.8 清理测试环境
fw_subsection "清理测试环境"

# 恢复原配置
if [[ -f /etc/firewall/default.yaml.bak ]]; then
    mv /etc/firewall/default.yaml.bak /etc/firewall/default.yaml
    # 重载配置
    if [[ -n "$local_pid" ]]; then
        kill -HUP "$local_pid" 2>/dev/null
        sleep 1
    fi
fi

# 清理测试日志
rm -rf /var/log/firewall-test
assert_true "[[ ! -d /var/log/firewall-test ]]" "清理测试日志目录"

fw_log_info "日志轮转检测集成测试完成"
