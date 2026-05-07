#!/bin/bash
# 14_ban_netfilter.sh - 黑名单 IP netfilter 链表验证测试
# 使用真实可路由 IP (223.5.5.5) 验证 ban_table 封禁条目格式和功能

fw_test_header "黑名单 netfilter 封禁测试"

TEST_NETFILTER_IP="223.5.5.5"

# 14.1 检查 procfs 接口
fw_subsection "procfs 接口检查"
assert_success "test -f \"$PROC_BANS\"" "bans 接口存在"
assert_success "test -f \"$PROC_STATS\"" "stats 接口存在"

# 14.2 记录初始统计
fw_subsection "初始统计记录"
BEFORE_DROPPED=$(grep "packets_dropped" "$PROC_STATS" | awk '{print $2}')
BEFORE_ACCEPTED=$(grep "packets_accepted" "$PROC_STATS" | awk '{print $2}')
BEFORE_BANS=$(grep "current_bans" "$PROC_STATS" | awk '{print $2}')
assert_true "[[ $BEFORE_DROPPED -ge 0 ]]" "packets_dropped 初始值: $BEFORE_DROPPED"
assert_true "[[ $BEFORE_ACCEPTED -ge 0 ]]" "packets_accepted 初始值: $BEFORE_ACCEPTED"

# 14.3 封禁测试 IP
fw_subsection "封禁测试 IP"
echo "$TEST_NETFILTER_IP" | sudo tee "$PROC_BANS" > /dev/null 2>&1
sleep 1
assert_file_contains "$PROC_BANS" "$TEST_NETFILTER_IP" "IP $TEST_NETFILTER_IP 封禁成功"

# 14.4 验证 ban_table
fw_subsection "ban_table 验证"

CURRENT_BANS=$(grep "current_bans" "$PROC_STATS" | awk '{print $2}')
assert_true "[[ $CURRENT_BANS -gt $BEFORE_BANS ]]" "封禁数量增加 ($BEFORE_BANS → $CURRENT_BANS)"

# 14.5 验证 ban_table 封禁条目
fw_subsection "netfilter 封禁条目验证"

# 验证封禁条目格式（IP 地址和时间戳格式检查）
BAN_ENTRY=$(grep "$TEST_NETFILTER_IP" "$PROC_BANS" 2>/dev/null || true)
assert_true "[[ -n \"$BAN_ENTRY\" ]]" "ban_table 中存在 $TEST_NETFILTER_IP 的封禁记录"

# 验证封禁条目格式（匹配 bans_show() 输出格式 - 英文）
assert_true "echo \"$BAN_ENTRY\" | grep -qE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*\((permanent|expires in [0-9]+ seconds)\)'" "封禁条目格式正确"

# 14.6 验证内核模块
fw_subsection "内核模块验证"
if lsmod 2>/dev/null | grep -q "firewall"; then
    fw_pass "内核模块已加载"
else
    fw_log_warn "内核模块未加载（可能已被测试框架卸载）"
fi

# 14.7 解封测试 IP
fw_subsection "解封测试 IP"
echo "unban $TEST_NETFILTER_IP" | sudo tee "$PROC_BANS" > /dev/null 2>&1
sleep 1
assert_true "! grep -q \"$TEST_NETFILTER_IP\" \"$PROC_BANS\" 2>/dev/null" "IP $TEST_NETFILTER_IP 解封成功"

# 14.8 最终统计
fw_subsection "最终统计"
FINAL_DROPPED=$(grep "packets_dropped" "$PROC_STATS" | awk '{print $2}')
FINAL_ACCEPTED=$(grep "packets_accepted" "$PROC_STATS" | awk '{print $2}')
FINAL_BANS=$(grep "current_bans" "$PROC_STATS" | awk '{print $2}')
assert_true "[[ $FINAL_DROPPED -ge $BEFORE_DROPPED ]]" "packets_dropped 最终值: $FINAL_DROPPED"
assert_true "[[ $FINAL_BANS -le $BEFORE_BANS ]]" "current_bans 恢复到初始水平: $FINAL_BANS"
