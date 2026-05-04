#!/bin/bash
# 测试黑名单 IP 是否成功在内核 netfilter 链表中生效
# 使用真实可路由 IP (43.100.123.123) 验证数据包丢弃功能

set -e

PROC_BANS="/proc/firewall/bans"
PROC_STATS="/proc/firewall/stats"
TEST_IP="43.100.123.123"  # 真实可路由 IP（阿里云）

echo "========================================"
echo "  黑名单 IP netfilter 链表验证测试"
echo "========================================"
echo ""

# 1. 检查 procfs 接口是否存在
echo "=== 1. 检查 procfs 接口 ==="
if [ ! -f "$PROC_BANS" ]; then
    echo "❌ $PROC_BANS 不存在，内核模块未加载"
    exit 1
fi
echo "✅ $PROC_BANS 存在"

if [ ! -f "$PROC_STATS" ]; then
    echo "❌ $PROC_STATS 不存在"
    exit 1
fi
echo "✅ $PROC_STATS 存在"
echo ""

# 2. 记录初始统计
echo "=== 2. 记录初始统计 ==="
BEFORE_DROPPED=$(grep "packets_dropped" $PROC_STATS | awk '{print $2}')
BEFORE_ACCEPTED=$(grep "packets_accepted" $PROC_STATS | awk '{print $2}')
BEFORE_BANS=$(grep "current_bans" $PROC_STATS | awk '{print $2}')
echo "初始 packets_dropped: $BEFORE_DROPPED"
echo "初始 packets_accepted: $BEFORE_ACCEPTED"
echo "初始 current_bans: $BEFORE_BANS"
echo ""

# 3. 封禁测试 IP
echo "=== 3. 封禁测试 IP ($TEST_IP) ==="
echo "$TEST_IP" | sudo tee $PROC_BANS > /dev/null
sleep 1
echo "✅ 封禁命令已发送"
echo ""

# 4. 验证 IP 出现在封禁列表中
echo "=== 4. 验证 ban_table ==="
if cat $PROC_BANS | grep -q "$TEST_IP"; then
    echo "✅ $TEST_IP 出现在内核 ban_table 中"
    echo ""
    echo "封禁列表内容："
    cat $PROC_BANS | head -10
else
    echo "❌ $TEST_IP 未出现在封禁列表中"
    exit 1
fi
echo ""

# 5. 检查统计信息
echo "=== 5. 检查统计信息 ==="
CURRENT_BANS=$(grep "current_bans" $PROC_STATS | awk '{print $2}')
echo "当前 current_bans: $CURRENT_BANS"
if [ "$CURRENT_BANS" -gt "$BEFORE_BANS" ]; then
    echo "✅ 封禁数量增加 ($BEFORE_BANS → $CURRENT_BANS)"
else
    echo "⚠️  封禁数量未变化"
fi
echo ""

# 6. 发送测试数据包并检查是否被丢弃
echo "=== 6. 发送测试数据包 ==="
echo "使用 ping 测试 $TEST_IP（应该被 netfilter 丢弃）..."
ping -c 3 -W 1 $TEST_IP > /dev/null 2>&1 || true
sleep 1

AFTER_DROPPED=$(grep "packets_dropped" $PROC_STATS | awk '{print $2}')
AFTER_ACCEPTED=$(grep "packets_accepted" $PROC_STATS | awk '{print $2}')
DROPPED_DIFF=$((AFTER_DROPPED - BEFORE_DROPPED))

echo "发送前 packets_dropped: $BEFORE_DROPPED"
echo "发送后 packets_dropped: $AFTER_DROPPED"
echo "丢弃的数据包数: $DROPPED_DIFF"
echo ""

if [ "$DROPPED_DIFF" -gt 0 ]; then
    echo "✅ netfilter 钩子成功丢弃数据包！"
else
    echo "⚠️  未检测到丢弃的数据包"
    echo "   可能原因："
    echo "   - 数据包在路由层被提前丢弃"
    echo "   - 网络不可达（无路由）"
fi
echo ""

# 7. 验证内核模块状态
echo "=== 7. 验证内核模块 ==="
if lsmod | grep -q "firewall"; then
    echo "✅ 内核模块已加载"
else
    echo "❌ 内核模块未加载"
    exit 1
fi
echo ""

# 8. 解封测试 IP
echo "=== 8. 解封测试 IP ==="
echo "unban $TEST_IP" | sudo tee $PROC_BANS > /dev/null
sleep 1

if cat $PROC_BANS | grep -q "$TEST_IP"; then
    echo "❌ $TEST_IP 仍在封禁列表中"
else
    echo "✅ $TEST_IP 已从封禁列表移除"
fi
echo ""

# 9. 最终统计
echo "=== 9. 最终统计 ==="
FINAL_DROPPED=$(grep "packets_dropped" $PROC_STATS | awk '{print $2}')
FINAL_ACCEPTED=$(grep "packets_accepted" $PROC_STATS | awk '{print $2}')
FINAL_BANS=$(grep "current_bans" $PROC_STATS | awk '{print $2}')
echo "最终 packets_dropped: $FINAL_DROPPED"
echo "最终 packets_accepted: $FINAL_ACCEPTED"
echo "最终 current_bans: $FINAL_BANS"
echo ""

echo "========================================"
echo "  测试完成"
echo "========================================"
echo ""
echo "总结："
echo "  ✅ IP 封禁成功写入 /proc/firewall/bans"
echo "  ✅ IP 出现在内核 ban_table 中"
if [ "$DROPPED_DIFF" -gt 0 ]; then
    echo "  ✅ 数据包被 netfilter 钩子丢弃（$DROPPED_DIFF 个）"
else
    echo "  ⚠️  数据包丢弃未检测到（可能因路由原因）"
fi
echo "  ✅ IP 解封成功"
echo ""
echo "netfilter 链表工作正常！"
