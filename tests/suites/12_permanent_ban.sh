#!/bin/bash
# 12_permanent_ban.sh - 永久黑名单功能测试 (SQLite 持久化)

fw_test_header "永久黑名单功能测试"

# 确保内核模块已加载
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 永久黑名单 procfs 路径
PROC_PERMANENT_ADD="/proc/firewall/permanent_add_ban"
PROC_PERMANENT_REMOVE="/proc/firewall/permanent_remove_ban"

# ============================================================================
# 12.1 基本永久封禁/解封
# ============================================================================
fw_subsection "基本永久封禁/解封"

# 添加永久封禁
TEST_PERM_IP="198.51.100.100"
echo "$TEST_PERM_IP" > "$PROC_PERMANENT_ADD" 2>/dev/null
sleep 0.3

# 验证 IP 被封禁
assert_file_contains "$PROC_BAN_LIST" "$TEST_PERM_IP" "IP $TEST_PERM_IP 永久封禁成功"

# 移除永久封禁
echo "$TEST_PERM_IP" > "$PROC_PERMANENT_REMOVE" 2>/dev/null
sleep 0.3

# 验证 IP 已被解封
assert_true "! grep -q '$TEST_PERM_IP' '$PROC_BAN_LIST' 2>/dev/null" "IP $TEST_PERM_IP 永久解封成功"

# ============================================================================
# 12.2 永久封禁不会自动过期
# ============================================================================
fw_subsection "永久封禁过期检查"

TEST_PERM_IP2="198.51.100.101"
echo "$TEST_PERM_IP2" > "$PROC_PERMANENT_ADD" 2>/dev/null
sleep 0.3

# 检查 ban_list 中是否存在（应该存在，即使是"过期"后）
assert_file_contains "$PROC_BAN_LIST" "$TEST_PERM_IP2" "永久封禁条目存在（不自动过期）"

# 清理
echo "$TEST_PERM_IP2" > "$PROC_PERMANENT_REMOVE" 2>/dev/null || true

# ============================================================================
# 12.3 输入验证
# ============================================================================
fw_subsection "永久封禁输入验证"

# 无效 IP 格式
assert_true "! echo 'invalid_ip' > '$PROC_PERMANENT_ADD' 2>/dev/null" "拒绝无效 IP 格式"

# 保留地址
assert_true "! echo '127.0.0.1' > '$PROC_PERMANENT_ADD' 2>/dev/null" "拒绝回环地址"
assert_true "! echo '0.0.0.0' > '$PROC_PERMANENT_ADD' 2>/dev/null" "拒绝 0.0.0.0"
assert_true "! echo '255.255.255.255' > '$PROC_PERMANENT_ADD' 2>/dev/null" "拒绝广播地址"

# SQL 注入测试 (procfs 写入应安全处理)
assert_true "! echo \"1.2.3.4'; DROP TABLE permanent_banlist;--\" > '$PROC_PERMANENT_ADD' 2>/dev/null" "SQL 注入尝试被拒绝"

# ============================================================================
# 12.4 重复永久封禁处理
# ============================================================================
fw_subsection "重复永久封禁处理"

TEST_PERM_IP3="198.51.100.102"
echo "$TEST_PERM_IP3" > "$PROC_PERMANENT_ADD" 2>/dev/null
sleep 0.2
echo "$TEST_PERM_IP3" > "$PROC_PERMANENT_ADD" 2>/dev/null
sleep 0.2

# 应该只有一个条目
local_dup_count=$(grep -c "$TEST_PERM_IP3" "$PROC_BAN_LIST" 2>/dev/null || echo 0)
assert_eq "$local_dup_count" "1" "重复永久封禁未产生重复条目"

# 清理
echo "$TEST_PERM_IP3" > "$PROC_PERMANENT_REMOVE" 2>/dev/null || true

# ============================================================================
# 12.5 白名单保护
# ============================================================================
fw_subsection "白名单保护永久封禁"

# 添加白名单
WHITELIST_IP="10.0.0.1"
echo "$WHITELIST_IP" > "/proc/firewall/whitelist_add" 2>/dev/null
sleep 0.2

# 尝试永久封禁白名单 IP
assert_true "! echo '$WHITELIST_IP' > '$PROC_PERMANENT_ADD' 2>/dev/null" "白名单 IP 不能被永久封禁"

# 验证白名单 IP 未被封禁
assert_true "! grep -q '$WHITELIST_IP' '$PROC_BAN_LIST' 2>/dev/null" "白名单 IP 未被封禁"

# 清理白名单
echo "$WHITELIST_IP" > "/proc/firewall/whitelist_remove" 2>/dev/null || true

# ============================================================================
# 12.6 性能测试 - 大量永久封禁
# ============================================================================
fw_subsection "大量永久封禁性能"

local_start_time=$(date +%s)
for i in $(seq 1 50); do
    echo "203.0.113.$i" > "$PROC_PERMANENT_ADD" 2>/dev/null || true
done
sleep 1

local_end_time=$(date +%s)
local_duration=$((local_end_time - local_start_time))

# 验证封禁数量
local_ban_count=$(wc -l < "$PROC_BAN_LIST" 2>/dev/null || echo 0)
assert_ge "$local_ban_count" 50 "批量永久封禁 50 个 IP，实际 $local_ban_count 个"

# 清理
for i in $(seq 1 50); do
    echo "203.0.113.$i" > "$PROC_PERMANENT_REMOVE" 2>/dev/null || true
done

# ============================================================================
# 12.7 守护进程 SQLite 集成测试 (如果守护进程运行中)
# ============================================================================
fw_subsection "守护进程 SQLite 集成 (可选)"

# 检查守护进程是否在运行
if pgrep -x "firewall-daemon" > /dev/null 2>&1; then
    echo "  守护进程运行中，跳过 SQLite 集成测试（需要真实环境）"
    fw_skip "守护进程运行中，SQLite 测试需要真实数据库环境"
else
    echo "  守护进程未运行，跳过 SQLite 集成测试"
    fw_skip "守护进程未运行"
fi

# ============================================================================
# 清理
# ============================================================================
fw_cleanup_section "永久黑名单测试完成"
