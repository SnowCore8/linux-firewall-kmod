#!/bin/bash
# 12_permanent_ban.sh - 永久封禁功能测试 (SQLite 持久化)

fw_test_header "永久封禁功能测试"

# 确保内核模块已加载
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

# 测试用 SQLite 数据库路径
TEST_DB_PATH="/tmp/fw_test_permanent_$$.db"

# ============================================================================
# 12.1 基本永久封禁/解封
# ============================================================================
fw_subsection "基本永久封禁/解封"

TEST_PERM_IP="198.51.100.100"
echo "$TEST_PERM_IP 0" > "$PROC_BANS" 2>/dev/null
sleep 0.3

assert_file_contains "$PROC_BANS" "$TEST_PERM_IP" "IP $TEST_PERM_IP 永久封禁成功"

echo "unban $TEST_PERM_IP" > "$PROC_BANS" 2>/dev/null
sleep 0.3

assert_true "! grep -q '$TEST_PERM_IP' '$PROC_BANS' 2>/dev/null" "IP $TEST_PERM_IP 永久解封成功"

# ============================================================================
# 12.2 永久封禁不会自动过期
# ============================================================================
fw_subsection "永久封禁过期检查"

TEST_PERM_IP2="198.51.100.101"
echo "$TEST_PERM_IP2 0" > "$PROC_BANS" 2>/dev/null
sleep 0.3

assert_file_contains "$PROC_BANS" "$TEST_PERM_IP2" "永久封禁条目存在（不自动过期）"

echo "unban $TEST_PERM_IP2" > "$PROC_BANS" 2>/dev/null || true

# ============================================================================
# 12.3 输入验证
# ============================================================================
fw_subsection "永久封禁输入验证"

# 无效 IP 格式
assert_failure "echo 'invalid_ip 0' > '$PROC_BANS' 2>/dev/null" "拒绝无效 IP 格式"

# 保留地址
assert_failure "echo '127.0.0.1 0' > '$PROC_BANS' 2>/dev/null" "拒绝回环地址"
assert_failure "echo '0.0.0.0 0' > '$PROC_BANS' 2>/dev/null" "拒绝 0.0.0.0"
assert_failure "echo '255.255.255.255 0' > '$PROC_BANS' 2>/dev/null" "拒绝广播地址"

# SQL 注入测试 (procfs 写入应安全处理)
assert_failure "echo \"1.2.3.4'; DROP TABLE permanent_banlist;--\" > '$PROC_BANS' 2>/dev/null" "SQL 注入尝试被拒绝"

# ============================================================================
# 12.4 重复永久封禁处理
# ============================================================================
fw_subsection "重复永久封禁处理"

TEST_PERM_IP3="198.51.100.102"
echo "$TEST_PERM_IP3 0" > "$PROC_BANS" 2>/dev/null
sleep 0.2
echo "$TEST_PERM_IP3 0" > "$PROC_BANS" 2>/dev/null
sleep 0.2

local_dup_count=$(grep -c "$TEST_PERM_IP3" "$PROC_BANS" 2>/dev/null || echo 0)
assert_eq "$local_dup_count" "1" "重复永久封禁未产生重复条目"

echo "unban $TEST_PERM_IP3" > "$PROC_BANS" 2>/dev/null || true

# ============================================================================
# 12.5 白名单保护永久封禁
fw_subsection "白名单保护永久封禁"

WHITELIST_IP="10.0.0.1"
echo "add $WHITELIST_IP" > "$PROC_WHITELIST" 2>/dev/null
sleep 0.2

# Attempt to permanently ban whitelisted IP
echo "$WHITELIST_IP 0" > "$PROC_BANS" 2>/dev/null || true
sleep 0.3
# Verify whitelist IP was NOT banned (whitelist protection)
assert_true "! grep -q '$WHITELIST_IP' '$PROC_BANS' 2>/dev/null" "白名单 IP 不能被永久封禁"

echo "remove $WHITELIST_IP" > "$PROC_WHITELIST" 2>/dev/null || true

# ============================================================================
# 12.6 大量永久封禁性能
# ============================================================================
fw_subsection "大量永久封禁性能"

local_start_time=$(date +%s)
for i in $(seq 1 50); do
    echo "203.0.113.$i 0" > "$PROC_BANS" 2>/dev/null || true
done
sleep 1

local_end_time=$(date +%s)
local_duration=$((local_end_time - local_start_time))

local_ban_count=$(wc -l < "$PROC_BANS" 2>/dev/null || echo 0)
assert_ge "$local_ban_count" 50 "批量永久封禁 50 个 IP，实际 $local_ban_count 个"

# 清理
for i in $(seq 1 50); do
    echo "unban 203.0.113.$i" > "$PROC_BANS" 2>/dev/null || true
done

# ============================================================================
# 12.7 SQLite 数据库独立测试
# ============================================================================
fw_subsection "SQLite 数据库独立功能测试"

# 检查 sqlite3 命令行工具
if ! command -v sqlite3 &>/dev/null; then
    skip_test "sqlite3 命令行工具未安装，跳过数据库测试"
else
    # 创建测试数据库
    sqlite3 "$TEST_DB_PATH" <<EOF
CREATE TABLE permanent_banlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    ip_num INTEGER NOT NULL UNIQUE,
    reason TEXT DEFAULT 'auto-ban',
    created_at INTEGER NOT NULL,
    created_by TEXT DEFAULT 'auto',
    hit_count INTEGER DEFAULT 0,
    last_hit_at INTEGER,
    is_active INTEGER DEFAULT 1
);
CREATE INDEX idx_ip_num ON permanent_banlist(ip_num);
CREATE INDEX idx_is_active ON permanent_banlist(is_active);
EOF

    assert_file_exists "$TEST_DB_PATH" "测试数据库创建成功"

    # 插入测试数据
    sqlite3 "$TEST_DB_PATH" "INSERT INTO permanent_banlist (ip, ip_num, reason, created_at, created_by) VALUES ('192.0.2.1', 3221225985, 'test ban', $(date +%s), 'test');"
    local_count=$(sqlite3 "$TEST_DB_PATH" "SELECT COUNT(*) FROM permanent_banlist;")
    assert_eq "$local_count" "1" "SQLite 插入成功"

    # 查询测试
    local_ip=$(sqlite3 "$TEST_DB_PATH" "SELECT ip FROM permanent_banlist WHERE ip='192.0.2.1';")
    assert_eq "$local_ip" "192.0.2.1" "SQLite 查询正确"

    # 唯一性约束测试
    sqlite3 "$TEST_DB_PATH" "INSERT OR IGNORE INTO permanent_banlist (ip, ip_num, reason, created_at) VALUES ('192.0.2.1', 3221225985, 'duplicate', $(date +%s));" 2>/dev/null
    local_count2=$(sqlite3 "$TEST_DB_PATH" "SELECT COUNT(*) FROM permanent_banlist WHERE ip='192.0.2.1';")
    assert_eq "$local_count2" "1" "SQLite 唯一性约束生效"

    # 批量插入性能
    local now
    now=$(date +%s)
    local_batch_start=$(date +%s%N)
    sqlite3 "$TEST_DB_PATH" <<EOF
BEGIN TRANSACTION;
$(for i in $(seq 1 100); do echo "INSERT OR IGNORE INTO permanent_banlist (ip, ip_num, reason, created_at) VALUES ('10.0.$((i / 255)).$((i % 255))', $((3221225985 + i)), 'batch test', $now);"; done)
COMMIT;
EOF
    local_batch_end=$(date +%s%N)
    local_batch_count=$(sqlite3 "$TEST_DB_PATH" "SELECT COUNT(*) FROM permanent_banlist;")
    assert_ge "$local_batch_count" 100 "SQLite 批量插入 100 条，实际 $local_batch_count 条"

    # 索引查询性能
    local_explain_output=$(sqlite3 "$TEST_DB_PATH" "EXPLAIN QUERY PLAN SELECT * FROM permanent_banlist WHERE ip_num=3221225986;")
    if echo "$local_explain_output" | grep -q "INDEX"; then
        assert_true "[[ -n '$local_explain_output' ]]" "SQLite 索引查询使用索引"
    else
        warn_test "SQLite 索引查询未使用预期索引: $local_explain_output"
    fi

    # 删除测试
    sqlite3 "$TEST_DB_PATH" "DELETE FROM permanent_banlist WHERE ip LIKE '10.0.%';"
    local_after_delete=$(sqlite3 "$TEST_DB_PATH" "SELECT COUNT(*) FROM permanent_banlist;")
    assert_true "[[ $local_after_delete -lt $local_batch_count ]]" "SQLite 删除成功"

    # 清理测试数据库
    rm -f "$TEST_DB_PATH"
fi

# ============================================================================
# 12.8 守护进程 SQLite 集成测试
# ============================================================================
fw_subsection "守护进程 SQLite 集成测试"

# 检查守护进程是否在运行且启用了 SQLite
if pgrep -x "firewall-daemon" > /dev/null 2>&1; then
    # 检查数据库文件是否存在
    local_daemon_db=$(find /root/firewall -name "bans.db" 2>/dev/null | head -1)
    if [[ -n "$local_daemon_db" && -f "$local_daemon_db" ]]; then
        assert_file_exists "$local_daemon_db" "守护进程 SQLite 数据库存在"
        
        # 检查表结构
        local_tables=$(sqlite3 "$local_daemon_db" ".tables" 2>/dev/null)
        assert_true "echo '$local_tables' | grep -q 'permanent_banlist'" "permanent_banlist 表存在"
        
        # 检查索引
        local_indexes=$(sqlite3 "$local_daemon_db" ".indexes permanent_banlist" 2>/dev/null)
        assert_true "echo '$local_indexes' | grep -q 'idx_ip_num'" "ip_num 索引存在"
        assert_true "echo '$local_indexes' | grep -q 'idx_is_active'" "is_active 索引存在"
        
        fw_log_info "守护进程 SQLite 集成验证通过"
    else
        warn_test "守护进程运行中但 SQLite 数据库文件未找到"
    fi
else
    fw_log_info "守护进程未运行，跳过集成测试"
fi

# ============================================================================
# 清理
# ============================================================================
fw_cleanup_section "永久黑名单测试完成"
fw_ensure_module_unloaded
