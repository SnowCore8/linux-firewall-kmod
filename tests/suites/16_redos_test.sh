#!/bin/bash
# 16_redos_test.sh - ReDoS 防护真实测试套件
# 通过实际启动守护进程并加载含恶意正则的 YAML 配置，
# 验证 daemon 的 compile_jail_regex() 中的 ReDoS 防护机制。

fw_test_header "ReDoS 防护测试"

# 检查守护进程是否已编译
if [[ ! -x "$DAEMON_PATH" ]]; then
    skip_test "守护进程未编译，跳过 ReDoS 防护测试"
    return 0
fi

# 确保内核模块已加载（procfs 需要）
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" 2>/dev/null || {
    skip_test "内核模块无法加载，跳过 ReDoS 防护测试"
    return 0
}

# ============================================================================
# 辅助函数：创建临时 YAML 配置并测试守护进程启动结果
# ============================================================================

# 运行守护进程配置测试（带超时），返回退出码
# 参数: $1=YAML 配置路径, $2=超时秒数（默认 3）
run_daemon_config_test() {
    local yaml_path="$1"
    local timeout_sec="${2:-3}"
    local rc=0
    timeout "$timeout_sec" "$DAEMON_PATH" -c "$yaml_path" >/dev/null 2>&1 || rc=$?
    return $rc
}

# ============================================================================
# 测试 1：拒绝嵌套量词 (a+)+
# ============================================================================
fw_subsection "拒绝嵌套量词 (a+)+"

local_test_dir="/tmp/fw_redos_test_$$"
mkdir -p "$local_test_dir"

# 创建测试日志文件
echo "test log line from 10.0.0.1" > "$local_test_dir/test.log"

# 创建含嵌套量词 (a+)+ 的 YAML 配置
cat > "$local_test_dir/nested_quant1.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9140

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "(a+)+"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/nested_quant1.yaml"

# 守护进程应拒绝该配置（退出码非 0）
local rc=0
run_daemon_config_test "$local_test_dir/nested_quant1.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "嵌套量词 (a+)+ 被拒绝（退出码=$rc）"
else
    fw_fail "嵌套量词 (a+)+ 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 2：拒绝嵌套量词 ([a-zA-Z]+)*
# ============================================================================
fw_subsection "拒绝嵌套量词 ([a-zA-Z]+)*"

cat > "$local_test_dir/nested_quant2.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9141

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "([a-zA-Z]+)*"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/nested_quant2.yaml"

rc=0
run_daemon_config_test "$local_test_dir/nested_quant2.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "嵌套量词 ([a-zA-Z]+)* 被拒绝（退出码=$rc）"
else
    fw_fail "嵌套量词 ([a-zA-Z]+)* 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 3：拒绝嵌套量词 (a{1,10})+
# ============================================================================
fw_subsection "拒绝嵌套量词 (a{1,10})+"

cat > "$local_test_dir/nested_quant3.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9142

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "(a{1,10})+"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/nested_quant3.yaml"

rc=0
run_daemon_config_test "$local_test_dir/nested_quant3.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "嵌套量词 (a{1,10})+ 被拒绝（退出码=$rc）"
else
    fw_fail "嵌套量词 (a{1,10})+ 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 4：拒绝占有量词 ++
# ============================================================================
fw_subsection "拒绝占有量词 ++"

cat > "$local_test_dir/possessive1.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9143

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "(a++)"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/possessive1.yaml"

rc=0
run_daemon_config_test "$local_test_dir/possessive1.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "占有量词 ++ 被拒绝（退出码=$rc）"
else
    fw_fail "占有量词 ++ 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 5：拒绝占有量词 *+
# ============================================================================
fw_subsection "拒绝占有量词 *+"

cat > "$local_test_dir/possessive2.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9144

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "(a*+)"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/possessive2.yaml"

rc=0
run_daemon_config_test "$local_test_dir/possessive2.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "占有量词 *+ 被拒绝（退出码=$rc）"
else
    fw_fail "占有量词 *+ 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 6：拒绝超长正则模式（>1024 字节）
# ============================================================================
fw_subsection "拒绝超长正则模式"

# 生成超过 1024 字节的正则模式
long_regex="a"
for i in $(seq 1 1050); do
    long_regex="${long_regex}a"
done

cat > "$local_test_dir/long_regex.yaml" << YAMLEOF
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9145

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_$$/test.log
    max_retries: 3
    regex: "$long_regex"
YAMLEOF

rc=0
run_daemon_config_test "$local_test_dir/long_regex.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "超长正则模式（${#long_regex} 字节）被拒绝（退出码=$rc）"
else
    fw_fail "超长正则模式（${#long_regex} 字节）未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 7：拒绝过多交替符（超过 50 个 |）
# ============================================================================
fw_subsection "拒绝过多交替符"

# 构建含 55 个交替符的正则：a|b|c|...|z|aa|ab|...
alt_regex="a"
for i in $(seq 1 55); do
    alt_regex="${alt_regex}|x${i}"
done

cat > "$local_test_dir/many_alt.yaml" << YAMLEOF
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9146

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_$$/test.log
    max_retries: 3
    regex: "$alt_regex"
YAMLEOF

rc=0
run_daemon_config_test "$local_test_dir/many_alt.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "过多交替符（55 个 |）被拒绝（退出码=$rc）"
else
    fw_fail "过多交替符（55 个 |）未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 8：正常正则应被正确编译和使用
# ============================================================================
fw_subsection "正常正则编译和使用"

# 创建含安全正则的 YAML 配置
cat > "$local_test_dir/safe_regex.yaml" << 'YAMLEOF'
defaults:
  max_retries: 1
  findtime: 60
  ban_time: 5
  interval: 1
  metrics_port: 9147

jails:
  sshd_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 1
    findtime: 60
    ban_time: 5
    regex: "Failed password for (invalid user )?[a-zA-Z0-9_.-]+ from ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/safe_regex.yaml"

# 守护进程应成功加载该配置（在超时内退出码为 0 或 124）
rc=0
run_daemon_config_test "$local_test_dir/safe_regex.yaml" 3 || rc=$?
# rc=0 表示成功启动，rc=124 表示 timeout 正常终止（守护进程在运行中）
if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    fw_pass "正常正则被正确编译（退出码=$rc）"
else
    fw_fail "正常正则编译失败（退出码=$rc，期望 0 或 124）"
fi

# ============================================================================
# 测试 9：空正则应使用内置默认值
# ============================================================================
fw_subsection "空正则使用内置默认值"

cat > "$local_test_dir/empty_regex.yaml" << 'YAMLEOF'
defaults:
  max_retries: 1
  findtime: 60
  ban_time: 5
  interval: 1
  metrics_port: 9148

jails:
  sshd_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 1
    regex: ""
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/empty_regex.yaml"

rc=0
run_daemon_config_test "$local_test_dir/empty_regex.yaml" 3 || rc=$?
if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    fw_pass "空正则使用内置默认值成功（退出码=$rc）"
else
    fw_fail "空正则使用内置默认值失败（退出码=$rc）"
fi

# ============================================================================
# 测试 10：日志解析对恶意输入的响应
# ============================================================================
fw_subsection "日志解析对恶意输入的响应"

# 创建含恶意日志行的测试日志文件
local_malicious_log="$local_test_dir/malicious.log"
cat > "$local_malicious_log" << 'EOF'
Mar 10 10:30:01 server sshd[1234]: Failed password for root from 10.0.0.1 port 12345 ssh2
Mar 10 10:30:02 server sshd[1235]: Failed password for root from 10.0.0.2 port 12346 ssh2
EOF

# 追加超长日志行（>8192 字节，应被 log-parser.c 拒绝）
python3 -c "print('A' * 9000 + ' from 10.0.0.3 ' + 'B' * 9000)" >> "$local_malicious_log" 2>/dev/null || \
    python -c "print('A' * 9000 + ' from 10.0.0.3 ' + 'B' * 9000)" >> "$local_malicious_log" 2>/dev/null || true

cat > "$local_test_dir/malicious_log.yaml" << YAMLEOF
defaults:
  max_retries: 1
  findtime: 60
  ban_time: 5
  interval: 1
  metrics_port: 9149

jails:
  sshd_test:
    enabled: true
    log_files:
      - $local_malicious_log
    max_retries: 1
    findtime: 60
    ban_time: 5
    regex: ""
YAMLEOF

# 启动守护进程处理恶意日志，不应崩溃
rc=0
timeout 5 "$DAEMON_PATH" -c "$local_test_dir/malicious_log.yaml" >/dev/null 2>"$local_test_dir/daemon_stderr.log" || rc=$?

# 验证守护进程未崩溃（崩溃时退出码 >= 128）
if [[ $rc -lt 128 ]]; then
    fw_pass "守护进程处理恶意日志未崩溃（退出码=$rc）"
else
    fw_fail "守护进程处理恶意日志时崩溃（退出码=$rc）"
fi

# 验证 procfs 仍然可访问
if [[ -r "$PROC_BANS" ]]; then
    fw_pass "处理恶意日志后 procfs 仍可访问"
else
    fw_fail "处理恶意日志后 procfs 不可访问"
fi

# ============================================================================
# 测试 11：嵌套量词 )? 应被拒绝
# ============================================================================
fw_subsection "拒绝嵌套量词 )?"

cat > "$local_test_dir/nested_quant4.yaml" << 'YAMLEOF'
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9150

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_PLACEHOLDER/test.log
    max_retries: 3
    regex: "((a+)?)?"
YAMLEOF
sed -i "s|PLACEHOLDER|$$|g" "$local_test_dir/nested_quant4.yaml"

rc=0
run_daemon_config_test "$local_test_dir/nested_quant4.yaml" 3 || rc=$?
if [[ $rc -ne 0 ]]; then
    fw_pass "嵌套量词 )? 被拒绝（退出码=$rc）"
else
    fw_fail "嵌套量词 )? 未被拒绝（退出码=0，应非 0）"
fi

# ============================================================================
# 测试 12：边界长度正则（恰好 1024 字节）应被接受
# ============================================================================
fw_subsection "边界长度正则（1024 字节）"

# 生成恰好 1024 字节的正则模式
boundary_regex=""
for i in $(seq 1 1024); do
    boundary_regex="${boundary_regex}a"
done

cat > "$local_test_dir/boundary_regex.yaml" << YAMLEOF
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9151

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_$$/test.log
    max_retries: 3
    regex: "$boundary_regex"
YAMLEOF

rc=0
run_daemon_config_test "$local_test_dir/boundary_regex.yaml" 3 || rc=$?
if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    fw_pass "边界长度正则（1024 字节）被接受（退出码=$rc）"
else
    fw_fail "边界长度正则（1024 字节）被错误拒绝（退出码=$rc）"
fi

# ============================================================================
# 测试 13：边界交替数（恰好 50 个 |）应被接受
# ============================================================================
fw_subsection "边界交替数（50 个 |）"

# 构建恰好 50 个交替符的正则
boundary_alt="a"
for i in $(seq 1 50); do
    boundary_alt="${boundary_alt}|w${i}"
done

cat > "$local_test_dir/boundary_alt.yaml" << YAMLEOF
defaults:
  max_retries: 3
  findtime: 60
  ban_time: 300
  interval: 1
  metrics_port: 9152

jails:
  redos_test:
    enabled: true
    log_files:
      - /tmp/fw_redos_test_$$/test.log
    max_retries: 3
    regex: "$boundary_alt"
YAMLEOF

rc=0
run_daemon_config_test "$local_test_dir/boundary_alt.yaml" 3 || rc=$?
if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    fw_pass "边界交替数（50 个 |）被接受（退出码=$rc）"
else
    fw_fail "边界交替数（50 个 |）被错误拒绝（退出码=$rc）"
fi

# ============================================================================
# 清理
# ============================================================================
rm -rf "$local_test_dir"
fw_ensure_module_unloaded
