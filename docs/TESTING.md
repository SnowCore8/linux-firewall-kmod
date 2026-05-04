# Firewall 测试框架文档

**版本**: v2.0 | **更新日期**: 2026-05-04

## 1. 测试概览

项目采用模块化 Bash 测试框架，共 **147 项测试**，**16 个测试套件**，覆盖内核模块、守护进程、安全防护和性能等关键领域。

**覆盖范围**：模块加载/卸载、Procfs 接口、IP 封禁/解封、白名单管理、输入验证、安全加固（注入/溢出/路径/ReDoS）、并发安全、压力性能、YAML 配置加载、日志解析、资源管理、永久封禁持久化。

---

## 2. 测试套件列表

### 基础功能类

| 编号 | 套件名称 | 测试数 | 类别 | 说明 |
|------|----------|--------|------|------|
| 01 | `module_basic` | 10 | basic | 模块加载/卸载、参数验证、重复加载保护 |
| 02 | `procfs_interface` | 8 | basic | Procfs 接口读写、格式验证 |
| 03 | `ban_unban` | 10 | basic | 基本封禁/解封、批量操作、循环稳定性 |
| 04 | `whitelist` | 8 | basic | 白名单添加/移除、IP/子网支持 |

### 安全类

| 编号 | 套件名称 | 测试数 | 类别 | 说明 |
|------|----------|--------|------|------|
| 05 | `input_validation` | 10 | security | 无效 IP、边界值、格式验证 |
| 06 | `security` | 12 | security | 命令注入、procfs 权限、模块参数安全 |
| 14 | `integer_overflow` | 8 | security | 整数溢出防护、乘法溢出检测 |
| 15 | `path_traversal` | 6 | security | 路径穿越攻击防护、纵深防御 |
| 16 | `redos_test` | 5 | security | ReDoS 防护、正则安全检查 |

### 守护进程类

| 编号 | 套件名称 | 测试数 | 类别 | 说明 |
|------|----------|--------|------|------|
| 09 | `daemon_config` | 10 | daemon | YAML 配置加载、目录加载、无效配置处理 |
| 10 | `daemon_logparse` | 10 | daemon | 日志解析（sshd/vsftpd/nginx/frp） |
| 13 | `frp_jail` | 8 | daemon | FRP Jail 隔离、独立配置验证 |

### 性能与资源类

| 编号 | 套件名称 | 测试数 | 类别 | 说明 |
|------|----------|--------|------|------|
| 07 | `concurrency` | 10 | performance | 并发访问安全、竞态条件检测 |
| 08 | `stress_perf` | 10 | performance | 封禁/解封性能、压力测试、哈希碰撞 |
| 11 | `resource_mgmt` | 10 | resource | 资源管理、内存安全、泄漏检测 |
| 12 | `permanent_ban` | 12 | resource | SQLite 持久化、重启恢复、数据库完整性 |

---

## 3. 运行测试

```bash
# 运行所有测试（推荐）
make test
sudo ./tests/run_tests.sh

# 运行单个测试套件
sudo ./tests/run_tests.sh --suite 03        # 封禁/解封
sudo ./tests/run_tests.sh --suite 09        # 守护进程配置

# 按类别运行
sudo ./tests/run_tests.sh --category security   # 安全测试（05/06/14/15/16）
sudo ./tests/run_tests.sh --category daemon     # 守护进程（09/10/13）
sudo ./tests/run_tests.sh --category performance # 性能（07/08）
sudo ./tests/run_tests.sh --category basic      # 基础（01/02/03/04）

# 生成测试报告
sudo ./tests/run_tests.sh --report

# 调试模式（显示 [DEBUG] 日志）
sudo ./tests/run_tests.sh --debug

# 旧测试脚本兼容
make test-legacy

# 查看帮助
sudo ./tests/run_tests.sh --help
```

**注意事项**：
- 测试需要 root 权限运行
- 运行前自动编译内核模块和守护进程（如未编译）
- 测试模式仅加载/卸载模块，不安装到系统

---

## 4. 测试框架说明

### 4.1 核心文件

| 文件 | 职责 |
|------|------|
| `test_framework.sh` | 断言函数、彩色输出、统计汇总、报告生成、清理机制 |
| `test_config.sh` | 路径配置、测试 IP、超时参数、YAML/日志样本 |
| `run_tests.sh` | 统一入口、参数解析、预检、套件调度 |

### 4.2 断言函数

| 函数 | 用途 | 示例 |
|------|------|------|
| `assert_true` | 条件为真 | `assert_true "[[ -f 'file' ]]" "文件存在"` |
| `assert_false` | 条件为假 | `assert_false "[[ -d 'dir' ]]" "目录不存在"` |
| `assert_success` | 命令退出码为 0 | `assert_success "cmd" "执行成功"` |
| `assert_failure` | 命令退出码非 0 | `assert_failure "bad_cmd" "被拒绝"` |
| `assert_file_exists` | 文件存在 | `assert_file_exists "/path/to/file"` |
| `assert_dir_exists` | 目录存在 | `assert_dir_exists "/path/to/dir"` |
| `assert_file_contains` | 文件包含内容 | `assert_file_contains "log" "ERROR"` |
| `assert_contains` | 字符串包含子串 | `assert_contains "$out" "expected"` |
| `assert_eq` | 值相等 | `assert_eq "$actual" "expected"` |
| `assert_ge` / `assert_le` | 数值比较 | `assert_le "$time" 5000 "耗时 <= 5s"` |

**辅助函数**：`warn_test`（警告）、`skip_test`（跳过）、`fw_pass`（显式通过）、`fw_fail`（显式失败）

### 4.3 模块管理

```bash
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"              # 加载模块
fw_ensure_module_loaded "$KERNEL_MODULE_PATH" "param=val"  # 带参数加载
fw_ensure_module_unloaded                                  # 卸载模块
```

### 4.4 清理机制

通过 `trap fw_cleanup EXIT` 注册清理函数，测试结束后自动：
1. 卸载内核模块（`rmmod firewall`）
2. 删除临时文件（`/tmp/fw_test_*.log/tmp/yaml`）
3. 严格检查并清理被安装到系统的模块和守护进程

---

## 5. 编写新测试

### 5.1 添加测试套件

1. 在 `tests/suites/` 创建 `XX_name.sh`（XX 为两位编号）
2. 在 `run_tests.sh` 的 `SUITE_FILES` 和 `SUITE_CATEGORIES` 中添加映射
3. 使用框架断言函数编写测试

### 5.2 命名规范

- 套件文件：`XX_short_name.sh`（如 `03_ban_unban.sh`）
- 测试小节：`fw_subsection "描述"`
- 断言消息：简洁描述预期结果

### 5.3 示例

```bash
#!/bin/bash
# tests/suites/XX_example.sh

fw_test_header "示例测试"
fw_ensure_module_loaded "$KERNEL_MODULE_PATH"

fw_subsection "基本功能"
assert_success "cat '$PROC_DIR/stats'" "stats 接口可读"
assert_file_contains "$PROC_DIR/stats" "bans" "包含 bans 字段"

fw_subsection "边界条件"
assert_failure "echo 'invalid' > '$PROC_BANS' 2>&1" "无效输入被拒绝"

fw_ensure_module_unloaded
```

---

## 6. 测试报告

### 6.1 生成与位置

```bash
sudo ./tests/run_tests.sh --report
# 报告输出：tests/reports/test_report.md
```

### 6.2 报告格式

Markdown 格式，包含：生成时间戳、汇总统计表、详细结果列表（按套件分组）、最终结论。

### 6.3 状态说明

| 图标 | 状态 | 说明 |
|------|------|------|
| ✅ | PASS | 测试通过 |
| ❌ | FAIL | 测试失败（需修复） |
| ⚠️ | WARN | 警告（非阻塞） |
| ⏭️ | SKIP | 跳过（条件不满足） |

### 6.4 失败排查

1. 查看 `[FAIL]` 输出的错误消息
2. 使用 `--debug` 模式获取详细日志
3. 检查对应测试套件文件中的断言逻辑
4. 确认内核模块和守护进程已正确编译
