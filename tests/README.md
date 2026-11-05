# 测试系统文档

本目录包含 linux-firewall-kmod 项目的 Python 集成测试。

## 目录结构

```
tests/
├── __init__.py              # 包标识
├── config.py                # 测试配置常量（路径、IP、参数）
├── conftest.py              # pytest fixtures 和辅助函数
├── requirements.txt         # Python 测试依赖
├── README.md                # 本文档
│
├── test_01_module_lifecycle.py    # 模块装卸测试
├── test_02_procfs_interface.py    # Procfs 接口测试
├── test_03_ban_unban.py           # 封禁/解封测试
├── test_04_whitelist.py           # 白名单测试
├── test_07_concurrency.py         # 并发/竞态条件测试
├── test_08_stress_perf.py         # 压力/性能测试
├── test_09_daemon_config.py       # 守护进程配置测试
├── test_10_daemon_logparse.py     # 日志解析测试
├── test_11_resource_mgmt.py       # 资源管理测试
├── test_12_permanent_ban.py       # 永久封禁测试
├── test_13_frp_jail.py            # FRP Jail 配置测试
├── test_14_ban_netfilter.py       # Netfilter 封禁测试
├── test_15_ddos_detection.py      # DDoS 检测测试
├── test_16_webui_api.py           # Web UI API 端到端测试
├── test_17_config_reload.py       # 配置热重载测试
├── test_18_log_rotation.py        # 日志轮转检测
├── test_19_netlink_comm.py        # Netlink 通信与健康指标
├── test_20_daemon_lifecycle.py    # 守护进程生命周期
├── test_21_multi_jail.py          # 多 Jail 并发测试
└── test_22_cluster_scan.py        # 集群扫描检测
```

### 编号规则

- 编号 05/06 不使用；编号一旦分配就不再重排，避免破坏已有引用。
- 新增测试文件继续递增编号（从 23 开始）。

## 运行测试

### 前置条件

1. **root 权限**: 测试需要加载内核模块、操作 procfs
2. **构建产物**: `build/kernel-module/firewall.ko` 和 `build/daemon/firewall-daemon`
3. **Python 依赖**: `pip install -r tests/requirements.txt`

### 基本运行

```bash
# 运行所有测试（需要 root）
sudo python3 -m pytest tests/ -v

# 使用 Makefile 目标（自动构建依赖）
make test
```

### 按标记运行

```bash
# 只运行慢测试
sudo python3 -m pytest -m slow

# 跳过需要外部 daemon 的测试
sudo python3 -m pytest -m "not requires_daemon"

# 只运行需要内核模块的测试
sudo python3 -m pytest -m requires_module

# 只运行压力测试
sudo python3 -m pytest -m stress
```

### 生成报告

```bash
# JUnit XML（CI 使用）
sudo python3 -m pytest --junitxml=junit.xml

# HTML 报告
sudo python3 -m pytest --html=report.html --self-contained-html
```

## 测试标记

| 标记 | 说明 | 示例文件 |
|------|------|----------|
| `slow` | 运行时间超过 10 秒 | test_08_stress_perf.py |
| `requires_daemon` | 需要外部 daemon 运行 | test_15/16/17/19 |
| `requires_module` | 需要内核模块加载 | 大多数测试 |
| `requires_sqlite3` | 需要 sqlite3 CLI | test_12_permanent_ban.py |
| `stress` | 压力测试 | test_08_stress_perf.py |
| `perf` | 性能测试（阈值敏感） | test_08_stress_perf.py |

## 测试架构

### Fixture 层次

1. **session_setup** (scope="session", autouse)
   - 检查 root 权限、内核模块文件存在、加载模块
   - teardown: 重置数据 + 卸载模块

2. **test_isolation** (autouse, 每个用例)
   - setup: 重置数据 + 检查/加载模块
   - teardown: 清理状态 + 释放内核租约

3. **clean_bans** (显式使用)
   - 提供干净的封禁状态（与 test_isolation 有重叠，保留给显式调用的用例）

4. **共享 fixture** (conftest.py)
   - `check_daemon`: 检查 daemon 二进制存在
   - `running_daemon`: 确保有 daemon 在运行

### 内核租约卫生机制

内核模块对 daemon 有 30 秒租约（防止多 daemon 竞争）。测试系统通过以下机制保证卫生：

1. `mark_daemon_launched()`: 所有 daemon 启动点必须调用
2. `release_kernel_lease()`: teardown 时重载模块，清空租约
3. `terminate_process()`: SIGTERM → wait → SIGKILL 的优雅停止

### 两种测试形态

1. **daemon-up**: 假设外部已有 daemon 运行（test_15/16/17/19）
   - 使用 `running_daemon` fixture
   - 外部 daemon 不存在时 skip

2. **daemon-down**: 自行起 daemon（test_09-14, 18, 20-22）
   - 使用 `daemon_starts_ok` / `run_daemon_captured` 等辅助函数
   - 短时启动 daemon，测试完立即停止

## 配置常量

`config.py` 定义了所有测试配置：

- **路径**: `KERNEL_MODULE_PATH`, `DAEMON_PATH`, `CONFIG_DIR`, `PROC_*`
- **测试 IP**: `TEST_IP`, `TEST_IP2`, 特殊 IP（INVALID_IP, LOCALHOST_IP 等）
- **参数**: 超时、同步延迟、压力测试数量、性能阈值
- **日志数据**: `LOG_LINE_SSHD`, `LOG_LINE_VSFTPD` 等预定义日志行

## CI 集成

GitHub Actions (`.github/workflows/ci.yml`) 中的测试流程：

1. 安装依赖: `build-essential`, `linux-headers`, `python3-pytest`, `python3-yaml`
2. 针对本机内核重编 `firewall.ko`（CI runner 内核与本地不同）
3. 运行完整测试: `sudo python3 -m pytest tests/ -v --tb=short`
4. 降级模式（模块不兼容时）: `-k "daemon or logparse or ..."`
5. 上传测试报告为 artifact

## 常见问题

### Q: 测试失败 "模块未加载"

A: 确保以 root 运行，且 `build/kernel-module/firewall.ko` 存在。测试会自动加载模块。

### Q: 测试跳过 "守护进程不存在"

A: 先运行 `make daemon` 构建守护进程二进制。

### Q: 性能测试不稳定

A: 性能阈值硬编码在 `config.py`，不同机器可能差异大。可调整 `BAN_PERF_THRESHOLD_MS` 等参数。

### Q: 如何添加新测试

A:
1. 创建 `test_XX_<feature>.py`（XX 为下一个编号，从 23 开始）
2. 使用类组织: `class Test<Feature>:`
3. 添加适当的标记: `@pytest.mark.requires_daemon` 等
4. 使用 `clean_bans` fixture 确保干净状态（如需要）
5. 在 `conftest.py` 中添加必要的辅助函数
