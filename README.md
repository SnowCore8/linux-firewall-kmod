# Firewall

**版本**: v1.8（库替换 + 代码重构 + 测试扩展）

Firewall 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

## 特性

- ✅ 内核态 IP 封禁（netfilter hooks，比 iptables 用户态规则更高效）
- ✅ **Jail 系统** - 类似 fail2ban 的多服务隔离配置
- ✅ 哈希表存储封禁 IP（1024 容量，O(1) 查找）
- ✅ 自动过期清理机制
- ✅ IP 白名单保护（自动发现系统 IP + 手动添加，64 容量）
- ✅ 通过 procfs 的用户接口
- ✅ 可配置的封禁持续时间
- ✅ 纯 IPv4 支持
- ✅ C 语言用户态守护进程（无 Python 依赖）
  - Jail 级别独立配置（max_retries / findtime / ban_time）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）
- ✅ 统一分级日志系统（fw_pr_err/warn/info/debug）
- ✅ RCU 并发安全 + spinlock 保护
- ✅ 状态持久化（保存/恢复封禁和白名单）
- ✅ 输入验证和边界检查
- ✅ **v1.8 库替换与重构**
  - HTTP 服务器 → libmicrohttpd（-330行，RFC合规）
  - POSIX Regex → PCRE2（JIT加速，内置超时）
  - Ban/Unban 函数族统一（-75行）
  - 单 `make` 编译全部
- ✅ **v1.7 安全加固**
  - 整数溢出防护（`check_mul_overflow()` 全面覆盖）
  - SQLite use-after-free 修复（`SQLITE_TRANSIENT`）
  - 路径遍历纵深防御（多层验证）
  - ReDoS 防护（自定义 regex 安全检查）
  - HTTP Exporter 加固
  - YAML 解析边界防护
- ✅ 安全编译选项（-fstack-protector-strong, -D_FORTIFY_SOURCE=2, PIE）
- ✅ systemd 安全加固（NoNewPrivileges, ProtectSystem=strict 等 15 项）

## 快速开始

### 编译

```bash
# 编译两者（内核模块 + 守护进程）
make all-with-daemon

# 仅编译内核模块
make kernel-module

# 仅编译守护进程
make daemon

# 清理构建产物
make clean
```

### 加载模块

```bash
# 加载内核模块（带参数）
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600

# 查看配置
cat /proc/firewall/config

# 卸载模块
sudo rmmod firewall
```

### 基本操作

```bash
# 查看封禁列表
cat /proc/firewall/bans

# 临时封禁 IP（使用默认 ban_time）
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# 自定义时长封禁
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans    # 封禁 1 小时
echo "1.2.3.4 86400" | sudo tee /proc/firewall/bans   # 封禁 1 天

# 永久封禁（0 表示永久）
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# 解封 IP
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 查看白名单
cat /proc/firewall/whitelist

# 添加白名单（支持 IP 和子网）
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist
echo "add 192.168.1.0/24" | sudo tee /proc/firewall/whitelist

# 移除白名单
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist

# 运行时修改配置（目前仅支持 ban_time）
echo "ban_time 1200" | sudo tee /proc/firewall/config
```

### 启动守护进程

```bash
# 使用配置文件启动（推荐，加载 config/ 目录下所有 .yaml）
sudo ./build/daemon/firewall-daemon

# 指定配置目录
sudo ./build/daemon/firewall-daemon -C /etc/firewall/

# 指定单个配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 查看帮助
sudo ./build/daemon/firewall-daemon --help
```

## 配置说明

### 模块参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 封禁持续时间（秒） | 600 (10分钟) |

**注意**：`max_retries`（触发封禁的失败次数）和 `findtime`（失败记录时间窗口）是**守护进程参数**，在内核模块中不使用。这些参数在守护进程启动时通过 `-m` 和 `-f` 选项或 YAML 配置文件设置。

### 守护进程参数

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml --daemonize
```

| 参数 | 说明 | 默认值 | 状态 |
|------|------|--------|------|
| `-c` | 配置文件路径 | - | ✅ 推荐使用 |
| `-C` | 配置目录路径 | ./config/ 或 /etc/firewall/ | ✅ 推荐使用 |
| `-d`, `--daemonize` | 后台运行模式 | false | ✅ 生产环境推荐 |
| `-h`, `--help` | 显示帮助信息 | - | - |

**注意**：所有封禁策略参数（`max_retries`、`findtime`、`ban_time`、`interval`、`metrics_port`）必须通过 YAML 配置文件设置，不支持命令行参数。

### 配置文件

守护进程支持 YAML 配置文件，使用 Jail 系统实现多服务隔离：

**配置目录（推荐）**

默认情况下，守护进程会自动加载 `./config/` 或 `/etc/firewall/` 目录下的所有 `.yaml` / `.yml` 文件：

```
config/
├── default.yaml          # 默认配置（sshd 防护）
└── custom.yaml           # 其他自定义 jail
```

```bash
# 自动加载默认目录
sudo ./build/daemon/firewall-daemon

# 指定配置目录
sudo ./build/daemon/firewall-daemon -C /etc/firewall/
```

**单个配置文件**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

**新 Jail 配置格式**：

```yaml
# 全局默认值（所有 jail 共享）
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

# Jail 定义（每个服务独立监控）
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
      - /var/log/secure
    max_retries: 5        # 覆盖 defaults
    findtime: 600         # 覆盖 defaults
    ban_time: 900         # 覆盖 defaults
    regex: ""             # 空字符串使用内置 sshd 模式

  frp:
    enabled: true
    log_files:
      - /var/log/frp/frp.log
    max_retries: 10
    findtime: 300
    ban_time: 1800
    regex: ".*\\[E\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"

  # 可以添加更多 jail...
  # nginx:
  #   enabled: true
  #   log_files: [/var/log/nginx/error.log]
  #   max_retries: 3
  #   ban_time: 3600

# 永久封禁配置（SQLite 持久化）
permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

**关键特性**：
- 每个 Jail 独立监控自己的日志文件
- 每个 Jail 有独立的失败计数器和封禁阈值
- 多配置文件可定义不同的 Jail，不会互相覆盖
- Jail 未指定的参数使用 `defaults` 中的全局默认值

### procfs 接口

| 路径 | 功能 |
|------|------|
| `/proc/firewall/bans` | 查看封禁列表（读）；临时/自定义时长/永久封禁 IP（写 `IP` 或 `IP seconds`）；解封 IP（写 `unban IP`） |
| `/proc/firewall/whitelist` | 查看白名单（读）；添加白名单（写 `CIDR` 或 `add CIDR`）；移除白名单（写 `remove CIDR`） |
| `/proc/firewall/config` | 查看/修改运行时配置（读写） |
| `/proc/firewall/stats` | 查看统计信息（只读） |

## 日志系统

内核模块使用统一分级日志系统，所有日志以 `firewall: ` 为前缀。

### 日志级别

| 级别 | 宏 | 说明 |
|------|-----|------|
| ERR (1) | `fw_pr_err()` | 错误日志，始终输出 |
| WARN (2) | `fw_pr_warn()` | 警告日志，重要警告 |
| INFO (3) | `fw_pr_info()` | 信息日志，正常操作 |
| DEBUG (4) | `fw_pr_debug()` | 调试日志，开发调试 |

### 编译控制

通过 `DEBUG_LEVEL` 参数控制调试日志输出（0-4）：

```bash
# 关闭调试日志
make kernel-module DEBUG_LEVEL=0

# 开启调试日志
make debug3  # 等价于 DEBUG_LEVEL=3
```

### 限流保护

高频日志使用限流变体，防止日志风暴：

```c
fw_pr_info_ratelimited("high frequency message")
fw_pr_warn_ratelimited("warning with rate limit")
fw_pr_err_ratelimited("error with rate limit")
```

## 测试

项目采用模块化测试框架，共 149 项测试：

```bash
# 运行所有测试（推荐）
make test

# 或手动运行
sudo ./tests/run_tests.sh

# 运行单个测试套件
sudo ./tests/run_tests.sh --suite 03       # 封禁/解封测试
sudo ./tests/run_tests.sh --suite 09       # 配置测试

# 按类别运行
sudo ./tests/run_tests.sh --category security   # 安全测试
sudo ./tests/run_tests.sh --category daemon     # 守护进程测试

# 生成测试报告
sudo ./tests/run_tests.sh --report

# 运行旧测试脚本（向后兼容）
make test-legacy
```

**测试结果**: 149 项测试全部通过

### 测试覆盖

- 模块加载/卸载
- Procfs 接口功能
- 封禁/解封功能
- 白名单保护
- 输入验证和边界检查
- 安全测试（注入防护、权限检查）
- 并发访问安全
- 压力/性能测试
- Jail 配置加载和目录加载
- 日志解析功能
- 资源管理和内存安全
- 整数溢出防护（新增）
- 路径遍历防护（新增）
- ReDoS 防护（新增）

## 项目结构

```
firewall/
├── src/
│   ├── kernel-module/
│   │   ├── firewall.c          # 内核模块主源码（~2350 行）
│   │   └── firewall.h          # 头文件（含统一日志系统）
│   └── daemon/
│       ├── firewall-daemon.c   # 守护进程主源码（~3200 行，Jail 系统）
│       ├── http-exporter.c     # Prometheus 指标导出器（libmicrohttpd）
│       └── sqlite-persistent.c # SQLite 永久封禁持久化
├── tests/
│   ├── run_tests.sh            # 统一测试入口（149 项测试）
│   ├── test_framework.sh       # 测试框架核心
│   ├── test_config.sh          # 测试配置
│   ├── suites/                 # 16 个测试套件（含 3 个新增安全测试）
│   └── reports/                # 测试报告
├── config/                     # YAML 配置文件目录
│   └── default.yaml            # 默认配置（sshd jail）
├── docs/
│   ├── DOCUMENTATION.md        # 详细技术文档
│   └── PERMANENT_BAN_GUIDE.md  # 永久封禁指南 (v1.7 更新)
├── scripts/
│   ├── build.sh                # 构建脚本
│   ├── deploy.sh               # 部署脚本（v1.7 安全加固：确认提示 + SSH 密钥验证）
│   └── verify_project.sh       # 项目验证脚本
├── build/                      # 构建产物目录
│   ├── kernel-module/
│   │   └── firewall.ko
│   └── daemon/
│       └── firewall-daemon
├── Makefile                    # 构建配置
├── firewall-daemon.service     # systemd 服务文件
├── CHANGELOG.md                # 变更日志
├── LICENSE                     # GPL v2 许可证
├── README.md                   # 项目主文档
└── .gitignore                  # Git 忽略配置
```

## 已知限制

- **仅支持 IPv4**（纯 IPv4 实现）
- **封禁上限 1024 IP**
- **白名单上限 64 条目**
- **内核模块状态非持久化**（模块重启后封禁列表丢失，但有状态文件保存/恢复机制）
- **SQLite 永久封禁持久化**（可选功能，封禁记录保存在数据库中，重启后自动恢复）
- **procfs 通信**（不支持批量操作）
- **ban_time 限制**: 30 秒 ~ 1 年（防止整数溢出）
- **自定义 regex 限制**: 最大 1024 字节，最多 50 个交替符 `|`

## 适用场景

### 适合
- 个人 VPS 防护
- 开发/测试环境
- 小规模 SSH 暴力破解防护

### 不推荐
- 生产环境 DDoS 防护
- 需要审计合规的场景
- 大规模分布式部署

## 许可证

GPL v2
