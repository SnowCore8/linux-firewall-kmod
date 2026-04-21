# firewall 项目上下文

## 项目概述

**firewall** 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

**当前版本**: v1.5（YAML 配置 + 配置目录 + 模块化测试框架）

### 核心架构

项目由两部分组成：

1. **内核模块** (`firewall.ko`)
   - Netfilter Hook 拦截所有传入数据包
   - 哈希表存储封禁 IP（1024 容量，O(1) 查找）
   - 自动过期清理机制
   - IP 白名单保护（64 容量，自动发现系统 IP）
   - 通过 procfs 提供用户接口
   - RCU 并发安全 + spinlock 保护
   - 状态持久化（保存/恢复封禁和白名单）

2. **用户态守护进程** (`firewall-daemon`)
   - C 语言实现（无 Python 依赖）
   - 监控日志文件（/var/log/auth.log 等）
   - 使用 POSIX 正则表达式解析日志
   - 自动管理封禁（通过 procfs 接口）
   - YAML 配置文件支持（libyaml 解析）
   - 配置目录自动加载（`config/` 目录）
   - inotify 实时文件监控 + 日志轮转检测
   - 配置热重载（SIGHUP）
   - Prometheus metrics 导出（HTTP  exporter）

### 主要特性

- ✅ 内核态 IP 封禁（netfilter hooks）
- ✅ 哈希表存储封禁 IP（1024 容量）
- ✅ 自动过期清理机制
- ✅ IP 白名单保护（自动发现 + 手动添加）
- ✅ 通过 procfs 的用户接口
- ✅ 可配置的封禁时间和重试次数
- ✅ 纯 IPv4 支持
- ✅ C 语言用户态守护进程
- ✅ POSIX 正则表达式日志解析
- ✅ 统一分级日志系统（fw_pr_err/warn/info/debug）
- ✅ RCU 并发安全 + spinlock 保护
- ✅ 状态持久化
- ✅ 输入验证和边界检查
- ✅ YAML 配置文件（libyaml 解析）
- ✅ 配置目录自动加载（多配置合并）
- ✅ Prometheus metrics 导出
- ✅ 模块化测试框架（95+ 项测试）

### 技术栈

- **语言**: C
- **内核**: Linux（需要内核头文件）
- **构建工具**: make, gcc
- **框架**: Netfilter, procfs, RCU, hashtable
- **通信**: procfs 文件系统接口

## 项目结构

```
firewall/
├── src/
│   ├── kernel-module/
│   │   ├── firewall.c          # 内核模块主源码（~1880 行）
│   │   └── firewall.h          # 头文件（含统一日志系统）
│   └── daemon/
│       ├── firewall-daemon.c   # 守护进程主源码（~2600 行）
│       └── http-exporter.c     # Prometheus 指标导出器
├── tests/
│   ├── run_tests.sh            # 统一测试入口（95+ 项测试）
│   ├── test_framework.sh       # 测试框架核心
│   ├── test_config.sh          # 测试配置
│   ├── suites/                 # 11 个测试套件
│   └── reports/                # 测试报告
├── config/                     # YAML 配置文件目录
│   ├── default.yaml            # 默认配置
│   └── frps.yaml               # frps 保护配置
├── docs/
│   └── DOCUMENTATION.md        # 详细技术文档
├── scripts/
│   └── build.sh                # 构建脚本
├── build/                      # 构建产物目录（git 忽略）
│   ├── kernel-module/
│   │   └── firewall.ko
│   └── daemon/
│       └── firewall-daemon
├── Makefile                    # 构建配置
├── firewall-frps.service       # systemd 服务文件
├── CHANGELOG.md                # 变更日志
├── LICENSE                     # GPL v2 许可证
├── README.md                   # 项目主文档
└── .gitignore                  # Git 忽略配置
```

## 构建和运行

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

# 调试构建
make debug1  # DEBUG_LEVEL=1
make debug2  # DEBUG_LEVEL=2
make debug3  # DEBUG_LEVEL=3
```

### 加载和卸载模块

```bash
# 加载内核模块（带参数）
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600 fw_max_retries=3 fw_findtime=600

# 查看配置
cat /proc/firewall/config

# 卸载模块
sudo rmmod firewall
```

### 启动守护进程

```bash
# 基本用法（自动加载 config/ 目录）
sudo ./build/daemon/firewall-daemon

# 指定配置目录
sudo ./build/daemon/firewall-daemon -C /etc/firewall/config/

# 指定单个配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 指定日志文件和参数
sudo ./build/daemon/firewall-daemon -l /var/log/auth.log -m 3 -f 600 -b 600

# 查看帮助
sudo ./build/daemon/firewall-daemon --help
```

### 安装

```bash
sudo make install
```

这会：
- 复制 `firewall.ko` 到 `/lib/modules/$(uname -r)/kernel/net/`
- 复制 `firewall-daemon` 到 `/usr/local/bin/`
- 运行 `depmod -a`

## 使用方法

### 基本操作

```bash
# 查看封禁列表
cat /proc/firewall/ban_list

# 手动封禁 IP
echo "1.2.3.4" | sudo tee /proc/firewall/add_ban

# 手动解封 IP
echo "1.2.3.4" | sudo tee /proc/firewall/remove_ban

# 查看白名单
cat /proc/firewall/whitelist

# 添加白名单（支持 IP 和子网）
echo "10.0.0.0" | sudo tee /proc/firewall/whitelist_add
echo "192.168.1.0/24" | sudo tee /proc/firewall/whitelist_add

# 移除白名单
echo "10.0.0.0" | sudo tee /proc/firewall/whitelist_remove

# 运行时修改配置
echo "ban_time 1200" | sudo tee /proc/firewall/config
```

### 模块参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 封禁持续时间（秒） | 600 (10分钟) |
| `fw_max_retries` | 触发封禁的失败次数 | 3 |
| `fw_findtime` | 失败记录时间窗口（秒） | 600 (10分钟) |

### 守护进程参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 日志文件路径 | /var/log/auth.log |
| `-m` | 触发封禁的失败次数 | 3 |
| `-f` | 失败记录时间窗口（秒） | 600 |
| `-b` | 封禁持续时间（秒） | 600 |
| `-c` | 配置文件路径 | - |
| `-C` | 配置目录路径 | ./config/ |
| `-i` | 检查间隔（秒） | 1 |
| `-p` | Prometheus 端口 | 9119 |
| `--daemonize` | 后台运行 | false |

### procfs 接口

| 路径 | 功能 |
|------|------|
| `/proc/firewall/ban_list` | 查看封禁列表 |
| `/proc/firewall/add_ban` | 手动封禁 IP（写入） |
| `/proc/firewall/remove_ban` | 手动解封 IP（写入） |
| `/proc/firewall/whitelist` | 查看白名单 |
| `/proc/firewall/whitelist_add` | 添加白名单（写入） |
| `/proc/firewall/whitelist_remove` | 移除白名单（写入） |
| `/proc/firewall/config` | 查看/修改运行时配置（读写） |
| `/proc/firewall/settings` | 查看模块设置 |

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

```bash
# 运行所有测试（95+ 项）
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

**测试结果**: 93+ 通过，0 失败

### 测试覆盖

- 模块加载/卸载
- Procfs 接口功能
- 封禁/解封功能
- 白名单保护
- 输入验证和边界检查
- 安全测试（注入防护、权限检查）
- 并发访问安全
- 压力/性能测试
- YAML 配置目录加载
- 日志解析功能
- 资源管理和内存安全

## 关键数据结构

**内核模块** (`firewall.h`):
- `struct ban_entry` - 封禁条目（IP、时间、计数）
- `struct whitelist_entry` - 白名单条目（IP、掩码、设备名）
- `struct firewall_info` - 全局防火墙信息（哈希表、锁、定时器、procfs 入口）

**常量定义**:
- `BAN_HASH_BITS` = 10 → 最大 1024 个封禁条目
- `WHITELIST_HASH_BITS` = 6 → 最大 64 个白名单条目
- `DEFAULT_BAN_TIME` = 600 秒
- `DEFAULT_MAX_RETRIES` = 3
- `DEFAULT_FINDTIME` = 600 秒

## 开发约定

### 编码风格

- 使用 Linux 内核编码风格
- 函数命名采用小写下划线分隔（如 `ban_ip`, `is_in_whitelist`）
- 结构体命名使用小写下划线
- 使用 `fw_pr_*` 系列宏进行日志输出
- 使用 `spinlock` + RCU 保护并发访问

### 测试实践

- 使用 `run_tests.sh` 进行模块化测试（95+ 项测试）
- 测试需要 root 权限
- 可运行单个测试套件：`./tests/run_tests.sh --suite 03`
- 可按类别运行：`./tests/run_tests.sh --category security`
- 测试后自动清理，不遗留安装文件
- 支持生成测试报告：`./tests/run_tests.sh --report`

### 扩展开发

**添加新的日志解析模式**：
在 `firewall-daemon.c` 的 `init_log_patterns()` 函数中添加新的正则表达式

**修改封禁逻辑**：
修改 `firewall.c` 中的 `nf_hook_func()` 函数

## 已知限制

- **仅支持 IPv4**（纯 IPv4 实现）
- **封禁上限 1024 IP**
- **无持久化存储**（模块重启后状态丢失，但有状态文件保存/恢复）
- **procfs 通信**（不支持批量操作）
- **无监控集成**（无 Prometheus metrics 导出）

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
