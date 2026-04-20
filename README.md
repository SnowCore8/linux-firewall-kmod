# Firewall

**版本**: v1.4（哈希表优化 + 正则解析 + 扩大容量）

Firewall 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

## 特性

- ✅ 内核态 IP 封禁（netfilter hooks，比 iptables 用户态规则更高效）
- ✅ 哈希表存储封禁 IP（1024 容量，O(1) 查找）
- ✅ 自动过期清理机制
- ✅ IP 白名单保护（自动发现系统 IP + 手动添加，64 容量）
- ✅ 通过 procfs 的用户接口
- ✅ 可配置的封禁时间和重试次数
- ✅ 纯 IPv4 支持
- ✅ C 语言用户态守护进程（无 Python 依赖）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）
- ✅ 统一分级日志系统（fw_pr_err/warn/info/debug）
- ✅ RCU 并发安全 + spinlock 保护
- ✅ 状态持久化（保存/恢复封禁和白名单）
- ✅ 输入验证和边界检查

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
sudo insmod build/firewall.ko fw_ban_time=600 fw_max_retries=3 fw_findtime=600

# 查看配置
cat /proc/firewall/config

# 卸载模块
sudo rmmod firewall
```

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

### 启动守护进程

```bash
# 基本用法
sudo ./build/daemon/firewall-daemon

# 指定日志文件和参数
sudo ./build/daemon/firewall-daemon -l /var/log/auth.log -m 3 -f 600 -b 600

# 查看帮助
sudo ./build/daemon/firewall-daemon --help
```

## 配置说明

### 模块参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 封禁持续时间（秒） | 600 (10分钟) |
| `fw_max_retries` | 触发封禁的失败次数 | 3 |
| `fw_findtime` | 失败记录时间窗口（秒） | 600 (10分钟) |

### 守护进程参数

```bash
sudo ./build/daemon/firewall-daemon -l /var/log/auth.log -m 3 -f 600 -b 600
```

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-l` | 日志文件路径 | /var/log/auth.log |
| `-m` | 触发封禁的失败次数 | 3 |
| `-f` | 失败记录时间窗口（秒） | 600 |
| `-b` | 封禁持续时间（秒） | 600 |

### 配置文件

守护进程支持配置文件 `firewall.conf`：

```ini
max_retries = 3
findtime = 600
ban_time = 600
interval = 1
daemonize = false
log_file = /var/log/auth.log
log_file = /var/log/secure
log_file = /var/log/vsftpd.log
log_file = /var/log/nginx/error.log
```

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
# 运行综合测试（55 项）
make test

# 或手动运行
sudo ./tests/test_firewall.sh

# 运行安全测试（60 项）
sudo ./tests/security_test.sh
```

**测试结果**: 52 通过，0 失败，3 警告

### 测试覆盖

- 模块加载/卸载
- Procfs 接口功能
- 封禁/解封功能
- 白名单保护
- 自动发现系统 IP
- 运行时配置修改
- 边界情况和输入验证
- 并发访问安全
- 资源管理和内存安全

## 项目结构

```
firewall/
├── src/
│   ├── kernel-module/
│   │   ├── firewall.c          # 内核模块主源码（~1880 行）
│   │   └── firewall.h          # 头文件（含统一日志系统）
│   └── daemon/
│       └── firewall-daemon.c   # 守护进程主源码（~2200 行）
├── tests/
│   ├── test_firewall.sh        # 55 项综合测试
│   ├── security_test.sh        # 60 项安全测试
│   └── SECURITY_TEST_REPORT.md # 安全测试报告
├── docs/
│   └── DOCUMENTATION.md        # 详细技术文档
├── scripts/
│   ├── build.sh                # 构建脚本
│   └── verify_project.sh       # 项目验证脚本
├── build/                      # 构建产物目录
│   ├── firewall.ko
│   └── daemon/
│       └── firewall-daemon
├── Makefile                    # 构建配置
├── firewall.conf               # 守护进程配置
├── CHANGELOG.md                # 变更日志
├── LICENSE                     # GPL v2 许可证
├── README.md                   # 项目主文档
└── .gitignore                  # Git 忽略配置
```

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
