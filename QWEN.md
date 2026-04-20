# firewall 项目上下文

## 项目概述

**firewall** 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

**当前版本**: v1.4（哈希表优化 + 正则解析 + 扩大容量）

### 核心架构

项目由两部分组成：

1. **内核模块** (`firewall.ko`)
   - Netfilter Hook 拦截所有传入数据包
   - 哈希表存储封禁 IP（1024 容量，快速查找）
   - 自动过期清理机制
   - IP 白名单保护（防止网络瘫痪）
   - 通过 procfs 提供用户接口

2. **用户态守护进程** (`firewall-daemon`)
   - C 语言实现（无 Python 依赖）
   - 监控日志文件（/var/log/auth.log 等）
   - 使用 POSIX 正则表达式解析日志
   - 自动管理封禁（通过 procfs 接口）

### 主要特性

- ✅ 内核态 IP 封禁（比 iptables 用户态规则更高效）
- ✅ 自动 IP 白名单保护（哈希表存储，自动发现系统 IP）
- ✅ 基于哈希表的 IP 封禁查找（1024 容量）
- ✅ 自动过期清理机制
- ✅ 通过 procfs 的简单用户接口
- ✅ 可配置的封禁时间和重试次数
- ✅ 支持 IPv4 封禁
- ✅ C 语言用户态守护进程（无 Python 依赖）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）

### 技术栈

- **语言**: C
- **内核**: Linux（需要内核头文件）
- **构建工具**: make, gcc
- **框架**: Netfilter, procfs
- **通信**: procfs 文件系统接口

## 构建和运行

### 编译

```bash
# 编译内核模块
make

# 编译用户态守护进程
make daemon

# 同时编译两者
make all-with-daemon
```

### 加载和卸载模块

```bash
# 加载模块
sudo insmod firewall.ko
# 或
sudo modprobe firewall

# 带参数加载
sudo insmod firewall.ko fw_ban_time=900 fw_max_retries=5 fw_findtime=300

# 卸载模块
sudo rmmod firewall
```

### 启动守护进程

```bash
# 基本用法
sudo ./firewall-daemon

# 指定日志文件和参数
sudo ./firewall-daemon -l /var/log/auth.log -m 5 -f 600 -b 900

# 查看帮助
sudo ./firewall-daemon --help
```

### 安装

```bash
sudo make install
```

这会：
- 复制 `firewall.ko` 到 `/lib/modules/$(uname -r)/kernel/net/`
- 复制 `firewall-daemon` 到 `/usr/local/bin/`
- 运行 `depmod -a`

### 测试

```bash
sudo ./test_script.sh
```

## 使用方法

### 基本操作

```bash
# 查看封禁列表
cat /proc/firewall/ban_list

# 手动封禁 IP
echo "192.168.1.100" | sudo tee /proc/firewall/add_ban

# 手动解封 IP
echo "192.168.1.100" | sudo tee /proc/firewall/remove_ban

# 查看白名单
cat /proc/firewall/whitelist

# 添加白名单
echo "10.0.0.1" | sudo tee /proc/firewall/whitelist_add
echo "192.168.1.0/24" | sudo tee /proc/firewall/whitelist_add

# 移除白名单
echo "10.0.0.1" | sudo tee /proc/firewall/whitelist_remove
```

### 模块参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 封禁持续时间（秒） | 600 (10分钟) |
| `fw_max_retries` | 触发封禁的失败次数 | 3 |
| `fw_findtime` | 失败记录时间窗口（秒） | 600 (10分钟) |

## 代码结构

```
firewall/
├── src/
│   ├── kernel-module/
│   │   ├── firewall.c          # 内核模块主源码
│   │   └── firewall.h          # 内核模块头文件
│   └── daemon/
│       └── firewall-daemon.c   # 守护进程主源码
├── tests/
│   └── test_firewall.sh        # 综合测试脚本
├── docs/
│   └── DOCUMENTATION.md           # 详细技术文档
├── scripts/
│   ├── build.sh                   # 构建脚本
│   └── verify_project.sh          # 项目验证脚本
├── Makefile                       # 构建配置
├── firewall.conf               # 守护进程配置
├── performance_test.c             # 性能测试源码（可选）
├── README.md                      # 项目主文档
├── CHANGELOG.md                   # 变更日志
├── QWEN.md                        # 项目上下文
├── LICENSE                        # 许可证
└── .gitignore                     # Git 忽略配置
```

### 关键数据结构

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
- 结构体命名使用小写下划线加 `_t` 后缀
- 使用 `printk` 进行内核日志输出
- 使用 `spinlock` 保护并发访问

### 测试实践

- 使用 `test_script.sh` 进行自动化测试
- 测试需要 root 权限
- 测试覆盖：模块加载/卸载、procfs 接口、封禁/解封、白名单功能

### 扩展开发

**添加新的日志解析模式**：
在 `firewall-daemon.c` 的 `init_log_patterns()` 函数中添加新的正则表达式

**修改封禁逻辑**：
修改 `firewall.c` 中的 `nf_hook_func()` 函数

**添加 IPv6 支持**：
需要扩展 `ban_entry` 结构、更新 netfilter hook、添加 procfs 处理

## 已知限制

- 仅支持 IPv4（IPv6 支持计划中）
- 封禁上限 1024 IP
- 无持久化存储（模块重启后状态丢失）
- procfs 通信（不支持批量操作）
- 无监控集成（无 Prometheus metrics 导出）

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

## Qwen Added Memories
- firewall 项目安全测试于 2026-04-19 执行,总体评分 8.6/10 (优秀)。60 项测试中 56 项通过,3 项失败,1 项警告。主要问题: 1)哈希碰撞抗性测试发现 100 IP 仅封禁 6 个; 2)模块参数 fw_ban_time 设置与读取不一致; 3)边界 IP 254.255.255.255 未被封禁。输入验证、抗洪泛能力、并发安全性、资源管理均表现优秀。
