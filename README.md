# Firewall

**版本**: v1.4（哈希表优化 + 正则解析 + 扩大容量）

Firewall 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

## 特性

- ✅ 内核态 IP 封禁（比 iptables 用户态规则更高效）
- ✅ 自动 IP 白名单保护（哈希表存储，自动发现系统 IP）
- ✅ 基于哈希表的 IP 封禁查找（1024 容量，快速查找）
- ✅ 自动过期清理机制
- ✅ 通过 procfs 的简单用户接口
- ✅ 可配置的封禁时间和重试次数
- ✅ 支持 IPv4 封禁
- ✅ C 语言用户态守护进程（无 Python 依赖）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）
- ✅ 高性能和低延迟
- ✅ 强化安全性（RCU 并发、输入验证、边界检查、内存安全）
- ✅ 洪泛保护机制

## 架构

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

## 安装

### 方法一：使用构建脚本
```bash
# 构建所有组件
./scripts/build.sh

# 或者单独构建
sudo make install
```

### 方法二：手动安装
```bash
# 编译
make all-with-daemon

# 安装内核模块
sudo make install-kernel

# 安装守护进程
sudo make install-daemon

# 或者一次性安装
sudo make install
```

## 使用

### 基本操作
```bash
# 加载内核模块
sudo modprobe firewall

# 带参数加载
sudo insmod build/firewall.ko fw_ban_time=900 fw_max_retries=5 fw_findtime=300

# 卸载模块
sudo rmmod firewall

# 启动守护进程
sudo ./build/daemon/firewall-daemon

# 指定日志文件和参数
sudo ./build/daemon/firewall-daemon -l /var/log/auth.log -m 5 -f 600 -b 900

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

### 守护进程参数
```bash
sudo ./firewall-daemon -l /var/log/auth.log -m 5 -f 600 -b 900
```
参数说明：
- `-l`: 日志文件路径
- `-m`: 触发封禁的失败次数
- `-f`: 失败记录时间窗口（秒）
- `-b`: 封禁持续时间（秒）
- `--help`: 查看帮助

### 配置文件
守护进程支持配置文件 `firewall.conf`：
```ini
max_retries = 3
findtime = 600
ban_time = 600
log_file = /var/log/auth.log
```

## 测试

运行综合测试脚本验证所有功能：
```bash
sudo ./tests/test_firewall_ko.sh
```

该脚本测试以下功能：
- 模块加载/卸载
- Procfs 接口
- 封禁/解封功能
- 白名单保护
- 守护进程功能
- 边界情况和安全测试
- 洪泛保护
- 性能测试
- 模块参数验证
- 并发访问模拟
- 数据包拦截验证

## 性能

根据基准测试结果：
- 封禁操作: ~840 ops/ms
- 查询操作: ~885 ops/ms
- 解封操作: ~1235 ops/ms
- 白名单添加: ~1220 ops/ms
- 白名单查询: ~1227 ops/ms

### 性能优化
- 优化了 `nf_hook_func` 函数，实现了快速路径
- 改进了哈希表查找性能
- 优化了白名单查找效率
- 优化了守护进程链表操作算法
- 改进了日志文件监控的 I/O 效率

## 安全性

### 安全特性
- 使用 RCU 机制提高并发安全性
- 防止整数溢出和下溢
- 强化的输入验证（IP 地址、日志数据）
- 自动白名单保护防止自锁
- 洪泛保护机制防止滥用
- 数据包完整性验证
- 内存操作边界检查

### 修复的关键问题
- 修复了 `auto_discover_system_ips` 函数中的 RCU 使用问题
- 修复了守护进程中 inotify 事件处理的整数溢出漏洞
- 增强了 IP 地址和日志数据的验证机制
- 确保白名单中的子网能够正确保护其范围内的 IP

## 项目结构

```
firewall/
├── src/                    # 源代码目录
│   ├── kernel-module/      # 内核模块源代码
│   │   ├── firewall.c
│   │   └── firewall.h
│   └── daemon/             # 守护进程源代码
│       └── firewall-daemon.c
├── tests/                  # 测试文件目录
│   └── test_firewall.sh    # 综合测试脚本
├── docs/                   # 文档目录
│   └── DOCUMENTATION.md    # 详细技术文档
├── scripts/                # 脚本目录
│   ├── build.sh            # 构建脚本
│   └── verify_project.sh   # 项目验证脚本
├── Makefile                # 构建配置
├── firewall.conf           # 守护进程配置文件
├── performance_test.c      # 性能测试源码（可选）
├── .gitignore              # Git 忽略配置
├── LICENSE                 # 许可证文件
├── README.md               # 项目主文档
└── CHANGELOG.md            # 变更日志
```

## 适用场景

### 适合
- 个人 VPS 防护
- 开发/测试环境
- 小规模 SSH 暴力破解防护

### 不推荐
- 生产环境 DDoS 防护
- 需要审计合规的场景
- 大规模分布式部署

## 已知限制

- 仅支持 IPv4（IPv6 支持计划中）
- 封禁上限 1024 IP
- 无持久化存储（模块重启后状态丢失）
- procfs 通信（不支持批量操作）
- 无监控集成（无 Prometheus metrics 导出）

## 许可证

GPL v2