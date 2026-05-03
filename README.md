# Firewall

**版本**: v1.9（安全/并发修复 + 代码质量改进）

Firewall 是一个 Linux 内核模块版本的 fail2ban，用于实时 IP 封禁防护。它将 fail2ban 的核心功能从用户空间移动到内核空间，使用 netfilter 框架在数据包级别进行封禁，具有更低的延迟和更高的性能。

## 核心特性

- ✅ 内核态 IP 封禁（netfilter hooks，比 iptables 用户态更高效）
- ✅ **Jail 系统** — 类似 fail2ban 的多服务隔离配置
- ✅ 哈希表存储封禁 IP（1024 容量，O(1) 查找）
- ✅ 自动过期清理机制
- ✅ IP 白名单保护（自动发现系统 IP + 手动添加，64 容量）
- ✅ 通过 procfs 的用户接口（封禁/解封/白名单/配置）
- ✅ C 语言用户态守护进程（无 Python 依赖）
- ✅ POSIX 正则表达式日志解析（减少误判 90%+）
- ✅ RCU 并发安全 + spinlock 保护
- ✅ 状态持久化（保存/恢复封禁和白名单）

> v1.7/v1.8 详细变更（libmicrohttpd/PCRE2 替换、安全加固等）请查看 [CHANGELOG.md](CHANGELOG.md)。

## 快速开始

### 编译

```bash
# 编译两者（内核模块 + 守护进程）
make all-with-daemon

# 仅编译内核模块 / 仅编译守护进程
make kernel-module
make daemon

# 清理构建产物
make clean
```

### 加载模块

```bash
# 加载内核模块（带参数）
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600

# 查看当前配置
cat /proc/firewall/config

# 卸载模块
sudo rmmod firewall
```

### 基本操作

```bash
# 查看封禁列表
cat /proc/firewall/bans

# 封禁 IP（默认时长 / 自定义时长 / 永久）
echo "1.2.3.4"        | sudo tee /proc/firewall/bans
echo "1.2.3.4 3600"   | sudo tee /proc/firewall/bans    # 1 小时
echo "1.2.3.4 0"      | sudo tee /proc/firewall/bans    # 永久

# 解封 IP
echo "unban 1.2.3.4"  | sudo tee /proc/firewall/bans

# 查看/添加/移除白名单
cat /proc/firewall/whitelist
echo "10.0.0.0/8"             | sudo tee /proc/firewall/whitelist
echo "remove 10.0.0.0/8"     | sudo tee /proc/firewall/whitelist
```

> 完整 procfs 接口说明、已知限制、运维指南详见 [docs/OPERATIONS.md](docs/OPERATIONS.md)。

### 启动守护进程

```bash
# 使用配置文件启动（推荐，自动加载 config/ 目录下所有 .yaml）
sudo ./build/daemon/firewall-daemon

# 指定配置目录 / 单个配置文件
sudo ./build/daemon/firewall-daemon -C /etc/firewall/
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 查看帮助
sudo ./build/daemon/firewall-daemon --help
```

## 📚 文档导航

| 文档 | 内容 |
|------|------|
| [CONFIGURATION.md](docs/CONFIGURATION.md) | 完整配置说明：YAML Jail 格式、参数详解、热重载、自定义正则 |
| [OPERATIONS.md](docs/OPERATIONS.md) | 运维操作手册：安装部署、procfs 接口、故障排查、性能调优 |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 架构设计文档：内核模块设计、守护进程设计、数据流、组件交互 |
| [TESTING.md](docs/TESTING.md) | 测试框架文档：147 项测试覆盖、运行方式、编写新测试 |
| [SECURITY.md](docs/SECURITY.md) | 安全特性详解：编译选项、systemd 加固、v1.7/v1.9 安全修复 |
| [PERMANENT_BAN_GUIDE.md](docs/PERMANENT_BAN_GUIDE.md) | 永久封禁指南：SQLite 持久化、数据库 schema、使用方法 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更日志：v1.0 至 v1.9 详细变更记录 |

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
