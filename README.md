# Firewall

**Linux 内核模块版 fail2ban — 实时 IP 封禁防护**

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.1-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x-orange.svg)]()

> 🌍 [English README](README.en.md)

## 概述

Firewall 是一个 Linux 内核模块版本的 fail2ban，将封禁逻辑从用户空间移至内核空间，使用 netfilter 框架在数据包级别进行实时 IP 封禁，具有更低的延迟和更高的性能。

## 为什么选择本项目

| 对比项 | fail2ban（用户态） | Firewall（内核态） |
|--------|-------------------|-------------------|
| 封禁位置 | iptables/nftables 用户态 | netfilter 内核钩子 |
| 响应延迟 | 秒级 | 毫秒级 |
| 资源占用 | Python 运行时 + 依赖 | 轻量 C 守护进程 |
| 查找性能 | 线性遍历规则 | 哈希表 O(1) 查找 |

## 核心特性

- ✅ **内核态 IP 封禁** — netfilter hooks，比 iptables 用户态更高效
- ✅ **Jail 系统** — 类似 fail2ban 的多服务隔离配置
- ✅ **哈希表存储** — 4096 容量，O(1) 查找性能
- ✅ **自动过期清理** — 定时清理过期封禁记录
- ✅ **IP 白名单保护** — 自动发现系统 IP + 手动添加（64 容量）
- ✅ **procfs 用户接口** — 封禁/解封/白名单/配置操作
- ✅ **C 语言守护进程** — 无 Python 依赖，轻量高效
- ✅ **PCRE2 正则解析** — JIT 加速，ReDoS 防护
- ✅ **RCU 并发安全** — spinlock 保护，高并发安全
- ✅ **严格配置校验** — 未知参数或无效值直接报错拒绝加载
- ✅ **状态持久化** — SQLite 保存/恢复永久封禁
- ✅ **Prometheus 指标** — 端口 9119 导出监控指标
- ✅ **安全加固** — 整数溢出防护、Use-After-Free 修复、RCU 一致性增强
- ✅ **性能优化** — 哈希表容量 4096、SQLite 语句缓存、白名单两阶段匹配
- ✅ **代码质量** — 统一 goto cleanup 模式、提取通用配置解析函数

## 快速开始

### 编译

```bash
make                    # 编译全部
make kernel-module      # 仅内核模块
make daemon             # 仅守护进程
make clean              # 清理
```

### 加载模块

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
cat /proc/firewall/config
sudo rmmod firewall
```

### 基本操作

```bash
# 封禁（默认 / 自定义时长 / 永久）
echo "1.2.3.4"       | sudo tee /proc/firewall/bans
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans

# 解封 / 白名单
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist
```

### 启动守护进程

```bash
sudo ./build/daemon/firewall-daemon                         # 默认配置
sudo ./build/daemon/firewall-daemon -c config/default.yaml  # 指定配置
sudo ./build/daemon/firewall-daemon --help                  # 帮助
```

> 📖 完整 procfs 接口：[docs/OPERATIONS.md](docs/OPERATIONS.md)

## 📚 文档导航

| 文档 | 内容说明 | 适合人群 |
|------|----------|----------|
| [CONFIGURATION.md](docs/CONFIGURATION.md) | YAML Jail 格式、参数详解、热重载 | 配置管理 |
| [OPERATIONS.md](docs/OPERATIONS.md) | 安装部署、procfs API、故障排查 | 运维人员 |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | 内核模块设计、数据流、组件交互 | 开发者 |
| [TESTING.md](docs/TESTING.md) | 105 项测试覆盖、运行方式 | 测试人员 |
| [SECURITY.md](docs/SECURITY.md) | 编译选项、systemd 加固 | 安全工程师 |
| [PERMANENT_BAN_GUIDE.md](docs/PERMANENT_BAN_GUIDE.md) | SQLite 持久化、数据库 schema | 高级用户 |
| [FAQ.md](docs/FAQ.md) | 常见问题解答 | 所有用户 |
| [MIGRATION.md](docs/MIGRATION.md) | 从 fail2ban 迁移指南 | 迁移用户 |
| [CHANGELOG.md](CHANGELOG.md) | v1.0 至 v2.1 变更记录 | 所有用户 |

## 适用场景

| ✅ 适合 | ❌ 不推荐 |
|---------|-----------|
| 个人 VPS 防护 | 生产环境 DDoS 防护 |
| 开发/测试环境 | 需要审计合规的场景 |
| 小规模 SSH 暴力破解防护 | 大规模分布式部署 |

## 许可证与贡献

- **许可证**: [MIT License](LICENSE)
- **贡献**: [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) | [PRs](https://github.com/SnowCore8/linux-firewall-kmod/pulls)
- **作者**: [SnowCore8](https://github.com/SnowCore8) — 使用 [OpenCode](https://opencode.ai) 辅助开发
