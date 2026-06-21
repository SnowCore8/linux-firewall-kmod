# Firewall

**Linux 内核模块版 fail2ban — 实时 IP 封禁防护**

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.2.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-Rust%20%2B%20C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x-orange.svg)]()

> 🌍 [English README](README.en.md)

## 概述

Firewall 是一个 Linux 内核模块版本的 fail2ban，将封禁逻辑从用户空间移至内核空间，使用 netfilter 框架在数据包级别进行实时 IP 封禁，具有更低的延迟和更高的性能。守护进程用 Rust 实现（v2.2.0 起从 C 翻译），二进制 5.2MB stripped（含 Leptos WASM 前端），115 项集成测试全部通过。

## 为什么选择本项目

| 对比项 | fail2ban（用户态） | Firewall（内核态） |
|--------|-------------------|-------------------|
| 封禁位置 | iptables/nftables 用户态 | netfilter 内核钩子 |
| 响应延迟 | 秒级 | 毫秒级 |
| 资源占用 | Python 解释器 + 完整依赖链 | 单文件 5.2MB Rust 二进制（含 WASM 前端） |
| 查找性能 | 线性遍历规则 | 哈希表 O(1) 查找 |
| 永久封禁 | 配置文件 | 内存缓存，重启后失效 |

## 核心特性

- ✅ **内核态 IP 封禁** — netfilter hooks，比 iptables 用户态更高效
- ✅ **Jail 系统** — 类似 fail2ban 的多服务隔离配置
- ✅ **哈希表存储** — 4096 容量，O(1) 查找性能
- ✅ **自动过期清理** — 定时清理过期封禁记录
- ✅ **IP 白名单保护** — 自动发现系统 IP + 手动添加（64 容量）
- ✅ **procfs 用户接口** — 封禁/解封/白名单/配置操作
- ✅ **Rust 守护进程（v2.2.0+）** — 53 个源文件，5.2MB stripped 二进制（含 Leptos WASM 前端），行为与 C 版严格等价
- ✅ **Leptos WASM 前端（v2.2.1+）** — 纯 Rust 前端框架，无 Node.js 依赖，trunk 构建，7 个页面 + SVG 图表
- ✅ **正则解析** — 支持命名捕获组提取 IP
- ✅ **RCU 并发安全** — spinlock 保护，高并发安全
- ✅ **严格配置校验** — 未知参数或无效值直接报错拒绝加载
- ✅ **Prometheus 指标** — 端口 9119 导出 17 个监控指标（4 内核 + 13 用户态）
- ✅ **独立日志文件** — `cfg.log_file` 默认 `/var/log/firewall.log`，失败回退 syslog-only
- ✅ **安全加固** — 整数溢出防护、Use-After-Free 修复、RCU 一致性增强、49 个 unsafe 块全部带 `// SAFETY:` 注释
- ✅ **性能优化** — 哈希表容量 4096、白名单两阶段匹配、LTO 编译优化
- ✅ **代码质量** — 88 单元测试 + 115 集成测试 100% 通过，CI 三 job 全绿

## 快速开始

### 编译

```bash
make                    # 编译内核模块 + Rust 守护进程 + Leptos 前端
make kernel-module      # 仅内核模块
make daemon             # 仅 Rust 守护进程 (cargo build --release)
make frontend           # 仅 Leptos 前端 (trunk build --release)
make build-quick        # 快速编译（跳过格式检查）
make clean              # 清理
```

### 安装

```bash
# 方式一：一键安装（自动构建 + 验证）
sudo env "PATH=$PATH" make install

# 方式二：先构建后安装
make build
sudo env "PATH=$PATH" make install

# 卸载
sudo make uninstall
```

> 💡 **提示**：`make install` 会自动构建、安装、验证，并启动 systemd 服务。使用 `sudo env "PATH=$PATH"` 确保 cargo 在 PATH 中。

### 加载模块（手动方式）

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

### 构建 .deb 包

```bash
make deb                 # 调用 ./build-deb.sh
                         # 产物: build/deb/linux-firewall-kmod-2.2.0.deb (1.5MB)
sudo dpkg -i build/deb/linux-firewall-kmod-2.2.0.deb  # 安装（DKMS 自动编译 + systemd 启动）
```

> 📖 文档: [中文](docs/zh/) | [English](docs/en/) | [在线浏览](https://snowcore8.github.io/linux-firewall-kmod/)

## 📚 文档导航

完整文档请通过侧边栏浏览，章节速查：

- [快速开始](docs/zh/getting-started/README.md) - 安装、编译、首次使用
- [配置指南](docs/zh/configuration/README.md) - YAML Jail 格式、参数详解
- [架构设计](docs/zh/architecture/README.md) - 内核模块与守护进程设计
- [运维手册](docs/zh/operations/README.md) - 管理命令、监控
  - [故障排查](docs/zh/operations/troubleshooting.md)
- [开发指南](docs/zh/development/README.md) - 构建、贡献流程
  - [测试](docs/zh/development/testing.md)
- [迁移指南](docs/zh/migration/from-fail2ban.md) - 从 fail2ban 迁移
- [CHANGELOG.md](CHANGELOG.md) - v1.0 至 v2.2 变更记录

## 适用场景

| ✅ 适合 | ❌ 不推荐 |
|---------|-----------|
| 个人 VPS 防护 | 生产环境 DDoS 防护 |
| 开发/测试环境 | 需要审计合规的场景 |
| 小规模 SSH 暴力破解防护 | 大规模分布式部署 |

## 许可证与贡献

- **许可证**: [MIT License](LICENSE)
- **贡献**: [Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues) | [PRs](https://github.com/SnowCore8/linux-firewall-kmod/pulls)
- **作者**: [SnowCore8](https://github.com/SnowCore8) — 使用 [Code CLI](https://github.com/github/code-cli) 辅助开发
