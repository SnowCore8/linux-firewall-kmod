---
hide:
  - navigation
  - toc
---

# linux-firewall-kmod

<div align="center">

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/kernel-5.15%2B-orange.svg)]()
[![Language](https://img.shields.io/badge/language-C%20%2B%20YAML-green.svg)]()
[![Build](https://img.shields.io/badge/build-make-success.svg)]()

**Linux 内核模块版 fail2ban — 将 IP 封禁从用户态移至内核态。**

</div>

---

## 概述

**linux-firewall-kmod** 是 fail2ban 的高性能替代方案，直接在 Linux 内核中实现 IP 封禁逻辑。通过 Netfilter 钩子和内核态哈希表，实现微秒级数据包过滤与 O(1) 查找性能。
项目采用双层架构：内核模块负责实时数据包过滤，用户态守护进程负责日志监控、正则匹配和封禁管理。

## 为什么选择本项目而非 fail2ban？

| 特性 | fail2ban | linux-firewall-kmod |
|------|----------|---------------------|
| 封禁位置 | iptables/nftables（用户态规则） | Netfilter 内核钩子 |
| 响应延迟 | 秒级 | 毫秒级 |
| 开发语言 | Python | C（内核模块 + 守护进程） |
| 查找性能 | 线性规则遍历 | 哈希表 O(1) 查找 |
| 配置格式 | INI | YAML |
| 配置校验 | 宽松 | 严格模式（默认） |
| 持久化 | 文件系统 | SQLite 数据库 |
| 封禁容量 | 无硬性限制 | 1024 个 IP |
| 指标监控 | 无内置 | Prometheus 导出（端口 9119） |
## 核心特性

1. **内核态过滤** — Netfilter `NF_INET_PRE_ROUTING` 钩子，实时丢弃数据包
2. **O(1) 封禁查找** — 内核哈希表 + RCU 并发保护
3. **事件驱动日志监控** — inotify 文件监听，毫秒级响应
4. **PCRE2 正则引擎** — JIT 编译模式匹配，内置 ReDoS 防护
5. **YAML 配置** — 简洁的配置格式，默认启用严格校验
6. **12 种预设服务模板** — SSH、Nginx、Apache、MySQL、Redis、Docker 等
7. **Prometheus 指标** — 14 项内置指标，支持监控告警
8. **SQLite 持久化** — 永久封禁存储，守护进程重启不丢失
9. **热配置重载** — SIGHUP 触发原子配置切换，零停机
10. **自动 IP 发现** — 自动检测系统 IP 并加入白名单
11. **systemd 加固** — 沙箱化服务，最小权限运行
12. **完善的日志** — 内核 dmesg + systemd journal 集成
## 快速开始
### 编译与加载

```bash
# 安装依赖并编译（Debian/Ubuntu）
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev
make && sudo make install

# 加载内核模块
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a && sudo modprobe firewall
```

### 基本操作

```bash
cat /proc/firewall/bans                          # 查看已封禁 IP
echo "1.2.3.4" | sudo tee /proc/firewall/bans    # 封禁 IP（默认时长）
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans  # 封禁 3600 秒
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans # 解封 IP
cat /proc/firewall/stats                         # 查看统计信息
```

### 启动守护进程

```bash
sudo mkdir -p /etc/firewall && sudo cp config/*.yaml /etc/firewall/
sudo systemctl enable --now firewall-daemon
# 或前台调试：sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
```

## 适用场景

| 场景 | 推荐 | 说明 |
|------|------|------|
| 个人 VPS / 云服务器 | 推荐 | 适合 SSH 暴力破解防护 |
| Web 服务（Nginx/Apache） | 推荐 | 内置正则规则开箱即用 |
| 数据库（MySQL/Redis） | 推荐 | 防止未授权访问 |
| 企业级 DDoS 防护 | 不推荐 | 请使用专用硬件防火墙 |
| 纯 IPv6 环境 | 不推荐 | IPv6 支持计划中 |
| 封禁数 > 1024 个 IP | 不推荐 | 请考虑企业级方案 |
## 许可证与贡献

本项目采用 [MIT 许可证](LICENSE)。欢迎各类贡献——Bug 修复、功能新增、文档改进和翻译。详见[贡献指南](contributing.md)。

> **文档导航**：[配置说明](configuration.md) | [运维手册](operations.md) | [架构设计](architecture.md) | [安全特性](security.md) | [常见问题](faq.md)
