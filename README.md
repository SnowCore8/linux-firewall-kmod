# Firewall

读日志，判定坏 IP，下发到内核。内核收到包就丢。

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.2.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Platform](https://img.shields.io/badge/Platform-Linux%206.8%20loaded%20%7C%207.0%20builds-orange.svg)](#内核版本口径)

## 这是什么

判定在用户态，丢包在内核态。守护进程被调度走，也不影响已经在内核表里的封禁。

| 链路 | 走法 |
|------|------|
| 判定 | inotify 读日志 → 正则取 IP → 窗口计数 → 判定封禁 |
| 生效 | netlink 下发 → netfilter 钩子查表 → 命中即丢 |

详细架构见 [docs/zh/architecture/](docs/zh/architecture/README.md)。

## 快速开始

### 1. 编译

```bash
make                   # 格式检查 + 内核模块 + 守护进程
```

产物：
- 内核模块：`build/kernel-module/firewall.ko`
- 守护进程：`build/daemon/firewall-daemon`

### 2. 加载模块

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
```

### 3. 启动守护进程

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

### 4. 访问面板

```text
http://<host>:9119/dashboard
```

默认监听 `0.0.0.0:9119`。配了 `metrics_username` 和 `metrics_password` 时需要登录。

详细安装步骤见 [docs/zh/getting-started/installation.md](docs/zh/getting-started/installation.md)。

## 核心能力

| 能力 | 说明 |
|------|------|
| 日志采集 | inotify 监视，按源读增量，处理轮转 |
| IP 提取 | 正则命名捕获组；正则不可用时走关键字回退 |
| 封禁判定 | findtime 窗口内失败次数达阈值 |
| 渐进式时长 | 第 2 次 1800 秒，第 3 次 86400 秒，第 4 次起永久 |
| 集群扫描 | 同网段内低频源 IP 数达标（默认关闭，只审计不封） |
| 内核封禁表 | hlist + RCU，支持 CIDR |
| 白名单 | 精确桶 + 子网链 |
| 速率检测 | PPS / BPS，协议专项 |
| 端口扫描识别 | 唯一端口数达 5 即入列 |
| 服务探测识别 | 协议种类达 3 即入列 |
| 历史库 | SQLite 存封禁事件与信誉分 |
| 面板 | React 19 + antd-mobile 5，嵌入二进制 |
| 热重载 | SIGHUP 或配置文件变化触发 |

详细功能说明见 [docs/zh/architecture/](docs/zh/architecture/README.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/zh/architecture/](docs/zh/architecture/README.md) | 技术架构、核心组件、数据流 |
| [docs/zh/development/](docs/zh/development/README.md) | 构建、测试、开发规范、质量门禁 |
| [docs/zh/development/contract.md](docs/zh/development/contract.md) | 契约系统、API/netlink/procfs 契约 |
| [docs/zh/configuration/](docs/zh/configuration/README.md) | YAML 配置、ProcFS 接口 |
| [docs/zh/getting-started/](docs/zh/getting-started/README.md) | 安装、快速上手 |
| [docs/zh/operations/](docs/zh/operations/README.md) | 运维管理、监控、故障排查 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南、代码规范 |
| [SECURITY.md](SECURITY.md) | 安全策略、信任边界 |
| [STANDARDS.md](STANDARDS.md) | 问题定级规范 |
| [CHANGELOG.md](CHANGELOG.md) | 变更记录 |
| [AGENTS.md](AGENTS.md) | AI 代理工作指令 |

## 内核版本口径

| 内核 | 验证状态 |
|------|---------|
| 6.8.0-146（Ubuntu 24.04 GA） | 可编译、可加载、procfs 齐全 |
| 7.0.0-38 | 仅编译通过 |
| 5.x | 未验证 |

徽章写的是实测范围，不是兼容承诺。

## 依赖

| 依赖 | 版本 |
|------|------|
| Go | 1.26.0 |
| Node.js | 22 |
| 内核头文件 | 与运行内核一致 |
| clang-format | 18 |

## 许可证

MIT License，见 [LICENSE](LICENSE)。
内核模块源码声明为 Dual MIT/GPL。

## 联系

- 作者：[SnowCore8](https://github.com/SnowCore8)
- 邮箱：snowcore8@gmail.com
- 问题反馈：[Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues)
