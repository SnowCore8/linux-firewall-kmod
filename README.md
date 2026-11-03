# Firewall

智能内核防火墙：多维风险引擎 + 威胁情报聚合 + 自动化封禁 + 实时监控面板。

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.4.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Platform](https://img.shields.io/badge/Platform-Linux%205.x%20%7C%206.x%20%7C%207.x-orange.svg)](#内核兼容性)

## 这是什么

**用户态智能判定 + 内核态高速封禁**的三层架构防火墙。

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐
│  日志采集    │ ───> │  多维风险引擎 │ ───> │  内核封禁表  │
│  (inotify)  │      │  (衰减+分类)  │      │ (netfilter) │
└─────────────┘      └──────────────┘      └─────────────┘
       ↓                     ↓                      ↓
   实时日志              风险评分               包过滤生效
   协议解析              自动封禁               零用户态开销
```

| 层级 | 技术栈 | 职责 |
|------|--------|------|
| 内核模块 | C (netfilter) | 高速包过滤，RCU 封禁表，命中即丢 |
| 守护进程 | Go | 日志采集、风险判定、HTTP API、面板服务 |
| 前端面板 | React 19 + TypeScript | 实时监控、配置管理、可视化分析 |
| 契约系统 | Python + .fwidl | 三端接口一致性保证，自动生成代码 |

详细架构见 [docs/zh/architecture/](docs/zh/architecture/README.md)。

## 快速开始

### 1. 检查依赖

```bash
make check-deps              # 检查所有构建依赖
```

### 2. 编译

```bash
make kmod                    # 编译内核模块（自动生成契约文件）
make daemon                  # 编译守护进程（含前端面板）
# 或一键构建
make build-quick             # 跳过格式检查的快速构建
```

产物：
- 内核模块：`build/kernel-module/firewall.ko`
- 守护进程：`build/daemon/firewall-daemon`

### 3. 加载模块

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
```

### 4. 启动守护进程

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

### 5. 访问面板

```text
http://<host>:9119/dashboard
```

默认监听 `0.0.0.0:9119`。配了 `metrics_username` 和 `metrics_password` 时需要登录。

详细安装步骤见 [docs/zh/getting-started/installation.md](docs/zh/getting-started/installation.md)。

## 核心能力

### 多维风险引擎（v2）

| 能力 | 说明 |
|------|------|
| 多维风险评分 | 5 维度独立评估：频率、扫描、探测、协议异常、历史信誉 |
| 时间衰减 | 风险分数随时间指数衰减，避免永久误判 |
| 加法阈值模型 | 修复旧乘法 Bug（内网×低信誉=1.0 导致系数抵消） |
| 自动分类 | 基于风险向量自动判定攻击类型 |
| 历史库分析 | SQLite 存储攻击事件，支持趋势分析和预测 |

### 威胁情报源（v2.4）

| 能力 | 说明 |
|------|------|
| 自动聚合 | 每日自动拉取公网威胁情报（IPsum、FireHOL、DShield 等） |
| 并发刷新 | 多源并行拉取，总耗时取最慢源 |
| 错误隔离 | 单个源失败不影响其他源 |
| 热重载 | SIGHUP 触发配置重载时同步刷新情报 |
| SSRF 防护 | HTTPS 强制 + 域名白名单 + 重定向限制 |
| 智能判定 | 高置信度 IP 直接封禁，跳过窗口计数 |

### 封禁与防护

| 能力 | 说明 |
|------|------|
| 内核封禁表 | hlist + RCU，支持 CIDR，零用户态开销 |
| 渐进式时长 | 第 2 次 1800 秒，第 3 次 86400 秒，第 4 次起永久 |
| DDoS 防护 | 速率检测（PPS/BPS），自动封禁攻击源 |
| 端口扫描识别 | 唯一端口数达阈值即入列 |
| 服务探测识别 | 协议种类达阈值即入列 |
| 集群扫描 | 同网段内低频源 IP 数达标（默认关闭，只审计不封） |
| 白名单 | 精确桶 + 子网链，支持动态添加 |

### 日志与采集

| 能力 | 说明 |
|------|------|
| 日志采集 | inotify 监视，按源读增量，处理轮转 |
| IP 提取 | 正则命名捕获组；正则不可用时走关键字回退 |
| 协议解析 | TCP/UDP/ICMP 全协议支持 |
| 实时统计 | PPS、BPS、连接数、协议分布 |

### 监控与管理

| 能力 | 说明 |
|------|------|
| Web 面板 | React 19 + antd-mobile 5，嵌入二进制 |
| HTTP API | RESTful API，支持认证和速率限制 |
| SSE 事件流 | 实时推送封禁事件和统计更新 |
| Prometheus 指标 | `/metrics` 端点，支持 Grafana 集成 |
| 热重载 | SIGHUP 或配置文件变化触发 |
| ProcFS 接口 | `/proc/firewall/*`，13 个条目，3 个可写 |

详细功能说明见 [docs/zh/architecture/](docs/zh/architecture/README.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/zh/architecture/](docs/zh/architecture/README.md) | 技术架构、核心组件、数据流 |
| [docs/zh/development/](docs/zh/development/README.md) | 构建、测试、开发规范、质量门禁 |
| [docs/zh/development/build-system.md](docs/zh/development/build-system.md) | **构建系统指南**：标准化流程、依赖检查、多版本编译 |
| [docs/zh/development/ci-workflow.md](docs/zh/development/ci-workflow.md) | **CI 流程**：6 阶段自动化、配置选项、故障排查 |
| [docs/zh/development/kernel-api-compatibility.md](docs/zh/development/kernel-api-compatibility.md) | **API 兼容性检查**：netfilter/netlink/procfs 自动检测 |
| [docs/zh/development/multi-version-kmod.md](docs/zh/development/multi-version-kmod.md) | **多版本编译**：跨内核版本支持、远程编译 |
| [docs/zh/development/contract.md](docs/zh/development/contract.md) | 契约系统、API/netlink/procfs 契约 |
| [docs/zh/configuration/](docs/zh/configuration/README.md) | YAML 配置、ProcFS 接口 |
| [docs/zh/getting-started/](docs/zh/getting-started/README.md) | 安装、快速上手 |
| [docs/zh/operations/](docs/zh/operations/README.md) | 运维管理、监控、故障排查 |
| [docs/zh/migration-risk-engine-v2.md](docs/zh/migration-risk-engine-v2.md) | 多维风险引擎迁移指南 |
| [docs/zh/configuration/threat-feeds.md](docs/zh/configuration/threat-feeds.md) | 威胁情报源配置指南 |
| [docs/zh/migration-threat-feeds.md](docs/zh/migration-threat-feeds.md) | 威胁情报源迁移指南 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南、代码规范 |
| [SECURITY.md](SECURITY.md) | 安全策略、信任边界 |
| [STANDARDS.md](STANDARDS.md) | 问题定级规范 |
| [CHANGELOG.md](CHANGELOG.md) | 变更记录 |
| [AGENTS.md](AGENTS.md) | AI 代理工作指令 |

## 内核兼容性

**API 兼容性检查策略**：模块在加载时自动检查关键 API 可用性，而非依赖内核版本号。

| 检查项 | API | 说明 |
|--------|-----|------|
| ✓ | netfilter | `nf_register_net_hook` / `nf_unregister_net_hook` |
| ✓ | netlink | `netlink_kernel_create` / `netlink_kernel_release` |
| ✓ | procfs | `proc_create` / `proc_remove` |

**已验证内核版本**：

| 内核版本 | 编译 | 加载 | 功能 |
|---------|------|------|------|
| 5.x | 未验证 | 未验证 | 未验证 |
| 6.8.0-146 | ✓ | ✓ | ✓ procfs 齐全 |
| 6.8.0-147 | ✓ | ✓ | ✓ 完整测试 |
| 7.0.0-38 | ✓ | 未验证 | 仅编译通过 |
| 7.0.0-42 | ✓ | ✓ | ✓ 完整测试 |

**多版本编译支持**：

```bash
# 编译当前内核版本
make kmod

# 编译所有已安装内核版本
make kmod-all

# 远程编译（交叉编译）
make kmod-remote HOST=192.168.8.119 USER=ubuntu

# 指定内核版本
make kmod KVER=6.8.0-147-generic
```

详细指南见 [docs/zh/development/multi-version-kmod.md](docs/zh/development/multi-version-kmod.md) 和 [docs/zh/development/kernel-api-compatibility.md](docs/zh/development/kernel-api-compatibility.md)。

## 构建系统

**标准化构建流程**：

```bash
# 1. 检查依赖
make check-deps

# 2. 运行 CI（完整流程）
make ci                        # 环境检查 + 格式 + 契约 + 构建 + 测试
make ci SKIP_TESTS=1           # 跳过测试
make ci SKIP_FORMAT_CHECK=1    # 跳过格式检查

# 3. 分步构建
make kmod                      # 仅内核模块
make daemon                    # 仅守护进程
make frontend                  # 仅前端

# 4. 测试
make test                      # 集成测试（需 root）
cd src/daemon && go test ./... # 单元测试
```

详细文档见 [docs/zh/development/build-system.md](docs/zh/development/build-system.md) 和 [docs/zh/development/ci-workflow.md](docs/zh/development/ci-workflow.md)。

## 许可证

MIT License - 详见 [LICENSE](LICENSE) 文件。

## 贡献

欢迎提交 Issue 和 Pull Request。详见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 安全

发现安全漏洞请通过 [SECURITY.md](SECURITY.md) 中说明的方式报告。

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
