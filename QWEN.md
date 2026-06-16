# QWEN.md - Linux Firewall Kernel Module 项目指南

## 项目概述

**Linux 内核模块版 fail2ban** — 实时 IP 封禁防护系统

本项目是一个高性能的 Linux 防火墙解决方案，将封禁逻辑从用户空间移至内核空间，使用 netfilter 框架在数据包级别进行实时 IP 封禁。相比传统 fail2ban，具有更低的延迟（毫秒级 vs 秒级）和更高的性能（哈希表 O(1) 查找 vs 线性遍历）。

### 技术栈

- **内核模块**：C 语言，Linux Kernel Module + netfilter hooks
- **守护进程**：Rust（v2.2.0 起从 C 翻译），3.8MB stripped 二进制
- **构建系统**：Makefile + Cargo
- **测试框架**：Bash 集成测试（115 项用例，13 个套件）+ Rust 单元测试（108 项）
- **配置格式**：YAML（Jail 配置）
- **监控导出**：Prometheus 指标（端口 9119）

### 核心架构

```
┌─────────────────────────────────────────────────────────┐
│                    用户空间（Rust 守护进程）              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │日志解析  │  │DDoS检测  │  │Jail管理  │  │Web UI   │ │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│       └──────────────┴──────────────┴─────────────┘      │
│                         │ procfs 写入                    │
└─────────────────────────┼───────────────────────────────┘
                          │
┌─────────────────────────┼───────────────────────────────┐
│                    内核空间（内核模块）                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │procfs    │  │ban-manager│ │whitelist │  │netfilter│ │
│  │接口      │→ │封禁管理  │  │白名单    │→ │钩子     │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│                                                         │
│  ┌──────────┐  ┌──────────┐                             │
│  │rate-     │  │cleanup   │                             │
│  │detector  │  │清理      │                             │
│  └──────────┘  └──────────┘                             │
└─────────────────────────────────────────────────────────┘
```

## 目录结构

```
linux-firewall-kmod/
├── src/
│   ├── kernel-module/          # 内核模块 C 源码
│   │   ├── firewall-main.c     # 模块入口（init/exit）
│   │   ├── netfilter.c         # netfilter 钩子函数
│   │   ├── ban-manager.c       # 封禁/解封逻辑
│   │   ├── whitelist.c         # 白名单管理
│   │   ├── rate-detector.c     # DDoS 速率检测
│   │   ├── procfs.c            # procfs 接口
│   │   └── firewall.h          # 公共头文件
│   └── daemon/                 # Rust 守护进程源码
│       ├── main.rs             # 守护进程入口
│       ├── ban/                # 封禁操作（procfs 写入）
│       ├── config/             # 配置加载和校验
│       ├── jail/               # Jail 系统实现
│       ├── log_parser/         # 日志解析器
│       ├── ddos_detector.rs    # DDoS 检测
│       ├── http_exporter/      # Prometheus 指标导出
│       ├── web_ui/             # Web UI API
│       └── types/              # 公共类型定义
├── config/                     # Jail 配置文件（YAML）
│   ├── default.yaml            # 默认配置
│   ├── nginx.yaml              # Nginx Jail
│   └── ...                     # 其他服务 Jail
├── tests/                      # 集成测试
│   ├── run_tests.sh            # 测试入口脚本
│   ├── test_framework.sh       # 测试框架
│   └── suites/                 # 测试套件（01-15）
├── docs/                       # 文档
├── build/                      # 构建产物（git-ignored）
│   ├── kernel-module/firewall.ko
│   └── daemon/firewall-daemon
├── Makefile                    # 构建脚本
├── Cargo.toml                  # Rust 依赖配置
└── README.md                   # 项目说明
```

## 构建与运行

### 编译命令

```bash
# 完整构建（含格式检查）
make                            # 编译内核模块 + Rust 守护进程
make kernel-module              # 仅内核模块
make daemon                     # 仅 Rust 守护进程

# 快速构建（跳过格式检查，用于调试）
make build-quick

# 清理
make clean

# 代码格式化（提交前必做）
make format                     # C 代码格式化（clang-format）
cargo fmt                       # Rust 代码格式化
```

### 安装与卸载

```bash
# 一键安装（自动构建 + 验证 + 启动服务）
sudo env "PATH=$PATH" make install

# 卸载
sudo make uninstall

# 手动加载模块
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
sudo rmmod firewall
```

### 运行测试

```bash
# 完整测试套件（115 项集成测试 + 108 项单元测试）
make test

# 仅 Rust 单元测试
cargo test --release

# 仅集成测试（需要 root 权限）
sudo ./tests/run_tests.sh

# 跳过重复编译运行测试（使用已有构建产物）
SKIP_COMPILE=1 sudo -E ./tests/run_tests.sh

# 运行单个测试套件
sudo ./tests/run_tests.sh --suite 03    # 封禁/解封测试
sudo ./tests/run_tests.sh --suite 09    # 守护进程配置测试
```

### 启动守护进程

```bash
# 前台运行（调试用）
sudo ./build/daemon/firewall-daemon

# 指定配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 使用 systemd（生产环境）
sudo systemctl start firewall-daemon
sudo systemctl enable firewall-daemon
sudo journalctl -u firewall-daemon -f
```

## 开发规范

### 代码格式化（强制）

**每次修改代码提交前必须运行格式化工具**：

```bash
make format     # C 内核代码（clang-format）
cargo fmt       # Rust 守护进程
```

CI 会检查代码格式，不符合规范将拒绝合并。

### 编码规范

#### C 内核模块

- **命名**：函数/变量 `snake_case`，宏 `UPPER_CASE`
- **缩进**：2 个空格（见 `.clang-format`）
- **行宽**：最大 80 字符
- **括号**：K&R 风格（左括号不换行）
- **注释**：统一使用中文
- **函数长度**：单个函数不超过 50 行

#### Rust 守护进程

- **格式化**：`cargo fmt`（强制）
- **Lint**：`cargo clippy -- -D warnings`（强制，零警告）
- **错误处理**：使用 `anyhow::Result`
- **注释**：统一使用中文
- **unsafe 块**：每个 unsafe 块必须紧跟 `// SAFETY:` 注释

### 提交规范

遵循 [Conventional Commits](https://www.conventionalcommits.org/)：

```
<type>(<scope>): <subject>

<body>
```

**Type 类型**：
- `feat` - 新功能
- `fix` - Bug 修复
- `docs` - 文档更新
- `style` - 代码格式（不影响逻辑）
- `refactor` - 代码重构
- `perf` - 性能优化
- `test` - 测试相关
- `chore` - 构建/工具

**示例**：
```
feat(kmod): 增强 netfilter 数据包验证
fix(daemon): 修复 DDoS 违规计数并发安全
style(kmod,daemon): 统一代码格式化
perf(kmod): 优化速率检测使用平均速率
```

### 测试要求

**修改以下内容时必跑完整测试**：
- YAML 配置 schema / 字段
- procfs 命令接口（`/proc/firewall/*`）
- 守护进程与内核模块的交互协议

**测试分层**：
- **单元测试**：`cargo test`（108 项）
- **集成测试**：`make test`（115 项，13 个套件）
- **行为审计**：C 到 Rust 移植时按需触发

### 内存安全（Rust unsafe）

当前代码库有 **19 个 unsafe 块**，分布在：
- `ban/procfs.rs` - fd 生命周期管理
- `main.rs` - fork 守护进程化
- `logger.rs` - syslog 接入

**硬性要求**：
- 每个 unsafe 块必须紧跟 `// SAFETY:` 注释
- 说明前置条件、后置不变量、错误路径
- 没有 SAFETY 注释的 unsafe 代码一律不合并

## 核心功能

### procfs 接口

内核模块通过 `/proc/firewall/` 暴露操作接口：

```bash
# 封禁 IP（默认时长 / 自定义 / 永久）
echo "1.2.3.4"       | sudo tee /proc/firewall/bans
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans  # 永久

# 解封
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 白名单
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist

# 查看统计
cat /proc/firewall/stats
cat /proc/firewall/config
```

### Jail 系统

类似 fail2ban 的多服务隔离配置，每个 Jail 定义：
- 监控的日志文件路径
- 正则表达式（提取 IP）
- 封禁时长和阈值
- 白名单排除

配置文件位于 `config/*.yaml`。

### DDoS 防护

内核模块内置速率检测：
- **PPS 检测**：每秒数据包数
- **BPS 检测**：每秒字节数
- **协议专项**：SYN Flood / UDP Flood / ICMP Flood
- **自动封禁**：超过阈值自动封禁 IP

### Prometheus 指标

端口 9119 导出 14 个监控指标：
- `firewall_current_bans` - 当前封禁数
- `firewall_total_bans` - 累计封禁数
- `firewall_ddos_events` - DDoS 事件数
- `firewall_packets_dropped` - 丢弃数据包数
- 等等

## 质量门禁

每次提交前必须通过：

1. **格式化检查**
   ```bash
   make format-check   # C 代码
   cargo fmt --check   # Rust 代码
   ```

2. **Lint 检查**
   ```bash
   cargo clippy -- -D warnings   # Rust（零警告）
   ```

3. **测试套件**
   ```bash
   make test           # 完整测试（集成 + 单元）
   ```

**任一环节失败不得提交**。

## 常见问题

### 编译错误：内核构建目录不存在

```bash
# 安装内核头文件
sudo apt install linux-headers-$(uname -r)

# 或指定 KDIR
make KDIR=/lib/modules/$(uname -r)/build
```

### 测试错误：需要 root 权限

```bash
# 使用 sudo
sudo -E ./tests/run_tests.sh

# 或设置 SKIP_COMPILE 避免重复编译
SKIP_COMPILE=1 sudo -E ./tests/run_tests.sh
```

### 模块加载失败

```bash
# 检查 dmesg
sudo dmesg | tail

# 确认内核版本兼容
uname -r

# 卸载旧模块
sudo rmmod firewall
sudo insmod build/kernel-module/firewall.ko
```

## 性能指标

| 指标 | 数值 |
|------|------|
| 封禁查找 | O(1) 哈希表 |
| 哈希表容量 | 4096 条目 |
| 白名单容量 | 64 条目 |
| 守护进程体积 | 3.8 MB stripped |
| 测试覆盖 | 115 集成 + 108 单元 |
| 响应延迟 | 毫秒级 |

## 相关文档

### 项目根文档

| 文档 | 说明 |
|------|------|
| [README.md](README.md) | 项目介绍、快速开始、核心特性 |
| [README.en.md](README.en.md) | 英文版 README |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南、代码规范、PR 流程 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录 |
| [SECURITY.md](SECURITY.md) | 安全策略和漏洞报告流程 |
| [AUDIT.md](AUDIT.md) | 安全审计报告 |
| [PLAN.md](PLAN.md) | 项目开发计划、待办事项、版本路线图 |
| [STANDARDS.md](STANDARDS.md) | 统一问题/任务/性能/安全定级规范 |

### 详细文档（docs/zh/）

#### 快速开始
- [docs/zh/getting-started/quick-start.md](docs/zh/getting-started/quick-start.md) - 快速开始指南
- [docs/zh/getting-started/installation.md](docs/zh/getting-started/installation.md) - 安装指南

#### 架构设计
- [docs/zh/architecture/kernel-module.md](docs/zh/architecture/kernel-module.md) - 内核模块架构
- [docs/zh/architecture/daemon.md](docs/zh/architecture/daemon.md) - 守护进程架构
- [docs/zh/architecture/data-flow.md](docs/zh/architecture/data-flow.md) - 数据流说明

#### 配置说明
- [docs/zh/configuration/yaml-config.md](docs/zh/configuration/yaml-config.md) - YAML 配置详解
- [docs/zh/configuration/procfs.md](docs/zh/configuration/procfs.md) - procfs 接口说明
- [docs/zh/configuration/examples.md](docs/zh/configuration/examples.md) - 配置示例

#### 开发指南
- [docs/zh/development/building.md](docs/zh/development/building.md) - 编译指南
- [docs/zh/development/testing.md](docs/zh/development/testing.md) - 测试指南
- [docs/zh/development/rust-kmod-design.md](docs/zh/development/rust-kmod-design.md) - Rust 内核模块设计

#### 运维管理
- [docs/zh/operations/management.md](docs/zh/operations/management.md) - 日常管理
- [docs/zh/operations/monitoring.md](docs/zh/operations/monitoring.md) - 监控配置
- [docs/zh/operations/troubleshooting.md](docs/zh/operations/troubleshooting.md) - 故障排查

#### 迁移指南
- [docs/zh/migration/from-fail2ban.md](docs/zh/migration/from-fail2ban.md) - 从 fail2ban 迁移

### GitHub 模板

- [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md) - Bug 报告模板
- [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md) - 功能请求模板
- [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) - PR 模板

## 许可证

MIT License

## 联系方式

- **GitHub**: [@SnowCore8](https://github.com/SnowCore8)
- **邮箱**: snowcore8@gmail.com
- **Issues**: [提交问题或建议](https://github.com/SnowCore8/linux-firewall-kmod/issues)
