# QWEN.md - Linux Firewall Kernel Module 项目指南

## 项目概述

**Linux 内核模块版 fail2ban** — 实时 IP 封禁防护系统

本项目是一个高性能的 Linux 防火墙解决方案，将封禁逻辑从用户空间移至内核空间，使用 netfilter 框架在数据包级别进行实时 IP 封禁。相比传统 fail2ban，具有更低的延迟（毫秒级 vs 秒级）和更高的性能（哈希表 O(1) 查找 vs 线性遍历）。

### 技术栈

- **内核模块**：C 语言，Linux Kernel Module + netfilter hooks
- **守护进程**：Rust（v2.2.0 起从 C 翻译），单文件 stripped 二进制（含前端构建产物）
- **前端**：React 19 + TypeScript + Vite + antd-mobile 5（移动优先，hash 路由），底部 TabBar + 卡片式布局，手写 SVG 图表，支持 PWA
- **构建系统**：Makefile + Cargo + npm/vite
- **测试框架**：Python pytest（集成测试）+ Rust 单元测试；用例数随开发变动，跑 `make test` / `cargo test --release` 取实时值
- **配置格式**：YAML（Jail 配置）
- **监控导出**：Prometheus 指标（端口 9119；指标清单以 `src/daemon/http_exporter/metrics.rs` 为准）

### 核心架构

```
┌──────────────────────────────────────────────────────────┐
│                                                          │
│                用户空间（Rust 守护进程）                 │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│   │ 日志解析 │  │DDoS 检测 │  │Jail 管理 │  │  Web UI  │ │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│        └─────────────┴──────┬──────┴─────────────┘       │
│                             │ netlink 通信               │
└──────────────────────────────────────────────────────────┘
                             │
┌──────────────────────────────────────────────────────────┐
│                                                          │
│                   内核空间（内核模块）                   │
│                                                          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│   │  procfs  │  │ netlink  │  │  封禁表  │  │  白名单  │ │
│   └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│          ┌──────────┐  ┌──────────┐  ┌──────────┐        │
│          │netfilter │  │ 速率检测 │  │状态/清理 │        │
│          └──────────┘  └──────────┘  └──────────┘        │
└──────────────────────────────────────────────────────────┘
```

> 守护进程与内核模块之间走 **netlink** 双向通道（`src/daemon/kernel/` ↔ `fw_netlink.c`）：
> 下发封禁/白名单指令、回推内核事件与统计。`/proc/firewall` 的 procfs 条目仍保留，
> 供手动操作与调试读取（见下文「procfs 接口」）。

## 目录结构

```
linux-firewall-kmod/
├── src/
│   ├── kernel-module/          # 内核模块 C 源码（统一 fw_* 前缀）
│   │   ├── fw_main.c           # 模块入口（init/exit）+ 模块参数
│   │   ├── fw_hook.c           # netfilter 钩子函数
│   │   ├── fw_ban.c            # 封禁表（hlist + RCU + per-entry 定时器）
│   │   ├── fw_wl.c             # 白名单（精确桶 + 子网链）
│   │   ├── fw_rate.c           # 速率 / 端口扫描 / 服务探测检测
│   │   ├── fw_local.c          # 本机地址集合
│   │   ├── fw_netlink.c        # netlink 通道（与守护进程双向通信）
│   │   ├── fw_procfs.c         # /proc/firewall 条目
│   │   ├── fw_state.c          # 状态快照与持久化还原
│   │   ├── fw_stats.c          # 每 CPU 统计聚合
│   │   ├── fw_netdev.c         # 网卡事件（本机地址维护）
│   │   └── fw_types.h          # 契约公共类型与表规模常量
│   └── daemon/                 # Rust 守护进程源码
│       ├── main.rs, lib.rs     # 入口与库根（模块装配）
│       ├── kernel/             # netlink 传输层（transport/codec/reactor/client/lease）
│       ├── api/                # HTTP/JSON API（routes/、SSE 推送、envelope 封装）
│       ├── state/              # 内存状态（封禁/白名单/CIDR/速率/统计）
│       ├── runtime/            # 运行时（通道/调度/关闭/定时器/监督）
│       ├── file_monitor/       # inotify 日志监听与轮转检测
│       ├── ingest/, pipeline/  # 日志读取与处理管线
│       ├── parse/, log_parser/ # 日志解析（正则/规则/切分/提取）
│       ├── decision/           # DDoS 决策（ddos/policy/window）
│       ├── ban/                # 封禁动作（校验 + netlink 投递）
│       ├── jail/               # Jail 配置与匹配
│       ├── config/             # 配置加载和校验
│       ├── web_ui/             # Web UI 后端（统计/日志/分析）
│       ├── http_exporter/      # Prometheus 指标导出
│       └── types/              # 公共类型定义
├── config/                     # Jail 配置文件（YAML）
│   ├── default.yaml            # 默认配置
│   ├── nginx.yaml              # Nginx Jail
│   └── ...                     # 其他服务 Jail
├── tests/                      # 集成测试（Python pytest）
│   ├── conftest.py             # pytest fixtures + 辅助函数
│   ├── config.py               # 测试配置（路径、IP、参数）
│   ├── test_01_module_lifecycle.py # 模块加载/卸载生命周期测试
│   ├── ...                     # 其余测试套件
│   └── e2e/                    # Playwright E2E 测试
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
make                            # 编译内核模块 + Rust 守护进程（前端经 npm/vite 构建后嵌入）
make kernel-module              # 仅内核模块
make daemon                     # 仅 Rust 守护进程（含前端构建）
make frontend                   # 仅前端（npm ci + vite build）
make frontend-typecheck         # 仅前端类型检查（tsc --noEmit）

# 快速构建（跳过格式检查，用于调试）
make build-quick

# 清理
make clean

# 代码格式化（提交前必做）
make format                     # C 代码格式化（clang-format）
cargo fmt                       # Rust 代码格式化
```

### 构建依赖

- Rust 工具链（`cargo`）
- **Node.js ≥ 20 + npm**（前端为 React 19 + TypeScript + Vite + antd-mobile，`make daemon` / `make all` 会先跑 `npm ci` 再 `vite build`）
- 前端依赖锁在 `frontend/package-lock.json`（已入库），CI 使用 `npm ci` 保证可复现

### Web UI / PWA

移动端优先的 React 应用，构建产物经 `rust-embed` 嵌入守护进程，访问 `http://<host>:9119/dashboard`。

- 前端入口：`frontend/index.html` + `frontend/src/main.tsx`；路由用 hash 模式（守护进程只对若干页面路径返回同一份 HTML，无 catch-all）
- **认证**：配置了 `metrics_username` / `metrics_password` 时，页面会显示应用内登录表单（不使用浏览器原生 Basic 对话框 —— SPA 外壳是公开路由，顶层文档不返回 401，原生对话框根本不会出现）。
  - 登录成功后令牌存入 `sessionStorage`（键 `firewall.access_token`），所有 `fetch` 显式带 `Authorization: Basic <令牌>`
  - SSE 走 `?access_token=<令牌>`（`EventSource` 无法设置自定义请求头），服务端中间件同时兼容该参数
  - 免登录直达：`http://<host>:9119/?access_token=<base64(user:pass)>`（令牌会被写入 `sessionStorage` 后从地址栏清除）
  - 说明：`/api/v1/**` 的 401 **不**带 `WWW-Authenticate` 头，避免浏览器弹原生对话框并让请求挂起
- PWA：`frontend/public/manifest.webmanifest` + 手写 Service Worker `frontend/public/sw.js`（由守护进程的 `GET /sw.js` 提供，带 `Service-Worker-Allowed: /`）；`/api/*` 不做缓存，保证实时数据新鲜
- **限制：Service Worker 只在安全上下文（HTTPS 或 localhost）注册。** 通过局域网 `http://<ip>:9119` 访问时 Chrome 会静默拒绝注册 SW，界面可用但无法"添加到主屏幕"；需要 PWA 安装能力时请用 HTTPS 或本机 localhost 访问

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
# 集成测试套件（需要 root；`make test` 只跑 pytest，不含 cargo test），用例数见实时输出
make test

# 仅 Rust 单元测试（含 doctest）
cargo test --release

# 直接调用集成测试（需要 root 权限）
sudo python3 -m pytest tests/ -v

# 运行单个测试套件
sudo python3 -m pytest tests/test_03_ban_unban.py -v    # 封禁/解封测试
sudo python3 -m pytest tests/test_09_daemon_config.py -v # 守护进程配置测试

# 按关键字筛选
sudo python3 -m pytest tests/ -k "ban" -v
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
- **单元测试**：`cargo test`
- **集成测试**：`make test`
- **行为审计**：C 到 Rust 移植时按需触发

### 内存安全（Rust unsafe）

unsafe 块集中在 netlink 传输、signalfd/sigaction 信号、守护进程化（fork/flock/fd）、
线格式指针访问、syslog、IP 地址操作、inotify/poll 封装等处。具体清单与块数以
`grep -rn 'unsafe {' src/daemon` 为准：
- `kernel/transport.rs` — netlink socket 的 open/bind/send/recv/close
- `signal/mod.rs` — signalfd 读取 siginfo（信号转 fd）
- `daemonizer.rs` — fork 守护进程化 / flock / fd 接管
- `kernel/codec/mod.rs` — 线格式布局的指针访问
- `signals.rs` — sigaction 信号处理器注册
- `logger.rs` — syslog(3) 接入
- `ip_utils.rs` — IP 地址原始操作
- `ingest/watcher.rs` — inotify fd 读取
- `file_monitor/monitor_loop.rs` — poll 系统调用封装

**硬性要求**：
- 每个 unsafe 块必须紧跟 `// SAFETY:` 注释
- 说明前置条件、后置不变量、错误路径
- 没有 SAFETY 注释的 unsafe 代码一律不合并

## 核心功能

### procfs 接口

内核模块通过 `/proc/firewall/` 暴露操作接口：`bans`、`config`、`whitelist` 为
0600 可写，其余为 0400 只读统计/分析视图（完整条目与权限由 `contract/procfs.fwidl`
生成到 `contract/generated/procfs_uapi.h`）：

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

端口 9119 导出监控指标（清单以 `src/daemon/http_exporter/metrics.rs` 为准）：

**内核侧指标**：
- `firewall_kernel_banned_ips_current` - 当前封禁 IP 数
- `firewall_kernel_bans_total` - 累计封禁操作数
- `firewall_kernel_unbans_total` - 累计解封操作数
- `firewall_kernel_whitelist_count` - 当前白名单条目数

**守护进程侧指标**：
- `firewall_daemon_uptime_seconds` - 守护进程运行时长
- `firewall_daemon_config_reloads_total` - 配置重载次数
- `firewall_daemon_inotify_events_total` - inotify 事件数
- `firewall_daemon_log_rotations_total` - 日志轮转次数
- `firewall_daemon_lines_parsed_total` - 已解析日志行数
- `firewall_daemon_lines_skipped_total` - 跳过的日志行数
- `firewall_daemon_regex_matches_total` - 正则匹配次数
- `firewall_daemon_ips_extracted_total` - 提取的 IP 数
- `firewall_daemon_ips_banned_total` - 触发封禁的 IP 数
- `firewall_daemon_failed_attempts_total` - 封禁失败次数
- `firewall_ddos_events_detected_total` - DDoS 事件检测数
- `firewall_ddos_auto_bans_total` - DDoS 自动封禁数
- `firewall_ddos_tracked_ips_current` - DDoS 跟踪 IP 数

**Netlink 健康指标**：
- `firewall_netlink_messages_sent_total` - netlink 发送消息数
- `firewall_netlink_messages_received_total` - netlink 接收消息数
- `firewall_netlink_send_errors_total` - netlink 发送失败数
- `firewall_netlink_recv_errors_total` - netlink 接收/解析失败数

**IP 信誉分指标**：
- `firewall_reputation_tracked_ips` - 信誉系统跟踪 IP 数
- `firewall_reputation_low_count` - 低信誉 IP 数（< 80）
- `firewall_reputation_critical_count` - 高危 IP 数（< 50）

## 质量门禁

每次提交前必须通过：

1. **格式化检查**
   ```bash
   make format-check   # C 代码
   cargo fmt --check   # Rust 代码
   ```

2. **Lint 检查**
   ```bash
   cargo clippy --all-targets -- -D warnings   # Rust（零警告）
   ```

3. **测试套件**
   ```bash
   make test           # 集成测试（仅 pytest）
   cargo test --release # Rust 单元测试（含 doctest）
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
sudo python3 -m pytest tests/ -v

# 仅运行守护进程相关测试（不需要加载内核模块）
sudo python3 -m pytest tests/ -v -k "daemon or config or logparse"
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
| 封禁表 | hlist + RCU + per-entry 定时器；桶数与条目录上限见 `fw_types.h` 与 `fw_main.c` 模块参数 |
| 白名单 | 精确桶 + 子网链两阶段匹配；桶数与条目录上限同上 |
| 速率表 | 哈希表；桶数与条目上限同上 |
| 守护进程体积 | 单文件 stripped 二进制（含前端产物），`stat -c %s build/daemon/firewall-daemon` 实测 |
| 测试覆盖 | 集成测试 + Rust 单元测试；以 `make test` / `cargo test` 实时输出为准 |
| 响应延迟 | 毫秒级 |

## 相关文档

### 项目根文档

| 文档 | 说明 |
|------|------|
| [README.md](README.md) | 项目介绍、快速开始、核心特性 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南、代码规范、PR 流程 |
| [CHANGELOG.md](CHANGELOG.md) | 版本变更记录 |
| [SECURITY.md](SECURITY.md) | 安全策略和漏洞报告流程 |
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
