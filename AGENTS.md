# AGENTS.md — AI 代理工作指令

本文给 AI 代理看。告诉你在本仓库干活必须知道的事。
每条事实都有仓库内出处。没核实的说法标「未验证」。

## 核心原则

1. **代码是唯一真相源**。文档可能过时，代码不会。遇到矛盾时，读代码。
2. **每条技术声明必须可验证**。引用文件路径和行号，不要凭印象。
3. **改契约前先读契约**。`contract/*.fwidl` 是线格式的单一真相源，实现必须与生成物一致。
4. **集成测试是行为规格**。改配置/procfs/netlink 相关代码必跑 `make test`，测试与实现冲突时先确认哪侧错。

## 项目概述

读日志 → 判定坏 IP → netlink 下发 → 内核命中即丢。

| 组件 | 语言 | 职责 |
|------|------|------|
| 内核模块 | C | netfilter 钩子查封禁表，命中丢包 |
| 守护进程 | Go | 日志采集、判定、HTTP API、面板 |
| 前端 | TypeScript | React 面板，嵌入守护进程二进制 |
| 契约 | .fwidl + Python | 定义线格式，生成三端代码 |

详细架构见 [docs/zh/architecture/](docs/zh/architecture/README.md)。

## 关键路径

### 构建

**标准化构建流程**（推荐）：

```bash
# 1. 检查依赖
make check-deps              # 检查所有依赖
make check-deps-kmod         # 仅检查内核模块依赖
make check-deps-daemon       # 仅检查守护进程依赖
make check-deps-frontend     # 仅检查前端依赖

# 2. 生成契约文件（内核模块自动依赖此步骤）
make contract                # 手动生成契约文件
make contract-clean          # 清理契约生成文件

# 3. 编译
make kmod                    # 仅编译内核模块（当前内核版本）
make daemon                  # 仅编译守护进程（含前端）
make build-quick             # 快速编译全部（跳过格式检查）
make all                     # 完整编译（含格式检查）

# 4. 测试
make test                    # 集成测试（需 root）
cd src/daemon && go test ./...  # 单元测试
```

**多版本内核模块编译**（解决跨版本兼容性问题）：

```bash
# 使用 Makefile 目标（推荐）
make kmod-all                # 编译所有已安装内核版本的模块

# 使用脚本（更多控制）
./scripts/build-kmod-multi-version.sh              # 智能模式：编译当前运行内核
./scripts/build-kmod-multi-version.sh --all         # 编译所有已安装头文件的版本
./scripts/build-kmod-multi-version.sh --list        # 列出可用版本与兼容性
./scripts/build-kmod-multi-version.sh --check       # 仅检测兼容性
./scripts/build-kmod-multi-version.sh 6.8.0-147-generic  # 指定版本

# 远程编译（交叉编译支持）
make kmod-remote HOST=192.168.8.119 USER=ubuntu
```

**构建产物位置**：

```
build/
├── kernel-module/
│   ├── firewall.ko                    # 当前内核版本
│   └── <kernel-version>/
│       └── firewall.ko                # 指定内核版本
├── daemon/
│   └── firewall-daemon                # 守护进程二进制
└── frontend/                          # 前端构建产物
```

详细指南见 [docs/zh/development/multi-version-kmod.md](docs/zh/development/multi-version-kmod.md)。

详细命令见 [docs/zh/development/](docs/zh/development/README.md)。

### 质量门禁（提交前必跑）

**完整 CI 流程**（推荐）：

```bash
make ci                        # 完整 CI：环境检查 + 格式 + 契约 + 构建 + 测试
make ci SKIP_TESTS=1           # 跳过测试的 CI（仅验证构建）
make ci SKIP_FORMAT_CHECK=1    # 跳过格式检查的 CI（紧急修复）
```

**分步运行**：

```bash
# 1. 依赖检查
make check-deps

# 2. 代码格式
make format-check
cd src/daemon && gofmt -l ./cmd ./internal   # 输出须为空
cd src/daemon && go vet ./cmd/... ./internal/...

# 3. 契约验证
make contract-check

# 4. 构建
make build-quick

# 5. 测试
cd src/daemon && go test ./...
make test
```

详见 [docs/zh/development/ci-workflow.md](docs/zh/development/ci-workflow.md)。

### 契约改动流程

1. 改 `contract/*.fwidl`
2. `python3 contract/gen.py`
3. `make contract-drift`
4. `make contract-check`

详见 [docs/zh/development/contract.md](docs/zh/development/contract.md)。

## 必须知道的事实

### 内核模块

- 产物：`build/kernel-module/firewall.ko`
- 加载：`sudo insmod build/kernel-module/firewall.ko`
- procfs：`/proc/firewall/*`（13 个条目，3 个可写）
- 模块参数：`fw_ban_time`、`state_file`、`fw_max_bans_per_second` 等（见 `fw_main.c`）
- **内核兼容性**：采用 API 可用性检查策略
  - 内核版本号仅作参考信息，不作为硬性限制
  - 重点检查关键 API：netfilter, netlink, procfs
  - 任一 API 不可用时拒绝加载并输出详细错误
  - 检查日志：`dmesg | grep firewall`
- 已验证内核：5.x（未验证）、6.8.0-146（可加载）、6.8.0-147（可加载）、7.0.0-38（可加载）、7.0.0-42（可加载）

### 守护进程

- 产物：`build/daemon/firewall-daemon`
- 组合根：`src/daemon/cmd/firewall-daemon/main.go`
- 配置：`config/default.yaml`（被 git 跟踪，真实凭据不要写在这里）
- 默认监听：`0.0.0.0:9119`（`config/default.yaml` 的值）
- 认证：HTTP Basic，凭据可走环境变量 `FIREWALL_METRICS_USERNAME/PASSWORD`
- 面板：`http://<host>:9119/dashboard`（hash 路由）

### 前端

- 依赖：React 19 + antd-mobile 5 + react-router-dom 7
- 构建：`npm ci` → `npm run build` → 产物写入 `src/daemon/web_ui/static/`
- 嵌入：`assets.go` 用 `//go:embed *` 带进二进制
- **不要删 `assets.go`**，它是 embed 持有文件
- **`vite.config.ts` 的 `emptyOutDir` 必须是 false**

### 测试

- 单元测试：`cd src/daemon && go test ./...`
- 集成测试：`make test`（需 root，依赖 `.ko` 和二进制）
- 端到端：`npx playwright test`
- 集成测试是行为规格，不是可协商的文档

### 多维风险引擎（v2）

- **Feature Flag**：`risk_engine.enabled`（默认 false，使用旧单维度模型）
- **新包**：`src/daemon/internal/risk/`（types.go、decay.go、classifier.go、engine.go）
- **新表**：`schema_migrations`、`attack_events`、`ip_risk_vectors`
- **新 API**：`/api/v2/risk/vectors/*`、`/api/v2/risk/events/*`
- **阈值模型**：加法模型（修复旧乘法 Bug：内网×低信誉=1.0 导致系数抵消）
- **迁移指南**：`docs/zh/migration-risk-engine-v2.md`

### 威胁情报源系统（v2.4）

- **Feature Flag**：`threat_feeds.enabled`（默认 true，启用 IPsum + FireHOL Level 1）
- **新包**：`src/daemon/internal/threatfeeds/`（types.go、config.go、manager.go、parser.go、http.go、cache.go、scheduler.go）
- **源适配器**：`src/daemon/internal/threatfeeds/sources/`（ipsum.go、firehol.go、dshield.go、blocklist.go、feodo.go）
- **核心能力**：自动拉取、并发刷新、错误隔离、热重载、SSRF 防护
- **推荐情报源**：IPsum（多源聚合）、FireHOL Level 1（保守名单）、DShield、Blocklist.de、Feodo Tracker
- **配置文档**：`docs/zh/configuration/threat-feeds.md`
- **迁移指南**：`docs/zh/migration-threat-feeds.md`

## 常见坑

1. **编译过 ≠ 加载得了**。CI runner 用自定义内核，`.ko` 可能 `insmod` 不了。真验证加载得在能加载的机器上跑 `make test`。
2. **本地 `node_modules` 全会掩盖 `package.json` 缺依赖**。验证前端必须走 `npm ci`。
3. **`make format` 只格式化 C**。Go 要单独 `gofmt -w`，YAML 只在 `format-check` 里查。
4. **`go build` 的 `-o` 要用绝对路径**。`Makefile` 已处理，别自己改。
5. **`clean` 不能删 `assets.go`**。`Makefile` 已处理，别自己改。
6. **正则编译失败只告警，进程不退**。结构性非法配置才拒绝启动。

## 文档索引

| 文档 | 内容 |
|------|------|
| [README.md](README.md) | 项目简介、快速开始 |
| [docs/zh/architecture/](docs/zh/architecture/README.md) | 技术架构、核心组件 |
| [docs/zh/development/](docs/zh/development/README.md) | 构建、测试、开发规范 |
| [docs/zh/development/contract.md](docs/zh/development/contract.md) | 契约系统详解 |
| [docs/zh/configuration/](docs/zh/configuration/README.md) | YAML 配置、ProcFS 接口 |
| [docs/zh/getting-started/](docs/zh/getting-started/README.md) | 安装、快速上手 |
| [docs/zh/operations/](docs/zh/operations/README.md) | 运维管理、监控、故障排查 |
| [docs/zh/development/multi-version-kmod.md](docs/zh/development/multi-version-kmod.md) | 多版本内核模块编译指南 |
| [docs/zh/migration-risk-engine-v2.md](docs/zh/migration-risk-engine-v2.md) | 多维风险引擎迁移指南 |
| [docs/zh/configuration/threat-feeds.md](docs/zh/configuration/threat-feeds.md) | 威胁情报源配置指南 |
| [docs/zh/migration-threat-feeds.md](docs/zh/migration-threat-feeds.md) | 威胁情报源迁移指南 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 贡献指南 |
| [SECURITY.md](SECURITY.md) | 安全策略 |
| [STANDARDS.md](STANDARDS.md) | 定级规范 |
| [CHANGELOG.md](CHANGELOG.md) | 变更记录 |

## 输出规范

- 结论先行，证据后置
- 引用代码时给文件路径和行号
- 不确定的标「未验证」
- 不编造函数名、参数名、配置键
- 粘贴命令输出时隐藏凭据
