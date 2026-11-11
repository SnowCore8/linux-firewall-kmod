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
| 加法阈值模型 | 各因子相加，内网与低信誉不会互相抵消 |
| 自动分类 | 基于风险向量自动判定攻击类型 |
| 历史库分析 | SQLite 存储攻击事件，支持趋势分析和预测 |

### 威胁情报源（v2.4）

| 能力 | 说明 |
|------|------|
| 自动聚合 | 每日自动拉取公网威胁情报（IPsum、FireHOL、DShield 等） |
| 并发刷新 | 多源并行拉取，总耗时取最慢源 |
| 错误隔离 | 单个源失败不影响其他源 |
| 定时刷新 | 按 `refresh_interval` 自动拉取，也可经 HTTP 接口手动同步 |
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
| Web 面板 | React 19 + Ant Design 6 + ECharts，桌面优先响应式，嵌入二进制 |
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
| [docs/zh/development/agent-architecture.md](docs/zh/development/agent-architecture.md) | **AI 协作**：四个角色怎么分工、一条评论怎么推动下一棒、状态存在哪 |
| [docs/zh/development/merge-gate.md](docs/zh/development/merge-gate.md) | **合并闸门**：五条判据、为什么模型不能自己合、主干红了怎么办 |
| [docs/zh/development/qwen-cli-runner.md](docs/zh/development/qwen-cli-runner.md) | **引擎层**：`.github/actions/run-agent` 怎么跑模型，换引擎要动哪 |
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

**内核兼容性状态**：

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

## 🤖 仓库里的四个 AI 同事

四个 App 各自装到这个仓库上，一条 Issue / 评论 / PR 由 `.github/scripts/route.mjs` 判给其中一个人，`qwen-dispatch.yml` 起一次 runner，跑完即弃。没有常驻进程，状态全在 GitHub 上。

| 名字 | 英文名 | 干什么 | 不干什么 |
|---|---|---|---|
| 顾清 | `clara` | 读 Issue、问清情况、打标、判断该谁接手 | 不改代码、不合并 |
| 叶澜 | `nora` | 定做不做、做多大、先做哪个、怎么算做完 | 不写代码、不评审、不合并 |
| 陈实 | `miles` | 写代码、跑测试、开 PR、按意见改、批准后申请合并 | 不动别人的分支、不为变绿删测试 |
| 周正 | `frank` | 读 diff、留行内意见、批准或要求修改 | 不写业务代码、不合并 |

他们的行为写在 `.qwen/workflows/*.js`（`clara-triage.js` / `nora-decide.js` / `miles-fix.js` / `frank-review.js`），红线与协作规矩在 [QWEN.md](QWEN.md)。架构与失败处理见 [docs/zh/development/agent-architecture.md](docs/zh/development/agent-architecture.md)。

### 配置说明

| 名称 | 类型 | 必需 | 描述 |
|---|---|---|---|
| `QWEN_API_KEY` | Secret | ✅ | Qwen API 密钥 |
| `QWEN_BASE_URL` | Variable | ❌ | API 基础 URL |
| `QWEN_MODEL` | Variable | ❌ | 模型名称 |
| `QWEN_CLI_VERSION` | Variable | ❌ | CLI 版本 |
| `QWEN_MENTION` | Variable | ❌ | 触发用的提及词，默认 `@qwencoder` |
| `APP_ID` | Variable | ❌ | GitHub App ID（四个角色共用时的退路） |
| `APP_PRIVATE_KEY` | Secret | ❌ | GitHub App 私钥（同上） |
| `AGENT_MAX_HANDOFFS` | Variable | ❌ | 24 小时内机器人自动交接上限，默认 20 |
| `AGENT_MAX_CALLS` | Variable | ❌ | 24 小时内机器人点名上限，默认 40 |
| `AGENT_CALL_COOLDOWN_MINUTES` | Variable | ❌ | 同一话题两次点名的最短间隔（分钟），默认 10 |
| `TRIAGE_BATCH_LIMIT` | Variable | ❌ | 顾清每次批量分诊处理的 Issue 数，默认 5。手动触发 `qwen-clara` 时可在界面填 `batch_limit` 单次覆盖，留空仍取此变量 |
| `PATROL_IDLE_MINUTES` | Variable | ❌ | 巡检叫陈实前，PR 至少安静多少分钟，默认 15 |
| `PATROL_REVIEW_IDLE_MINUTES` | Variable | ❌ | 巡检叫周正前，PR 至少开了多少分钟，默认 30 |
| `PATROL_DECISION_IDLE_HOURS` | Variable | ❌ | 巡检叫叶澜前，Issue 至少停了多少小时，默认 24 |
| `PATROL_MAX_INSPECT` | Variable | ❌ | 巡检时最多翻多少个 Issue 的评论，默认 15 |
| `MILES_CI_WAIT_MINUTES` | Variable | ❌ | 合并前等待检查的上限（分钟），默认 10 |
| `UPLOAD_ARTIFACTS` | Variable | ❌ | 让 action 把运行产物（含 `stdout.log`）上传成 artifact |
| `APP_ID_CLARA` / `APP_PRIVATE_KEY_CLARA` | Variable / Secret | ❌ | 顾清独立身份，未配则退回 `APP_ID_TRIAGER`、再退回 `APP_ID` |
| `APP_ID_NORA` / `APP_PRIVATE_KEY_NORA` | Variable / Secret | ❌ | 叶澜独立身份，未配则退回 `APP_ID_PRODUCT`、再退回 `APP_ID` |
| `APP_ID_MILES` / `APP_PRIVATE_KEY_MILES` | Variable / Secret | ❌ | 陈实独立身份，未配则退回 `APP_ID_ENGINEER`、再退回 `APP_ID` |
| `APP_ID_FRANK` / `APP_PRIVATE_KEY_FRANK` | Variable / Secret | ❌ | 周正独立身份，未配则退回 `APP_ID_REVIEWER`、再退回 `APP_ID` |

建 App 与写这些配置可以用 `.github/scripts/setup-app.mjs`（用 CDP 驱动一个已登录的 Chrome，登录与 2FA 只能由人输入）。

标签三枚：`status/needs-triage`（顾清还没看完，巡检会跳过）、`do-not-merge` 与 `manual-review`（人放的闸，巡检和陈实都认）。

### 验证改动

改工作流或 `.qwen/workflows/` 下的脚本后，至少跑这几条自检：

```bash
python3 -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/workflows/*.yml')]"
for f in .qwen/workflows/*.js; do node --check "$f"; done
python3 -c "import json,glob;[json.load(open(f)) for f in glob.glob('.github/agents/*.json')]"
node --test .github/scripts/*.test.mjs
```

这几条在 `.github/workflows/qwen-ci.yml` 里也会跑，PR 上多出一个叫 `qwen test` 的检查项（不叫 `test`：`ci.yml` 里已经有一个同名 job）。它不只是图方便 —— 合并闸门的 `checks` 判据看的是 PR 上的检查项，测试不进 CI 就等于闸门在核一堆不验判断逻辑的东西。

哪些事件跑哪份工作流：`pull_request_review`、`pull_request_review_comment` 与 `pull_request` 跑的是 **PR 分支里的** workflow 定义，其余事件跑默认分支。所以改完 `.github/workflows/` 想验证效果，得先让改动出现在 PR 分支上。

`qwen-dispatch.yml` 里那一步 `actions/checkout` 显式钉在**默认分支**上取 `.github/scripts/`，所以事件触发的那次运行用的永远是主干上的脚本。**改了脚本要先合进默认分支才会生效。**

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
| Node.js | 24 |
| 内核头文件 | 与运行内核一致 |
| clang-format | 18 |

## 许可证

MIT License，见 [LICENSE](LICENSE)。
内核模块源码声明为 Dual MIT/GPL。

## 联系

- 作者：[SnowCore8](https://github.com/SnowCore8)
- 邮箱：snowcore8@gmail.com
- 问题反馈：[Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues)
