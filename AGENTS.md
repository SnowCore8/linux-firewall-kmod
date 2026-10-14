# AGENTS.md — 在这个仓库怎么干活

本文给人和 AI 代理看。每条事实都有仓库内出处。
没核实的说法标「未验证」。命令名、字段名、端口一律照源码。

## 这个项目做什么

一句话：读日志 → 判定坏 IP → netlink 下发 → 内核命中即丢。

链路分步，每步都能点到源码：

| 步 | 做什么 | 出处 |
|----|--------|------|
| 1 | inotify 跟日志文件，读增量行 | `src/daemon/internal/ingest/` |
| 2 | 正则或关键字从行里取 IP | `src/daemon/internal/logparse/` |
| 3 | 在 findtime 窗口数失败次数，够 max_retries 就判封 | `src/daemon/internal/decision/` |
| 4 | 经 netlink 下发封禁、白名单、配置 | `src/daemon/internal/kernel/` ↔ `src/kernel-module/fw_netlink.c` |
| 5 | netfilter 钩子查封禁表，命中丢包 | `src/kernel-module/fw_hook.c`、`fw_ban.c` |
| 6 | 内核事件与统计回推，汇成快照供面板读 | `src/daemon/internal/kernel/consumer.go` |

封禁在内核里生效，不看用户态进程有没有被调度走。
包路径上只做「命中封禁表就丢」，不表达 allow 规则、不做 NAT。

## 技术栈

| 部件 | 选型 | 出处 |
|------|------|------|
| 内核模块 | C，Linux Kernel Module + netfilter + RCU | `src/kernel-module/` |
| 守护进程 | Go（纯 Go，无 cgo） | `src/daemon/go.mod`（`go 1.26.0`） |
| 前端 | React 19 + TypeScript + Vite + antd-mobile 5 + three | `frontend/package.json` |
| 构建 | Makefile + Go toolchain + npm/vite | `Makefile` |
| 契约 | 自研 `.fwidl` + Python 生成器 | `contract/` |
| 集成测试 | Python pytest | `tests/`、`Makefile` 的 `test` 目标 |
| 端到端 | Playwright | `playwright.config.ts`、`tests/e2e/` |
| 配置 | YAML | `config/*.yaml` |
| 历史库 | SQLite（`modernc.org/sqlite`） | `src/daemon/internal/persist/` |
| 指标导出 | Prometheus 文本格式，端口 9119 | `config/default.yaml` 的 `metrics_port` |

## 目录结构

按当前 `ls` 核对过。

```text
linux-firewall-kmod/
├── src/
│   ├── kernel-module/          # 内核模块 C 源码，统一 fw_* 前缀
│   │   ├── Makefile            # kbuild 描述
│   │   ├── fw_main.c           # 模块入口 + 模块参数
│   │   ├── fw_hook.c           # netfilter 钩子
│   │   ├── fw_ban.c            # 封禁表：hlist + RCU + 每条自定时器
│   │   ├── fw_wl.c             # 白名单：精确桶 + 子网链
│   │   ├── fw_rate.c           # 速率、端口扫描、服务探测检测
│   │   ├── fw_ports.c          # 受保护端口位图（65536 位）
│   │   ├── fw_local.c          # 本机接口地址集合
│   │   ├── fw_netdev.c         # 网卡事件：重建本机地址、对账白名单
│   │   ├── fw_netlink.c        # netlink 通道
│   │   ├── fw_procfs.c         # /proc/firewall 条目
│   │   ├── fw_state.c          # 状态快照与还原
│   │   ├── fw_stats.c          # 每 CPU 统计聚合
│   │   └── fw_types.h          # 公共类型与表规模常量
│   │                           # 每个 .c 有同名 .h，此处不重复列
│   └── daemon/                 # Go 守护进程（一个 Go module）
│       ├── cmd/firewall-daemon/main.go  # 组合根：装配与生命周期
│       ├── internal/kernel/    # netlink 传输层与事件泵
│       ├── internal/http/      # HTTP/JSON API、SSE、认证、指标
│       ├── internal/httpcontract/  # 契约生成的路由常量与接口
│       ├── internal/contract/  # netlink 线格式的 Go 侧消息定义
│       ├── internal/bans/      # 封禁与白名单动作
│       ├── internal/detect/    # CIDR、失败窗口等检测原语
│       ├── internal/decision/  # 策略、窗口、DDoS、集群判定
│       ├── internal/runtime/   # 监督、调度、重载、定时器
│       ├── internal/ingest/    # 入站主链路（inotify）
│       ├── internal/logparse/  # 正则与关键字解析
│       ├── internal/jail/      # Jail 配置、校验、编译
│       ├── internal/config/    # 配置加载与严格校验
│       ├── internal/analysis/  # 异常、预测、推荐、网络分布
│       ├── internal/telemetry/ # 内核快照与速率历史
│       ├── internal/persist/   # SQLite 历史库
│       ├── internal/logger/    # JSON Lines 日志
│       └── web_ui/static/      # 面板产物，assets.go 用 go:embed 带进二进制
├── contract/                   # 单一真相源
│   ├── http.fwidl              # HTTP 与 SSE 契约
│   ├── procfs.fwidl            # /proc/firewall 契约
│   ├── netlink.fwidl           # netlink 线格式契约
│   ├── gen.py                  # 生成器
│   ├── verify_layout.py        # 二进制布局对账
│   ├── verify_procfs.py        # procfs 文本协议校验
│   ├── verify_http.py          # HTTP 面校验
│   ├── http_gap_baseline.txt   # HTTP 未接线条目基线，只减不增
│   └── generated/              # 生成物：C 头、TS、JSON 布局
├── frontend/                   # React 面板源码
│   ├── index.html              # 入口 HTML
│   ├── package.json            # 依赖与脚本
│   ├── package-lock.json       # 锁文件，CI 用 npm ci
│   ├── vite.config.ts          # 产物直接输出到 web_ui/static
│   ├── tsconfig.json           # jsx = react-jsx
│   ├── src/                    # App.tsx、main.tsx、api、views、charts…
│   └── public/                 # sw.js、manifest.webmanifest、icons
├── config/                     # Jail 配置（YAML）
│   ├── default.yaml            # 默认配置与全局 defaults
│   ├── _overrides.yaml         # 覆盖位
│   ├── nginx.yaml …            # 各服务 Jail
│   ├── logrotate/firewall-daemon
│   └── modules-load.d/firewall.conf
├── tests/                      # pytest 集成套件
│   ├── conftest.py             # fixtures 与辅助函数
│   ├── config.py               # 测试常量（路径、IP、参数）
│   ├── test_01_module_lifecycle.py …  # 编号套件
│   └── e2e/                    # Playwright 用例
├── scripts/                    # deploy.sh、e2e-daemon.sh、check_contract.sh、bench/
├── grafana/                    # 面板 JSON 与告警规则
├── docs/                       # HonKit 文档站，中文在 docs/zh/
├── debian/                     # deb 打包元数据（dpkg-buildpackage 那条路；make deb 不走它）
├── build/                      # 构建产物，git 忽略
├── .github/workflows/          # ci.yml、gitbook.yml、release.yml
├── Makefile                    # 唯一的构建入口
└── build-deb.sh                # deb 构建脚本
```

## 构建与运行

### Makefile 的真实目标

`make help` 只列了一部分。以下清单照 `Makefile` 抄：

| 目标 | 做什么 |
|------|--------|
| `all` | 默认目标 = `format-check` + `build` |
| `build` | `kernel-module` + `daemon` |
| `build-quick` | 同上，跳过格式检查 |
| `kernel-module` | 编内核模块，产物 `build/kernel-module/firewall.ko` |
| `daemon` | 先出面板产物，再 `go build` |
| `frontend` | 面板构建，产物写入 `src/daemon/web_ui/static/` |
| `frontend-install` | 只装依赖：`npm ci --no-audit --no-fund` |
| `frontend-typecheck` | 只跑 `tsc --noEmit`，不产出文件 |
| `format` | `clang-format -i`，只动 C 源码 |
| `format-check` | `clang-format --dry-run --Werror` + `yamllint config/` |
| `contract-drift` | 生成物必须等于生成器当前输出 |
| `contract-check` | 先 `contract-drift`，再跑三个校验器 |
| `ci` | `format-check` + `build` + `test` |
| `test` | `sudo python3 -m pytest tests/ -v`（依赖 `.ko` 与二进制） |
| `install` | 装模块、二进制、配置、状态目录、systemd、启动、验证 |
| `uninstall` | 反向卸载，逐项验证 |
| `deb` | 调 `./build-deb.sh`（它自己用 heredoc 生成 `DEBIAN/control`，不读 `debian/`） |
| `clean` | 删 `build/`、`go clean`、清面板产物但留 `assets.go` |
| `distclean` | `clean` + 清内核中间文件 |
| `help` | 打印目标列表 |

另有 `_guard_local_install` 目标：它写好了「禁止直接部署到本机」的拒绝文案与三条
合规路径，但没有挂进 `install` / `uninstall` 的依赖链，所以现在**不拦**——
`DESTDIR` 为空时 `sudo make install` 直接写宿主机。想只暂存不写本机就用
`make install DESTDIR=<目录>`（`depmod`/`insmod`/`systemctl` 那几步按
`[ -z "$(DESTDIR)" ]` 跳过），实机部署走 `./scripts/deploy.sh <host>`。

### 面板目标的三处事实（旧文档写错过）

1. 面板产物目标只依赖真实输入：
   `$(WEBUI_STATIC_DIR): frontend-install $(FRONTEND_SRCS)`。
   早期写法让 `frontend` 与面板目录互为依赖，make 丢弃其中一条
   （CI 日志 `Circular frontend <- src/daemon/web_ui/static dependency dropped`），
   结果是 `npm ci` 从不执行。
2. 重建前先清陈旧产物，但要留下 embed 持有文件：
   `find $(WEBUI_STATIC_DIR) -mindepth 1 ! -name assets.go -delete`。
3. `go build` 的 `-o` 必须是 `$(PWD)/$(DAEMON_BIN)`。
   那一行先 `cd $(DAEMON_SRCS_DIR)`，相对写法会把二进制写进
   `src/daemon/build/`，仓库根产物一直是空的。

`clean` 里的 `$(GOC) clean` 也修过：`go clean -cached` 是非法参数，
会让 `make clean` 以 exit 2 中断。

### 依赖

- Go：`src/daemon/go.mod` 写 `go 1.26.0`。
  `Makefile` 的引导检查用 `GOVER ?= 1.23`，只保证有 Go 可用。
- Node.js 22 + npm：CI 的 `frontend` 与 `build` 任务用
  `node-version: '22'`，装依赖用 `npm ci`。
- clang-format：`format-check` 与 CI 都调它。
  本仓库以 18 为准（`CHANGELOG.md` 记有一次 clang-format 18 清零）。
  不同大版本的排版规则不同，换版本会误报。
- 内核头文件：`KDIR ?= /lib/modules/$(shell uname -r)/build`，
  缺失时 `Makefile` 会打印可用目录并退出 1。
- Go 依赖全为纯 Go，无 cgo，不需要系统开发库。

### 常用命令

```bash
make                        # 格式检查 + 内核模块 + 守护进程
make build-quick            # 跳过格式检查
make kernel-module          # 只编内核模块
make daemon                 # 只编守护进程（先出面板）
make frontend               # 只构前端
make frontend-typecheck     # 只做 TS 类型检查
make clean                  # 清构建产物
make format                 # 格式化 C（不含 Go，见下）
cd src/daemon && gofmt -w ./cmd ./internal   # 格式化 Go
```

### 跑测试

```bash
make test                              # 集成测试，需要 root
cd src/daemon && go test ./...         # Go 单元测试
sudo python3 -m pytest tests/ -v       # 等价于 make test 的 pytest 部分
sudo python3 -m pytest tests/test_03_ban_unban.py -v   # 单个套件
npx playwright test                    # 浏览器端到端
```

端到端脚本走 `scripts/e2e-daemon.sh` 的 probe / start / stop / env。
内核模块加载不了的环境会显式跳过。
用例数随开发变动，以命令实时输出为准，别照文档抄数字。

### 手动加载与运行

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
sudo rmmod firewall

sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

模块参数名照 `src/kernel-module/fw_main.c` 的 `module_param`：
`fw_ban_time`、`state_file`、`fw_max_bans_per_second`、
`fw_max_rate_entries`、`fw_max_ban_entries`、
`fw_max_whitelist_entries`、`fw_max_local_ips`、
`fw_static_threshold`、`fw_dynamic_threshold`、`fw_ddos_detection`。

## 开发规范

### 格式化

改代码提交前必须跑。三件事互相独立，跑一件不等于另外两件：

| 检查 | 命令 | 覆盖 |
|------|------|------|
| C 格式 | `make format-check` | `src/kernel-module/*.c *.h` |
| C 自动修 | `make format` | 同上，只改 C |
| YAML | `make format-check` 附带 `yamllint config/` | 仅当装了 yamllint |
| Go 格式 | `cd src/daemon && gofmt -l ./cmd ./internal` | 输出必须为空 |
| Go 修格式 | `cd src/daemon && gofmt -w ./cmd ./internal` | |
| TS 类型 | `make frontend-typecheck` | `tsc --noEmit` |

### 编码规范

C 内核模块（以 `.clang-format` 为准）：

- 函数与变量 `snake_case`，宏 `UPPER_CASE`。
- 缩进 2 空格，行宽 80。
- K&R 括号风格。
- 注释写中文。
- 单个函数不超过 50 行。

Go 守护进程：

- `gofmt` 干净，`go vet ./cmd/... ./internal/...` 通过。
- 错误用 `fmt.Errorf("...: %w", err)` 包装。
- 注释写中文。
- 纯 Go，无 cgo，无 `unsafe`。

前端 TS：

- `strict`、`noUnusedLocals`、`noUnusedParameters`
  （见 `frontend/tsconfig.json`）。
- JSX 走 React 自动运行时：`jsx: "react-jsx"` +
  `jsxImportSource: "react"` + `@vitejs/plugin-react`。
  这两处必须成对改，否则 tsc 与打包器各解析一套实现。
- 注释写中文。

### 提交规范

Conventional Commits，格式 `类型(范围): 描述`。
类型表见 [CONTRIBUTING.md](CONTRIBUTING.md)。
一次提交只做一件事。

### 测试分层

| 层 | 命令 | 说明 |
|----|------|------|
| 单元 | `cd src/daemon && go test ./...` | Go 包内 `_test.go` |
| 集成 | `make test` | `tests/test_*_*.py`，需要 root |
| 端到端 | `npx playwright test` | `tests/e2e/*.spec.ts` |

改以下内容必跑集成套件：

- YAML 配置 schema 与字段含义。
- `/proc/firewall/*` 的节点与写文法。
- 守护进程与内核模块的 netlink 协议。
- `contract/*.fwidl`。

集成套件是行为规格，不是可协商的文档。
规格与实现冲突时，先确认哪一侧错，别改测试迁就实现。

### 质量门禁

本地提交前跑齐，CI 按同样口径：

```bash
make format-check
make contract-check
cd src/daemon && gofmt -l ./cmd ./internal
cd src/daemon && go vet ./cmd/... ./internal/...
cd src/daemon && go test ./...
make test
```

## 契约

`contract/http.fwidl`、`contract/procfs.fwidl`、
`contract/netlink.fwidl` 是线格式与文本协议的单一真相源。

生成物在 `contract/generated/`（C 头、TS、JSON 布局）
和 `src/daemon/internal/httpcontract/http_contract.go`。

改流程：

1. 改 `.fwidl`。
2. 跑 `python3 contract/gen.py` 重新生成。
3. 跑 `make contract-drift`（生成物必须等于生成器输出）。
4. 跑 `make contract-check`（三个校验器全跑完再汇总退出码）。

HTTP 面尚未接线的条目冻结在 `contract/http_gap_baseline.txt`。
规则是只减不增：新缺口要显式加行，补上了要删行。

请求体里的 `Option<T>` 生成 TS 的 `field?: T | null`。
缺席和 `null` 都合法，语义是「可以整个不提交」，
不是「必填但可为 null」。出处：`contract/gen.py` 的请求侧生成逻辑。

生成器有自检：`verify_http.py` 会把生成的 `http_contract.go`
真编一遍，所以要传 `GO` 环境变量（`make contract-check` 已传）。

## 核心功能

### procfs 接口

条目与权限照 `contract/procfs.fwidl`，生成到
`contract/generated/procfs_uapi.h`。

| 条目 | 权限 | 说明 |
|------|------|------|
| `bans` | 0600 可写 | 封禁与解封 |
| `whitelist` | 0600 可写 | 白名单增删 |
| `config` | 0600 可写 | 写 `ban_time <秒>`，读当前配置 |
| `stats` | 0400 | 13 个计数器，每行 `<key> <value>` |
| `rates` | 0400 | 速率表明细 |
| `udp_ports` | 0400 | UDP 端口分布 |
| `icmp_types` | 0400 | ICMP 类型分布 |
| `pkt_sizes` | 0400 | 包大小分布 |
| `ttl_dist` | 0400 | TTL 分布 |
| `ip_frags` | 0400 | IP 分片统计 |
| `port_scanners` | 0400 | 端口扫描嫌疑，阈值 5 个唯一端口 |
| `service_probes` | 0400 | 服务探测嫌疑，阈值 3 种协议 |
| `protected_ports` | 0400 | 受保护端口集合，只读观测面 |

```bash
echo "1.2.3.4"       | sudo tee /proc/firewall/bans   # 默认时长
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans   # 自定义
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans   # 永久
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist
cat /proc/firewall/stats
```

`bans` 的输出形状是 `<ip> (permanent)` 或
`<ip> (expires in <N> seconds)`。不是表格。
写文法的完整定义在 `contract/procfs.fwidl` 的 `write` 段。

受保护端口集合只由守护进程经 netlink 下发，procfs 不提供写入口。
位图为空时语义是「全端口受保护」，出处 `src/kernel-module/fw_ports.c`。

配置的 `trusted_ips` 是白名单的第二个写入者：组合根在拿到内核守护进程租约之后逐条下发
（`src/daemon/cmd/firewall-daemon/main.go` 的 `pushTrustedIPs`）。单 IP 与 CIDR 都接受，
键的归一化与 HTTP 写入侧同源（`internal/bans/whitelist_prefix.go`）；一条解析失败只跳过
并告警，不阻断启动。只有启动时下发一次，改这一段要重启。

### Jail

一个 Jail = 一个日志源 + 一组正则 + 一套封禁参数。
配置在 `config/*.yaml`，`jails:` 段的每个键是一个 Jail 名。

字段照 `src/daemon/internal/config/parser.go` 的 `yamlJail`：
`enabled`、`log_files`、`max_retries`、`findtime`、`ban_time`、
`regex`、`regex_name`、`regexes`、`cluster`。
`regex` 是单条写法，`regexes` 是嵌套映射，两种都支持。

- `ban_time: -1` 在守护进程侧表示永久
  （`src/daemon/internal/config/types.go`）。
  procfs 写入侧的永久写法是 `echo "<ip> 0"`（`contract/procfs.fwidl` 的 `write bans`）。
  两边取值不同，`src/daemon/internal/config/kernel_view.go`
  负责不把 `-1` 直接发给内核。
- 每个 Jail 的正则最多 10 条
  （`src/daemon/internal/config/types.go` 的 `MaxRegexPatterns`）。
- 正则最长 1024 字节、分支最多 50；嵌套量词、占有量词、量化交替组
  这类易回溯模式直接拒绝编译。校验逻辑在
  `src/daemon/internal/logparse/rule.go`。
- 正则编译失败只告警，该 Jail 退化为解析层的关键字回退，进程不退。
  这条是 `jail.Finalize` 的当前改动方向，未提交前以工作树为准。
- 结构性非法配置（未知键、非法值、`Validate` 拒绝）仍然拒绝启动。
  严格模式默认开，`--no-strict` 才忽略未知键
  （`src/daemon/internal/config/args.go`）。

### 速率与检测

内核侧（`src/kernel-module/fw_rate.c`）：

- PPS / BPS 计数，按协议分别看 SYN、UDP、ICMP、ACK、RST、FIN。
- 端口扫描与服务探测识别，见上面两个 procfs 条目。
- 阈值由 `config/default.yaml` 的 `ddos:` 段下发：
  `max_syn_per_second`、`max_udp_per_second`、`max_icmp_per_second`、
  `max_ack_per_second`、`max_rst_per_second`、`max_fin_per_second`、
  `auto_ban_duration`、`auto_ban_threshold`、`max_bans_per_second`。
- 每秒封禁数受 `fw_max_bans_per_second` 限流（`fw_ban_flood_allow`）。

守护进程侧集群检测（`src/daemon/internal/decision/cluster.go`）：

- 判据方向：同一网段内 IP 多、每个 IP 次数少。
- 参数在配置的 `cluster:` 段：`prefix_v4`（默认 24）、
  `prefix_v6`（默认 48）、`window`（默认 60）、`min_ips`（默认 5）、
  `max_per_ip`、`ban_time`、`audit_only`。
- 默认关闭，默认只审计不封
  （`src/daemon/internal/config/types.go` 的 `DefaultClusterConfig`）。

### 指标面

`/metrics` 需要认证，端口来自 `defaults.metrics_port`（默认 9119）。
只导出守护进程计数器，无 gauge。名字照源码：

| 指标 | 出处 |
|------|------|
| `firewall_lines_parsed_total` | `src/daemon/cmd/firewall-daemon/main.go` 的 statsSink |
| `firewall_lines_skipped_total` | 同上 |
| `firewall_regex_matches_total` | 同上 |
| `firewall_inotify_events_total` | 同上 |
| `firewall_log_rotations_total` | 同上 |
| `firewall_bans_triggered_total` | 同上 |
| `firewall_daemon_config_reloads_total` | 同上 |
| `firewall_ddos_events_total` | `src/daemon/internal/kernel/consumer.go` |
| `firewall_kernel_commands_rejected_total` | 同上 |
| `firewall_netlink_messages_sent_total` | `src/daemon/internal/kernel/transport.go` |
| `firewall_netlink_messages_received_total` | 同上 |
| `firewall_netlink_recv_errors_total` | 同上 |
| `firewall_netlink_send_errors_total` | 同上 |

内核侧读数不走 Prometheus。封禁、白名单、速率统计由
`/proc/firewall/stats` 的键值文本给出，经事件泵汇入内存快照，
再由 `/api/v1/stats` 与 `/health` 透出。

### 面板与认证

移动端优先的 React 面板，产物经
`src/daemon/web_ui/static/assets.go` 的 `//go:embed *` 带进二进制。
访问 `http://<host>:9119/dashboard`。

- 路由用 hash 模式。守护进程只对若干固定路径返回同一份 HTML，
  没有 catch-all。出处：`frontend/vite.config.ts` 顶部注释。
- 认证是 HTTP Basic，凭据来自 `defaults.metrics_username`
  和 `defaults.metrics_password`。
  两项都为空才视为未配置认证并放行；只填一项判失败。
  出处：`contract/http.fwidl` 的 `auth` 段。
- 连续失败 10 次锁定 60 秒，锁定期内正确凭据也拒。
  参数名 `failure_threshold` / `lockout_seconds`，同一出处。
- 登录表单在应用内，不用浏览器原生对话框。
  SPA 外壳是公开路由，顶层文档不返回 401，原生对话框不会出现。
- `/api/v1/**` 的 401 不带 `WWW-Authenticate` 头。
- 令牌存 `sessionStorage`，键 `firewall.access_token`。
  每个 `fetch` 显式带 `Authorization: Basic <令牌>`。
- SSE 走 `?access_token=<令牌>`，因为 `EventSource` 不能设请求头。
  免登录直达：`http://<host>:9119/?access_token=<base64(user:pass)>`，
  写入 `sessionStorage` 后从地址栏清掉。
- SSE 连接上限：`/api/v1/events` 10 条，`/api/v1/logs/stream` 5 条，
  两条各自独立。超限返回 503。出处：`contract/http.fwidl`。

### PWA 的限制

- `frontend/public/manifest.webmanifest` + 手写 Service Worker
  `frontend/public/sw.js`。守护进程用 `GET /sw.js` 提供，
  带 `Service-Worker-Allowed: /`。
- `/api/*` 不做缓存，保证读数新鲜。
- Service Worker 只在安全上下文注册（HTTPS 或 localhost）。
  用局域网 `http://<ip>:9119` 访问时浏览器会静默拒绝注册：
  界面能用，但无法「添加到主屏幕」。
  需要安装能力就用 HTTPS 或本机 localhost。

### 历史库与地理库

- 封禁事件写 SQLite（`src/daemon/internal/persist/`），
  供趋势与热力图读没有实时源的那一维。
- 失败次数与 DDoS 命中目前只有本进程累计值，没有按天历史。
  因此 `/api/v1/stats` 的 `failed_attempts_trend` 与热力图的
  `failed_attempts`、`ddos_events` 两列报空或全零。
  这是契约里记着的已知缺口：
  `contract/http.fwidl` 的 `HTTP_FAILURE_HISTORY_NOT_PERSISTED`。
- 攻击地图需要城市级 GeoIP 库，用 `scripts/fetch-geoip.sh` 取。
  国家库没有经纬度，不能打点。

## 内核版本口径

已验证：6.8.0-146（Ubuntu 24.04 GA 内核），可编译、可 `insmod`、
`/proc/firewall` 条目齐全。7.0.0-38 可编译。
5.x 未做过任何验证（未验证）。

README 顶部的徽章写的是实测范围（`Linux 6.8 loaded | 7.0 builds`），不是兼容承诺；
没实测过的版本范围不写进徽章。6.x 内部有真实的 API 断层，两处已在 `src/kernel-module/` 显式适配：

1. `timer_container_of` 与 `from_timer`
   按「宏是否存在」适配，不比 `LINUX_VERSION_CODE`。
   前者是 6.16 引入的名字，7.0 起旧名已删，两个名字不共存。
   6.8 只有 `from_timer`。出处：`src/kernel-module/fw_ban.c` 的兼容宏。
2. 单次 per-CPU 申请有 32 KiB 上限。
   速率槽表整表 512 槽是 168 × 512 = 86016 字节，超上限会拿到 NULL。
   所以按 `FW_RATE_CHUNK_SLOTS=128` × `FW_RATE_CPU_CHUNKS=4`
   分块申请。**索引空间仍是 0..511，`slot_idx` 语义不变，容量没变。**
   出处：`fw_types.h` 与 `fw_rate.c` 的注释。

新版本内核的验证记录随 `CHANGELOG.md` 补，别只凭徽章宣称范围。

## 常见坑

只列真撞过的。

1. **编译过不等于加载得了。**
   CI 的 runner 用自定义内核，编出的 `.ko` 可能 `insmod` 不了。
   `e2e` 与 `test` 任务都先探测可加载性，加载不了就显式跳过并加注解。
   真要验证加载，得在能 `insmod` 的机器上跑 `make test`。
2. **本地 `node_modules` 齐全会掩盖 `package.json` 缺依赖。**
   CI 用 `npm ci` 按 `package.json` 裁剪安装。
   依赖段丢过一次，本地照跑，CI 全线 `tsc` 报错。
   验证前端必须走 `npm ci`，别用现成的 `node_modules`。
   `package.json` 与 `package-lock.json` 要同步。
3. **只跑 `make format` 不跑 `make format-check` 会漏。**
   `format` 只格式化 C，不管 Go 和 YAML。
   Go 要单独 `gofmt -w`，YAML 只在 `format-check` 里查。
4. **`go build` 的 `-o` 要用绝对路径。**
   见上面面板目标那三条。
5. **`clean` 不能删 `assets.go`。**
   它是 `go:embed` 的持有文件。删了之后 `go build`
   报「包内无 .go 文件」。`Makefile` 的清理动作都带 `! -name assets.go`。
6. **vite 的 `emptyOutDir` 必须是 false。**
   同一个目录里住着 `assets.go`，清空会连它一起删。
   陈旧文件的清理由 `make frontend` 的前置步骤完成。

## CI

`.github/workflows/ci.yml` 六个任务：

| 任务 | 名 | 做什么 |
|------|----|--------|
| `lint` | 代码质量检查 | `clang-format --dry-run --Werror`、`gofmt -l`、`go vet`、`go test ./...`、`yamllint` |
| `contract` | 契约一致性 | `make contract-drift`、`verify_layout.py`、`verify_procfs.py`、`verify_http.py` |
| `frontend` | 前端构建 | `npm ci`、`npm run typecheck`、`npm run build:only`、产物与 manifest 校验、`node --check sw.js` |
| `build` | 编译 | `make clean` + `make all`，编内核模块与守护进程，上传产物 |
| `e2e` | 浏览器端到端 | 起真守护进程跑 Playwright，模块加载不了则跳过 |
| `test` | 运行测试 | 装 `sqlite3`、`python3-pytest`、`python3-yaml`，跑 pytest 套件 |

`.github/workflows/gitbook.yml` 用 HonKit 构多语言文档站并发 GitHub Pages，
Node 20，装依赖走 `docs/package-lock.json`。
`docs/package.json` 的 `overrides` 把 `brace-expansion` 与 `moment`
锁进有补丁的版本。`braces` 与 `sprintf-js` 上游没有补丁，
按可接受风险处置（这条是维护者裁定，仓库里没有记录文件）。

## 文档索引

以下路径逐个 `ls` 确认存在。

根文档：

- [README.md](README.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [STANDARDS.md](STANDARDS.md)
- [CHANGELOG.md](CHANGELOG.md)
- [LICENSE](LICENSE)

快速开始：

- [docs/zh/getting-started/quick-start.md](docs/zh/getting-started/quick-start.md)
- [docs/zh/getting-started/installation.md](docs/zh/getting-started/installation.md)

架构：

- [docs/zh/architecture/kernel-module.md](docs/zh/architecture/kernel-module.md)
- [docs/zh/architecture/daemon.md](docs/zh/architecture/daemon.md)
- [docs/zh/architecture/frontend.md](docs/zh/architecture/frontend.md)
- [docs/zh/architecture/data-flow.md](docs/zh/architecture/data-flow.md)

配置：

- [docs/zh/configuration/yaml-config.md](docs/zh/configuration/yaml-config.md)
- [docs/zh/configuration/procfs.md](docs/zh/configuration/procfs.md)
- [docs/zh/configuration/examples.md](docs/zh/configuration/examples.md)

开发：

- [docs/zh/development/building.md](docs/zh/development/building.md)
- [docs/zh/development/testing.md](docs/zh/development/testing.md)
- [docs/zh/development/kernel-rewrite-design.md](docs/zh/development/kernel-rewrite-design.md)
- [docs/zh/development/cluster-detection-design.md](docs/zh/development/cluster-detection-design.md)
- [docs/zh/development/perf-baseline.md](docs/zh/development/perf-baseline.md)

运维：

- [docs/zh/operations/management.md](docs/zh/operations/management.md)
- [docs/zh/operations/monitoring.md](docs/zh/operations/monitoring.md)
- [docs/zh/operations/troubleshooting.md](docs/zh/operations/troubleshooting.md)

GitHub 模板：

- [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)
- [.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md)
- [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md)

## 许可证

MIT License，见 [LICENSE](LICENSE)。
