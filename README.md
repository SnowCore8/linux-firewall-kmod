# Firewall

读日志，判定坏 IP，下发到内核。内核收到包就丢。

[![CI](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml/badge.svg)](https://github.com/SnowCore8/linux-firewall-kmod/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Release](https://img.shields.io/badge/release-v2.2.0-green.svg)](https://github.com/SnowCore8/linux-firewall-kmod/releases)
[![Language](https://img.shields.io/badge/Language-Go%20%7C%20C-blue.svg)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%206.8%20loaded%20%7C%207.0%20builds-orange.svg)](#内核版本口径)

## 这是什么

判定在用户态，丢包在内核态。两条链路：

| 链路 | 走法 | 出处 |
|------|------|------|
| 判定 | inotify 读日志 → 正则或关键字取 IP → 窗口内数失败次数 | `src/daemon/internal/ingest/`、`logparse/`、`decision/` |
| 生效 | netlink 下发封禁 → netfilter 钩子查封禁表 → 命中即丢 | `src/daemon/internal/kernel/`、`src/kernel-module/fw_hook.c`、`fw_ban.c` |

守护进程被调度走，也不影响已经在内核表里的封禁。

## 项目目标

三条判据。每条都有验收方。

| 判据 | 说什么 | 谁验收 |
|------|--------|--------|
| 防护真的在跑 | 守护进程和内核模块要处于工作状态。单个 jail 的配置劣化不能让整个进程起不来 | [`STANDARDS.md`](STANDARDS.md) 把「封禁失效、日志解析完全错误」定为 Critical；[`tests/`](tests/) 集成套件是行为规格 |
| 装得进普通 Linux | 目标发行版上 `.ko` 编得出来、载得进去，`/proc/firewall` 要出现。编过不等于载得进 | [`tests/test_01_module_lifecycle.py`](tests/test_01_module_lifecycle.py)；见下面「内核版本口径」 |
| 分得开扫描器和正常访客 | 扫描的形态是同一网段里 IP 多、每个 IP 次数少 | [`src/daemon/internal/decision/cluster.go`](src/daemon/internal/decision/cluster.go) 的判据说明、[`docs/zh/development/cluster-detection-design.md`](docs/zh/development/cluster-detection-design.md)、[`config/frp.yaml`](config/frp.yaml) 的停用原因 |

口径：宁可少封。不能不封，不能乱封，不能在用户的机器上起不来。

### 配置写坏了会怎样

正则编译不出来，只影响那一个 jail。该 jail 退到解析层的关键字回退，其余 jail 照常。
出处：`jail.Finalize` 把编译失败放进 warnings，[`src/daemon/cmd/firewall-daemon/main.go`](src/daemon/cmd/firewall-daemon/main.go)
逐条打告警后继续启动。热重载和回滚走同一口径（`internal/runtime/file_reloader.go`）。

结构性非法的配置仍然致命：未知键、非法值、`Validate` 拒绝，都会拒绝启动或拒绝重载。
严格模式默认开，`--no-strict` 才忽略未知键。出处：`src/daemon/internal/jail/jail.go`、
`src/daemon/internal/config/args.go`。

## 非目标

- 不是通用防火墙。不表达 allow 规则，不做 NAT、端口映射、QoS。钩子只返回
  `NF_ACCEPT` 和 `NF_DROP`，出处：[`src/kernel-module/fw_hook.c`](src/kernel-module/fw_hook.c)。
- 包路径上只做「命中封禁表就丢」。不追求吞吐本身。性能口径是「不拖垮宿主」：
  [`STANDARDS.md`](STANDARDS.md) 把 10Gbps 目标场景下性能下降超过 30% 定为 High。
- 不做应用层。不解析 HTTP 语义，不看 payload。
- 不是零配置。每个 jail 要写日志路径和正则。

## 交付形态

| 部件 | 形态 | 位置 |
|------|------|------|
| 内核模块 | 单个 `firewall.ko`，C，netfilter + RCU + 哈希表 | [`src/kernel-module/`](src/kernel-module/) |
| 守护进程 | 一个 Go 二进制。面板经 `//go:embed` 一起装进去 | [`src/daemon/`](src/daemon/)，组合根 `cmd/firewall-daemon/main.go` |
| 操作面 | procfs 13 个条目、HTTP/JSON API、SSE、Prometheus 指标 | [`contract/procfs.fwidl`](contract/procfs.fwidl)、[`contract/http.fwidl`](contract/http.fwidl) |

接口清单的唯一出处是 `contract/`，生成物在 `contract/generated/`。

## 快速开始

### 依赖

| 依赖 | 取值 | 出处 |
|------|------|------|
| Go | `go 1.26.0` | [`src/daemon/go.mod`](src/daemon/go.mod) |
| Node.js | 22 | [`.github/workflows/ci.yml`](.github/workflows/ci.yml) 的 `setup-node` |
| 内核头文件 | `KDIR ?= /lib/modules/$(uname -r)/build` | [`Makefile`](Makefile) |
| clang-format | 大版本按 18 | [`CHANGELOG.md`](CHANGELOG.md)（clang-format 18 清零那次）；检查由 `Makefile` 的 `format-check` 与 CI 的 lint 任务执行 |

Go 依赖全是纯 Go，无 cgo，不需要系统开发库。

### 编译

```bash
make                   # 格式检查 + 内核模块 + 守护进程
make build-quick       # 同上，跳过格式检查
make kernel-module     # 只编内核模块，产物 build/kernel-module/firewall.ko
make daemon            # 只编守护进程：先 npm ci 和 npm run build 出面板，再 go build
make frontend          # 只构面板，产物写入 src/daemon/web_ui/static/
make frontend-typecheck # 只跑 tsc --noEmit
make clean             # 清构建产物，保留 assets.go
```

面板目录里住着 `assets.go`，它是 `go:embed` 的持有文件。构建和清理都不删它。
出处：`Makefile` 的 `$(WEBUI_STATIC_DIR)` 规则、`src/daemon/web_ui/static/assets.go`。

### 安装

```bash
sudo make install      # 装模块、二进制、配置、systemd 单元，并启动服务
sudo make uninstall    # 逐项反向卸载并验证
make install DESTDIR=$(pwd)/build/stage   # 只暂存，不写本机
```

`install` 的落点：`/lib/modules/$(uname -r)/extra/firewall.ko`、
`/usr/local/sbin/firewall-daemon`、`/etc/firewall/`、`/var/lib/firewall/`、
`/etc/systemd/system/firewall-daemon.service`。出处：`Makefile` 的 `install-*` 目标。

远程部署走 [`scripts/deploy.sh`](scripts/deploy.sh)：本地编译，只上传产物。

### 加载模块

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600
cat /proc/firewall/config
sudo rmmod firewall
```

参数名照 `src/kernel-module/fw_main.c` 的 `module_param`：`fw_ban_time`、`state_file`、
`fw_max_bans_per_second`、`fw_max_rate_entries`、`fw_max_ban_entries`、
`fw_max_whitelist_entries`、`fw_max_local_ips`、`fw_static_threshold`、
`fw_dynamic_threshold`、`fw_ddos_detection`。

### 跑守护进程

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml   # 单文件
sudo ./build/daemon/firewall-daemon -C /etc/firewall         # 目录，按名字母序合并
sudo ./build/daemon/firewall-daemon --help                   # 全部参数
```

不带 `-c` / `-C` 时读 `/etc/firewall-daemon/config.yml`。出处：`internal/config/args.go`
的 `DefaultConfigPath`。

启动会先确认 `/proc/firewall` 和 `/proc/firewall/bans` 存在。缺了就报启动失败并退出，
不会带着缺内核的壳继续跑。出处：`cmd/firewall-daemon/main.go` 的 `checkProcfs`。

### 看面板

默认监听 `127.0.0.1:9119`。地址由 `defaults.metrics_bind_address` 和
`defaults.metrics_port` 合成，出处：`internal/config/types.go` 的 `ListenAddress`。
`metrics_port` 设为 0 即关掉整个 HTTP 面。

```text
http://127.0.0.1:9119/dashboard
```

配了 `metrics_username` 和 `metrics_password` 就要登录。两项都空才是不启用认证。
凭据填错 10 次会锁 60 秒，锁定期内正确凭据也拒。出处：`contract/http.fwidl` 的 `auth` 段。

### 手动封禁

```bash
echo "1.2.3.4"       | sudo tee /proc/firewall/bans   # 默认时长
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans   # 指定秒数
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans   # 永久
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
echo "10.0.0.0/8"    | sudo tee /proc/firewall/whitelist
```

写文法的完整定义在 `contract/procfs.fwidl` 的 `write` 段。写失败返回负 errno，
没有文本错误通道，原因只进内核日志。

### 打 deb 包

```bash
make deb    # 调 ./build-deb.sh，DKMS 模式：装包时在目标机编内核模块
```

### 跑测试

```bash
make test                          # sudo python3 -m pytest tests/ -v
cd src/daemon && go test ./...     # Go 单元测试
npx playwright test                # 浏览器端到端，见 tests/e2e/
```

用例数量以命令实时输出为准。CI 的 test 任务在内核模块加载不了时会筛掉内核套件，
只跑守护进程相关用例。出处：`.github/workflows/ci.yml`。

## 核心能力

只列代码里真有的。

| 能力 | 实现 | 出处 |
|------|------|------|
| 日志采集 | inotify 监视，按源读增量，处理轮转 | `src/daemon/internal/ingest/` |
| 取 IP | 正则命名捕获组；正则不可用时走关键字回退 | `src/daemon/internal/logparse/` |
| 单 IP 判定 | findtime 窗口内失败次数达阈值；阈值乘高峰 1.5、内网 2.0、信誉系数 | `src/daemon/internal/decision/policy.go` |
| 渐进式时长 | 第 2 次 1800 秒，第 3 次 86400 秒，第 4 次起永久 | 同上 |
| 集群扫描判定 | 同网段内低频源 IP 数达标；默认关闭，默认只审计不封 | `decision/cluster.go`、`config/types.go` 的 `DefaultClusterConfig` |
| 内核封禁表 | 按前缀长度分层桶表，hlist + RCU，每条自带到期定时器；支持 CIDR | `src/kernel-module/fw_ban.c` |
| 白名单 | 64 个精确桶 + 子网链，两阶段匹配 | `fw_types.h`、`fw_wl.c` |
| 本机地址豁免 | 网卡事件重建本机精确地址集合，钩子里先于封禁表判定 | `fw_local.c`、`fw_netdev.c`、`fw_hook.c` |
| 速率检测 | PPS / BPS，协议专项 SYN、ACK、RST、FIN、UDP、ICMP | `fw_rate.c` |
| 端口扫描识别 | 唯一端口数达 5 即入列，最多显示 20 条 | `fw_types.h` 的 `PORT_SCAN_THRESHOLD`、`procfs.fwidl` |
| 服务探测识别 | 协议种类达 3 即入列，最多显示 20 条 | `fw_types.h` 的 `SERVICE_PROBE_THRESHOLD` |
| 受保护端口 | daemon 扫本机监听端口下发位图；位图为空时按全端口受保护处理 | `fw_ports.c` |
| 泛洪闸门 | 每秒封禁添加次数受 `fw_max_bans_per_second` 限，三条下发路径共用 | `fw_ban.c` 的 `fw_ban_flood_allow` |
| 状态持久化 | 封禁与白名单写 `state_file`，默认 `/var/lib/firewall/state` | `fw_state.c`、`fw_main.c` |
| procfs 面 | 3 个可写条目 0600，10 个只读条目 0400 | `contract/generated/procfs_uapi.h` |
| HTTP API | `/api/v1/` 下的读取与写入端点，统一信封 | `contract/http.fwidl` |
| SSE | `/api/v1/events` 上限 10 条，`/api/v1/logs/stream` 上限 5 条，两条独立，超限回 503 | `contract/http.fwidl` |
| 指标 | `/metrics` 导出 13 个守护进程计数器，无 gauge | `cmd/firewall-daemon/main.go`、`internal/kernel/` |
| 历史库 | SQLite 存封禁事件与信誉分，供趋势和热力图读数 | `internal/persist/` |
| 面板 | React 19 + antd-mobile 5 + react-router-dom 7（hash 路由）+ three，产物嵌进二进制 | [`frontend/package.json`](frontend/package.json)、`frontend/src/views/` |
| 热重载 | SIGHUP 或配置文件变化触发；`--rollback` 发 SIGUSR1 回到上一版 | `internal/runtime/`、`cmd/firewall-daemon/main.go` |

内核侧读数不走 Prometheus。封禁、白名单、速率统计由 `/proc/firewall/stats` 的
键值文本给出，经事件泵汇入内存快照，再由 `/api/v1/stats` 与 `/health` 透出。

## 内核版本口径

顶部徽章写的是实测范围，不是兼容承诺。

| 内核 | 验证到哪一步 | 出处 |
|------|--------------|------|
| 6.8.0-146（Ubuntu 24.04 GA） | `make kernel-module` 通过、可 `insmod`、`/proc/firewall/` 13 个条目齐全、dmesg 无 percpu WARN | [`CHANGELOG.md`](CHANGELOG.md) 的「验证」段 |
| 7.0.0-38 | 仅 `make kernel-module` 通过，未在该内核上加载验证 | 同上 |
| 5.x | 未做过任何验证（未验证） | — |

「6.x」不等于 6.x 里每个内核都验证过。6.x 内部有真实的 API 断层，两处已在
`src/kernel-module/` 显式适配：

1. `timer_container_of` 与 `from_timer` 是两个时期的名字，不共存。适配按「宏是否
   存在」判断，不比 `LINUX_VERSION_CODE`，因为发行版会 backport。出处：`fw_ban.c`
   的兼容宏。
2. 单次 per-CPU 申请有 32 KiB 上限。速率槽表整表 512 槽会超限拿到 NULL，所以按
   128 槽 × 4 块分别申请。索引空间仍是 0..511，容量没变。出处：`fw_types.h` 的
   `FW_RATE_CHUNK_SLOTS` 与 `fw_rate.c` 的注释。

新内核上的验证记录随 `CHANGELOG.md` 补。没实测过的版本范围不写进徽章。

## 文档索引

以下路径逐个确认存在。

根文档：[CONTRIBUTING.md](CONTRIBUTING.md)、[SECURITY.md](SECURITY.md)、
[STANDARDS.md](STANDARDS.md)、[CHANGELOG.md](CHANGELOG.md)、[LICENSE](LICENSE)。

| 主题 | 路径 |
|------|------|
| 快速开始 | [docs/zh/getting-started/quick-start.md](docs/zh/getting-started/quick-start.md)、[docs/zh/getting-started/installation.md](docs/zh/getting-started/installation.md) |
| 架构 | [docs/zh/architecture/kernel-module.md](docs/zh/architecture/kernel-module.md)、[docs/zh/architecture/daemon.md](docs/zh/architecture/daemon.md)、[docs/zh/architecture/frontend.md](docs/zh/architecture/frontend.md)、[docs/zh/architecture/data-flow.md](docs/zh/architecture/data-flow.md) |
| 配置 | [docs/zh/configuration/yaml-config.md](docs/zh/configuration/yaml-config.md)、[docs/zh/configuration/procfs.md](docs/zh/configuration/procfs.md)、[docs/zh/configuration/examples.md](docs/zh/configuration/examples.md) |
| 开发 | [docs/zh/development/building.md](docs/zh/development/building.md)、[docs/zh/development/testing.md](docs/zh/development/testing.md)、[docs/zh/development/kernel-rewrite-design.md](docs/zh/development/kernel-rewrite-design.md)、[docs/zh/development/cluster-detection-design.md](docs/zh/development/cluster-detection-design.md)、[docs/zh/development/perf-baseline.md](docs/zh/development/perf-baseline.md) |
| 运维 | [docs/zh/operations/management.md](docs/zh/operations/management.md)、[docs/zh/operations/monitoring.md](docs/zh/operations/monitoring.md)、[docs/zh/operations/troubleshooting.md](docs/zh/operations/troubleshooting.md) |
| 提 Issue | [.github/ISSUE_TEMPLATE/bug_report.md](.github/ISSUE_TEMPLATE/bug_report.md)、[.github/ISSUE_TEMPLATE/feature_request.md](.github/ISSUE_TEMPLATE/feature_request.md) |

## 质量门禁

提交前跑齐这几条。CI 按同样口径检查。

```bash
make format-check
make contract-check
cd src/daemon && gofmt -l ./cmd ./internal   # 输出须为空
cd src/daemon && go vet ./cmd/... ./internal/...
cd src/daemon && go test ./...
make test
```

`make format` 只格式化 C。Go 要单独 `gofmt -w`，YAML 只在 `format-check` 里查。

## 许可证与联系

- 许可证：MIT，见 [LICENSE](LICENSE)。内核模块源码声明为 Dual MIT/GPL，
  出处：`src/kernel-module/fw_main.c` 的 `MODULE_LICENSE`。
- 作者：[SnowCore8](https://github.com/SnowCore8)
- 邮箱：snowcore8@gmail.com
- 问题反馈：[Issues](https://github.com/SnowCore8/linux-firewall-kmod/issues)
