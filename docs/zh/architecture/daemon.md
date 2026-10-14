# 用户态守护进程

`firewall-daemon` 是内核模块的用户态对手侧。它读日志、判定坏 IP、
经 netlink 下发封禁与白名单，并把状态经 HTTP / SSE 透出。

两条边界：

- 守护进程与内核之间的内部通道**只有 netlink**。
  `/proc/firewall/*` 给人和运维用，不是内部通道。
- 威胁模型是入站单向防守。没有出站钩子，没有外发检测。

相关文档：

- 报文判定路径：[数据流](data-flow.md)
- 内核侧结构：[内核模块](kernel-module.md)
- 面板：[Web 前端](frontend.md)
- 接口真相源：`contract/netlink.fwidl`、`contract/procfs.fwidl`、`contract/http.fwidl`
- 配置字段：`docs/zh/configuration/yaml-config.md`

## 技术栈

| 项 | 内容 | 出处 |
|----|------|------|
| 语言 | Go，纯 Go，无 cgo | `src/daemon/go.mod`；全仓无 `import "C"` |
| Go 版本 | `go 1.26.0` | `src/daemon/go.mod` |
| 组合根 | `cmd/firewall-daemon/main.go` | `main` / `run` |
| 业务包 | `internal/*` | 见下文包职责表 |
| 依赖 | `golang.org/x/sys`、`gopkg.in/yaml.v3`、`modernc.org/sqlite` | `src/daemon/go.mod` 的 `require` |
| 产物 | 单文件 stripped 二进制，内嵌面板 | 根 `Makefile`：`go build -ldflags "-s -w=1"` |
| 面板嵌入 | `//go:embed *` | `src/daemon/web_ui/static/assets.go` |

## 包职责

包名以 `ls src/daemon/internal/` 为准。

| 包 | 拥有什么 | 对外提供 |
|----|---------|---------|
| `kernel/` | netlink socket 与在途请求 | `transport`（单写者）、`codec`（字节↔语义）、`router`（按 `(type, seq)` 路由）、`reactor`（接收回路）、`client`（类型化请求）、`consumer`（事件泵、采样、对账） |
| `http/` | HTTP 面 | 路由注册、REST 处理器、两条 SSE 流、`/metrics`、认证与失败锁定、静态面板挂载 |
| `httpcontract/` | 无（生成物） | 契约生成的路由常量、业务码、SSE 上限与安全头表；`contract/verify_http.py` 与 `routes.go` 逐项核对 |
| `contract/` | 无（生成物） | netlink 线格式的消息名与字段，供 `kernel/codec` 与配置下发引用 |
| `bans/` | 活跃封禁集合与白名单镜像 | 封禁/白名单动作的参数校验与 netlink 投递、缓存 |
| `detect/` | 无（纯原语） | `cidr.go` 的网段键、`window.go` 的失败窗口 |
| `decision/` | 无（纯计算） | `policy.go` 的有效阈值与时长、`ddos.go` 的内核阈值投影、`cluster.go` 的集群扫描判据 |
| `runtime/` | 执行体生命周期与配置所有权 | `supervisor`（登记与逆序关停）、`executor`（入站主链路）、`pipeline`（行判定与集群扫描）、`shutdown`、`signals`、`timers`、`hooks`、`file_reloader`、`directives`、`enabled` |
| `ingest/` | 日志源与读偏移 | `watcher`（inotify）、`reader`（按 offset 读增量）、`registry`（稳定源标识） |
| `logparse/` | 行缓冲与规则 | `splitter`（切行）、`rule`（正则与 IP 提取）、`ip`（地址归类） |
| `jail/` | jail 状态与规则集 | `jail.go`、`compile.go`、`pipeline.go`、`service.go`；`Finalize` 是启动、热重载与 PUT 写入共用的后处理 |
| `config/` | 配置对象与字段语义 | `args`（CLI）、`parser`（YAML）、`loader`、`types`、`path`、`logging`、`jails_api`、`kernel_view` |
| `analysis/` | 分析派生 | 异常（`anomaly`、`detection`）、预测（`prediction`）、时长与阈值推荐（`recommendations`）、网络分布（`network`）、平滑（`ewma`） |
| `telemetry/` | 内核观测快照 | `store`（版本化快照）、`ring` + `rate_history`（速率环形缓冲） |
| `persist/` | SQLite 历史库 | `db`、`history`、`ban_events`、`reputation`、`activity`、`recovery`、`facts`（按 IP 折叠的判定缓存） |
| `logger/` | 日志目的地与整行不变量 | slog handler，JSON Lines，按大小轮转 |

跨包只传消息或不可变快照。共享状态用显式对象承载
（`bans.GlobalCache()`、`bans.GlobalWhitelist()`、`telemetry.Store`），其余构造期注入。

## 运行时形态

组合根装配四条 goroutine，登记在同一个 `Supervisor` 上：

| 名称 | 承担者 | 形态 |
|------|--------|------|
| `ingest` | `runtime.InboundExecutor.Run` | 一个 goroutine 顺序走「读字节 → 切行 → 规则判定 → 封禁下发」；段间无队列，因此不存在「满时丢弃」 |
| `kernel-reactor` | `kernel.Reactor.Run` | 阻塞收包 + 路由 |
| `kernel-event-pump` | `kernel.EventPump.Run` | 消费事件流、周期采样与对账、按域发布 SSE |
| `http-server` | `http.Server.Start` | 网络 IO |

信号层（`runtime.NewSignalSource`）不是 goroutine，它先把信号转成
与 inotify 同一个 `poll` 池里的普通 fd。inotify fd 和信号管道 fd 一起 poll。

### 关停

`Supervisor.Shutdown()` 按**登记逆序逐段串行**：对当前段 `Request()` 后
`join` 到结束，才停下一段（`runtime/supervisor.go`）。

一次性广播停止信号会让上下游同时收尾，「上游已完全停止」就不成立了。
登记的必要不变量是：netlink 停止后才能在途事件写库。

生产顺序是 `ingest` 最先停，随后 `kernel-event-pump`、`http-server`、
`kernel-reactor`；登记顺序即依赖顺序，下游先登记。
之后延迟清理按 LIFO 释放依赖资源。`persist.DB.Close` 会把已入队的持久化落盘。

## 组合根的装配顺序

`run(args []string) error` 是 `main` 的可测入口。顺序（`cmd/firewall-daemon/main.go`）：

| # | 动作 | 为什么在这个位置 |
|---|------|----------------|
| 1 | `config.ParseConfigArgs`；`--help` 返回成功，`--rollback` 走短路径 | 回滚不加载配置，只给运行中的进程发 SIGUSR1 |
| 2 | 检查 `panelres.PanelDir` 非空 | 面板缺失直接返回启动错误，不假装可运行 |
| 3 | `runtime.NewSignalSource` | 必须早于任何 goroutine，否则启动窗口内的信号丢失 |
| 4 | `startedAt = time.Now()` | `uptime_seconds` 从这里起算，不是从 HTTP 构造起算 |
| 5 | `config.Default` + `loadConfig` | 后面所有装配都读它 |
| 6 | `jail.Finalize` | 智能默认 → 校验 → 编译正则；与热重载、PUT 写入同一个函数，保证三处口径一致 |
| 7 | `newLogger` | 日志目的地、格式、级别门槛、轮转都在 `internal/logger` |
| 8 | 逐条 `logger.Warn` 输出 `finalWarnings` | logger 建在 `Finalize` 之后，告警只能暂存到这里 |
| 9 | `checkProcfs` | `/proc/firewall` 与 `/proc/firewall/bans` 缺失即启动失败 |
| 10 | `runtime.NewSupervisor` | 后续每段都登记在它上面 |
| 11 | `http.NewMetrics` + 预注册 5 个计数器 | 内核链路、入站、HTTP 三面都要往里写，且装配顺序不固定；预注册让 `/metrics` 从启动起就有稳定 0 值行 |
| 12 | `persist.NewDB` + 两个调度器 + `persist.NewFacts` | 库缺失只降级，不影响主链路 |
| 13 | 内核链路：`OpenTransport` → `Subscribe` → `SetMetrics` → `NewEventChannel` → `NewReactor` → `NewClient` | 打开失败只告警；`Subscribe` 必须先于接收回路，否则 `Poll` 永远只返回 deadline |
| 14 | `newBanSink` / `newWhitelistSink` / `newConfigSink` | 入站主链路与 HTTP 共用同一实例，避免两份配置分叉 |
| 15 | `telemetry.NewStore` | 无条件建立；链路缺失时保持零值快照，读侧不必区分「没有内核」与「还没采到样」 |
| 16 | `runtime.NewJailEnabledSource` | HTTP API 与入站主链路共享启用状态 |
| 17 | HTTP 段：`NewServer` → `NewEventsBroker` → `NewLogsStream` → `NewAPIHandlers` → `RegisterRoutes` → `RegisterStaticFiles` → `Spawn("http-server")` | 只在 `HTTPAddress` 非空时装配 |
| 18 | `kernelCmd` 通道（容量 256） | 内核反向指令交给入站执行体落地 |
| 19 | `kernel.NewEventPump` + `Spawn("kernel-event-pump")` | `NewEventChannel` 的事件流到这里才有消费者 |
| 20 | `runtime.NewInboundExecutor` + `Spawn("ingest")` | 配置所有权此后归执行体 |
| 21 | 主 goroutine 阻塞在 `stopCh`；`sup.Shutdown(5 * time.Second)` | 先逆序停执行体，再由延迟清理释放资源 |

三条降级规则：

| 缺失 | 行为 |
|------|------|
| 内核链路打不开 | 只告警，入站主链路照常；封禁表只反映本进程的下发记录 |
| 历史库打不开 | 判定层退回 `runtime.NoHistory{}`，阈值乘数按满分算 |
| 未配 HTTP 监听 | `api` 为 nil，事件泵的域载荷镜像与 jail 快照通知都按缺席处理 |

## netlink 层

线格式以契约生成物为唯一定义。

| 事实 | 值 |
|------|-----|
| 协议号 | `NETLINK_USERSOCK` |
| 魔数 | `0x46574C4E` |
| 公共头 | 12 字节 |
| 字节序 | 多字节整数一律大端 |
| 结构 | `packed` |

出处：`contract/netlink.fwidl` 与 `contract/generated/netlink_uapi.h`。

分层与取舍（`internal/kernel/`）：

| 文件 | 职责 | 关键取舍 |
|------|------|---------|
| `codec.go` | 字节 ↔ 语义类型 | 每个多字节字段显式转宿主序，原始字节不流出本包 |
| `transport.go` | socket 唯一所有者，单写者 | 长度以 `nlmsghdr.nlmsg_len` 为准，不用收包字节数：netlink 按 4 字节对齐，收包数可能多 3 字节填充 |
| `reactor.go` + `router.go` | 接收回路 + `(type, seq)` 路由 | `Router` 是纯状态机，可单测；未知类型即计数 |
| `client.go` | 类型化请求 API | 区分「已投递」与「已确认」；`List*` 请求契约单页上限并续页到底 |
| `consumer.go` | 事件消费与对账 | 重建封禁/白名单镜像、周期采样、注册租约与失联可见 |

泵的四类周期（`consumer.go`，命名常量而非配置项）：

| 常量 | 值 | 用途 |
|------|-----|------|
| `SampleInterval` | 5 秒 | 统计 / 分析 / 速率三张表一并取回 |
| `ReconcileInterval` | 30 秒 | 封禁表与内核对账 |
| `RegisterInterval` | 10 秒 | 注册租约续约，须明显短于内核 30 秒判死 |
| `DefaultRequestTimeout` | 2 秒 | 单次 netlink 请求超时 |

两条容易被改回去的语义：

1. **配对只允许白名单内的类型**。内核有两套序号：`DaemonRegisterAck`、
   `ConfigAck`、`StatsResponse`、`AnalysisResponse`、三个 `List*Response`
   回显请求 `seq`；`DdosEvent`、`BanStateChange`、`WhitelistStateChange`、
   `ConfigChange`、`CmdResult` 用内核自增序号。两组取值必然碰撞。
   把 `CmdResult` 拿去配对，一条「封禁失败」通知会被误认成某次 LIST 的回复而吞掉。
2. **分页的收尾信号是空页，不是 `total`**。契约里 `limit == 0` 表示
   「内核默认页大小」，不是「不限量」。内核在 `offset >= total` 时回空页，
   而 `total` 是另一时刻取的值。续页另加「本页起点未推进即停」的防死循环判据。

## 判定语义

这条判据是对外承诺，实现落在 `internal/decision/policy.go`，
窗口由 `internal/detect/window.go` 提供。

| 项 | 规则 |
|----|------|
| 白名单 | 命中即永不封禁 |
| 有效阈值 | `max_retries × 高峰系数 × 内网系数 × 信誉系数`，向上取整且不小于 1 |
| 高峰时段 | UTC `9..18`；时间源由调用方注入，便于用固定小时写测试 |
| 信誉系数 | 分数 ≥80 取 1.0，≥50 取 0.8，否则 0.5 |
| 渐进式时长 | 第 1 次 `base`、第 2 次 1800、第 3 次 86400、第 4 次起永久 |
| 配置级永久 | `ban_time < 0` |
| 失败窗口 | 只统计 `now - findtime <= ts <= now` 的时间戳 |
| 单 IP 时间戳上限 | `MaxTimestampsPerIP = 100`，FIFO 淘汰最旧 |

集群扫描判据（`internal/decision/cluster.go`）：窗口内同一网段的失败源 IP 数达到
`min_ips`，且各 IP 自身次数不超过 `max_per_ip`。默认关闭、默认只审计。
设计论证见 `docs/zh/development/cluster-detection-design.md`。

## 状态层与 SSE

内核观测快照由事件泵唯一写入（`telemetry.Store`）。写侧独占，读侧拿不可变快照。
域载荷形状出自表现层：泵只报「哪个域变了、那张表里现在有什么」，
具体载荷由 `internal/http` 的纯函数派生（`SSEReplicas`）。

| 域 | 事件名 | 说明 |
|----|-------|------|
| `Stats` | `stats` | 周期事件：无变化也按契约间隔重发，否则安静时段数字会冻住 |
| `Bans` | `bans` | 活跃封禁 |
| `Jails` | `jails` | 派生域：载荷渲染时现读内核快照与封禁表计数，没有内容可比对，故由知道输入变了的一方显式推进 |
| `Whitelist` | `whitelist` | 键是规范化 `CidrKey` |
| `Rates` | `rates` | 速率与 EWMA 基线 |

每个域都必须有生产者。`contract/verify_http.py` 的 `check_sse_events`
断言契约声明的每个域事件在生产代码里都有发布者。

结构性保证：

| 保证 | 做法 |
|------|------|
| 只序列化变化的域 | 连接持有上次发出的版本集合，每轮求差集；只有新连接发全部五域 |
| SSE 与 REST 同形 | 域载荷由同一批纯函数派生，改一处字段只有一处可改 |
| 慢消费者被断开 | 写侧只做「推进版本 + 覆盖式通知」，序列化与发送在各连接自己的 goroutine 里 |
| 两条流各自计数 | `events` 与 `logs/stream` 各自上限、各自回 503、各自声明心跳；合用会让日志页开满连接时饿死事件流 |

数值（连接上限、keepalive、事件集）以 `contract/http.fwidl` 与生成物
`internal/httpcontract/http_contract.go` 为准，本文不复制。

### 白名单键的规范化

键是 `CidrKey`，不是 `String`。两个构造入口（`NewCidrKey` 走结构、
`ParseCidrKey` 走文本）都过同一套规范化。

规则取自内核，不是自拟：内核把白名单存成**网络地址**（`fw_addr_normalize`），
精确主机条目的判据是 IPv4 `/32`、IPv6 `/128`。键的形态固定为
「主机位清零 + 恒带 `/prefix`」。`10.0.0.5/24` 存成 `10.0.0.0/24`，
裸地址 `10.0.0.1` 存成 `10.0.0.1/32`。

## HTTP 与 API

单个 HTTP 服务承载全部内容：面板、REST、SSE、指标。
监听 `metrics_bind_address` + `metrics_port`。

| 事实 | 值 | 出处 |
|------|-----|------|
| 端口 | 9119 | `config/default.yaml` 的 `defaults.metrics_port` |
| 代码默认绑定地址 | `127.0.0.1` | `internal/config` |
| 随包配置绑定地址 | `0.0.0.0` | `config/default.yaml` |

### 路由分层

| 组 | 认证 | 内容 |
|----|------|------|
| SPA 外壳与静态资源 | 无 | 一组**固定的**页面路径 + `/static/*path` + `/sw.js`；注册见 `internal/http/static.go`，清单以 `contract/http.fwidl` 为准 |
| 探针 | 无 | `/health`、`/healthz`：有意不套信封，由就绪判定决定 200/503 |
| 业务面 | Basic Auth | `/metrics` 与 `/api/v1/*`；完整清单以 `contract/http.fwidl` 为准，`verify_http.py` 逐项核对 |

新增页面路径必须同时加进安全头中间件的面板路径判定
（`internal/http/headers.go` 的 `isWebUIPath`），
否则外壳以 `default-src 'none'` 下发：页面能打开，样式与脚本全被拦掉。

### 信封与认证

| 项 | 规则 |
|----|------|
| 形状 | `{code, data, message}`；成功 `code = 0` 且 `message` 空串，失败 `data = null`；两个字段都必然存在 |
| 业务码 | 与 HTTP 状态码是两套编号，常量在契约里声明 |
| 凭据读取 | 中间件**每请求**读取，故 SIGHUP 换凭据无需重启 |
| 未配置凭据 | 两项都为空时中间件直接放行；只填一项拒绝启动 |
| 401 响应 | **有意不发 `WWW-Authenticate`**：那个头会让浏览器弹原生对话框，并让 `fetch` 挂起 |
| SSE 令牌 | 额外接受 `?access_token=<base64(user:pass)>`，因为 `EventSource` 不能设请求头 |
| 失败锁定 | 连续失败达阈值锁定一段时间，参数名 `failure_threshold` / `lockout_seconds`，取值见契约 |
| 启动硬约束 | 非回环地址绑定且完全未配置凭据 → 拒绝启动 HTTP 服务 |
| 读路径 | 零副作用：不清理、不累加统计、不限流 |

### 健康与统计出口

| 端点 | 数据来源 |
|------|---------|
| `/health`、`/healthz` | `telemetry.Store` 快照：netlink 就绪、`/proc/firewall` 存在、封禁缓存与历史是否初始化、当前封禁数 |
| `/api/v1/stats` | 同一份快照 + `StartedAt` 起算的运行时长 + `telemetry.Ring` 的速率样本 + `KernelVersion` |
| `/api/v1/stats/sse-status` | 两条流各自的连接数与上限 |

## 配置与热重载

| 项 | 规则 | 出处 |
|----|------|------|
| 来源 | `-c` 单文件或 `-C` 目录；路径不存在直接启动失败 | `internal/config/args.go`、`main.go` 的 `loadConfig` |
| 严格模式 | 未知 key 报错退出；`--no-strict` 才忽略 | `internal/config/parser.go` |
| 后处理 | `jail.Finalize` 三步；正则编译失败只告警，该 jail 退化为关键字回退，进程不退 | `internal/jail/compile.go` |
| 运行期回写 | Web UI 改的字段经 `internal/http/config_api.go` 回写原路径；目标是目录时写该目录下 `_` 前缀的自动管理文件 | `internal/config/loader.go` 的 `RuntimeOverridePrefix` |
| 覆盖文件合并 | 目录加载时**最后**合并，只承载运行期状态 | 同上 |
| 热重载 | SIGHUP 或文件变化：重读 → 比较差异 → 重挂 watch、重编译正则、更新内核白名单；失败保留旧快照 | `internal/runtime/file_reloader.go` |
| 重载不重置失败窗口 | 只换规则集与参数；否则一次 SIGHUP 就帮攻击者清零已积累的失败计数 | 同上 |
| 回滚 | `SIGUSR1` 或 `--rollback` | `internal/runtime/directives.go` |
| 配置下发内核 | `configSink.ApplyConfig` 投影成 `SetConfig`；手工改文件、SIGHUP、SIGUSR1、PUT 共用同一出口 | `main.go` 的 `newConfigSink` |

容量字段（`capacity.max_ban_entries` / `max_whitelist_entries` /
`max_rate_entries` / `max_local_ip_cache`）在守护进程侧只做持久化与展示。
`SetConfig` 消息没有容量字段，真正的上限是内核模块参数 `fw_max_*`
（见 [内核模块](kernel-module.md)）。

## 持久化

`internal/persist` 用 SQLite 保存三类数据（建表语句见该包）：

| 表 | 内容 |
|----|------|
| `ban_history` | 按 IP 折叠的封禁历史：封禁次数、最近封禁/解封时刻、是否永久 |
| `ban_events` | 逐条封禁事件底账，趋势与热力图读它 |
| `ip_reputation` | IP 信誉分 |

时序统计没有独立的表：趋势与「今日」窗口都从 `ban_events` 的原始时间戳读，
归桶在调用方用同一个 `time.Location` 做（`internal/persist/activity.go` 的注释说明为什么不
把分桶下推到 SQL）。

分析面（`internal/analysis`）在这些表上派生攻击预测、协同检测、
时长与阈值推荐、网络分布。

读侧不做重活：判定层每行日志都要扣一次信誉分并立刻取分，直接查库会把
入站主链路钉在磁盘上。`persist.Facts` 按 IP 折叠缓存并周期刷盘
（`StartFlusher`）。库自带清理调度器与信誉恢复调度器，三者共用同一条
stop 通道，关停时最后刷一次盘。

已知缺口：失败次数与 DDoS 命中没有按天历史，
见 `contract/http.fwidl` 的 `HTTP_FAILURE_HISTORY_NOT_PERSISTED`。

## 日志

| 项 | 规则 | 出处 |
|----|------|------|
| 格式 | JSON Lines，每行一条 JSON 对象 | `internal/logger/json.go` |
| 写入 | 自定义 handler，整行（含换行）合并为单次 `write()` | `internal/logger/handler.go`；多写者并存时每行仍是独立合法 JSON |
| 路径 | 取 `defaults.log_file`；为空时用 `defaultLogPath` | `config/default.yaml`；`internal/logger/logger.go` 的 `/var/log/firewall-daemon.log` |
| 打开失败 | 回退 stderr（`dup` 复制 fd 2，不接管原始 stderr） | `internal/logger/file.go` |
| 轮转 | `log_max_size_mb`（默认 10）切片，当前片改名 `.1`，旧片依次顺移；`log_max_files`（默认 10，含当前片）控制保留数 | `internal/logger/file.go` |
| 关闭轮转 | `log_max_size_mb=0`；`log_max_files=1` 表示轮转时直接截断 | 同上 |
| 不随热重载切换 | `log_max_*` 改动需要重启守护进程 | `internal/runtime/file_reloader.go` |

## 信号

| 信号 | 行为 | 出处 |
|------|------|------|
| `SIGTERM` / `SIGINT` | 置位终止令牌，主线程醒来走逆序关停 | `internal/runtime/signals.go`、`main.go` |
| `SIGHUP` | 配置热重载 | `internal/runtime/file_reloader.go` |
| `SIGUSR1` | 配置回滚 | `internal/runtime/directives.go` |
| `SIGPIPE` | 忽略：HTTP 客户端断开不应杀死进程 | Go 运行时不向其发送 |

## 可观测性

### 指标

`/metrics` 由 `internal/http/metrics.go` 渲染，注册即导出，当前没有 gauge。
`main.go` 预注册 5 个计数器，其余在首次调用 `Counter(name)` 时登记。

| 指标 | 计数点 |
|------|--------|
| `firewall_lines_parsed_total` | `main.go` 的 `statsSink.AddGlobal` / `AddJail` |
| `firewall_lines_skipped_total` | `statsSink.AddGlobal` |
| `firewall_regex_matches_total` | `statsSink.AddGlobal` / `AddJail` |
| `firewall_inotify_events_total` | `statsSink.IncInotifyEvents` |
| `firewall_log_rotations_total` | `statsSink.IncLogRotations` |
| `firewall_bans_triggered_total` | `statsSink.IncBansTriggered` |
| `firewall_daemon_config_reloads_total` | `statsSink.IncConfigReloads`（`configReloadsMetric`） |
| `firewall_ddos_events_total` | `internal/kernel/consumer.go` 的 `CounterDdosEvents` |
| `firewall_kernel_commands_rejected_total` | 同文件的 `CounterCommandRejected` |
| `firewall_netlink_messages_sent_total` | `internal/kernel/transport.go` |
| `firewall_netlink_messages_received_total` | 同上 |
| `firewall_netlink_send_errors_total` | 同上 |
| `firewall_netlink_recv_errors_total` | 同上 |

清单以这三处注册点为唯一真相源。运维口径见
`docs/zh/operations/monitoring.md`。

### 内核读数不走 Prometheus

封禁、白名单、速率等内核统计由 `/proc/firewall/stats` 的键值文本给出，
由事件泵按 `SampleInterval` 采样汇入 `telemetry.Store`，
再经 `/api/v1/stats` 与 `/health` 透出。仓库不提供 procfs → metrics 的适配。
