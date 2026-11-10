---
kind: configuration_system
name: firewall-daemon YAML 配置系统：defaults/jails/功能段分层合并与运行期覆盖
category: configuration_system
scope:
    - '**'
source_files:
    - src/daemon/internal/config/types.go
    - src/daemon/internal/config/parser.go
    - src/daemon/internal/config/loader.go
    - src/daemon/internal/config/args.go
    - src/daemon/internal/config/credentials_env.go
    - config/default.yaml
    - src/daemon/cmd/firewall-daemon/main.go
---

## 1. 总体方案

守护进程 `src/daemon/internal/config` 包实现了一套基于 `gopkg.in/yaml.v3` 的 YAML 配置加载器，配合命令行参数与环境变量完成三路合并。配置文件采用「全局 defaults + 多 jail 定义 + 各功能段（ddos/webui/capacity/threat_feeds/geoip）」的分层结构，默认值由 Go 代码中的 `Default()` / `DefaultXxxConfig()` 函数提供。

## 2. 关键文件

- `src/daemon/internal/config/types.go` — 运行时配置结构体、常量上限、默认值工厂、`ListenAddress()` 等派生字段
- `src/daemon/internal/config/parser.go` — YAML 反序列化结构体、`parseConfigFrom` 主解析流水线、各段 apply 函数
- `src/daemon/internal/config/loader.go` — 单文件 `ParseConfigFile` 与目录 `LoadConfigDirectory` 入口，含运行期覆盖前缀 `_`
- `src/daemon/internal/config/args.go` — 命令行参数解析（`-c`/`-C`/`--no-strict`/`--rollback`），默认路径 `/etc/firewall-daemon/config.yml`
- `src/daemon/internal/config/credentials_env.go` — `FIREWALL_METRICS_USERNAME` / `FIREWALL_METRICS_PASSWORD` 环境变量覆盖逻辑
- `config/default.yaml` — 仓库自带的完整默认配置样例（包含 sshd jail、威胁情报源等）
- `src/daemon/cmd/firewall-daemon/main.go` — 组合根，负责调用 `loadConfig`、`jail.Finalize`、构造 `runtime.FileReloader` 并驱动热重载

## 3. 架构与约定

### 3.1 配置来源优先级

解析顺序严格为：**`Default()` → YAML defaults/jails/各段 → 环境变量凭据**（见 `parser.go` 第 203-205 行注释）。环境变量仅覆盖认证凭据，且发生在 YAML 全部应用之后；其他字段不通过环境变量注入。

### 3.2 命令行入口

- `-c/--config <FILE>`：加载单个 YAML 文件
- `-C/--config-dir <DIR>`：加载目录下所有 `.yml/.yaml` 文件（字母序合并）
- `--no-strict`：关闭未知 key 校验（默认开启严格模式）
- `--rollback`：向运行中守护进程发 `SIGUSR1` 触发回滚，不走配置加载

默认单文件路径为 `/etc/firewall-daemon/config.yml`（`args.go` 第 9 行）。

### 3.3 目录加载与运行期覆盖

`LoadConfigDirectory` 按文件名排序后逐个 `ParseConfigFile`，但把以 `_` 开头的文件（`RuntimeOverridePrefix = '_'`）排到最后——这些是守护进程自动写回的运行期状态（当前是 jail 的 `enabled`），对预置定义拥有最终发言权。目录模式下 `cfg.ConfigDir` 被设置而 `cfg.ConfigFile` 清空，避免重载只吃单个文件。

### 3.4 原子性保证

`ParseConfigFile` 在解析前做 `saved := *cfg` 快照，失败时整体回滚（loader.go 第 38-47 行）。`parseConfigFrom` 同样在局部结构上校验通过后一次性写入，唯一例外是后置的环境变量凭据覆盖，它只在成功后执行，因此「解析失败不改 cfg」的语义仍然成立。

### 3.5 字段合并规则

- **同名 jail**：按键排序后后到优先，只覆盖显式给出的字段（Go map 迭代随机，故先 sort.Strings(names)）
- **Jail 数值字段**：使用 `*_Set` 布尔区分「用户显式配置」与「智能默认推断」，避免默认值覆盖用户值
- **Cluster/Jail 子段**：每个字段用 `*T` 指针表示可选，空指针即跳过
- **ThreatFeeds.Sources**：YAML 给出完整列表时替换默认值，而非追加
- **TrustedIPs**：直接 append 一份拷贝，启动时下发一次内核白名单（main.go 第 382-392 行）

### 3.6 严格模式与未知 key

解码器通过 `dec.KnownFields(strict)` 启用 deny_unknown_fields 语义；严格模式下未知顶层字段直接报错。`StrictMode` 字段也写入最终 `Config`，供日志和 API 报告。

### 3.7 安全相关约定

- 面板认证凭据必须**两项都非空**才算启用（`AuthEnabled()`）；只填一项判为非法、整组端点拒绝
- 绑定到非回环地址且未配置认证时，组合根会告警（main.go 第 110-114 行）
- 出厂默认口令 `changeme` 在启动时单独检测并告警（main.go 第 117-120 行）
- 环境变量名统一以 `FIREWALL_` 前缀（`EnvMetricsUsername` / `EnvMetricsPassword`）
- 出口 IP 探测 URL 走严格的 `normalizeProbeURL`：只允许 `http://` / `https://`，长度上限 2048，禁止空白与控制字符

### 3.8 热重载链路

组合根通过 `runtime.NewFileReloader(configSource, parsed.Strict, logger)` 持有配置来源（单文件或目录），SIGHUP/SIGUSR1/文件变更都会触发重载；重载后的配置经同一套 `jail.Finalize` 校验后再推送到内核（`configSink.ApplyConfig`），确保启动能过的配置与热重载口径一致。

## 4. 约束与规则

- **Jail 数量上限**：`MaxJails = 32`（types.go 第 36 行），超过时报错
- **正则表达式上限**：每 jail `MaxRegexPatterns = 10`，`log_files` 上限 `MaxLogFiles = 10`（types.go 第 26-37 行）
- **坐标成对约束**：`server_latitude` 与 `server_longitude` 必须同时给出或同时省略，否则报「必须成对给出」（parser.go 第 609 行）
- **坐标范围**：纬度 [-90, 90]，经度 [-180, 180]，越界直接拒绝加载
- **`metrics_port = 0`**：表示关闭 HTTP 面（metrics_bind_address 与 metrics_port 现场合成 ListenAddress，main.go 第 444-454 行）
- **`ban_time = -1`**：表示永久封禁（types.go 第 99 行注释）
- **`log_destination` / `log_format`**：取值受限为 `syslog|file|both|journal` 与 `plain|json`，非法值直接报错（parser.go 第 246-257 行）
- **默认日志格式为 JSON Lines**：`LogFormatJSON`，便于采集端直接解析（types.go 第 416-419 行注释）
- **历史库为空字符串即禁用分析面**：面板的分析页全部回 503「依赖未就绪」（parser.go 第 265-273 行注释）
- **`trusted_ips` 仅在启动时下发一次**：改此段需重启守护进程（config/default.yaml 第 97-98 行注释）
- **运行期覆盖文件不能凭空创建 jail**：`runtimeOverride` 模式下引用未定义的 jail 名会被忽略并告警（parser.go 第 305-311 行）
- **默认端口与监听地址**：`metrics_port: 9119`，`metrics_bind_address: "0.0.0.0"`（config/default.yaml 第 12-13 行）
- **默认威胁情报源**：启用 ipsum 与 firehol_level1，其余 dshield/blocklist_de/feodo 默认关闭（types.go DefaultThreatFeedsConfig）

## 5. 部署位置

- 默认配置单文件：`/etc/firewall-daemon/config.yml`
- 默认配置目录模式：`/etc/firewall/`（deb 包安装时复制 `config/*.yaml` 到 `etc/firewall/`）
- 凭据文件：`/etc/firewall/credentials.env`（systemd `EnvironmentFile=-/etc/firewall/credentials.env`，0600 权限）
- 日志：`/var/log/firewall.log`（config/default.yaml 第 22 行）
- 历史数据库：`/var/lib/firewall/history.db`（config/default.yaml 第 28 行）
