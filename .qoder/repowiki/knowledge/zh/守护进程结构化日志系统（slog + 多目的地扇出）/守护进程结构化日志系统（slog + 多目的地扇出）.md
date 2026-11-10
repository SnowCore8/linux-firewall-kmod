---
kind: logging_system
name: 守护进程结构化日志系统（slog + 多目的地扇出）
category: logging_system
scope:
    - '**'
source_files:
    - src/daemon/internal/logger/logger.go
    - src/daemon/internal/logger/handler.go
    - src/daemon/internal/logger/file.go
    - src/daemon/internal/logger/json.go
    - src/daemon/internal/config/logging.go
    - src/daemon/internal/config/parser.go
    - src/daemon/cmd/firewall-daemon/main.go
---

## 1. 使用的框架与总体方案

守护进程使用 Go 标准库 `log/slog` 作为结构化日志核心，未引入第三方日志库。日志系统在 `src/daemon/internal/logger` 包中实现，由 `src/daemon/cmd/firewall-daemon/main.go` 中的 `newLogger` 在组合根装配阶段调用 `logger.Init(cfg)` 初始化，返回的 `*slog.Logger` 通过依赖注入传给 HTTP、内核链路、持久化等所有子模块。

输出目标（destination）支持四种：
- `syslog`：写本地 syslog（先试 unixgram `/dev/log`，失败回退 unix）
- `journal`：写 systemd-journald（先试 `/run/systemd/journal/dev-log`，失败回退本地 syslog）
- `file`：写本地文件，默认路径 `/var/log/firewall.log`
- `both`：同时写 syslog 与文件

当所有配置的目标都不可用时，自动降级到 `os.Stderr`，保证「至少有一条可写通道」。

## 2. 关键文件与职责

| 文件 | 职责 |
|---|---|
| `src/daemon/internal/logger/logger.go` | 初始化入口 `Init`、从配置映射选项、构建 sink 集合、`SetLogFile`/`LogFilePath` 暴露给日志查看器、`LogThrottler` 高频节流 |
| `src/daemon/internal/logger/handler.go` | `sink` 接口、`fanoutWriter` 把一次写分发给多个 sink（任一出错不中断其余）、按格式选择处理器 |
| `src/daemon/internal/logger/file.go` | `stderrSink`、带大小轮转的 `fileSink`（`.1`…`.N` 命名，单锁保护写入与轮转） |
| `src/daemon/internal/logger/json.go` | 自定义 `jsonHandler`，字段顺序固定为 `ts → level → msg → version → 记录属性`，时间用 RFC3339 UTC（毫秒/微秒/纳秒自适应精度） |
| `src/daemon/internal/config/logging.go` | 配置加载期的 `logWarnf`，因早于日志系统初始化而直接走 `slog.Default()` |
| `src/daemon/internal/config/parser.go` | 解析 `log_destination`（`syslog/file/both/journal`）、`log_format`（`plain/json`）、`log_level`、`log_file`、`log_max_size_mb`、`log_max_files` |
| `src/daemon/cmd/firewall-daemon/main.go` | 组合根中 `newLogger` 调用 `logger.Init`，并把 logger 注入各子系统 |

## 3. 架构与设计决策

### 3.1 无全局实例
`logger.Init` 返回 `*slog.Logger`，注释明确「不存在全局实例」。调用方经参数注入使用，便于测试替换。

### 3.2 多 sink 扇出与容错
`buildSinks` 根据 destination 决定要哪些 sink；单个 sink 建立失败只向 stderr 告警并跳过，不阻断启动。`fanoutWriter.Write` 遍历所有 sink，取已写出最大字节数与首个错误，因此「文件写失败但 syslog 照常」是预期行为。

### 3.3 级别映射
配置值到 `slog.Level` 的映射集中在 `levelFromConfig`：
- `NONE` → `levelSilent = slog.Level(127)`（使 `Enabled` 恒 false）
- `ERROR` → `slog.LevelError`
- `WARN` → `slog.LevelWarn`
- `DEBUG` → `slog.LevelDebug`
- 其他 → `slog.LevelInfo`

JSON 模式下级别名映射为 `ERROR/WARN/INFO/DEBUG`。

### 3.4 JSON 字段约定
自定义 `jsonHandler` 强制字段顺序：`ts`（RFC3339 UTC）、`level`（大写字符串）、`msg`、处理器级属性（`version`，来自 `config.Version`）、记录自身属性。分组键以 `.` 连接（如 `group.key`）。NaN/Inf 数字退化为字符串，error 类型取其 `.Error()` 消息，确保每行都是合法 JSON。

### 3.5 文件轮转策略
`fileSink` 使用单把 `sync.Mutex` 保护写入与轮转，避免并发写者看到中途 inode 或把一条记录切进两片。轮转时：删除最旧片 `.maxFiles-1` → 依次 rename `.i` → `.i+1` → 当前文件 rename 为 `.1` → 打开新文件。`maxBytes=0` 关闭轮转；`maxFiles<1` 归一为 1（只截断当前片，不留历史）。

### 3.6 高频日志节流
`LogThrottler` 基于 `atomic.Int64` 记录上次放行时间戳，`CanLog()` 在距上次放行 ≥ interval 秒时才放行，用于热路径上抑制高频日志。

### 3.7 日志文件路径共享
通过 `atomic.Pointer[string] logFilePath` 暴露 `SetLogFile`/`LogFilePath`，供日志查看器读取当前日志文件路径；重复登记会报错，保证只设置一次。

## 4. 约定与约束

- **日志 API**：业务代码统一调用返回的 `*slog.Logger` 的 `Info/Warn/Error/Debug` 方法，不使用 `fmt.Println` 或 `log.Printf`。
- **结构化字段**：所有日志必须附带语义化 key-value 属性（如 `error`、`addr`、`ip`、`cidr`、`jail`），而非拼接消息。
- **目的地优先级**：`both` 同时写 syslog 与文件；任一 sink 失败不影响其余 sink；全部失败时回退到 stderr。
- **级别阈值**：`log_level=NONE` 对应一个高于所有真实级别的哨兵值，使 `Enabled` 恒 false，达到零开销禁用。
- **JSON 输出**：启用 `log_format=json` 时使用自定义 `jsonHandler`，字段顺序固定且始终产出单行合法 JSON。
- **文件轮转**：`log_max_size_mb` 以 MB 为单位，内部转为 `uint64` 后乘以 `1024*1024` 以避免 32 位溢出；`log_max_files` 最小值为 1。
- **Syslog/Journald 标签**：所有 syslog 消息使用 tag `firewall-daemon`。
- **默认路径**：未配置 `log_file` 时默认写 `/var/log/firewall.log`。
- **配置加载期日志**：配置解析发生在日志系统初始化之前，因此 `config/logging.go` 中的 `logWarnf` 直接调用 `slog.Warn` 走默认处理器，避免循环依赖。
- **线程安全**：`fileSink` 的写入与轮转共用一把互斥锁；`logFilePath` 使用 `atomic.Pointer` 并通过 `CompareAndSwap` 保证单次登记。
- **测试隔离**：`syslogDialer` 是可注入函数，测试可替换为指向临时套接字的实现；`initLogger` 返回的 `close` 回调用于测试释放句柄，生产路径不调用。

## 5. 配置项来源

配置项定义在 `src/daemon/internal/config/parser.go` 的 `Config` 结构体中，YAML 键包括：
- `log_destination`：`syslog` / `file` / `both` / `journal`
- `log_format`：`plain` / `json`
- `log_level`：`NONE` / `ERROR` / `WARN` / `INFO` / `DEBUG`
- `log_file`：日志文件路径（空串表示默认）
- `log_max_size_mb`：单文件大小上限（MB）
- `log_max_files`：保留的历史文件数量

这些字段在 `optionsFromConfig` 中映射为 `logger.options`，再由 `buildSinks`/`newHandler` 消费。