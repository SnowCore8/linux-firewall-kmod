---
kind: error_handling
name: 守护进程错误处理体系：业务码信封、哨兵错误与 panic 边界
category: error_handling
scope:
    - '**'
source_files:
    - src/daemon/internal/http/envelope.go
    - src/daemon/internal/httpcontract/http_contract.go
    - src/daemon/internal/http/handlers.go
    - src/daemon/internal/http/bans.go
    - src/daemon/internal/http/analysis.go
    - src/daemon/internal/detect/cidr.go
    - src/daemon/internal/kernel/consumer.go
    - src/daemon/internal/kernel/transport.go
    - src/daemon/internal/config/path.go
    - src/daemon/internal/runtime/executor.go
---

## 1. 总体方案

仓库包含两个独立子系统，错误处理方式不同：

- **Go 守护进程**（`src/daemon/`）：采用「哨兵 `error` + HTTP 业务码信封」模式。所有可观测的错误以包级 `var ErrXxx = errors.New(...)` 暴露；HTTP 层统一通过 `http/envelope.go` 的 `WriteSuccess / WriteCreated / WriteCode / WriteInternalError / WriteServiceUnavailable` 写出带 `code/data/message` 三字段信封，业务码与 HTTP 状态码的映射集中在 `internal/httpcontract/http_contract.go`。
- **C 内核模块**（`src/kernel-module/`）：遵循 Linux 内核惯例，返回负 errno（如 `-EINVAL`、`-ENOMEM`），由 netlink 传输层在用户态转换为 Go error（见 `kernel/transport.go` 中的 `ErrTruncated`、`ErrMalformedDatagram`）。内核侧没有自定义 error 类型，也没有 panic/recover（内核中不可用）。

前端（`frontend/src/`）仅消费 HTTP 响应信封，不直接处理 Go 错误。

## 2. 关键文件与包

| 层次 | 文件 | 职责 |
|---|---|---|
| HTTP 信封 | `src/daemon/internal/http/envelope.go` | 唯一写出点：`ApiResponse` 结构体、`SuccessEnvelope`、`ErrorEnvelope`、`WriteCode`、`WriteInternalError`、`WriteServiceUnavailable` |
| 契约常量 | `src/daemon/internal/httpcontract/http_contract.go` | 业务码常量（`Code40001..50003`）、`CodeHTTPStatus` 映射表、路由注册串、安全头常量 |
| CIDR 解析 | `src/daemon/internal/detect/cidr.go` | 定义 `ErrCidrEmpty/MultipleSlashes/InvalidAddr/InvalidPrefix/PrefixTooLarge` 五个哨兵错误 |
| 内核通信 | `src/daemon/internal/kernel/consumer.go` | `ErrLeaseRefused`（守护进程独占锁冲突） |
| 内核传输 | `src/daemon/internal/kernel/transport.go` | `ErrTruncated`、`ErrMalformedDatagram`（netlink 报文异常） |
| 配置校验 | `src/daemon/internal/config/path.go` | `ValidateAndNormalizePath` 拒绝路径遍历、URL 编码绕过、shell 元字符注入 |
| HTTP 处理器 | `src/daemon/internal/http/handlers.go`、`bans.go`、`analysis.go` 等 | 调用方统一使用 `WriteCode(业务码, message)` 输出失败 |

## 3. 架构与约定

### 3.1 HTTP 业务码信封

`ApiResponse` 固定三个 JSON key：`code`、`data`、`message`，顺序由 struct tag 与契约强制保证（`envelope.go` 注释明确说明“三条规矩都来自契约”）。

- 成功：`code=0`（`CodeOK`），`message=""`，`data` 为载荷本体。
- 失败：`code` 为契约声明的业务码，`data=null`，`message` 含原因。
- 所有失败必须经 `WriteCode(code, message)` 写出，禁止手写 HTTP 状态码——`WriteCode` 内部查 `httpcontract.CodeHTTPStatus` 表，未知码回 500。
- 两类特殊失败有专用函数：`WriteInternalError` → `Code50002`（服务端内部错误），`WriteServiceUnavailable` → `Code50003`（依赖未就绪，如历史库未初始化、SSE 名额已满）。

业务码与 HTTP 状态码解耦：同一业务码（如 `Code40001` 封禁失败）可能对应多个 HTTP 语义（400），而 `Code50002` 恒映射 500、`Code50003` 恒映射 503。新增业务码必须在 `http_contract.go` 同时声明常量与映射，否则 `verify_http.py` 会报门禁失败。

### 3.2 哨兵错误（Sentinel Errors）

可被调用方显式判断的错误以包级变量形式暴露：

```go
// detect/cidr.go
var (
    ErrCidrEmpty        = errors.New("CIDR 文本为空")
    ErrCidrMultipleSlashes = errors.New("CIDR 文本含多个 /")
    ErrCidrInvalidAddr  = errors.New("CIDR 地址部分非法")
    ErrCidrInvalidPrefix = errors.New("CIDR 前缀部分非法")
    ErrCidrPrefixTooLarge = errors.New("CIDR 前缀超出地址族位宽")
)
```

其他哨兵错误：
- `kernel/consumer.go`: `ErrLeaseRefused`（已有活跃守护进程）
- `kernel/transport.go`: `ErrTruncated`、`ErrMalformedDatagram`

非可恢复的输入错误（如 IP 非法、参数非法）在 handler 层直接转成 `WriteCode(Code4000x, ...)`，不向上冒泡。

### 3.3 panic 的使用边界

仓库中仅有三处 `panic`，全部位于「不可能发生」的内部不变量检查或测试辅助函数：

1. `detect/cidr.go:97` — `MustCidrKey`：文档写明是「测试与常量场景简写」，解析失败直接 panic。
2. `detect/cidr.go:133` — `CidrKey.Prefix()`：键只可能由本包构造，解析失败意味着内部数据损坏，panic 而非静默返回零值。
3. `runtime/executor.go:211` — 定时器容量登记失败，属于启动期配置缺陷。

这些 panic 不是常规错误路径，而是「如果走到这里说明实现有 bug」的断言式保护。

### 3.4 配置输入的安全错误

`config/path.go` 的 `ValidateAndNormalizePath` 对日志路径做五重安全检查：路径遍历（`..`）、URL 编码绕过（`%2e/%2f/%5c` 及其双重编码）、shell 元字符注入（`|&;$`()<>{} `）、长度上限（4096）、符号链接规范化后仍检测 `..`。任一命中返回 `fmt.Errorf` 错误，消息统一以「路径校验失败（检测到…）」开头，便于运维快速定位。

### 3.5 降级 vs 报错

代码严格区分「服务不可用」和「查询无数据」：

- 依赖缺失（`db == nil`）→ `WriteServiceUnavailable`（503 + `Code50003`）。
- 契约未声明 codes 的统计路由（如 `BanEffectiveness`、`BanDurationHistogram`、`AttackGeo`）→ 在 200 信封内返回空读数 + summary，而不是 500，因为契约没给它们编错误码。
- 契约已声明 codes 的路由 → 按契约如实上报 `Code50002` / `Code50003`。

## 4. 约定与约束（描述性）

- HTTP 响应**唯一写出点**是 `http/envelope.go` 的 `WriteSuccess / WriteCreated / WriteCode / WriteInternalError / WriteServiceUnavailable`，handler 不得直接 `w.Write` 业务响应。
- 业务码与 HTTP 状态码的映射**唯一真相源**是 `httpcontract/http_contract.go` 的 `CodeHTTPStatus` 表，调用方不得手写状态码。
- 每个失败都有编号（`Code40001..50008`、`Code404`、`Code50002`、`Code50003`），前端按 code 区分同一 HTTP 状态码下的不同原因。
- 成功时 `message` 为空串，失败时 `data` 必须存在且为 null —— 由 `ApiResponse` 字面量与 struct tag 保证，`envelope.go` 注释明确这是「门禁就红一处」的契约约束。
- 新增业务码必须同时在 `http_contract.go` 声明常量并加入 `CodeHTTPStatus` 映射，否则 `contract/verify_http.py` 的契约校验会失败。
- 只有「不可能发生」的内部不变量检查才使用 `panic`；常规错误一律返回 `error` 并由调用方决定是记录日志还是转为 HTTP 信封。
- 内核模块侧遵循 Linux 内核惯例：返回负 errno，用户态通过 netlink 层包装为 Go error（`ErrTruncated`、`ErrMalformedDatagram`、`ErrLeaseRefused`）。

## 5. 前端侧

前端 `providers/ErrorBoundary.tsx` 捕获 React 组件渲染错误，`components/state/ErrorState.tsx` 提供统一的错误 UI 展示，但前端本身不定义业务错误类型——它消费后端 `ApiResponse.code` 进行分支显示。

## 6. 结论

该仓库的错误处理体系围绕「契约驱动」展开：业务码、HTTP 状态码映射、信封格式、路由注册串全部由 `contract/http.fwidl` 生成并在多处校验。Go 侧以哨兵错误表达可诊断的失败，以 panic 表达内部不变量破坏，以 `WriteCode` 系列函数作为 HTTP 响应的唯一出口；内核侧沿用 Linux errno 惯例。这种设计使错误从内核到 HTTP 到前端保持可追踪、可分类、可契约化。