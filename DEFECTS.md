# 功能缺陷清单

本文件只记录当前代码中仍未修复的缺陷；每条给出位置、影响与验证方式，修复后删除对应条目。

## 统计

| 严重度 | 数量 |
|--------|------|
| HIGH | 1 |
| MEDIUM | 5 |

## HIGH

### H-1 自动封禁底账先于内核确认落库，内核拒绝后不回滚

- **位置**：`src/daemon/cmd/firewall-daemon/main.go:905-925`、`src/daemon/internal/kernel/consumer.go:531-546`
- **问题**：`InsertPending` 占位后立即 `recordBanLedger` 写 `ban_events`/`ban_history`/`ip_reputation` 并 `noteBan`；而内核下发在 executor 里随后才做。同步失败只 `RollbackInsert`（撤缓存），内核异步 `CmdResult` 拒绝只 `cache.Remove`，数据库没有补偿。
- **影响**：内核表满或通道拒绝时留下从未生效的封禁，`priorBanCount` 与信誉扣分虚高，后续封禁会被升档到更长时长甚至永久。
- **修复方向**：把底账移到内核确认（`BanStateChange`）之后，或为拒绝路径引入可回滚补偿。先定「封禁何时算发生」。
- **验证方式**：伪造 `Send` 同步失败与拒绝 `CmdResult`，断言三张表无新增或已回退。

## MEDIUM

### M-1 手工/批量封禁绕过 Facts 缓存与重试队列

- **位置**：`src/daemon/internal/http/bans.go:170`、`:403`；`src/daemon/cmd/firewall-daemon/main.go:905-925`
- **问题**：HTTP 写路径直接 `bans.GlobalCache().InsertPending` 并自行写库，不走 banSink；`APIConfig` 没有 Facts/RetryQueue 依赖。
- **影响**：手工封禁后自动判定仍按旧次数/旧信誉算渐进时长；写库瞬时失败时手工封禁底账永久丢失。
- **修复方向**：把 Facts/RetryQueue 注入 HTTP 层，或统一走 banSink 的底账入口。

### M-2 SSE 连接共用全局连接配额

- **位置**：`src/daemon/internal/http/server.go:130-150`；`src/daemon/cmd/firewall-daemon/main.go:465`
- **问题**：`connectionLimiter` 统计所有在途请求，长驻 SSE 占普通请求名额；`MaxConnections` 直接复用 `cfg.MaxSSEConnections`。满额响应已改为 50003 信封，但配额口径未拆。
- **影响**：日志页开满连接时事件流可能被饿死。
- **修复方向**：按连接类型分账，SSE 走各自上限。

### M-3 封禁表占用率分母不是内核真实上限

- **位置**：`src/daemon/internal/http/stats.go:518-533`；契约 `contract/http.fwidl:1156`
- **问题**：分母取 `cfg.Capacity.MaxBanEntries`，契约称它与 `fw_max_ban_entries` 同值，但仓库里没有把容量下发给模块的路径。
- **影响**：模块参数被 modprobe/sysfs 调整时，占用率与威胁等级按错误分母计算。
- **修复方向**：内核统计暴露真实容量，或启动时把容量真正下发给模块参数。

### M-4 生命周期测试没有真正验证 PID 文件与单实例约束

- **位置**：`tests/test_20_daemon_lifecycle.py:101-109`、`:111-128`
- **问题**：PID 用例以前台方式启动 daemon，PID 文件只在 `--daemon` 模式写入，分支永不执行；单实例用例对任意非零退出都判通过，第二实例存活时直接 `pytest.skip`。
- **影响**：PID 文件创建/内容/清理与单实例拒绝的回归全部漏测。
- **修复方向**：用 `--daemon` 启动并轮询 PID 文件；第二实例用独立端口，断言退出码与明确拒绝原因，存活则失败。

### M-5 测试形态端口冲突

- **位置**：`tests/conftest.py:641-672`（默认 `metrics_port=9119`）；`tests/test_10_daemon_logparse.py:49`、`tests/test_13_frp_jail.py:61`、`tests/test_09_daemon_config.py:44`
- **问题**：daemon-up 与 daemon-down 两种测试形态共用固定端口，外部 daemon 占用 9119 时自起实例会假失败或假通过。
- **修复方向**：自起 daemon 一律 `free_tcp_port()`，两种形态用 marker 分隔。
