# 监控

本文说明如何监控内核模块与守护进程的运行状态。

两套读数，走两条路，**不要混**：

| 来源 | 出口 | 内容 |
|------|------|------|
| 守护进程计数器 | Prometheus `/metrics`（9119） | 日志解析、封禁触发、netlink 链路健康、配置重载 |
| 内核侧读数 | `/proc/firewall/stats` 的键值文本 | 封禁数、丢包数、白名单拒绝数、报文计数 |

## 两条路各走什么

```
内核 stats_show（跨 CPU flush）
      ↓ 键值文本
/proc/firewall/stats
      ↓ kernel.EventPump 每 5 秒 STATS_QUERY / ANALYSIS_QUERY
telemetry.Store（内存快照，唯一写入者是事件泵）
      ↓
/api/v1/stats 与 /health          ← 面板与外部探针读这里
```

**内核读数不走 Prometheus。** 封禁、白名单、速率等内核统计由
`/proc/firewall/stats` 的键值文本给出，经事件泵汇入内存快照，
再由 `/api/v1/stats` 与 `/health` 透出。
出处：`src/daemon/internal/kernel/consumer.go`、`internal/telemetry/store.go`、
`internal/http/stats.go`、`internal/http/health.go`。

仓库不提供 procfs → metrics 的适配器。要把内核计数送进 Prometheus，
需要自己写一层采集（node_exporter 的 textfile collector 或脚本抓取均可）。

## Prometheus 监控

### 抓取配置

`/metrics` 在认证组内。配了凭据就必须带 `basic_auth`。

```yaml
scrape_configs:
  - job_name: 'firewall'
    static_configs:
      - targets: ['localhost:9119']
    scrape_interval: 15s
    basic_auth:
      username: <metrics_username>
      password: <metrics_password>
```

端口来自 `defaults.metrics_port`（默认 9119，`config/default.yaml`）。
绑定地址来自 `defaults.metrics_bind_address`。

### 指标清单

`/metrics` 由 `src/daemon/internal/http/metrics.go` 渲染：**注册即导出**，
按名字排序输出，当前没有注册任何 gauge。

| 指标 | 类型 | 含义 | 计数点 |
|------|------|------|--------|
| `firewall_lines_parsed_total` | counter | 已解析的日志行数 | `cmd/firewall-daemon/main.go` 的 `statsSink.AddGlobal` / `AddJail` |
| `firewall_lines_skipped_total` | counter | 跳过的行数 | `statsSink.AddGlobal` |
| `firewall_regex_matches_total` | counter | 正则命中次数 | `statsSink.AddGlobal` / `AddJail` |
| `firewall_inotify_events_total` | counter | inotify 唤醒次数（非事件条数） | `statsSink.IncInotifyEvents` |
| `firewall_log_rotations_total` | counter | 轮转检测次数 | `statsSink.IncLogRotations` |
| `firewall_bans_triggered_total` | counter | 实际发起的封禁数 | `statsSink.IncBansTriggered` |
| `firewall_daemon_config_reloads_total` | counter | 配置重载成功次数 | `statsSink.IncConfigReloads`（常量 `configReloadsMetric`） |
| `firewall_ddos_events_total` | counter | 内核推来的 DDoS 事件数 | `internal/kernel/consumer.go` 的 `CounterDdosEvents` |
| `firewall_kernel_commands_rejected_total` | counter | 内核以 `CmdResult` 回执失败的指令数 | 同文件的 `CounterCommandRejected` |
| `firewall_netlink_messages_sent_total` | counter | netlink 报文成功投递次数 | `internal/kernel/transport.go` |
| `firewall_netlink_messages_received_total` | counter | 从内核成功收取的报文数 | 同上 |
| `firewall_netlink_send_errors_total` | counter | netlink 发送失败次数 | 同上 |
| `firewall_netlink_recv_errors_total` | counter | netlink 收取失败次数（含截断 / 畸形） | 同上 |

清单以这三处注册点为唯一真相源。改动指标要同步改本表与 `grafana/` 两份资源。

5 个计数器（四个 netlink + 配置重载）在启动时预注册，
所以从进程启动起 `/metrics` 里就有 0 值样本行。
netlink 链路建不起来时那四个也各留一条 0 值行。
出处：`main.go` 装配链第 11 步。

### 查询示例

```promql
# 日志解析速率
rate(firewall_lines_parsed_total[5m])

# 正则命中率（命中数 / 已解析行数）
rate(firewall_regex_matches_total[5m])
  / rate(firewall_lines_parsed_total[5m])

# 封禁速率
rate(firewall_bans_triggered_total[5m])

# 内核拒绝指令速率：非零说明下发有问题
rate(firewall_kernel_commands_rejected_total[5m])

# 检出 DDoS 事件的速率
rate(firewall_ddos_events_total[5m])

# 配置重载速率：运维改配置的频次
rate(firewall_daemon_config_reloads_total[5m])

# netlink 发送错误速率：非零说明与内核的链路有问题
rate(firewall_netlink_send_errors_total[5m])

# 收 / 发是否失衡：长期单向偏离说明报文被截断或畸形
rate(firewall_netlink_messages_received_total[5m])
  - rate(firewall_netlink_messages_sent_total[5m])
```

## 内核侧计数

### `/proc/firewall/stats`

`read_format = machine`：每行 `<key> <value>`，十进制整数。
key 名与数值可解析性都是契约（`contract/procfs.fwidl` 的 `key stats`），
`tests/test_02_procfs_interface.py` 逐行断言。

| key | 宽度 | 含义 |
|-----|------|------|
| `total_bans` | u32 | 累计封禁操作数 |
| `total_unbans` | u32 | 累计解封操作数 |
| `whitelist_rejects` | u32 | 被白名单挡下的封禁请求数 |
| `ban_table_full_rejects` | u32 | 封禁表满而拒绝的新增数 |
| `alloc_failures` | u32 | 内存分配失败数 |
| `packets_dropped` | u64 | 丢弃的报文数 |
| `packets_accepted` | u64 | 经钩子放行的报文数 |
| `tcp_anomaly_dropped` | u64 | TCP 标志异常丢弃数 |
| `cleanup_cycles` | u32 | **恒为 0**：无全局清理线程，保留键位只为不破坏按行解析的脚本 |
| `cleanup_expired_total` | u32 | per-entry 定时器到期摘链的条目数 |
| `current_bans` | i32 | 当前封禁条目数 |
| `current_whitelist` | i32 | 当前白名单条目数 |
| `recent_additions` | u32 | 当前 1 秒泛洪窗口内的封禁添加数 |

读之前内核会先 `fw_stats_flush_all()` 跨 CPU 汇总，与 netlink `STATS_QUERY` 同口径。

```bash
sudo cat /proc/firewall/stats
# 取单个键
sudo cat /proc/firewall/stats | awk '$1=="current_bans"{print $2}'
```

### 其他只读条目

| 条目 | 用途 | 契约强度 |
|------|------|---------|
| `rates` | 速率表明细，含每 CPU 槽数与 `rate_slot_spill` | `unstable` |
| `port_scanners` | 端口扫描嫌疑：阈值 5 个唯一端口，最多列 20 条 | `unstable` |
| `service_probes` | 服务探测嫌疑：阈值 3 种协议，最多列 20 条 | `unstable` |
| `udp_ports` / `icmp_types` / `pkt_sizes` / `ttl_dist` / `ip_frags` | 分布统计 | `unstable` |
| `protected_ports` | 受保护端口集合；未下发时显示全端口受保护 | `unstable` |
| `config` | `ban_time` 与封禁 / 白名单条目数 | `unstable` |

`unstable` 意味着**允许改版式**。监控脚本只解析 `stats`，
其余条目留给人看。

## HTTP 出口

| 端点 | 认证 | 内容 |
|------|------|------|
| `GET /health`、`GET /healthz` | 无 | 就绪判定：200 / 503，**有意不套信封** |
| `GET /api/v1/stats` | Basic | 内核快照 + 运行时长 + 速率样本 + 内核模块版本 |
| `GET /api/v1/stats/sse-status` | Basic | 两条 SSE 流各自的连接数与上限 |
| `GET /api/v1/rates*`、协议分布类端点 | Basic | 同一份内核快照的投影 |
| `GET /metrics` | Basic | Prometheus 文本 |

`/health` 与 `/healthz` 的出处：`contract/http.fwidl`，
两条都映射到 `Health` 处理器。

```bash
curl -s http://127.0.0.1:9119/health
curl -s -u <user>:<pass> http://127.0.0.1:9119/api/v1/stats
```

### `/health` 报什么

`/health` 读 `telemetry.Store` 的快照，覆盖：netlink 链路就绪、
`/proc/firewall` 是否存在、封禁缓存与历史库是否初始化、当前封禁数。

链路缺失时快照保持零值，读侧不需要区分「没有内核」与「内核还没采到样」。
所以 `/health` 返回 503 时，先确认模块是否加载、事件泵是否启动。

## 日志监控

### 格式

守护进程写 **JSON Lines**：每行一条 JSON 对象。
字段顺序固定为 `ts` → `level` → `msg` → `version` → 记录自身属性。
整行（含换行）合并为单次 `write()`，所以重启期间新旧进程并存时每行仍是独立合法 JSON。

出处：`src/daemon/internal/logger/`（`json.go`、`handler.go`）。

```json
{"ts":"2026-10-14T10:30:45.123Z","level":"INFO","msg":"内核 netlink 链路已就绪","version":"dev"}
```

### 路径与级别

| 项 | 值 | 出处 |
|----|-----|------|
| 路径 | `defaults.log_file`；留空时用 `/var/log/firewall-daemon.log` | `config/default.yaml`、`internal/logger/logger.go` |
| 随包配置的默认路径 | `/var/log/firewall.log` | `config/default.yaml` |
| 级别取值 | `0=NONE 1=ERR 2=WARN 3=INFO 4=DEBUG` | `internal/config/types.go` |
| 打开失败 | 回退 stderr，进程继续 | `internal/logger/file.go` |

```bash
# 今日封禁相关条目
grep "$(date +%Y-%m-%d)" /var/log/firewall.log | jq -c 'select(.msg|test("封禁"))'

# 按 jail 聚合
jq -r 'select(.jail) | .jail' /var/log/firewall.log | sort | uniq -c | sort -rn

# 只看 ERROR / WARN
jq -c 'select(.level=="ERROR" or .level=="WARN")' /var/log/firewall.log
```

`jq` 需要单独安装（`apt install jq`），不是本项目的依赖。

### 轮转

守护进程内置**按大小轮转**，不需要 logrotate、也不需要 SIGHUP：

| 参数 | 默认 | 行为 |
|------|------|------|
| `log_max_size_mb` | 10 | 超过即切片；`0` 关闭轮转 |
| `log_max_files` | 10（含当前片） | 当前片改名 `.1`，旧片依次顺移，超出删最旧；`1` 表示轮转时直接截断 |

`log_max_*` 不随热重载切换，改后要重启守护进程。
出处：`internal/logger/file.go`、`internal/runtime/file_reloader.go`。

仓库另有 `config/logrotate/firewall-daemon`，供 journald / syslog 那侧使用。

## 告警规则

### 只使用本进程确实产出的指标

```yaml
groups:
  - name: firewall
    rules:
      - alert: HighBanRate
        expr: rate(firewall_bans_triggered_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "封禁速率偏高"

      - alert: KernelRejectingCommands
        expr: rate(firewall_kernel_commands_rejected_total[5m]) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "内核在拒绝下发的指令"

      - alert: NetlinkErrors
        expr: rate(firewall_netlink_send_errors_total[5m])
              + rate(firewall_netlink_recv_errors_total[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "netlink 链路报错"

      - alert: DaemonDown
        # 进程不在时 /metrics 抓取失败，用 up 判定
        expr: up{job="firewall"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "firewall-daemon 未在运行"
```

阈值是给起点，不是结论：按自己的流量规模调。

### 随包资源

`grafana/alert-rules.yaml` 与 `grafana/firewall-dashboard.json` 是导入起点。
两份文件里出现的指标名已核对为本表列出的 13 个名字：

```bash
grep -o 'firewall_[a-z_]*' grafana/firewall-dashboard.json grafana/alert-rules.yaml \
  | sed 's/.*://' | sort -u
```

改指标名时这条命令的输出必须仍全在本表内，否则面板与告警会静默失去数据。

## 健康检查脚本

```bash
#!/bin/bash
# /usr/local/bin/firewall-health.sh

fail() { echo "CRITICAL: $1"; exit 2; }

lsmod | grep -q '^firewall '        || fail "内核模块未加载"
systemctl is-active --quiet firewall-daemon || fail "守护进程未运行"
[ -f /proc/firewall/stats ]         || fail "procfs 接口不可用"

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/health)
[ "$code" = "200" ]                 || fail "/health 返回 $code"

echo "OK: 全部检查通过"
exit 0
```

`/health` 在认证组之外，无需凭据。就绪返回 200，否则 503。

### systemd timer 挂载

```ini
# /etc/systemd/system/firewall-health.service
[Unit]
Description=Firewall Health Check
After=firewall-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall-health.sh
```

```ini
# /etc/systemd/system/firewall-health.timer
[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl enable --now firewall-health.timer
```

## 运维阈值参考

| 现象 | 先看哪个读数 |
|------|-------------|
| 封禁数持续走高 | `current_bans`（procfs）与 `rate(firewall_bans_triggered_total[5m])` |
| 下发不生效 | `rate(firewall_kernel_commands_rejected_total[5m])` 是否非零，再查 `dmesg` |
| 内核链路不稳 | 四个 `firewall_netlink_*` 计数器 + `/health` 的链路字段 |
| 速率表在丢样本 | `sudo cat /proc/firewall/rates` 表头的 `rate_slot_spill`：非零说明活跃源已超上限，新源不做速率判定 |
| 封禁表满 | `ban_table_full_rejects` 是否增长 |
| 白名单在挡下发 | `whitelist_rejects` 是否增长 |
| 丢包突增 | `packets_dropped` 与 `tcp_anomaly_dropped` 分别看：后者涨说明是畸形标志位 |
| 日志解析跟不上 | `firewall_lines_skipped_total` 是否持续增长 |

## 相关文档

- [管理命令](management.md)：procfs 文法与运行期操作
- [故障排查](troubleshooting.md)：读数异常时的定位路径
- [用户态守护进程](../architecture/daemon.md)「可观测性」：注册点与计数点
- [内核模块](../architecture/kernel-module.md)「ProcFS 接口」：读侧纪律
