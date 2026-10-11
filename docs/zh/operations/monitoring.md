# 监控

本文档介绍如何监控 Linux Firewall 内核模块与守护进程的运行状态。

## Prometheus 监控

### 配置 Prometheus

在 `prometheus.yml` 中添加 job（`/metrics` 在认证组内，若配置了凭据需带 `basic_auth`）：

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

### 本进程暴露的指标（`/metrics`）

`internal/http` 暴露 `/metrics`；注册点为 `cmd/firewall-daemon/main.go` 的 `statsSink`
（日志/判定计数、配置重载）、`internal/kernel/transport.go`（netlink 链路健康）与
`internal/kernel/consumer.go`（内核事件）。当前注册的 counter：

| 指标 | 说明 |
|------|------|
| `firewall_lines_parsed_total` | 已解析日志行数 |
| `firewall_lines_skipped_total` | 因超长/异常跳过的行数 |
| `firewall_regex_matches_total` | 正则命中总数 |
| `firewall_inotify_events_total` | inotify 唤醒次数（非事件数） |
| `firewall_log_rotations_total` | 轮转检测次数 |
| `firewall_bans_triggered_total` | 实际发起封禁的次数 |
| `firewall_ddos_events_total` | 检出的 DDoS 事件数 |
| `firewall_kernel_commands_rejected_total` | 被内核拒绝的指令数 |
| `firewall_daemon_config_reloads_total` | 配置热重载成功次数（SIGHUP / 文件变化） |
| `firewall_netlink_messages_sent_total` | netlink 报文成功投递到内核的次数 |
| `firewall_netlink_messages_received_total` | 从内核成功收取的 netlink 报文数 |
| `firewall_netlink_send_errors_total` | netlink 发送失败次数 |
| `firewall_netlink_recv_errors_total` | netlink 收取失败次数（含截断/畸形报文） |

清单以代码里的注册点为唯一真相源；当前没有注册任何 gauge。上述计数器在启动时预注册，
因此从进程启动起就各有一条 0 值样本行。

### 内核侧计数（经 `/proc/firewall/stats` 读取）

内核级计数**不走 Prometheus**，而以 `key value` 行暴露在 `/proc/firewall/stats`
（`read_format = machine`，字段清单以 `contract/procfs.fwidl` 的 `key stats` 为准）。关键键：

| 键 | 说明 |
|----|------|
| `total_bans` | 累计封禁操作数 |
| `total_unbans` | 累计解封操作数 |
| `current_bans` | 当前封禁条目数 |
| `current_whitelist` | 当前白名单条目数 |
| `whitelist_rejects` | 白名单拒绝的封禁请求数 |
| `packets_dropped` | 因命中封禁而丢弃的数据包数 |
| `packets_accepted` | 经 netfilter 钩子放行的数据包数 |
| `cleanup_expired_total` | per-entry 定时器过期回调累计移除的条目数 |
| `cleanup_cycles` | 遗留键位：已无全局清理线程，恒为 0（保留以兼容解析） |
| `recent_additions` | 当前 1 秒窗口内的封禁操作数 |

**不变量**：`total_bans == current_bans + total_unbans + cleanup_expired_total`

读 `stats` 前内核会经 `fw_stats_snapshot()` 跨 CPU flush，与 netlink `STATS_QUERY` 同口径。
若要把这些计数也送进 Prometheus，需要额外的 procfs→metrics 适配；仓库当前不提供。

### 查询示例

```promql
# 日志解析速率
rate(firewall_lines_parsed_total[5m])

# 匹配率（解析中命中正则的比例）
rate(firewall_regex_matches_total[5m])
  / rate(firewall_lines_parsed_total[5m])

# 封禁速率
rate(firewall_bans_triggered_total[5m])

# 内核拒绝指令速率（非零说明下发有问题）
rate(firewall_kernel_commands_rejected_total[5m])

# 配置热重载速率（运维改配置的频次）
rate(firewall_daemon_config_reloads_total[5m])

# netlink 发送错误速率（非零说明与内核的链路有问题）
rate(firewall_netlink_send_errors_total[5m])
```

## 日志监控

### 日志格式

守护进程写 **JSON Lines**：每行一条 JSON 对象，字段顺序固定为
`ts` → `level` → `msg` → `version` → 记录自身属性。默认路径 `/var/log/firewall-daemon.log`。

```
{"ts":"2026-10-11T10:30:45.123Z","level":"INFO","msg":"内核 netlink 链路已就绪","version":"..."}
```

### 日志级别

| 级别 | 说明 |
|------|------|
| `DEBUG` | 调试信息（详细匹配过程） |
| `INFO` | 一般信息（封禁/解封事件、启动/关停） |
| `WARN` | 警告（资源接近上限、链路降级） |
| `ERROR` | 错误（操作失败） |

### 日志轮转

守护进程内置**按大小轮转**：`log_max_size_mb`（默认 10MB）切片、`log_max_files`（默认 10，含
当前片）控制保留片数，`log_max_size_mb=0` 关闭轮转。轮转不需要 logrotate，也不需要 `SIGHUP`
（`log_max_*` 不随热重载切换，改后需重启 daemon）。

### 日志分析命令

日志是 JSON Lines，配合 `jq` 统计：

```bash
# 统计今日封禁次数
grep "$(date +%Y-%m-%d)" /var/log/firewall-daemon.log | jq -c 'select(.msg|test("封禁|ban"))' | wc -l

# 按 jail 聚合封禁条数
jq -r 'select(.jail) | .jail' /var/log/firewall-daemon.log | sort | uniq -c | sort -rn

# 只看 ERROR / WARN
jq -c 'select(.level=="ERROR" or .level=="WARN")' /var/log/firewall-daemon.log
```

## 告警规则

### Prometheus AlertManager

下例只使用本进程确实产出的指标：

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
          summary: "High ban rate detected"
          description: "Ban rate is {{ $value }} per second"

      - alert: KernelRejectingCommands
        expr: rate(firewall_kernel_commands_rejected_total[5m]) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "内核在拒绝指令"
          description: "{{ $value }} rejections per second"

      - alert: DaemonDown
        # 进程不在时 /metrics 抓取失败，用 up 判定
        expr: up{job="firewall"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "firewall-daemon not running"
```

仓库另附 `grafana/alert-rules.yaml` 与 `grafana/firewall-dashboard.json` 作为导入起点；
其中的指标名需与本进程 `/metrics` 的实际产出对齐后再启用。

## 健康检查

### 本地健康检查脚本

```bash
#!/bin/bash
# /usr/local/bin/firewall-health.sh

# 检查内核模块
if ! lsmod | grep -q firewall; then
    echo "CRITICAL: Kernel module not loaded"
    exit 2
fi

# 检查守护进程
if ! systemctl is-active --quiet firewall-daemon; then
    echo "CRITICAL: Daemon not running"
    exit 2
fi

# 检查 ProcFS
if [ ! -f /proc/firewall/stats ]; then
    echo "CRITICAL: ProcFS interface not available"
    exit 2
fi

# 检查只读 HTTP 探针（/health 就绪返回 200，否则 503；探针在认证组之外，无需凭据）
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/health)
if [ "$code" != "200" ]; then
    echo "CRITICAL: /health returned $code"
    exit 2
fi

echo "OK: All checks passed"
exit 0
```

### systemd 集成

```ini
# /etc/systemd/system/firewall-health.service
[Unit]
Description=Linux Firewall Health Check
After=firewall-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/firewall-health.sh

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```
