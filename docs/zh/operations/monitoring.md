# 监控

本文档介绍如何监控 Linux Firewall 内核模块的运行状态。

## Prometheus 监控

### 配置 Prometheus

在 `prometheus.yml` 中添加 job：

```yaml
scrape_configs:
  - job_name: 'firewall'
    static_configs:
      - targets: ['localhost:9119']
    scrape_interval: 15s
```

### 可用指标

> 以下 17 个指标由 `src/daemon/http_exporter/metrics.rs` 实际暴露。
> 早期文档中 `firewall_ban_events_total` / `firewall_packets_dropped_total` /
> `firewall_hash_table_*` / `firewall_jail_*` 等条目均不存在，已删除。

#### 内核侧（来自 `/proc/firewall/stats`）

`/proc/firewall/stats` 完整暴露 12 个字段，映射到以下内核级计数器。
字段名与不变量见 `docs/configuration/procfs.md`。

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_kernel_banned_ips_current` | gauge | 当前封禁 IP 数（`current_bans`） |
| `firewall_kernel_bans_total` | counter | 累计封禁操作数（`total_bans`） |
| `firewall_kernel_unbans_total` | counter | 累计解封操作数（`total_unbans`） |
| `firewall_kernel_whitelist_count` | gauge | 当前白名单条目数（`current_whitelist`） |
| `firewall_kernel_whitelist_rejects_total` | counter | 白名单拒绝的封禁请求数 |
| `firewall_kernel_ban_table_full_rejects_total` | counter | 因封禁表满而拒绝的请求数 |
| `firewall_kernel_alloc_failures_total` | counter | `kmalloc` 失败次数 |
| `firewall_kernel_packets_dropped_total` | counter | 因命中封禁而丢弃的数据包数 |
| `firewall_kernel_packets_accepted_total` | counter | 经 netfilter 钩子放行的数据包数 |
| `firewall_kernel_cleanup_cycles_total` | counter | 清理定时器周期数 |
| `firewall_kernel_cleanup_expired_total` | counter | 清理定时器累计移除的条目数 |
| `firewall_kernel_recent_additions` | gauge | 当前 1 秒窗口内的封禁操作数 |

**不变量**：`total_bans == current_bans + total_unbans + cleanup_expired_total`

#### 守护进程侧

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_daemon_uptime_seconds` | counter | 守护进程运行时长 |
| `firewall_daemon_config_reloads_total` | counter | SIGHUP 触发的配置重载次数 |
| `firewall_daemon_inotify_events_total` | counter | inotify 事件总数 |
| `firewall_daemon_log_rotations_total` | counter | 日志轮转次数 |
| `firewall_daemon_lines_parsed_total` | counter | 已解析日志行数 |
| `firewall_daemon_lines_skipped_total` | counter | 跳过的日志行数 |
| `firewall_daemon_regex_matches_total` | counter | 正则匹配命中数 |
| `firewall_daemon_ips_extracted_total` | counter | 提取出的 IP 数 |
| `firewall_daemon_ips_banned_total` | counter | 实际触发内核封禁的 IP 数 |
| `firewall_daemon_failed_attempts_total` | counter | 封禁失败次数（与 max_retries 相关） |

### 查询示例

```promql
# 当前封禁 IP 数
firewall_kernel_banned_ips_current

# 最近 5 分钟封禁速率（内核态）
rate(firewall_kernel_bans_total[5m])

# 最近 5 分钟 IP 提取速率
rate(firewall_daemon_ips_extracted_total[5m])

# 匹配率（提取但未触发封禁 = 仍在窗口内累积）
rate(firewall_daemon_ips_extracted_total[5m])
  - rate(firewall_daemon_ips_banned_total[5m])

# 守护进程 uptime（小时）
firewall_daemon_uptime_seconds / 3600

# 解析与匹配比（健康度）
rate(firewall_daemon_regex_matches_total[5m])
  / rate(firewall_daemon_lines_parsed_total[5m])
```

## Grafana 仪表板

### 导入仪表板

1. 打开 Grafana
2. 点击 `+` → `Import`
3. 输入仪表板 JSON 或上传文件

### 推荐面板

#### 当前封禁 IP

```
Title: Current Banned IPs
Panel: Stat
Query: firewall_kernel_banned_ips_current
Thresholds: 100 (warning), 1000 (critical)
```

#### 封禁速率趋势

```
Title: Ban Rate (kernel)
Panel: Time Series
Query: rate(firewall_kernel_bans_total[5m])
```

#### 解封速率趋势

```
Title: Unban Rate (kernel)
Panel: Time Series
Query: rate(firewall_kernel_unbans_total[5m])
```

#### 守护进程健康度

```
Title: Daemon Health
Panel: Time Series
Queries:
  - rate(firewall_daemon_lines_parsed_total[5m])    # 解析
  - rate(firewall_daemon_regex_matches_total[5m])   # 匹配
  - rate(firewall_daemon_lines_skipped_total[5m])   # 跳过
  - rate(firewall_daemon_failed_attempts_total[5m])  # 失败
```

#### 容量使用

```
Title: Whitelist Capacity
Panel: Gauge
Query: firewall_kernel_whitelist_count
Thresholds: 50 (warning), 60 (critical)
Max: 64
```

## 日志监控

### 日志格式

```
[2024-01-15 10:30:45] [INFO] [sshd] Banned 192.168.1.100 (5 failures in 600s)
[2024-01-15 10:30:45] [INFO] Kernel: Added 192.168.1.100 to hash table
[2024-01-15 11:30:45] [INFO] [sshd] Unbanned 192.168.1.100 (expired)
[2024-01-15 12:00:00] [WARN] Hash table 75% full
```

### 日志级别

| 级别 | 说明 | 示例 |
|------|------|------|
| `DEBUG` | 调试信息 | 详细匹配过程 |
| `INFO` | 一般信息 | 封禁/解封事件 |
| `WARN` | 警告 | 资源接近上限 |
| `ERROR` | 错误 | 操作失败 |

### 日志轮转

配置 logrotate：

```
/etc/logrotate.d/firewall

/var/log/firewall.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    postrotate
        systemctl reload firewall > /dev/null 2>&1 || true
    endscript
}
```

### 日志分析命令

```bash
# 统计今日封禁数
grep "$(date +%Y-%m-%d)" /var/log/firewall.log | grep "Banned" | wc -l

# 查看最常被封禁的 IP
grep "Banned" /var/log/firewall.log | grep -oP '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -rn | head -20

# 查看各 Jail 封禁数
grep "Banned" /var/log/firewall.log | grep -oP '\[\w+\]' | sort | uniq -c | sort -rn

# 查看最近 10 次封禁
grep "Banned" /var/log/firewall.log | tail -10
```

## 告警规则

### Prometheus AlertManager

```yaml
groups:
  - name: firewall
    rules:
      - alert: HighBanRate
        expr: rate(firewall_kernel_bans_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High kernel ban rate detected"
          description: "Ban rate is {{ $value }} per second"

      - alert: WhitelistNearlyFull
        expr: firewall_kernel_whitelist_count > 50
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Whitelist nearing 64-entry cap"
          description: "{{ $value }} entries used (max 64)"

      - alert: DaemonDown
        # 守护进程崩溃或未运行时，uptime 计数器停止递增
        expr: rate(firewall_daemon_uptime_seconds[5m]) == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "firewall-daemon not running"
          description: "Daemon uptime counter not advancing"

      - alert: DaemonFailingExtraction
        expr: rate(firewall_daemon_failed_attempts_total[5m]) > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High daemon failure rate"
          description: "Failure rate is {{ $value }} per second"
```

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
if ! systemctl is-active --quiet firewall; then
    echo "CRITICAL: Daemon not running"
    exit 2
fi

# 检查 ProcFS
if [ ! -f /proc/firewall/config ]; then
    echo "CRITICAL: ProcFS interface not available"
    exit 2
fi

# 检查 Prometheus 端口
if ! curl -s http://localhost:9119/metrics > /dev/null 2>&1; then
    echo "WARNING: Prometheus metrics not available"
    exit 1
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