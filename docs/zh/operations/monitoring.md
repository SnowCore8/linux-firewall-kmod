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

#### 通用指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_banned_ips_total` | gauge | 当前封禁 IP 数量 |
| `firewall_ban_events_total` | counter | 累计封禁事件数 |
| `firewall_unban_events_total` | counter | 累计解封事件数 |
| `firewall_packets_dropped_total` | counter | 累计丢弃数据包数 |
| `firewall_packets_passed_total` | counter | 累计放行数据包数 |

#### 容量指标

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_whitelist_entries_total` | gauge | 当前白名单条目数 |
| `firewall_hash_table_usage` | gauge | 哈希表使用率 (0.0-1.0) |
| `firewall_hash_table_capacity` | gauge | 哈希表总容量 (4096) |
| `firewall_whitelist_capacity` | gauge | 白名单总容量 (64) |

#### Jail 指标

| 指标 | 类型 | 标签 | 说明 |
|------|------|------|------|
| `firewall_jail_failures_total` | counter | `jail` | 各 jail 失败匹配次数 |
| `firewall_jail_bans_total` | counter | `jail` | 各 jail 触发的封禁数 |
| `firewall_jail_active` | gauge | `jail` | jail 是否启用 (0/1) |

### 查询示例

```yaml
# 当前封禁 IP 数
firewall_banned_ips_total

# 最近 5 分钟封禁速率
rate(firewall_ban_events_total[5m])

# 各 Jail 封禁数
sum by (jail) (firewall_jail_bans_total)

# 哈希表使用百分比
firewall_hash_table_usage * 100

# 数据包丢弃率
rate(firewall_packets_dropped_total[5m])
```

## Grafana 仪表板

### 导入仪表板

1. 打开 Grafana
2. 点击 `+` → `Import`
3. 输入仪表板 JSON 或上传文件

### 推荐面板

#### 封禁概览

```
Title: Current Banned IPs
Panel: Stat
Query: firewall_banned_ips_total
Thresholds: 100 (warning), 1000 (critical)
```

#### 封禁趋势

```
Title: Ban Events Rate
Panel: Time Series
Query: rate(firewall_ban_events_total[5m])
```

#### Jail 分布

```
Title: Bans by Jail
Panel: Pie Chart
Query: sum by (jail) (firewall_jail_bans_total)
```

#### 数据包统计

```
Title: Packets Processed
Panel: Time Series
Query: 
  rate(firewall_packets_dropped_total[5m])  # 丢弃
  rate(firewall_packets_passed_total[5m])   # 放行
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
        expr: rate(firewall_ban_events_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High ban rate detected"
          description: "Ban rate is {{ $value }} per second"

      - alert: HashTableNearlyFull
        expr: firewall_hash_table_usage > 0.8
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Hash table nearly full"
          description: "Usage is {{ $value | humanizePercentage }}"

      - alert: FirewallDown
        expr: firewall_banned_ips_total == -1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Firewall module is not responding"

      - alert: HighDropRate
        expr: rate(firewall_packets_dropped_total[5m]) > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High packet drop rate"
          description: "Drop rate is {{ $value }} per second"
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
if [ ! -f /proc/firewall/status ]; then
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