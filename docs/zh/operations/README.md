# 运维管理

本章节介绍本项目的日常运维操作。

| 文档 | 内容 |
|------|------|
| [管理命令](management.md) | 服务与模块生命周期、procfs 真实文法、批量操作、配置与日志 |
| [监控](monitoring.md) | 13 个 Prometheus 计数器、内核侧 13 个 `stats` 键、两套读数的口径、告警与健康检查 |
| [故障排查](troubleshooting.md) | 按症状定位：加载失败、启动失败、封禁不生效、性能、PWA、CI |

所有运行时操作走两条通道：`/proc/firewall/` 与 systemd。
项目**没有**额外的 CLI 封装。procfs 文法的权威定义在
`contract/procfs.fwidl`，说明文档见
[ProcFS 接口](../configuration/procfs.md)。

## 日常检查清单

| 检查项 | 频率 | 命令 |
|--------|------|------|
| 服务状态 | 每日 | `systemctl status firewall-daemon` |
| 模块是否加载 | 每日 | `lsmod \| grep '^firewall '` |
| 当前封禁数 | 每日 | `sudo cat /proc/firewall/stats \| awk '$1=="current_bans"'` |
| 丢包量 | 每日 | `sudo cat /proc/firewall/stats \| awk '$1=="packets_dropped"'` |
| 就绪探针 | 每日 | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9119/health` |
| 日志大小 | 每周 | `sudo du -m /var/log/firewall*` |
| 历史库大小 | 每周 | `sudo ls -lh /var/lib/firewall/` |
| 磁盘空间 | 每周 | `df -h /var` |
| 内核日志有无新增错误 | 每周 | `sudo dmesg --level=err,warn \| grep firewall` |

单元名是 `firewall-daemon.service`。`systemctl status firewall` 查不到东西。

## 关键读数

下列都是**读数**，不是自动告警。仓库不提供阈值判定。

| 读数 | 出处 | 非零意味着什么 |
|------|------|---------------|
| `whitelist_rejects` | `/proc/firewall/stats` | 下发被白名单前检拒绝。少量正常，持续增长要看是谁在下发 |
| `ban_table_full_rejects` | 同上 | 封禁表到限，新增被拒。要调 `fw_max_ban_entries` 或降灵敏度 |
| `alloc_failures` | 同上 | 内核内存分配失败，需要看整体内存压力 |
| `tcp_anomaly_dropped` | 同上 | 畸形 TCP 标志位在进 DDoS 判定之前就被丢 |
| `cleanup_cycles` | 同上 | **恒为 0**：无全局清理线程，到期由 per-entry 定时器处理 |
| `recent_additions` | 同上 | 当前 1 秒泛洪窗口内的封禁添加数；顶在 `fw_max_bans_per_second` 说明正被限流 |
| `rate_slot_spill` | `/proc/firewall/rates` 表头 | 活跃源超过每 CPU 槽上限，新源**有意放行**（不做速率判定） |
| `firewall_netlink_send_errors_total` | `/metrics` | 与内核的链路有问题 |
| `firewall_kernel_commands_rejected_total` | `/metrics` | 内核在拒绝下发的指令 |

条目上限由**内核模块参数**决定，不由守护进程配置决定。
`capacity:` 段只做持久化与展示，见
[用户态守护进程](../architecture/daemon.md)「配置与热重载」。

## 健康检查脚本

```bash
#!/bin/bash
# /usr/local/bin/firewall-health.sh

fail() { echo "CRITICAL: $1"; exit 2; }

lsmod | grep -q '^firewall '             || fail "内核模块未加载"
systemctl is-active --quiet firewall-daemon || fail "守护进程未运行"
[ -f /proc/firewall/stats ]              || fail "procfs 接口不可用"

code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9119/health)
[ "$code" = "200" ]                      || fail "/health 返回 $code"

echo "OK: 全部检查通过"
exit 0
```

`/health` 在认证组之外，无需凭据；就绪返回 200，否则 503。
`/metrics` 与 `/api/v1/*` 需要 Basic 凭据，脚本里不要用它们做存活判定。

## 阈值建议

**未验证**：仓库内没有阈值实测数据。
下面的数只在「封禁条目数」这一项上有一条出处，其余按你的流量规模自定。

| 项 | 参考 | 出处 |
|----|------|------|
| 封禁条目数接近上限 | `current_bans` 接近 `fw_max_ban_entries`（默认 65535）就该告警，到限后新增一律被拒 | `src/kernel-module/fw_main.c` 的模块参数 |
| 速率表活跃源 | `rate_slot_spill` 持续增长说明活跃源超过 512（每 CPU 槽上限） | `fw_types.h` 的 `FW_RATE_CPU_SLOTS` |
| 泛洪窗口 | `recent_additions` 长期顶在 `fw_max_bans_per_second`（默认 200） | `fw_main.c`、`fw_ban_flood_allow` |
| 日志文件大小 | 由 `log_max_size_mb`（默认 10MB）× `log_max_files`（默认 10）自动轮转，不需要人工阈值 | `config/default.yaml`、`internal/logger/file.go` |

## 相关文档

- [管理命令](management.md)：命令与 procfs 文法
- [监控](monitoring.md)：指标清单与查询
- [故障排查](troubleshooting.md)：遇到问题先看这份
