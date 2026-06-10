# 管理命令

本节列出 Linux Firewall 日常管理涉及的真实命令。所有运行时操作都通过
`/proc/firewall/`（见 [ProcFS 接口](../configuration/procfs.md)）和
systemd 完成——项目未提供额外的 CLI 封装。

## 服务管理

| 操作 | 命令 |
|------|------|
| 启动守护进程 | `sudo systemctl start firewall-daemon` |
| 停止守护进程 | `sudo systemctl stop firewall-daemon` |
| 重启守护进程 | `sudo systemctl restart firewall-daemon` |
| 查看服务状态 | `systemctl status firewall-daemon` |
| 开机自启 | `sudo systemctl enable firewall-daemon` |
| 重新加载 YAML 配置（不中断） | `sudo systemctl reload firewall-daemon` |
| 验证配置语法 | `sudo firewall-daemon -c /etc/firewall/default.yaml` （前台运行，便于检查报错） |

`firewall-daemon` 守护进程接受的参数：

| 参数 | 含义 |
|------|------|
| `-c <file>` | 加载单个 YAML 配置文件 |
| `-C <dir>` | 加载目录下所有 YAML 配置（按字母序） |
| `--daemon` | 守护模式（fork 到后台） |

## 内核模块

| 操作 | 命令 |
|------|------|
| 加载模块 | `sudo modprobe firewall` |
| 带参数加载 | `sudo modprobe firewall fw_ban_time=600 fw_max_bans=4096` |
| 查看已加载 | `lsmod \| grep firewall` |
| 卸载模块 | `sudo rmmod firewall` |
| 查看模块信息 | `modinfo firewall` |

## 封禁管理

```bash
# 封禁（默认时长，fw_ban_time）
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# 封禁（指定秒数）
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans

# 永久封禁
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# 解封
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 批量封禁（IP 列表）
while read ip; do echo "$ip" | sudo tee -a /proc/firewall/bans; done < ip_list.txt

# 清空所有封禁（无原生命令，见下方）
```

清空所有封禁：模块未提供“一键清空”接口。可逐条 `unban`：

```bash
# 解析 bans 中的 IP 列表，循环 unban
while read -r line; do
  ip=$(echo "$line" | awk '/^[0-9]/ {print $1}')
  [ -n "$ip" ] && echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null
done < <(cat /proc/firewall/bans)
```

或重载模块彻底重置内核态状态（注意：会丢失所有非持久化封禁）：

```bash
sudo rmmod firewall && sudo modprobe firewall fw_ban_time=600
```

## 白名单管理

```bash
# 查看
cat /proc/firewall/whitelist

# 添加 IP / CIDR
echo "10.0.0.1" | sudo tee /proc/firewall/whitelist
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist

# 移除
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

> 白名单上限 64 条目。`/etc/firewall/*.yaml` 中预先定义的条目
> 在 `systemctl restart firewall-daemon` 时由守护进程自动下发。

## 状态与统计

```bash
# 运行时配置（ban_time、当前条目数）
cat /proc/firewall/config

# 计数器（total_bans、total_unbans、packets_dropped 等）
cat /proc/firewall/stats

# Prometheus 指标（默认 :9119）
curl http://localhost:9119/metrics
```

Jail 维度的统计需要从 Prometheus 指标 `firewall_kernel_*` 与守护进程
日志中获取，procfs 不直接暴露 jail 表格。

## 日志

```bash
# 守护进程日志
tail -f /var/log/firewall.log

# 内核日志（含模块输出）
sudo dmesg --follow | grep -i firewall

# 按严重级别过滤
sudo dmesg --level=err,warn | grep -i firewall
```

修改守护进程日志级别：编辑 `/etc/firewall/default.yaml` 的 `global.log_level`
字段后 `systemctl reload firewall-daemon`。

## 配置

| 操作 | 命令 |
|------|------|
| 验证 YAML 语法 | `yamllint /etc/firewall/` |
| 模拟运行（看启动日志而不实际常驻） | `sudo firewall-daemon -c /etc/firewall/default.yaml` |
| 应用配置（热重载） | `sudo systemctl reload firewall-daemon` |
| 查看当前生效的配置 | `cat /proc/firewall/config`（仅运行时字段） |

> YAML 配置的字段说明与示例参见
> [配置指南 - YAML 配置](../configuration/yaml-config.md)。

## 命令速查表

| 用途 | 命令 |
|------|------|
| 启动 | `sudo systemctl start firewall-daemon` |
| 停止 | `sudo systemctl stop firewall-daemon` |
| 重启 | `sudo systemctl restart firewall-daemon` |
| 重载配置 | `sudo systemctl reload firewall-daemon` |
| 加载模块 | `sudo modprobe firewall` |
| 卸载模块 | `sudo rmmod firewall` |
| 查看封禁 | `cat /proc/firewall/bans` |
| 封禁 IP | `echo "<ip> [<seconds>]" \| sudo tee /proc/firewall/bans` |
| 解封 IP | `echo "unban <ip>" \| sudo tee /proc/firewall/bans` |
| 查看白名单 | `cat /proc/firewall/whitelist` |
| 添加白名单 | `echo "<ip-or-cidr>" \| sudo tee /proc/firewall/whitelist` |
| 移除白名单 | `echo "remove <ip-or-cidr>" \| sudo tee /proc/firewall/whitelist` |
| 查看运行时配置 | `cat /proc/firewall/config` |
| 查看计数器 | `cat /proc/firewall/stats` |
| 守护进程日志 | `tail -f /var/log/firewall.log` |
| 内核日志 | `sudo dmesg \| grep -i firewall` |
| Prometheus 指标 | `curl http://localhost:9119/metrics` |
