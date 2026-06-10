# 管理命令

本文档介绍 `firewall-daemon` 命令行工具的所有命令。

## firewall-daemon 概览

`firewall-daemon` 是 Linux Firewall 的用户态管理工具，提供完整的命令行接口来管理封禁、白名单和查看状态。

### 语法

```bash
firewall-daemon <command> [arguments]
```

### 全局选项

| 选项 | 说明 |
|------|------|
| `-c, --config <path>` | 指定配置文件路径（默认 `/etc/firewall/default.yaml`） |
| `-h, --help` | 显示帮助信息 |
| `-v, --version` | 显示版本信息 |
| `-d, --debug` | 启用调试模式 |

## 服务管理

### 启动

```bash
firewall-daemon start
```

启动守护进程和加载内核模块。

### 停止

```bash
firewall-daemon stop
```

停止守护进程并卸载内核模块。

### 重启

```bash
firewall-daemon restart
```

重启守护进程。

### 状态

```bash
cat /proc/firewall/config
```

输出示例：

```
firewall Status
==============
Daemon:     running (PID: 12345)
Module:     loaded
Banned:     15 IPs
Whitelisted: 3 IPs
Uptime:     2d 5h 30m
```

### 重新加载配置

```bash
firewall-daemon reload
```

发送 SIGHUP 信号给守护进程，重新加载 YAML 配置而不中断服务。

## 封禁管理

### 查看封禁列表

```bash
cat /proc/firewall/bans
```

输出示例：

```
Banned IPs (15)
================
IP              Jail      Remaining   Protocol  Port
192.168.1.100   sshd      3452s       tcp       22
10.0.0.50       nginx     1200s       tcp       80
172.16.0.1      postfix   5800s       tcp       25
```

### 封禁 IP

```bash
firewall-daemon ban <ip> [duration] [protocol] [port]
```

示例：

```bash
# 封禁 1 小时
echo "192.168.1.100 3600" | sudo tee /proc/firewall/bans

# 封禁 30 分钟，指定 TCP 80 端口
firewall-daemon ban 192.168.1.100 1800 tcp 80

# 永久封禁所有端口
firewall-daemon ban 192.168.1.100 0 all 0
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `duration` | 3600 | 封禁时长（秒），0 = 永久 |
| `protocol` | tcp | `tcp`, `udp`, `all` |
| `port` | 0 | 端口，0 = 所有端口 |

### 解封 IP

```bash
echo "unban <ip>" | sudo tee /proc/firewall/bans
```

示例：

```bash
echo "unban 192.168.1.100" | sudo tee /proc/firewall/bans
```

### 批量封禁

```bash
firewall-daemon ban-file <file>
```

文件格式（每行一个 IP）：

```
192.168.1.100
10.0.0.50
172.16.0.1
```

### 清空所有封禁

```bash
firewall-daemon clear
```

确认提示：

```
Are you sure you want to unban all IPs? [y/N]
```

强制清空（无提示）：

```bash
firewall-daemon clear --force
```

## 白名单管理

### 查看白名单

```bash
cat /proc/firewall/whitelist
```

输出示例：

```
Whitelist (3/64)
================
127.0.0.1
192.168.1.0/24
10.0.0.1
```

### 添加白名单

```bash
firewall-daemon whitelist-add <ip[/cidr]>
```

示例：

```bash
firewall-daemon whitelist-add 192.168.1.50
firewall-daemon whitelist-add 10.0.0.0/8
```

### 移除白名单

```bash
firewall-daemon whitelist-remove <ip[/cidr]>
```

示例：

```bash
firewall-daemon whitelist-remove 192.168.1.50
```

## 统计信息

### 查看统计

```bash
cat /proc/firewall/stats
```

输出示例：

```
Statistics
==========
Total ban events:       125
Total unban events:     98
Total packets dropped:  45230
Total packets passed:   1250340
Current banned:         15
Hash table usage:       0.37%
```

### 查看 Jail 统计

```bash
firewall-daemon jail-stats
```

输出示例：

```
Jail Statistics
===============
Jail        Enabled  Failures  Bans
sshd        yes      523       15
nginx       yes      1250      45
postfix     yes      89        3
```

### 实时统计

```bash
watch -n 1 firewall-daemon stats
```

## 日志

### 查看守护进程日志

```bash
firewall-daemon log
```

等同于：

```bash
tail -f /var/log/firewall.log
```

### 查看内核日志

```bash
firewall-daemon dmesg
```

等同于：

```bash
dmesg | grep firewall
```

## 配置

### 验证配置

```bash
firewall-daemon check-config
```

检查 YAML 配置文件的语法和有效性。

### 显示当前配置

```bash
firewall-daemon show-config
```

显示解析后的当前配置。

## 命令速查表

| 命令 | 说明 |
|------|------|
| `firewall-daemon start` | 启动服务 |
| `firewall-daemon stop` | 停止服务 |
| `firewall-daemon restart` | 重启服务 |
| `cat /proc/firewall/config` | 查看状态 |
| `firewall-daemon reload` | 重载配置 |
| `cat /proc/firewall/bans` | 查看封禁列表 |
| `echo "<ip>" | sudo tee /proc/firewall/bans` | 封禁 IP |
| `echo "unban <ip>" | sudo tee /proc/firewall/bans` | 解封 IP |
| `sudo rmmod firewall && sudo insmod firewall.ko` | 清空所有封禁 |
| `cat /proc/firewall/whitelist` | 查看白名单 |
| `firewall-daemon whitelist-add <ip>` | 添加白名单 |
| `firewall-daemon whitelist-remove <ip>` | 移除白名单 |
| `cat /proc/firewall/stats` | 查看统计 |
| `firewall-daemon jail-stats` | 查看 Jail 统计 |
| `firewall-daemon log` | 查看日志 |
| `firewall-daemon dmesg` | 查看内核日志 |
| `firewall-daemon check-config` | 验证配置 |
| `firewall-daemon show-config` | 显示配置 |