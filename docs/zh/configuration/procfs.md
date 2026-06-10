# ProcFS 接口

Linux Firewall 内核模块通过 `/proc/fw_fire/` 目录提供运行时管理和监控接口。

## 接口总览

```
/proc/fw_fire/
├── status          # 模块状态
├── banned_ips      # 当前封禁 IP 列表
├── whitelist       # 当前白名单 IP 列表
├── stats           # 统计信息
├── config          # 运行时配置
├── clear           # 清空封禁列表（写入触发）
└── version         # 模块版本
```

## 读取接口

### 模块状态

```bash
cat /proc/fw_fire/status
```

输出：

```
Firewall Module Status
======================
Module: loaded
Version: 1.0.0
State: active
Banned IPs: 15 / 4096
Whitelisted IPs: 3 / 64
```

| 字段 | 说明 |
|------|------|
| `Module` | 模块加载状态 |
| `Version` | 模块版本号 |
| `State` | 运行状态：`active`, `inactive` |
| `Banned IPs` | 当前封禁数 / 总容量 |
| `Whitelisted IPs` | 当前白名单数 / 总容量 |

### 封禁 IP 列表

```bash
cat /proc/fw_fire/banned_ips
```

输出：

```
Banned IP List
==============
IP              Jail      Remaining(s)  Protocol  Port
192.168.1.100   sshd      3452          tcp       22
10.0.0.50       nginx     1200          tcp       80
172.16.0.1      postfix   5800          tcp       25
```

| 字段 | 说明 |
|------|------|
| `IP` | 被封禁的 IP 地址 |
| `Jail` | 触发封禁的 jail 名称 |
| `Remaining(s)` | 剩余封禁时间（秒） |
| `Protocol` | 封禁协议 |
| `Port` | 封禁端口 |

### 白名单列表

```bash
cat /proc/fw_fire/whitelist
```

输出：

```
Whitelist
=========
IP/Range
127.0.0.1
192.168.1.0/24
10.0.0.1
```

### 统计信息

```bash
cat /proc/fw_fire/stats
```

输出：

```
Statistics
==========
Total ban events:     125
Total unban events:   98
Total packets dropped: 45230
Total packets passed:  1250340
Current banned:       15
```

| 字段 | 说明 |
|------|------|
| `Total ban events` | 累计封禁次数 |
| `Total unban events` | 累计解封次数 |
| `Total packets dropped` | 累计丢弃数据包数 |
| `Total packets passed` | 累计放行数据包数 |
| `Current banned` | 当前封禁 IP 数 |

### 模块版本

```bash
cat /proc/fw_fire/version
```

输出：

```
1.0.0
```

## 写入接口

### 添加封禁

向 `config` 写入封禁指令：

```bash
echo "ban 192.168.1.100 3600 tcp 22 sshd" | sudo tee /proc/fw_fire/config
```

格式：`ban <ip> <duration> <protocol> <port> <jail>`

| 参数 | 说明 |
|------|------|
| `ip` | 要封禁的 IP 地址 |
| `duration` | 封禁时长（秒），0 表示永久 |
| `protocol` | `tcp`, `udp`, `all` |
| `port` | 目标端口 |
| `jail` | jail 名称（可选） |

### 移除封禁

```bash
echo "unban 192.168.1.100" | sudo tee /proc/fw_fire/config
```

格式：`unban <ip>`

### 添加白名单

```bash
echo "whitelist 192.168.1.50" | sudo tee /proc/fw_fire/config
```

格式：`whitelist <ip>`

> **限制**：白名单最多 64 个条目。

### 移除白名单

```bash
echo "unwhitelist 192.168.1.50" | sudo tee /proc/fw_fire/config
```

格式：`unwhitelist <ip>`

### 清空所有封禁

```bash
echo "clear" | sudo tee /proc/fw_fire/clear
```

或写入 `config`：

```bash
echo "clear" | sudo tee /proc/fw_fire/config
```

### 启用/禁用模块

```bash
# 禁用（停止处理数据包）
echo "disable" | sudo tee /proc/fw_fire/config

# 启用
echo "enable" | sudo tee /proc/fw_fire/config
```

## 通过 fwctl 访问

`fwctl` 工具封装了 ProcFS 操作：

| fwctl 命令 | ProcFS 操作 |
|------------|-------------|
| `fwctl status` | 读取 `/proc/fw_fire/status` |
| `fwctl banned` | 读取 `/proc/fw_fire/banned_ips` |
| `fwctl whitelist` | 读取 `/proc/fw_fire/whitelist` |
| `fwctl stats` | 读取 `/proc/fw_fire/stats` |
| `fwctl ban <ip> <time>` | 写入 `/proc/fw_fire/config` |
| `fwctl unban <ip>` | 写入 `/proc/fw_fire/config` |
| `fwctl clear` | 写入 `/proc/fw_fire/clear` |

## 权限要求

| 操作 | 权限 |
|------|------|
| 读取 | 需要 root 或 `fw_fire` 组 |
| 写入 | 需要 root |

```bash
# 创建 fw_fire 组
sudo groupadd fw_fire

# 将用户加入组
sudo usermod -aG fw_fire $USER

# 修改 ProcFS 文件权限（需要 udev 规则）
```

## 调试

### 启用调试日志

编译时启用调试级别：

```bash
make debug DL=2
```

查看内核日志：

```bash
sudo dmesg | grep fw_fire
```

### 调试级别

| 级别 | 说明 |
|------|------|
| `DL=0` | 无调试输出 |
| `DL=1` | 关键调试信息 |
| `DL=2` | 详细调试信息 |
| `DL=3` | 所有调试信息 |