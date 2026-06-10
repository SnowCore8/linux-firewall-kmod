# ProcFS 接口

Linux Firewall 内核模块通过 `/proc/firewall/` 目录提供运行时管理和监控接口。

## 接口总览

```
/proc/firewall/
├── bans           # 封禁列表（可写：ban / unban）
├── whitelist       # 白名单（可写：添加条目）
├── stats           # 计数器（只读）
└── config          # 运行时配置（只读）
```

> 上表即真实接口。早期文档中曾出现 `status` / `clear` / `version`
> 等条目，源码中并不存在；`config` 同样为只读文件，写入会返回
> `-EINVAL`。如需清空封禁，请逐条 `unban` 或重新加载模块。

## 读取接口

### 运行时配置

```bash
cat /proc/firewall/config
```

输出：

```
Current Firewall Configuration:
--------------------------------
ban_time: 3600 seconds
Ban entries: 15
Whitelist entries: 3
```

| 字段 | 说明 |
|------|------|
| `ban_time` | 默认封禁时长（秒） |
| `Ban entries` | 当前封禁条目数 |
| `Whitelist entries` | 当前白名单条目数 |

### 封禁 IP 列表

```bash
cat /proc/firewall/bans
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
cat /proc/firewall/whitelist
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
cat /proc/firewall/stats
```

输出（key-value 格式，每行一个指标）：

```
total_bans 0
total_unbans 0
whitelist_rejects 0
ban_table_full_rejects 0
alloc_failures 0
packets_dropped 0
packets_accepted 0
cleanup_cycles 0
cleanup_expired_total 0
current_bans 0
current_whitelist 19
recent_additions 0
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `total_bans` | counter | 累计产生新条目的封禁操作数（对已封禁 IP 的重复封禁**不计入**） |
| `total_unbans` | counter | 累计解封操作数（含永久解封） |
| `whitelist_rejects` | counter | 因命中白名单而被拒绝的封禁请求（阶段 1 检查 + 每桶锁重检） |
| `ban_table_full_rejects` | counter | 因封禁表满（4096 条）而被拒绝的封禁请求 |
| `alloc_failures` | counter | 申请 `ban_entry` 内存失败的次数 |
| `packets_dropped` | counter | netfilter 钩子因命中封禁而丢弃的数据包。分片包与非法源 IP 包**不计入**。 |
| `packets_accepted` | counter | netfilter 钩子经白名单/封禁检查后放行的数据包。范围同 `packets_dropped`。 |
| `cleanup_cycles` | counter | 清理定时器已触发的周期数 |
| `cleanup_expired_total` | counter | 清理定时器累计移除的过期条目数 |
| `current_bans` | gauge | 当前封禁条目数（永久 + 临时） |
| `current_whitelist` | gauge | 当前白名单条目数 |
| `recent_additions` | gauge | 当前 1 秒洪水保护窗口内的封禁操作数 |

**统计不变量**（修复后任一时刻成立）：

```
total_bans == current_bans + total_unbans + cleanup_expired_total
```

对已有效封禁的重复 ban、对过期条目的续期刷新均不计入 `total_bans`，保证该等式恒成立。

### 模块版本

模块不提供单独 `version` 接口；版本信息通过内核模块标识与
`dmesg | grep firewall` 启动日志获取。

## 写入接口

`/proc/firewall/config` 与 `/proc/firewall/stats` 为只读文件，
所有写入操作都通过 `/proc/firewall/bans` 与 `/proc/firewall/whitelist`。

### 添加封禁

```bash
# 默认时长（fw_ban_time）
echo "1.2.3.4" | sudo tee /proc/firewall/bans

# 指定时长（秒）
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans

# 永久封禁
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans
```

格式：`<ip>` 或 `<ip> <seconds>`（秒，0 表示永久）

### 解除封禁

```bash
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
```

格式：`unban <ip>`

### 添加白名单

```bash
# 单个 IP
echo "10.0.0.1" | sudo tee /proc/firewall/whitelist

# CIDR 网段
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

> **限制**：白名单最多 64 个条目。

### 移除白名单

```bash
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

格式：`remove <ip-or-cidr>`

### 清空所有封禁

源码未提供“一键清空”接口。如需清空：

```bash
# 方案一：逐条 unban（脚本中可循环）
while read -r ip _; do
  [ -n "$ip" ] && echo "unban $ip" | sudo tee /proc/firewall/bans >/dev/null
done < <(awk '/^[0-9]/ {print $1}' /proc/firewall/bans)

# 方案二：重载模块（清空所有内核态封禁/白名单）
sudo rmmod firewall && sudo insmod $(modinfo -n firewall) fw_ban_time=600
```

## 权限要求

| 操作 | 权限 |
|------|------|
| 读取 | 需要 root 或 `firewall` 组 |
| 写入 | 需要 root |

```bash
# 创建 firewall 组
sudo groupadd firewall

# 将用户加入组
sudo usermod -aG firewall $USER

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
sudo dmesg | grep firewall
```

### 调试级别

| 级别 | 说明 |
|------|------|
| `DL=0` | 无调试输出 |
| `DL=1` | 关键调试信息 |
| `DL=2` | 详细调试信息 |
| `DL=3` | 所有调试信息 |