# 从 fail2ban 迁移指南

**版本**: v2.1.1
**最后更新**: 2026-05-07

---

## 1. 概述

### 为什么从 fail2ban 迁移？

fail2ban 是一个成熟可靠的日志监控工具，但其基于 Python 用户态 + iptables 规则的设计在面对高并发场景时存在性能瓶颈。Firewall 将封禁逻辑移至内核空间，带来以下优势：

| 优势 | 说明 |
|------|------|
| **更快的封禁响应** | 毫秒级 vs 秒级，攻击者在封禁生效前能发出的请求更少 |
| **更低的资源占用** | ~10MB vs ~50-100MB，无 Python 运行时开销 |
| **更高的查找性能** | 哈希表 O(1) vs iptables 线性遍历规则 |
| **更严格的配置校验** | 默认严格模式，防止配置拼写错误导致安全策略遗漏 |
| **更好的可观测性** | 内置 Prometheus 指标导出，方便监控和告警 |
| **状态持久化** | SQLite 数据库保存永久封禁，重启后自动恢复 |

### 核心差异对比

| 维度 | fail2ban | Firewall |
|------|----------|----------|
| **架构** | 单进程 Python（用户态） | 双层架构：C 守护进程 + 内核模块 |
| **封禁机制** | iptables/nftables 规则 | Netfilter `NF_INET_PRE_ROUTING` 钩子 |
| **配置格式** | INI（`jail.conf` / `jail.local`） | YAML（`*.yaml`） |
| **正则引擎** | Python `re` 模块 | PCRE2（JIT 编译加速） |
| **失败追踪** | Python 字典 | khash 哈希表 |
| **日志监控** | 轮询（`polling`） | inotify 事件驱动 |
| **持久化** | 文件系统（`/var/lib/fail2ban/`） | SQLite 数据库 |
| **监控指标** | 无内置 | Prometheus（端口 9119） |
| **封禁容量** | 无硬性限制 | 4096 IP |
| **白名单** | `ignoreip` 参数 | 独立白名单表（64 条目） |
| **IPv6** | 支持 | 仅支持 IPv4 |
| **配置校验** | 宽松（未知参数被忽略） | 严格（默认拒绝加载） |

---

## 2. 迁移前准备

### 2.1 停止 fail2ban 服务

```bash
# 停止服务
sudo systemctl stop fail2ban

# 禁用开机自启
sudo systemctl disable fail2ban

# 确认服务已停止
sudo systemctl status fail2ban
```

### 2.2 备份现有配置

```bash
# 备份 fail2ban 配置目录
sudo cp -r /etc/fail2ban /etc/fail2ban.backup

# 确认备份完成
ls -la /etc/fail2ban.backup/
```

### 2.3 备份封禁列表

```bash
# 查看当前 fail2ban 封禁的 IP
sudo fail2ban-client status
sudo fail2ban-client status sshd

# 导出所有 jail 的封禁 IP 列表
for jail in $(sudo fail2ban-client status | grep "Jail list" | cut -d: -f2 | tr ',' ' '); do
  echo "=== Jail: $jail ==="
  sudo fail2ban-client get "$jail" banip
done > /tmp/fail2ban-banned-ips.txt

# 备份封禁数据库（如果使用）
sudo cp /var/lib/fail2ban/fail2ban.sqlite3 /tmp/fail2ban.sqlite3.backup 2>/dev/null || true
```

### 2.4 清理 fail2ban 规则（可选）

```bash
# 查看当前 iptables 规则
sudo iptables -L -n

# 如果 fail2ban 使用了自定义链，可以清理
# 注意：这会移除所有 fail2ban 添加的 iptables 规则
sudo fail2ban-client stop  # 如果还在运行
sudo iptables -F fail2ban-ssh 2>/dev/null || true
sudo iptables -X fail2ban-ssh 2>/dev/null || true
```

---

## 3. 安装 Firewall

### 3.1 安装依赖

**Debian / Ubuntu：**

```bash
sudo apt update
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev
```

**RHEL / CentOS / AlmaLinux：**

```bash
sudo dnf install -y gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel
```

### 3.2 编译安装

```bash
# 克隆或进入项目目录
cd /root/firewall

# 编译全部（内核模块 + 守护进程）
make

# 如果只需要编译特定组件
make kernel-module    # 仅内核模块
make daemon           # 仅守护进程

# 安装所有组件
sudo make install
```

`make install` 会自动完成以下操作：
- 安装内核模块到 `/lib/modules/$(uname -r)/extra/firewall.ko`
- 安装守护进程到 `/usr/local/sbin/firewall-daemon`
- 安装配置文件到 `/etc/firewall/`
- 创建状态目录 `/var/lib/firewall/`
- 安装 systemd 服务并启动

### 3.3 验证安装

```bash
# 检查内核模块是否加载
lsmod | grep firewall

# 检查 procfs 接口
ls -la /proc/firewall/

# 检查守护进程是否运行
sudo systemctl status firewall-daemon

# 检查 Prometheus 指标
curl -s http://localhost:9119/metrics | head -20
```

---

## 4. 配置迁移

### 4.1 fail2ban jail.conf → Firewall YAML 对照表

| fail2ban 参数 | Firewall 参数 | 说明 |
|--------------|--------------|------|
| `[jail]` 区块 | `<jail_name>:` 区块 | Jail 定义 |
| `enabled = true` | `enabled: true` | 是否启用 |
| `filter = sshd` | 智能推断（基于 jail 名称） | 自动匹配内置正则 |
| `logpath = /var/log/auth.log` | `log_files: [/var/log/auth.log]` | 日志文件路径 |
| `maxretry = 5` | `max_retries: 5` | 最大失败次数 |
| `findtime = 600` | `findtime: 600` | 时间窗口（秒） |
| `bantime = 900` | `ban_time: 900` | 封禁时长（秒） |
| `ignoreip = 127.0.0.1` | `/proc/firewall/whitelist` | 白名单（独立管理） |
| `backend = auto` | inotify（固定） | 日志监控方式 |
| `action = iptables` | Netfilter 钩子（自动） | 封禁动作 |
| `port = ssh` | 不适用 | Firewall 在网络层封禁，不绑定端口 |
| `protocol = tcp` | 不适用 | Firewall 不区分协议 |

### 4.2 全局默认配置对照

**fail2ban (`jail.conf` `[DEFAULT]` 段)：**

```ini
[DEFAULT]
bantime  = 10m
findtime = 10m
maxretry = 5
backend  = auto
```

**Firewall (`defaults` 块)：**

```yaml
defaults:
  max_retries: 3
  findtime: 600         # 10 分钟
  ban_time: 600         # 10 分钟
  interval: 1           # 日志检查间隔（秒）
  metrics_port: 9119    # Prometheus 指标端口
```

### 4.3 常见服务配置示例

#### SSH 服务 (sshd)

**fail2ban：**

```ini
[sshd]
enabled = true
port    = ssh
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime  = 600
findtime = 600
```

**Firewall：**

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log       # Debian/Ubuntu
    - /var/log/secure         # RHEL/CentOS
  max_retries: 5
  findtime: 600
  ban_time: 600
  regex: ""                   # 使用内置 SSHD 模式
```

#### Nginx 服务

**fail2ban：**

```ini
[nginx-http-auth]
enabled  = true
filter   = nginx-http-auth
logpath  = /var/log/nginx/error.log
maxretry = 5
bantime  = 3600
```

**Firewall：**

```yaml
nginx:
  enabled: true
  log_files:
    - /var/log/nginx/error.log
  max_retries: 5
  findtime: 600
  ban_time: 3600
  regex: ""                   # 使用内置 Nginx 模式
```

#### Apache 服务

**fail2ban：**

```ini
[apache-auth]
enabled  = true
filter   = apache-auth
logpath  = /var/log/apache2/error.log
maxretry = 5
bantime  = 3600
```

**Firewall：**

```yaml
apache:
  enabled: true
  log_files:
    - /var/log/apache2/error.log
  max_retries: 5
  findtime: 600
  ban_time: 3600
  regex: ""                   # 使用内置 Apache 模式
```

#### MySQL 服务

**fail2ban：**

```ini
[mysqld-auth]
enabled  = true
filter   = mysqld-auth
logpath  = /var/log/mysql/error.log
maxretry = 5
bantime  = 3600
```

**Firewall：**

```yaml
mysql:
  enabled: true
  log_files:
    - /var/log/mysql/error.log
  max_retries: 5
  findtime: 600
  ban_time: 3600
  regex: ""                   # 使用内置 MySQL 模式
```

### 4.4 正则表达式差异说明

#### fail2ban 正则语法

fail2ban 使用 Python `re` 模块，支持 Python 正则语法：

```ini
failregex = ^%(__prefix_line)sFailed password for .* from <HOST>\s*$
```

#### Firewall 正则语法

Firewall 使用 PCRE2 引擎，语法基本兼容，但有以下差异：

| 特性 | fail2ban | Firewall |
|------|----------|----------|
| IP 占位符 | `<HOST>` | `<IP>` |
| 前缀行占位符 | `%(__prefix_line)s` | 不需要（自动处理） |
| 正则引擎 | Python `re` | PCRE2 |
| JIT 编译 | 不支持 | 支持（自动启用） |
| ReDoS 防护 | 无 | 自动检测并拒绝危险模式 |

#### 转换示例

**fail2ban 自定义 filter：**

```ini
[Definition]
failregex = ^.*Failed password for .* from <HOST> port \d+ ssh2$
            ^.*Invalid user .* from <HOST> port \d+$
ignoreregex =
```

**Firewall 自定义 regex：**

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  regex: "Failed password for .* from <IP>|Invalid user .* from <IP>"
```

> **注意**：
> 1. Firewall 的 `<IP>` 对应 fail2ban 的 `<HOST>`
> 2. Firewall 不需要 `%(__prefix_line)s` 前缀
> 3. 多个模式可以用 `|` 连接
> 4. 系统会自动检测 ReDoS 危险模式（如嵌套量词 `(a+)+`）并拒绝加载

### 4.5 白名单迁移

**fail2ban (`ignoreip`)：**

```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 192.168.1.0/24
```

**Firewall（通过 procfs 添加）：**

```bash
# 系统 IP 会自动发现并加入白名单
# 手动添加额外白名单：
echo "127.0.0.1/8"     | sudo tee /proc/firewall/whitelist
echo "10.0.0.0/8"      | sudo tee /proc/firewall/whitelist
echo "192.168.1.0/24"  | sudo tee /proc/firewall/whitelist
```

> **注意**：Firewall 不支持 IPv6 白名单（`::1` 等），当前仅支持 IPv4。

---

## 5. 功能对照表

| fail2ban 功能 | Firewall 对应 | 说明 |
|--------------|--------------|------|
| `jail.conf` / `jail.local` | `config/*.yaml` | 配置文件，YAML 格式 |
| `[DEFAULT]` 段 | `defaults:` 块 | 全局默认配置 |
| `[jail]` 段 | `<jail_name>:` 块 | Jail 定义 |
| `banaction = iptables` | 内核 Netfilter | 自动使用，无需配置 |
| `filter = sshd` | 智能推断（基于 jail 名称） | 自动匹配内置正则 |
| `failregex` | `regex:` | 自定义正则表达式 |
| `ignoreregex` | 不支持 | 可通过修改正则实现 |
| `findtime` | `findtime` | 相同，时间窗口（秒） |
| `maxretry` | `max_retries` | 名称不同，含义相同 |
| `bantime` | `ban_time` | 名称不同，含义相同 |
| `ignoreip` | `/proc/firewall/whitelist` | 白名单，独立管理 |
| `backend = polling/auto` | inotify（固定） | 事件驱动，性能更好 |
| `action` 系统 | 不适用 | Firewall 仅支持 Netfilter 封禁 |
| `recidive` jail | 不适用 | 可使用永久封禁替代 |
| `banip` / `unbanip` | `/proc/firewall/bans` | procfs 接口操作 |
| `fail2ban-client status` | `/proc/firewall/stats` + Prometheus | 统计信息 |
| `fail2ban-client reload` | `kill -HUP` | 配置热重载 |
| `/var/lib/fail2ban/` | `/var/lib/firewall/bans.db` | SQLite 持久化 |
| `fail2ban-server.log` | `journalctl -u firewall-daemon` + `dmesg` | 日志位置 |

---

## 6. 迁移后验证

### 6.1 检查模块加载

```bash
# 确认内核模块已加载
lsmod | grep firewall
# 预期输出：firewall <size> 0

# 查看模块参数
cat /sys/module/firewall/parameters/fw_ban_time
# 预期输出：600（默认值）
```

### 6.2 检查守护进程运行

```bash
# 检查 systemd 服务状态
sudo systemctl status firewall-daemon

# 检查 PID 文件
cat /run/firewall-daemon.pid

# 检查 Prometheus 端点
curl -s http://localhost:9119/health
# 预期输出：OK

curl -s http://localhost:9119/metrics | grep firewall_daemon_uptime
# 预期输出：firewall_daemon_uptime_seconds <数值>
```

### 6.3 测试封禁功能

**方法一：手动封禁测试**

```bash
# 封禁一个测试 IP
echo "192.0.2.1" | sudo tee /proc/firewall/bans

# 确认封禁已添加
cat /proc/firewall/bans

# 检查统计信息
cat /proc/firewall/stats
# 观察 current_bans 和 total_bans 是否增加

# 解封测试 IP
echo "unban 192.0.2.1" | sudo tee /proc/firewall/bans
```

**方法二：模拟日志攻击测试**

```bash
# 向 SSH 日志写入模拟的失败登录记录
sudo bash -c 'for i in $(seq 1 6); do
  echo "$(date) server sshd[$$]: Failed password for root from 192.0.2.100 port 22 ssh2" >> /var/log/auth.log
  sleep 1
done'

# 观察守护进程日志
sudo journalctl -u firewall-daemon -f

# 检查是否自动封禁
cat /proc/firewall/bans
```

### 6.4 监控日志

```bash
# 实时监控守护进程日志
sudo journalctl -u firewall-daemon -f

# 查看内核模块日志
dmesg -w | grep firewall

# 查看 Prometheus 指标
curl -s http://localhost:9119/metrics | grep -E "firewall_(kernel|daemon)"
```

**关键指标检查：**

| 指标 | 说明 | 正常值 |
|------|------|--------|
| `firewall_daemon_uptime_seconds` | 守护进程运行时间 | > 0 |
| `firewall_daemon_lines_parsed_total` | 已解析日志行数 | 持续增长 |
| `firewall_daemon_ips_banned_total` | 累计封禁 IP 数 | >= 0 |
| `firewall_kernel_banned_ips_current` | 当前活跃封禁数 | >= 0 |
| `firewall_kernel_packets_dropped` | 已丢弃数据包数 | >= 0 |

---

## 7. 回滚方案

### 7.1 恢复 fail2ban

如果 Firewall 出现问题，可以快速回滚到 fail2ban：

```bash
# 步骤 1：停止 Firewall
sudo systemctl stop firewall-daemon
sudo systemctl disable firewall-daemon

# 步骤 2：卸载内核模块
sudo rmmod firewall

# 步骤 3：启动 fail2ban
sudo systemctl start fail2ban
sudo systemctl enable fail2ban

# 步骤 4：确认 fail2ban 正常运行
sudo systemctl status fail2ban
sudo fail2ban-client status
```

### 7.2 卸载 Firewall

**使用 Makefile 卸载（推荐）：**

```bash
cd /root/firewall
sudo make uninstall
```

该命令会按顺序执行：
1. 停止守护进程
2. 安全卸载内核模块（检查使用情况）
3. 移除 systemd 服务
4. 删除模块自动加载配置
5. 删除二进制文件
6. 删除配置目录
7. 删除状态目录
8. 验证卸载结果

**手动卸载：**

```bash
# 停止服务
sudo systemctl stop firewall-daemon
sudo systemctl disable firewall-daemon

# 卸载内核模块
sudo rmmod firewall

# 删除 systemd 服务
sudo rm -f /etc/systemd/system/firewall-daemon.service
sudo systemctl daemon-reload

# 删除模块自动加载配置
sudo rm -f /etc/modules-load.d/firewall.conf

# 删除二进制文件
sudo rm -f /usr/local/sbin/firewall-daemon

# 删除内核模块文件
sudo rm -f /lib/modules/$(uname -r)/extra/firewall.ko
sudo depmod -a

# 删除配置和状态目录（谨慎操作，会丢失数据）
sudo rm -rf /etc/firewall
sudo rm -rf /var/lib/firewall
```

### 7.3 回滚后验证

```bash
# 确认 Firewall 已完全移除
lsmod | grep firewall          # 应无输出
ls /proc/firewall/             # 应报错 "No such file or directory"
which firewall-daemon          # 应无输出或报错

# 确认 fail2ban 正常运行
sudo fail2ban-client status
sudo iptables -L -n | grep fail2ban
```

---

## 附录

### A. 预设服务模板

Firewall 提供 12 个预设服务模板，安装后位于 `/etc/firewall/`：

| 文件 | Jail 名称 | 服务类型 | 默认日志路径 |
|------|-----------|---------|-------------|
| `default.yaml` | sshd | SSH | `/var/log/auth.log` |
| `nginx.yaml` | nginx | Web 服务器 | `/var/log/nginx/error.log` |
| `apache.yaml` | apache | Web 服务器 | `/var/log/apache2/error.log` |
| `dovecot.yaml` | dovecot | 邮件服务 | `/var/log/mail.log` |
| `postfix.yaml` | postfix | 邮件服务 | `/var/log/mail.log` |
| `mysql.yaml` | mysql | 数据库 | `/var/log/mysql/error.log` |
| `vsftpd.yaml` | vsftpd | FTP 服务 | `/var/log/vsftpd.log` |
| `wordpress.yaml` | wordpress | Web 应用 | `/var/log/nginx/error.log` |
| `redis.yaml` | redis | 数据库 | `/var/log/redis/redis-server.log` |
| `docker.yaml` | docker | 容器平台 | `/var/log/docker.log` |
| `traefik.yaml` | traefik | 反向代理 | `/var/log/traefik/traefik.log` |
| `frp.yaml` | frp | 内网穿透 | `/var/log/frp/frp.log` |

### B. 常用命令速查

| 操作 | fail2ban 命令 | Firewall 命令 |
|------|--------------|--------------|
| 启动服务 | `sudo systemctl start fail2ban` | `sudo systemctl start firewall-daemon` |
| 停止服务 | `sudo systemctl stop fail2ban` | `sudo systemctl stop firewall-daemon` |
| 查看状态 | `sudo fail2ban-client status` | `cat /proc/firewall/stats` |
| 封禁 IP | `sudo fail2ban-client set <jail> banip <ip>` | `echo "<ip>" \| sudo tee /proc/firewall/bans` |
| 解封 IP | `sudo fail2ban-client set <jail> unbanip <ip>` | `echo "unban <ip>" \| sudo tee /proc/firewall/bans` |
| 重载配置 | `sudo fail2ban-client reload` | `sudo kill -HUP $(cat /run/firewall-daemon.pid)` |
| 查看日志 | `sudo tail -f /var/log/fail2ban.log` | `sudo journalctl -u firewall-daemon -f` |

### C. 相关文档

- [配置指南](../user-guide/configuration.md) — YAML 配置格式、参数详解、热重载
- [运维操作手册](../user-guide/operations.md) — 安装部署、procfs 接口、故障排查
- [架构设计文档](../developer/architecture.md) — 内核模块设计、守护进程设计
- [永久封禁指南](../user-guide/permanent-ban.md) — SQLite 持久化、数据库维护
- [常见问题解答](../user-guide/faq.md) — 常见问题与解决方案
