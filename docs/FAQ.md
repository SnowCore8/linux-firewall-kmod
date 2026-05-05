# 常见问题解答 (FAQ)

**版本**: v2.0
**最后更新**: 2026-05-05

---

## 一般问题

### 什么是 Firewall？

Firewall 是一个 **Linux 内核模块版本的 fail2ban**，将 IP 封禁逻辑从用户空间移至内核空间。它使用 Netfilter 钩子在数据包级别进行实时 IP 封禁，具有比传统 fail2ban 更低的延迟和更高的性能。

核心架构为**双层设计**：
- **内核态模块**（C 语言）：通过 Netfilter `NF_INET_PRE_ROUTING` 钩子执行数据包过滤，使用哈希表实现 O(1) 查找
- **用户态守护进程**（C 语言）：通过 inotify 监控日志文件，使用 PCRE2 进行正则解析，通过 procfs 接口与内核模块通信

### 与 fail2ban 有什么区别？

| 对比项 | fail2ban | Firewall |
|--------|----------|----------|
| 封禁位置 | iptables/nftables（用户态规则） | Netfilter 内核钩子 |
| 响应延迟 | 秒级 | 毫秒级 |
| 编程语言 | Python | C（内核模块 + 守护进程） |
| 查找性能 | 线性遍历规则 | 哈希表 O(1) 查找 |
| 配置格式 | INI | YAML |
| 配置校验 | 宽松模式 | 严格模式（默认） |
| 持久化 | 文件系统 | SQLite 数据库 |
| 封禁容量 | 无硬性限制 | 1024 IP |
| 监控指标 | 无内置 | Prometheus 导出（端口 9119） |

> 详细对比请参考 [从 fail2ban 迁移指南](MIGRATION.md)。

### 这个项目适合什么场景？

| 推荐场景 | 不推荐场景 |
|----------|-----------|
| 个人 VPS / 云服务器防护 | 生产环境 DDoS 防护 |
| SSH 暴力破解防护 | 需要审计合规的企业环境 |
| 开发 / 测试环境 | 大规模分布式部署 |
| Web 服务（Nginx/Apache）防护 | 需要 IPv6 支持的环境 |
| 数据库（MySQL/Redis）防护 | 封禁 IP 数量超过 1024 的场景 |

### 支持 IPv6 吗？

**不支持。** 当前版本仅支持 IPv4 地址封禁和白名单管理。IPv6 支持已在规划中，请关注后续版本更新。

---

## 安装与配置

### 需要什么系统要求？

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux |
| 内核版本 | 5.15+ |
| CPU 架构 | x86_64 |
| 权限 | root（加载内核模块和管理 procfs） |
| 磁盘空间 | 约 5MB（含编译产物） |
| 内存 | 约 10MB（内核模块 + 守护进程） |

### 如何安装依赖？

**Debian / Ubuntu：**

```bash
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev
```

**RHEL / CentOS / AlmaLinux：**

```bash
sudo dnf install -y gcc make kernel-devel kernel-headers \
  libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel
```

> 如果包管理器中没有 `libmicrohttpd-dev` 或 `libpcre2-dev`，可能需要启用 EPEL 源或从源码编译。

### 配置文件在哪里？

| 位置 | 说明 |
|------|------|
| `config/` | 项目内置配置模板（12 个预设服务） |
| `/etc/firewall/` | 生产环境配置目录（安装后） |

安装后所有配置文件会复制到 `/etc/firewall/`：

```bash
ls /etc/firewall/
# default.yaml  nginx.yaml  apache.yaml  mysql.yaml  ...
```

### 如何添加自定义服务防护？

在 `/etc/firewall/` 目录下创建新的 YAML 配置文件，例如 `myapp.yaml`：

```yaml
myapp:
  enabled: true
  log_files:
    - /var/log/myapp/access.log
  max_retries: 3
  findtime: 300
  ban_time: 1800
  regex: "Authentication failure.*from\s+<IP>"
```

> **注意**：正则表达式必须包含 `<IP>` 占位符用于 IP 提取。

然后通过配置热重载生效：

```bash
sudo kill -HUP $(cat /run/firewall-daemon.pid)
```

或重启服务：

```bash
sudo systemctl restart firewall-daemon
```

---

## 运行与使用

### 如何查看当前封禁的 IP？

**方法一：通过 procfs 接口**

```bash
cat /proc/firewall/bans
```

输出示例：
```
192.168.1.100    expires: 2026-05-05 12:30:00    permanent: no
10.0.0.50        expires: permanent              permanent: yes
```

**方法二：通过 Prometheus 指标**

```bash
curl -s http://localhost:9119/metrics | grep firewall_kernel_banned_ips_current
# firewall_kernel_banned_ips_current 15
```

**方法三：通过统计信息**

```bash
cat /proc/firewall/stats
```

### 如何手动封禁/解封 IP？

**封禁 IP（使用默认时长）：**

```bash
echo "1.2.3.4" | sudo tee /proc/firewall/bans
```

**封禁 IP（自定义时长，单位：秒）：**

```bash
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans  # 封禁 1 小时
```

**永久封禁 IP：**

```bash
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans
```

> 永久封禁会保存到 SQLite 数据库（需启用 `permanent_ban_enabled`），重启后不丢失。

**解封 IP：**

```bash
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
```

### 如何白名单某个 IP/子网？

**添加白名单：**

```bash
# 单个 IP
echo "192.168.1.1/32" | sudo tee /proc/firewall/whitelist

# 整个子网
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist
echo "172.16.0.0/12" | sudo tee /proc/firewall/whitelist
```

**查看白名单：**

```bash
cat /proc/firewall/whitelist
```

**移除白名单：**

```bash
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

> 白名单上限为 64 个条目。系统 IP 会自动发现并加入白名单，防止误封本机地址。

### 封禁上限是多少？满了怎么办？

| 项目 | 上限 |
|------|------|
| 封禁 IP | 1024 个 |
| 白名单条目 | 64 个 |

**封禁表满时的行为：**
- 新的封禁请求会被**拒绝**，内核模块返回错误
- 守护进程日志中会记录 `ban table full` 警告

**解决方法：**

1. **等待过期封禁自动清理**：内核定时器定期清理过期条目
2. **手动解封不需要的 IP**：
   ```bash
   echo "unban <old_ip>" | sudo tee /proc/firewall/bans
   ```
3. **缩短封禁时长**：在配置中减小 `ban_time` 值，让封禁更快过期
4. **使用永久封禁筛选**：只将确认的攻击者设为永久封禁（`ban_time: 0`）

---

## 故障排查

### 模块加载失败怎么办？

**步骤 1：检查内核版本**

```bash
uname -r
# 需要 5.15+ 内核
```

**步骤 2：检查内核头文件是否安装**

```bash
ls /lib/modules/$(uname -r)/build/Makefile
# 如果不存在，需要安装对应版本的内核头文件
```

**步骤 3：查看内核日志**

```bash
dmesg | tail -20
dmesg | grep firewall
```

**步骤 4：检查模块信息**

```bash
modinfo build/kernel-module/firewall.ko
```

**步骤 5：手动加载并观察错误**

```bash
sudo insmod build/kernel-module/firewall.ko
# 观察错误输出
```

**常见问题：**
- `Invalid module format`：内核版本与编译环境不匹配，需要重新编译
- `Unknown symbol`：内核 API 变更，需要适配当前内核版本

### 守护进程启动失败怎么办？

**步骤 1：检查配置文件语法**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml --strict
# 观察配置解析错误输出
```

**步骤 2：检查 systemd 日志**

```bash
sudo journalctl -u firewall-daemon -n 50 --no-pager
```

**步骤 3：检查端口占用**

```bash
sudo ss -tlnp | grep 9119
# 如果端口被占用，修改配置中的 metrics_port
```

**步骤 4：检查内核模块是否加载**

```bash
lsmod | grep firewall
# 如果未加载，先加载模块：
sudo insmod build/kernel-module/firewall.ko
```

**步骤 5：前台模式调试**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
# 前台运行，输出详细日志
```

### 封禁不生效怎么办？

**步骤 1：确认内核模块已加载**

```bash
lsmod | grep firewall
```

**步骤 2：确认 procfs 接口存在**

```bash
ls -la /proc/firewall/
# 应包含 bans, whitelist, config, stats
```

**步骤 3：手动测试封禁**

```bash
echo "1.2.3.4" | sudo tee /proc/firewall/bans
cat /proc/firewall/bans  # 确认封禁已添加
```

**步骤 4：检查统计信息**

```bash
cat /proc/firewall/stats
```

关注 `packets_dropped` 计数器是否在增长：
- 如果 `packets_dropped` 不变，说明封禁的数据包没有到达内核模块
- 如果 `packets_dropped` 增长，说明封禁正在工作

**步骤 5：检查内核日志**

```bash
dmesg | grep firewall
```

**步骤 6：确认 IP 不在白名单中**

```bash
cat /proc/firewall/whitelist
# 如果目标 IP 在白名单中，封禁不会生效
```

### 如何查看日志？

**内核模块日志：**

```bash
# 实时查看
dmesg -w | grep firewall

# 查看最近 100 条
dmesg | grep firewall | tail -100
```

**守护进程日志（systemd）：**

```bash
# 实时跟踪
sudo journalctl -u firewall-daemon -f

# 查看最近 100 条
sudo journalctl -u firewall-daemon -n 100 --no-pager

# 查看今天的日志
sudo journalctl -u firewall-daemon --since today
```

**守护进程日志（前台模式）：**

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml -f -v
```

> 使用 `-v`（verbose）参数可以输出更详细的调试信息。

---

## 性能与限制

### 性能如何？比 fail2ban 快多少？

| 操作 | Firewall | fail2ban | 说明 |
|------|----------|----------|------|
| 封禁查找 | <1 μs | ~10-100 μs | O(1) 哈希 vs 线性遍历 |
| 数据包过滤 | <0.5 μs | ~1-5 ms | 内核 Netfilter vs iptables 用户态规则 |
| 封禁响应 | 毫秒级 | 秒级 | 直接内核写入 vs 调用 iptables 命令 |
| 日志解析 | ~10 μs | ~50-100 μs | PCRE2 JIT vs Python re |
| 失败追踪 | <1 μs | ~5-10 μs | khash O(1) vs Python 字典 |
| 内存占用 | ~10 MB | ~50-100 MB | 轻量 C vs Python 运行时 |

**总结**：在封禁响应速度和资源占用方面，Firewall 比 fail2ban 快 **1-2 个数量级**。

### 有什么已知限制？

| 限制 | 说明 | 影响 |
|------|------|------|
| 封禁容量 | 最多 1024 个 IP | 大规模攻击场景可能不够用 |
| 白名单容量 | 最多 64 个条目 | 大型网络需要合理规划子网 |
| IPv6 支持 | 仅支持 IPv4 | 纯 IPv6 环境无法使用 |
| 分片包处理 | 无法检查分片包内容 | 分片包会被直接放行 |
| 内核版本 | 需要 5.15+ | 旧内核（如 CentOS 7 的 3.10）不兼容 |
| 配置热重载 | 需要 SIGHUP 信号 | 部分配置变更需要重启 |
| 日志格式 | 依赖正则匹配 | 非标准日志格式需要自定义正则 |

### 能用于生产环境吗？

**可以，但需要评估以下因素：**

**适合生产环境的场景：**
- 个人 VPS / 小型服务器防护
- SSH 暴力破解防护
- Web 服务基础防护
- 封禁 IP 数量 < 1024 的场景

**需要谨慎评估的场景：**
- 大规模 DDoS 防护（建议使用专业硬件防火墙）
- 需要审计合规的企业环境（需额外日志记录方案）
- 纯 IPv6 网络（当前不支持）
- 封禁 IP 数量超过 1024 的高流量场景

**生产环境建议：**
1. 启用永久封禁功能（`permanent_ban_enabled: true`）
2. 配置 Prometheus 监控和告警
3. 定期备份 SQLite 数据库
4. 使用 systemd 服务管理（含安全加固）
5. 保留 fail2ban 作为临时回滚方案

---

## 迁移

### 如何从 fail2ban 迁移？

请参考 [从 fail2ban 迁移指南](MIGRATION.md)，包含完整的迁移步骤。

**快速迁移步骤概览：**

1. **停止 fail2ban**：
   ```bash
   sudo systemctl stop fail2ban
   sudo systemctl disable fail2ban
   ```

2. **备份配置**：
   ```bash
   sudo cp -r /etc/fail2ban /etc/fail2ban.backup
   ```

3. **安装 Firewall**：
   ```bash
   make && sudo make install
   ```

4. **迁移配置**：将 fail2ban 的 jail 配置转换为 YAML 格式（参考迁移指南）

5. **启动 Firewall**：
   ```bash
   sudo systemctl start firewall-daemon
   ```

### 可以和 fail2ban 同时运行吗？

**不建议同时运行。** 原因如下：

| 问题 | 说明 |
|------|------|
| 端口冲突 | 两者可能监控相同的日志文件，导致重复封禁 |
| 规则冲突 | fail2ban 使用 iptables，Firewall 使用 Netfilter 钩子，可能产生冲突 |
| 资源浪费 | 双重监控同一日志文件，浪费系统资源 |
| 管理混乱 | 封禁来源不明确，故障排查困难 |

**推荐做法：**
1. 完全停止并禁用 fail2ban
2. 迁移配置到 Firewall
3. 验证 Firewall 工作正常
4. 保留 fail2ban 作为回滚方案（不启动）

如果确实需要过渡期共存，请确保：
- fail2ban 和 Firewall 监控**不同的日志文件**
- fail2ban 使用不同的封禁链（自定义 iptables chain）
- 密切监控两者是否产生冲突
