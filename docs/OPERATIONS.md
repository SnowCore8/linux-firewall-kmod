# Firewall 运维操作手册

**版本**: v2.1  
**最后更新**: 2026-05-06

## 1. 安装部署

### 1.1 系统要求

| 项目 | 要求 |
|------|------|
| 操作系统 | Linux (内核 5.15+) |
| 架构 | x86_64 |
| 依赖 | libyaml, libsqlite3, libmicrohttpd, libpcre2-8 |
| 权限 | root (加载内核模块) |

### 1.2 编译安装

```bash
# 安装依赖 (Debian/Ubuntu)
sudo apt install -y build-essential linux-headers-$(uname -r) \
  libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev

# 编译
make

# 安装
sudo make install
```

### 1.3 手动安装

```bash
# 1. 安装内核模块
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/extra/
sudo depmod -a
sudo modprobe firewall

# 2. 安装守护进程
sudo cp build/daemon/firewall-daemon /usr/local/sbin/

# 3. 安装配置
sudo mkdir -p /etc/firewall
sudo cp config/*.yaml /etc/firewall/

# 4. 安装 systemd 服务
sudo cp firewall-daemon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-daemon
```

## 2. procfs 接口

> **架构说明**：procfs 接口的内部实现和设计原理，请参考 [架构设计文档 → procfs 接口](ARCHITECTURE.md#35-procfs-接口)。

所有操作通过 `/proc/firewall/` 目录进行，需要 root 权限。

### 2.1 接口列表

| 路径 | 权限 | 功能 |
|------|------|------|
| `/proc/firewall/bans` | 0600 | 封禁列表管理 |
| `/proc/firewall/whitelist` | 0600 | 白名单管理 |
| `/proc/firewall/config` | 0600 | 运行时配置 |
| `/proc/firewall/stats` | 0400 | 统计信息 |

### 2.1.1 安全增强（v2.1）

**输入验证**：
- IP 地址长度验证：防止缓冲区溢出
- 输入长度检查：`count > sizeof(input) - 1` 拒绝超大输入
- 控制字符过滤：拒绝非 printable 字符（除空格和制表符）

**路径验证**：
- `O_NOFOLLOW` 标志：防止符号链接绕过
- `/proc/self/fd/` 验证：确认文件描述符指向 procfs 路径
- 字符白名单：仅允许字母、数字、`/`、`-`、`_`、`.`

### 2.2 封禁操作

| 操作 | 格式 | 示例 |
|------|------|------|
| 读取 | `cat` | `cat /proc/firewall/bans` |
| 默认封禁 | `IP` | `echo "1.2.3.4" \| sudo tee /proc/firewall/bans` |
| 自定义时长 | `IP seconds` | `echo "1.2.3.4 7200" \| sudo tee /proc/firewall/bans` |
| 永久封禁 | `IP 0` | `echo "1.2.3.4 0" \| sudo tee /proc/firewall/bans` |
| 解封 | `unban IP` | `echo "unban 1.2.3.4" \| sudo tee /proc/firewall/bans` |

**限制**：封禁上限 4096 IP，ban_time 范围 30 秒 ~ 31,536,000 秒（1 年）。

### 2.3 白名单操作

| 操作 | 格式 | 示例 |
|------|------|------|
| 读取 | `cat` | `cat /proc/firewall/whitelist` |
| 添加子网 | `subnet/prefix` | `echo "10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |
| 移除子网 | `remove subnet/prefix` | `echo "remove 10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |

**限制**：白名单上限 64 条目。

### 2.4 统计信息

```bash
cat /proc/firewall/stats
```

输出示例：
```
current_bans: 15
total_bans: 1234
total_unbans: 1200
packets_dropped: 56789
packets_accepted: 1234567
whitelist_entries: 5
```

## 3. 命令行参数

```bash
sudo ./build/daemon/firewall-daemon --help
```

选项：
| 选项 | 说明 |
|------|------|
| `-c, --config FILE` | 单个配置文件路径 |
| `-C, --config-dir DIR` | 配置目录（自动加载所有 .yaml/.yml 文件） |
| `-f, --foreground` | 前台运行（不守护进程化） |
| `-v, --verbose` | 详细日志输出 |
| `-s, --strict` | 启用严格配置校验（默认） |
| `-p, --permissive` | 允许未知参数并输出警告 |
| `-h, --help` | 显示帮助信息 |

## 4. systemd 服务管理

### 4.1 基本操作

```bash
# 启动服务
sudo systemctl start firewall-daemon

# 停止服务
sudo systemctl stop firewall-daemon

# 重启服务
sudo systemctl restart firewall-daemon

# 查看状态
sudo systemctl status firewall-daemon

# 查看日志
sudo journalctl -u firewall-daemon -f
```

### 4.2 开机自启

```bash
sudo systemctl enable firewall-daemon
```

### 4.3 服务加固

`firewall-daemon.service` 已包含以下安全加固：
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `NoNewPrivileges=yes`
- `PrivateTmp=yes`
- `CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH`

## 5. 监控与可观测性

### 5.1 日志

```bash
# 内核日志
dmesg | grep firewall

# 守护进程日志
sudo journalctl -u firewall-daemon -n 100
```

### 5.2 Prometheus 指标

```bash
curl http://localhost:9119/metrics   # 指标端点
curl http://localhost:9119/health    # 健康检查
curl http://localhost:9119/healthz   # 健康检查（K8s 兼容）
```

#### 内核模块指标（4 项）

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_kernel_banned_ips_current` | gauge | 当前活跃封禁数 |
| `firewall_kernel_total_bans_total` | counter | 累计封禁次数 |
| `firewall_kernel_total_unbans_total` | counter | 累计解封次数 |
| `firewall_kernel_whitelist_count` | gauge | 白名单条目数 |

#### 守护进程指标（10 项）

| 指标 | 类型 | 说明 |
|------|------|------|
| `firewall_daemon_lines_parsed_total` | counter | 解析的日志行总数 |
| `firewall_daemon_ips_extracted_total` | counter | 提取的 IP 地址总数 |
| `firewall_daemon_ips_banned_total` | counter | 封禁的 IP 总数 |
| `firewall_daemon_failed_attempts_total` | counter | 失败尝试总数 |
| `firewall_daemon_config_reloads_total` | counter | 配置重载次数 |
| `firewall_daemon_inotify_events_total` | counter | inotify 事件总数 |
| `firewall_daemon_log_rotations_total` | counter | 日志轮转检测次数 |
| `firewall_daemon_lines_skipped_total` | counter | 跳过的日志行总数 |
| `firewall_daemon_regex_matches_total` | counter | 正则匹配成功次数 |
| `firewall_daemon_uptime_seconds` | gauge | 守护进程运行时间（秒） |

### 5.3 Grafana 仪表板

Prometheus 配置示例：
```yaml
scrape_configs:
  - job_name: 'firewall'
    static_configs:
      - targets: ['localhost:9119']
```

## 6. 故障排查

### 6.1 模块加载失败

```bash
# 检查内核版本
uname -r

# 检查模块依赖
modinfo build/kernel-module/firewall.ko

# 查看内核日志
dmesg | tail -20
```

### 6.2 守护进程启动失败

```bash
# 检查配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml --strict

# 检查日志
sudo journalctl -u firewall-daemon -n 50 --no-pager

# 检查端口占用
sudo ss -tlnp | grep 9119
```

### 6.3 封禁不生效

```bash
# 检查模块是否加载
lsmod | grep firewall

# 检查 procfs 接口
cat /proc/firewall/bans

# 检查统计信息
cat /proc/firewall/stats

# 检查内核日志
dmesg | grep firewall
```

### 6.4 性能问题

```bash
# 查看封禁表使用率
cat /proc/firewall/stats | grep current_bans

# 查看 Prometheus 指标
curl -s http://localhost:9119/metrics | grep firewall

# 检查系统负载
top -p $(pgrep firewall-daemon)
```

## 7. 维护操作

### 7.1 配置热重载

```bash
# 修改配置后重载
sudo kill -HUP $(cat /run/firewall-daemon.pid)

# 或使用 systemctl
sudo systemctl reload firewall-daemon
```

### 7.2 状态保存/恢复

```bash
# 手动保存状态
echo "save /var/lib/firewall/state.bin" | sudo tee /proc/firewall/config

# 手动恢复状态
echo "restore /var/lib/firewall/state.bin" | sudo tee /proc/firewall/config
```

### 7.3 清理过期封禁

过期封禁由内核定时器自动清理，无需手动操作。

## 8. 已知限制

| 限制 | 说明 |
|------|------|
| 封禁容量 | 最多 4096 个 IP |
| 白名单容量 | 最多 64 个条目 |
| IPv6 支持 | 仅支持 IPv4 |
| 分片包 | 无法检查分片包内容，直接放行 |
| 内核版本 | 需要 5.15+ 内核 |

## 9. 性能基准

| 操作 | 延迟 | 说明 |
|------|------|------|
| 封禁查找 | <1μs | O(1) 哈希查找 |
| 数据包过滤 | <0.5μs | Netfilter 钩子 |
| 日志解析 | ~10μs | PCRE2 JIT 加速 |
| 失败追踪 | <1μs | khash O(1) 插入 |
