# 故障排查

本文档介绍 Linux Firewall 内核模块的常见问题和解决方案。

## 诊断工具

### 快速诊断脚本

```bash
#!/bin/bash
# firewall-diagnose.sh

echo "=== Linux Firewall Diagnosis ==="
echo ""

# 1. 内核模块
echo "1. Kernel Module"
echo "   Loaded: $(lsmod | grep -c firewall)"
lsmod | grep firewall
echo ""

# 2. 守护进程
echo "2. Daemon"
systemctl status firewall --no-pager
echo ""

# 3. ProcFS
echo "3. ProcFS"
cat /proc/firewall/status
echo ""

# 4. 封禁统计
echo "4. Statistics"
cat /proc/firewall/stats
echo ""

# 5. 内核日志
echo "5. Kernel Log (last 20 lines)"
dmesg | grep firewall | tail -20
echo ""

# 6. 守护进程日志
echo "6. Daemon Log (last 20 lines)"
tail -20 /var/log/firewall.log
echo ""

# 7. Prometheus
echo "7. Prometheus Metrics"
curl -s http://localhost:9119/metrics | head -20
```

## 常见问题

### 模块无法加载

**症状**：

```
modprobe: ERROR: could not insert 'firewall': Operation not permitted
```

**原因和解决方案**：

| 原因 | 解决方案 |
|------|----------|
| 不是 root 用户 | 使用 `sudo modprobe firewall` |
| Secure Boot 启用 | 签名模块或禁用 Secure Boot |
| 内核版本不匹配 | 重新编译：`make clean && make` |
| 缺少内核头文件 | 安装：`apt install linux-headers-$(uname -r)` |

### 守护进程无法启动

**症状**：

```
Job for firewall-daemon.service failed because the control process exited with error code.
```

**排查步骤**：

```bash
# 查看详细错误
journalctl -u firewall -n 50

# 检查配置文件
fwctl check-config

# 检查端口占用
ss -tlnp | grep 9119

# 检查依赖库
ldd /usr/local/sbin/fwctl
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 配置文件语法错误 | 修复 YAML 格式 |
| 端口被占用 | 修改配置或关闭占用进程 |
| 缺少依赖库 | 安装缺失的库 |
| 日志目录不存在 | `mkdir -p /var/lib/firewall` |
| 数据库目录权限 | `chown root:root /var/lib/firewall` |

### IP 未被封禁

**症状**：日志显示匹配成功，但 IP 仍可访问。

**排查步骤**：

```bash
# 1. 检查内核模块是否加载
lsmod | grep firewall

# 2. 检查 IP 是否在白名单
cat /proc/firewall/whitelist

# 3. 检查封禁是否成功写入
cat /proc/firewall/banned_ips

# 4. 检查内核日志
dmesg | grep firewall

# 5. 验证数据包是否经过 Hook
# 在模块中添加 pr_info 调试输出
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| IP 在白名单 | 从白名单移除该 IP |
| 模块未加载 | `sudo modprobe firewall` |
| 端口不匹配 | 检查 jail 的 port 配置 |
| 协议不匹配 | 检查 jail 的 protocol 配置 |
| 哈希表已满 | 清空过期封禁或增加容量 |

### 正则匹配失败

**症状**：日志中有匹配内容但未触发封禁。

**排查步骤**：

```bash
# 1. 启用调试模式
sudo systemctl stop firewall
sudo fwctl -d start

# 2. 查看匹配日志
tail -f /var/log/firewall.log | grep "match"

# 3. 测试正则
echo "Failed password for root from 192.168.1.100" | \
    grep -P 'Failed password for (?:invalid user )?.+ from \d+\.\d+\.\d+\.\d+'
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 正则语法错误 | 使用在线工具测试 PCRE2 |
| `<HOST>` 未替换 | 检查配置中的拼写 |
| 日志格式变化 | 更新正则表达式 |
| inotify 未触发 | 检查文件权限和轮转 |

### 性能问题

**症状**：网络延迟增加或 CPU 使用率高。

**排查步骤**：

```bash
# 1. 检查封禁数量
fwctl stats

# 2. 检查哈希表使用率
curl -s http://localhost:9119/metrics | grep hash_table

# 3. 检查数据包丢弃率
curl -s http://localhost:9119/metrics | grep dropped

# 4. 检查内核态 CPU 使用
top -b -n 1 | head -20
```

**优化建议**：

| 问题 | 解决方案 |
|------|----------|
| 封禁数过多 | 减少 `find_time` 或增加 `max_retries` |
| 日志文件过大 | 配置日志轮转 |
| 数据库膨胀 | 手动清理过期记录 |

### 日志文件监控失败

**症状**：inotify 事件丢失或未检测到新日志。

**排查步骤**：

```bash
# 检查 inotify 限制
cat /proc/sys/fs/inotify/max_user_watches
cat /proc/sys/fs/inotify/max_queued_events

# 增加限制
echo 524288 | sudo tee /proc/sys/fs/inotify/max_user_watches
```

**持久化配置**：

```
# /etc/sysctl.d/99-inotify.conf
fs.inotify.max_user_watches = 524288
fs.inotify.max_queued_events = 32768
```

### 封禁重启后丢失

**症状**：重启服务器后所有封禁记录丢失。

**排查步骤**：

```bash
# 检查 SQLite 数据库
ls -la /var/lib/firewall/bans.db

# 检查数据库内容
sqlite3 /var/lib/firewall/bans.db "SELECT COUNT(*) FROM bans;"

# 检查守护进程启动日志
journalctl -u firewall | grep -i "restore\|recover"
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 数据库路径错误 | 检查 `db_path` 配置 |
| 数据库权限 | `chmod 644 /var/lib/firewall/bans.db` |
| SQLite 损坏 | 备份并重建数据库 |

## 内核调试

### 启用调试输出

```bash
# 编译调试版本
make debug DL=2

# 重新安装
sudo make install
sudo modprobe -r firewall
sudo modprobe firewall

# 查看内核日志
dmesg -w | grep firewall
```

### 调试级别

```bash
# 在代码中修改
#define DEBUG_LEVEL 2  # 0=关闭, 1=基本, 2=详细, 3=全部
```

### RCU 调试

```bash
# 检查 RCU 状态
cat /sys/kernel/debug/rcu/rcudata

# 检查 RCU 回调
cat /sys/kernel/debug/rcu/rcu_pending
```

## 获取帮助

### 收集诊断信息

```bash
# 收集完整诊断包
sudo fwctl diagnose > firewall-diag-$(date +%Y%m%d).txt
```

### 报告问题

在 GitHub 提交 Issue 时请包含：

1. 诊断信息输出
2. 配置文件（脱敏后）
3. 内核版本：`uname -r`
4. 发行版：`cat /etc/os-release`
5. 复现步骤

### 社区支持

- GitHub Issues: https://github.com/SnowCore8/linux-firewall-kmod/issues
- 文档: 本 GitBook