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
systemctl status firewall-daemon --no-pager
echo ""

# 3. ProcFS
echo "3. ProcFS"
cat /proc/firewall/config
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
journalctl -u firewall-daemon -n 50

# 验证配置文件语法
sudo firewall-daemon -c /etc/firewall/default.yaml
# 或用 yamllint
yamllint /etc/firewall/

# 检查端口占用
ss -tlnp | grep 9119

# 检查依赖库
ldd /usr/local/sbin/firewall-daemon
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
cat /proc/firewall/bans

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
# 重新编译并加载带 DL=2 的模块
make clean && make debug DL=2
sudo rmmod firewall 2>/dev/null
sudo modprobe firewall fw_ban_time=600
# 同时编辑 /etc/firewall/default.yaml 的 global.log_level: debug
sudo systemctl restart firewall-daemon

# 2. 查看匹配日志
tail -f /var/log/firewall.log | grep "match"

# 3. 测试正则
echo "Failed password for root from 192.168.1.100" | \
    grep -P 'Failed password for (?:invalid user )?.+ from \d+\.\d+\.\d+\.\d+'
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 正则语法错误 | 使用在线工具测试正则 |
| `<HOST>` 未替换 | 检查配置中的拼写 |
| 日志格式变化 | 更新正则表达式 |
| inotify 未触发 | 检查文件权限和轮转 |

### 性能问题

**症状**：网络延迟增加或 CPU 使用率高。

**排查步骤**：

```bash
# 1. 检查封禁数量
cat /proc/firewall/stats

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
journalctl -u firewall-daemon | grep -i "restore\|recover"
```

**常见原因**：

| 原因 | 解决方案 |
|------|----------|
| 数据库路径错误 | 检查 `db_path` 配置 |
| 数据库权限 | `chmod 644 /var/lib/firewall/bans.db` |
| SQLite 损坏 | 备份并重建数据库 |

### 永久黑名单 SQLite 不创建

**症状**：

- 守护进程运行但 `/var/lib/firewall/bans.db` 不存在
- prometheus `firewall_daemon_*` 指标工作正常
- `journalctl -u firewall-daemon` 没有 "SQLite database initialized" 日志

**诊断**：

1. 查 `cfg.permanent_ban_enabled` 的实际值(daemon 启动时若为 `false` 就不会初始化 SQLite)。
2. 查 `/etc/firewall/default.yaml` 中 `permanent_ban_enabled` 和 `permanent_db_path` 的位置。
3. 如果这俩字段在顶层(在 `jails:` 之后),Rust parser 静默忽略 — 整个 `defaults:` 块以外的字段都不会进入 `Config` 结构体。

**修复**：

```yaml
# 错误 (字段在顶层,被静默忽略):
jails:
  sshd: ...
permanent_ban_enabled: true        # ← 顶层,parser 看不到
permanent_db_path: "/var/lib/firewall/bans.db"

# 正确 (字段必须在 defaults: 内):
defaults:
  ...
  permanent_ban_enabled: true      # ← defaults: 内部
  permanent_db_path: "/var/lib/firewall/bans.db"
jails:
  sshd: ...
```

### 守护进程无法打开 /var/log/firewall.log

**症状**：启动时日志出现：

```
WARN  Failed to open log file /var/log/firewall.log: Read-only file system (os error 30) (falling back to syslog-only)
```

**原因**：systemd 单元的 `ProtectSystem=strict` 让 `/var/log` 在 daemon 视角下是只读。`/var/log` 属 `system` 命名空间,daemon 没有写权限。

**修复(不推荐)**：修改 systemd 单元加 `ReadWritePaths=/var/log`:

```bash
sudo systemctl edit firewall-daemon
# 写入:
# [Service]
# ReadWritePaths=/var/log
```

但这是设计上的"安全默认值" — daemon 不应该有写任意位置的权限,日志落 syslog-only 是合理选择。`journalctl -u firewall-daemon` 仍能查看全部日志。

**替代方案**：把 `log_file` 路径改成 `/var/log/firewall/` 子目录,然后编辑 systemd 单元加 `ReadWritePaths=/var/log/firewall`(只对该子目录放权,比全开 `/var/log` 收敛得多):

```yaml
# /etc/firewall/default.yaml
log_file: /var/log/firewall/firewall.log
```

```bash
sudo mkdir -p /var/log/firewall
sudo chown root:root /var/log/firewall
sudo chmod 755 /var/log/firewall
sudo systemctl edit firewall-daemon
# [Service]
# ReadWritePaths=/var/lib/firewall /var/log/firewall
sudo systemctl restart firewall-daemon
```

### 测试报 "bans.db 未找到"

**症状**：`make test` 跑 `tests/suites/12_permanent_ban.sh` 时部分 case 失败,提示 "bans.db not found" 或 "no such file or directory"。

**原因**：与 [永久黑名单 SQLite 不创建](#永久黑名单-sqlite-不创建) 同根因 — `permanent_ban_enabled: true` 没写在 `defaults:` 内,daemon 跳过了 SQLite 初始化。

**修复**：把 `permanent_ban_enabled` 和 `permanent_db_path` 移到 `defaults:` 块内,然后:

```bash
sudo systemctl restart firewall-daemon
ls -la /var/lib/firewall/bans.db   # 应该存在了
make test
```

### `make deb` 报 "没有规则可制作目标"

**症状**：

```
make: *** 没有规则可制作目标 'deb'。 停止。
```

**原因**：旧版 Makefile(v2.2.0 之前)没有 `deb:` 规则。v2.2.1 起已修复(`make help` 也列了 `deb`)。

**修复**：

- 升级到 v2.2.1+:
  ```bash
  git pull origin main
  make deb
  ```
- 或直接用 `./build-deb.sh`(不走 `make`):
  ```bash
  ./build-deb.sh
  ```

### `cargo: not found` 在 sudo 下

**症状**：`sudo ./tests/run_tests.sh` 报：

```
make: cargo: 没有那个文件或目录
make: *** [Makefile:100: daemon] 错误 127
```

**原因**：`sudo` 默认 `secure_path` 不含 `~/.cargo/bin`,而 rustup 装在 `~/.cargo/bin/cargo`。

**修复**：

- 先 `source ~/.cargo/env` 再 sudo:
  ```bash
  source ~/.cargo/env
  sudo -E ./tests/run_tests.sh
  ```
- 或 `sudo -E` 保留当前 PATH(同样需要先 source):
  ```bash
  source ~/.cargo/env
  sudo -E make test
  ```
- v2.2.1 起 `tests/run_tests.sh` 已自动 source `~/.cargo/env`(见 `tests/run_tests.sh:134-139`),所以重跑应该 OK。

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
journalctl -u firewall-daemon --since "1 day ago" > firewall-diag-journal.txt
dmesg | grep -i firewall > firewall-diag-dmesg.txt
cat /proc/firewall/bans /proc/firewall/whitelist /proc/firewall/config /proc/firewall/stats \
    > firewall-diag-procfs.txt
echo "# Captured $(date)" > firewall-diag-$(date +%Y%m%d).txt
cat firewall-diag-journal.txt firewall-diag-dmesg.txt firewall-diag-procfs.txt \
    >> firewall-diag-$(date +%Y%m%d).txt
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