# Firewall 运维操作手册

**版本**: v1.9  
**最后更新**: 2026-05-04

---

## 1. 安装部署

### 1.1 系统依赖

```bash
# Debian/Ubuntu
sudo apt install -y build-essential linux-headers-$(uname -r) libyaml-dev libsqlite3-dev libmicrohttpd-dev libpcre2-dev
# RHEL/CentOS/Rocky
sudo yum install -y gcc make kernel-devel kernel-headers libyaml-devel sqlite-devel libmicrohttpd-devel pcre2-devel
```

### 1.2 编译安装

```bash
make all-with-daemon    # 编译内核模块 + 守护进程
sudo make install       # 安装到系统
```

安装路径：内核模块 → `/lib/modules/$(uname -r)/extra/firewall.ko`，守护进程 → `/usr/local/sbin/firewall-daemon`，配置 → `/etc/firewall/`，状态目录 → `/var/lib/firewall/`，systemd 服务 → `/etc/systemd/system/firewall-daemon.service`。

### 1.3 手动安装

```bash
sudo cp build/kernel-module/firewall.ko /lib/modules/$(uname -r)/extra/ && sudo depmod -a
sudo cp build/daemon/firewall-daemon /usr/local/sbin/
sudo install -d -m 755 /etc/firewall && sudo install -m 644 config/*.yaml /etc/firewall/
sudo install -d -m 750 /var/lib/firewall
sudo install -D -m 644 firewall-daemon.service /etc/systemd/system/firewall-daemon.service && sudo systemctl daemon-reload
```

---

## 2. 日常操作

### 2.1 服务管理

```bash
sudo systemctl start firewall-daemon      # 启动
sudo systemctl stop firewall-daemon       # 停止
sudo systemctl restart firewall-daemon    # 重启
sudo systemctl status firewall-daemon     # 状态
sudo systemctl enable firewall-daemon     # 开机自启
sudo systemctl reload firewall-daemon     # 热重载配置（SIGHUP）
```

### 2.2 封禁/解封与白名单

```bash
cat /proc/firewall/bans                              # 查看封禁列表
echo "1.2.3.4" | sudo tee /proc/firewall/bans        # 默认时长封禁
echo "1.2.3.4 3600" | sudo tee /proc/firewall/bans   # 自定义时长（秒）
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans      # 永久封禁
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans  # 解封
cat /proc/firewall/whitelist                         # 查看白名单
echo "10.0.0.0/8" | sudo tee /proc/firewall/whitelist           # 添加白名单
echo "add 192.168.1.0/24" | sudo tee /proc/firewall/whitelist   # 添加（显式）
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist    # 移除白名单
```

---

## 3. procfs 接口完整参考

所有接口需要 `CAP_NET_ADMIN` 权限（通过 `sudo` 获取）。

### 3.1 /proc/firewall/bans（读写）

| 操作 | 格式 | 示例 |
|------|------|------|
| 读取 | `cat` | `cat /proc/firewall/bans` |
| 默认封禁 | `IP` | `echo "1.2.3.4" \| sudo tee /proc/firewall/bans` |
| 自定义时长 | `IP seconds` | `echo "1.2.3.4 7200" \| sudo tee /proc/firewall/bans` |
| 永久封禁 | `IP 0` | `echo "1.2.3.4 0" \| sudo tee /proc/firewall/bans` |
| 解封 | `unban IP` | `echo "unban 1.2.3.4" \| sudo tee /proc/firewall/bans` |

**限制**：封禁上限 1024 IP，ban_time 范围 30 秒 ~ 31,536,000 秒（1 年）。

### 3.2 /proc/firewall/whitelist（读写）

| 操作 | 格式 | 示例 |
|------|------|------|
| 读取 | `cat` | `cat /proc/firewall/whitelist` |
| 添加 | `CIDR` 或 `add CIDR` | `echo "10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |
| 移除 | `remove CIDR` | `echo "remove 10.0.0.0/8" \| sudo tee /proc/firewall/whitelist` |

**限制**：白名单上限 64 条目，支持 CIDR 格式。

### 3.3 /proc/firewall/config（读写）

```bash
cat /proc/firewall/config                              # 查看当前配置
echo "ban_time 1200" | sudo tee /proc/firewall/config  # 修改 ban_time
```

目前仅支持运行时修改 `ban_time` 参数。

### 3.4 /proc/firewall/stats（只读）

```bash
cat /proc/firewall/stats   # 输出：总封禁数、总解封数、当前活跃封禁数、白名单条目数
```

---

## 4. 内核模块管理

### 4.1 加载与卸载

```bash
sudo insmod build/kernel-module/firewall.ko fw_ban_time=600   # 加载
sudo systemctl stop firewall-daemon && sudo rmmod firewall    # 卸载
```

### 4.2 模块参数与状态检查

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `fw_ban_time` | 默认封禁时长（秒） | 600 |

```bash
cat /sys/module/firewall/parameters/fw_ban_time           # 查看参数
echo 900 | sudo tee /sys/module/firewall/parameters/fw_ban_time  # 运行时修改
lsmod | grep firewall          # 检查是否加载
modinfo firewall               # 查看模块信息
ls -la /proc/firewall/         # 检查 procfs 是否就绪
```

---

## 5. 日志与监控

### 5.1 日志查看

```bash
dmesg | grep firewall          # 内核日志
dmesg -w | grep firewall       # 实时跟踪
sudo journalctl -u firewall-daemon      # 守护进程日志
sudo journalctl -u firewall-daemon -f   # 实时跟踪
grep firewall /var/log/syslog           # syslog 查看
```

### 5.2 Prometheus 指标

```bash
curl http://localhost:9119/metrics   # 指标端点
curl http://localhost:9119/health    # 健康检查
```

| 指标 | 说明 |
|------|------|
| `firewall_bans_total` | 累计封禁次数 |
| `firewall_unbans_total` | 累计解封次数 |
| `firewall_active_bans` | 当前活跃封禁数 |
| `firewall_whitelist_entries` | 白名单条目数 |
| `firewall_parse_errors_total` | 日志解析错误数 |
| `firewall_jail_events_total` | 各 Jail 触发事件数 |

---

## 6. 故障排查

### 6.1 模块加载失败

```bash
ls /lib/modules/$(uname -r)/build        # 检查内核 headers
mokutil --sb-state                       # 检查 Secure Boot
sudo insmod build/kernel-module/firewall.ko && dmesg | tail -20
```

**解决**：安装对应版本 `linux-headers`，或禁用 Secure Boot。

### 6.2 守护进程无法启动

```bash
ldd /usr/local/sbin/firewall-daemon          # 检查依赖库
sudo ss -tlnp | grep 9119                    # 检查端口占用
sudo journalctl -u firewall-daemon -n 50     # 查看最近日志
```

**解决**：安装缺失依赖（libyaml、libsqlite3、libmicrohttpd、libpcre2）。

### 6.3 封禁不生效

```bash
lsmod | grep firewall                        # 检查模块加载
cat /proc/firewall/whitelist                 # 检查是否在白名单
dmesg | grep firewall | tail -20             # 查看内核日志
```

### 6.4 配置文件语法错误

```bash
python3 -c "import yaml; yaml.safe_load(open('/etc/firewall/default.yaml'))"
```

**常见错误**：缩进不一致、缺少冒号、非法字符。

### 6.5 日志解析失败

```bash
ls -la /var/log/auth.log                     # 检查日志文件存在
sudo journalctl -u firewall-daemon | grep -i parse  # 查看解析错误
```

---

## 7. 调试模式

### 7.1 内核模块调试

```bash
make kernel-module DEBUG_LEVEL=0   # 生产环境（关闭调试）
make debug1                        # 少量调试
make debug2                        # 中等调试
make debug3                        # 详细调试
```

DEBUG_LEVEL 范围 0-4，加载后通过 `dmesg -w | grep firewall` 查看输出。

### 7.2 守护进程调试与 ASAN

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml   # 前台运行
make asan    # ASAN 内存检测
ASAN_OPTIONS=detect_leaks=1 sudo ./build/daemon/firewall-daemon-asan -c config/default.yaml
```

---

## 8. 性能调优

### 8.1 基准测试数据

| 操作 | 吞吐量 |
|------|--------|
| 封禁操作 | ~840 ops/ms |
| 查询操作 | ~885 ops/ms |
| 解封操作 | ~1235 ops/ms |
| 白名单添加 | ~1220 ops/ms |
| 白名单查询 | ~1227 ops/ms |

> 注：v1.7 安全加固后性能约下降 1-2%（溢出检查开销）。

### 8.2 调优建议

- **ban_time**：推荐 600-3600 秒，避免过短导致频繁过期清理
- **max_retries**：sshd 推荐 5 次，公开服务可降至 3 次
- **findtime**：推荐 300-600 秒，与 max_retries 配合使用
- **SQLite 维护**：定期检查数据库大小，必要时执行 `VACUUM`

### 8.3 监控告警阈值

| 指标 | 警告 | 严重 |
|------|------|------|
| `active_bans` | > 800 | > 1000 |
| `parse_errors_total`（每分钟） | > 10 | > 50 |
| 守护进程 CPU 使用率 | > 30% | > 60% |
| SQLite 数据库大小 | > 100MB | > 500MB |
