# 管理命令

本节列日常运维的真实命令。运行时操作走两条路：

| 通道 | 面向 | 出处 |
|------|------|------|
| `/proc/firewall/*` | 人与运维：封禁、解封、白名单、配置、读数 | `contract/procfs.fwidl` |
| systemd | 服务生命周期 | `firewall-daemon.service` |

项目**没有**额外的 CLI 封装：除 `firewall-daemon` 自身的启动参数外，
运行期管理只能写 procfs 或用 HTTP API。

procfs 读写文法的权威定义见 `docs/zh/configuration/procfs.md`
（由 `contract/procfs.fwidl` 冻结）。本文的命令与该文法逐条对齐。

## 服务管理

单元名 `firewall-daemon.service`。

| 操作 | 命令 |
|------|------|
| 启动 | `sudo systemctl start firewall-daemon` |
| 停止 | `sudo systemctl stop firewall-daemon` |
| 重启 | `sudo systemctl restart firewall-daemon` |
| 状态 | `systemctl status firewall-daemon` |
| 开机自启 | `sudo systemctl enable firewall-daemon` |
| 重载配置 | `sudo systemctl reload firewall-daemon` |
| 看日志 | `journalctl -u firewall-daemon -f` |

`reload` 能用的原因是单元里有 `ExecReload=/bin/kill -HUP $MAINPID`
（`firewall-daemon.service`）。SIGHUP 触发配置热重载。

单元的实际启动命令是 `-C /etc/firewall`，即加载目录下的 YAML。

### 启动参数

参数表以 `src/daemon/internal/config/args.go` 为准。

| 参数 | 含义 |
|------|------|
| `-c, --config <FILE>` | 单个 YAML 配置文件 |
| `-C, --config-dir <DIR>` | 加载目录下所有 YAML（含 `_` 前缀的运行期覆盖文件） |
| `-d, --daemon` | 后台运行 |
| `--no-strict` | 忽略未知配置键；默认严格模式会拒绝 |
| `--rollback` | 回滚到上一个配置版本，需守护进程在跑 |
| `-h, --help` | 打印帮助并成功退出 |
| `--config=<FILE>` / `--config-dir=<DIR>` | 等号形式同样接受 |

未指定 `-c` / `-C` 时用默认路径 `/etc/firewall-daemon/config.yml`
（`config.DefaultConfigPath`）。随包安装走的是 `/etc/firewall/` 目录，
由 systemd 单元显式指定。

前台跑一次可以当配置检查用：

```bash
sudo ./build/daemon/firewall-daemon -c config/default.yaml
```

## 内核模块

| 操作 | 命令 |
|------|------|
| 加载 | `sudo insmod build/kernel-module/firewall.ko` |
| 带参数加载 | `sudo insmod build/kernel-module/firewall.ko fw_ban_time=600` |
| 已安装后加载 | `sudo modprobe firewall` |
| 查看是否加载 | `lsmod \| grep '^firewall '` |
| 卸载 | `sudo rmmod firewall` |
| 查看模块信息 | `modinfo firewall` |
| 看参数取值 | `sudo cat /sys/module/firewall/parameters/fw_ban_time` |
| 开机自动加载 | 由 `config/modules-load.d/firewall.conf` 提供，内容是一行 `firewall` |

参数名与默认值以 `src/kernel-module/fw_main.c` 的 `module_param` 为准，
共 10 个：

```
fw_ban_time · state_file · fw_max_bans_per_second · fw_max_rate_entries
fw_max_ban_entries · fw_max_whitelist_entries · fw_max_local_ips
fw_static_threshold · fw_dynamic_threshold · fw_ddos_detection
```

0644 的四个可以在运行期写 sysfs 改：

```bash
echo 100000 | sudo tee /sys/module/firewall/parameters/fw_max_rate_entries
echo 0 | sudo tee /sys/module/firewall/parameters/fw_ddos_detection   # 关 DDoS 检测
```

0400 / 0444 的只能加载时传。完整表见
[内核模块](../architecture/kernel-module.md)「模块参数」。

> **`insmod` 失败要看 `dmesg`。** 编译通过不等于加载得进去。
> 见 [故障排查](troubleshooting.md)。

## procfs 条目与权限

`/proc/firewall/` 下 13 个条目。权限位取自
`contract/generated/procfs_uapi.h` 的 `FW_PROCFS_*_MODE`。

| 条目 | 权限 | 读 | 写 |
|------|------|-----|-----|
| `bans` | 0600 | 封禁列表 | 封禁 / 解封 |
| `whitelist` | 0600 | 白名单 | 增 / 删 |
| `config` | 0600 | 运行时配置 | `ban_time <seconds>` |
| `stats` | 0400 | 13 行 `key value` | 无 |
| `rates` | 0400 | 速率表明细 | 无 |
| `udp_ports` | 0400 | UDP 端口分布 | 无 |
| `icmp_types` | 0400 | ICMP 类型分布 | 无 |
| `pkt_sizes` | 0400 | 包大小分布 | 无 |
| `ttl_dist` | 0400 | TTL 分布 | 无 |
| `ip_frags` | 0400 | IP 分片统计 | 无 |
| `port_scanners` | 0400 | 端口扫描嫌疑 | 无 |
| `service_probes` | 0400 | 服务探测嫌疑 | 无 |
| `protected_ports` | 0400 | 受保护端口集合 | **无写入口** |

三条要点：

1. `config` **可写**，不是只读接口。
2. `protected_ports` 是只读观测面：集合由守护进程扫描本机监听端口后经
   netlink 下发。运维侧改不了「谁受保护」。未下发时显示全端口受保护。
3. 只有 `stats` 是机器可读（`read_format = machine`）；
   其余只读条目是人类可读表格，无排版稳定性承诺，脚本不要解析它们。

写侧的共性约定：

| 约定 | 内容 |
|------|------|
| 一次一条命令 | 一次 `write(2)` 一条命令，末尾换行可选 |
| 分隔符 | 空格或制表符 |
| 控制字符 | 除 `\t` 外所有 `< 0x20` 字节一律拒绝 |
| 失败 | 返回负 errno，**没有文本错误通道**，原因只进内核日志（`dmesg`） |

## 封禁管理

写文法只有四种形式（`contract/procfs.fwidl` 的 `write bans`）：

| 形式 | 语义 |
|------|------|
| `<ip>` | 按默认时长封禁（`fw_ban_time`） |
| `<ip> <seconds>` | 按指定秒数封禁 |
| `<ip> 0` | 永久封禁 |
| `unban <ip>` | 解封 |

```bash
# 封禁（默认时长）
echo "1.2.3.4"       | sudo tee /proc/firewall/bans

# 封禁（指定秒数）
echo "1.2.3.4 3600"  | sudo tee /proc/firewall/bans

# 永久封禁
echo "1.2.3.4 0"     | sudo tee /proc/firewall/bans

# 解封
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 查看
sudo cat /proc/firewall/bans
```

### procfs 不能封网段

该入口没有 CIDR 文法，一律按**精确单机**（全长前缀）封禁。
网段封禁只由守护进程的集群扫描经 netlink 下发
（`src/kernel-module/fw_procfs.c`）。

网段条目在 `bans` 的输出里带 `/前缀`，与单机条目可区分。

### 读输出形状

`bans` 的输出（`fw_procfs.c` 的 `bans_show`）：

```
Banned IP List:
-------------------
1.2.3.4                                  (permanent)
5.6.7.8                                  (expires in 599 seconds)
10.0.0.0/24                              (expires in 3599 seconds)
-------------------
Total: 3 active bans (1 permanent, 2 temporary)
```

两行表头 + `Total:` 汇总行也是这个条目的输出。
已过期待摘链的条目不显示。

### 批量封禁

一行一条命令，逐行 `tee`：

```bash
while read -r ip; do
  [ -n "$ip" ] && echo "$ip" | sudo tee /proc/firewall/bans >/dev/null
done < ip_list.txt
```

### 清空所有封禁

**模块未提供「一键清空」接口**（`contract/procfs.fwidl` 的 `write bans` 没有这条）。
两种办法：

```bash
# 1) 逐条 unban：从 bans 输出里取第一列
sudo cat /proc/firewall/bans | while read -r line; do
  ip=$(echo "$line" | awk '/^[0-9]/ {print $1}')
  [ -n "$ip" ] && echo "unban ${ip%%/*}" | sudo tee /proc/firewall/bans >/dev/null
done

# 2) 重载模块：会先保存状态再清表，重启后按 state_file 还原
sudo rmmod firewall && sudo insmod build/kernel-module/firewall.ko
```

第 2 条不是「彻底重置」：`fw_state_save()` 在卸载时把封禁与白名单写进
`state_file`（默认 `/var/lib/firewall/state`），加载时 `fw_state_restore()`
再读回来。要真正丢弃状态，得先停守护进程并删掉状态文件。

### 临时封禁批量解除

HTTP API 有这条路由（`POST /api/v1/bans/unban-temporary`），
procfs 没有对应命令。见 [用户态守护进程](../architecture/daemon.md)。

## 白名单管理

写文法三种（`contract/procfs.fwidl` 的 `write whitelist`）：

| 形式 | 语义 |
|------|------|
| `add <subnet>` | 添加 |
| `<subnet>` | 添加（省略 `add`） |
| `remove <subnet>` | 移除 |

```bash
sudo cat /proc/firewall/whitelist

echo "10.0.0.1"          | sudo tee /proc/firewall/whitelist   # 精确主机
echo "10.0.0.0/8"        | sudo tee /proc/firewall/whitelist   # CIDR
echo "add 192.168.0.0/16"| sudo tee /proc/firewall/whitelist
echo "remove 10.0.0.0/8" | sudo tee /proc/firewall/whitelist
```

| 行为 | 说明 | 出处 |
|------|------|------|
| 省略前缀 | 按地址族全长：IPv4 `/32`、IPv6 `/128` | `fw_procfs.c` |
| 存储形态 | 存的是**归一化后的网络地址**：`10.0.0.5/24` 存成 `10.0.0.0/24` | `fw_addr_normalize` |
| 移除匹配 | 要求 `(af, 地址, prefix_len)` 三元组完全一致 | `fw_wl.h` |
| 重复添加 | 同一三元组只保留一条，不报错 | `fw_wl.c` |
| 本机接口地址 | 由内核按网卡事件自动维护；手工 `remove` 命中本机地址返回 `-EPERM` | `fw_netdev.c`、`fw_wl.c` |
| 移除的联动 | 移除一条白名单后，落在其覆盖范围内的封禁一并解除 | `fw_ban_del_matching` |
| 地址准入 | 拒绝 `0.0.0.0` / 广播 / 组播 / 回环 / 链路本地 | `fw_wl.c` |
| 读输出 | 每行 `<ip>/<prefix>  on <dev>`，末行 `Total: <n> entries` | `fw_procfs.c` |

条目上限由内核模块参数 `fw_max_whitelist_entries` 控制（默认 65535）。
守护进程配置里的 `capacity.max_whitelist_entries` **只是持久化与展示**：
`SetConfig` 消息没有容量字段，改它不影响内核。
出处：`contract/netlink.fwidl`、[daemon.md](../architecture/daemon.md)。

配置层面预置的可信地址写在与 `defaults`、`jails` 同级的顶层列表键里。
键名与写法见 [YAML 配置](../configuration/yaml-config.md)
（解析入口在 `src/daemon/internal/config/parser.go`）。
守护进程启动时把它们下发进内核白名单。

## 配置查询与修改

```bash
# 运行时配置（ban_time、当前条目数）
sudo cat /proc/firewall/config

# 写默认封禁时长
echo "ban_time 600" | sudo tee /proc/firewall/config
```

`config` 的读输出（`fw_procfs.c`）：

```
Current Firewall Configuration:
--------------------------------
ban_time: 600 seconds
Ban entries: 3
Whitelist entries: 12
```

写 `ban_time` 成功后内核推送 `CONFIG_CHANGE` 事件，守护进程会跟上。

其他读数：

```bash
sudo cat /proc/firewall/stats            # 13 行机器可读计数器
sudo cat /proc/firewall/rates            # 速率表
sudo cat /proc/firewall/protected_ports  # 受保护端口集合
sudo cat /proc/firewall/port_scanners    # 端口扫描嫌疑
sudo cat /proc/firewall/service_probes   # 服务探测嫌疑
```

## 状态与统计

`stats` 的 13 个 key（`contract/procfs.fwidl` 的 `key stats`，
实现在 `src/kernel-module/fw_procfs.c`）：

| key | 含义 |
|-----|------|
| `total_bans` | 累计封禁操作数 |
| `total_unbans` | 累计解封操作数 |
| `whitelist_rejects` | 被白名单挡下的封禁请求数 |
| `ban_table_full_rejects` | 封禁表满而拒绝的新增数 |
| `alloc_failures` | 内存分配失败数 |
| `packets_dropped` | 丢弃的报文数 |
| `packets_accepted` | 经钩子放行的报文数 |
| `tcp_anomaly_dropped` | TCP 标志异常丢弃数 |
| `cleanup_cycles` | 遗留键位：无全局清理线程，恒为 0 |
| `cleanup_expired_total` | per-entry 定时器到期摘链的条目数 |
| `current_bans` | 当前封禁条目数 |
| `current_whitelist` | 当前白名单条目数 |
| `recent_additions` | 当前 1 秒泛洪窗口内的封禁添加数 |

读 `stats` 前内核会先做跨 CPU 汇总（`fw_stats_flush_all()`），
低速率下也不会读到各 CPU 尚未汇出的陈旧值。

## 日志

```bash
# 守护进程日志（路径来自 defaults.log_file）
sudo tail -f /var/log/firewall.log

# 随包配置的默认路径；defaults.log_file 留空时代码回退到
# /var/log/firewall-daemon.log（src/daemon/internal/logger/logger.go）

# 经 systemd 时看 journal
journalctl -u firewall-daemon -f

# 内核日志（模块输出统一带 "firewall:" 前缀）
sudo dmesg --follow | grep firewall
sudo dmesg --level=err,warn | grep firewall
```

改日志级别：编辑 `defaults.log_level`（`0=NONE 1=ERR 2=WARN 3=INFO 4=DEBUG`），
再 `sudo systemctl reload firewall-daemon`。
`defaults.log_max_size_mb` / `log_max_files`（轮转）不随热重载切换，需要重启。

## 配置管理

| 操作 | 命令 |
|------|------|
| 校验 YAML 语法 | `yamllint /etc/firewall/` |
| 看启动日志而不常驻 | `sudo firewall-daemon -C /etc/firewall` |
| 热重载 | `sudo systemctl reload firewall-daemon`（等价 `kill -HUP`） |
| 回滚上一个配置版本 | `sudo firewall-daemon --rollback`（需进程在跑） |
| 查看运行时生效的内核配置 | `sudo cat /proc/firewall/config` |
| 查看当前 jail 与启用状态 | `curl -u <user>:<pass> http://127.0.0.1:9119/api/v1/jails` |

字段说明与示例见 [配置指南 - YAML 配置](../configuration/yaml-config.md)。

> 严格模式默认开启：未知键直接报错退出。
> 需要忽略未知键时加 `--no-strict`。

目录形态加载时，`_` 前缀的文件是守护进程自己维护的运行期覆盖文件
（Web UI 改的字段写回这里），合并顺序在最后。
手工编辑时不要动它。

## 命令速查表

| 用途 | 命令 |
|------|------|
| 启动 / 停止 / 重启 | `sudo systemctl start\|stop\|restart firewall-daemon` |
| 重载配置 | `sudo systemctl reload firewall-daemon` |
| 看服务状态与日志 | `systemctl status firewall-daemon` / `journalctl -u firewall-daemon -f` |
| 加载模块 | `sudo insmod build/kernel-module/firewall.ko` |
| 卸载模块 | `sudo rmmod firewall` |
| 封禁 | `echo "<ip>[ <秒数>]" \| sudo tee /proc/firewall/bans` |
| 永久封禁 | `echo "<ip> 0" \| sudo tee /proc/firewall/bans` |
| 解封 | `echo "unban <ip>" \| sudo tee /proc/firewall/bans` |
| 看封禁 | `sudo cat /proc/firewall/bans` |
| 加白名单 | `echo "<cidr>" \| sudo tee /proc/firewall/whitelist` |
| 删白名单 | `echo "remove <cidr>" \| sudo tee /proc/firewall/whitelist` |
| 看白名单 | `sudo cat /proc/firewall/whitelist` |
| 改默认封禁时长 | `echo "ban_time <秒>" \| sudo tee /proc/firewall/config` |
| 看运行时配置 | `sudo cat /proc/firewall/config` |
| 看计数器 | `sudo cat /proc/firewall/stats` |
| 看健康 | `curl http://127.0.0.1:9119/health` |

`/proc/firewall/` 的 13 个条目权限只有两种：`bans` / `config` / `whitelist` 是
0600 可读写，其余 10 个是 0400 只读，一律要 `sudo`。

## 相关文档

- [监控](monitoring.md)：指标清单与健康检查
- [故障排查](troubleshooting.md)：真撞到的问题与定位路径
- [ProcFS 接口](../configuration/procfs.md)：完整文法、输出示例与错误码
- [内核模块](../architecture/kernel-module.md)：判定顺序与表结构
