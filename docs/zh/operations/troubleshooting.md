# 故障排查

本文按「症状 → 定位 → 处理」组织。每条都有仓库内出处。
标「未验证」的条目是没在本仓库复现过的推断。

## 先看这三处

| 位置 | 看什么 |
|------|--------|
| `sudo dmesg \| grep firewall` | 内核模块的日志（`pr_fmt` 统一带 `firewall:` 前缀） |
| `journalctl -u firewall-daemon -n 50` | 守护进程的启动与关停记录 |
| `sudo cat /proc/firewall/stats` | 计数器是否合理、有没有在增长 |

procfs 的写侧**没有文本错误通道**：失败返回负 errno，原因只进内核日志。
所以 `echo` 写 procfs 报错时，第一件事是看 `dmesg`，不是找错误文本。
出处：`contract/procfs.fwidl`、`src/kernel-module/fw_procfs.c`。

## 模块无法加载

### 症状：`Cannot allocate memory`

```
insmod: ERROR: could not insert module build/kernel-module/firewall.ko: Cannot allocate memory
```

**这是本仓库真撞到过的问题**，实测于 Ubuntu 24.04 GA 的 6.8.0-146。

`dmesg` 里能看到真正的原因：

```
firewall: illegal size (86016) or align (64) for percpu allocation
firewall: 速率表初始化失败: -12
```

| 项 | 内容 |
|----|------|
| 根因 | 内核对**单次** per-CPU 申请有 32 KiB 上限：`mm/percpu.c` 对超限 `WARN` 并返回 NULL |
| 触发值 | 速率槽表整表 512 槽 × 168 字节 = 86016 字节，超限 |
| 传播路径 | `fw_rate_init()` 拿不到槽表 → 返回 `-ENOMEM`（即 `-12`）→ `fw_init` 放弃加载 → `insmod` 报 `Cannot allocate memory` |
| 修法 | 按 `FW_RATE_CHUNK_SLOTS`（128）× `FW_RATE_CPU_CHUNKS`（4）分块申请，单块 21504 字节，落在上限内。任一块失败即回滚已分配的部分 |
| 出处 | `src/kernel-module/fw_rate.c` 的 `fw_rate_this_slot` 注释与 `fw_rate_init`；`fw_types.h` 的三个常量；`fw_main.c` 的「速率表初始化失败」分支 |

**编译完全正常，问题只在加载期暴露。** 所以「编译通过不等于加载得进去」。

若你自己改大了槽表，又看到这个错误，先算尺寸：
`FW_RATE_CPU_SLOTS × sizeof(struct fw_rate_cpu_slot)` 必须靠分块控制在 32 KiB 内。
分块只是底层申请方式，**索引空间与 `slot_idx` 语义不变**。

### 其他加载失败原因

| 症状 | 原因 | 处理 |
|------|------|------|
| `Invalid module format` | vermagic 与运行内核不匹配（交叉编译产物拿去加载） | 针对当前内核重编：`make clean && make kernel-module` |
| `Unknown symbol in module` | 缺依赖符号，或模块与内核版本断层 | 看 `dmesg` 里缺哪个符号；本仓库的两处内核适配见下节 |
| `Operation not permitted` | 不是 root | 用 `sudo` |
| `Key was rejected by service` / 加载被拒 | Secure Boot 拦未签名模块 | 给模块签名，或在受控环境里关 Secure Boot。本仓库不提供签名流程 |
| `File exists` | 模块已加载 | 先 `sudo rmmod firewall`；netlink 是 portid 独占，残留进程会占住租约 |
| `Resource temporarily unavailable` | 已有守护进程持有 netlink 链路 | 先停 `firewall-daemon` |
| `ERROR: Kernel configuration is invalid.` | 内核头文件与运行内核不匹配 | `sudo apt install --reinstall linux-headers-$(uname -r)` |

内核把单守护进程实现为 **portid 独占 + 30 秒活动超时**，且模块没有注销消息。
所以 `rmmod` 后立刻重跑守护进程可能被拒，等一个超时周期或重启进程。
出处：`src/kernel-module/fw_netlink.c`、`scripts/e2e-daemon.sh` 的收尾说明。

### 症状：编译报 `implicit declaration of function 'timer_container_of'`

```
error: implicit declaration of function 'timer_container_of'
       [-Werror=implicit-function-declaration]
```

**同样是本仓库真撞到的问题。**

| 项 | 内容 |
|----|------|
| 根因 | `timer_container_of()` 是 6.16 才引入的名字；此前同一件事叫 `from_timer()`，而 7.0 起旧名已删除。**两个名字不共存** |
| 具体表现 | Ubuntu 24.04 GA 的 6.8 只有 `from_timer`，缺适配就直接卡在 `-Werror=implicit-function-declaration` |
| 修法 | 按**宏是否存在**适配：`#ifndef timer_container_of` 时用 `from_timer` 定义它 |
| 出处 | `src/kernel-module/fw_ban.c` 的兼容宏段 |

**为什么不用 `LINUX_VERSION_CODE` 判断版本号**：发行版会把新宏 backport
进旧版本号的内核，也会反过来砍掉旧宏。照版本号判断在这类内核上正好判反。
这段取舍写在 `fw_ban.c` 的注释里。

新加一处内核 API 依赖时，按同样口径处理：查宏 / 符号是否存在，不查版本号。

## 守护进程无法启动

### 症状：报内核接口不可用

```
firewall-daemon: 内核接口不可用: /proc/firewall/bans 不存在（内核模块未加载？）
```

`main.go` 的 `checkProcfs` 在启动前 `stat` 若干 procfs 路径，
缺失即**直接以启动错误返回**，不留一个「界面正常但永不算」的进程。

处理顺序：

```bash
lsmod | grep '^firewall '          # 模块在不在
sudo dmesg | tail -30              # 加载为什么失败
sudo insmod build/kernel-module/firewall.ko
```

### 症状：`make: go: 没有那个文件或目录`，错误 127

```
sudo make daemon
make: go: 没有那个文件或目录
```

`sudo` 默认 `secure_path` 不含用户目录下的 Go 安装位置
（常见 `~/.go/bin`、`/usr/local/go/bin`）。

```bash
go version                                          # 先确认当前 shell 里能用
sudo env "PATH=$PATH" make daemon                   # 与仓库脚本一致的写法
sudo --preserve-env=PATH make daemon                # 等价写法
```

### 症状：启动就退出，日志说面板缺失

```
firewall-daemon: 前端静态面板缺失（go:embed web_ui/static 为空）
```

`main.go` 检查 `panelres.PanelDir`。原因通常是没跑过 `make daemon`，
或者 `src/daemon/web_ui/static/assets.go` 被清理动作删掉了
（它是 `//go:embed` 的持有文件，删掉后包内无 `.go` 文件）。

```bash
ls src/daemon/web_ui/static/assets.go
make frontend && make daemon
```

### 症状：面板能开，但所有数据都是 401 / 一直转圈

先看这一条：**服务侧的 401 有意不带 `WWW-Authenticate`**。

出处：`src/daemon/internal/http/auth.go`；断言在
`src/daemon/internal/http/routes_contract_test.go`
（「`%s 发了 WWW-Authenticate，契约声明有意不发`」）。

为什么要刻意不发这个头：

| 事实 | 后果 |
|------|------|
| SPA 外壳是公开路由，顶层文档**不返回 401** | 浏览器不会弹原生 Basic 对话框，也就不会缓存凭据 |
| 若带上 `WWW-Authenticate` | 浏览器弹原生对话框；用户在对话框里输错密码时按钮会永久转圈，`fetch` 请求挂起 |
| 页面自身发出的请求会全部 401 | 每个无凭据请求都在累加服务侧的暴力破解计数，最终把正确凭据一起锁死，表现为「越刷新越不可用」 |

所以**不要**把「浏览器不弹登录框」当 bug 修。凭据由前端显式携带。

排查顺序：

```bash
# 1) 未配凭据时不需要认证：两项都为空则中间件直接放行
grep -n "metrics_username\|metrics_password" /etc/firewall/*.yaml

# 2) 命令行验证凭据本身对不对（绕过前端）
curl -i -u <user>:<pass> http://127.0.0.1:9119/api/v1/stats

# 3) 不带凭据时的响应里确实没有 WWW-Authenticate
curl -i http://127.0.0.1:9119/api/v1/stats | grep -i www-authenticate   # 应无输出

# 4) 是否已被锁定：连续失败达阈值后锁定一段时间
journalctl -u firewall-daemon -n 50 | grep -i 认证
```

| 情况 | 表现 | 处理 |
|------|------|------|
| 凭据只填一项 | **拒绝启动** HTTP 服务 | 两项都填，或都留空 |
| 绑定非回环地址且完全未配凭据 | 拒绝启动 HTTP 服务 | 配凭据，或改回 `127.0.0.1` |
| 锁定窗口内提交正确凭据 | 仍然 401 | 等锁定期过。锁定窗口不区分来源 IP（进程级一份账本） |
| 前端令牌过期 | 界面回到登录页 | 重新输入。前端**不做自动重登**：锁定期间重试只会延长锁定 |
| SSE 一直 401，REST 正常 | 两条通道携带凭据的方式不同 | `withAccessToken()` 做 `encodeURIComponent`，服务侧做百分号解码；只改一边就永久 401（`frontend/src/api/auth.ts`、`internal/http/auth.go`） |

免登录直达（本机调试用）：`http://<host>:9119/?access_token=<base64(user:pass)>`。
令牌写入 `sessionStorage` 后会从地址栏清掉。

### 症状：`Failed to open log file ... Read-only file system (os error 30)`

| 项 | 内容 |
|----|------|
| 原因 | systemd 单元的 `ProtectSystem=strict` 让除 `ReadWritePaths` 之外的路径都只读 |
| 现状 | 随包单元里 `ReadWritePaths=/var/lib/firewall /var/log`，所以默认路径 `/var/log/firewall.log` 可写（`firewall-daemon.service`） |
| 触发场景 | 你把 `defaults.log_file` 改到了 `ReadWritePaths` 没覆盖的目录；或本地 override 删掉了那行 |
| 行为 | 守护进程回退 stderr 继续运行，**不会退出**（`internal/logger/file.go`） |

两种处理，选一个：

```bash
# A) 把日志目录放权（比放开整个 /var 收敛）
sudo mkdir -p /var/log/firewall
sudo systemctl edit firewall-daemon
# [Service]
# ReadWritePaths=/var/lib/firewall /var/log/firewall
sudo systemctl restart firewall-daemon

# B) 不改单元，直接用 journal
journalctl -u firewall-daemon -f
```

不要把 `ProtectSystem=strict` 整行删掉：那是随包单元的安全基线。

## IP 未被封禁

```bash
lsmod | grep '^firewall '                    # 模块在不在
sudo cat /proc/firewall/whitelist            # 是不是被白名单挡了
sudo cat /proc/firewall/bans                 # 封禁条目到底进没进表
sudo cat /proc/firewall/stats                # whitelist_rejects / ban_table_full_rejects 在不在涨
sudo dmesg | grep firewall | tail -30        # 写侧失败原因只在这里
```

按读数分流：

| 读数 | 结论 | 出处 |
|------|------|------|
| `whitelist_rejects` 在涨 | 下发被白名单前检拒绝 | `fw_ban.c` 的 `fw_ban_try_add` 返回 `-EPERM` |
| `ban_table_full_rejects` 在涨 | 封禁表满 | 提高 `fw_max_ban_entries` 或降 jail 灵敏度 |
| `recent_additions` 顶在 `fw_max_bans_per_second` | 被泛洪闸门限流（三条路径共用这道闸） | `fw_ban_flood_allow` |
| 表里有，但包还在进 | 见下节 | — |
| 表里没有，日志也没封禁记录 | 判定在守护进程侧，往下走「封禁没触发」 | — |
| 本机地址在 `whitelist` 里且 `device_name` 是接口名 | 内核按网卡事件自动收录本机地址，这是预期 | `fw_netdev.c` |

### 封禁表里有，但包没被丢

| 可能原因 | 判据 | 说明 |
|----------|------|------|
| 流量走 lo 接口 | `tcpdump -i lo` 能看到 | 钩子对 `IFF_LOOPBACK` 的报文入口即放行 |
| 单个网络命名空间内部的流量 | 收发两端在同一 netns | 钩子只注册在 `init_net`；不出 netns 的流量到不了它 |
| 前缀不匹配 | 封的是 `/24`，源 IP 不在该网段 | 条目身份是 `(af, addr, prefix_len)`，移除要求三元组一致 |
| 已经到期摘链 | `bans` 输出里没有该条 | per-entry 定时器到期即摘链 |
| 源地址被判为非法 | 源是 `0` / 广播 / 组播 / 回环 / 链路本地 | 这类报文不进任何表、也不计丢弃 |
| 封的是精确单机，想封网段 | procfs 写的条目不带 `/前缀` | **procfs 的 `bans` 没有 CIDR 文法**，一律精确单机；网段封禁只由守护进程经 netlink 下发 |

出处：`src/kernel-module/fw_hook.c`、`fw_ban.c`、`fw_procfs.c`。

## 封禁没触发（jail 侧）

```bash
# 1) 守护进程有没有在读这个文件
journalctl -u firewall-daemon | grep -i "jail\|inotify"

# 2) 有没有解析到行
curl -s -u <user>:<pass> http://127.0.0.1:9119/api/v1/stats | jq '.data'
curl -s -u <user>:<pass> http://127.0.0.1:9119/metrics | grep firewall_lines_parsed_total

# 3) 正则能不能匹配这一行（先离线验）
echo '<一行真实日志>' | grep -P '<你的正则>'

# 4) 该 jail 有没有因正则编译失败退化为关键字回退
journalctl -u firewall-daemon | grep "正则未能编译"
```

| 现象 | 原因 | 处理 |
|------|------|------|
| `firewall_lines_parsed_total` 为 0 | 文件没被 watch：路径错、权限不足或目录不存在 | 核对 `log_files`；守护进程找不到可监视的日志源会**启动失败** |
| 解析有、命中为 0 | 正则与真实日志格式不符 | 用第 3 步离线验，注意转义 |
| 命中有、封禁为 0 | 没到阈值。有效阈值不等于 `max_retries` 原值：高峰时段 ×1.5、内网来源 ×2.0、再乘信誉系数 | 看 `internal/decision/policy.go` 的 `EffectiveThreshold`；`internal/analysis/ewma.go` 的 `PeakHours` |
| 反复重载后计数归零 | 不会发生：重载只换规则集与参数，不重置失败窗口 | 若确实在归零，是配置换了 jail 名，窗口键随之变了 |
| 轮转后不再增长 | 轮转靠 `MOVE_SELF` / `DELETE_SELF` 重挂新 inode | 看 `firewall_log_rotations_total` 是否在涨 |
| 日志文件缺失 | 守护进程容忍缺失文件（按行解析那一侧不校验存在性） | 文件出现后会自动跟上 |
| 集群扫描不触发 | 默认关闭且默认只审计：`enabled: false`、`audit_only: true` | 见 `cluster-detection-design.md`；检测周期 10 秒，必须显著小于 `window` |

## 性能问题

| 症状 | 先看 | 处理 |
|------|------|------|
| CPU 偏高 | `sudo cat /proc/firewall/stats` 的 `packets_accepted`；`top -b -n 1 \| head -20` | 关 DDoS 检测对照：`echo 0 \| sudo tee /sys/module/firewall/parameters/fw_ddos_detection` |
| 速率检测像在误伤 | `sudo cat /proc/firewall/rates` 表头的 `rate_slot_spill` | 非零说明活跃源已超上限，新源**有意放行**（表满不丢包）；提高 `fw_max_rate_entries` 不会突破 `FW_RATE_CPU_SLOTS` = 512 这个瓶颈 |
| 端口扫描嫌疑刷屏 | `sudo cat /proc/firewall/port_scanners` | 阈值是 5 个唯一端口（`fw_types.h` 的 `PORT_SCAN_THRESHOLD`） |
| 封禁数持续走高 | `current_bans`；各 jail 的 `bans_triggered` | 减 `findtime` 或加 `max_retries`；`fw_max_ban_entries` 到限会拒绝新增 |
| 历史库变大 | `sudo ls -lh /var/lib/firewall/` | 由清理调度器按保留天数删除旧记录；保留天数取 `defaults.history_retention_days`（默认 7，`internal/config/types.go` 的 `HistoryRetentionDays`）。库本身由 `defaults.history_db_path` 决定开不开：留空时 persist 根本不建，面板的分析面全部回 503 |
| 日志变大 | `sudo du -m /var/log/firewall*` | 内置按大小轮转，`log_max_size_mb` / `log_max_files`；改后要重启 |

绝对性能数字不要照文档引用。口径与复现方法见
[性能基线](../development/perf-baseline.md)。

## PWA 装不上

| 症状 | 原因 | 处理 |
|------|------|------|
| 局域网 IP 访问时无法「添加到主屏幕」，界面正常 | 浏览器只在安全上下文（HTTPS 或 localhost）暴露 `serviceWorker` API | 用 HTTPS 或本机 `localhost` 访问 |
| 控制台没有报错，就是没注册 | `main.tsx` 检测不到就静默跳过，不打警告 | 这是**有意设计**：已知限制，不是缺陷 |

**不要**为此塞 polyfill，也不要改注册路径。
`/sw.js` 必须由守护进程单独提供并带 `Service-Worker-Allowed: /`，
否则脚本作用域只有 `/static/`，接管不了页面导航。
出处：`src/daemon/internal/http/static.go`、`frontend/src/main.tsx`。

机械证据在 `tests/e2e/pwa-context.spec.ts`。

## 集成测试跑不了

三层测试的可行范围不同，见 [测试](../development/testing.md)。要点：

| 事实 | 说明 |
|------|------|
| CI 的 runner 加载不了内核模块 | GitHub Actions 的 Azure VM 用自定义内核，编出的 `.ko` 可能 `insmod` 不了 |
| 因此 `运行测试` 只跑守护进程子集 | `compatible=false` 时用 `-k` 过滤；`浏览器端到端测试` 整段带 `::warning::` 跳过 |
| 内核模块套件要在真机上跑 | 必须能 `insmod` 的机器 + root |

**CI 绿不代表内核模块套件跑过。**

`sudo python3 -m pytest` 报 `No module named pytest`：
runner 镜像的系统 python3 不带 pytest 与 PyYAML，且 `--user` 安装对 root 不可见。
要装进系统站点目录（`python3-pytest`、`python3-yaml`）。

## 定位工具

| 用途 | 命令 |
|------|------|
| 看模块自身日志 | `sudo dmesg \| grep firewall` |
| 读模块参数当前值 | `sudo ls /sys/module/firewall/parameters/` |
| 读模块版本 | `modinfo firewall \| grep '^version:'` |
| 看 netlink 占用者 | `sudo ss -f netlink -p \| grep firewall` |
| 验进程内函数 | `nm build/kernel-module/firewall.ko \| grep <函数名>`（模块不 `EXPORT_SYMBOL`，用这个而不是 `lsmod` 的引用计数） |
| 验内核接口 | `sudo ls /proc/firewall/`（应有 13 个条目） |
| 抓包看是否到钩子 | `sudo tcpdump -ni <if> host <ip>` |
| 热路径测量 | `scripts/bench/`，方法与判定纪律见性能基线 |

模块不提供自有的调试级别开关。历史文档里的 `make debug DL=2` 与
`DL=0..3` 分级在当前仓库不存在（`Makefile` 无 `debug` 目标）。
要更详细的信息就用 `log_level: 4`（DEBUG）。

## 报告问题前收集

```bash
{
  echo "# 采集时间 $(date)"
  echo "## uname -r";      uname -r
  echo "## os-release";    cat /etc/os-release
  echo "## lsmod";         lsmod | grep '^firewall '
  echo "## dmesg";         sudo dmesg | grep -i firewall
  echo "## procfs stats";  sudo cat /proc/firewall/stats
  echo "## procfs config"; sudo cat /proc/firewall/config
  echo "## journal";       journalctl -u firewall-daemon --since "1 day ago" --no-pager | tail -200
  echo "## module version"; modinfo firewall | grep '^version:'
} > firewall-diag-$(date +%Y%m%d).txt
```

提交 Issue 时附上这份输出，并带：

1. 配置文件（**先脱敏**：`defaults.metrics_username` / `metrics_password` 是明文凭据）；
2. 内核版本 `uname -r`；
3. 复现步骤，以及「期望 / 实际」。

Issues 地址：<https://github.com/SnowCore8/linux-firewall-kmod/issues>。

## 相关文档

- [管理命令](management.md)：procfs 真实文法
- [监控](monitoring.md)：两套读数的口径
- [测试](../development/testing.md)：三层测试与 CI 六个任务
- [构建](../development/building.md)：构建期问题的常见坑
