# 安全策略

本文说清两件事：怎么报漏洞、这个系统的信任边界在哪里。
只写仓库里能查到出处的事。没实现的不承诺。

## 支持的版本

| 版本 | 是否支持 |
|------|----------|
| 2.x（当前发布 v2.2.0，见 `git tag`） | 是 |
| < 2.0 | 否 |

## 报告漏洞

1. 不要提交公开 Issue。
2. 联系维护者：邮件 snowcore8@gmail.com，
   或用 GitHub 的私有漏洞报告功能。
3. 报告请包含：漏洞描述、复现步骤、潜在影响、修复建议（可选）。

维护者在 **48 小时内**响应。

## 信任边界

这套系统的机制是：读日志 → 判定坏 IP → netlink 下发 → 内核命中即丢。
边界按这条链分。

### 谁能写 procfs，谁就能封 IP

| 条目 | 权限 | 后果 |
|------|------|------|
| `/proc/firewall/bans` | 0600 | 封禁、解封任意 IP |
| `/proc/firewall/whitelist` | 0600 | 放行任意地址，绕过封禁 |
| `/proc/firewall/config` | 0600 | 改全局封禁时长 |
| 其余条目 | 0400 | 只读观测面 |

出处：`contract/procfs.fwidl`，生成到
`contract/generated/procfs_uapi.h`。

推论：拿到 root 就能改封禁面。这不是漏洞，是设计。
procfs 不提供受保护端口的写入口，集合只由守护进程经 netlink 下发，
运维侧改不了「谁受保护」。出处同上。

### 守护进程以 root 跑

`firewall-daemon.service` 里 `User=root`、`Group=root`，
因为要加载模块、写 procfs。单元同时带这些沙箱项：

`NoNewPrivileges`、`ProtectSystem=strict`、
`ReadWritePaths=/var/lib/firewall /var/log`、`ReadOnlyPaths=/etc/firewall`、
`PrivateTmp`、`ProtectHome`、`ProtectKernelTunables`、
`ProtectControlGroups`、`RestrictNamespaces`、`RestrictRealtime`、
`RestrictSUIDSGID`、`MemoryDenyWriteExecute`、`LockPersonality`、
`SystemCallFilter=@system-service`、`SystemCallArchitectures=native`、
`LimitNOFILE=65536`、`LimitNPROC=10`。

注意 `ProtectKernelModules` 在单元里是注释掉的：
模块走 `modules-load.d` 在启动时加载，这条开了会挡自己。

### 面板与 API 的认证

出处：`contract/http.fwidl` 的 `auth` 段与
`src/daemon/internal/http/auth.go`、`auth_lockout.go`。

| 项 | 值 | 说明 |
|----|----|------|
| 方案 | `Basic` | 凭据来自 `defaults.metrics_username` / `defaults.metrics_password` |
| 未配置判定 | 两项都为空 | 只填一项判失败，避免配置笔误把整个 API 开放 |
| 失败锁定 | `failure_threshold = 10`、`lockout_seconds = 60` | 锁定期内正确凭据也拒 |
| 查询参数 | `token_query = "access_token"` | SSE 与免登录直达用 |
| 未授权状态 | `unauthorized_status = 401` | `/api/v1/**` 的 401 不带 `WWW-Authenticate` |

要点：

- Basic 是编码，不是加密。凭据以 base64 出现在 URL 查询参数里时，
  会进浏览器历史与反向代理日志（推测：具体取决于浏览器与代理配置）。
- 服务只提供 HTTP，没内置 TLS。
  出处：`src/daemon/internal/http/server.go` 用 `http.Server.Serve(listener)`，
  未找到 TLS 配置。要 HTTPS 自己放反向代理。
- 面板的 SPA 外壳是公开路由，顶层文档不返回 401。
  这是登录表单做成应用内页面的原因，不是绕过认证的口子：
  拿到 HTML 不等于拿到数据，`/api/v1/**`、`/metrics`、SSE 都要认证。
- SSE 有连接上限：`/api/v1/events` 10 条、`/api/v1/logs/stream` 5 条，
  两条各自独立，超限返回 503。出处：`contract/http.fwidl`。
  除此之外没有对 API 做限速（未在本仓库找到实现）。

### 监听地址与凭据存放

- 代码默认值是 `127.0.0.1`（`src/daemon/internal/config/types.go`）。
- 仓库的 `config/default.yaml` 写的是 `0.0.0.0`，即对所有接口开放。
- 绑定到非回环地址时必须配凭据；两项留空等于面板对所有可达者开放。
  这条警告写在 `config/default.yaml` 的注释里。
- **只在可信网络暴露面板。** 明文 Basic + 无 TLS 的组合，
  不适合直接放到公网。
- 凭据在 YAML 里是明文。安装时 `/etc/firewall` 目录 0700、
  配置文件 0600、属主 root（`Makefile` 的 `install-config`）。
  `config/default.yaml` 已被 git 跟踪，不要把真实凭据提交进去。

### 输入校验

| 面 | 校验 | 出处 |
|----|------|------|
| 静态资源路径 | `fs.ValidPath` 且拒绝含 `..` 的名字 | `src/daemon/internal/http/static.go` |
| 配置正则 | 拒嵌套量词、占有量词、量化交替组等易回溯模式 | `src/daemon/internal/logparse/rule.go` |
| 正则规模 | 模式上限 1024 字节、分支上限 50 | 同上 |
| 每 jail 正则数 | 上限 10 条 | `src/daemon/internal/config/types.go` 的 `MaxRegexPatterns` |
| 配置结构 | 严格模式：未知顶层键直接报错；`--no-strict` 才忽略 | `src/daemon/internal/config/parser.go`、`args.go` |
| 出口探测地址 | 有长度上限 | `src/daemon/internal/config/parser.go` 的 `MaxProbeURLLen` |
| 本机经纬度 | 必须成对给出，只给一个拒绝加载 | 同上 |

### 内核侧的内生自限

- 每秒封禁添加数受限流保护：
  `fw_ban_flood_allow`（`src/kernel-module/fw_ban.c`），
  上限来自 `fw_max_bans_per_second` 模块参数与配置的
  `ddos.max_bans_per_second`。
- 本机地址集合在 netfilter 钩子注册之前发布，运行期必然有一张已发布的表。
  旧实现的「空表即判非本机」失败开放窗口已消除。
  出处：`src/kernel-module/fw_local.c`、`fw_netdev.c` 的头部注释。
- 本机地址只存精确主机地址（IPv4 /32、IPv6 /128），不扩成子网豁免。
  旧实现按掩码比较，接口配 /24 时整段的显式白名单条目删不掉。
  出处：`src/kernel-module/fw_local.c`。
- 受保护端口位图为空时按「全端口受保护」处理，不会静默关掉检测。
  出处：`src/kernel-module/fw_ports.c`。
- 表规模有上限：封禁、白名单、速率条目数由模块参数与配置的
  `capacity:` 段给出（默认 65535，见 `config/default.yaml`）。
  速率每 CPU 槽表定长 512（`FW_RATE_CPU_SLOTS`）。

## 已知缺口

写在这里，不在别处含糊：

- 失败次数与 DDoS 命中只有本进程累计值，没有按天历史。
  所以 `/api/v1/stats` 的 `failed_attempts_trend` 是空标签 + 全零序列，
  热力图的 `failed_attempts` 与 `ddos_events` 两列恒为 0。
  出处：`contract/http.fwidl` 的
  `HTTP_FAILURE_HISTORY_NOT_PERSISTED`。
- 未认证时（凭据两项都留空）面板对任何可达者完全开放，
  包括写操作。这是配置选择，不是缺陷，但必须知情。
- 没有内置 TLS，没有 API 限速。
- HTTP 面尚未接线的条目冻结在 `contract/http_gap_baseline.txt`，
  基线只减不增。

## 不提供的能力

别按这些指望它：

- 不是 WAF。不解析 HTTP 语义、不识别 payload。
- 不表达 allow 规则，不做 NAT、端口映射、QoS，
  不替代 iptables 的规则表达能力。

封禁与白名单可以跨重启保留：`fw_state.c` 读写状态文件，
路径由模块参数 `state_file` 给出（默认 `/var/lib/firewall/state`）。
没配置或没落到这个路径时，表在卸载模块后就空了。
还原路径仍走容量检查，超限的行跳过并计数；快照的 CRC32 尾行是必需的，
缺了整份文件按不可信处理。出处：`src/kernel-module/fw_state.c` 头部注释。

## 安全实践

| 实践 | 说明 |
|------|------|
| 用 systemd 启动 | 单元带沙箱项，见上节 |
| 绑回环或内网 | 需要广绑时务必配凭据 |
| 前面放 TLS 反向代理 | 服务本身不提供 HTTPS |
| 凭据当密钥对待 | 别提交进 git，别写进脚本 |
| 保持配置校验严格 | 默认开，别长期挂 `--no-strict` |
| 看 `/proc/firewall/stats` 与指标 | 端口默认 9119 |
| 定期回看封禁面 | `bans` 与 `whitelist` 都要看 |

## 变更记录

历史修复不在此重复。见 [CHANGELOG.md](CHANGELOG.md)。

机制细节见 [docs/zh/architecture/](docs/zh/architecture/)。
