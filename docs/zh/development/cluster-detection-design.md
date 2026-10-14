# 集群扫描检测（按网段）设计

本文是设计论证，属于 ADR 一类。里面描述「当初为什么这样定」。

**现状口径**请以[内核模块](../architecture/kernel-module.md)与
[用户态守护进程](../architecture/daemon.md)为准。
文中标注「落地前」「原设计」的句子说的是过去。

## 1. 背景

`frp` jail 的教训（见 `config/frp.yaml` 的停用说明）：
**单 IP 计数只封得住活跃的正常访客**。

| 事实 | 说明 |
|------|------|
| 旧 `frp` jail 的判据 | 把「成功建立连接」当失败计数 |
| 后果 | 频繁访问的访客被封，真实扫描器反而碰不到阈值：扫描器每个源 IP 只连 1 次 |
| 定性 | 这不是正则写错，而是判据方向错了 |

扫描的形态是「同一网段内 IP 多、每个 IP 少」。**单 IP 计数器恰好把这类流量漏掉。**

## 2. 判据

> 在 M 秒窗口内，同一 jail 的失败源 IP 中，同一网段出现 ≥ N 个不同源 IP，
> 且这些 IP 各自的失败次数 ≤ K ⇒ 判定该网段为集群扫描。

`≤ K` 是必须的，它把三种形态分开：

| 形态 | 网段内 IP 数 | 每 IP 失败数 | 判定 |
|---|---|---|---|
| 正常高频访客（单用户 / 单出口） | 1 | 多 | 不命中 |
| CGNAT / 运营商 NAT（多用户共性出口） | 多 | 多 | 不命中（被 K 排除） |
| 分布式扫描 / 暴力破解 | 多 | 少 | **命中** |

## 3. 实测依据（2026-09-22，frps 全量日志 6337 条连接）

| 流量 | /24 | 同 /24 不同 IP 数 | 总连接 |
|---|---|---|---|
| 正常访客（本机 9119 面板） | 14.150.163.0/24 | **1** | 418 |
| 正常访客（本机面板） | 14.150.163.0/24 | **1** | 325 |
| 正常访客（面板，另一出口） | 58.255.79.0/24 | **1** | 599 |
| 扫描（面板） | 36.155.132.0/24 | **12** | 14 |
| 暴力破解（ssh 隧道） | 213.209.159.0/24 | **10** | 365 |
| 暴力破解（ssh 隧道） | 45.148.10.0/24 | **6** | 460 |
| 扫描（llama.cpp 隧道） | 64.62.156.0/24 | 7 | 11 |

结论：正常流量永远是「一个 /24 一个 IP」，扫描与暴力破解是「一个 /24 一堆 IP」。
判据在真实数据上可分。

这批数据是一次性观察，不在仓库里（原始日志未入库）。
表格数值以当时记录为准：未验证（本次未重跑）。

## 4. 内核侧改动（网段封禁能力）

**落地前**的状态：封禁表是精确 IP 哈希，不支持前缀。

当时的四处事实（现已按下面 §4.1–§4.3 改掉）：

| 位置 | 落地前 |
|------|--------|
| `src/kernel-module/fw_ban.c` | `fw_ban_find_locked` 与 `fw_ban_lookup` 只做 `fw_addr_equal` 精确比较 |
| `src/kernel-module/fw_types.h` | `struct fw_ban_node` 无 `prefix_len` 字段 |
| `contract/generated/netlink_uapi.h` | `struct fw_ban_ip` 只有 `af` / `duration_secs` / `addr` / `reason`，**无 `prefix_len`**；而白名单的 `fw_add_whitelist` / `fw_whitelist_state_change` **有** `prefix_len`——协议本身能表达前缀，封禁故意没带 |
| `src/kernel-module/fw_netlink.c` | ban 处理分支只取 `af` / `addr` |

**为什么故意不带**：威胁模型里封禁是「对单个源 IP 的判定结果」。
加前缀等于把封禁的作用面从一台主机放大到一片网段，
误伤半径变化很大，必须先有能分得开扫描器与正常访客的判据（§2、§3），
再放大力度。

### 4.1 数据结构

`struct fw_ban_node` 增 `u8 prefix_len`，`32` / `128` 表示精确单机。
匹配从 `fw_addr_equal` 改为**前缀比较**，复用白名单已有的 `fw_prefix_match`
（`fw_types.h`），避免出现两套前缀比较逻辑漂移。

条目身份从 `(af, addr)` 变成 `(af, addr, prefix_len)` 三元组。

### 4.2 查表：分层前缀表（关键取舍）

前缀条目无法用「按完整地址哈希」直接命中：同一 /24 内的不同 IP 会散落到不同桶。
两条路：

| 方案 | 做法 | 代价 |
|---|---|---|
| 逐层探测 | 对每个候选前缀长度各算一次哈希并探测 | 每次查找最多 32（IPv4）/ 129（IPv6）次，热路径不可接受 |
| **分层桶表（选定）** | 按 `prefix_len` 分层的桶数组 + 一个「已用长度」位图；查找只遍历位图中置位的层，每层一次哈希 | 常态仅 1–3 层（实际只会封 /24、/16 这类少数长度）；内存是 129 组桶头 |

选定方案的具体形状（`fw_types.h`）：全长层复用 4096 桶的大数组，
短前缀层各用 64 桶的小数组。这样「分层省内存」这条取舍才成立，
同时精确单机封禁的常数项与落地前一致。

层下标即 `prefix_len`，所以 IPv6 最长 128 要有 129 层，IPv4 只用前 33 层。
层号与位移量的不变量放在**编译期**断言，不留到运行时。

### 4.3 协议与契约

| 步骤 | 内容 | 现状 |
|------|------|------|
| 1 | `contract/netlink.fwidl` 的 ban 段增 `prefix_len` | 已落地 |
| 2 | 跑 `python3 contract/gen.py` 重新生成 `contract/generated/netlink_uapi.h` | **必须先 gen 再 verify**，见下 |
| 3 | `struct fw_ban_ip` 的尺寸断言随之更新 | 落地前是 65 字节；加 `prefix_len` 后是 **66 字节**（`contract/generated/netlink_uapi.h` 的 `_Static_assert`） |
| 4 | 守护进程下发路径：`kernel.Client.Ban` 已带 `prefixLen` 参数 | `src/daemon/internal/kernel/client.go` |
| 5 | 地址校验接受 CIDR 形式 | `src/daemon/internal/bans/` |

顺序固定的原因：`contract/verify_layout.py` 与内核的编译期断言都读生成物。
先改代码再改契约，两边会按不同布局走。

### 4.4 热路径性能

封禁查找在包处理热路径上（每个报文调一次 `fw_ban_lookup`）。
分层查表改变了常数项，**必须重测**：
用 `scripts/bench/` 的对照法跑新旧模块，确认无回归。
验收口径是实时性 / 稳定性 / 规范性，见
[内核重写设计](kernel-rewrite-design.md)「范围与验收」。

**实测（2026-09-22，同一台机、同一份 `scripts/bench/fwsweep.sh`、
新旧模块交替 `insmod`）**。
A 路径 = 白名单未命中 + 封禁表未命中，即分层查表的成本落点。
单通路 3 线程、`secs=8`、重复 3 次取中位：

| 版本 | E 白名单短路 | A 两表未命中 | D 已封禁丢弃 |
|------|------|------|------|
| 落地前（精确哈希） | 2.176 / 2.147 µs | 2.237 / 2.220 µs | 1.266 / 1.167 µs |
| 落地后（分层前缀表） | 2.232 / 2.124 µs | 2.295 / 2.202 µs | 1.263 / 1.219 µs |

A 路径两轮均值差 **+0.9%**，小于同一次运行内本应同路径的 E 与 C 之间的自身离散
（0.02–0.29 µs，即 2–13%）——**无可测回归**。

原因与设计一致：未封禁时 `used` 位图全零（或只有精确层），
查找一次哈希即返回，与落地前的哈希表同阶。

这批数字是当时的单次测量，测的是当时的内核与主机。
当前内核上的复测：未验证。引用时按[性能基线](perf-baseline.md)的判定纪律重跑。

## 5. 守护进程侧改动

### 5.1 新纯函数

`src/daemon/internal/decision/cluster.go`：
输入是窗口、`now`、集群配置；输出是待处置网段与命中 IP 列表
（`DetectCluster` / `ClusterHit`）。

与 `internal/detect/window.go` 同层：纯计算、无 I/O，便于单测。

复用了三处已有逻辑，避免判据漂移：

| 复用的东西 | 位置 | 为什么复用它 |
|-----------|------|-------------|
| `SubnetKey` / `NewCidrKey` | `internal/detect/cidr.go` | 取网段键，网络位已置零 |
| `FailureWindow.Peek` / `Iter` | `internal/detect/window.go` | 只读计数与遍历，判定不改窗口状态 |
| 按 /24 分组的同类逻辑 | `internal/analysis/network.go` | 那张表用于攻击源网络分布，语义须与本判据对齐 |

### 5.2 接入点

| 环节 | 位置 |
|------|------|
| 判定 | `internal/runtime/pipeline.go` 的 `ScanClusters` |
| 处置 | `internal/runtime/executor.go` 的 `dispatchClusterHit`，按 `(网络地址, prefix_len)` 下发内核 |

**为什么只能周期判定，不能单行判定**：集群检测的输入是**跨 IP** 的
（同一网段内有多少个不同源）。单行判定只看得到一个源，凑不出这个结论。

### 5.3 检测周期必须显著小于 `window`

这是实现阶段撞出来的结论，不是先验设计。

| 事实 | 值 | 出处 |
|------|-----|------|
| 集群检测周期 `clusterScanInterval` | 10 秒 | `internal/runtime/executor.go` |
| 窗口清理周期 | 60 秒 | `internal/runtime/timers.go` |
| 默认 `cluster.window` | 60 秒 | `internal/config/types.go` 的 `DefaultClusterConfig` |

`FailureWindow.Peek` 按 `now - ts <= window` 计数。
若检测恰好每 `window` 秒跑一次，一批刚写入的失败会在下一次检测前滑出窗口，
扫描永远凑不够 `min_ips`。

**实测**：在 `window=600` 的夹具上，让检测与清理周期（60 秒）同拍时，
写入的 4 个源**一个也没被检出**。
因此检测单独占一个短周期，不跟着清理周期走。

检测是纯读（`detect` 不改窗口），所以可以远快于清理周期重复而不影响窗口状态。

### 5.4 下发形状

与白名单路径一致：取 `CidrKey.Addr()`（已归一，主机位为零）+ `prefix_len`，
对应内核的 `(af, addr, prefix_len)` 三元组。

**不要**用 `CidrKey.String()` 的 `a.b.c.0/24` 文本——那是给人看与当键用的，
不是协议入参。

### 5.5 配置项

YAML 键名照 `internal/config/parser.go` 的 `yamlCluster`：

| 键 | 类型 | 默认值 |
|----|------|--------|
| `enabled` | bool | `false` |
| `audit_only` | bool | `true` |
| `prefix_v4` | uint8 | 24 |
| `prefix_v6` | uint8 | 48 |
| `window` | uint32 | 60 |
| `min_ips` | uint32 | 5 |
| `max_per_ip` | uint32 | 3 |
| `ban_time` | uint32 | 3600 |

默认值出处：`internal/config/types.go` 的 `DefaultClusterConfig`。
每个字段都是指针（`Option`）语义，逐字段覆盖默认值。

`yamlJail` 用 `dec.KnownFields(true)` 拒绝未知字段，所以新增一个键要同步改多处。
改动面按当前代码核对如下：

| # | 位置 | 改什么 |
|---|------|--------|
| 1 | `internal/config/parser.go` | `yamlCluster` 的字段与 jail 后处理 |
| 2 | `internal/config/types.go` + `internal/jail/jail.go` | 结构字段与默认值 |
| 3 | `internal/runtime/pipeline.go` | `JailPolicy` 里的集群参数 |
| 4 | `internal/runtime/executor.go` | 重建规则集时的桥接 |
| 5 | `internal/runtime/file_reloader.go` | 可回滚字段：捕获 / 回滚 / 发布 |
| 6 | `internal/jail/compile.go` | 参数范围校验 |
| 7 | `contract/http.fwidl` 的 `JailResponse`（若透出 HTTP） | 加字段 → `python3 contract/gen.py` → 前端类型 |

第 7 步顺序不能倒：`contract/verify_http.py` 拿契约与生成物、
`internal/http/routes.go`、前端 TS 三面对账。

### 5.6 误伤控制与上线顺序

| 控制 | 做法 | 出处 |
|------|------|------|
| 热路径白名单短路 | 内核判定时 `fw_wl_lookup` 在 `fw_ban_lookup` **之前**，白名单内的主机即使落在被封网段也照样放行 | `src/kernel-module/fw_hook.c` |
| 下发侧白名单前检 | `fw_ban_try_add` 对「网段地址本身落在白名单覆盖范围内」直接返回 `-EPERM` | `src/kernel-module/fw_ban.c` |
| 无需在守护进程侧另加前检 | 上面两条合起来已覆盖，再加一道只是重复 | 设计裁定 |
| **首版以 audit 模式落地** | `cluster.audit_only: true`：只记日志，不封禁；观察一段确无误判再接处置 | `internal/config/types.go` 的默认值 |

## 6. 验证计划

| 层 | 方式 | 现状 |
|---|------|------|
| 算式 | `internal/decision/cluster.go` 的内嵌单测：边界（恰好 N、恰好 K、跨窗口、/24 边界 IP 如 `x.y.z.255`） | 已落地：`cluster_test.go` |
| 端到端 | `tests/test_22_cluster_scan.py`：配置接受 / 单高频 IP 不触发 / 同 /24 多源触发 | 已落地 |
| 内核 | `make kernel-module`，封禁表新判定加内核侧对照 | 已落地 |
| 契约 | `bash scripts/check_contract.sh`；`netlink.fwidl` 改动后先 `gen.py` | 已落地 |
| 性能 | `scripts/bench/` 新旧对照，确认封禁查找无回归 | 见 §4.4；当前内核未复测（未验证） |

`tests/` 里的多 IP 日志夹具照 `tests/test_21_multi_jail.py` 的写法造。

## 7. 分期

| 期 | 内容 | 结果 |
|----|------|------|
| **P1** | `internal/decision/cluster.go` + 单测 + audit 日志 | 零行为变更，可独立合入。已落地 |
| **P2** | 内核前缀封禁（§4）→ 守护进程处置接入（§5.2）+ 配置项（§5.5）+ pytest | 已落地 |
| 上线顺序 | 先 audit 观察，确认无误判后再开处置 | 默认仍是 `enabled: false`、`audit_only: true` |

## 8. 当前实现状态

P1 与 P2 均已落地（2026-09-22）。下表逐项在当次重写中重新核对过代码。

| 项 | 落点 |
|---|---|
| 判定算式 | `src/daemon/internal/decision/cluster.go`（含 `cluster_test.go`） |
| 内核前缀封禁 | `fw_types.h` 的 `struct fw_ban_table` / `struct fw_ban_layer`；`fw_ban.c` 的 `fw_ban_lookup` / `fw_ban_probe_layer` 按 `(af, addr, prefix_len)` 匹配 |
| 线格式 | `contract/netlink.fwidl` 的 ban 相关消息带 `prefix_len`；生成物 `struct fw_ban_ip` 66 字节 |
| 配置 | `yamlCluster` 八个键，默认 `enabled: false`、`audit_only: true` |
| 周期检测 | `ScanClusters`，10 秒独立周期，经 `dispatchClusterHit` 下发 |
| 端到端 | `tests/test_22_cluster_scan.py` |

默认关闭、且开启后首版只审计，与 §5.6 的上线顺序一致。

## 9. 未决事项

| 项 | 状态 |
|----|------|
| IPv6 网段封禁的默认前缀长度是否合适（48） | 未验证：§3 的实测数据全是 IPv4 |
| `max_per_ip` 默认值 3 在不同服务上的普适性 | 未验证：只在 frps 一份日志上标定过 |
| 打开处置（`audit_only: false`）的实际误伤率 | 未验证：需要更长观察期 |

## 相关文档

- [内核重写设计](kernel-rewrite-design.md)：封禁表骨架的设计来源
- [内核模块](../architecture/kernel-module.md)：分层桶表的当前结构
- [性能基线](perf-baseline.md)：复测的判定纪律
