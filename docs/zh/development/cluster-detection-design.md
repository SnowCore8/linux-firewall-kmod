# 集群扫描检测（按 /24）设计

## 1. 背景

`frp` jail 的教训（见 `config/frp.yaml` 的停用说明）：**单 IP 计数只封得住活跃的正常访客**。

- 旧 `frp` jail 把 `get a user connection`（成功连接）当失败计数 → 频繁访问的访客被封，真实扫描器反而碰不到阈值（扫描器每个源 IP 只连 1 次）。
- 这不是正则写错，而是判据方向错了：**扫描的形态是「同一网段内 IP 多、每个 IP 少」，单 IP 计数器恰好把这类流量漏掉。**

## 2. 判据

> **在 M 秒窗口内，同一 jail 的失败源 IP 中，同一 /24 出现 ≥ N 个不同源 IP，且这些 IP 各自的失败次数 ≤ K → 判定该 /24 为集群扫描。**

`≤ K` 是必须的，它把两种形态分开：

| 形态 | /24 内 IP 数 | 每 IP 失败数 | 判定 |
|---|---|---|---|
| 正常高频访客（单用户/单出口） | 1 | 多 | 不命中 |
| CGNAT / 运营商 NAT（多用户共性出口） | 多 | 多 | 不命中（被 K 排除） |
| 分布式扫描 / 暴破 | 多 | 少 | **命中** |

## 3. 实测依据（2026-09-22，frps 全量日志 6337 条连接）

| 流量 | /24 | 同 /24 不同 IP 数 | 总连接 |
|---|---|---|---|
| 正常访客（本机 9119 面板） | 14.150.163.0/24 | **1** | 418 |
| 正常访客（本机 WebUI） | 14.150.163.0/24 | **1** | 325 |
| 正常访客（WebUI，另一出口） | 58.255.79.0/24 | **1** | 599 |
| 扫描（WebUI） | 36.155.132.0/24 | **12** | 14 |
| 暴破（ssh 隧道） | 213.209.159.0/24 | **10** | 365 |
| 暴破（ssh 隧道） | 45.148.10.0/24 | **6** | 460 |
| 扫描（llama.cpp 隧道） | 64.62.156.0/24 | 7 | 11 |

正常流量永远是「一个 /24 一个 IP」，扫描/暴破是「一个 /24 一堆 IP」——判据在真实数据上可分。

## 4. 内核侧改动（CIDR 封禁能力）

现状：封禁表是**精确 IP 哈希**，不支持前缀。

- `src/kernel-module/fw_ban.c`：`fw_ban_find_locked` 与 `fw_ban_lookup` 只做 `fw_addr_equal` 精确比较
- `src/kernel-module/fw_types.h`：`struct fw_ban_node` 无 prefix 字段
- `contract/generated/netlink_uapi.h`：`struct fw_ban_ip` 只有 `af/duration_secs/addr/reason`，**无 `prefix_len`**；而白名单的 `fw_add_whitelist` / `fw_whitelist_state_change` **有** `prefix_len` —— 协议本身能表达前缀，封禁故意没带
- `src/kernel-module/fw_netlink.c`：ban 处理分支只取 `af` / `addr`

### 4.1 数据结构

`struct fw_ban_node` 增 `u8 prefix_len`（`32`/`128` 表示精确单机）。匹配从 `fw_addr_equal` 改为**前缀比较**；白名单已有 `fw_prefix_match`（子网链实现），封禁侧应复用同一语义函数，避免两套前缀比较逻辑漂移。

### 4.2 查表：分层前缀表（关键取舍）

前缀条目无法用「按完整地址哈希」直接命中——同一 /24 内的不同 IP 会散落到不同桶。两条路：

| 方案 | 做法 | 代价 |
|---|---|---|
| 逐层探测 | 对每个候选 prefix 长度各算一次哈希并探测 | 每次 lookup 最多 32（IPv4）/128（IPv6）次探测，热路径不可接受 |
| **分层桶表（推荐）** | 按 `prefix_len` 分层的桶数组 + 一个「已用长度」位图；lookup 只遍历位图中置位的层，每层一次哈希 | 常态仅 1–3 层（实际只会封 /24、/16 这类少数长度），内存为 33 组桶头（可接受） |

推荐分层桶表：把「已用前缀长度集合」位图放在封禁表头，插入/删除时维护；lookup 先查精确层（/32），再按位图遍历更短前缀层。常态开销接近现状。

### 4.3 协议与契约

- `contract/netlink.fwidl` 的 ban 段增 `prefix_len`
- 跑 `contract/gen.py` 重新生成 `contract/generated/netlink_uapi.h`（**必须先 gen 再 verify**，见 `contract-assertion-verification`）
- `struct fw_ban_ip` 的 `_Static_assert(sizeof(...) == 65)` 需同步更新
- daemon 侧下发路径：`ban::ban_ip` 增前缀参数（或新增 `ban_cidr`），`ban/operations.rs` 的 `validate_ip` 需接受 CIDR 形式

### 4.4 热路径性能

封禁 lookup 在包处理热路径上（`fw_ban_lookup` 每个包调用）。分层查表改变了常数项，**必须重测**：用 `scripts/bench/` 的对照法跑新旧模块的 pps/延迟，确认无回归（内核侧验收口径是实时性/稳定性/规范性）。

实测（2026-09-22，同一台机、同一 `scripts/bench/fwsweep.sh`、`insmod` 新旧模块交替，A 路径 = 白名单未命中 + 封禁表未命中，即分层查表的成本落点，单通路 3 线程、`secs=8`、重复 3 次取中位）：

| 版本 | E 白名单短路 | A 两表未命中 | D 已封禁丢弃 |
|------|------|------|------|
| 旧（精确哈希） | 2.176 / 2.147 µs | 2.237 / 2.220 µs | 1.266 / 1.167 µs |
| 新（分层前缀表） | 2.232 / 2.124 µs | 2.295 / 2.202 µs | 1.263 / 1.219 µs |

A 路径两轮均值差 **+0.9%**，小于同一次运行内本应同路径的 E 与 C 之间的自身离散
（0.02–0.29 µs，即 2–13%）——**无可测回归**。原因与设计一致：未封禁时位图全零，
lookup 一次哈希即返回，与旧哈希表同阶。

## 5. daemon 侧改动

### 5.1 新纯函数

`src/daemon/decision/cluster.rs`：输入（窗口内失败源的 IP + 时间戳、`prefix`、`now`、`M`、`N`、`K`），输出待处置网段与命中 IP 列表。与 `decision/window.rs` 同层，纯计算、无 I/O，便于单测。

复用：
- `src/daemon/state/cidr.rs` 的 `CidrKey::new(addr, 24)` 取网段（`mask_v4`/`mask_v6` 现为私有，需提为 `pub` 或经 `CidrKey` 取）
- `src/daemon/web_ui/analysis.rs` 已有「同 /24 ≥ 3 个不同 IP」的同类分组逻辑（消费封禁历史、用途是推荐白名单），语义应对齐，避免两处判据漂移

### 5.2 接入点

- 判定：`src/daemon/pipeline/mod.rs` 的 `Pipeline::scan_clusters`——集群检测的输入是**跨 IP** 的（同一网段内有多少个不同源），单行判定只看得到一个源，凑不出这个结论，故只能周期判定
- 处置：`src/daemon/pipeline/executor.rs` 的 `dispatch_cluster_hit`，把命中网段按 `(网络地址, prefix_len)` 下发内核

**检测周期必须显著小于 `cluster.window`**（实现取 10 秒 vs 默认窗口 60 秒）。理由：`FailureWindow::peek` 按 `now - ts <= window` 计数，若检测恰好每 `window` 秒跑一次，一批刚写入的失败会在下一次检测前滑出窗口，扫描永远凑不够 `min_ips`。实测：在 `window=600` 的夹具上前者与清理周期（60 秒）同拍时，写入的 4 个源**一个也没被检出**。故检测单独一个短周期，不跟着清理周期走。

检测是纯读（`detect` 不改窗口），故可远快于清理周期重复而不影响窗口状态。

**下发形状**：与白名单路径一致，取 `CidrKey::addr()`（已归一，主机位为零）+ `prefix_len`，对应内核的 `(af, addr, prefix_len)` 三元组；**不要**用 `CidrKey::as_str()` 的 `a.b.c.0/24` 文本——那是给人看与当键用的。

### 5.3 配置项

`YamlJail` 是 `deny_unknown_fields`，新增 `cluster: { enabled, window, min_ips, max_per_ip, ban_time }` 需同步：

1. `src/daemon/config/parser.rs`（`YamlJail` + `apply_jail_definition`）
2. `src/daemon/types/jail.rs`（字段 + `Jail::new` 初值）
3. `src/daemon/pipeline/mod.rs`（`JailPolicy`）
4. `src/daemon/pipeline/executor.rs`（重建规则集时的桥接）
5. `src/daemon/config_reloader.rs`（可回滚字段：捕获/回滚/发布，共 4 处）
6. `src/daemon/jail/config_ops.rs`（参数范围校验）
7. 若透出 HTTP：`contract/http.fwidl` 的 `JailResponse` + `gen.py` + 前端类型

### 5.4 误伤控制与上线顺序

- 网段命中前先查白名单：内核热路径的 `fw_wl_lookup` 在 `fw_ban_lookup` **之前**（`fw_hook.c`），故白名单内的主机即使落在被封网段也照样放行；另外 `fw_ban_try_add` 对「网段地址本身落在白名单覆盖范围内」的下发直接返回 `-EPERM`。两条合起来，白名单 IP 不会被网段封禁波及，无需在 daemon 侧另加白名单前检
- **首版以 audit 模式落地**（`cluster.audit_only: true`，只记录 `检测到集群扫描` 到日志与指标，不封禁），观察一段确无误判再接处置

## 6. 验证计划

| 层 | 方式 |
|---|---|
| 算式 | `decision/cluster.rs` 内嵌 `mod tests`：边界（恰好 N、恰好 K、跨窗口、/24 边界 IP 如 x.y.z.255） |
| 端到端 | `tests/` 新增 pytest：照 `tests/test_21_multi_jail.py` 造多 IP 日志，断言网段被处置 |
| 内核 | `make kernel-module`；封禁表新判定加内核侧对照测试 |
| 契约 | `bash scripts/check_contract.sh`（`netlink.fwidl` 改动后先 `gen.py`） |
| 性能 | `scripts/bench/` 新旧模块对照，确认封禁 lookup 无回归 |

## 7. 分期

1. **P1**：`decision/cluster.rs` + 单测 + audit 日志/指标（零行为变更，可独立合入）
2. **P2**：内核 prefix 封禁（4.x）→ daemon 处置接入（5.2）+ 配置项（5.3）+ pytest
3. 上线顺序：先 audit 观察，确认无误判后再开处置

## 8. 当前实现状态

P1 与 P2 均已落地（2026-09-22）：

| 项 | 落点 |
|---|---|
| 判定算式 | `src/daemon/decision/cluster.rs`（含 9 条内嵌单测） |
| 内核前缀封禁 | `fw_types.h` 分层桶表 + `fw_ban.c` 按 `(af, addr, prefix_len)` 匹配 |
| 线格式 | `contract/netlink.fwidl` 的四个 ban 消息增 `prefix_len` |
| 配置 | `YamlJail.cluster`（全字段 `Option`，逐字段覆盖默认值） |
| 周期检测 | `Pipeline::scan_clusters`，10 秒独立周期，经 `dispatch_cluster_hit` 下发 |
| 端到端 | `tests/test_22_cluster_scan.py`（配置接受 / 单高频 IP 不触发 / 同 /24 多源触发） |

默认 `enabled: false`、`audit_only: true`——**默认关闭，且开启后首版只审计**，与 §5.4 的上线顺序一致。
