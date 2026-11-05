# 内核模块设计决策

本文记录 `src/kernel-module/` 的设计取舍与约束，是实现与评审的依据。
当前实现结构以 [内核模块](../architecture/kernel-module.md) 为准。

热路径的数字与量化目标见[性能基线](perf-baseline.md)，本文只引用不重复。

## 设计决策

| 项 | 结论 | 依据 |
|----|------|------|
| 实现语言 | **C** | 不新增任何构建依赖；softirq / 包基线可直接复用；per-CPU、RCU、位图等语义在 C 中完全可控 |
| 候选语言 | 放弃 | 需新增系统包与工具链才能构建，且已建立的基线要重新标定 |
| 源码组织 | **按职责分层** | 文件划分与数据结构按本节约束；行为以契约与 `tests/` 为准 |
| 契约地位 | 三份 `contract/*.fwidl` 是接口真相源 | 实现不得偏离生成物；要改接口先改契约再改代码 |

## 范围与验收

**范围**：`src/kernel-module/` 全部实现，以及它与守护进程的两条接口面
（netlink、procfs）。

**验收标准**：

| # | 项 | 判据 |
|---|----|------|
| 1 | 全量门禁 | 见 `AGENTS.md` 与根 `Makefile` 定义的门禁目标 |
| 2 | 契约校验 | `contract/verify_procfs.py`、`verify_layout.py`、`verify_http.py` 全绿；契约里每条 defect 要么修复并同步改写契约，要么显式改判为「有意保留」 |
| 3 | 性能指标 | 达到[性能基线](perf-baseline.md)的量化目标全部条目，在同一台机、同一 `scripts/bench/`、同一模块参数下重测 |
| 4 | 集成验收 | `tests/` 全部 pytest 用例通过 |

判定以**内核与守护进程的稳定性 + 性能**为主标准。稳定性优先于绝对值：
目标值定在主机协议栈地板之下时不追求该绝对值，
改为给出「钩子净成本」的对照与地板分解。

三项目标各自的落点：

| 目标 | 落点 |
|------|------|
| 实时性 | 每包 softirq 与热路径结构指标 |
| 稳定性 | 消除无界增长与无上限插入（封禁表、白名单表、自决封禁速率）；消除失败开放的判定分支；清掉不可达代码 |
| 规范性 | 接口以契约为准、三端一致；模块划分按数据所有权切分；文档与实现不再互相矛盾 |

### 结构指标与复测口径

结构问题与目标（采样自 `function_graph`；当前代码未复测）：

| 结构项 | 被否决设计 | 目标 |
|--------|--------|------|
| 速率表查表次数 / 包 | 每包多次重复查表：统计与三类违规检查各查一次 | ≤ 1.0（合并为一次查表） |
| 热路径速率桶自旋锁 / 包 | 只要目的端口非 0 就取桶锁更新端口去重集合 | 0 |
| 热路径共享 cache line 写 / 包 | 直方图与分析表用全局原子累加 | 0（改 per-CPU 聚合） |
| 本机地址判定 | 每包一次 O(N) 线性扫描，集合为空时偏向放行 | O(1) 哈希探测，且不存在空集合窗口 |

**当前设计**：一次查表、热路径不取锁、每包只写本 CPU 内存、
本机地址走开放寻址哈希集。出处见
[内核模块](../architecture/kernel-module.md)「RCU 与锁」「速率表与 per-CPU 槽」。

每条结论都要在同一台机、同一 `scripts/bench/`、同一模块参数下重测才能引用数字。

## 冻结面：必须逐字保持的对外行为

以下内容由契约与 `tests/` 承载，实现**不得改变**。
这些是对外承诺，不是实现细节。

### netlink（`contract/generated/netlink_uapi.h`）

| 项 | 内容 |
|----|------|
| 协议号 | `NETLINK_USERSOCK` |
| 魔数 | `0x46574C4E` |
| 消息头 | 12 字节 |
| 结构 | `packed` |
| 字节序 | 全部多字节整数大端 |
| 地址 | 裸字节，IPv4 占前 4 字节 |
| 单守护进程 | 互斥注册：`DAEMON_REGISTER` 成功后独占；已有活跃守护进程时 `accepted = 0`；注册时先探活旧 portid（已死则立即放行接管），30 秒活动超时作「活着但卡死」的兜底 |
| 硬性要求 | **未注册实例下发的指令必须被拒绝** |
| 变长响应 | 必须分页：`ListBansResponse`、`ListWhitelistResponse`、`ListRatesResponse` 都带 `count` / `total` / `offset` 与尾部元素 |
| 定长响应 | `AnalysisResponse` 全定长，无变长尾部 |
| 位序 | `ConfigFlags`、`DynThresholdFlags` 的位序不可改 |

各消息的定长尺寸与分页上限**不在本文写死**：改一次线格式就全失效。
跑 `python3 contract/gen.py`，它逐条打印定长字节数与
「单条消息上限内最多可承载多少尾部条目」，以那份输出为准。

消息类型数：以 `contract/netlink.fwidl` 为准，不在本文复制。

### procfs（`contract/procfs.fwidl`）

| 项 | 内容 |
|----|------|
| 根目录 | `/proc/firewall` |
| 条目清单 | 以契约的 `file` 声明为准，不在本文写死个数 |
| 唯一机器可读条目 | `stats`：13 行 `key value`，key 名与数值类型不可改 |
| 其余条目 | `read_format = unstable`，实现**允许**改变排版 |
| 权限位 | `bans` / `whitelist` / `config` 为 0600，其余只读条目为 0400 |

三份写文法不可扩展（新增形式须先改契约）：

| 文件 | 命令 | 语义 |
|------|------|------|
| `bans` | `<ip>` / `<ip> <seconds>` / `<ip> 0` / `unban <ip>` | `BAN_DEFAULT` / `BAN_TIMED` / `BAN_PERMANENT` / `UNBAN` |
| `whitelist` | `add <subnet>` / `<subnet>` / `remove <subnet>` | `ADD` / `ADD_IMPLICIT` / `REMOVE` |
| `config` | `ban_time <seconds>` | `BAN_TIME` |

写侧约定：一次 `write(2)` 一条命令；分隔符为空格或制表符；
除 `\t` 外所有 `< 0x20` 字节一律拒绝；失败返回负 errno，无文本错误通道。

### module_param

契约冻结的参数名称与默认值不变。当前共 10 个（`fw_main.c`）：
`fw_ban_time`、`state_file`、`fw_max_bans_per_second`、`fw_max_rate_entries`、
`fw_max_ban_entries`、`fw_max_whitelist_entries`、`fw_max_local_ips`、
`fw_static_threshold`、`fw_dynamic_threshold`、`fw_ddos_detection`。

新增参数只允许追加，不得改既有名称。
取值与 sysfs 权限表见[内核模块](../architecture/kernel-module.md)「模块参数」。

### 判定语义

| 规则 | 内容 |
|------|------|
| 白名单 | 命中 ⇒ 永不封禁 |
| 本机接口精确地址 | 直接放行，且跳过速率判定 |
| 封禁表 | 命中 ⇒ 丢包 |
| DDoS 检测 | 只在「非白名单、非本机地址、未命中封禁表、总开关开启、端口受保护」时运行 |
| 临时封禁到期 | per-entry 定时器摘链，无全局清理线程 |

## 模块划分

按**数据所有权**切分。每个文件只暴露一个窄接口。

当前文件清单与每个文件的对外接口以
[内核模块](../architecture/kernel-module.md)「源文件与数据所有权」为准。

## 数据结构的设计取舍

### 封禁表

保留「哈希桶 + hlist + RCU + 桶锁」这个骨架；该结构未被基线证伪。关键取舍：

| 取舍 | 原因 |
|------|------|
| 删除 `retry_count` | 全仓库只有置零、没有读取点，是不可达字段 |
| 加条目上限 `fw_max_ban_entries` | 无上限插入时，每条封禁都伴随内存分配 + 定时器 + 链表插入 + 事件推送 |
| 让 `ban_table_full_rejects` 有唯一递增点 | 计数器只在真正拒绝时递增，对应契约 defect `PROC_BAN_TABLE_FULL_NEVER_INC` |
| 带 `prefix_len` | 支持网段封禁，见[集群扫描检测设计](cluster-detection-design.md)§4；结构为分层桶表 |

### 白名单

保留「精确桶 + 子网链表」。子网链是必要设计：
命中判定不必为前缀比较遍历全部桶。

| 取舍 | 原因 |
|------|------|
| 加条目上限 `fw_max_whitelist_entries` | 按需扩展必须检查容量，对应 `PROC_WHITELIST_CAPACITY_UNENFORCED` |
| IPv6 比较去冗余 | 桶内候选与子网链候选都拼装一次完整地址再整体比较。条目发布后不再修改，RCU 读者只看得到完整旧值或完整新值 |
| `remove` 的本机地址判定用精确匹配 | 接口配 `/24` 时也只删单条显式白名单（`PROC_WHITELIST_REMOVE_SUBNET_OVERREACH`） |

### 本机地址集合

热路径不能每包线性扫描本机地址，且空集合不得判定为「非本机」。

| 设计 | 原因 |
|--------|------|
| 开放寻址哈希集，键为 `(af, addr)` | 热路径 O(1) 探测 |
| 整张重建后 `rcu_assign_pointer` 发布，旧表交 `kfree_rcu` | 发布是原子的，读者不会看到半成品 |
| 首次地址发现必须在注册钩子之前 | 消除空集合窗口；发现失败即放弃加载 |
| **不扩成子网豁免**：只豁免精确主机地址 | 子网匹配会放大误伤面，且与 `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` 同类的错误模式 |
| 集合容量按下界扩容 | 本机地址数超过参数下界时按需扩，绝不因容量不足漏掉本机地址 |

### 速率表

保留「65536 桶 + hlist + RCU + per-bucket 锁（仅建条目的冷路径）」。
窗口计数不能放在条目共享的原子变量上，否则多核同源流量争用同一条 cache line。
这些原始计数**只在一个地方被读取**：窗口滚动时算新 EWMA。
判定路径读的是平滑值，不读原始计数。

因此：

| 设计 | 依据 |
|--------|------|
| 原始计数移到 per-CPU 槽 | 热路径只写本 CPU 内存 |
| 由 `atomic_cmpxchg(&n->rolling, 0, 1)` 选出的那个 CPU 汇总各槽并清零 | 滚动路径无需自旋锁，热路径全程无锁 |
| 端口去重集合也移到 per-CPU 槽，滚动时取并集 | 热路径不取桶锁，也不做最长 32 项线性扫描 |
| 一条目占一槽，槽号建条目时确定，此后固定 | 见下条 |

槽被别的源地址顶替时先把旧计数冲入所属条目再复用不可行：
折回计数要求跨 CPU 读写该槽，而顶替发生在持桶锁的建条目路径上，
`on_each_cpu(wait=1)` 不能在桶锁内跑；不折回又留下「哈希里还在、槽已易主」的僵尸条目。

因此采用：不顶替。整表探测不到空槽即视为表满，
走契约里记录的**满则放行**（`PROC_RATE_TABLE_FULL_FAILS_OPEN`），
由 `rate_slot_spill` 观测。

表满不能是稳态，所以加了静默回收工作项 `fw_rate_reclaim_work`：
条目静默超过 `FW_RATE_PIN_SECONDS` 即摘链、清各 CPU 槽、`call_rcu` 释放。
代价是重新活跃的源需要约 3 个窗口才把 EWMA 拉回真实速率——
这远比「表满后永久不再检测」便宜。
回收只释放空闲槽，`rate_slot_spill` 只记「满则放行」，两者口径不混。

可跟踪的源地址数上限是 `min(fw_max_rate_entries, FW_RATE_CPU_SLOTS)`，
后者通常是瓶颈。

### 槽表必须分块申请

每 CPU 槽表不能一次 `alloc_percpu`：512 槽 × 168 字节 = 86016 字节。

内核对**单次** per-CPU 申请有 32 KiB 上限：`mm/percpu.c` 对超限 `WARN` 并返回 NULL。
实测（Ubuntu 24.04 GA 的 6.8.0-146）：编译完全正常，`insmod` 报
`Cannot allocate memory`，`dmesg` 给的是
`illegal size (86016) or align (64) for percpu allocation`。

处理：按 `FW_RATE_CHUNK_SLOTS`（128）× `FW_RATE_CPU_CHUNKS`（4）分块申请，
单块 21504 字节，落在上限内。**索引空间与 `slot_idx` 语义不变。**
细节见[内核模块](../architecture/kernel-module.md)「速率表与 per-CPU 槽」。

### 分析直方图与分布表

`pkt_sizes`（5 桶）、`ttl_dist`（6 桶）、`ip_frags` 都是单调直方图，
且每包只落一个 size 桶、一个 TTL 桶。UDP 端口与 ICMP 类型分布同理。

按 per-CPU 无条件累加，读侧（procfs 的 5 个分析条目、netlink `ANALYSIS_QUERY`）
先跨 CPU flush 再求和——复用既有的 `on_each_cpu` 冲刷机制与「读前先刷」纪律。
读侧语义不变：表格内容与条目上限不变。

### 每包共享写的口径

统计口径按**站位数**列出上界：5 个 size 桶是 5 个**站点**，但每个包只落 1 个；
`ttl` 同理 1 个；分片统计是固定的 1 次加可能 1 次。
实际每包原子次数以代码为准，站位数只是上界。

热路径共享写目标为 0。

## 热路径

判定顺序（出处 `fw_hook.c`）：

```
fw_hook_ipv4 / fw_hook_ipv6
  ├─ shutting_down                                    ─ 是 ⇒ NF_ACCEPT
  ├─ skb 为空                                          ─ 是 ⇒ NF_ACCEPT
  ├─ 从 lo 进入（IFF_LOOPBACK）                         ─ 是 ⇒ NF_ACCEPT（不进任何表、不计统计）
  ├─ 报文合法性（长度 / 版本 / 头长 / 校验和）          ─ 非法 ⇒ NF_ACCEPT
  ├─ 源地址合法性（0 / 广播 / 组播 / 回环 / 链路本地）  ─ 非法 ⇒ NF_ACCEPT
  ├─ 基础统计 + 传输层解析                              ← per-CPU，无共享写
  ├─ TCP 标志异常                                       ─ 异常 ⇒ NF_DROP
  ├─ 全局流量累加
  └─ fw_ban_check                                      ← 单次 RCU 临界区
       ├─ fw_wl_lookup
       ├─ fw_local_lookup
       ├─ fw_ban_lookup
       └─ 以上都未命中，且 DDoS 开关开启且 fw_ports_observe(dst_port)
            └─ fw_rate_observe：一次查表 + 窗口滚动 + 违规判定
```

热路径的四条约束：

| # | 约束 | 实现 |
|---|------|------|
| 1 | RCU 临界区只进一次 | 白名单/封禁判定、统计更新、违规判定在同一次进入内完成 |
| 2 | 速率表只查一次 | 统计更新与三类违规检查共用一次查表 |
| 3 | 热路径不取自旋锁 | 端口去重集合在 per-CPU 槽，滚动时取并集 |
| 4 | 热路径无共享 cache line 写 | 直方图、分布、窗口计数、最后活跃时间均为 per-CPU |

### lo 接口豁免为什么和回环地址检查都保留

两条互补，不是重复：

| 判据 | 管什么 |
|------|--------|
| `IFF_LOOPBACK`（接口侧） | 从 lo 进入的流量：本机内部通信，不是外来流量 |
| 源地址回环段（地址侧） | 从外部接口伪造回环源地址的报文 |

### 受保护端口位图（速率判定的作用面）

`fw_ports.c` 维护一张 65536 位（8KB）的端口位图，由守护进程扫描本机对外监听端口
后经 netlink 下发（`SET_PROTECTED_PORTS`）。语义是**纳入防护**，不是豁免。

| 事实 | 说明 |
|------|------|
| 置位端口 | 该端口的入站流量参与 DDoS 速率判定。公网能打到本机的地方就是这些对外监听端口 |
| 未置位端口 | 不参与速率判定，避免内部流量产生误封 |
| 封禁表 | **不受影响**，仍对所有端口生效 |

为什么封禁表不受端口门控：封禁条目由 jail 日志判定或手工下发，
它不该因为某个端口没在对外监听就失效。收窄的只是「谁参与速率判定」。

三条边界语义都要显式保证，缺一条就会静默削弱防护：

| 情形 | 行为 | 理由 |
|------|------|------|
| 位图从未下发（守护进程不在） | **全端口**受保护 | 失败安全：守护进程缺席不等于关检测 |
| 下发全零位图 | 无端口受保护 | 显式关闭，仅供排查与对照；与「从未下发」是两回事 |
| 报文无端口（ICMP、非首片、解析失败） | 一律参与判定 | 按端口收窄作用面，不能顺带关掉没有端口的协议判定（ICMP flood 走这条） |

实现要点：热路径是单次 `test_bit`；换表走 `kzalloc` → 填充 →
`rcu_assign_pointer` → `kfree_rcu(old)` 整体换指针，无索引重建。
线格式是 8192 字节；内核侧存储用 `unsigned long bitmap[]`，
因为 `test_bit` / `bitmap_weight` 要求该类型。
置位数由内核用 `bitmap_weight` 重算，**不采信发送方给的 count**
（展示字段不作为状态依据）。

发现侧（守护进程扫描 `/proc/net/{tcp,tcp6,udp,udp6}`）：

| 判据 | 取值 |
|------|------|
| TCP | 状态 `0A`（LISTEN） |
| UDP | 状态 `07`（未连接绑定）；须排除 `01`（已连接） |
| 环回 | **整个 `127.0.0.0/8`** |

`/proc` 里 IPv4 地址是小端十六进制，首字节落在最后一个字节对上，
所以 `127.0.0.53` 写作 `3500007F`。只看 `0100007F` 会把
systemd-resolved 的 `:53` 误判成对外监听。

语义边界是「本机对外监听的端口」，取保守超集：
路由器 NAT 与上游过滤，本机无从得知。

扫描失败（非「表不存在」）**不下发**。
扫描结果用于收窄保护面，凭残缺数据下发会让漏读那张表里的端口静默失去判定。
「表不存在」等价于空表：未启用 IPv6 的内核本就没有该表。

## 并发与生命周期

**锁**（数目与职责重排，顺序协议文档化在 `fw_types.h`）：

| 锁 | 保护 | 获取 |
|----|------|------|
| 封禁层桶锁 | 层内桶、条目定时器、摘链 | `spin_lock_bh` |
| `ban_layer_lock` | 封禁表的 `used` 位图与层计数；与桶锁**不嵌套** | `spin_lock_bh` |
| `wl_lock` | 白名单表、子网链、计数 | `spin_lock_bh` |
| `rate_locks[bkt]` | 速率桶（仅建条目的冷路径） | `spin_lock_bh` |
| `rate_slot_lock` | per-CPU 槽的「探测空槽 + 发布」 | `spin_lock_bh`，唯一允许的嵌套 |
| `flood_lock` | 泛洪保护窗口 | `spin_lock_bh` |
| `udp_port_lock` / `icmp_type_lock` | 分析表，仅 flush 与惰性建条目 | `spin_lock_bh` |

热路径（软中断上下文）不持有其中任何一把。

**RCU**：封禁条目、白名单条目、速率条目、本机地址集合、分析表条目、端口位图
全部 RCU 发布；删除走 `hlist_del_rcu` + `call_rcu`；
退出路径 `synchronize_rcu` + `rcu_barrier`。

**定时器**：临时封禁用 per-entry `timer_list`，到期在回调内持桶锁摘链、
`call_rcu` 释放、推送 `BAN_STATE_CHANGE`。永久封禁只 `timer_setup` 不 `mod_timer`。
续期路径必须处理「旧回调已在跑」的竞态：在回调内重新比较 `unban_jiffies`，
未到则重武装。持桶锁时不调 `timer_delete_sync()`（会自锁死）。

**workqueue**：netdev 事件后 500 ms 防抖的 delayed work，重建本机地址集合；
另有速率槽的周期回收工作项 `fw_rate_reclaim_work`。

**init / exit 顺序**：

```
init:  参数校验 → 单例与默认值 → 锁/表/原子初始化 → 各子系统 init
       → netlink → 状态恢复 → 本机地址首次发现 → netdev notifier
       → procfs → netfilter hook(v4, v6)
exit:  shutting_down=1 → cancel delayed work → 注销 hook(v4, v6) → synchronize_rcu
       → 注销 notifier → 销毁 procfs → synchronize_rcu → 保存状态 → 全表清理 → netlink
```

| 硬约束 | 原因 |
|--------|------|
| 本机地址首次发现早于注册钩子 | 消除「集合为空即判定非本机」的失败开放窗口；发现失败则放弃注册钩子、整个模块放弃加载 |
| 状态保存早于全表清理 | `fw_state_save()` 要读封禁表与白名单表 |
| netlink 最后销毁 | 前面每一步都可能推送事件 |
| `shutting_down` 双检 | 钩子入口与判定函数各判一次；置位后热路径直接放行，退出不被新流量拖住 |

## 契约修订

契约修订必须**先改契约再改代码**，并走 `contract/` 的校验。
当前内核实现与契约的对应关系：

| 契约位置 | 当前对应 | 说明 |
|----------|----------|------|
| `netlink.fwidl` `DaemonRegisterAck` | 内核把 `accepted` 写入独立字节，`seq` 只作序列号 | 守护进程侧不解析 `accepted` |
| `netlink.fwidl` `ListRatesResponse` | 契约要求分页；内核按 `count` / `total` 返回，单页有上限 | — |
| `procfs.fwidl` `limit bans` | `entries` 取 `fw_max_ban_entries` 的默认值 | — |
| `procfs.fwidl` `limit whitelist` | `entries` 取 `fw_max_whitelist_entries` 的默认值 | — |
| `procfs.fwidl` `limit rates` | `where` 指向对应的模块参数声明 | 位置随参数表变化 |
| `procfs.fwidl` defect 段 | 逐条处置，见下节 | 契约规定：缺陷被修复必须同步改写 |

## 契约缺陷

契约中的缺陷是**契约的一部分**，处置后契约必须同步。

### 处置方式

| 缺陷 | 修法 |
|------|------|
| `PROC_DEAD_UNBAN_FORM`（high） | 删除不可达的 `<ip> -1` 分支与其枚举值，并同步修正文档宣传。若保留该形式则必须让它真正可达——二选一，不留死代码 |
| `PROC_BAN_TABLE_FULL_NEVER_INC`（high） | 加容量上限，使该计数器获得唯一递增点 |
| `PROC_WHITELIST_CAPACITY_UNENFORCED`（medium） | 加容量上限 |
| `PROC_DOC_FORMAT_FICTIONAL`（medium） | procfs 文档按生成物与实现描述真实格式 |
| `PROC_CONFIG_DOC_SAYS_READONLY`（low） | 同上：`config` 为可写（0600，支持 `ban_time`） |
| `PROC_CLEANUP_CYCLES_DEAD`（low） | 保留字段（外部解析依赖），契约改写为「有意保留」并说明理由 |
| `PROC_WRITE_NO_TEXT_ERROR`（low） | 契约改写为「有意保留」：内核侧无文本错误通道是有意设计，原因只进内核日志 |
| `PROC_STATS_STALE_NO_FLUSH`（medium） | 读 `stats` 前调跨 CPU flush，与 netlink `STATS_QUERY` 一致 |
| `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH`（low） | `remove` 的本机地址判定改精确匹配 |
| `DaemonRegisterAck` 载荷错位 | `accepted` 写独立字节，`seq` 只作序列号 |
| `ListRatesResponse` 无分页 | 按 `count` / `total` 分页，单页上限由 `gen.py` 打印 |

每条的当前状态以 `contract/procfs.fwidl`、`contract/netlink.fwidl` 的
defect 段为准，本文不复制。

### 稳定性约束

三条约束都先写入契约再实现：

| # | 约束 | 要求 |
|---|------|------|
| 1 | **泛洪保护覆盖三条封禁路径** | procfs、netlink 指令与 DDoS 自决封禁都检查每秒封禁上限，统一由 `fw_ban_flood_allow()`（`fw_ban_try_add()` 调用）执行 |
| 2 | **失败开放必须显式化** | 「信息不足」时偏向放行只有两处：本机地址集合为空、速率表满。前者不允许出现（发现失败即放弃加载）；后者保留放行——速率表满时丢包会误伤正常流量，契约与设计都写明 |
| 3 | **不导出模块内无调用的符号** | 模块不调用 `EXPORT_SYMBOL` |

## 验收范围

| 项 | 内容 | 验收 |
|----|------|------|
| 模块划分与死代码 | 按数据所有权分文件；删除 `retry_count`、不可达解封分支 | 门禁绿；热路径无共享原子写 |
| 速率热路径 | 一次查表 + per-CPU 窗口计数 + per-CPU 端口去重集合 | 每包查表 ≤ 1 次；热路径无桶自旋锁 |
| 本机地址与分析表 | 开放寻址哈希集 + per-CPU 聚合 | 单通路的未命中与丢弃路径 softirq 达标（目标值见性能基线） |
| 契约 | 修订与缺陷处置 | `make contract-check` 绿；pytest 全绿 |
| 文档 | `docs/zh/architecture/kernel-module.md` 与实现逐项对齐 | 钩子优先级、表结构、白名单容量、`config` 权限、到期机制 |

## 判定纪律

| 纪律 | 内容 |
|------|------|
| 同机同参 | 每项性能结论必须在同一台机、同一 `scripts/bench/`、同一模块参数下重测 |
| 通路数不混用 | 单通路与多通路的数字不得直接比较，多通路有显著跨核争用 |
| pps 不作硬指标 | 打流侧未达自身上限前，测到的 pps 只反映打流能力 |
| 每次测量留证据 | 必须有可复查记录：门禁输出 + 基线对照数据 + 契约校验结果 |

## 相关文档

- [内核模块](../architecture/kernel-module.md)：当前实现
- [性能基线](perf-baseline.md)：口径与测量方法
- [集群扫描检测设计](cluster-detection-design.md)：封禁表加前缀的动因
- [测试](testing.md)：验收命令与 CI 实测结论
