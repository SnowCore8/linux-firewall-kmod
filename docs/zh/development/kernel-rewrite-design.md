# 内核模块重写设计（Phase 1）

本文档是 `src/kernel-module/` 按新设计重写的唯一设计来源。热路径的实测数字与量化目标
见[性能基线](perf-baseline.md)，本文档只引用不重复。

## 决策记录

| 项 | 结论 | 依据 |
|----|------|------|
| 实现语言 | **C**，按新设计重写 | 不新增任何构建依赖；既有 softirq/包基线可直接复用；per-CPU、RCU、static_key 等语义在 C 中完全可控 |
| 旧代码复用 | **不复用** | 新代码不复用旧文件划分、旧数据结构与旧热路径算法。旧实现只作为**行为证据与缺陷证据**的来源 |
| 契约地位 | 三份 `contract/*.fwidl` 是接口真相源 | 重写不得偏离生成物；需要改接口时先改契约再改代码 |
| 上游翻译方案 | **作废** | `rust-kmod-design.md` 描述的「C 逐文件翻译为 Rust」不再执行，见该文件的取代说明 |

> 为什么不是 Rust：本机内核 `6.17.0-35-generic` 有 `CONFIG_RUST=y` 且 `CONFIG_RUSTC_VERSION=108200`
> （rustup 侧 `1.82.0` 工具链已装），但 `build/rust` 指向未安装的
> `linux-hwe-6.17-lib-rust-6.17.0-35-generic`，且 `bindgen` 不存在 —— 需新增系统包才能构建。
> 采用 C 可零依赖推进，且不必对已建立的基线重新标定。

## 范围与验收

**改动范围**：`src/kernel-module/` 全部实现，以及它与 daemon 的两条接口面（netlink、procfs）。

**验收标准**：

1. **全量门禁**通过（见仓库根 `AGENTS.md`／`Makefile` 定义的门禁目标）。
2. **契约校验**：`contract/verify_procfs.py`、`verify_layout.py`、`verify_http.py` 全绿；
   契约中每条 defect 要么被修复并同步改写契约，要么显式改判为「有意保留」。
3. **性能指标**：达到[性能基线 § Phase 1 量化目标](perf-baseline.md#phase-1-量化目标)的全部条目，
   在同一台机、同一 `scripts/bench/`、同一模块参数下重测。
4. **集成验收**：`tests/` 全部 pytest 用例通过。

三项目标各自的落点：

- **实时性** —— 每包 softirq 与热路径结构指标（见量化目标表）。
- **稳定性** —— 消除无界增长与无上限插入（封禁表、白名单表、DDoS 自决封禁速率），
  消除失败开放的判定分支，把「无可达代码」的字段清掉。
- **规范性** —— 接口以契约为准、三端一致；模块划分按数据所有权切分；
  文档与实现不再互相矛盾（含 `docs/zh/architecture/kernel-module.md` 的重写）。

## 冻结面：必须逐字保持的对外行为

以下内容由契约与 `tests/` 承载，重写**不得改变**。它们不是「旧代码」，而是对外承诺。

### netlink（`contract/generated/netlink_uapi.h`）

- 协议号 `NETLINK_USERSOCK`；魔数 `0x46574C4E`；消息头 **12 字节**；全部结构 `packed`；
  全部多字节整数 **大端**；地址为裸字节（IPv4 占前 4 字节）。
- **23 个消息类型**（1–21 历史 + 22 `DAEMON_REGISTER` / 23 `DAEMON_REGISTER_ACK`）。
- 单守护进程互斥注册：`DAEMON_REGISTER` 成功后独占；已有活跃守护进程时 `accepted = 0`；
  活动超时 30 s。**未注册实例下发的指令必须被拒绝。**
- 各消息定长：`DdosEvent` 65、`BanStateChange` 122、`WhitelistStateChange` 51、`CmdResult` 37、
  `ConfigAck` 20、`ConfigChange`/`SetConfig` 116、`StatsResponse` 60、`BanIp`/`UnbanIp` 65、
  `AddWhitelist`/`RemoveWhitelist` 46、`StatsResponse` 系列裸头 12。
- **变长响应必须分页**：`ListBansResponse` 24 + 94×N（N ≤ 696）、
  `ListWhitelistResponse` 16 + 34×N（N ≤ 1927）、`ListRatesResponse` 36 + 84×N（N ≤ 779）。
- `AnalysisResponse` 全定长 **4756 字节**，无变长尾部。
- `ConfigFlags` 13 位、`DynThresholdFlags` 1 位，位序不可改。

### procfs（`contract/procfs.fwidl`）

- 根目录 `/proc/firewall`，**12 个条目**。
- `stats` 是**唯一机器可读**条目：13 个 `key value` 行，key 名与数值类型不可改。
- 其余 11 个条目 `read_format = unstable`，重写**允许**改变排版。
- 权限位：`bans`/`whitelist`/`config` 为 0600，其余 9 个为 0400。
- 三份写文法不可扩展（新增形式须先改契约）：

  | 文件 | 命令 | 语义 |
  |------|------|------|
  | `bans` | `<ip>` / `<ip> <seconds>` / `<ip> 0` / `unban <ip>` | `BAN_DEFAULT` / `BAN_TIMED` / `BAN_PERMANENT` / `UNBAN` |
  | `whitelist` | `add <subnet>` / `<subnet>` / `remove <subnet>` | `ADD` / `ADD_IMPLICIT` / `REMOVE` |
  | `config` | `ban_time <seconds>` | `BAN_TIME` |

- 写侧约定：一次 `write(2)` 一条命令；分隔符为空格或制表符；拒绝除 `\t` 外的所有 < 0x20 字节；
  失败返回负 errno，无文本错误通道。

### module_param

7 个参数，名称与默认值不变（`fw_ban_time`=600、`state_file`=`/var/lib/firewall/state`、
`fw_max_bans_per_second`=200、`fw_max_rate_entries`=65536、`fw_static_threshold`=1、
`fw_dynamic_threshold`=0、`fw_ddos_detection`=1）。新增参数只允许追加，不得改既有名称。

### 判定语义

白名单命中 ⇒ 永不封禁；本机接口精确地址 ⇒ 直接放行；封禁表命中 ⇒ 丢包；
DDoS 检测只在「非白名单且总开关开启」时运行；临时封禁到期由 per-entry 定时器摘链，
无全局清理线程。

## 新模块划分

按**数据所有权**切分，每个文件只暴露一个窄接口，热路径函数放头文件做 `static inline`。

| 文件 | 数据所有权 | 对外接口 |
|------|-----------|---------|
| `fw_types.h` | 无（类型与常量） | 引入契约生成头、内部结构体、`BAN_HASH_BITS` 等常量 |
| `fw_main.c` | 模块生命周期、`fw_info` 单例 | `module_param`、`fw_init`/`fw_exit`、shutdown 状态机 |
| `fw_stats.c` | per-CPU 统计与直方图 | `fw_stat_account()`（热路径）、`fw_stats_flush_local/_all()` |
| `fw_local.c` | 本机地址集合 | `fw_is_local()`（热路径 RCU 读） |
| `fw_wl.c` | 白名单精确桶 + 子网链 | `fw_wl_lookup()`（热路径 RCU 读）、`fw_wl_add/remove()` |
| `fw_ban.c` | 封禁表 | `fw_ban_lookup()`（热路径 RCU 读）、`fw_ban_add/remove()`、per-entry 定时器 |
| `fw_rate.c` | 速率表、窗口、EWMA、违规判定 | `fw_rate_observe()`（热路径，一次查表返回判定） |
| `fw_hook.c` | netfilter 钩子注册与报文解析 | 无（仅注册时暴露 hook 注册表） |
| `fw_netlink.c` | netlink socket 与收发 | `fw_nl_init/exit()`、`fw_nl_send_*()` |
| `fw_procfs.c` | 12 个 procfs 条目 | `fw_procfs_init/exit()` |
| `fw_state.c` | 状态文件读写 | `fw_state_save()`、`fw_state_restore()` |
| `fw_netdev.c` | netdev notifier、本机地址重建 | `fw_netdev_init/exit()` |

旧文件按职责打散重组，新文件不复用旧代码：`netfilter.c` 拆为 `fw_hook.c`（解析）+
`fw_local.c`/`fw_wl.c`/`fw_ban.c`/`fw_rate.c`（判定）；`firewall.h` 拆为
`fw_types.h`（纯类型）+ 各模块私有头；`cleanup.c` 并入 `fw_ban.c`/`fw_state.c`。
`rate-detector.c` 的速率算法**重写**而非搬移（见下节），因为旧的窗口计数方式是本轮要消除的对象。

## 数据结构

### 封禁表

沿用「4096 桶 hlist + RCU + per-bucket 自旋锁」——这不是复用旧算法，而是该结构未被基线证伪
（已封禁路径 1.272 µs 是五条路径中最低）。改动点：

- **删除 `retry_count`**：全仓库只有置零、无读取点。
- **加真正的容量上限**：新增 `fw_max_ban_entries` 模块参数（默认 65535，与 daemon 侧设置项对齐），
  插入前在桶锁内原子检查；到限拒绝并递增 `ban_table_full_rejects`。
- `ban_table_full_rejects` 由此获得唯一的递增点（修复 `PROC_BAN_TABLE_FULL_NEVER_INC`）。

### 白名单

沿用「64 精确桶 + 子网链表」。子网链表是必要设计（避免遍历 64 个桶做前缀比较），保留。

- **加容量上限**：新增 `fw_max_whitelist_entries`（默认 65535），修复
  `PROC_WHITELIST_CAPACITY_UNENFORCED`。
- **IPv6 比较去冗余**：旧实现在「桶内候选」与「子网链候选」两处都做
  `4 × READ_ONCE(u32) + barrier()` 拼装 `struct in6_addr` 再比较。白名单条目在
  `hlist_add_head_rcu` 之后就**不再修改**，RCU 读者只看得到完整旧值或完整新值，
  整体比较即可。改为直接比较整个 `struct in6_addr`；若 KCSAN 对此报数据竞争，
  用 `data_race()` 显式标注，而不是退回逐字拼装。
- **`remove` 的「本机接口 IP」判定改精确匹配**：修复
  `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` —— 旧实现用子网比较，导致接口配 `/24` 时
  整个子网的显式白名单条目都删不掉（`-EPERM`）。

### 本机地址集合

旧实现是「数组 + 每包 O(N) 线性扫描 + 掩码比较」，且 `count == 0` 时直接返回「非本机」。
改为**开放寻址哈希集**：

- key 为 `(af, addr)`，容量固定（默认 256，模块参数 `fw_max_local_ips`），
  以 `af` + 完整地址精确匹配。
- 重建路径：`fw_netdev.c` 在 notifier 与 init 中构建**新表**，`rcu_assign_pointer` 发布，
  旧表交 `kfree_rcu`。发布是原子的，读者不会看到半成品。
- `count == 0` 的退化态被消除：钩子注册发生在首次地址发现**之后**，运行期不存在空表窗口。
- **不扩成子网豁免**：只豁免精确主机地址。旧实现在此处的教训正是
  `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH` 的同一个错误模式。

### 速率表

沿用「65536 桶 hlist + RCU + per-bucket 锁（仅建条目的冷路径）」。窗口内计数的方式**重写**：

- 旧实现的窗口内计数（`packet_count`、`byte_count`、`syn/udp/icmp/ack/rst/fin_count`）
  是**共享 `atomic64_t`**，每包在多核间争用同一条 cache line。
- 这些原始计数**只在一个地方被读取**：窗口滚动时计算新 EWMA。
  判定路径读的是 `smoothed_*`（已平滑值），不读原始计数。
- 因此把原始计数移到 **per-CPU 槽位**：每 CPU 一组直接映射槽
  `{af, addr, packets, bytes, syn, udp, icmp, ack, rst, fin, seen_ports[32], seen_port_n, last_activity}`。
  热路径只写本 CPU 内存；窗口滚动时（持桶锁的那个 CPU）汇总各 CPU 槽位并清零。
- 槽位被不同源地址顶替时，**先把旧槽位归属的计数冲入对应条目**再复用，不允许静默丢计数
  （速率检测不能容忍丢计数；分析类计数可以，见下）。

### 分析直方图

`pkt_size_*`（5 桶）、`ttl_*`（6 桶）、`ip_total_count`/`ip_frag_count` 都是单调直方图，
且每包只落一个 size 桶、一个 TTL 桶。改为 **per-CPU 无条件累加**，
读侧（procfs 的 5 个分析条目、netlink `ANALYSIS_QUERY`）先跨 CPU flush 再求和——
复用既有的 `on_each_cpu` 冲刷机制与「读前先刷」纪律。

### UDP 端口 / ICMP 类型分布

上限 512 / 128，当前在热路径做「全局表查找 + 命中即 2 次 `atomic64` 与一次 `WRITE_ONCE`」。
改为 per-CPU 直接映射槽累加，达批次阈值或读侧 flush 时并入全局表。
读侧语义不变（表格内容与条目上限不变）。

## 热路径重设计

### 判定顺序（新）

```
nf_hook(ipv4/ipv6)
  ├─ 报文合法性（长度/版本/校验和/首片/扩展头深度）  ─ 非法 ⇒ ACCEPT
  ├─ 源地址合法性（0/广播/回环/组播/link-local）      ─ 非法 ⇒ ACCEPT
  ├─ fw_stats_account_basic()      ← per-CPU，无共享写
  ├─ 传输层解析 + 协议异常判定（TCP 标志异常）        ─ 异常 ⇒ NF_DROP
  └─ fw_ban_check(af, src, ...)    ← 单次 RCU 临界区
       ├─ 1 次查表：fw_wl_lookup()
       ├─ 1 次查表：fw_ban_lookup()
       ├─ 本机地址：fw_is_local()          （哈希 O(1)）
       └─ 非白名单且 DDoS 开启 ⇒ fw_rate_observe()
            └─ 内部：1 次查表，同一指针完成窗口滚动 + 四类违规判定
```

与旧结构的关键差别：

1. **RCU 临界区只进一次**。旧实现先进一次做白名单/封禁判定、退出、调
   `update_rate_stats`、再进一次做违规判定，共 3 处 `rcu_read_lock` 配对。
2. **速率表只查一次**。旧实现的 `update_rate_stats`、`check_rate_violation`、
   `check_protocol_violation`（或 `check_tcp_flood_violation`）各自调用
   `find_rate_entry_rcu`，合计 2.81 次/包。新实现把 `ip_rate_entry *` 从一次查表
   一路传下去。
3. **热路径无自旋锁**。旧实现在「窗口未过期」的快速路径上，只要 `dst_port > 0`
   就取速率桶锁去更新 `seen_ports`（最多 32 项线性扫描）。端口去重集合移到 per-CPU 槽，
   窗口滚动时取并集。
4. **热路径无共享 cache line 写**。直方图、UDP/ICMP 分布、速率窗口计数、`last_activity`
   全部落 per-CPU 内存。

### 每包共享 cache line 写：基线口径更正

性能基线文档把「≈11」记为每包原子次数，这个口径需要更正为**站位数**：
`record_packet_size` 5 个桶是 5 个**站点**，但每个包只落 1 个；`record_ttl` 同理 1 个；
`record_ip_frag` 是固定的 1 次（`ip_total_count`）加可能 1 次（`ip_frag_count`）。
按代码逐包计数：

| 路径 | 每包共享原子写 | 每包自旋锁 |
|------|---------------|-----------|
| 白名单命中 / DDoS 关闭（UDP 流量） | 6（size 1 + ttl 1 + ip_total 1 + UDP packet/byte/last_seen 3） | 0 |
| DDoS 开启（UDP 流量） | 10（上面 6 + 速率条目 packet/byte/udp/last_activity 4） | 1 |
| 已封禁丢弃 | 0 | 0 |

新设计的对应值为 **0**，优于「≤2」的目标。

## 并发与生命周期

**锁**（数目与职责重排，顺序协议文档化在 `fw_types.h`）：

| 锁 | 保护 | 获取方式 |
|----|------|---------|
| `ban_locks[4096]` | 封禁桶、条目定时器、摘链 | `spin_lock_bh` |
| `wl_lock` | 白名单表、子网链、计数 | `spin_lock_bh` |
| `rate_locks[65536]` | 速率桶、窗口滚动 | `spin_lock_bh` |
| `flood_lock` | 封禁速率窗口 | `spin_lock_bh` |
| `udp_port_lock` / `icmp_type_lock` | 分析表（仅 flush 与惰性建条目） | `spin_lock_bh` |

热路径（软中断上下文）不持有其中任何一把。旧的「全局锁 + 桶锁不嵌套」与
「桶锁 → `active_bans_lock` 单向」两条顺序协议保留并写进头文件注释。

**RCU**：封禁条目、白名单条目、速率条目、本机地址表、分析表条目全部 RCU 发布，
删除走 `hlist_del_rcu` + `call_rcu`，退出路径 `synchronize_rcu` + `rcu_barrier`。

**定时器**：临时封禁用 per-entry `timer_list`，到期在回调内持桶锁摘链、`call_rcu` 释放、
推送 `BAN_STATE_CHANGE`。永久封禁只 `timer_setup` 不 `mod_timer`。续期路径必须处理
「旧回调已在跑」的竞态（旧实现的做法保留：在回调内重新比较 `unban_time`，未到则重武装）。

**workqueue**：仅 1 个 delayed work，netdev 事件后 500 ms 防抖，重建本机地址表。
无周期性工作。

**init/exit 顺序**：

```
init:  参数校验 → 锁/表/原子初始化 → 速率默认值 → netlink → 状态恢复
       → 本机地址首次发现 → netdev notifier → procfs → netfilter hook(v4,v6)
exit:  shutting_down=1 → cancel delayed work → 注销 hook(v4,v6) → synchronize_rcu
       → 注销 notifier → 销毁 procfs → synchronize_rcu → 保存状态 → 全表清理 → netlink
```

`shutting_down` 是热路径的第一道判断（双检），置位后热路径直接放行，保证退出不被新流量拖住。

## 契约修订清单

重写允许改契约，但必须**先改契约再改代码**，且走 `contract/` 的校验。Phase 1 需要以下修订：

| 契约位置 | 修订 | 原因 |
|----------|------|------|
| `netlink.fwidl` `DaemonRegisterAck` | 无需改（已是正确的意图定义） | 修的是内核实现：旧实现把 `accepted` 写进 `seq` 低字节，daemon 侧完全不解析 |
| `netlink.fwidl` `ListRatesResponse` | 无需改（已要求分页） | 修的是内核实现：旧实现无分页无上限，`msg_len` 在 780 条以上回绕 |
| `procfs.fwidl` `limit bans` | `entries` 从 `none` 改为新参数的默认值 | 新增 `fw_max_ban_entries` |
| `procfs.fwidl` `limit whitelist` | `entries` 从 `none` 改为新参数的默认值 | 新增 `fw_max_whitelist_entries` |
| `procfs.fwidl` `limit rates` | `where` 指向新的模块参数声明行 | 行号会变 |
| `procfs.fwidl` defect 段 | 逐条处置（见下节） | 契约规定：缺陷被修复就必须同步改写 |

## 缺陷处置

契约中的缺陷是**契约的一部分**，处置后契约必须同步。内核侧共 10 条（`procfs.fwidl`）+
2 条（`netlink.fwidl`），另有 3 条本次新查出的稳定性问题。

### 修复

| 缺陷 | 修法 |
|------|------|
| `PROC_DEAD_UNBAN_FORM`（high） | 删除不可达的 `<ip> -1` 分支与其枚举值；同步修正 README 与 `docs/*/configuration/procfs.md` 的宣传。若决定保留该形式，则必须让它真正可达（改 `validate_duration_string` 接受负号）——二选一，不留死代码 |
| `PROC_BAN_TABLE_FULL_NEVER_INC`（high） | 加容量上限，获得唯一递增点（见「封禁表」） |
| `PROC_WHITELIST_CAPACITY_UNENFORCED`（medium） | 加容量上限（见「白名单」） |
| `PROC_DOC_FORMAT_FICTIONAL`（medium） | 重写 `docs/{zh,en}/configuration/procfs.md`，按生成物与实现描述真实格式 |
| `PROC_CONFIG_DOC_SAYS_READONLY`（low） | 同上，`config` 为可写（0600，支持 `ban_time`） |
| `PROC_CLEANUP_CYCLES_DEAD`（low） | 保留字段（外部解析依赖）但注释说明恒为 0；契约改写为「有意保留」并说明理由 |
| `PROC_WRITE_NO_TEXT_ERROR`（low） | 契约改写为「有意保留」：内核侧无文本错误通道是有意设计，错误原因只进内核日志 |
| `PROC_STATS_STALE_NO_FLUSH`（medium） | `stats_show` 读前调用跨 CPU flush，与 netlink `STATS_QUERY` 一致 |
| `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH`（low） | `remove` 的「本机接口 IP」判定改精确匹配（见「白名单」） |
| `DaemonRegisterAck` 载荷错位 | `accepted` 写独立字节，`seq` 只作序列号 |
| `ListRatesResponse` 无分页 | 按 `count`/`total` 分页，单页 ≤ 779 条 |

### 本次新查出的稳定性问题（需先写入契约再修）

1. **泛洪保护只在 procfs 路径生效**。`check_flood_protection()` 全仓库唯一调用点是
   `procfs.c:264`；netlink 指令路径与 DDoS 自决封禁路径都不检查 `fw_max_bans_per_second`。
   后果：内核自决封禁与 daemon 下发封禁都无速率上限，每条封禁都伴随 `kmalloc` + 定时器 +
   链表插入 + netlink 事件。修法：三条路径统一经过同一道速率闸门。
2. **失败开放的判定分支**：本机地址 `count == 0` 与速率表 `-ENOSPC` 这两处都在
   「信息不足」时偏向放行。前者的空表窗口在重构后消失；后者的行为需在契约里明确
   （推荐保留放行，因为速率表满时丢包会误伤正常流量，但必须写进设计说明而不是隐式）。
3. **`is_banned()` / `is_permanently_banned()` 只有 `EXPORT_SYMBOL`、模块内无调用点**。
   若确认无外部使用者，删除导出；否则说明使用者。

## 分阶段实施与验收

每阶段独立可测、独立提交、独立回退。前置依赖为 0。

| 阶段 | 内容 | 验收 |
|------|------|------|
| **1.A** | 模块划分重组 + 直方图 per-CPU 化 + 删除死代码（`retry_count`、`proc_settings`、不可达解封分支） | 门禁绿；A/E 组每包 softirq 下降；无共享原子写（A 组 6 → ≤3） |
| **1.B** | 速率热路径重写：一次查表 + per-CPU 窗口计数 + per-CPU 端口去重集合 | `find_rate_entry_rcu` ≤1.0 次/包；热路径无 `_raw_spin_lock_bh`；B 组每包 softirq 达标 |
| **1.C** | 本机地址改哈希 + UDP/ICMP 分析表 per-CPU 化 | 单通路 A 组 ≤1.8 µs；已封禁 D 组 ≤1.0 µs |
| **1.D** | 契约修订 + 10 条缺陷逐条处置 + 新增 3 条稳定性问题修复 | `contract/*` 校验绿；pytest 全绿 |
| **1.E** | 文档重写：`docs/{zh,en}/architecture/kernel-module.md` 按新实现全量重写 | 文档与代码逐项对齐（钩子优先级、哈希结构、白名单容量、`config` 权限、过期机制） |

`docs/zh/architecture/kernel-module.md` 目前与实现严重不符，1.E 必须处理：
`priority` 实际是 `NF_IP_PRI_FILTER - 1` 而非 `NF_IP_PRI_FIRST`；`HASH_TABLE_SIZE 4096` 的
`struct banned_ip` 不存在；`WHITELIST_SIZE 64` 数组已改为哈希桶 + 子网链；
`config` 实为可写；「全局清理线程」实为 per-entry 定时器。

## 判定纪律

- 每项性能结论必须在同一台机、同一 `scripts/bench/`、同一模块参数下重测。
- 单通路与多通路的数字**不得混用**比较（多通路有显著跨核争用）。
- 打流侧未达上限前，pps 上限不作为硬指标。
- 每阶段结束必须有可复查增量：门禁输出 + 基线对照数据 + 契约校验结果。
