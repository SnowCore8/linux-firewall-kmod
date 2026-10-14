# 性能口径与测量方法

本文给出**验收口径**与**可复现的测量方法**。

旧文档里的 µs / pps 绝对数字已删除：它们测的是重构前的实现，
不能拿来当现状。方法部分仍可核对（脚本在 `scripts/bench/`）。

## 本文档的口径

| 类型 | 处理 |
|------|------|
| 红线定义 | 照 `STANDARDS.md` 抄，标明出处 |
| 结构口径 | 读当前代码即可核对，标明出处 |
| 测量方法 | 脚本存在、参数可读，照脚本注释描述 |
| 绝对数字 | **未验证**：本次重写未复跑任何测量 |

任何一次对外引用性能数字，都必须先用下面的方法实测，并注明机器、内核版本、
通路数与模块参数。

## 红线：什么时候算性能问题

出处：`STANDARDS.md`。

| 定级 | 判据 |
|------|------|
| Critical | 性能下降 > 30%（在目标场景 10Gbps 下） |
| High | 性能下降 10–30%（非热路径或低频操作） |

`STANDARDS.md` 另外两条口径：

- 核心功能性能优化按 10Gbps 热路径定优先级。
- 10Gbps 场景下的性能问题优先于其他场景。

因此**验收口径是 10Gbps 场景的相对变化**，不是某个绝对 µs 数。
仓库内没有 10Gbps 场景的实测记录（未验证）。

## 结构口径：读代码能确定的部分

这些是设计上的硬约束，逐条能在源码里点到位置。

| 项 | 现状 | 出处 |
|----|------|------|
| 封禁查找 | 哈希表。按 `prefix_len` 分层的桶表；精确层（/32、/128）常态一次哈希即返回 | `src/kernel-module/fw_ban.c` 的 `fw_ban_lookup` |
| 白名单查找 | 精确桶（64）+ 子网链两步匹配 | `fw_wl.c` 的 `fw_wl_lookup` |
| 本机地址查找 | 开放寻址哈希集，线性探测 | `fw_local.c` 的 `fw_local_lookup` |
| 速率表 | 65536 桶哈希 + per-CPU 直接映射槽 | `fw_types.h` 的 `RATE_HASH_BITS`、`FW_RATE_CPU_SLOTS` |
| 每包查表次数 | 一次：`fw_rate_observe` 查表拿到条目指针，同一指针完成窗口滚动与违规判定 | `fw_rate.h` 与 `fw_rate.c` |
| 热路径 RCU 临界区 | 一次：四张表在同一次 `rcu_read_lock` 内读完 | `fw_hook.c` 的 `fw_ban_check` |
| 热路径自旋锁 | 速率桶锁只在建条目的冷路径取；热路径全程无锁 | `fw_types.h` 锁顺序协议注释、`fw_rate.c` |
| 热路径共享写 | 统计与速率窗口原始计数落 per-CPU；跨 CPU 汇总只在窗口滚动与读侧 flush | `fw_stats.c`、`fw_rate.c` |
| 到期清理 | per-entry 定时器，无全局扫描线程 | `fw_ban.c` 的 `fw_ban_expire_cb` |
| 端口门控 | 单次位测试 `test_bit`；位图整体换指针 | `fw_ports.c`、`fw_ports.h` |

### 复杂度口径

| 操作 | 复杂度 | 依据 |
|------|--------|------|
| 封禁 / 白名单 / 速率查找 | 平均 O(1) | 哈希定位桶，桶内链表比较 |
| 封禁插入 / 删除 | 平均 O(1) | `hlist_add_head_rcu` / `hlist_del_rcu` |
| 本机地址查找 | 平均 O(1) | 线性探测到空槽即判定不存在 |
| 短前缀封禁层遍历 | O(已用层数) | 只遍历 `used` 位图置位的层，常态 1–3 层 |

桶数不等于条目上限。上限由模块参数给出，见
[内核模块](../architecture/kernel-module.md)「表结构」。

## 测量方法

工具在 `scripts/bench/`：

| 文件 | 作用 |
|------|------|
| `blast2.c` | 发包器（多线程 `sendmmsg`） |
| `sink.c` | 只 `bind` 不 `recv` 的接收端 |
| `fwflow.sh` | 单条 IPv4 打流通路：netns（打流侧）→ veth → init_net（收侧 sink） |
| `fwsweep.sh` | 五条路径的每包成本对照 |
| `mflow.sh` | N 条通路并发，测跨核争用 |
| `fwctl.sh` | 无钩子对照组 |
| `Makefile` | `make` 构建 `blast2` 与 `sink`，只依赖 libc 与 pthread |

构建产物 `blast2`、`sink` 都不入库。

### 复现步骤

按 `scripts/bench/` 各脚本头部注释的命令：

```bash
# 1) 构建发包器与 sink
sudo make -C scripts/bench

# 2) 起一条打流通路，记下打印的 NS_PID（前台运行，Ctrl-C 自动清理）
sudo scripts/bench/fwflow.sh 10.99.0.11 10.99.0.1 9999

# 3) 另一个终端跑五路径对照
sudo scripts/bench/fwsweep.sh <NS_PID> 8 3 3

# 4) 无钩子对照
sudo scripts/bench/fwctl.sh 8 3

# 5) 多通路并发
sudo scripts/bench/mflow.sh 4
```

打流期间脚本会读写 `/proc/firewall/{bans,whitelist,stats}` 与模块参数
`fw_ddos_detection`，结束时恢复为 `1`。脚本只增删自己的 veth 与子进程。

### 四条方法约束

这四条不是习惯，缺一条数据就失真。出处都写在对应脚本的注释里。

| 约束 | 原因 |
|------|------|
| **必须跨 netns 架 veth** | 钩子只注册在 `init_net`。`lo` 与 `127.0.0.0/8` 的流量到不了钩子；单个 netns 内部的流量不出该 netns，也不经过 init_net 的 `NF_INET_PRE_ROUTING`。本机 `ip netns add` 报 `Invalid argument`，改用 `unshare -n` 长驻进程持有 netns + `ip link set <dev> netns <pid>` |
| **收侧必须是不读数据的 sink** | 读取型接收端会让未匹配的 UDP 包触发 ICMP 端口不可达，每个请求多一个应答包再走一趟钩子。sink 只 `bind` 不 `recv`：包仍走本地投递与 netfilter，但无 ICMP 反噬、无用户态 CPU |
| **看 softirq 而不是总 CPU** | `blast2` 在 ~1 Mpps 时自身要吃掉数核的用户态 CPU（`sendmmsg` 系统调用），总 CPU 增量会被发送侧淹没。每包成本 = `/proc/stat` 第 8 字段的增量 ÷ 处理包数 |
| **固定一个「不在白名单」的源地址** | 内核会把本机接口 IP 自动加进白名单。源地址一旦被收录，钩子就走白名单短路，五组对照退化成同一条路径。收侧接口配 `/32`、打流侧配 `/24` |

### 五条对照路径

`fwsweep.sh` 的路径定义（同一源地址）：

| 组 | 配置 | 含义 |
|----|------|------|
| E | `ddos` 关 + 白名单 | 钩子最短路径 |
| A | `ddos` 关 + 非白名单 | 白名单未命中 + 封禁表未命中；分层查表的成本落点 |
| B | `ddos` 开 + 非白名单 | A 再加速率引擎 |
| C | `ddos` 开 + 白名单 | 与 E 同路径，用来估算开关噪声 |
| D | 已封禁 | 命中 → `NF_DROP` |

C 与 E 理论上同路径，二者之差就是本次测量的自身离散。
引用任何单条路径的数时，先给出这个离散量。

### 「无钩子对照」的口径缺陷

`fwctl.sh` 把 veth **两端都放进同一个新 netns**。
这条流的收发、路由、netfilter 框架、本地投递都与主测量一致，
唯一差别是不出该 netns，因此不经过注册在 `init_net` 上的钩子。

但 init_net 侧还挂着 `nf_conntrack` 与 nftables 的 nat 规则。
两条流的「地板」不同，所以「主测量 − fwctl」混算了两条不同地板，
**会高估钩子净成本**。

干净口径是**同一条流、模块 ON 与 `rmmod` OFF 相减**。
`scripts/bench/fwctl.sh` 的注释仍写着旧口径，读脚本时注意这一点。

### `function_graph` 只能定位结构，不能当成本

两条污染：

| 污染 | 说明 |
|------|------|
| 固定膨胀 | 每条被跟踪调用有约 0.4 µs 的固定开销；每包几十次被跟踪调用会累出十几 µs |
| 中断污染 | 落在被跟踪区间里的定时器中断会被算进模块耗时 |

所以结构指标（每包查表次数、每包锁次数）用 `function_profile` 的计数比，
成本结论用 softirq/包。

## 判定纪律

| 纪律 | 内容 |
|------|------|
| 同机同参 | 每项结论必须在同一台机、同一份 `scripts/bench/`、同一模块参数下重测 |
| 通路数必须注明 | 单通路与多通路的数字不得混用比较；多通路有跨核争用 |
| pps 不作为硬指标 | 打流侧未达自身上限前，测到的 pps 只反映打流能力 |
| 相对变化优先 | 绝对数随 CPU、内核版本、网卡变化；红线看相对下降比例 |
| 结论要有出处 | 引用数字时注明测量日期、内核版本（`uname -r`）、通路数、脚本与参数 |

## 待补的实测

以下是本文件目前欠的账，补齐后才能把数字写回文档：

| 项 | 状态 | 怎么补 |
|----|------|--------|
| 10Gbps 目标场景的每包成本 | 未验证 | 需要能产生 10Gbps 的环境；`scripts/bench/` 的打流侧不足以覆盖 |
| 五条路径的当前每包 softirq | 未验证 | `sudo scripts/bench/fwsweep.sh <NS_PID> 8 3 3` |
| 多通路并发下的跨核争用 | 未验证 | `sudo scripts/bench/mflow.sh 4` |
| 钩子净成本（ON/OFF 同流相减） | 未验证 | 同一条流分别 `insmod` / `rmmod` 各测一轮 |
| 封禁查找的每次哈希成本 | 未验证 | `function_profile` 计数 + softirq 对照 |
| 速率表满（`rate_slot_spill` 非零）时的行为成本 | 未验证 | 构造活跃源超过 512 的流量 |

## 相关文档

- [内核模块](../architecture/kernel-module.md)：结构与常量
- [测试](testing.md)：三层测试与 CI 实测结论
- `STANDARDS.md`：定级与红线定义
