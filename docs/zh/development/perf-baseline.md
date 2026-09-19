# 内核热路径性能基线

本文记录**重写前**的热路径实测基线，用于给 Phase 1 内核重写定可判定的量化目标，
并给出可复现的测量方法（脚本在 `scripts/bench/`）。

主机的绝对数字会随 CPU、内核版本、网卡变化；**方法是可移植的，数字只作参照**。
任何一次重写后的对比，都必须用同一台机器、同一份 `scripts/bench/` 重新跑。

## 测量环境

| 项 | 值 |
|------|------|
| 内核 | `6.17.0-35-generic` |
| CPU | 8 逻辑核，无 `isolcpus` |
| 模块 | 已加载的 `firewall.ko` srcversion `229754D1C290E8A436A112B`，与 `build/kernel-module/firewall.ko` 一致 |
| 钩子 | `nf_register_net_hook(&init_net, ...)`，`NF_INET_PRE_ROUTING`，`priority = NF_IP_PRI_FILTER - 1` |
| 模块参数 | `fw_ddos_detection=1`（默认）、`fw_static_threshold=1`、`fw_dynamic_threshold=0` |

## 方法

### 为什么必须跨命名空间架 veth

钩子只注册在 **init_net**。两种常见测法都到不了钩子：

- `lo` 与 `127.0.0.0/8`：`netfilter.c` 在入口提前 `return`，且 `skb->dev->flags & IFF_LOOPBACK` 会被跳过；
- 单个 netns 内部的流量：不出该 netns，不会经过 init_net 的 `NF_INET_PRE_ROUTING`。

所以要在两个 netns 之间架 veth，让包**跨 netns 边界进入 init_net**。
本机 `ip netns add` 报 `Invalid argument`（`/var/run/netns` 挂载方式不被支持），
改用 `unshare -n` 长驻进程持有 netns + `ip link set <dev> netns <pid>`。

### 为什么收侧必须是不读数据的 sink

若收侧是「读取型」接收端，未匹配的 UDP 包会让内核回 **ICMP 端口不可达**，
每个请求额外多出一个应答包并再走一趟钩子，测量随之失真。
sink 只 `bind` 不 `recv`：包仍走本地投递与 netfilter，收侧既无 ICMP 反噬也无用户态 CPU 开销。

### 为什么看 softirq 而不是总 CPU

`blast2` 在 ~1 Mpps 时自身要吃掉数核的用户态 CPU（sendmmsg 系统调用），
总 CPU 增量会被发送侧淹没。softirq（`/proc/stat` 第 8 字段）才是协议栈 +
netfilter + 钩子的落点，因此每包成本一律用 softirq 增量除以处理包数。

### 为什么固定一个「不在白名单」的源地址

内核会把本机接口 IP 自动加进白名单（`netdev.c` 地址发现，`device_name` 为接口名）。
源地址一旦被自动收录，钩子就走白名单短路分支，五组对照会退化成同一条路径。
另外 `procfs` 的白名单 `remove` 用**接口子网**判定本机 IP
（见 `contract/procfs.fwidl` 的 `PROC_WHITELIST_REMOVE_SUBNET_OVERREACH`），
故收侧接口配 `/32`、打流侧配 `/24`，否则同网段的对照源地址无法从白名单删除。

### 为什么对照必须含一条「无钩子」流

单看「已封禁 9.7 µs/包、未命中 18.1 µs/包」无法区分哪部分是钩子的、哪部分是协议栈本身的。
`fwctl.sh` 在同 netns 内 veth 互打，收发/路由/netfilter 框架/本地投递完全一致，
只少了钩子，其差值即钩子净成本。

## 复现步骤

```bash
# 1) 构建发包器与 sink
sudo make -C scripts/bench

# 2) 起一条打流通路，记下打印的 NS_PID（前台运行，Ctrl-C 自动清理）
sudo scripts/bench/fwflow.sh 10.99.0.11 10.99.0.1 9999

# 3) 另一个终端里跑五路径对照
sudo scripts/bench/fwsweep.sh <NS_PID> 8 3 3

# 4) 无钩子对照
sudo scripts/bench/fwctl.sh 8 3
```

脚本只增删自己的 veth 与子进程，退出即清理。打流期间会读写
`/proc/firewall/{bans,whitelist,stats}` 与模块参数 `fw_ddos_detection`，结束会恢复为 `1`。

## 实测结果

### 五路径每包 softirq 成本

单通路 3 线程，`secs=8`，重复 3 次取中位（`scripts/bench/fwsweep.sh`）：

| 路径 | 处理量（中位） | softirq（中位） | 每包 |
|------|------|------|------|
| E) `ddos`关 + 白名单（最短路径） | 6,258,765 | 13.470 s | **2.15 µs** |
| A) `ddos`关 + 非白名单（两表未命中） | 5,707,857 | 14.040 s | **2.46 µs** |
| B) `ddos`开 + 非白名单（+速率引擎） | 5,754,122 | 13.990 s | **2.44 µs** |
| C) `ddos`开 + 白名单（对照 E） | 6,226,313 | 13.500 s | **2.17 µs** |
| D) 已封禁（命中 → `NF_DROP`） | 8,256,448 | 10.500 s | **1.27 µs** |

### 无钩子对照与钩子净成本

同 netns 内 veth 互打，3 次：**0.67 / 0.68 / 0.69 µs/包**（`scripts/bench/fwctl.sh`）。

单通路下钩子净成本（主测量的每包 softirq − 对照基线）：

| 路径 | 每包 | 减对照后（钩子净） |
|------|------|------|
| E 白名单短路 | 2.15 µs | ≈ **1.5 µs** |
| A 两表未命中 | 2.46 µs | ≈ **1.8 µs** |
| D 已封禁丢弃 | 1.27 µs | ≈ **0.6 µs** |

> 注意：多通路并发时（`mflow.sh`，4 通路）每包 softirq 升到 **4.6 µs**，
> 说明跨核争用（共享计数器的 cache line ping-pong）显著。
> 单通路与多通路的绝对数不可直接相比，引用时必须注明通路数。

### pps 上限（本机打流侧受限）

| 场景 | 生成侧 | 钩子处理 |
|------|------|------|
| 单通路，单线程 | 250 Kpps | 与生成侧一致（无丢包） |
| 单通路，8 线程 | 1.07 Mpps | 1.07 Mpps |
| 4 通路并发（各 2 线程） | 0.97 Mpps | 0.97 Mpps |

**打流侧上限约 1.5 Mpps/通路**，单通路压不满 8 核；钩子始终未成为丢弃点
（生成侧包数 == 钩子处理包数，无 `packets_dropped`）。

模块重载后测过的**历史峰值**（`fw_ddos_detection=0`、无白名单、单通路多线程）：

- 接受路径：**2.21 Mpps**（4 线程即饱和，单核瓶颈）；
- 丢弃路径（已封禁）：**2.74 Mpps**。

### 静态结构与 `function_graph`

`function_graph` 采样（n=715）给出每包内核操作次数与模块自有函数耗时：

| 项 | 每包 |
|------|------|
| `__rcu_read_lock` / `__rcu_read_unlock` | 各 3.16 次 |
| `find_rate_entry_rcu` | 2.81 次 |
| `_raw_spin_lock_bh` | 0.71 次 |
| `update_rate_stats` | 0.71 次 |
| `check_rate_violation` / `check_protocol_violation` / `check_tcp_flood_violation` | 各约 0.7 次 |

模块自有函数 `function_graph` 耗时（p50）：

| 函数 | p50 |
|------|------|
| `nf_hook_func_ipv4` | 26.1 µs |
| `handle_ban_check` | 23.3 µs |
| `update_rate_stats` | 8.3 µs |

> **`function_graph` 的绝对值不可直接当成本**：每条被跟踪调用有约 0.4 µs 的固定膨胀，
> 每包约 65 次被跟踪调用 → 约 25 µs，正好解释了 26 µs 与实测 2.15 µs 之间的量级差。
> 另需剔除中断污染：最长块 151 µs 中约 134 µs 是
> `__sysvec_apic_timer_interrupt` → `hrtimer_interrupt` 落入被跟踪区间，不是本模块代码。
> 因此**结论以计数器口径（softirq/包）为准，`function_graph` 只用于定位结构问题**。

## 定位到的热路径结构问题

1. **每包多次重复查表**：`update_rate_stats` 内先 `find_rate_entry_rcu`，
   随后 `check_rate_violation`、`check_protocol_violation`、`check_tcp_flood_violation`
   各自再查一次（合计 2.81 次/包），同一个源 IP 的条目被反复查找。
2. **每包约 11 次共享 cache line 的原子操作**：
   `record_packet_size`（5 桶）、`record_ttl`（6 桶）、`record_ip_frag`（1–2）
   以及 `record_udp_port` / `record_icmp_type`，全是全局 `atomic64_inc`。
3. **窗口滚动路径持自旋锁**：`update_rate_stats` 在窗口过期时走 `spin_lock_bh`，
   同锁内最多 18 次原子读 + 8 次 EWMA 原子写；热路径因此出现 `_raw_spin_lock_bh` 0.71 次/包。
4. **`is_local_ip` 每包一次 O(N) 线性扫描**：每 CPU 一条目、掩码 `0xFFFFFFFF` 精确匹配；
   `cache->count == 0` 时**失败开放**返回 false（不拒绝）。
5. **`stats` 从不刷新 per-CPU 计数器**：见 `contract/procfs.fwidl` 的
   `PROC_STATS_STALE_NO_FLUSH`（模块缺陷，已入契约并有机械断言）。

## Phase 1 量化目标

目标以**多通路并发下的每包 softirq** 为主指标（单通路会被打流侧掩盖），
以 `function_graph` 结构指标为辅指标。

| 指标 | 基线 | 目标 | 验收方式 |
|------|------|------|------|
| 每包 softirq（4 通路并发，两表未命中） | 4.6 µs | **≤ 3.0 µs**（−35%） | `mflow.sh 4` |
| 每包 softirq（单通路，两表未命中） | 2.46 µs | **≤ 1.8 µs** | `fwsweep.sh` A 组 |
| 每包 softirq（单通路，已封禁丢弃） | 1.27 µs | **≤ 1.0 µs** | `fwsweep.sh` D 组 |
| `find_rate_entry_rcu` 次数/包 | 2.81 | **≤ 1.0**（合并为一次查表） | `function_graph` |
| 窗口滚动路径是否持锁 | 是（0.71 次/包） | **否**（全原子或 per-CPU） | `function_graph` 无 `_raw_spin_lock_bh` |
| 共享原子操作次数/包 | ≈11 | **≤ 2**（改 per-CPU 聚合） | 源码 + `function_graph` |

判定纪律：

- 每项必须在**同一台机、同一 `scripts/bench/`、同一模块参数**下重测；
- 未打到打流侧上限前，pps 上限不作为硬指标（本机打流能力不足，见上表）；
- 单通路与多通路的数字**不得混用**比较。
