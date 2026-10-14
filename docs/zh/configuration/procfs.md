# ProcFS 接口

内核模块在 `/proc/firewall/` 下建 13 个条目。
这份文档的条目名、权限、写文法、字段名都以生成物为准：

- 契约源文件：`contract/procfs.fwidl`
- 生成物：`contract/generated/procfs_uapi.h`

改接口要先改契约，再重跑生成器。手改生成物会被 `make contract-drift` 拦下。

## 一、条目清单

| 条目 | 权限 | 能做什么 |
|------|------|----------|
| `bans` | 0600 可读写 | 看当前封禁列表；下封锁、时长封、永久封、解封 |
| `whitelist` | 0600 可读写 | 看白名单；加子网、删子网 |
| `config` | 0600 可读写 | 看内核运行时配置；改默认封禁时长 |
| `stats` | 0400 只读 | 13 个计数器，机器可读的「键 值」行 |
| `rates` | 0400 只读 | 速率表：每个被跟踪地址的包数、字节数、窗口 |
| `udp_ports` | 0400 只读 | UDP 端口分布 |
| `icmp_types` | 0400 只读 | ICMP 类型与代码分布 |
| `pkt_sizes` | 0400 只读 | 包长分布，5 个固定区间加百分比 |
| `ttl_dist` | 0400 只读 | TTL 分布，6 个固定区间加百分比 |
| `ip_frags` | 0400 只读 | IP 分片统计：总包数、分片数、比例 |
| `port_scanners` | 0400 只读 | 端口扫描嫌疑地址，最多 20 条 |
| `service_probes` | 0400 只读 | 多协议探测嫌疑地址，最多 20 条 |
| `protected_ports` | 0400 只读 | 受保护端口集合，由守护进程下发 |

只有 `bans`、`whitelist`、`config` 可写，其余全部只读。
0600 意味着只有 root 能读能写。

## 二、写侧的规矩

这四条适用于全部三个可写条目：

- 一次 `write(2)` 写一条命令，末尾可以带换行。
- 成功返回写入的字节数；失败返回负 errno。没有文本错误通道，拒绝原因只进内核日志。
- 分隔符只能是空格或制表符，不接受多余参数。
- 除制表符以外，所有小于 `0x20` 的字节一律拒绝。

errno 只能区分到 `-EINVAL`、`-EBUSY`、`-ENOMEM`、`-EPERM` 这一层。
想知道具体为什么被拒，看 `dmesg`。

## 三、bans

写文法四种：

| 写法 | 含义 |
|------|------|
| `<ip>` | 用内核默认时长封（`fw_ban_time`） |
| `<ip> <seconds>` | 封指定秒数，可填 1 到 31536000 |
| `<ip> 0` | 永久封 |
| `unban <ip>` | 解封 |

时长必须是纯十进制数字。超过 31536000 秒会被拒。
`<ip>` 只接受单个地址，IPv4 和 IPv6 都行，不认 CIDR 写法。
网段封禁只有守护进程经 netlink 才能下发。
`unban` 后面不允许再跟任何东西。

可抄的命令：

```bash
# 按内核默认时长封
echo "203.0.113.9"      | sudo tee /proc/firewall/bans

# 封一小时
echo "203.0.113.9 3600" | sudo tee /proc/firewall/bans

# 永久封
echo "203.0.113.9 0"    | sudo tee /proc/firewall/bans

# 解封
echo "unban 203.0.113.9" | sudo tee /proc/firewall/bans
```

读回来的样子：

```text
Banned IP List:
-------------------
203.0.113.9                              (expires in 3540 seconds)
2001:db8::66                             (permanent)
-------------------
Total: 2 active bans (1 permanent, 1 temporary)
```

行格式是「地址按 40 列左对齐 + 状态」。
精确到单机的条目只打地址；网段条目会带 `/前缀`。
已过期待摘链的临时条目不显示。

## 四、whitelist

写文法三种：

| 写法 | 含义 |
|------|------|
| `add <subnet>` | 加一条白名单 |
| `<subnet>` | 不写动词也是加 |
| `remove <subnet>` | 删一条 |

`<subnet>` 是「地址」或「地址/前缀长度」。
不写前缀时按地址族补齐：IPv4 补 `/32`，IPv6 补 `/128`。
前缀超过 32（IPv4）或 128（IPv6）会被拒。
入表前先把地址归一化成网络地址，主机位清零。
`0.0.0.0`、广播、组播、回环、链路本地地址不允许加进来。

```bash
# 加一个网段
echo "203.0.113.0/24"      | sudo tee /proc/firewall/whitelist

# 同样的效果，带动词
echo "add 203.0.113.0/24"  | sudo tee /proc/firewall/whitelist

# 加单个地址
echo "add 198.51.100.7"    | sudo tee /proc/firewall/whitelist

# 删掉
echo "remove 203.0.113.0/24" | sudo tee /proc/firewall/whitelist
```

读回来的样子：

```text
Whitelisted IPs (protected from banning):
--------------------------------------
203.0.113.0/24  on manual
198.51.100.7/32  on manual
--------------------------------------
Total: 2 entries
```

设备列写 `manual` 的是这里手工加的，`restored` 是从状态文件恢复的。
网卡事件带进来的本机地址，那一列是网卡名。
本机接口地址由内核自己维护，不用手工加，也删不掉：删它返回 `-EPERM`。

`remove` 有连带效果，动手前要看清：
删掉一条白名单时，落在它覆盖范围内的封禁会一并解除，`total_unbans` 跟着涨。
`fw_wl_remove_quiet` 那条不联动的路径只给网卡变更用，procfs 走不到。

## 五、config

读它看运行时配置，写它只认一个参数。

写文法：`ban_time <seconds>`，取值 1 到 31536000。
参数名写错、超出范围、值不是十进制，都返回 `-EINVAL`。

```bash
# 改内核默认封禁时长
echo "ban_time 300" | sudo tee /proc/firewall/config

# 确认
sudo cat /proc/firewall/config
```

读回来的样子：

```text
Current Firewall Configuration:
--------------------------------
ban_time: 300 seconds
Ban entries: 0
Whitelist entries: 2
```

## 六、stats

这是唯一一个机器可读的只读条目，格式是每行「键 空格 十进制整数」。
键名和数值宽度都是契约，下游脚本按键取值。

| 键 | 宽度 | 含义 |
|----|------|------|
| `total_bans` | u32 | 累计封禁次数 |
| `total_unbans` | u32 | 累计解封次数 |
| `whitelist_rejects` | u32 | 两处都记在这个键上：封禁请求命中白名单被拒；白名单表到条目上限被拒 |
| `ban_table_full_rejects` | u32 | 封禁表到上限被拒的次数 |
| `alloc_failures` | u32 | 建条目时内存分配失败的次数 |
| `packets_dropped` | u64 | 丢弃的数据包数 |
| `packets_accepted` | u64 | 放行的数据包数 |
| `tcp_anomaly_dropped` | u64 | 按 TCP 异常丢弃的包数 |
| `cleanup_cycles` | u32 | 恒为 0，见下文 |
| `cleanup_expired_total` | u32 | 因到期被摘除的封禁条目数 |
| `current_bans` | i32 | 当前封禁条目数 |
| `current_whitelist` | i32 | 当前白名单条目数 |
| `recent_additions` | u32 | 当前一秒窗口内已记的封禁添加次数，泛洪限流用它判断 |

```bash
sudo cat /proc/firewall/stats
```

读这个文件时内核会先把各 CPU 的批量计数汇总，再取快照。
低速率下不会看到落后的数。

`cleanup_cycles` 恒为 0。
现在过期条目靠每条自己的定时器摘除，没有全局清理线程。
这个键留着只为不破坏外部脚本的行解析。

## 七、其余只读条目

这些是人类可读的表格，没有稳定性承诺。
排版允许改，别拿它们当机器可读接口。

```bash
sudo cat /proc/firewall/rates
sudo cat /proc/firewall/udp_ports
sudo cat /proc/firewall/icmp_types
sudo cat /proc/firewall/pkt_sizes
sudo cat /proc/firewall/ttl_dist
sudo cat /proc/firewall/ip_frags
sudo cat /proc/firewall/port_scanners
sudo cat /proc/firewall/service_probes
sudo cat /proc/firewall/protected_ports
```

列表类条目的顺序是哈希遍历顺序，两次读取不保证一致。
别按行号取值。

| 条目 | 内容形状 |
|------|----------|
| `rates` | 先是配置头（窗口秒数、每秒包上限、每秒字节上限、表容量、CPU 槽位、溢出计数），再是明细行「地址 包数 字节数 窗口秒」 |
| `udp_ports` | 头行 `Total entries: <n> / 512`，明细列端口、包数、字节数、最后可见 |
| `icmp_types` | 头行 `Total entries: <n> / 128`，明细列类型、代码、包数、字节数、最后可见 |
| `pkt_sizes` | 5 个长度区间，带计数和百分比 |
| `ttl_dist` | 6 个 TTL 区间，带计数和百分比 |
| `ip_frags` | 总包数、分片数、比例 |
| `port_scanners` | 判定阈值 5 个唯一端口，最多列 20 条 |
| `service_probes` | 判定阈值 3 种协议，最多列 20 条 |
| `protected_ports` | 一行状态加端口清单；守护进程没下发时按全端口受保护处理 |

`protected_ports` 只读。运维侧改不了这个集合，它由守护进程扫描本机监听端口后经 netlink 下发。

## 八、容量上限

| 条目 | 条目上限 | 由什么控制 | 代码锚点 |
|------|----------|------------|----------|
| `bans` | 65535 | 模块参数 `fw_max_ban_entries` | `src/kernel-module/fw_ban.c:fw_info.max_ban_entries` |
| `whitelist` | 65535 | 模块参数 `fw_max_whitelist_entries` | `src/kernel-module/fw_wl.c:fw_info.max_wl_entries` |
| `rates` | 65536 | 模块参数 `fw_max_rate_entries`，文档化范围 1024–262144 | `src/kernel-module/fw_main.c:fw_max_rate_entries` |
| `udp_ports` | 512 | 常量 | `src/kernel-module/fw_types.h:MAX_UDP_PORT_ENTRIES` |
| `icmp_types` | 128 | 常量 | `src/kernel-module/fw_types.h:MAX_ICMP_TYPE_ENTRIES` |
| `port_scanners` | 20 | 常量 | `src/kernel-module/fw_types.h:PORT_SCAN_MAX_RESULTS` |
| `service_probes` | 20 | 常量 | `src/kernel-module/fw_types.h:SERVICE_PROBE_MAX_RESULTS` |
| `protected_ports` | 256 | 0400 条目的展示行数上限 | `src/kernel-module/fw_types.h:FW_PROCFS_PROTECTED_PORTS_MAX_LINES` |

几条要分清：

- 封禁表到上限时返回 `-ENOSPC`，并把 `ban_table_full_rejects` 加一。4096 是哈希桶数，不是容量。
- 速率表满时新来的源地址有意放行，因为满了就丢包会误伤正常流量。溢出计数是 `rate_slot_spill`，在 `rates` 的配置头里看。
- `protected_ports` 的展示上限是 256 行，位图本身有 65536 位。超出会在末尾打一行截断提示。
- `udp_ports` 与 `icmp_types` 的明细行来自同一份分析快照，单次快照各最多打包 64 行。

## 九、出错怎么查

写命令没生效，按这个顺序看：

```bash
# 1. 内核日志里的拒绝原因
sudo dmesg | tail

# 2. 目标是不是被白名单挡住了
sudo cat /proc/firewall/whitelist

# 3. 封禁表是不是到顶了
sudo cat /proc/firewall/stats | grep ban_table_full_rejects

# 4. 写进去的到底是什么
echo "203.0.113.9 3600" | sudo tee /proc/firewall/bans
```

`tee` 退出码非 0，说明内核返回了负 errno。
