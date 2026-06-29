# 内核模块逻辑穷举审计报告

> 审计范围：`/root/linux-firewall-kmod/src/kernel-module/` 全部 11 个文件
> 审计日期：2026-06-26

---

## 一、数据结构（firewall.h）

### 1.1 宏定义

| 宏名 | 值 | 用途 |
|------|-----|------|
| `FW_PER_CPU_BATCH_SIZE` | 1024 | per-CPU 统计刷新阈值 |
| `BAN_HASH_BITS` | 12 | 封禁表哈希位（4096 桶） |
| `MAX_BAN_ENTRIES` | 4096 | 保留：临时数组大小 |
| `DEFAULT_BAN_TIME` | 600 | 默认封禁时长（秒） |
| `MAX_BAN_TIME` | 31536000 | 最大封禁时长（1 年） |
| `MIN_BAN_TIME` | 30 | 最小封禁时长 |
| `WHITELIST_HASH_BITS` | 6 | 白名单表（64 桶） |
| `RATE_HASH_BITS` | 16 | 速率表（65536 桶） |
| `DEFAULT_RATE_WINDOW_SECONDS` | 1 | 速率窗口 |
| `DEFAULT_MAX_PACKETS_PER_SECOND` | 10000 | PPS 阈值 |
| `DEFAULT_MAX_BYTES_PER_SECOND` | 10485760 | BPS 阈值（10MB/s） |
| `DEFAULT_MAX_SYN_PER_SECOND` | 200 | SYN Flood 阈值 |
| `DEFAULT_MAX_UDP_PER_SECOND` | 1000 | UDP Flood 阈值 |
| `DEFAULT_MAX_ICMP_PER_SECOND` | 50 | ICMP Flood 阈值 |
| `DEFAULT_MAX_ACK_PER_SECOND` | 2000 | ACK Flood 阈值 |
| `DEFAULT_MAX_RST_PER_SECOND` | 200 | RST Flood 阈值 |
| `DEFAULT_MAX_FIN_PER_SECOND` | 200 | FIN Flood 阈值 |
| `DEFAULT_DYNAMIC_THRESHOLD_ENABLED` | 0 | 动态阈值默认关闭 |
| `DEFAULT_DYNAMIC_THRESHOLD_RATIO_X100` | 300 | 动态阈值 3.0 倍 |
| `MAX_DISCOVERED_IPS` | 4096 | 自动发现 IP 临时数组 |
| `INET6_STR_LEN` | 48 | IPv6 字符串最大长度 |
| `FW_AF_INET` | 2 | 地址族 IPv4 |
| `FW_AF_INET6` | 10 | 地址族 IPv6 |
| `TCP_FLAGS_FIN` | 0x01 | TCP FIN 标志 |
| `TCP_FLAGS_SYN` | 0x02 | TCP SYN 标志 |
| `TCP_FLAGS_RST` | 0x04 | TCP RST 标志 |
| `TCP_FLAGS_ACK` | 0x10 | TCP ACK 标志 |

### 1.2 结构体

#### `struct fw_per_cpu_stats`
per-CPU 数据包统计，避免热路径 atomic 竞争。
| 字段 | 类型 | 说明 |
|------|------|------|
| `packets_accepted` | u64 | 本地接受计数 |
| `packets_dropped` | u64 | 本地丢弃计数 |
| `global_packets` | u64 | 全局流量 per-CPU 本地 |
| `global_bytes` | u64 | 全局字节 per-CPU 本地 |

#### `struct local_ip_cache_entry`
本地 IP 缓存条目（热路径优化）。
| 字段 | 类型 | 说明 |
|------|------|------|
| `af` | u8 | 地址族 |
| `addr.ipv4` / `addr.ipv6` | 联合体 | IP 地址 |
| `mask.ipv4_mask` / `mask.prefix_len` | 联合体 | 子网掩码/前缀长度 |

#### `struct whitelist_entry`
白名单条目（支持 IPv4/IPv6）。
| 字段 | 类型 | 说明 |
|------|------|------|
| `af` | u8 | 地址族 |
| `addr` | union | IPv4/IPv6 地址 |
| `mask` | union | IPv4 掩码/IPv6 前缀 |
| `device_name[16]` | char | 网络设备名 |
| `hash` | hlist_node | 哈希表节点 |
| `rcu_head` | rcu_head | RCU 释放回调 |
| `subnet_node` | list_head | 子网链表节点（非精确匹配条目） |

#### `struct ban_entry`
封禁条目（支持 IPv4/IPv6）。
| 字段 | 类型 | 说明 |
|------|------|------|
| `af` | u8 | 地址族 |
| `addr` | union | IP 地址 |
| `ban_time` | unsigned long | 封禁时刻（jiffies） |
| `unban_time` | unsigned long | 解封时刻（0=永久） |
| `retry_count` | atomic_t | 保留 |
| `is_permanent` | bool | 永久封禁标志 |
| `jail_name[32]` | char | Jail 名称 |
| `reason[32]` | char | 封禁原因 |
| `hash` | hlist_node | 哈希表节点 |
| `ban_node` | list_head | 全局活跃封禁链表节点 |
| `rcu_head` | rcu_head | RCU 释放 |
| `expire_timer` | timer_list | per-entry 过期定时器 |

#### `struct ip_rate_entry`
IP 速率统计条目。
| 字段 | 类型 | 说明 |
|------|------|------|
| `af` | u8 | 地址族 |
| `addr` | union | IP 地址 |
| `packet_count` | atomic64_t | 当前窗口包数 |
| `byte_count` | atomic64_t | 当前窗口字节数 |
| `syn/udp/icmp/ack/rst/fin_count` | atomic64_t | 协议专项计数（6 个） |
| `smoothed_pps/bps/syn/udp/icmp/ack/rst/fin` | atomic64_t | EWMA 平滑速率（8 个） |
| `window_start` | unsigned long | 窗口起始 jiffies |
| `last_activity` | unsigned long | 最后活动时间 |
| `pinned` | u8 | 白名单 IP 不被 LRU 踢出 |
| `hash` | hlist_node | 哈希表节点 |
| `rcu_head` | rcu_head | RCU 释放 |

#### `struct firewall_info`
全局防火墙结构（核心）。
| 字段组 | 字段 | 说明 |
|--------|------|------|
| 封禁表 | `ban_table_ipv4[4096]`, `ban_table_ipv6[4096]` | 哈希表 |
| 封禁锁 | `lock`（全局）, `ban_locks_ipv4[4096]`, `ban_locks_ipv6[4096]` | per-bucket 锁 |
| 封禁计数 | `ban_count`, `total_ban_count`, `total_unban_count` | atomic 计数器 |
| 活跃链表 | `active_bans_list` | 全局活跃封禁链表 |
| 关闭标志 | `shutting_down` | 防止关闭期间定时器触发 |
| 泛洪保护 | `flood_lock`, `last_flood_check`, `recent_additions` | 滑动窗口限流 |
| 统计 | `packets_dropped/accepted`, `cleanup_cycles`, `cleanup_expired_total` 等 | atomic 计数器 |
| 白名单表 | `whitelist_table_ipv4[64]`, `whitelist_table_ipv6[64]` | 哈希表 |
| 白名单锁 | `whitelist_lock` | 全局自旋锁 |
| 子网链表 | `ipv4_subnet_wl`, `ipv6_subnet_wl` | RCU 链表（加速子网匹配） |
| 本地 IP 缓存 | `local_ip_cache`, `local_ip_cache_count` | RCU 保护 |
| 速率表 | `rate_table_ipv4[65536]`, `rate_table_ipv6[65536]` | 哈希表 |
| 速率锁 | `rate_locks_ipv4[65536]`, `rate_locks_ipv6[65536]` | per-bucket 锁 |
| 速率配置 | `rate_window_seconds/jiffies`, `max_packets/bytes_per_second` | 滑动窗口配置 |
| 协议阈值 | `max_syn/udp/icmp/ack/rst/fin_per_second` | 6 个协议阈值 |
| 动态阈值 | `dynamic_threshold_enabled`, `ratio_x100`, `global_baseline_pps/bps` | EWMA 基线 |
| DDoS 配置 | `ddos_ban_duration` | 0=永久 |
| 全局流量 | `global_traffic_packets/bytes` | atomic64，守护进程读取 |
| procfs | `proc_dir`, `proc_bans/whitelist/config/settings/stats/rates` | procfs 条目 |
| 网络事件 | `netdev_notifier`, `sync_work`, `netdev_notifier_registered` | 设备事件 |

### 1.3 内联辅助函数（firewall.h）

| 函数 | 参数 | 返回 | 说明 |
|------|------|------|------|
| `ip_to_str(af, ip, buf, len)` | u8, void*, char*, size_t | void | IP→字符串 |
| `compare_ips(af, ip1, ip2)` | u8, void*, void* | bool | IP 比较 |
| `hash_ip(af, ip, bits)` | u8, void*, int | u32 | 通用哈希→桶索引 |
| `hash_ip_for_rate(af, ip, bits)` | 同上 | u32 | 速率表哈希（=hash_ip） |
| `get_rate_table(fw, af)` | fw*, u8 | hlist_head* | 获取对应地址族速率表 |
| `get_rate_lock(fw, af, bucket)` | fw*, u8, u32 | spinlock_t* | 获取 per-bucket 锁 |
| `validate_ipv4_address(ip, str, ctx, allow_loopback)` | __be32, ... | int | 验证 IPv4 合法性 |
| `validate_ipv6_address(addr, str, ctx, allow_loopback)` | in6_addr*, ... | int | 验证 IPv6 合法性 |
| `validate_ip_address(af, ip, ...)` | u8, void*, ... | int | 统一验证入口 |
| `is_local_ip(fw, af, ip)` | fw*, u8, void* | bool | 热路径本地 IP 检查（RCU 缓存） |

**`validate_ipv4_address` 拒绝规则：**
- `ip == 0` 或 `0xFFFFFFFF`
- 回环 `127.0.0.0/8`（`allow_loopback=false` 时）
- 多播 `224.0.0.0/4`
- `0.0.0.0/8`
- `255.0.0.0/8`

**`validate_ipv6_address` 拒绝规则：**
- `::`（全零）
- `::1`（回环，`allow_loopback=false` 时）
- 多播地址

---

## 二、模块参数（firewall-main.c）

| 参数名 | 类型 | 权限 | 默认值 | 说明 |
|--------|------|------|--------|------|
| `fw_ban_time` | uint | 0400 | 600 | 封禁时长（秒） |
| `state_file` | charp | 0444 | "/var/lib/firewall/state" | 状态文件路径 |
| `fw_max_bans_per_second` | uint | 0400 | 200 | 泛洪保护阈值 |
| `fw_max_rate_entries` | uint | 0644 | 65536 | 速率表条目数 |
| `fw_static_threshold` | uint | 0644 | 1 | 静态阈值检测开关 |
| `fw_dynamic_threshold` | uint | 0644 | 0 | 动态阈值检测开关 |
| `fw_ddos_detection` | uint | 0644 | 1 | DDoS 检测总开关 |

**全局变量：**
- `struct firewall_info fw_info` — 全局防火墙实例
- `u32 fw_hash_seed` — 随机哈希种子（防碰撞攻击）

---

## 三、firewall-main.c — 模块入口

### 函数清单

#### `get_fw_info()` → `struct firewall_info *`
- **逻辑**：返回 `&fw_info`
- **锁**：无
- **sleep**：否
- **导出**：`EXPORT_SYMBOL_GPL`

#### `cleanup_all_entries()` → void（static）
- **逻辑**：
  1. 遍历 `ban_table_ipv4`：对每个条目 `timer_delete_sync` → `list_del_rcu` → `hlist_del_rcu` → `call_rcu(free_ban_entry_rcu)`
  2. 遍历 `ban_table_ipv6`：同上
  3. 遍历 `whitelist_table_ipv4/ipv6`：`hlist_del_rcu` → `call_rcu(free_whitelist_entry_rcu)`
  4. 遍历 `rate_table_ipv4/ipv6`：`hlist_del_rcu` → `call_rcu(free_rate_entry_rcu)`
  5. 清理 `local_ip_cache`：`RCU_INIT_POINTER(NULL)` → `synchronize_rcu()` → `kfree`
  6. `synchronize_rcu()` 等待所有 RCU 回调完成
- **锁**：无（模块退出时调用，无并发）
- **sleep**：`timer_delete_sync` 和 `synchronize_rcu` 会 sleep
- **错误路径**：无

#### `firewall_init()` → int（`module_init`）
- **逻辑**：
  1. 随机生成 `fw_hash_seed`
  2. 校验 `fw_ban_time`（1 ~ 31536000）
  3. 初始化所有锁（`lock`, `ban_locks_ipv4[4096]`, `ban_locks_ipv6[4096]`, `flood_lock`, `whitelist_lock`, `rate_locks_*[65536]`）
  4. 初始化所有哈希表（`hash_init` × 6）
  5. 初始化子网链表（`INIT_LIST_HEAD` × 2）
  6. 设置速率检测默认配置
  7. 设置动态阈值默认配置
  8. 初始化所有 atomic 计数器为 0
  9. `INIT_DELAYED_WORK(&sync_work, sync_work_handler)`
  10. `fw_netlink_init()` — 失败→`err_notifier`
  11. `restore_state_from_file(state_file)` — 恢复持久化状态
  12. `auto_discover_system_ips()` — 自动发现本机 IP
  13. `register_netdev_notifier()` — 注册设备事件
  14. `create_procfs_entries()` — 失败→`err_notifier`
  15. `nf_register_net_hook(IPv4)` — 失败→`err_procfs`
  16. `nf_register_net_hook(IPv6)` — 失败→`err_nf_ipv4`（注销 IPv4 钩子）
- **错误路径**：分级回退（`err_nf_ipv4` → `err_procfs` → `err_notifier`）
- **sleep**：可能（`kmalloc GFP_KERNEL` 路径）

#### `firewall_exit()` → void（`module_exit`）
- **逻辑**：
  1. `atomic_set(shutting_down, 1)`
  2. `cancel_delayed_work_sync(&sync_work)`
  3. 注销 IPv4/IPv6 netfilter 钩子
  4. `synchronize_rcu()`
  5. `unregister_netdev_notifier()`
  6. `destroy_procfs_entries()`
  7. `synchronize_rcu()`
  8. `save_state_to_file(state_file)` — 持久化当前状态
  9. `cleanup_all_entries()`
  10. `fw_netlink_exit()`

---

## 四、netfilter.c — netfilter 钩子

### 函数清单

#### `fw_flush_cpu_stats()` → void
- **逻辑**：将当前 CPU 的 per-CPU 统计刷新到全局 atomic 计数器
  - `packets_accepted` → `atomic64_add` → 清零本地
  - `packets_dropped` → `atomic64_add` → 清零本地
  - `global_packets` → `atomic64_add(global_traffic_packets)` → 清零本地
  - `global_bytes` → `atomic64_add(global_traffic_bytes)` → 清零本地
- **锁**：无（per-CPU 本地操作）
- **sleep**：否

#### `fw_flush_all_cpu_stats()` → void
- **逻辑**：`on_each_cpu(fw_flush_cpu_stats_ipi, NULL, 1)` — IPI 在所有 CPU 上执行 flush
- **锁**：无
- **sleep**：是（`on_each_cpu` 等待所有 CPU 完成）

#### `handle_ban_check(af, src_ip, skb, protocol, tcp_flags)` → uint
- **核心逻辑（热路径）**：
  1. 检查 `shutting_down` → 是则 `NF_ACCEPT`
  2. `rcu_read_lock()`
  3. 二次检查 `shutting_down`
  4. **本地 IP 缓存检查**：`is_local_ip()` → 命中则 `NF_ACCEPT`
  5. **白名单精确匹配**：
     - IPv4：`hash_min(ipv4, WHITELIST_HASH_BITS)` 定位桶 → 遍历匹配 `/32` 条目
     - IPv6：`jhash` 定位桶 → 遍历匹配 `/128` 条目（逐 u32 READ_ONCE + barrier）
  6. **白名单子网匹配**（精确未命中时）：
     - 遍历 `ipv4_subnet_wl` 或 `ipv6_subnet_wl` 链表
     - IPv4：`(ip & mask) == (wl_ip & mask)`
     - IPv6：`ipv6_prefix_equal(ip, wl_ip, prefix)`
  7. **封禁表查找**（白名单未命中时）：
     - IPv4/IPv6：定位桶 → 遍历匹配
     - 检查 `is_permanent || time_before(now, unban_time)`
  8. `rcu_read_unlock()`
  9. 如果被封禁 → 递增 drop 计数 → `NF_DROP`
  10. **速率检测**（非白名单 && `fw_ddos_detection=1`）：
      - `update_rate_stats()` → 更新统计
      - `check_rate_violation()` → 总速率违规？
      - `check_protocol_violation()` → SYN/UDP/ICMP Flood？
      - `check_tcp_flood_violation()` → ACK/RST/FIN Flood？
      - 违规 → `ban_ip_permanent()` 或 `ban_ip_with_duration()` → `fw_netlink_send_event()` → `NF_DROP`
  11. 未违规 → 递增 accept 计数 → `NF_ACCEPT`
- **锁**：`rcu_read_lock`（步骤 2-8, 10 中的 check 部分）
- **sleep**：否（softirq 上下文）
- **可能调用的 sleep 函数**：`ban_ip_*` 内部 `kmalloc(GFP_ATOMIC)` 不 sleep

#### `nf_hook_func_ipv4(priv, skb, state)` → uint
- **逻辑**：
  1. `skb` 空检查
  2. `pskb_may_pull(sizeof(iphdr))` — 验证最小长度
  3. `skb_header_pointer` 获取 IP 头
  4. 验证 `version == 4`
  5. 验证 `ihl >= 5 && ihl <= 15`
  6. 验证 `ihl * 4 <= tot_len`
  7. 验证 `tot_len <= skb->len`
  8. 校验和检查（跳过 `CHECKSUM_UNNECESSARY`）
  9. 源 IP 过滤：拒绝 `0`, `0xFFFFFFFF`, `127.0.0.0/8`, `224.0.0.0/4`, `0.0.0.0/8`
  10. 协议分类：
      - 分片包（`IP_OFFSET`）→ `proto=0`（跳过传输层检测）
      - TCP → 提取 `tcp_flags`（SYN/ACK/RST/FIN）
      - ICMP → 仅 Echo Request（type=8）→ 其他 → `proto=0`
  11. 递增全局流量计数（per-CPU）
  12. 调用 `handle_ban_check(FW_AF_INET, ...)`
- **锁**：无
- **sleep**：否

#### `nf_hook_func_ipv6(priv, skb, state)` → uint
- **逻辑**：
  1. 空检查 + `pskb_may_pull`
  2. 验证 `version == 6`
  3. 验证 `payload_len + 40 <= skb->len`
  4. **扩展头遍历**：`NEXTHDR_HOP/ROUTING/DEST/AUTH` → 深度限制 8 层
      - 超过深度 → `NF_DROP`
  5. **分片处理**：`NEXTHDR_FRAGMENT` → `proto=0`（无传输层头）
  6. 源 IP 过滤：拒绝 `::`, `::1`, 多播, `fe80::/10`（link-local）
  7. 协议分类（类似 IPv4）：TCP 提取标志位，ICMPv6 仅 Echo Request
  8. 递增全局流量计数（per-CPU）
  9. 调用 `handle_ban_check(FW_AF_INET6, ...)`
- **锁**：无
- **sleep**：否

### 钩子注册

```c
nf_ops_ipv4: NF_INET_PRE_ROUTING, priority = NF_IP_PRI_FILTER - 1
nf_ops_ipv6: NF_INET_PRE_ROUTING, priority = NF_IP_PRI_FILTER - 1
```
优先级比 iptables FILTER 高 1（先执行）。

---

## 五、ban-manager.c — 封禁/解封管理

### 函数清单

#### `ban_entry_expire_callback(t)` → void
- **触发**：per-entry 定时器到期
- **逻辑**：
  1. `container_of` 获取 `ban_entry`
  2. IPv4 路径：
     - 计算桶索引 `hash_min(ipv4, BAN_HASH_BITS)`
     - `spin_lock(ban_locks_ipv4[bkt])`
     - 二次检查 `hlist_unhashed(&entry->hash)` — 条目是否已被删除
     - 若仍在表中：`list_del_rcu` → `hlist_del_rcu` → `atomic_dec(ban_count)` → `atomic_inc(cleanup_expired_total)`
     - `spin_unlock`
     - `call_rcu(free_ban_entry_rcu)`
     - `fw_netlink_send_ban_state_change(af, ip, action=2, reason="expired")`
  3. IPv6 路径：同上，使用 `hash_ipv6()` 计算桶
- **锁**：`ban_locks_ipv4/ipv6[bkt]`（per-bucket spinlock）
- **sleep**：否（定时器上下文）
- **注意**：`timer_delete_sync` 已在调用方（`__do_unban_ip`、`cleanup_all_entries`）处理

#### `__recheck_whitelist_ipv6(fw, ip6)` → int（static inline）
- **逻辑**：遍历所有白名单桶，`ipv6_prefix_equal` 匹配 → 返回 `-EPERM`
- **锁**：需 `rcu_read_lock`
- **sleep**：否

#### `__recheck_whitelist_ipv4(fw, ipv4)` → int（static inline）
- **逻辑**：同上，IPv4 版本
- **锁**：需 `rcu_read_lock`

#### `hash_ipv6(addr)` → u32
- **逻辑**：`jhash(addr, 16, fw_hash_seed) & ((1<<BAN_HASH_BITS)-1)`
- **归属问题**：应移入 `firewall.h`（见审计报告首节）

#### `__do_ban_ip_ipv6(fw, ip6, entry, unban_time, is_permanent, reason, is_new_ban)` → int（static）
- **前置**：`entry` 已分配，未初始化
- **逻辑**：
  1. `spin_lock(ban_locks_ipv6[bkt])`
  2. **白名单二次检查**：`rcu_read_lock` → `__recheck_whitelist_ipv6` → 命中则 `kfree(entry)` + 返回 `-EPERM`
  3. 遍历桶内已有条目：
     - 找到匹配 IP：
       - 永久或未过期 → `kfree(entry)` + 返回 `-EEXIST`（no-op）
       - 已过期 → 刷新 `ban_time/unban_time` + `mod_timer` → `kfree(entry)` + 返回 `0`（续期，不影响统计）
  4. 新条目：初始化字段 → `hlist_add_head_rcu` + `list_add_tail_rcu`
  5. 非永久 → `timer_setup` + `mod_timer(expire_timer, unban_time)`
  6. `spin_unlock`
  7. `atomic_inc(ban_count)` + `atomic_inc(total_ban_count)` + `*is_new_ban = true`
- **返回值**：0=新插入/续期，-EEXIST=已存在，-EPERM=白名单拒绝
- **锁**：`ban_locks_ipv6[bkt]`
- **统计不变量**：`total_bans == current_bans + total_unbans + cleanup_expired_total`

#### `__do_ban_ip_ipv4(fw, ipv4, entry, ...)` → int（static）
- **逻辑**：与 IPv6 版本完全对称，使用 `hash_min(ipv4, BAN_HASH_BITS)`

#### `__do_ban_ip(fw, af, ip, unban_time, is_permanent, reason, log_msg, log_arg, is_new_ban)` → int（static）
- **两阶段锁策略**：
  - **阶段 1（全局锁 `fw->lock`）**：
    1. IP 空检查 → `-EINVAL`
    2. IP 合法性验证 → `-EINVAL`
    3. `kmalloc(GFP_ATOMIC)` → 失败 `-ENOMEM`
    4. `spin_lock(fw->lock)`
    5. 白名单遍历：命中 → `-EPERM`
    6. **本机 IP 保护**：遍历所有网络设备地址 → 匹配则 `-EPERM`
       - IPv4：`for_each_netdev_rcu` → `in_ifaddr` 遍历
       - IPv6：`for_each_netdev_rcu` → `inet6_ifaddr` 遍历（`read_lock_bh(idev->lock)`）
    7. `spin_unlock(fw->lock)`
  - **阶段 2（per-bucket 锁）**：
    8. 调用 `__do_ban_ip_ipv4/ipv6`
- **锁顺序规则**：全局锁和每桶锁不嵌套持有
- **sleep**：否（`GFP_ATOMIC`）

#### `__find_ban_entry_rcu(fw, af, ip)` → `ban_entry *`（static）
- **逻辑**：RCU 下遍历对应桶，返回匹配条目或 NULL
- **锁**：`rcu_read_lock`（调用方持有）

#### `__do_unban_ip(fw, af, ip, permanent_only)` → int（static）
- **逻辑**：
  1. 计算桶索引
  2. `spin_lock(ban_locks[bkt])`
  3. 遍历桶：找到匹配 → 若 `!permanent_only || is_permanent`：
     - `timer_delete_sync(expire_timer)` — 取消过期定时器
     - `list_del_rcu` + `hlist_del_rcu`
     - `atomic_dec(ban_count)`
     - `call_rcu(free_ban_entry_rcu)`
  4. `spin_unlock`
  5. 找到 → `atomic_inc(total_unban_count)` + 返回 0
  6. 未找到 → `-ENOENT`
- **锁**：`ban_locks[bkt]`

#### `unban_ip(fw, af, ip)` → int
- **逻辑**：`__do_unban_ip(permanent_only=false)` → 成功则 `fw_netlink_send_ban_state_change`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `unban_permanent_ip(fw, af, ip)` → int
- **逻辑**：`__do_unban_ip(permanent_only=true)` — 仅解封永久封禁
- **导出**：`EXPORT_SYMBOL_GPL`

#### `is_banned(fw, af, ip)` → int
- **逻辑**：RCU 下查找 → 永久=true，未过期=true，已过期=false
- **锁**：`rcu_read_lock`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `ban_ip(fw, af, ip, reason)` → int
- **逻辑**：
  1. `ban_secs = fw_ban_time`
  2. `check_mul_overflow(ban_secs, HZ, &ban_duration)` → 溢出返回 `-EINVAL`
  3. `__do_ban_ip(unban_time=jiffies+ban_duration, is_permanent=false)`
  4. 新封禁 → `fw_netlink_send_ban_state_change`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `ban_ip_permanent(fw, af, ip, reason)` → int
- **逻辑**：`__do_ban_ip(unban_time=0, is_permanent=true)` → 新封禁推送事件
- **导出**：`EXPORT_SYMBOL_GPL`

#### `is_permanently_banned(fw, af, ip)` → int
- **逻辑**：RCU 查找 → 仅检查 `is_permanent`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `check_flood_protection()` → int
- **逻辑**：
  1. `spin_lock(flood_lock)`
  2. 若距上次检查 > 1 秒 → 重置计数器为 1
  3. 否则 → 计数器++ → 超过 `fw_max_bans_per_second` → `-EBUSY`
  4. `spin_unlock`

#### `ban_ip_with_duration(fw, af, ip, seconds, reason)` → int
- **逻辑**：类似 `ban_ip`，但使用指定的 `seconds` 而非 `fw_ban_time`
- **校验**：`seconds == 0` → `-EINVAL`（0 应走 `ban_ip_permanent`）

---

## 六、whitelist.c — 白名单管理

### 函数清单

#### `hash_wl_ipv6(addr)` → u32（static）
- **逻辑**：`jhash(addr, 16, fw_hash_seed) & ((1<<WHITELIST_HASH_BITS)-1)`

#### `add_whitelist_entry(fw, af, ip, mask, prefix_len, dev_name)` → int
- **逻辑**：
  1. `kmalloc(GFP_KERNEL)` → 失败 `-ENOMEM`
  2. 地址族分支：
     - IPv6：校验 `prefix_len` 0~128 → `-EINVAL`
     - IPv4：校验子网掩码合法性（连续 1 后跟连续 0）→ `-EINVAL`；`addr = ip & mask`
  3. 复制 `dev_name`
  4. `spin_lock(whitelist_lock)`
  5. 去重检查：遍历对应桶 → 已存在 → `kfree` + 返回 0
  6. `hlist_add_head_rcu` 到对应桶
  7. 子网条目 → `list_add_tail_rcu` 到子网链表
  8. `atomic_inc(whitelist_count)`
  9. `spin_unlock`
  10. **解除匹配封禁**：
      - 精确匹配（`/32` 或 `/128`）→ O(1) 定位桶 → 遍历删除匹配条目
      - CIDR 子网 → 遍历 `active_bans_list` → 对每个匹配条目：
        - `spin_lock_bh(ban_locks[bkt])` → `timer_delete_sync` → `list_del_rcu` + `hlist_del_rcu` → `spin_unlock_bh` → `call_rcu`
        - `fw_netlink_send_ban_state_change(reason="whitelist")`
  11. `fw_netlink_send_whitelist_state_change(action=1)`
- **锁**：`whitelist_lock`（步骤 4-9），`ban_locks[bkt]`（步骤 10）
- **sleep**：步骤 1 `GFP_KERNEL`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `remove_whitelist_entry(fw, af, ip, prefix_len)` → int
- **逻辑**：
  1. `spin_lock(whitelist_lock)`
  2. 遍历对应桶 → 匹配 → 保存 `device_name` → `hlist_del_rcu` → 从子网链表移除 → `atomic_dec` → `call_rcu`
  3. `spin_unlock`
  4. 找到 → `fw_netlink_send_whitelist_state_change(action=2, removed_dev)`
  5. 未找到 → `-ENOENT`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `is_in_whitelist(fw, af, ip)` → bool
- **逻辑**：
  1. `rcu_read_lock`
  2. IPv4：精确匹配桶 → 子网链表遍历
  3. IPv6：精确匹配桶 → 子网链表遍历
  4. `rcu_read_unlock`
- **锁**：`rcu_read_lock`
- **导出**：`EXPORT_SYMBOL_GPL`

---

## 七、rate-detector.c — DDoS 速率检测

### 函数清单

#### `free_rate_entry_rcu(head)` → void
- **逻辑**：`container_of` + `kfree`
- **sleep**：否

#### `find_rate_entry_rcu(fw, af, ip)` → `ip_rate_entry *`（static）
- **逻辑**：RCU 遍历对应桶 → 匹配返回 / NULL
- **锁**：需 `rcu_read_lock`

#### `create_rate_entry(fw, af, ip)` → `ip_rate_entry *`（static）
- **逻辑**：
  1. `kzalloc(GFP_ATOMIC)` → 失败 `-ENOMEM`
  2. 初始化所有字段为 0
  3. `pinned = is_in_whitelist() ? 1 : 0`
  4. `hlist_add_head_rcu` + `atomic_inc(rate_count)`
- **锁**：需调用方持有 per-bucket spinlock
- **sleep**：否（`GFP_ATOMIC`）

#### `update_rate_stats(fw, af, ip, packet_len, protocol, tcp_flags)` → int
- **热路径核心**：
  1. 参数校验
  2. **RCU 快速路径**：`find_rate_entry_rcu` → 找到：
     - 窗口过期？
       - 是 → `rcu_read_unlock` → `spin_lock_bh(per-bucket)` → 双重检查：
         - 仍过期 → EWMA 更新 `smoothed_*`（α=0.3） → 重置计数器 → 按协议设置初始值
         - 其他 CPU 已重置 → 递增计数器
       - `spin_unlock_bh`
     - 未过期 → 原子递增计数器（无锁） → `rcu_read_unlock`
  3. **慢速路径**：条目不存在
     - `spin_lock_bh(per-bucket)` → 双重检查 → 存在则递增
     - 不存在 → `create_rate_entry` → 设置初始计数
     - `spin_unlock_bh`
- **返回值**：0=成功，负数=失败
- **锁**：RCU（快速路径），`spin_lock_bh`（慢速路径/窗口重置）
- **sleep**：否

#### `check_rate_violation(fw, af, ip)` → bool
- **逻辑**：
  1. RCU 查找条目
  2. 读取 `smoothed_pps/bps`
  3. 计算阈值：
     - 静态 + 动态都关 → `return false`
     - 静态开 → `pps_threshold = max_packets_per_second`
     - 动态开 → `dynamic_pps = baseline_pps * ratio / 100`（溢出保护 `check_mul_overflow`）→ 取 `max(static, dynamic)`
  4. `pps > pps_threshold || bps > bps_threshold` → `true`
- **锁**：需 `rcu_read_lock`
- **sleep**：否

#### `check_protocol_violation(fw, af, ip, protocol)` → bool
- **逻辑**：RCU 查找 → 按协议读对应 `smoothed_*` → 比较 `max_syn/udp/icmp_per_second`
- **锁**：需 `rcu_read_lock`

#### `check_tcp_flood_violation(fw, af, ip, tcp_flags)` → `const char *`
- **逻辑**：RCU 查找 → 按 `tcp_flags` 检查 ACK/RST/FIN → 返回违规类型字符串或 NULL
- **锁**：需 `rcu_read_lock`

#### `update_global_baseline(fw, total_pps, total_bps)` → void
- **逻辑**：EWMA α=0.01：`baseline = (1*current + 99*baseline) / 100`
- **调用方**：守护进程通过 netlink `BASELINE_UPDATE` 配置项调用

#### `cleanup_rate_entries(fw)` → void
- **逻辑**：遍历所有桶（IPv4 + IPv6）→ `spin_lock_bh` → 删除 `last_activity + 10s` 之前的条目 → `call_rcu`
- **锁**：`rate_locks[bkt]`（per-bucket，逐桶加锁）
- **调用方**：清理定时器

#### `clear_all_rate_entries(fw)` → void
- **逻辑**：遍历所有桶 → 删除全部条目
- **调用方**：`rate_window` 配置更新时

---

## 八、procfs.c — procfs 接口

### 8.1 `/proc/firewall/bans`（读写 0600）

**读（`bans_show`）**：
- RCU 遍历 `ban_table_ipv4/ipv6`
- 输出格式：`IP (permanent)` 或 `IP (expires in N seconds)`
- 统计 permanent/temporary 数量

**写（`bans_write`）**：
- 命令格式：
  - `"unban <ip>"` → 解封
  - `"<ip>"` → 默认时长封禁
  - `"<ip> <seconds>"` → 指定时长
  - `"<ip> 0"` → 永久封禁
  - `"<ip> -1"` → 解封
- 解析链：`parse_ban_command` → `validate_and_copy_ip` → `parse_ban_duration` → `execute_ban_action`
- IP 解析：`in4_pton` → `in6_pton` → `validate_ipv4/ipv6_address`
- 控制字符校验：拒绝 `< 0x20`（除 `\t`）
- 封禁后推送 `fw_netlink_send_ban_state_change`

### 8.2 `/proc/firewall/whitelist`（读写 0600）

**读（`whitelist_read`）**：
- 输出：`IP/prefix  on dev_name`

**写（`whitelist_write`）**：
- 命令格式：`"add <ip>[/<prefix>]"` 或 `"remove <ip>[/<prefix>]"`
- 解析链：`parse_whitelist_command` → `parse_whitelist_subnet` → `execute_whitelist_action`
- `remove` 操作：禁止删除本机接口 IP（遍历网络设备校验 → `-EPERM`）
- `add` 操作：IP 归一化（`ip & mask`）后调用 `add_whitelist_entry`

### 8.3 `/proc/firewall/config`（读写 0600）

**读（`config_show`）**：
- 输出 `ban_time`, `Ban entries`, `Whitelist entries`

**写（`config_write`）**：
- 格式：`"ban_time <seconds>"`
- 校验：`1 <= value <= 31536000`，溢出检查
- 同步写入 `fw_ban_time` 和 `fw_info.ban_time`
- 推送 `fw_netlink_send_config_change(flag=1, value)`

### 8.4 `/proc/firewall/stats`（只读 0400）

输出字段：
```
total_bans, total_unbans, whitelist_rejects, ban_table_full_rejects,
alloc_failures, packets_dropped, packets_accepted, cleanup_cycles,
cleanup_expired_total, current_bans, current_whitelist, recent_additions
```

### 8.5 `/proc/firewall/rates`（只读 0400）

- 输出速率配置 + 每个 IP 的包数/字节数/窗口时间

---

## 九、netlink.c — Netlink 通信

### 9.1 消息类型（19 种）

| 编号 | 名称 | 方向 | 说明 |
|------|------|------|------|
| 1 | `FW_NL_DDOS_EVENT` | 内核→守护 | DDoS 违规事件 |
| 2 | `FW_NL_BAN_IP` | 守护→内核 | 封禁 IP |
| 3 | `FW_NL_UNBAN_IP` | 守护→内核 | 解封 IP |
| 4 | `FW_NL_SET_CONFIG` | 守护→内核 | 配置更新 |
| 5 | `FW_NL_BAN_STATE_CHANGE` | 内核→守护 | 封禁状态变更 |
| 6 | `FW_NL_LIST_BANS_QUERY` | 守护→内核 | 查询封禁列表 |
| 7 | `FW_NL_LIST_BANS_RESPONSE` | 内核→守护 | 封禁列表响应 |
| 8 | `FW_NL_STATS_QUERY` | 守护→内核 | 查询统计 |
| 9 | `FW_NL_STATS_RESPONSE` | 内核→守护 | 统计响应 |
| 10 | `FW_NL_LIST_WHITELIST_QUERY` | 守护→内核 | 查询白名单 |
| 11 | `FW_NL_LIST_WHITELIST_RESPONSE` | 内核→守护 | 白名单响应 |
| 12 | `FW_NL_ADD_WHITELIST` | 守护→内核 | 添加白名单 |
| 13 | `FW_NL_REMOVE_WHITELIST` | 守护→内核 | 移除白名单 |
| 14 | `FW_NL_CONFIG_ACK` | 内核→守护 | 配置确认 |
| 15 | `FW_NL_LIST_RATES_QUERY` | 守护→内核 | 查询速率 |
| 16 | `FW_NL_LIST_RATES_RESPONSE` | 内核→守护 | 速率响应 |
| 17 | `FW_NL_WHITELIST_STATE_CHANGE` | 内核→守护 | 白名单状态变更 |
| 18 | `FW_NL_CMD_RESULT` | 内核→守护 | 命令失败结果 |
| 19 | `FW_NL_CONFIG_CHANGE` | 内核→守护 | procfs 配置变更 |

### 9.2 消息头（20 字节）

```c
struct fw_nlmsg_hdr {
  __u32 magic;     // 0x46574C4E ("FWLN")
  __u16 msg_type;
  __u16 msg_len;
  __u32 seq;
} __packed;
```

### 9.3 配置标志位

| 标志 | 位 | 对应字段 |
|------|-----|---------|
| `FW_NL_CFG_BAN_TIME` | bit 0 | `ban_time` |
| `FW_NL_CFG_RATE_WINDOW` | bit 1 | `rate_window_seconds` |
| `FW_NL_CFG_MAX_PPS` | bit 2 | `max_packets_per_second` |
| `FW_NL_CFG_MAX_BPS` | bit 3 | `max_bytes_per_second` |
| `FW_NL_CFG_MAX_SYN` | bit 4 | `max_syn_per_second` |
| `FW_NL_CFG_MAX_UDP` | bit 5 | `max_udp_per_second` |
| `FW_NL_CFG_MAX_ICMP` | bit 6 | `max_icmp_per_second` |
| `FW_NL_CFG_MAX_ACK` | bit 7 | `max_ack_per_second` |
| `FW_NL_CFG_MAX_RST` | bit 8 | `max_rst_per_second` |
| `FW_NL_CFG_MAX_FIN` | bit 9 | `max_fin_per_second` |
| `FW_NL_CFG_DYNAMIC_THRESHOLD` | bit 10 | `dynamic_threshold_flags + ratio` |
| `FW_NL_CFG_BASELINE_UPDATE` | bit 11 | `baseline_pps/bps` |
| `FW_NL_CFG_DDOS_BAN_DURATION` | bit 12 | `ddos_ban_duration` |

### 9.4 接收处理（`fw_netlink_recv_msg`）

消息处理 switch：
- **BAN_IP**：`duration==0` → `ban_ip_permanent`，否则 `ban_ip_with_duration` → 失败推送 `CMD_RESULT`
- **UNBAN_IP**：`unban_ip` → 失败推送 `CMD_RESULT`
- **SET_CONFIG**：
  - 验证：`ban_time=0` 拒绝，`max_pps=0` 拒绝，`max_bps=0` 拒绝
  - 按 flag 位逐项 `WRITE_ONCE` 更新
  - `RATE_WINDOW` 更新后 `clear_all_rate_entries`
  - `BASELINE_UPDATE` → `update_global_baseline`
  - 推送 `CONFIG_ACK`
- **STATS_QUERY** → `fw_netlink_send_stats_response`（先 `fw_flush_all_cpu_stats`）
- **LIST_BANS_QUERY** → `fw_netlink_send_list_bans_response`（动态分配）
- **LIST_WHITELIST_QUERY** → `fw_netlink_send_list_whitelist_response`
- **LIST_RATES_QUERY** → `fw_netlink_send_list_rates_response`（`atomic64_xchg` 读取并重置全局流量）
- **ADD_WHITELIST**：IPv4 计算掩码 → `add_whitelist_entry`
- **REMOVE_WHITELIST**：`remove_whitelist_entry`

### 9.5 发送函数

| 函数 | 传输方式 | 说明 |
|------|---------|------|
| `fw_netlink_send_event` | `netlink_broadcast` | DDoS 事件 |
| `fw_netlink_send_ban_state_change` | `netlink_broadcast` | 封禁变更（含实时统计） |
| `fw_netlink_send_whitelist_state_change` | `netlink_broadcast` | 白名单变更 |
| `fw_netlink_send_cmd_result` | `netlink_broadcast` | 命令失败 |
| `fw_netlink_send_config_change` | `netlink_broadcast` | procfs 配置变更 |
| `fw_netlink_send_list_bans_response` | `netlink_unicast` | 封禁列表（按 portid） |
| `fw_netlink_send_stats_response` | `netlink_unicast` | 统计 |
| `fw_netlink_send_config_ack` | `netlink_unicast` | 配置确认 |
| `fw_netlink_send_list_whitelist_response` | `netlink_unicast` | 白名单列表 |
| `fw_netlink_send_list_rates_response` | `netlink_unicast` | 速率列表 |

---

## 十、cleanup.c — RCU 释放回调

#### `free_ban_entry_rcu(head)` → void
- `container_of` + `kfree(ban_entry)`

#### `free_whitelist_entry_rcu(head)` → void
- `container_of` + `kfree(whitelist_entry)`

**说明**：per-entry 过期由 `ban_entry.expire_timer` 自动管理，无全局 cleanup_timer。

---

## 十一、netdev.c — 网络设备事件

### 函数清单

#### `sync_work_handler(work)` → void
- **触发**：`sync_system_ips` 调度 500ms 延迟后执行
- **逻辑**：
  1. 检查 `shutting_down`
  2. `kmalloc_array(MAX_BAN_ENTRIES, ...)` 临时数组
  3. RCU 遍历所有 UP 网络设备 → 收集 IPv4/IPv6 地址到 `current_ips[]`
  4. 构建 `lookup_table[]`（用于差异比较）
  5. `spin_lock(whitelist_lock)` → 遍历白名单表：
     - 跳过 `device_name == "manual"` 或 `"restored"` 的条目
     - 不在 `current_ips` 中 → 删除 + 推送 `WHITELIST_STATE_CHANGE(action=2)`
  6. `spin_unlock`
  7. 遍历 `lookup_table[]`：`found==false` → `add_whitelist_entry`（新增 IP）
  8. **重建本地 IP 缓存**：
     - `kmalloc_array` 新缓存数组
     - `rcu_assign_pointer(local_ip_cache, new_cache)` — 原子切换
     - 旧数组 `synchronize_rcu()` + `kfree`
  9. 释放临时数组
- **锁**：`whitelist_lock`（步骤 5-6），RCU（步骤 3）
- **sleep**：`GFP_KERNEL` 分配，`synchronize_rcu`

#### `sync_system_ips(fw)` → void
- **逻辑**：`mod_delayed_work(system_wq, &sync_work, 500ms)` — 防抖调度
- **导出**：`EXPORT_SYMBOL_GPL`

#### `netdev_event_handler(nb, event, ptr)` → int（static）
- **事件处理**：
  - `NETDEV_UP` / `NETDEV_DOWN` / `NETDEV_CHANGE` → `sync_system_ips(fw)`
  - 其他 → `NOTIFY_DONE`

#### `register_netdev_notifier(fw)` → int
- `register_netdevice_notifier`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `unregister_netdev_notifier(fw)` → void
- 检查 `netdev_notifier_registered` → `unregister_netdevice_notifier`
- **导出**：`EXPORT_SYMBOL_GPL`

#### `auto_discover_system_ips(fw)` → void
- **逻辑**：遍历所有 UP 设备 → 收集 IP → 逐个 `add_whitelist_entry`
- **调用方**：`firewall_init`（模块初始化时一次性调用）
- **导出**：`EXPORT_SYMBOL_GPL`

---

## 十二、state-persist.c — 状态持久化

### 函数清单

#### `validate_state_path(filename)` → int（static）
- **安全检查**：
  - 空路径 → `-EINVAL`
  - URL 编码（`%2e`, `%2f`）→ `-EINVAL`
  - 危险字符（`|;&`$(){}<>!~*?[]`）→ `-EINVAL`
  - 路径遍历（`..`）→ `-EINVAL`
  - 仅允许 `/var/lib/`, `/tmp/`, `/etc/` 前缀 → `-EPERM`

#### `save_state_to_file(filename)` → int
- **逻辑**：
  1. 路径验证
  2. 分配 4 个临时数组（ban_v4/v6, wl_v4/v6，各 4096 条目）
  3. RCU 遍历收集封禁和白名单条目
  4. 封禁条目计算 `remaining_time`（过期条目跳过）
  5. `filp_open(O_CREAT|O_WRONLY|O_TRUNC|O_NOFOLLOW, 0600)`
  6. `vfs_getattr` 保存 inode/dev（TOCTOU 防护）
  7. 逐行写入：
     - `BAN_V4 <ip> <remaining> <jail> <reason>\n`
     - `BAN_V6 <ip> <remaining> <jail> <reason>\n`
     - `WL_V4 <ip> <prefix> <dev>\n`
     - `WL_V6 <ip> <prefix> <dev>\n`
  8. 写入后再次 `vfs_getattr` 验证 inode/dev 未变（TOCTOU 防护）
  9. 释放临时数组
- **导出**：`EXPORT_SYMBOL_GPL`

#### `restore_state_from_file(filename)` → int
- **防重复**：`state_restored` 标记（模块生命周期内仅一次）
- **逻辑**：
  1. 路径验证
  2. `kmalloc(128KB)` 读缓冲区
  3. `filp_open(O_RDONLY|O_NOFOLLOW)`
  4. `vfs_getattr` 验证常规文件
  5. 分块读取全部内容
  6. 逐行解析（`strsep`）：
     - `BAN_V4`：`in4_pton` → 白名单检查 → 计算 `unban_time` → `kmalloc(GFP_KERNEL)` → 每桶锁插入 → 启动定时器 → 推送 netlink
     - `BAN_V6`：同上，IPv6 版本
     - `WL_V4`：`in4_pton` → IP 归一化 → `add_whitelist_entry(dev_name="restored")`
     - `WL_V6`：同上
  7. 标记 `state_restored = true`
- **导出**：`EXPORT_SYMBOL_GPL`

---

## 十三、并发模型

### 13.1 锁清单

| 锁 | 类型 | 保护对象 | 持有上下文 |
|----|------|---------|-----------|
| `fw->lock` | spinlock | 白名单检查（阶段 1） | process / softirq |
| `fw->ban_locks_ipv4[4096]` | spinlock | 封禁表 per-bucket | process / softirq / timer |
| `fw->ban_locks_ipv6[4096]` | spinlock | 同上 | 同上 |
| `fw->whitelist_lock` | spinlock | 白名单表增删 | process |
| `fw->flood_lock` | spinlock | 泛洪保护计数器 | process |
| `fw->rate_locks_ipv4[65536]` | spinlock_bh | 速率表 per-bucket | softirq / process |
| `fw->rate_locks_ipv6[65536]` | spinlock_bh | 同上 | 同上 |
| `idev->lock` | rwlock (bh) | IPv6 地址列表 | process |

### 13.2 锁顺序规则

1. **全局锁和每桶锁不嵌套**：必须先释放全局锁再获取每桶锁
2. **不同桶锁可并发**：无顺序要求
3. **RCU 读锁可与任何锁嵌套**：`rcu_read_lock` 不阻塞

### 13.3 RCU 使用模式

| 数据结构 | 读路径 | 写路径 |
|---------|--------|--------|
| 封禁表 | `rcu_read_lock` + `hlist_for_each_entry_rcu` | `hlist_del_rcu` + `call_rcu` |
| 白名单表 | 同上 | 同上 |
| 速率表 | 同上 | 同上 |
| 活跃封禁链表 | `list_for_each_entry_rcu` | `list_del_rcu` + `list_add_tail_rcu` |
| 子网白名单链表 | `list_for_each_entry_rcu` | 同上 |
| 本地 IP 缓存 | `rcu_dereference` + 数组遍历 | `rcu_assign_pointer` + `synchronize_rcu` + `kfree` |

### 13.4 定时器管理

| 定时器 | 类型 | 创建 | 取消 | 回调 |
|--------|------|------|------|------|
| `ban_entry.expire_timer` | per-entry | `timer_setup` + `mod_timer(unban_time)` | `timer_delete_sync` | `ban_entry_expire_callback` |
| `fw->sync_work` | delayed_work | `INIT_DELAYED_WORK` | `cancel_delayed_work_sync` | `sync_work_handler` |

**过期定时器语义**：
- 非永久封禁 → 创建定时器
- 永久封禁 → 不创建定时器
- 解封/过期 → `timer_delete_sync` 取消
- 续期 → `mod_timer` 重设
- 模块关闭 → `atomic_set(shutting_down, 1)` 防止回调中操作

---

## 十四、数据流

### 14.1 数据包从进入到封禁的完整路径

```
数据包到达
  │
  ▼
nf_hook_func_ipv4/ipv6
  │
  ├─ skb 验证（长度/版本/IHL/校验和）
  ├─ 源 IP 过滤（0/回环/多播/link-local）
  ├─ 协议分类（TCP 标志位提取/ICMP type 检查）
  ├─ per-CPU 全局流量计数
  │
  ▼
handle_ban_check
  │
  ├─ shutting_down 检查 → NF_ACCEPT
  ├─ 本地 IP 缓存检查 → NF_ACCEPT
  │
  ├─ 白名单精确匹配（hash 桶 O(1)）
  │   └─ 命中 → 跳过封禁检查
  │
  ├─ 白名单子网匹配（链表遍历 O(n)）
  │   └─ 命中 → 跳过封禁检查
  │
  ├─ 封禁表查找（hash 桶 O(1)）
  │   └─ 命中（永久/未过期）→ NF_DROP
  │
  ├─ 速率检测（fw_ddos_detection=1 && 非白名单）
  │   ├─ update_rate_stats（原子计数/窗口重置/EWMA）
  │   ├─ check_rate_violation（总速率 + 动态阈值）
  │   ├─ check_protocol_violation（SYN/UDP/ICMP Flood）
  │   ├─ check_tcp_flood_violation（ACK/RST/FIN Flood）
  │   └─ 违规 → ban_ip_permanent/with_duration
  │        └─ fw_netlink_send_event → NF_DROP
  │
  └─ 未违规 → NF_ACCEPT
```

### 14.2 封禁操作的锁流

```
ban_ip / ban_ip_permanent / ban_ip_with_duration
  │
  ▼
__do_ban_ip
  │
  ├─ 阶段 1：spin_lock(fw->lock)
  │   ├─ 白名单检查（RCU 遍历）
  │   ├─ 本机 IP 保护（RCU 遍历网络设备）
  │   └─ spin_unlock(fw->lock)
  │
  ├─ 阶段 2：spin_lock(ban_locks[bkt])
  │   ├─ 白名单二次检查
  │   ├─ 查找已有条目（已存在/过期续期/新插入）
  │   ├─ hlist_add_head_rcu + list_add_tail_rcu
  │   ├─ timer_setup + mod_timer（非永久）
  │   └─ spin_unlock(ban_locks[bkt])
  │
  └─ fw_netlink_send_ban_state_change（broadcast）
```

### 14.3 Netlink 双向通信流

```
内核 → 守护进程（broadcast）：
  DDoS 事件、封禁变更、白名单变更、配置变更、命令失败

守护进程 → 内核（unicast）：
  封禁/解封指令、配置更新、白名单操作、查询请求

内核 → 守护进程（unicast 回复）：
  封禁列表、统计、白名单列表、速率列表、配置确认
```

---

## 十五、边界条件和错误处理汇总

### 15.1 内存分配失败

| 位置 | 分配方式 | 失败处理 |
|------|---------|---------|
| `__do_ban_ip` | `GFP_ATOMIC` | `atomic_inc(alloc_failure_count)` + `-ENOMEM` |
| `add_whitelist_entry` | `GFP_KERNEL` | `-ENOMEM` |
| `create_rate_entry` | `GFP_ATOMIC` | `atomic_inc(alloc_failure_count)` + `ERR_PTR(-ENOMEM)` |
| `sync_work_handler` | `GFP_KERNEL` ×3 | 日志 + `return` / 降级 |
| `save_state_to_file` | `GFP_KERNEL` ×4 | 全部释放 + `-ENOMEM` |
| `restore_state_from_file` | `GFP_KERNEL` | `-ENOMEM` |

### 15.2 整数溢出防护

- `ban_ip`：`check_mul_overflow(ban_secs, HZ, &ban_duration)` → `-EINVAL`
- `ban_ip_with_duration`：同上
- `check_rate_violation`：`check_mul_overflow(baseline, ratio, &dynamic)` → `U64_MAX`
- `restore_state_from_file`：`check_mul_overflow(remaining, HZ, &duration)` → `continue`

### 15.3 TOCTOU 防护

- `save_state_to_file`：打开后 + 写入后两次 `vfs_getattr` 比较 inode/dev
- `ban_entry_expire_callback`：定时器触发后二次检查 `hlist_unhashed`
- `update_rate_stats`：窗口重置时双重检查 `time_after`
- `create_rate_entry`：获取锁后再次 `find_rate_entry_rcu` 检查

### 15.4 哈希碰撞防护

- `fw_hash_seed`：模块初始化时 `get_random_bytes` 随机生成
- IPv6 使用 `jhash(addr, 16, seed)` 而非简单截断
- IPv4 使用 `hash_min(ip, bits)`（32 位 IP 本身就是好的哈希源）

### 15.5 关闭期间防护

- `atomic_set(shutting_down, 1)` 在所有清理操作之前
- `handle_ban_check`：两次检查 `shutting_down`
- `ban_entry_expire_callback`：通过 `shutting_down` 防止关闭期间操作
- `sync_work_handler`：检查 `shutting_down`

---

## 十六、已知问题：`hash_ipv6()` 归属

详见审计报告首节分析。

**影响范围**：
- `ban-manager.c`：定义 + 内部 3 处使用
- `whitelist.c`：`extern` 声明 + 1 处使用
- `state-persist.c`：`extern` 声明 + 1 处使用

**修复方案**：删除 `hash_ipv6()` 定义，所有调用方改用 `firewall.h` 中已有的 `hash_ip(FW_AF_INET6, addr, BAN_HASH_BITS)` inline 函数。
