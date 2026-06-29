# 代码库逻辑穷举报告

> 生成时间：2026-06-26 | 64 个源文件 | 内核模块(C) + 守护进程(Rust) + Leptos 前端(Rust/WASM)

---

## 一、内核模块（11 个文件，~4500 行 C）

### 1.1 数据结构（firewall.h）

| 结构体 | 用途 | 关键字段 |
|--------|------|----------|
| `firewall_info` | 全局状态容器 | 封禁表(×2)、白名单表(×2)、哈希锁(×2)、白名单锁、速率检测器、统计、模块参数 |
| `ban_entry` | 封禁条目 | addr(af+ipv4/ipv6)、banned_at、duration、expire_timer、jail_name[32]、reason[32]、packets_dropped/accepted、rcu_head、ban_node(active链表)、hash(哈希链) |
| `whitelist_entry` | 白名单条目 | addr、mask(前缀/掩码)、device_name[16]、subnet_node、hash |
| `rate_entry` | 速率跟踪 | addr、packets/bytes/syn/udp/icmp/ack/rst/fin(8 个计数器)、window_start、last_activity |

**宏定义**：28 个，包括 `BAN_HASH_BITS=12`（4096桶）、`WHITELIST_HASH_BITS=6`（64桶）、`RATE_HASH_BITS=16`（65536桶）、`FW_AF_INET=2`/`FW_AF_INET6=10`

**内联函数**：6 个 — `hash_ip()`、`is_ipv4_mapped_ipv6()` 等

### 1.2 模块参数（firewall-main.c）

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `fw_ban_time` | 600 | 默认封禁时长(秒) |
| `fw_max_bans` | 4096 | 封禁表容量（已移除，按需扩展） |
| `fw_max_whitelist` | 64 | 白名单容量（已移除，按需扩展） |
| `fw_static_threshold` | 1 | 静态阈值开关 |
| `fw_dynamic_threshold` | 0 | 动态阈值开关 |
| `fw_ddos_detection` | 1 | DDoS 检测总开关 |
| `fw_log_level` | 1 | 日志级别(0=NONE, 1=ERROR, 2=WARN, 3=INFO, 4=DEBUG) |

### 1.3 初始化流程（firewall-main.c）

```
module_init(firewall_init)
  → kmalloc(firewall_info)
  → 初始化 4096 个 ban_locks_ipv4 + 4096 个 ban_locks_ipv6
  → 初始化 whitelist_lock
  → 初始化哈希表(×4)、链表(×2)
  → 初始化哈希种子(get_random_u32)
  → init_local_ip_cache()  — 发现本机所有 IP
  → register_netdevice_notifier()  — 监听网卡事件
  → fw_procfs_init()  — 创建 /proc/firewall/*
  → fw_netfilter_init()  — 注册 5 个 netfilter 钩子
  → fw_netlink_init()  — 创建 netlink socket
  → fw_rate_detector_init()  — 初始化速率检测
  → restore_state_from_file()  — 从持久化文件恢复封禁
```

### 1.4 netfilter 钩子（netfilter.c）

**5 个钩子点**（全部 NFPROTO_IPV4 + NFPROTO_IPV6 双注册）：

| 钩子 | 优先级 | 功能 |
|------|--------|------|
| `fw_nf_hook_pre_routing` | NF_IP_PRI_FILTER(-50) | 主检查点 |
| `fw_nf_hook_forward` | NF_IP_PRI_FILTER(-50) | 转发路径 |
| `fw_nf_hook_local_in` | NF_IP_PRI_FILTER(-50) | 本机入站 |
| `fw_nf_hook_local_out` | NF_IP_PRI_FILTER(-50) | 本机上站 |
| `fw_nf_hook_post_routing` | NF_IP_PRI_FILTER(-50) | 路由后 |

**实际只使用 `fw_nf_hook_pre_routing`**，其余 4 个返回 NF_ACCEPT。

**数据包处理路径**（fw_nf_hook_pre_routing）：
```
1. skb 有效性检查（NULL、线性化、最小长度）
2. 提取 IP 头（IPv4/IPv6 分支）
3. 提取协议类型（TCP/UDP/ICMP）
4. 提取源 IP 地址
5. 白名单检查 → is_in_whitelist() → NF_ACCEPT
6. 本地 IP 缓存检查 → NF_ACCEPT（热路径优化）
7. 封禁表查找 → find_ban_entry()
   7a. 命中 → NF_DROP，统计 packets_dropped++
   7b. 未命中 → 继续
8. 速率检测 → fw_rate_detector_check()
   8a. 超阈值 → 自动封禁 + NF_DROP
   8b. 未超 → NF_ACCEPT
9. 统计 packets_accepted++
```

**并发安全**：
- 白名单查找：RCU 读锁
- 本地 IP 缓存：无锁（启动时初始化，热路径只读）
- 封禁表查找：`rcu_read_lock()` + `hlist_for_each_entry_rcu()`
- 速率检测：per-CPU 计数器 + spinlock

### 1.5 封禁管理（ban-manager.c）

| 函数 | 锁 | 功能 |
|------|-----|------|
| `add_ban_entry(af, ip, duration, reason, jail_name)` | spinlock_bh | 创建 ban_entry + 启动 expire_timer |
| `remove_ban_entry(af, ip)` | spinlock_bh | 查找 + timer_delete_sync + 删除 + call_rcu |
| `find_ban_entry(af, ip)` | rcu_read_lock | 哈希表 O(1) 查找 |
| `ban_entry_expire_callback(timer)` | spinlock_bh | per-entry 定时器回调：删除 + call_rcu + netlink 通知 |
| `free_ban_entry_rcu(rcu_head)` | 无 | RCU 回调释放内存 |
| `hash_ipv6(addr)` | 无 | IPv6 地址哈希（jhash） |

**TTL 机制**：
- `duration > 0`：启动 `timer_setup` + `mod_timer(jiffies + duration * HZ)`
- `duration == 0`：永久封禁，不启动定时器
- `duration == -1`：永久封禁（语义等同 0）
- 定时器到期 → `ban_entry_expire_callback` → 删除 + netlink unban 事件

### 1.6 白名单管理（whitelist.c）

| 函数 | 功能 |
|------|------|
| `add_whitelist_entry()` | 创建条目 + 子网链表 + 解封匹配封禁 |
| `remove_whitelist_entry()` | 从哈希表 + 子网链表移除 + call_rcu |
| `is_in_whitelist()` | 精确匹配(哈希) + 子网匹配(链表遍历) |

**白名单添加时的解封逻辑**（4 个路径）：
1. IPv4 精确(/32)：O(1) 定位桶 → `timer_delete_sync` → `hlist_del_rcu` → `call_rcu`
2. IPv4 CIDR：遍历 `active_bans_list` → 同上的删除流程
3. IPv6 精确(/128)：同 IPv4 精确
4. IPv6 CIDR：同 IPv4 CIDR

### 1.7 速率检测（rate-detector.c）

| 函数 | 功能 |
|------|------|
| `fw_rate_detector_init()` | 分配哈希表(65536桶) |
| `fw_rate_detector_check(af, ip, protocol)` | 核心检测：累计计数 → 窗口比较 → 阈值判断 |
| `fw_rate_detector_cleanup()` | 清理过期条目(5分钟) |
| `fw_rate_detector_get_rates()` | 返回所有速率条目 |

**检测算法**：
```
1. hash(IP) → 查找或创建 rate_entry
2. 根据 protocol 递增对应计数器(packets/syn/udp/icmp/ack/rst/fin)
3. 检查时间窗口（1 秒）
4. 窗口到期 → 比较 PPS/BPS 与阈值
5. 超阈值 → 返回 RATE_EXCEEDED + 自动封禁
```

**阈值配置**：
- `max_packets_per_second`（默认 10000）
- `max_bytes_per_second`（默认 0 = 不检测）
- `max_syn/udp/icmp/ack/rst/fin_per_second`（协议专项）

### 1.8 procfs 接口（procfs.c）

| 文件 | 读操作 | 写操作 |
|------|--------|--------|
| `/proc/firewall/bans` | — | `IP [duration]` 封禁 / `unban IP` 解封 |
| `/proc/firewall/whitelist` | 列出所有白名单 | `CIDR` 添加 / `remove CIDR` 移除 |
| `/proc/firewall/stats` | 统计信息 | — |
| `/proc/firewall/config` | 当前配置 | 修改参数 |
| `/proc/firewall/rates` | 速率统计 | — |
| `/proc/firewall/version` | 模块版本 | — |

**写命令解析**：
- `bans`：解析 `IP [duration]` 或 `unban IP`
- `whitelist`：解析 `CIDR` 或 `remove CIDR`
- `config`：解析 `key=value` 格式

### 1.9 netlink 通信（netlink.c）

**21 种消息类型**：

| 编号 | 名称 | 方向 | 载荷 |
|------|------|------|------|
| 1 | DdosEvent | 内核→守护进程 | IP + reason[32] + rate_pps |
| 2 | BanIp | 守护进程→内核 | af + duration + addr + reason[32] |
| 3 | UnbanIp | 守护进程→内核 | af + addr |
| 4 | SetConfig | 守护进程→内核 | flags + ban_time + 8个阈值 + 动态阈值参数 |
| 5 | BanStateChange | 内核→守护进程 | action + af + duration + addr + reason + jail_name + packets_dropped/accepted + current_bans + whitelist_count |
| 6 | ListBansQuery | 守护进程→内核 | seq |
| 7 | ListBansResponse | 内核→守护进程 | count + FwNlBanEntry[] |
| 8 | StatsQuery | 守护进程→内核 | seq |
| 9 | StatsResponse | 内核→守护进程 | 6 个 u64 计数器（发送前 flush per-CPU） |
| 10 | ListWhitelistQuery | 守护进程→内核 | seq |
| 11 | ListWhitelistResponse | 内核→守护进程 | count + FwNlWhitelistEntry[] |
| 12 | AddWhitelist | 守护进程→内核 | af + prefix_len + addr + device[16] |
| 13 | RemoveWhitelist | 守护进程→内核 | af + prefix_len + addr |
| 14 | ConfigAck | 内核→守护进程 | applied_flags + rejected_flags |
| 15 | ListRatesQuery | 守护进程→内核 | seq |
| 16 | ListRatesResponse | 内核→守护进程 | count + total + global_pps/bps + FwNlRateEntry[] |
| 17 | WhitelistStateChange | 内核→守护进程 | action + af + prefix_len + addr + device |
| 18 | CmdResult | 内核→守护进程 | original_cmd + error_code + af + addr |
| 19 | ConfigChange | 内核→守护进程 | 复用 ConfigUpdate 格式 |
| 20 | AnalysisQuery | 守护进程→内核 | 仅消息头 |
| 21 | AnalysisResponse | 内核→守护进程 | 包大小/TTL/分片/UDP/ICMP/端口扫描/服务探测 |

**消息格式**：`#[repr(C, packed)]` + 大端传输 + 魔数 0x46574C4E

### 1.10 状态持久化（state-persist.c）

| 函数 | 功能 |
|------|------|
| `save_state_to_file()` | 序列化封禁表到 `/var/lib/firewall/state.bin` |
| `restore_state_from_file()` | 反序列化恢复封禁 + 发送 BanStateChange 事件 |

**持久化格式**：
```
header: magic(4) + version(4) + ban_count(4)
per-entry: af(1) + is_permanent(1) + duration(4) + banned_at(8) + addr(16) + jail_name(32) + reason(32)
```

### 1.11 清理逻辑（cleanup.c + netdev.c）

**cleanup.c**：
- `firewall_cleanup()`：反向拆除所有组件
- 拆除顺序：netfilter钩子 → netlink → procfs → netdev_notifier → rate_detector → free ban/whitelist

**netdev.c**：
- `fw_netdev_event_handler()`：监听 `NETDEV_UP`/`NETDEV_DOWN`/`NETDEV_CHANGE`
- 网卡 IP 变化时更新本地 IP 缓存

---

## 二、Rust 守护进程（53 个文件）

### 2.1 启动流程（main.rs）

14 步初始化：
1. CLI 解析（`--config`/`--config-dir`/`--daemon`/`--no-strict`/`--rollback`）
2. 回滚处理（`SIGUSR1` → 找 PID → 发信号）
3. 配置加载（文件或目录）
4. 持久化配置合并
5. 智能默认（SSH/WEB/FTP/MAIL/FRP/DB 匹配）
6. 配置校验
7. procfs 前置检查
8. 守护进程化（双 fork + setsid + PID flock）
9. 日志初始化（JSON Lines）
10. 信号注册
11. inotify 启动
12. 日志模式编译
13. 历史数据库初始化（SQLite）
14. Netlink 通信初始化 + 状态恢复

### 2.2 ban/ 模块

| 文件 | 核心函数 | 功能 |
|------|----------|------|
| mod.rs | `init_trusted_ips()` | 通过 netlink 设置白名单 |
| mod.rs | `remove_trusted_ips()` | 差集移除白名单 |
| operations.rs | `execute_ban_action()` | 统一封禁/解封入口 |
| operations.rs | `ban_ip()` / `unban_ip()` | 包装函数 |
| ip_validation.rs | `validate_ip()` | 拒绝 loopback/broadcast/multicast/link-local |
| ip_validation.rs | `validate_ipv4()` | 拒绝 0.x/127.x/224-239.x/255.255.255.255 |

### 2.3 config/ 模块

| 文件 | 功能 |
|------|------|
| args.rs | CLI 参数解析（手动实现，不依赖 clap） |
| parser.rs | YAML 解析 + 5 重安全检查（路径遍历/URL编码/Shell元字符/长度/规范化） |
| parser.rs | `serde(deny_unknown_fields)` 拒绝未知配置项 |
| file_loader.rs | 文件加载 + 17 字段原子回滚 |
| file_loader.rs | 目录加载（字母序遍历，任一失败整体回滚） |

**YAML 配置结构**：
```yaml
defaults: { max_retries, findtime, ban_time, interval, metrics_*, log_* }
jails: [{ enabled, log_files, max_retries, findtime, ban_time, regex/regexes }]
ddos: { enabled, per_ip_conn_rate/fail_rate, global_conn_rate, auto_ban_*, 
        check_interval, baseline_warmup_samples, 6个协议阈值, 3个算法开关, 
        max_bans_per_second, max_rate_entries }
webui: { sse_push_interval, rate_warning/critical_pps/syn }
trusted_ips: [String]
capacity: { max_ban_entries, max_whitelist_entries, max_rate_entries, max_local_ip_cache }
```

### 2.4 jail/ 模块

| 文件 | 功能 |
|------|------|
| service_match.rs | 6 类服务名匹配（SSH/WEB/FTP/MAIL/FRP/DB）+ 智能默认 |
| config_ops.rs | 配置克隆/校验/迁移/清理 |
| operations.rs | Jail 查找/创建/销毁/正则编译 |
| regex.rs | ReDoS 防护（嵌套量词/占有量词/分支数限制/量化交替） |

**智能默认值**：
| 服务 | max_retries | findtime | ban_time |
|------|-------------|----------|----------|
| SSH | 5 | 600 | 900 |
| WEB | 10 | 300 | 1800 |
| FTP | 5 | 600 | 1800 |
| MAIL | 5 | 300 | 1800 |
| FRP | 10 | 300 | 1800 |
| DB | 3 | 300 | 3600 |

**Jail 校验规则**：
- jails 数量 ∈ [1, 16]
- interval ∈ [1, 60]
- max_retries > 0, findtime > 0
- ban_time ∈ {-1} ∪ (0, ∞)，-1 = 永久
- enabled jail 必须有非空 log_files

### 2.5 failed_tracker/ 模块

| 函数 | 功能 |
|------|------|
| `count_recent()` | 滑动窗口计数（R9-7 优化：recent_head 跳过过期前缀） |
| `process_failed_timestamps()` | 追加时间戳 + FIFO 满时 pop_front |
| `cleanup_expired_entries()` | 清理全部时间戳已过期的条目 |
| `handle_failed_attempt_for_jail()` | **核心封禁触发** |

**封禁触发流程**：
```
1. 空 IP 跳过
2. failed_attempts++
3. 获取 failed_hash 写锁
4. 查找或创建 FailedEntry
5. 追加时间戳 + 滑动窗口统计
6. 达 max_retries 时：
   a. validate_ip → BanInfo
   b. 释放写锁（防死锁）
   c. ACTIVE_BAN_CACHE.try_insert() 原子检查
   d. ban::ban_ip() 通过 netlink 封禁
   e. 失败时 cache.remove() 回滚
   f. 成功后从 failed_hash 移除
```

### 2.6 file_monitor/ 模块

| 文件 | 功能 |
|------|------|
| state.rs | FileState（路径/偏移/inode/wd/jail_idx） + InotifyState |
| inotify_setup.rs | inotify 创建 + 文件监控注册（跳过符号链接） |
| monitor_loop.rs | poll 主循环 + 超时周期任务 |
| processor.rs | 文件读取 + 轮转检测 + 256KB 批量读 + 行处理 |
| periodic_tasks.rs | 6 个周期任务（60s/5min/2s 不同频率） |

**主循环逻辑**：
```
loop {
  poll(inotify_fd, interval*1000ms)
  if poll > 0:
    读 inotify 事件
    if GLOBAL_ROLLBACK → rollback_config()
    elif GLOBAL_RELOAD → reload_configuration()
    else → handle_inotify_events()
  elif poll == 0:
    handle_timeout()  // 6 个周期任务
  elif poll < 0 && errno != EINTR:
    break
}
```

**6 个周期任务**：
| 频率 | 任务 |
|------|------|
| 每 60s | partial line 清理、新日志文件检查、统计快照 |
| 按 ddos.check_interval | DDoS 过期条目清理 |
| 每 5 分钟 | 历史数据快照 |
| 每 2 秒 | 速率查询 + EWMA 基线下发到内核 |

### 2.7 history_snapshot/ 模块

SQLite 时间序列存储（`/var/lib/firewall/history.db`）：
- 保留最近 24 小时
- 每 5 分钟快照（bans/failed_attempts/ddos_events 三个指标）
- `record_snapshot()`、`get_trend_data()`、`get_jail_distribution()`

### 2.8 config_reloader.rs

**SIGHUP 热重载**（15 步）：
1. 确定配置源
2. 克隆旧配置
3. 创建新 Config
4. 解析新配置
5. 应用智能默认
6. 校验
7. 迁移 failed_hash
8. 编译正则
9. 更新 trusted_ips（差集）
10. 保存旧版本快照
11. 原子替换配置
12. 设置基线预热样本
13. 重建 inotify
14. 同步到 4 个组件（DdosDecisionEngine + 内核 + WebUI + Jail）
15. 持久化运行时配置

**配置版本历史**：最多 5 个版本（`SIGUSR1` 回滚到上一个）

### 2.9 netlink/ 模块

**socket 操作**：
- `AF_NETLINK` + `SOCK_RAW` + `NETLINK_USERSOCK(2)`
- 512KB 接收缓冲区
- 非阻塞 + 100ms poll 超时
- 截断检测（MSG_TRUNC）

**事件循环消息分发**：
- DdosEvent → DdosDecisionEngine::handle_event
- BanStateChange → ACTIVE_BAN_CACHE 更新 + 统计同步
- ListBansResponse → 恢复 ACTIVE_BAN_CACHE
- StatsResponse → DAEMON_STATS 更新
- ListWhitelistResponse → WHITELIST_CACHE 重建
- ListRatesResponse → RATE_CACHE 重建 + EWMA 基线更新
- ConfigAck → 日志记录
- WhitelistStateChange → WHITELIST_CACHE 更新
- CmdResult → 错误日志
- ConfigChange → 配置变更处理

### 2.10 ddos_detector.rs

**三层缓冲流水线**：
```
线程本地缓冲(50-500) → SegQueue → DashMap
```

- `ConnRateTracker`：IPv4 DashMap<u32> + IPv6 DashMap<[u8;16]>
- `record_connection()`：原子全局计数 + 线程本地缓冲（无锁）
- `detect()`：两阶段（读锁收集违规 → 写锁更新 violation_count）
- `cleanup_stale_entries()`：5 分钟无活动清理

**DdosDecisionEngine**：
- 每 IP 违规跟踪（violation_count + last_violation）
- 内核已封禁 → 守护进程只记录日志，不重复封禁
- `cleanup_stale_trackers()`：300 秒无活动清理

### 2.11 http_exporter/ 模块

**架构**：独立线程 + tokio(2 worker) + axum

**路由分层**：
- 无认证：`/health`、`/healthz`、6 SPA 路由、`/api/v1/events`(SSE)
- 需认证：`/metrics`、`/dashboard`、`/static/*`、14 REST API

**安全**：
- Basic Auth + 恒定时间比较（防时序攻击）
- 暴力破解防护（10 次失败 → 60s 锁定）
- CSP 头（Web UI 宽松，其他 `default-src 'none'`）

**22 个 Prometheus 指标**：4 内核 + 13 用户态 + 4 netlink 健康 + 1 uptime

### 2.12 log_parser/ 模块

**解析流程**：
```
行长度 > 8192 → None
有正则 → match_regex → captures → 从后往前扫描捕获组 → 长度窗口 7..46 → validate_ip_candidate
正则未匹配 → fallback_string_match（"Failed password for" / "authentication failure"）
```

**IP 候选定位**：词边界检查（前后不能是 hex/./:)

### 2.13 ip_utils.rs

| 函数 | 功能 |
|------|------|
| `parse_ipv4_fast()` | 单次遍历 → u32 |
| `parse_ipv6_fast()` | 支持压缩/环回/IPv4映射 → [u8;16] |
| `parse_ip()` | 统一入口 → ParsedIp |
| `validate_ipv4_chars_simd()` | SSE2 加速验证（x86_64） |
| `u32_to_ipv4()` / `bytes_to_ipv6()` | 反向转换 |

### 2.14 web_ui/ 模块

**14 个 REST API 端点**：

| 路由 | 方法 | 功能 |
|------|------|------|
| `/api/v1/stats` | GET | 统计数据 + 图表数据 |
| `/api/v1/bans` | GET | 分页封禁列表（7 种排序） |
| `/api/v1/bans` | POST | 封禁 IP |
| `/api/v1/bans/:ip` | DELETE | 解封 IP |
| `/api/v1/jails` | GET | Jail 列表 |
| `/api/v1/jails/:name` | PUT | 启用/禁用 Jail |
| `/api/v1/config` | GET | 获取配置 |
| `/api/v1/config` | PUT | 更新配置 |
| `/api/v1/whitelist` | GET | 白名单列表 |
| `/api/v1/whitelist` | POST | 添加白名单 |
| `/api/v1/whitelist/:cidr` | DELETE | 移除白名单 |
| `/api/v1/rates/current` | GET | 当前 DDoS 速率 |
| `/api/v1/rates/history` | GET | 速率历史（1 小时） |
| `/api/v1/logs` | GET | 日志分页查询 |

**SSE 推送**（`/api/v1/events`）：
- 连接数限制 10（原子 CAS 防 TOCTOU）
- 推送间隔可配（默认 1s）
- 推送顺序：connected → stats → bans → jails → whitelist → rates → 循环
- Keep-Alive 15s

**日志 SSE**（`/api/v1/logs/stream`）：
- 连接数限制 5
- tail -f 语义 + 轮转检测
- 500ms 轮询

### 2.15 types/ 模块

**ActiveBanCache**：双索引设计
- `bans: HashMap<String, Arc<BanInfo>>` — IP → 封禁信息
- `by_jail: HashMap<String, HashSet<String>>` — jail → IP 集合
- `try_insert()`：原子性检查插入（消除 check-then-act 竞态）

**DaemonStats**：18 个原子计数器（Relaxed 序）

**EWMA 动态阈值**：
- 启动期（前 50 次）α=0.1 快速收敛
- 稳定期 α=0.01 长期跟踪
- `update_traffic_baseline(global_pps, global_bps)` — saturating 防溢出

### 2.16 基础设施

| 模块 | 功能 | unsafe 数 |
|------|------|-----------|
| daemonizer.rs | 双 fork + setsid + PID flock + fd 重定向 | 7 |
| signals.rs | 3 个全局 AtomicBool + 5 个信号处理 | 1（5 次 sigaction） |
| logger.rs | slog JSON Lines + thread-local 缓存 + 节流宏 | 1 |

---

## 三、Leptos WASM 前端（~15 个文件）

### 3.1 路由

| 路径 | 页面 | 功能 |
|------|------|------|
| `/dashboard` | Dashboard | 威胁状态 + 攻击源 TOP10 + 协议分布 + 流量趋势 |
| `/bans` | Bans | 封禁列表 + 手动封禁 + 解封 + 原因分布 |
| `/whitelist` | Whitelist | 白名单管理 |
| `/jails` | Jails | Jail 卡片 + 分布饼图 + 启用/禁用 |
| `/ddos` | DdosMonitor | 威胁状态 + 协议分布 + 阈值对比 + 流量趋势 |
| `/logs` | Logs | 实时日志流 + 级别过滤 + 关键词搜索 |
| `/settings` | Settings | 配置编辑 + 系统信息 |

### 3.2 状态管理

**SseState**（全局 Signals）：
- stats / bans / jails / rates / whitelist / rate_history
- 主 SSE + 日志 SSE 分离（独立重连）
- 指数退避重连（max 30s）+ 防重入

### 3.3 图表组件（纯 SVG）

- **LineChart**：渐变填充 + 发光滤镜 + 数据点高亮 + 网格线
- **PieChart**：环形图 + 6 色循环 + 中心总量

### 3.4 主题

- dark/light 双主题
- localStorage 持久化
- `<html data-theme="dark|light">`

---

## 四、跨模块关注点

### 4.1 并发安全

| 层级 | 机制 | 锁序规则 |
|------|------|----------|
| 内核 netfilter | RCU 读锁 | 白名单 → 封禁表（禁止反向） |
| 内核 procfs 写 | spinlock_bh | 每桶独立锁 |
| 内核白名单 | whitelist_lock(spinlock) | 全局唯一白名单锁 |
| 守护进程 netlink | 独立接收线程 | OnceLock 单例 |
| 守护进程状态 | RwLock + AtomicBool | bans → by_jail |
| 守护进程统计 | AtomicU64(Relaxed) | 无锁 |

### 4.2 错误处理

- **内核**：ENOMEM / EINVAL / EEXIST / ENOENT 返回值
- **守护进程**：`anyhow::Result<T>` 全链路传播
- **前端**：`ApiResponse { code, data, message }` 统一信封

### 4.3 资源管理

| 资源 | 管理方式 |
|------|----------|
| 内核 ban_entry | per-entry 定时器 + RCU + call_rcu |
| 内核 whitelist_entry | RCU + call_rcu |
| 内核 rate_entry | cleanup 定时器（5 分钟） |
| 守护进程 inotify fd | RwLock + close_on_drop |
| 守护进程 netlink fd | Drop trait close |
| 守护进程 PID 文件 | mem::forget 保持 flock |
| 守护进程 SQLite | Lazy<Mutex<Option<Connection>>> |
| 前端 SSE | SseSource Drop close() |

### 4.4 unsafe 块统计

| 模块 | 数量 | 用途 |
|------|------|------|
| netlink/protocol.rs | 14 | 消息序列化/反序列化 |
| netlink/mod.rs | 13 | socket 操作 |
| ban/procfs.rs | 11 | fd 生命周期 |
| daemonizer.rs | 7 | fork/flock/dup2 |
| signals.rs | 1 | sigaction |
| logger.rs | 1 | from_raw_fd |
| ip_utils.rs | 1 | SSE2 SIMD |
| file_monitor/monitor_loop.rs | 1 | poll |
| **合计** | **49** | 全部带 `// SAFETY:` 注释 |

---

## 五、数据流全景

```
用户日志 → inotify 事件 → process_new_lines() → regex 匹配 → IP 提取
  → failed_tracker 计数 → 达阈值 → ban::ban_ip()
    → netlink BanIp → 内核 add_ban_entry() → netfilter NF_DROP
    
内核检测 DDoS → rate_detector 超阈值 → 自动封禁
  → netlink BanStateChange → ACTIVE_BAN_CACHE 更新

用户 procfs write → 内核 add/remove_ban_entry()
  → netlink BanStateChange → 守护进程缓存同步

守护进程热重载 → SIGHUP → reload_configuration()
  → netlink SetConfig → 内核参数更新
  → ConfigAck → 确认生效

前端 SSE → /api/v1/events → 定时推送 DAEMON_STATS + ACTIVE_BAN_CACHE
  → 前端 Signals 更新 → 响应式渲染
```

---

## 六、关键发现

### 6.1 `hash_ipv6()` 归属问题（agent 发现）

`hash_ipv6()` 定义在 `ban-manager.c`，被 `whitelist.c` 和 `state-persist.c` 通过 `extern` 手动声明引用。`firewall.h` 中既无定义也无声明。

`firewall.h` 已有 `static inline hash_ip(af, ip, bits)` 可完全替代。修复方案：删除 `hash_ipv6()` 独立定义，3 个文件共 5 处调用改为 `hash_ip(FW_AF_INET6, addr, BAN_HASH_BITS)`。

### 6.2 已修复的历史问题

| 问题 | 修复提交 | 状态 |
|------|----------|------|
| whitelist.c 解封未取消定时器(use-after-free) | 39a9345 | ✅ 已修复 |
| 全局 cleanup_timer 轮询 | cda66b2 | ✅ 已移除，改为 per-entry |
| 内核数据完整性 gaps | 多个提交 | ✅ 全部修复 |
