# Firewall 架构设计文档

**版本**: v2.0 | **最后更新**: 2026-05-04

---

## 目录

1. [系统概览](#1-系统概览)
2. [内核模块设计](#2-内核模块设计)
3. [守护进程设计](#3-守护进程设计)
4. [数据流：从日志行到 IP 封禁](#4-数据流从日志行到-ip-封禁)
5. [组件交互图](#5-组件交互图)
6. [关键设计决策](#6-关键设计决策)
7. [模块依赖图](#7-模块依赖图)

---

## 1. 系统概览

Firewall 是 Linux 内核模块版本的 fail2ban，采用**双层架构**：内核态负责高性能数据包过滤，用户态负责智能日志分析和策略决策。

```
  外部网络流量
       │
       ▼
┌──────────────────────────────────────────────────┐
│              内核空间 (Ring 0)                     │
│                                                  │
│  Netfilter Hook (PRE_ROUTING, 优先级 filter-1)    │
│  ┌────────────┐  ┌──────────┐  ┌──────────────┐  │
│  │ 白名单检查  │─▶│封禁表检查 │─▶│DROP / ACCEPT │  │
│  │ RCU 遍历    │  │ 哈希O(1)  │  │              │  │
│  └────────────┘  └──────────┘  └──────────────┘  │
│                                                  │
│  ban_table(1024)  whitelist_table(64)  清理定时器  │
│  procfs: /proc/firewall/{bans,whitelist,config,   │
│                          stats}                   │
└──────────────────────┬───────────────────────────┘
                       │ procfs 读写
                       ▼
┌──────────────────────────────────────────────────┐
│              用户空间 (Ring 3)                     │
│                                                  │
│  firewall-daemon (主线程)                          │
│  ┌─────────┐  ┌─────────┐  ┌──────────────────┐  │
│  │ inotify │─▶│ PCRE2   │  │ Jail 系统(≤16个)  │  │
│  │ 日志监控 │  │ 正则引擎 │  │ 独立计数/阈值     │  │
│  └─────────┘  └─────────┘  └──────────────────┘  │
│                                                  │
│  HTTP Exporter(:9119)    SQLite 持久化(可选)       │
│  libmicrohttpd           线程安全, SQLITE_TRANSIENT│
└──────────────────────────────────────────────────┘
```

**内核模块**：

| 组件 | 文件 | 行数 | 职责 |
|------|------|------|------|
| 内核模块 | `src/kernel-module/firewall.c` | 2462 | Netfilter 过滤、封禁表管理 |
| 内核头文件 | `src/kernel-module/firewall.h` | 191 | 数据结构、日志宏、函数声明 |

**守护进程模块**（v2.0 重构后，原 3475 行单文件拆分为 8 个模块）：

| 模块 | 文件 (.c/.h) | 行数 | 职责 |
|------|-------------|------|------|
| 共享头文件 | `firewall-daemon.h` | 202 | 类型定义、宏、常量、全局 extern 声明 |
| 主入口 | `firewall-daemon.c` | 361 | main()、信号处理、守护进程化、清理 |
| Jail 管理 | `jail-manager.c/h` | 596 | Jail 生命周期、配置克隆、正则编译、迁移 |
| 配置解析 | `config-parser.c/h` | 1012 | YAML 解析、目录加载、CLI 参数、路径验证 |
| 日志解析 | `log-parser.c/h` | 201 | PCRE2 正则匹配、IP 提取、日志行解析 |
| 失败追踪 | `failed-tracker.c/h` | 350 | khash 失败记录、时间窗口计数、封禁阈值检查 |
| 封禁管理 | `ban-manager.c/h` | 260 | 封禁/解封操作、procfs 安全写入、IP 验证 |
| 文件监控 | `file-monitor.c/h` | 780 | inotify 事件、日志读取、轮转检测、monitor_loop |

**已有独立模块**：

| 模块 | 文件 | 行数 | 职责 |
|------|------|------|------|
| HTTP 导出器 | `http-exporter.c` | 374 | Prometheus 指标服务 |
| SQLite 持久化 | `sqlite-persistent.c/h` | 793 | 永久封禁数据库 |

**工具库**：

| 模块 | 文件 | 行数 | 职责 |
|------|------|------|------|
| 哈希库 | `khash.h` | 627 | 头文件哈希库（第三方，O(1) 查找） |

> 总计：18 个文件，~8319 行。原单文件 3475 行 → 模块化后平均每模块 ~460 行。

---

## 2. 内核模块设计

### 2.1 Netfilter Hook 数据流

钩子注册在 `NF_INET_PRE_ROUTING`，优先级 `NF_IP_PRI_FILTER - 1`（高于 iptables filter 链）：

```
  数据包到达
    │
    ▼
  skb 验证 (skb!=NULL, len>=IP头, pskb_may_pull)
    │
    ▼
  IP 头部校验 (version==4, ihl∈[5,15], 长度一致)
    │
    ▼
  分片包检测 → 分片包直接 ACCEPT
    │
    ▼
  保留地址过滤 (0.0.0.0, 127.x, 224.x/4, 255.x → ACCEPT)
    │
    ▼
  ┌─ RCU 读锁 ──────────────────────────────┐
  │  白名单遍历 (子网匹配) → 命中 → ACCEPT   │
  │  封禁表查找 hash_for_each_possible_rcu   │
  │    → 命中且未过期 → NF_DROP              │
  │    → 未命中 → NF_ACCEPT                  │
  └─────────────────────────────────────────┘
```

**快速路径**：白名单 IP 首次检查即放行，不进入封禁表查找。

### 2.2 哈希表设计

| 哈希表 | 容量 | Hash Bits | 查找 | 用途 |
|--------|------|-----------|------|------|
| `ban_table` | 1024 | 10 | O(1) | 封禁 IP |
| `whitelist_table` | 64 | 6 | O(1) 均摊 | 白名单 IP/子网 |

```c
struct ban_entry {
    __be32 ip;                 /* 网络字节序 IPv4 */
    unsigned long ban_time;    /* 封禁时间 (jiffies) */
    unsigned long unban_time;  /* 解封时间 (0=永久) */
    atomic_t retry_count;
    bool is_permanent;
    struct hlist_node hash;
    struct rcu_head rcu_head;  /* RCU 延迟释放 */
};
```

白名单支持子网匹配：存储时 IP 按掩码归一化，匹配使用 `(src_ip & mask) == (entry_ip & mask)`。

### 2.3 RCU 并发机制和锁设计

| 操作 | 机制 | 说明 |
|------|------|------|
| 数据包路径查找 | `rcu_read_lock()` | 无锁读取，零等待 |
| 封禁/解封 | `spin_lock()` | 写操作互斥 |
| 过期条目释放 | `call_rcu()` | 延迟释放，安全回收 |
| 洪泛保护 | `spin_lock(&flood_lock)` | 独立锁减少竞争 |

```c
/* RCU 回调 - 安全时机释放内存 */
static void free_ban_entry_rcu(struct rcu_head *head) {
    struct ban_entry *e = container_of(head, struct ban_entry, rcu_head);
    kfree(e);
}

/* 删除条目: 先标记删除，再延迟释放 */
hlist_del_rcu(&entry->hash);
call_rcu(&entry->rcu_head, free_ban_entry_rcu);
```

**优势**：热路径（数据包处理）完全无锁，仅 `rcu_read_lock()`（禁止抢占），确保网络延迟最小化。

### 2.4 procfs 接口

| 路径 | 模式 | 功能 |
|------|------|------|
| `/proc/firewall/bans` | 读写 | 封禁列表；写入 `IP` / `IP seconds` / `unban IP` |
| `/proc/firewall/whitelist` | 读写 | 白名单；`CIDR` / `add CIDR` / `remove CIDR` |
| `/proc/firewall/config` | 读写 | 运行时配置（目前仅 `ban_time`） |
| `/proc/firewall/stats` | 只读 | 统计信息 |

### 2.5 统一分级日志系统

```c
#define FW_LOG_LEVEL_ERR    1  /* 始终输出 */
#define FW_LOG_LEVEL_WARN   2  /* 重要警告 */
#define FW_LOG_LEVEL_INFO   3  /* 正常操作 */
#define FW_LOG_LEVEL_DEBUG  4  /* 开发调试 */

fw_pr_err("...");              /* 错误 - 始终输出 */
fw_pr_info_ratelimited("..."); /* 高频日志限流，防风暴 */
```

编译时通过 `DEBUG_LEVEL` (0-4) 控制输出级别，生产环境建议 `DEBUG_LEVEL=0`。

### 2.6 自动过期清理机制

定时器实现**增量清理**，避免一次性遍历全表：

```c
void cleanup_expired_bans(struct firewall_info *fw) {
    int start = fw->cleanup_last_bucket;  /* 从上次位置继续 */
    int max_per_call = 50;                /* 每次最多 50 个桶 */
    /* 遍历桶 → spin_lock → 收集过期条目 → unlock → call_rcu 释放 */
    fw->cleanup_last_bucket = (i >= HASH_SIZE) ? 0 : i;  /* 保存进度 */
}
```

### 2.7 IP 白名单保护

- **自动发现**：模块加载时遍历系统网络接口，自动添加本地 IP
- **手动添加**：支持 IP 和 CIDR 子网
- **安全保护**：白名单 IP 不能被 `ban_ip()` 封禁（返回 `-EPERM`）

---

## 3. 守护进程设计

v2.0 将原 3475 行单文件 `firewall-daemon.c` 重构为 **8 个职责清晰的模块**，所有模块通过 `firewall-daemon.h` 共享类型定义、全局状态（`cfg`、`config_mutex`、`daemon_stats`）和宏。

### 3.1 模块架构总览

```
                    ┌─────────────────────┐
                    │  firewall-daemon.h   │  ← 共享头文件
                    │  (类型/宏/externs)   │     所有模块依赖
                    └──────────┬──────────┘
                               │
          ┌─────────┬──────────┼──────────┬─────────┐
          ▼         ▼          ▼          ▼         ▼
   ┌──────────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌──────────┐
   │jail-mgr  │ │config │ │log    │ │failed │ │ban-mgr   │
   │.c/h      │ │-parser│ │-parser│ │-tracker│ │.c/h      │
   └──────────┘ └───────┘ └───────┘ └───────┘ └──────────┘
          │                              │
          └──────────┬───────────────────┘
                     ▼
              ┌────────────┐
              │file-monitor│  ← 主循环，串联所有模块
              │.c/h        │
              └────────────┘
```

**共享头文件 `firewall-daemon.h` 提供**：
- 核心数据结构：`struct jail`、`struct config`、`struct failed_entry`、`struct file_state`
- 全局状态 extern：`cfg`、`config_mutex`、`daemon_stats`、`inotify_fd`、`file_states[]`、`sqlite_db`
- 统一日志宏：`daemon_log_err/warn/info/debug`（syslog 封装）
- 常量定义：`MAX_JAILS`(16)、`MAX_LOG_FILES`(10)、`DEFAULT_*` 默认值
- 枚举类型：`ban_action_t`（TEMP/PERMANENT/UNBAN/UNBAN_PERM）

### 3.2 Jail 系统架构（`jail-manager.c/h`）

类似 fail2ban 的多服务隔离，每个 Jail 独立监控、计数、封禁：

```
   Global Config (defaults)
   ┌─────────────────────────────────────┐
   │ max_retries=5  findtime=600  ...    │
   └─────────────────────────────────────┘
          │
   ┌──────┴──────┐  ┌──────┴──────┐
   │ Jail: sshd  │  │ Jail: frp   │
   │ log:auth.log│  │ log:frp.log │
   │ max_retry:5 │  │ max_retry:10│
   │ regex:builtin│ │ regex:custom│
   │ failed_hash │  │ failed_hash │
   └─────────────┘  └─────────────┘
          │                │
          └───────┬────────┘
                  ▼
          execute_ban_action()
          → procfs 写入 + SQLite 持久化
```

**限制**：最多 16 个 Jail，每个最多 10 个日志文件，自定义 regex 最大 1024 字节（最多 50 个 `|`）。

**核心函数**：
| 函数 | 职责 |
|------|------|
| `find_or_create_jail()` | 查找或创建 Jail |
| `clone_jail()` / `config_clone()` | 深拷贝配置（双缓冲热重载用） |
| `migrate_failed_entries()` | 迁移失败计数器（保留攻击记录） |
| `compile_jail_regex()` | PCRE2 正则编译 |
| `cleanup_all_jails()` | 释放所有 Jail 资源 |

### 3.3 日志监控（`file-monitor.c/h`）

`inotify` + `select()` 实现事件驱动 + 定时轮询混合模式：

```
   monitor_loop():
     select(inotify_fd, timeout=interval)
       │
       ├─ 超时 → cleanup_expired_bans()
       │        → 检查 reload_config (SIGHUP)
       │
       └─ inotify 事件 (IN_MODIFY | IN_MOVED_TO)
            → 匹配 file_states[wd]
            → 检测日志轮转 (inode 变化 / 文件减小)
            → process_new_lines(idx)
               → parse_log_line()          ← log-parser.c/h
               → handle_failed_attempt_for_jail() ← failed-tracker.c/h
```

每个 Jail 维护 8192 字节 `partial_line_buffer`，处理跨读取调用的不完整行。

### 3.4 PCRE2 正则引擎（`log-parser.c/h`）

| 特性 | POSIX regex | PCRE2 |
|------|------------|-------|
| 性能 | 基准 | JIT 加速 2-10x |
| 超时防护 | 无 | 内置 match_context 超时 |
| 捕获组 | 硬编码索引 | 动态检测 |

**ReDoS 防护**：编译前检查嵌套量词（`)`, `)*` 等）、交替数量（≤50）、模式长度（≤1024）。

**核心函数**：
| 函数 | 职责 |
|------|------|
| `parse_log_line()` | 使用 Jail 的 PCRE2 正则匹配日志行 |
| `extract_and_validate_ip()` | 提取并验证 IP 地址 |
| `extract_ip()` / `extract_ipv4()` | 基础 IP 提取（回退模式） |

### 3.5 失败追踪与封禁阈值（`failed-tracker.c/h`）

使用 khash (`khash_t(ip_map)`) 实现 O(1) 查找，每个 Jail 独立维护失败记录：

```
   handle_failed_attempt_for_jail(jail, ip, max_retries, findtime)
     │
     ├─ find_entry_for_jail() → 查找已有记录
     │   (未找到 → create_entry_for_jail())
     │
     ├─ process_failed_timestamps() → 添加时间戳
     │
     ├─ count_recent() → 滑动窗口计数
     │   (仅统计 findtime 时间窗口内的失败)
     │
     └─ check_and_ban() → 阈值检查
         │ count >= max_retries
         ▼
         execute_ban_action() → 触发封禁
         remove_entry_for_jail() → 清除记录
```

**核心函数**：
| 函数 | 职责 |
|------|------|
| `handle_failed_attempt_for_jail()` | 主入口：记录失败、计数、检查阈值 |
| `find_entry_for_jail()` | khash O(1) 查找 |
| `count_recent()` | 滑动窗口内失败计数 |
| `check_and_ban()` | 阈值判断并触发封禁 |

> **向后兼容**：旧的全局函数 `find_entry()` / `create_entry()` / `remove_entry()` / `handle_failed_attempt()` 保留为包装器，内部委托给 Jail 感知版本。新代码应使用 `_for_jail` 后缀的函数。

### 3.6 封禁操作（`ban-manager.c/h`）

统一封禁/解封入口，支持四种动作类型：

```
   execute_ban_action(action, ip)
     │
     ├─ BAN_ACTION_TEMP      → procfs 写入 IP（临时封禁）
     ├─ BAN_ACTION_PERMANENT → procfs 写入 IP + SQLite 持久化
     ├─ BAN_ACTION_UNBAN     → procfs 写入 "unban IP"
     └─ BAN_ACTION_UNBAN_PERM → SQLite 删除 + procfs 解封
```

**核心函数**：
| 函数 | 职责 |
|------|------|
| `execute_ban_action()` | 统一封禁/解封入口 |
| `validate_ipv4()` | IP 格式验证 + 网络字节序转换 |
| `secure_procfs_write()` | 安全的 procfs 文件写入 |
| `cleanup_expired_bans()` | 清理内核过期封禁 |

### 3.7 配置解析与热重载（`config-parser.c/h` + `jail-manager.c/h`）

```
   SIGHUP → reload_config=1 → monitor_loop 超时检查
     │
     ├─ 阶段1: 无锁解析 YAML 到临时 config  ← config-parser.c/h
     │    parse_config_file() / load_config_directory()
     ├─ 阶段2: 短暂持锁交换  ← jail-manager.c/h
     │    → config_clone() 深拷贝
     │    → migrate_failed_entries() 迁移失败计数
     │    → free_config_partial() 释放旧资源
     ├─ 阶段3: 重建 inotify 监控  ← file-monitor.c/h
     └─ 解析失败 → 保留旧配置
```

**优势**：解析不阻塞日志处理，切换瞬间完成，失败时不影响运行。

### 3.8 HTTP Exporter（`http-exporter.c`）

`libmicrohttpd` 实现，独立 pthread 运行：

| 端点 | 说明 |
|------|------|
| `/metrics` | 14 项 Prometheus 指标 |
| `/health`, `/healthz` | 健康检查 |

关键配置：端口 9119，最大连接 10，超时 5 秒。指标来源涵盖内核模块（包计数、封禁计数）和守护进程（解析行数、封禁 IP 数、配置重载次数等）。

### 3.9 SQLite 持久化（`sqlite-persistent.c/h`）

```c
struct sqlite_db {
    sqlite3 *conn;
    char db_path[512];
    pthread_mutex_t lock;  /* 线程安全 */
};
```

所有 `sqlite3_bind_text()` 使用 `SQLITE_TRANSIENT`（非 `SQLITE_STATIC`），防止 use-after-free。

---

## 4. 数据流：从日志行到 IP 封禁

```
   攻击者 SSH 暴力破解
     │ 失败日志
     ▼
   /var/log/auth.log
     │ inotify IN_MODIFY
     ▼
   file-monitor.c: monitor_loop()
     → select() 收到事件
     → process_new_lines() 读取日志
     ▼
   log-parser.c: parse_log_line()
     → PCRE2 JIT 正则匹配
     → extract_and_validate_ip() 提取 IP
     ▼
   failed-tracker.c: handle_failed_attempt_for_jail()
     → find_entry_for_jail() / create_entry_for_jail()  khash O(1)
     → process_failed_timestamps() 添加时间戳
     → count_recent() 滑动窗口计数
     → check_and_ban() 阈值检查
     │ 失败次数 >= max_retries
     ▼
   ban-manager.c: execute_ban_action()
     → validate_ipv4() IP 验证
     → secure_procfs_write("/proc/firewall/bans", "192.168.1.100\n")
     → SQLite 持久化 (如启用)
     │ procfs 写入
     ▼
   内核模块: bans_write()
     → 解析 IP → 验证 → 白名单检查
     → __do_ban_ip(): spin_lock → hash_add → unlock
     │ 封禁生效
     ▼
   后续数据包: nf_hook_func_ipv4()
     → RCU 读锁 → 白名单检查 → 封禁表查找
     → 命中 → NF_DROP ◀── 数据包丢弃
```

**时间线**：日志写入 → inotify 触发（毫秒级）→ 正则匹配 (`log-parser.c`) → 计数器检查 (`failed-tracker.c`) → procfs 写入 (`ban-manager.c`) → 内核封禁（微秒级）→ 后续包 DROP。

---

## 5. 组件交互图

```
   ┌─────────────┐  inotify   ┌──────────────────────────────────────┐  procfs   ┌─────────────┐
   │ 系统日志     │ ─────────▶ │         firewall-daemon 进程          │ ─────────▶│  内核模块    │
   │ auth.log    │            │                                      │           │  firewall.ko │
   │ frp.log     │            │  ┌────────────┐  ┌─────────────┐     │           │             │
   └─────────────┘            │  │file-monitor│─▶│ log-parser  │     │           │ ┌─────────┐ │
                              │  │ .c/h       │  │ .c/h        │     │           │ │ban_table│ │
                              │  └─────┬──────┘  └─────────────┘     │           │ │(1024)   │ │
                              │        │                             │           │ └─────────┘ │
                              │        ▼                             │           │ ┌─────────┐ │
                              │  ┌─────────────┐  ┌─────────────┐   │           │ │whitelist│ │
                              │  │failed-tracker│─▶│ban-manager  │   │           │ │(64)     │ │
                              │  │ .c/h (khash) │  │ .c/h        │   │           │ └─────────┘ │
                              │  └─────────────┘  └──────┬──────┘   │           │ ┌─────────┐ │
                              │  ┌─────────────┐         │          │           │ │Netfilter│ │
                              │  │config-parser│         │          │           │ │ Hook    │ │
                              │  │ .c/h        │         │          │           │ └─────────┘ │
                              │  └─────────────┘         │          │           └─────────────┘
                              │  ┌─────────────┐         │          │
                              │  │jail-manager │◀────────┘          │
                              │  │ .c/h        │                    │
                              │  └─────────────┘                    │
                              └──────────┬───────────────────────────┘
                                         │
                      ┌──────────────────┼──────────────────┐
                      ▼                  ▼                  ▼
            ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
            │HTTP Exporter │  │ SQLite 持久化 │  │ khash.h (工具库)  │
            │ :9119        │  │ (可选)       │  │ O(1) 哈希查找     │
            └──────────────┘  └──────────────┘  └──────────────────┘
```

---

## 6. 关键设计决策

### 6.1 为什么选择内核态而非 iptables

| 方案 | 查找复杂度 | 延迟 | 用户态交互 |
|------|-----------|------|-----------|
| **内核模块 (当前)** | O(1) 哈希 | 零切换 | 仅 procfs 配置 |
| iptables 规则 | O(n) 线性遍历 | 每次规则匹配 | 规则更新需系统调用 |
| nftables | 优化规则集 | 中等 | 仍需用户态交互 |

**核心理由**：
1. **性能**：1024 容量哈希表 O(1) vs iptables 1000 条规则线性遍历
2. **延迟**：内核态直接 DROP，无用户态-内核态切换
3. **原子性**：封禁在内核态原子完成，无 TOCTOU 竞态

### 6.2 RCU vs spinlock 的选择

| 机制 | 读操作 | 写操作 | 适用场景 |
|------|--------|--------|---------|
| 纯 spinlock | 需获取锁（可能阻塞） | 获取锁 | 读写频率相近 |
| **RCU + spinlock** | `rcu_read_lock()` 无锁 | spinlock 序列化 | **读多写少（本场景）** |
| rwlock | 读锁（共享） | 写锁（独占） | 中等读写比 |

**选择 RCU**：数据包路径是读密集型（每个包都查表），RCU 读路径零等待（仅禁止抢占）。写操作（封禁/解封）通过 procfs 触发，频率远低于包到达率，spinlock 序列化可接受。

```c
/* 热路径：无锁读取 */
rcu_read_lock();
entry = __find_ban_entry_rcu(fw, ip);  /* O(1)，无锁 */
rcu_read_unlock();

/* 冷路径：spinlock 序列化 */
spin_lock(&fw->lock);
hash_add(fw->ban_table, &entry->hash, hash);
spin_unlock(&fw->lock);
call_rcu(&entry->rcu_head, free_ban_entry_rcu);
```

### 6.3 双缓冲配置解析的设计

```
  传统方案（有锁解析）:
  持有 config_mutex → 解析 YAML (数秒) → 更新配置 → 释放锁
  ❌ 解析期间所有日志处理被阻塞

  双缓冲方案（当前）:
  阶段1: 无锁解析 YAML 到临时结构（主循环正常运行）
  阶段2: 短暂持锁 → memcpy 交换 → 迁移 failed_hash → 释放旧资源
  ✅ 解析不阻塞日志处理，切换瞬间完成
```

**关键设计点**：
- **failed_hash 迁移**：配置重载时通过 `jail-manager.c/h` 的 `migrate_failed_entries()` 保留失败计数器，防止攻击者利用重载间隙"重置"计数
- **原子性**：配置交换在短暂持锁期间完成（`config_clone()` 深拷贝 + memcpy 交换），所有线程看到一致视图
- **失败安全**：解析失败保留旧配置，不影响运行

---

## 7. 模块依赖图

### 7.1 依赖关系

```
                    ┌─────────────────────┐
                    │  firewall-daemon.h   │  ← 共享头文件（所有模块依赖）
                    │  (类型/宏/externs)   │
                    └──────────┬──────────┘
                               │
          ┌─────────┬──────────┼──────────┬─────────┐
          ▼         ▼          ▼          ▼         ▼
   ┌──────────┐ ┌───────┐ ┌───────┐ ┌───────┐ ┌──────────┐
   │jail-mgr  │ │config │ │log    │ │failed │ │ban-mgr   │
   │.c/h      │ │-parser│ │-parser│ │-tracker│ │.c/h      │
   │          │ │.c/h   │ │.c/h   │ │.c/h    │ │          │
   └────┬─────┘ └───┬───┘ └───┬───┘ └───┬───┘ └────┬─────┘
        │            │         │         │          │
        │            ▼         │         ▼          │
        │       ┌────────┐    │    ┌────────┐      │
        │       │jail-mgr│    │    │ban-mgr │      │
        │       │(clone) │    │    │        │      │
        │       └────────┘    │    └────────┘      │
        │                     │                    │
        └──────────┬──────────┘                    │
                   ▼                               ▼
            ┌────────────┐                  ┌──────────┐
            │file-monitor│ ────────────────▶│ban-mgr   │
            │.c/h        │   (触发封禁)      │.c/h      │
            └────────────┘                  └──────────┘
                   │
                   ▼
            ┌────────────┐
            │firewall-   │  ← main() 调用 monitor_loop()
            │daemon.c    │
            └────────────┘

  独立模块（不依赖 firewall-daemon.h）:
  ┌──────────────┐  ┌──────────────┐  ┌──────────┐
  │http-exporter │  │sqlite-persist│  │ khash.h  │
  │.c            │  │.c/h          │  │(第三方)   │
  └──────────────┘  └──────────────┘  └──────────┘
```

### 7.2 模块职责速查表

| 模块 | 核心函数 | 被谁调用 | 调用谁 |
|------|---------|---------|--------|
| `firewall-daemon.c` | `main()`, `signal_handler()`, `daemonize_process()`, `cleanup()` | 操作系统 | 所有模块 |
| `jail-manager.c/h` | `find_or_create_jail()`, `clone_jail()`, `config_clone()`, `migrate_failed_entries()` | `config-parser`, `firewall-daemon` | `firewall-daemon.h` |
| `config-parser.c/h` | `parse_config_file()`, `load_config_directory()`, `parse_config()` | `firewall-daemon` | `jail-manager`, `firewall-daemon.h` |
| `log-parser.c/h` | `parse_log_line()`, `extract_and_validate_ip()`, `extract_ip()` | `file-monitor` | `firewall-daemon.h` |
| `failed-tracker.c/h` | `handle_failed_attempt_for_jail()`, `find_entry_for_jail()`, `check_and_ban()` | `file-monitor` | `jail-manager`, `ban-manager`, `firewall-daemon.h` |
| `ban-manager.c/h` | `execute_ban_action()`, `validate_ipv4()`, `secure_procfs_write()` | `failed-tracker`, `firewall-daemon` | `firewall-daemon.h` |
| `file-monitor.c/h` | `monitor_loop()`, `process_new_lines()`, `handle_log_rotation()` | `firewall-daemon` | `log-parser`, `failed-tracker`, `firewall-daemon.h` |
| `http-exporter.c` | `start_http_exporter()`, `stop_http_exporter()` | `firewall-daemon` | 无（独立） |
| `sqlite-persistent.c/h` | `sqlite_init()`, `sqlite_insert_ban()`, ... | `ban-manager` | 无（独立） |

---

*文档版本: v2.0 | 架构基于 Linux 内核模块 + C 用户态守护进程（模块化 v2.0）*
