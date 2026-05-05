# 架构设计文档

**版本**: v2.0

## 1. 整体架构

Firewall 采用**双层架构**，将 fail2ban 的核心功能从用户空间移动到内核空间：

```
┌─────────────────────────────────────────────────────────────────┐
│                        用户态 (守护进程)                         │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ inotify     │  │ PCRE2       │  │ Jail        │             │
│  │ 文件监控    │→ │ 正则解析    │→ │ 管理器      │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│         │                                    │                  │
│         ▼                                    ▼                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ 失败追踪    │  │ 封禁管理    │  │ Prometheus  │             │
│  │ (khash)     │→ │ (procfs)    │  │ 指标导出    │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│                           │                                     │
└───────────────────────────┼─────────────────────────────────────┘
                            │ procfs 写入
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        内核态 (内核模块)                         │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │              Netfilter PRE_ROUTING 钩子                  │   │
│  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │   │
│  │  │ 封禁表      │    │ 白名单表    │    │ 统计信息    │  │   │
│  │  │ (1024 容量) │    │ (64 容量)   │    │             │  │   │
│  │  └─────────────┘    └─────────────┘    └─────────────┘  │   │
│  │              RCU 并发保护 + spinlock                     │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ procfs 接口 │  │ 定时器      │  │ 网络设备    │             │
│  │ (bans/stats)│  │ (过期清理)  │  │ (IP 发现)   │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 数据流

```
攻击者暴力破解
    ↓
系统日志 (/var/log/auth.log 等)
    ↓ inotify 事件驱动 (毫秒级)
守护进程 (用户态)
    ├─ PCRE2 正则解析日志
    ├─ khash O(1) 失败追踪
    └─ 触发阈值 → /proc/firewall/bans
    ↓ procfs 写入
内核模块 (内核态)
    ├─ Netfilter 钩子 (NF_INET_PRE_ROUTING)
    ├─ RCU 无锁读取 + spinlock 写入
    └─ 后续数据包 → NF_DROP (微秒级)
```

## 3. 内核模块设计

### 3.1 文件结构

| 文件 | 行数 | 职责 |
|------|------|------|
| `firewall.c` | ~200 | 模块入口、参数定义、初始化/清理 |
| `firewall.h` | ~225 | 数据结构、宏定义、函数声明 |
| `ban-manager.c` | ~375 | 封禁/解封管理、哈希表操作 |
| `whitelist.c` | ~180 | 白名单管理、系统 IP 自动发现 |
| `cleanup.c` | ~150 | 过期清理、定时器回调 |
| `netdev.c` | ~320 | 网络设备通知器、IP 自动发现 |
| `procfs.c` | ~770 | procfs 接口实现 |
| `netfilter.c` | ~150 | Netfilter 钩子、数据包过滤 |
| `state-persist.c` | ~445 | 状态持久化（保存/恢复） |

### 3.2 核心数据结构

```c
/* 封禁条目 */
struct ban_entry {
    __be32 ip;              /* IP 地址 */
    unsigned long ban_time; /* 封禁时间 (jiffies) */
    unsigned long unban_time; /* 解封时间 (jiffies) */
    bool is_permanent;      /* 是否永久封禁 */
    struct hlist_node hash; /* 哈希表节点 */
    struct rcu_head rcu_head; /* RCU 释放头 */
};

/* 白名单条目 */
struct whitelist_entry {
    __be32 ip;              /* 子网地址 */
    __be32 mask;            /* 子网掩码 */
    char dev_name[IFNAMSIZ]; /* 设备名 */
    struct hlist_node hash; /* 哈希表节点 */
    struct rcu_head rcu_head; /* RCU 释放头 */
};

/* 防火墙全局状态 */
struct firewall_info {
    DECLARE_HASHTABLE(ban_table, BAN_HASH_BITS);     /* 封禁哈希表 */
    DECLARE_HASHTABLE(whitelist_table, WL_HASH_BITS); /* 白名单哈希表 */
    spinlock_t lock;          /* 写锁 */
    atomic_t ban_count;       /* 当前封禁数 */
    atomic_t total_ban_count; /* 累计封禁数 */
    atomic_t total_unban_count; /* 累计解封数 */
    struct timer_list cleanup_timer; /* 清理定时器 */
    struct delayed_work sync_work;   /* 同步工作 */
    struct notifier_block netdev_nb; /* 网络设备通知器 */
};
```

### 3.3 并发模型

```
读路径 (Netfilter 钩子)          写路径 (procfs 写入)
─────────────────────────        ─────────────────────────
rcu_read_lock()                  spin_lock(&fw->lock)
  hash_for_each_possible_rcu()     hash_add_rcu()
  READ_ONCE(entry->field)          hlist_del_rcu()
rcu_read_unlock()                spin_unlock(&fw->lock)
                                 call_rcu(&entry->rcu_head, free)
```

**关键设计**：
- 读路径使用 RCU，无锁高性能
- 写路径使用 spinlock + RCU 安全删除
- 字段读写使用 `READ_ONCE`/`WRITE_ONCE` 防止编译器重排序

### 3.4 模块参数

| 参数 | 类型 | 默认值 | 权限 | 说明 |
|------|------|--------|------|------|
| `fw_ban_time` | int | 600 | 0644 | 默认封禁时长（秒） |
| `fw_max_bans_per_second` | int | 200 | 0444 | 每秒最大封禁次数（洪泛保护） |
| `state_file` | charp | NULL | 0444 | 状态文件路径（只读） |

### 3.5 procfs 接口

内核模块通过 `/proc/firewall/` 目录提供用户态交互接口，包括封禁管理、白名单管理、运行时配置和统计信息。

详细的接口操作说明、命令示例和限制条件，请参考 [运维操作手册 → procfs 接口](OPERATIONS.md#2-procfs-接口)。

## 4. 守护进程设计

### 4.1 文件结构

| 文件 | 职责 |
|------|------|
| `firewall-daemon.c/h` | 主入口、信号处理、守护进程化、命令行解析 |
| `jail-manager.c/h` | Jail 生命周期管理：创建/销毁/重载 |
| `config-parser.c/h` | YAML 配置解析：全局 defaults + jail 配置 |
| `log-parser.c/h` | PCRE2 正则日志解析：JIT 编译、IP 提取 |
| `failed-tracker.c/h` | 失败尝试追踪：khash 哈希表、时间窗口计数 |
| `ban-manager.c/h` | 封禁管理：通过 procfs 下发封禁指令到内核 |
| `file-monitor.c/h` | inotify 日志文件监控：事件监听、文件轮转检测 |
| `http-exporter.c` | Prometheus 指标导出：HTTP 服务器、指标收集 |
| `sqlite-persistent.c/h` | SQLite 永久封禁持久化：表操作、批量插入 |
| `khash.h` | 第三方哈希库（头文件-only） |

### 4.2 配置系统

**双层配置结构**：

```yaml
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  max_retries: 5      # 覆盖默认
  findtime: 600       # 覆盖默认
  ban_time: 900       # 覆盖默认
  regex: ""           # 使用内置模式
```

**配置加载流程**：
1. 解析 `defaults` 块 → 全局默认值
2. 解析各 jail 块 → 服务特定配置
3. 智能推断：根据 jail 名称自动匹配内置模式
4. 严格校验：未知参数/无效值 → 报错拒绝（默认）
5. 双缓冲重载：SIGHUP → 解析到临时结构 → 原子交换

### 4.3 核心组件交互

```
main()
  ├─ config_parse()          # 加载配置
  ├─ jail_manager_init()     # 初始化 Jail
  │   ├─ log_parser_compile()  # 编译 PCRE2 正则
  │   └─ failed_tracker_init() # 初始化 khash 表
  ├─ file_monitor_start()    # 启动 inotify 监控
  │   └─ monitor_loop()        # 事件循环
  │       ├─ process_new_lines() # 处理新日志行
  │       │   ├─ log_parser_match() # 正则匹配
  │       │   └─ failed_tracker_add() # 记录失败
  │       └─ execute_ban_action() # 触发封禁
  ├─ http_exporter_start()   # 启动 Prometheus 导出
  └─ sqlite_persistent_init() # 初始化 SQLite
```

## 5. 模块依赖图

```
firewall.c (入口)
  ├── ban-manager.c
  ├── whitelist.c
  ├── cleanup.c
  ├── netdev.c
  ├── procfs.c
  ├── netfilter.c
  └── state-persist.c

firewall-daemon.c (入口)
  ├── jail-manager.c
  │   ├── config-parser.c
  │   ├── log-parser.c
  │   └── failed-tracker.c
  ├── ban-manager.c
  ├── file-monitor.c
  ├── http-exporter.c
  └── sqlite-persistent.c
```

## 6. 性能特性

| 操作 | 复杂度 | 说明 |
|------|--------|------|
| 封禁查找 | O(1) | 哈希表查找 |
| 封禁插入 | O(1) | 锁外预分配 + 锁内插入 |
| 白名单精确匹配 | O(1) | 哈希查找 /32 条目 |
| 白名单子网匹配 | O(n) | 全表遍历（有迭代限制） |
| 过期清理 | 增量 | 每次处理部分桶，避免长时持锁 |
| 日志解析 | JIT | PCRE2 JIT 编译加速 |
| 失败追踪 | O(1) | khash 哈希表 |

## 7. 安全设计

| 层面 | 措施 |
|------|------|
| 编译安全 | `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-fPIE -pie`, `-Wl,-z,relro,-z,now` |
| 输入验证 | IP 格式检查、路径遍历防护、URL 编码检测 |
| 并发安全 | RCU + spinlock + READ_ONCE/WRITE_ONCE |
| 内存安全 | 锁外预分配、call_rcu 异步释放、TOCTOU 防护 |
| 正则安全 | ReDoS 防护（嵌套量词检测、占有量词拒绝） |
| 路径安全 | 白名单目录检查、realpath 验证、`O_NOFOLLOW` |
