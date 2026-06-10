# 内核模块

本文档介绍 Linux Firewall 内核模块的实现细节。

## 模块概览

内核模块 `firewall.ko` 是整个系统的核心，负责在网络栈层面拦截和过滤数据包。

### 模块信息

| 属性 | 值 |
|------|-----|
| 模块名称 | `firewall` |
| 源文件 | `src/kernel/firewall.c` |
| 许可证 | MIT |
| 加载路径 | `/lib/modules/$(uname -r)/extra/firewall.ko` |

## Netfilter Hook

### Hook 注册点

模块在 `NF_INET_PRE_ROUTING` 链上注册 Hook，这是数据包进入网络栈后的最早处理点之一。

```c
struct nf_hook_ops nf_ops_ipv4 __read_mostly = {
    .hook     = nf_hook_func_ipv4,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

struct nf_hook_ops nf_ops_ipv6 __read_mostly = {
    .hook     = nf_hook_func_ipv6,
    .pf       = NFPROTO_IPV6,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};
```

### Hook 函数流程

```
网络数据包到达
      │
      ▼
┌────────────────────┐
│ nf_hook_func_ipv4  │ （IPv4 数据包）
│  / _ipv6           │ （IPv6 数据包）
└────────┬───────────┘
         │
         ▼
┌─────────────────┐
│ 检查白名单       │◄── 匹配则 ACCEPT
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ 查找哈希表       │◄── 封禁表中则 DROP
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ NF_ACCEPT       │◄── 不在封禁表则放行
└─────────────────┘
```

### 返回值

| 返回值 | 说明 |
|--------|------|
| `NF_ACCEPT` | 允许数据包通过 |
| `NF_DROP` | 丢弃数据包 |

## 哈希表

### 数据结构

内核使用哈希表存储被封禁的 IP 地址，容量为 4096。

```c
#define HASH_TABLE_SIZE 4096

struct banned_ip {
    __be32 ip;                // IPv4 地址
    u32 port;                 // 端口
    u8 protocol;              // 协议
    ktime_t ban_time;         // 封禁时间
    ktime_t expire_time;      // 过期时间
    char jail_name[64];       // Jail 名称
    struct hlist_node node;   // 哈希链表节点
};
```

### 哈希函数

```c
static inline u32 hash_ip(__be32 ip, u32 port)
{
    return jhash_2words((__force u32)ip, port, HASH_SEED) % HASH_TABLE_SIZE;
}
```

### 操作复杂度

| 操作 | 复杂度 | 说明 |
|------|--------|------|
| 查找 | O(1) 平均 | 哈希查找 |
| 插入 | O(1) 平均 | 头插法 |
| 删除 | O(1) 平均 | 链表删除 |

## RCU 并发控制

### 读操作

数据包处理路径使用 RCU 读锁，确保多 CPU 并发安全且无锁竞争：

```c
rcu_read_lock();
entry = firewall_lookup(ip, port);
rcu_read_unlock();
```

### 写操作

添加/删除封禁时使用 RCU 写同步：

```c
spin_lock(&hash_lock);
hlist_add_head_rcu(&entry->node, &hash_table[hash]);
spin_unlock(&hash_lock);
synchronize_rcu();
```

### 优势

| 特性 | 说明 |
|------|------|
| 读无锁 | 数据包处理路径无锁，极低延迟 |
| 多 CPU | 支持所有 CPU 核心并行处理 |
| 安全 | 保证读者看到一致的数据 |

## 白名单

### 数据结构

白名单使用固定大小数组，容量为 64。

```c
#define WHITELIST_SIZE 64

struct whitelist_entry {
    __be32 ip;          // IP 地址
    __be32 mask;        // 子网掩码
    bool active;        // 是否激活
};
```

### 匹配逻辑

白名单检查在哈希表查找之前执行，确保白名单 IP 永远不会被封禁：

```c
if (is_whitelisted(ip)) {
    return NF_ACCEPT;
}
```

### CIDR 支持

白名单支持 CIDR 表示法，通过子网掩码匹配：

```c
/* 真实实现见 src/kernel-module/whitelist.c */
bool is_in_whitelist(struct firewall_info *fw, u8 af, const void *ip)
{
    struct whitelist_entry *entry;
    /* 两阶段匹配：先精确匹配（O(1) 哈希桶），再遍历 CIDR 子网 */
    ...
}
```

## 自动过期清理

### 清理线程

内核模块通过 timer 定期清理过期的封禁条目（实现见
`src/kernel-module/cleanup.c`）：

```c
/* 真实实现见 src/kernel-module/cleanup.c */
void cleanup_timer_callback(struct timer_list *t)
{
    struct firewall_info *fw = container_of(t, struct firewall_info, cleanup_timer);
    cleanup_expired_bans(fw);  /* 清理 expired 封禁 */
    /* 重新调度下一次清理 */
    mod_timer(&fw->cleanup_timer, jiffies + CLEANUP_INTERVAL);
}
```

### 清理策略

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 清理间隔 | 30 秒 | 检查过期条目的频率 |
| 批量处理 | 100 条 | 单次清理最多处理的条目数 |

### 清理流程

```
清理线程唤醒
      │
      ▼
遍历哈希表
      │
      ▼
检查 expire_time < now
      │
      ├── 是 ──► 移除条目 ──► 通知用户态
      │
      └── 否 ──► 继续
```

## ProcFS 接口

### 注册

```c
static int __init firewall_proc_init(void)
{
    proc_create("firewall/status", 0444, NULL, &status_fops);
    proc_create("firewall/banned_ips", 0444, NULL, &banned_fops);
    proc_create("firewall/config", 0200, NULL, &config_fops);
    return 0;
}
```

### 文件操作

| 文件 | 权限 | 操作 |
|------|------|------|
| `status` | 0444 | 只读，返回模块状态 |
| `banned_ips` | 0444 | 只读，返回封禁列表 |
| `whitelist` | 0444 | 只读，返回白名单 |
| `stats` | 0444 | 只读，返回统计信息 |
| `config` | 0200 | 只写，接收配置命令 |
| `clear` | 0200 | 只写，清空封禁 |
| `version` | 0444 | 只读，返回版本号 |

## 模块生命周期

### 初始化

```
module_init()
    ├── 注册 Netfilter Hook
    ├── 初始化哈希表
    ├── 初始化白名单
    ├── 创建 ProcFS 接口
    └── 启动清理线程
```

### 退出

```
module_exit()
    ├── 停止清理线程
    ├── 移除 ProcFS 接口
    ├── 注销 Netfilter Hook
    ├── 释放哈希表内存
    └── 释放白名单内存
```

## 内核日志

使用 `pr_*` 宏输出日志：

```c
pr_info("firewall: module loaded\n");
pr_warn("firewall: hash table full\n");
pr_err("firewall: failed to register hook\n");
```

调试级别通过编译时宏控制：

```bash
make debug DL=2    # 启用调试级别 2
```