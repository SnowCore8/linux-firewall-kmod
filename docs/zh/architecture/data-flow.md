# 数据流

本文档描述 Linux Firewall 内核模块中的数据包流和事件流。

## 数据包处理流

### 入站数据包流程

```mermaid
graph TB
    A["网络接口"] --> B["网卡驱动"]
    B --> C["IP 层输入"]
    C --> D["Netfilter PREROUTING Hook"]
    D --> E["nf_hook_func_ipv4 / ipv6"]
    E --> F{"白名单?"}
    F -->|是| G["ACCEPT"]
    F -->|否| H{"封禁表?"}
    H -->|是| I["DROP"]
    H -->|否| J["ACCEPT"]
```

### 封禁决策树

```mermaid
graph TB
    A["数据包 src_ip, dst_port, protocol"] --> B{"src_ip 在白名单?"}
    B -->|是| C["ACCEPT"]
    B -->|否| D{"ip,port,proto 在封禁表?"}
    D -->|是| E["DROP"]
    D -->|否| F["ACCEPT"]
```

## 封禁事件流

### 完整封禁流程

```mermaid
sequenceDiagram
    participant Log as 日志文件
    participant Daemon as 守护进程
    participant Kernel as 内核模块
    participant Prometheus as Prometheus

    Log->>Daemon: IN_MODIFY 通知
    Daemon->>Daemon: 读取日志行
    Daemon->>Daemon: 正则匹配
    Daemon->>Daemon: 计数+1, 检查阈值
    Daemon->>Kernel: netlink BAN 1.2.3.4
    Kernel->>Kernel: 添加封禁到哈希表
    Kernel-->>Daemon: netlink 响应/统计
    Daemon->>Prometheus: 暴露更新后的指标
```

## 解封事件流

### 自动解封

```mermaid
graph TB
    A["ban_entry.expire_timer 到期"] --> B["ban_entry_expire_callback"]
    B --> C{"已摘链 / 已续期?"}
    C -->|已摘链| D["返回"]
    C -->|已续期| E["重武装 mod_timer"]
    C -->|应过期| F["从哈希表 / active_bans_list 移除"]
    F --> G["netlink BanStateChange expired"]
    G --> H["守护进程更新缓存与指标"]
```

### 手动解封

```mermaid
graph TB
    A["echo unban ip | sudo tee /proc/firewall/bans<br/>或 daemon netlink UnbanIp"] --> B["桶锁内 timer_delete + 摘链"]
    B --> C["call_rcu 释放"]
    C --> D["netlink / 指标更新"]
```

## 组件间通信

### 用户态 → 内核态

| 方式 | 接口 | 用途 |
|------|------|------|
| netlink | 内核模块协议 | 守护进程下发封禁、解封、白名单与配置 |
| ProcFS 写入 | `/proc/firewall/bans` | 用户手动封禁 / 解封（`unban <ip>`） |
| ProcFS 写入 | `/proc/firewall/whitelist` | 用户手动添加 / 移除白名单 |

> `/proc/firewall/config` 与 `/proc/firewall/stats` 为只读；模块不
> 提供“清空”原生命令，需逐条 `unban` 或重载模块。守护进程内部通信
> 以 netlink 为主，ProcFS 保留为用户操作和兼容接口。

### 内核态 → 用户态

| 方式 | 接口 | 用途 |
|------|------|------|
| netlink | 内核模块协议 | 命令响应、统计、状态快照与 DDoS 事件 |
| ProcFS 读取 | `/proc/firewall/config` | 获取 ban_time、当前封禁/白名单数 |
| ProcFS 读取 | `/proc/firewall/bans` | 获取封禁 IP 列表 |
| ProcFS 读取 | `/proc/firewall/whitelist` | 获取白名单 |
| ProcFS 读取 | `/proc/firewall/stats` | 获取计数器 |

### 内部通信

| 组件 | 通信方式 | 数据 |
|------|----------|------|
| 守护进程 → HTTP 客户端 | HTTP (axum) | Web UI、JSON API、SSE、健康检查与 Prometheus 指标 |
| 守护进程 → 日志 | 文件 I/O | 运行日志 |

## 时序图

### 封禁时序

```mermaid
sequenceDiagram
    participant Log as 日志文件
    participant Daemon as 守护进程
    participant Kernel as 内核模块
    participant Prometheus as Prometheus

    Log->>Daemon: IN_MODIFY
    Daemon->>Daemon: 读取日志行
    Daemon->>Daemon: 正则匹配
    Daemon->>Daemon: 计数+1, 检查阈值
    Daemon->>Kernel: netlink BAN 1.2.3.4
    Kernel->>Kernel: 添加封禁
    Kernel-->>Daemon: netlink 响应/统计
    Daemon->>Prometheus: 暴露更新后的指标
```

### 数据包处理时序

```mermaid
sequenceDiagram
    participant Net as 网络
    participant Kernel as 内核模块
    participant Whitelist as 白名单
    participant HashTable as 哈希表

    Net->>Kernel: 数据包
    Kernel->>Whitelist: 检查白名单
    Whitelist-->>Kernel: 不在白名单
    Kernel->>HashTable: 查询哈希表
    HashTable-->>Kernel: 不在表中
    Kernel-->>Net: NF_ACCEPT
    
    Net->>Kernel: 数据包
    Kernel->>HashTable: 查询哈希表
    HashTable-->>Kernel: 在表中
    Kernel-->>Net: NF_DROP
```

## 性能特征

### 数据包处理延迟

| 场景 | 延迟 |
|------|------|
| 白名单匹配 | ~50ns |
| 哈希查找（未命中） | ~100ns |
| 哈希查找（命中） | ~100ns |
| 总计（正常流量） | ~150ns |

### 吞吐量

| 配置 | 性能 |
|------|------|
| 空表 | 线速（10Gbps+） |
| 满表（4096） | 线速（10Gbps+） |
| 白名单（64） | 线速（10Gbps+） |

### 瓶颈分析

| 组件 | 瓶颈 | 优化 |
|------|------|------|
| Netfilter Hook | 无 | RCU 读，零锁竞争 |
| 哈希查找 | 哈希冲突 | jhash 均匀分布 |
| 白名单查找 | 线性扫描 | 容量小（64），影响可忽略 |