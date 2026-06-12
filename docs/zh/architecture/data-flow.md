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
    participant SQLite as SQLite
    participant Prometheus as Prometheus

    Log->>Daemon: IN_MODIFY 通知
    Daemon->>Daemon: 读取日志行
    Daemon->>Daemon: 正则匹配
    Daemon->>Daemon: 计数+1, 检查阈值
    Daemon->>Kernel: ban 1.2.3.4 (ProcFS)
    Kernel->>Kernel: 添加封禁到哈希表
    Kernel->>SQLite: INSERT 记录
    Kernel->>Prometheus: 更新指标
```

## 解封事件流

### 自动解封

```mermaid
graph TB
    A["内核清理线程 30s"] --> B["遍历哈希表"]
    B --> C{"expire_time < current?"}
    C -->|否| D["保留"]
    C -->|是| E["从哈希表移除"]
    E --> F["从 SQLite 删除"]
    F --> G["更新指标"]
```

### 手动解封

```mermaid
graph TB
    A["echo unban ip | sudo tee /proc/firewall/bans"] --> B["写入 ProcFS"]
    B --> C["内核从哈希表移除条目"]
    C --> D["从 SQLite 删除"]
    D --> E["更新指标"]
```

## 组件间通信

### 用户态 → 内核态

| 方式 | 路径 | 用途 |
|------|------|------|
| ProcFS 写入 | `/proc/firewall/bans` | 封禁 / 解封（`unban <ip>`） |
| ProcFS 写入 | `/proc/firewall/whitelist` | 添加 / 移除白名单 |

> `/proc/firewall/config` 与 `/proc/firewall/stats` 为只读；模块不
> 提供“清空”原生命令，需逐条 `unban` 或重载模块。

### 内核态 → 用户态

| 方式 | 路径 | 用途 |
|------|------|------|
| ProcFS 读取 | `/proc/firewall/config` | 获取 ban_time、当前封禁/白名单数 |
| ProcFS 读取 | `/proc/firewall/bans` | 获取封禁 IP 列表 |
| ProcFS 读取 | `/proc/firewall/whitelist` | 获取白名单 |
| ProcFS 读取 | `/proc/firewall/stats` | 获取计数器 |

### 内部通信

| 组件 | 通信方式 | 数据 |
|------|----------|------|
| 守护进程 → SQLite | 文件 I/O | 封禁记录 |
| 守护进程 → Prometheus | HTTP (tiny_http) | 指标数据 |
| 守护进程 → 日志 | 文件 I/O | 运行日志 |

## 时序图

### 封禁时序

```mermaid
sequenceDiagram
    participant Log as 日志文件
    participant Daemon as 守护进程
    participant Kernel as 内核模块
    participant SQLite as SQLite
    participant Prometheus as Prometheus

    Log->>Daemon: IN_MODIFY
    Daemon->>Daemon: 读取日志行
    Daemon->>Daemon: 正则匹配
    Daemon->>Daemon: 计数+1, 检查阈值
    Daemon->>Kernel: ban 1.2.3.4 (ProcFS)
    Kernel->>Kernel: 添加封禁
    Kernel->>SQLite: INSERT
    Kernel->>Prometheus: 更新指标
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