# 永久黑名单功能指南 (SQLite 持久化)

> **v1.9 更新**: 新增 SQLite 线程安全保护（pthread_mutex_t），修复状态保存/恢复中的 is_permanent 初始化和剩余时间计算问题

> **v1.7 更新**: SQLite 绑定已从 `SQLITE_STATIC` 改为 `SQLITE_TRANSIENT`，修复了潜在的 use-after-free 漏洞。

## 概述

永久黑名单功能为 firewall 项目增加了基于 SQLite 的持久化存储能力，使得关键恶意 IP 能够被永久封禁，即使在内核模块重新加载或系统重启后依然有效。

## 架构设计

### 双层持久化

```
┌─────────────────────────────────────────────────────────┐
│                    守护进程启动                          │
│  1. 初始化 SQLite 数据库 (sqlite-persistent.c)          │
│  2. 从数据库加载所有活跃永久封禁                         │
│  3. 批量写入内核模块 /proc/firewall/bans (IP 0)         │
│  4. 内核标记 is_permanent = true (永不超时)              │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                    运行时封禁                            │
│  日志解析触发封禁 → 检查配置 permanent_ban_enabled      │
│                    ↓                                    │
│         写入内核 (临时或永久)                            │
│                    ↓                                    │
│      如果 permanent: 同步写入 SQLite 数据库              │
└─────────────────────────────────────────────────────────┘
```

### 核心组件

| 组件 | 文件 | 说明 |
|------|------|------|
| SQLite 持久化模块 | `src/daemon/sqlite-persistent.c/h` | 数据库操作封装 |
| 内核永久封禁函数 | `src/kernel-module/firewall.c` | `ban_ip_permanent()`, `unban_permanent_ip()`, `is_permanently_banned()` |
| 内核 procfs 接口 | `/proc/firewall/bans`（写入 `IP 0` 表示永久封禁，`unban IP` 表示解封） | 用户态交互 |
| 守护进程集成 | `src/daemon/firewall-daemon.c` | SQLite 初始化、启动加载、运行时同步 |
| YAML 配置 | `config/default.yaml` | `permanent_db_path`, `permanent_ban_enabled` |

## 数据库 Schema

```sql
CREATE TABLE IF NOT EXISTS permanent_banlist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,          -- IP 地址 (点分十进制)
    ip_num INTEGER NOT NULL UNIQUE,   -- IP 数值 (网络字节序整数)
    reason TEXT,                      -- 封禁原因
    created_at INTEGER NOT NULL,      -- 创建时间 (Unix 时间戳)
    created_by TEXT DEFAULT 'auto',   -- 触发源 (auto/manual/api)
    hit_count INTEGER DEFAULT 0,      -- 匹配次数统计
    last_hit_at INTEGER,              -- 最后匹配时间
    is_active INTEGER DEFAULT 1       -- 是否生效 (0=已删除但保留记录)
);

CREATE INDEX IF NOT EXISTS idx_ip_num ON permanent_banlist(ip_num);
CREATE INDEX IF NOT EXISTS idx_is_active ON permanent_banlist(is_active);
```

## 使用方法

### 1. 配置永久黑名单

编辑 `config/default.yaml`:

```yaml
# SQLite 数据库路径 (必须设置以启用永久封禁)
permanent_db_path: "/var/lib/firewall/bans.db"

# 启用永久封禁
permanent_ban_enabled: true
```

### 2. 手动添加/移除永久封禁

```bash
# 添加永久封禁
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# 移除永久封禁
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans

# 查看所有封禁 (包括临时和永久)
cat /proc/firewall/bans
```

### 3. 通过守护进程 API (未来扩展)

守护进程启动时会自动：
1. 初始化 SQLite 数据库
2. 加载所有活跃永久封禁到内核模块
3. 运行时同步封禁事件到数据库

## 内核模块特性

### 永久封禁标记

`struct ban_entry` 新增 `is_permanent` 字段：

```c
struct ban_entry {
    __be32 ip;
    unsigned long ban_time;
    unsigned long unban_time;  /* 0 = permanent */
    atomic_t retry_count;
    bool is_permanent;         /* permanent ban flag */
    struct hlist_node hash;
    struct rcu_head rcu_head;
};
```

**v1.9 修复**: `is_permanent` 字段在所有创建路径中正确初始化：
- `ban_ip_permanent()` 中设置为 `true`
- 状态保存时通过 `save_state_to_file()` 持久化 `P` 标记
- 状态恢复时通过 `restore_state_from_file()` 正确解析 `P` 标记并恢复 `is_permanent = true`
- 修复了之前恢复后 `is_permanent` 未正确初始化导致剩余时间计算错误的问题

### 核心 API

| 函数 | 说明 |
|------|------|
| `ban_ip_permanent(fw, ip)` | 添加永久封禁 (unban_time=0, is_permanent=true) |
| `unban_permanent_ip(fw, ip)` | 移除永久封禁 (仅移除 is_permanent=true 的条目) |
| `is_permanently_banned(fw, ip)` | 检查是否为永久封禁 |
| `is_banned(fw, ip)` | 修改后支持检查永久封禁 (永不超时) |

### 过期清理逻辑

`cleanup_expired_bans()` 跳过 `is_permanent=true` 的条目，确保永久封禁不会被自动清理。

## 安全机制

| 机制 | 实现 |
|------|------|
| **白名单保护** | 永久封禁前检查白名单，拒绝封名单 IP |
| **输入验证** | IP 格式、范围、保留地址验证 |
| **SQL 注入防护** | 使用 SQLite 参数绑定 + `SQLITE_TRANSIENT`，杜绝注入和 use-after-free |
| **能力检查** | procfs 写入检查 `CAP_NET_ADMIN` |
| **软删除** | `is_active=0` 而非物理删除，保留审计记录 |
| **路径安全** | `ensure_db_dir()` 验证路径合法性 + `strdup()` NULL 检查 |
| **线程安全** | pthread_mutex_t 保护所有 SQLite 公共接口，防止并发访问竞争 |

## 测试覆盖

测试套件: `tests/suites/12_permanent_ban.sh`

| 测试项 | 说明 |
|--------|------|
| 基本封禁/解封 | 验证 procfs 接口功能 |
| 过期检查 | 验证永久封禁不自动过期 |
| 输入验证 | 无效 IP、保留地址、SQL 注入 |
| 重复处理 | 重复封禁不产生重复条目 |
| 白名单保护 | 白名单 IP 不能被永久封禁 |
| 性能测试 | 批量 50 个永久封禁 |
| SQLite 集成 | 守护进程数据库同步 (需真实环境) |

## 构建要求

### 依赖

- **SQLite3**: `libsqlite3-dev` (Ubuntu/Debian) 或 `sqlite-devel` (RHEL/CentOS)
- **libyaml**: `libyaml-dev` (Ubuntu/Debian) 或 `libyaml-devel` (RHEL/CentOS)
- 其他依赖: pthread, kernel headers

### 编译

```bash
# 完整编译
make all-with-daemon

# 仅编译守护进程
make daemon
```

Makefile 已更新，自动链接 `-lsqlite3`。

## 配置示例

### 完整配置 (default.yaml)

```yaml
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
      - /var/log/secure
    max_retries: 5
    findtime: 600
    ban_time: 900
    regex: ""

  frp:
    enabled: true
    log_files:
      - /var/log/frp/frp.log
    max_retries: 10
    findtime: 300
    ban_time: 1800
    regex: ".*\\[E\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"

# 永久黑名单配置
permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

## 注意事项

1. **数据库文件权限**: 确保 `firewall-daemon` 有写权限
2. **磁盘空间**: SQLite 数据库会增长，建议定期清理
3. **内核模块限制**: 永久封禁仍受 1024 条目上限限制
4. **重启恢复**: 守护进程启动时自动恢复所有永久封禁
5. **未使用的函数**: `ban_ip_permanent()` 在守护进程中为预留函数，供未来 API 调用

## 未来改进

- [ ] 增加 `/proc/firewall/bans` 过滤选项，仅显示永久封禁（如 `cat /proc/firewall/bans --permanent`）
- [ ] 守护进程 HTTP API 支持远程管理永久封禁
- [ ] 数据库自动备份机制
- [ ] 按原因分类统计封禁数据
- [ ] 支持 CIDR 子网永久封禁
- [ ] 数据库连接池优化
- [ ] SQLite 事务隔离级别优化
