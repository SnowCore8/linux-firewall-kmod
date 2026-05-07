# 安全特性技术文档

**版本**: v2.1.1

## 1. 编译安全

### 1.1 安全编译标志

| 标志 | 作用 |
|------|------|
| `-Wall -Wextra` | 启用所有常见警告 |
| `-Werror=format-security` | 格式化字符串安全错误 |
| `-O2` | 优化级别 2 |
| `-D_FORTIFY_SOURCE=2` | 缓冲区溢出检测 |
| `-fstack-protector-strong` | 栈溢出保护 |
| `-fPIE -pie` | PIE 可执行文件（配合 ASLR） |
| `-Wl,-z,relro,-z,now` | 完整 RELRO（延迟绑定保护） |

### 1.2 验证编译安全

```bash
# 检查 PIE
file build/daemon/firewall-daemon     # 输出应包含: pie executable

# 检查 RELRO
readelf -l build/daemon/firewall-daemon | grep GNU_RELRO

# 检查 BIND_NOW
readelf -d build/daemon/firewall-daemon | grep FLAGS  # 输出应包含: BIND_NOW
```

## 2. 运行时安全

### 2.1 systemd 服务加固

`firewall-daemon.service` 启用的安全限制：

```ini
[Service]
ProtectSystem=strict        # 保护系统目录
ProtectHome=yes             # 禁止访问 /home
NoNewPrivileges=yes         # 禁止提权
PrivateTmp=yes              # 私有 /tmp
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH  # 最小权限
```

### 2.2 最小权限原则

| 组件 | 权限 | 说明 |
|------|------|------|
| 内核模块 | ring 0 | 必须（内核态） |
| 守护进程 | root + capabilities | 仅保留必要能力 |
| 配置文件 | 600 root:root | 仅 root 可读写 |
| 状态目录 | 700 root:root | 仅 root 可访问 |

## 3. 输入验证

### 3.1 IP 地址验证

- 严格 IPv4 格式检查
- 拒绝回环地址 (`127.0.0.0/8`)、多播地址 (`224.0.0.0/4`)、广播地址和 `0.0.0.0`

### 3.2 路径遍历防护

- 白名单目录：仅允许 `/var/log/`、`/etc/`、`/home/`、`/srv/`
- `realpath` 解析验证，拒绝 `//` 连续斜杠和 `..` 路径回溯

### 3.3 URL 编码检测

procfs 接口检测编码绕过：`%2e` → `.`、`%2f` → `/`、`%2e%2e` → `..`

### 3.4 procfs 接口安全

- **IP 地址长度验证**：防止 `strncpy` 缓冲区溢出，确保输入 IP 地址不超过内部缓冲区大小
- **输入长度检查**：`config_write` 添加 `count` 参数验证，拒绝超长写入请求
- **控制字符过滤**：拒绝非 printable 字符，防止注入攻击和异常输入

## 4. 并发安全

### 4.1 RCU 机制

```
读路径 (无锁)                    写路径 (spinlock)
─────────────                    ─────────────────
rcu_read_lock()                  spin_lock()
  READ_ONCE()                      修改数据
rcu_read_unlock()                spin_unlock()
                                 call_rcu() → 延迟释放
```

**关键保证**：
- 读者无需等待写者；写者等待 RCU 宽限期后释放内存
- 所有共享字段读写配对使用 `READ_ONCE`/`WRITE_ONCE` 防止编译器重排序
- 白名单遍历中 `mask` 和 `ip` 字段使用 `READ_ONCE` 保护，确保读取一致性
- 配置重载使用双缓冲模式，锁内仅执行指针交换，避免持锁期间长时间操作

### 4.2 锁设计

```
firewall_info.lock           → ban_table (封禁哈希表)
firewall_info.whitelist_lock → whitelist_table (白名单哈希表)
```

双锁设计，避免锁竞争，无死锁风险。

## 5. 内存安全

### 5.1 预分配策略

```c
// 锁外预分配 (GFP_KERNEL)，锁内仅检查和插入
entry = kmalloc(sizeof(*entry), GFP_KERNEL);
spin_lock(&fw->lock);
if (duplicate) { kfree(entry); return 0; }
hash_add_rcu(fw->ban_table, &entry->hash, ip);
spin_unlock(&fw->lock);
```

### 5.2 RCU 安全释放

```c
hlist_del_rcu(&entry->hash);
call_rcu(&entry->rcu_head, free_ban_entry_rcu);  // 宽限期后执行 kfree
```

### 5.3 TOCTOU 防护

状态文件操作使用 `O_NOFOLLOW` + inode 一致性验证：

```c
vfs_getattr(&path, &saved_stat);   // 打开前记录 inode
// ... 写入操作 ...
vfs_getattr(&path, &close_stat);   // 写入后验证
if (close_stat.ino != saved_stat.ino)
    return -EACCES;                // TOCTOU 攻击检测
```

## 6. 正则安全

### 6.1 ReDoS 防护

编译前检测以下危险模式：

| 模式 | 示例 | 风险 |
|------|------|------|
| 嵌套量词 | `(a+)+` | 指数级回溯 |
| 占有量词 | `a++` | 不可回溯 |
| 过多分支 | `(a\|b\|c\|...){10,}` | 组合爆炸 |

### 6.2 正则限制

- 最大长度：1024 字节
- JIT 编译加速，匹配超时保护

### 6.3 运行时保护

- **PCRE2_MATCH_LIMIT**：10000 次最大回溯次数，防止正则表达式拒绝服务攻击（ReDoS）
- **PCRE2_DEPTH_LIMIT**：1000 层最大递归深度，防止深层嵌套正则导致栈溢出

## 7. 监控指标

Prometheus 指标（端口 9119）：

### 内核模块指标（4 项）

| 指标 | 说明 |
|------|------|
| `firewall_kernel_banned_ips_current` | 当前封禁数 |
| `firewall_kernel_total_bans_total` | 累计封禁次数 |
| `firewall_kernel_total_unbans_total` | 累计解封次数 |
| `firewall_kernel_whitelist_count` | 白名单条目数 |

### 守护进程指标（10 项）

| 指标 | 说明 |
|------|------|
| `firewall_daemon_lines_parsed_total` | 解析的日志行总数 |
| `firewall_daemon_ips_extracted_total` | 提取的 IP 地址总数 |
| `firewall_daemon_ips_banned_total` | 封禁的 IP 总数 |
| `firewall_daemon_failed_attempts_total` | 失败尝试总数 |
| `firewall_daemon_config_reloads_total` | 配置重载次数 |
| `firewall_daemon_inotify_events_total` | inotify 事件总数 |
| `firewall_daemon_log_rotations_total` | 日志轮转检测次数 |
| `firewall_daemon_lines_skipped_total` | 跳过的日志行总数 |
| `firewall_daemon_regex_matches_total` | 正则匹配成功次数 |
| `firewall_daemon_uptime_seconds` | 守护进程运行时间（秒） |

## 8. 安全修复历史

| 版本 | 修复内容 |
|------|---------|
| v2.1.1 | pthread_rwlock 自死锁修复（config-parser.c） |
| v2.1.1 | Use-After-Free 竞态修复（file-monitor.c） |
| v2.1.1 | 线程 join 修复（firewall-daemon.c） |
| v2.1.1 | clone_jail 失败路径状态不一致修复 |
| v2.1.1 | procfs 写入长度限制收紧（256→64 字节） |
| v2.1.1 | Basic Auth 恒定时间比较防时序攻击 |
| v2.1 | 整数溢出漏洞修复（`1U << 32` → `1ULL`） |
| v2.1 | Use-After-Free 漏洞修复（HTTP exporter 持锁复制字符串） |
| v2.1 | RCU 读取一致性修复（`READ_ONCE`/`WRITE_ONCE` 配对） |
| v2.1 | 路径验证增强（`O_NOFOLLOW` + `/proc/self/fd/` 验证） |
| v2.1 | ReDoS 防护增强（`PCRE2_MATCH_LIMIT` 限制回溯） |
| v2.0 | RCU 安全性修复（`hash_add_rcu`、`READ_ONCE`/`WRITE_ONCE`） |
| v2.0 | TOCTOU 竞态条件修复（`O_NOFOLLOW` + inode 验证） |
| v2.0 | 缓冲区溢出修复（独立解析缓冲区） |
| v2.0 | 路径验证增强（白名单目录拒绝） |
| v1.9 | SQLite 线程安全保护（`pthread_mutex_t`） |
| v1.9 | 状态保存/恢复 `is_permanent` 修复 |
| v1.8 | libmicrohttpd 替换（安全更新） |
| v1.7 | PCRE2 替换（ReDoS 防护） |
