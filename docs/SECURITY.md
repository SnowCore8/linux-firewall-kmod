# 安全特性技术文档

**版本**: v2.0

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

**关键保证**：读者无需等待写者；写者等待 RCU 宽限期后释放内存；字段读写使用 `READ_ONCE`/`WRITE_ONCE` 防止编译器重排序。

### 4.2 锁设计

```
firewall_info.lock
  ├── ban_table (哈希表)
  └── whitelist_table (哈希表)
```

单锁设计，无死锁风险。

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

## 7. 监控指标

Prometheus 指标（端口 9119）：

| 指标 | 说明 |
|------|------|
| `firewall_kernel_banned_ips_current` | 当前封禁数 |
| `firewall_kernel_total_bans_total` | 累计封禁次数 |
| `firewall_daemon_ips_banned_total` | 守护进程封禁次数 |

## 8. 安全修复历史

| 版本 | 修复内容 |
|------|---------|
| v2.0 | RCU 安全性修复（`hash_add_rcu`、`READ_ONCE`/`WRITE_ONCE`） |
| v2.0 | TOCTOU 竞态条件修复（`O_NOFOLLOW` + inode 验证） |
| v2.0 | 缓冲区溢出修复（独立解析缓冲区） |
| v2.0 | 路径验证增强（白名单目录拒绝） |
| v1.9 | SQLite 线程安全保护（`pthread_mutex_t`） |
| v1.9 | 状态保存/恢复 `is_permanent` 修复 |
| v1.8 | libmicrohttpd 替换（安全更新） |
| v1.7 | PCRE2 替换（ReDoS 防护） |
