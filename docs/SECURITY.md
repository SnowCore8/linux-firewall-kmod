# 安全特性文档

> **版本**: v2.0 | **更新日期**: 2026-05-04

本文档详述 Firewall 项目的安全特性、加固措施和历史安全修复。

---

## 目录

1. [安全编译选项](#1-安全编译选项)
2. [systemd 服务安全加固](#2-systemd-服务安全加固)
3. [v1.9 安全/并发修复](#3-v19-安全并发修复)
4. [v2.0 配置注入防护](#4-v20-配置注入防护)
5. [v1.7 安全加固](#5-v17-安全加固)
6. [TOCTOU 竞态修复](#6-toctou-竞态修复)
7. [其他安全特性](#7-其他安全特性)
8. [安全最佳实践](#8-安全最佳实践)

---

## 1. 安全编译选项

守护进程编译时启用多项安全加固标志（来自 `Makefile`）：

```makefile
SECURITY_CFLAGS = -Wall -Wextra -Werror=format-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
SECURITY_LDFLAGS = -pie -Wl,-z,relro,-z,now
```

| 选项 | 类型 | 说明 |
|------|------|------|
| `-fstack-protector-strong` | 编译 | 栈溢出保护，在含局部缓冲区的函数中插入 canary 值，检测缓冲区溢出攻击 |
| `-D_FORTIFY_SOURCE=2` | 编译 | 编译时和运行时检查常见缓冲区溢出，自动替换为安全版本（如 `strcpy` → `strncpy`） |
| `-fPIE` + `-pie` | 编译+链接 | 位置无关可执行文件，配合 ASLR 实现地址空间布局随机化 |
| `-Wl,-z,relro` | 链接 | 重定位只读，将 GOT 表标记为只读，防止 GOT 覆写攻击 |
| `-Wl,-z,now` | 链接 | 立即绑定所有符号（Full RELRO），消除延迟绑定的 GOT 可写窗口 |
| `-Werror=format-security` | 编译 | 将格式化字符串警告升级为错误，防止 `printf(user_input)` 类漏洞 |

---

## 2. systemd 服务安全加固

`firewall-daemon.service` 包含 15 项安全限制，遵循最小权限原则：

```ini
[Service]
Type=forking
ExecStart=/usr/local/sbin/firewall-daemon -C /etc/firewall --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure

# Security Hardening
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/firewall /etc/firewall
PrivateTmp=yes
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
```

| # | 限制项 | 说明 | 防护目标 |
|---|--------|------|----------|
| 1 | `NoNewPrivileges=yes` | 禁止进程获取新权限 | 权限提升攻击 |
| 2 | `ProtectSystem=strict` | `/usr`、`/boot`、`/etc` 只读 | 系统文件篡改 |
| 3 | `ReadWritePaths` | 仅允许写入指定路径 | 限制写入范围 |
| 4 | `PrivateTmp=yes` | 隔离 `/tmp` 命名空间 | `/tmp` 竞态攻击 |
| 5 | `ProtectHome=yes` | 禁止访问 `/home`、`/root` | 用户数据泄露 |
| 6 | `ProtectKernelTunables=yes` | 禁止修改内核参数 | 内核参数篡改 |
| 7 | `ProtectKernelModules=yes` | 禁止加载内核模块 | 恶意模块注入 |
| 8 | `ProtectControlGroups=yes` | 禁止修改 cgroup | 资源控制绕过 |
| 9 | `RestrictNamespaces=yes` | 禁止创建新命名空间 | 容器逃逸 |
| 10 | `RestrictRealtime=yes` | 禁止实时调度优先级 | 资源耗尽 |
| 11 | `RestrictSUIDSGID=yes` | 禁止创建 setuid/setgid 文件 | 权限持久化 |
| 12 | `MemoryDenyWriteExecute=yes` | 禁止可写可执行内存映射 | Shellcode 注入 |
| 13 | `LockPersonality=yes` | 锁定执行域 | 执行域切换攻击 |
| 14 | `SystemCallFilter=@system-service` | 系统调用白名单 | 减少攻击面 |
| 15 | `SystemCallArchitectures=native` | 仅允许本机架构 | 多架构攻击 |

---

## 3. v1.9 安全/并发修复

### 3.1 内核模块锁一致性

**问题**: `__do_ban_ip()` 和 `ban_ip_with_duration()` 持有 `fw_lock` 写锁时直接遍历 RCU 管理的 `whitelist_ht` 哈希表，导致读写冲突。

**影响**: 高 — 并发场景下可能内核 panic 或数据损坏。

**修复**: 改用 RCU 读取模式遍历白名单：

```c
rcu_read_lock();
hash_for_each_rcu(whitelist_ht, b, entry, node) {
    if (entry->ip == ip) { rcu_read_unlock(); return -EEXIST; }
}
rcu_read_unlock();
```

### 3.2 RCU 删除安全

**问题**: 删除哈希表节点使用 `hash_del()` 而非 `hlist_del_rcu()`，RCU 读取期间被删除节点可能已释放。

**影响**: 严重 — RCU 读取器访问已释放内存，导致内核崩溃。

**修复**: 所有删除路径统一替换为 `hlist_del_rcu()`：

```c
// 修复前: hash_del(&entry->node);
// 修复后:
hlist_del_rcu(&entry->node);
```

### 3.3 状态保存/恢复修复

**问题**:
1. 永久 ban 剩余时间计算 `unban_time - jiffies` 可能下溢（`unban_time` 为 0 时）
2. `is_permanent` 字段恢复时未正确初始化

**影响**: 中 — 永久 ban 可能被误判为临时 ban，导致自动解封。

**修复**:

```c
// 下溢防护
if (entry->unban_time == 0) {
    remaining = 0;  // 永久 ban
} else if (time_after(entry->unban_time, jiffies)) {
    remaining = jiffies_to_secs(entry->unban_time - jiffies);
} else {
    remaining = 0;
}
entry->is_permanent = (remaining == 0 && entry->unban_time == 0);
```

### 3.4 khash 悬空指针

**问题**: 永久 ban 哈希表使用外部字符串指针作为 key，调用方释放后成为悬空指针。

**影响**: 严重 — 悬空指针导致 use-after-free，可能内核崩溃或信息泄露。

**修复**: 使用 `kstrdup` 存储 key 副本，销毁时释放：

```c
char *key_copy = kstrdup(ip_str, GFP_KERNEL);
entry->key = key_copy;
// 销毁时: kfree(entry->key);
```

### 3.5 配置重载并发安全

**问题**: SIGHUP 重载配置时直接修改全局 jail 配置，日志处理线程并发读取导致 use-after-free。

**影响**: 高 — 配置重载期间并发访问导致段错误或配置错乱。

**修复**: 双缓冲模式 + 锁内复制（持锁代码从 ~340 行缩减到 ~50 行）：

```c
pthread_mutex_lock(&config_mutex);
parse_config_file(path, &new_jails);  // 解析到新缓冲
memcpy(global_jails, &new_jails, sizeof(new_jails));  // 原子交换
pthread_mutex_unlock(&config_mutex);
```

### 3.6 HTTP 线程优雅退出

**问题**: HTTP exporter 线程收到停止信号时未正确退出，导致线程泄漏。

**影响**: 中 — 多次重载后线程耗尽。

**修复**: 使用 `atomic_bool` 标志控制：

```c
static atomic_bool exporter_running = ATOMIC_VAR_INIT(false);
void exporter_stop(void) {
    atomic_store(&exporter_running, false);
    MHD_stop_daemon(mhd_daemon);
}
```

### 3.7 SQLite 线程安全

**问题**: 主线程和 HTTP exporter 线程并发访问 SQLite 数据库，缺少同步保护。

**影响**: 高 — 并发写入导致数据库文件损坏。

**修复**: 添加 `pthread_mutex_t` 保护所有 SQLite 操作：

```c
static pthread_mutex_t sqlite_mutex = PTHREAD_MUTEX_INITIALIZER;
int sqlite_add_permanent_ban(const char *ip, const char *reason) {
    pthread_mutex_lock(&sqlite_mutex);
    // ... SQLite 操作 ...
    pthread_mutex_unlock(&sqlite_mutex);
}
```

---

## 4. v2.0 配置注入防护

### 配置注入防护

- **严格模式默认开启**：配置文件中任何未知参数或无效值都会导致加载失败
- **参数白名单校验**：`defaults` 和 `jail` 部分分别维护有效参数列表
- **值范围校验**：所有数值参数在加载时验证有效性，防止边界溢出
- **统一错误提示**：错误消息包含参数名、值、位置，便于快速定位问题
- **路径安全验证**：日志文件路径必须为绝对路径，通过 `realpath()` 规范化并验证

### 防护场景

| 攻击类型 | 示例 | 防护机制 |
|----------|------|---------|
| **拼写错误注入** | `max_retrys: 999`（意图绕过限制） | 未知参数直接拒绝加载 |
| **无效值注入** | `max_retries: 999999` | 值范围校验拦截 |
| **未知参数注入** | 在 jail 中添加 `custom_backdoor: true` | 参数白名单校验拦截 |
| **路径遍历** | `log_files: ../../etc/passwd` | 5 层路径验证拒绝 |

### 错误消息格式

严格模式下，所有配置错误遵循统一格式：

```
Invalid config parameter '{key}' with value '{value}' in {location}
```

示例：
- `Invalid config parameter 'invalid_key' with value 'value' in [defaults] of config.yaml`
- `Invalid config parameter 'timeout' with value '30' in jail 'sshd'`
- `Invalid value for 'max_retries': '999' (must be integer between 1 and 100)`

### 有效参数白名单

**defaults 部分**（8 个）：
- `max_retries`, `findtime`, `ban_time`, `interval`, `metrics_port`
- `daemon`, `permanent_db_path`, `permanent_ban_enabled`

**Jail 部分**（6 个）：
- `enabled`, `log_files`, `max_retries`, `findtime`, `ban_time`
- `regex`

---

## 5. v1.7 安全加固

### 5.1 整数溢出防护

**问题**: `seconds * HZ` 运算未检查整数溢出，`ban_time` 过大时封禁时间异常。

**影响**: 高 — 溢出导致封禁时间变为极短或极长。

**修复**: 使用 `check_mul_overflow()` 覆盖所有 ban 时间计算路径：

```c
unsigned long ban_secs = READ_ONCE(fw_ban_time);
unsigned long ban_duration;
if (check_mul_overflow(ban_secs, (unsigned long)HZ, &ban_duration)) {
    fw_pr_err("ban_time overflow detected");
    return -EINVAL;
}
entry->unban_time = jiffies + ban_duration;
```

覆盖位置: `ban_ip()`、`ban_ip_with_duration()`、`bans_write()`。新增 `MAX_BAN_TIME` (365天)、`MIN_BAN_TIME` (30秒) 常量。

### 5.2 SQLite use-after-free

**问题**: `sqlite3_bind_text()` 使用 `SQLITE_STATIC`，调用方在 `sqlite3_step()` 前释放字符串。

**影响**: 严重 — 访问已释放内存可能导致崩溃或任意代码执行。

**修复**: 全部改为 `SQLITE_TRANSIENT`（7 处）：

```c
// 修复前: sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_STATIC);
// 修复后:
sqlite3_bind_text(stmt, 1, ip_str, -1, SQLITE_TRANSIENT);
```

### 5.3 路径遍历纵深防御

**问题**: 日志文件路径验证不足，可能通过特殊路径读取非预期文件。

**影响**: 高 — 路径遍历导致任意文件读取。

**修复**: 5 层纵深防御：

| 层级 | 检查项 | 示例 |
|------|--------|------|
| 1 | 扩展字符黑名单 | 拒绝 `|;&`$(){}<>!~*?[]` |
| 2 | URL 编码检测 | 拒绝 `%2e`、`%2f`（大小写不敏感） |
| 3 | `..` 检测 | 拒绝目录穿越 |
| 4 | `realpath()` 验证 | 规范化后验证路径在允许位置 |
| 5 | 前缀白名单 | 仅允许 `/var/log/` 下的文件 |

### 5.4 ReDoS 防护

**问题**: 自定义正则可能包含嵌套量词，导致正则引擎回溯爆炸。

**影响**: 高 — ReDoS 导致 CPU 100%，服务拒绝。

**修复**: 编译前 3 重检查：

| 检查项 | 限制 | 说明 |
|--------|------|------|
| 模式长度 | ≤ 1024 字节 | 防止超长正则 |
| 交替数量 | ≤ 50 个 `\|` | 防止回溯炸弹 |
| 嵌套量词 | 拒绝 `)+`、`)*`、`++` 等 | 防止指数级回溯 |

### 5.5 HTTP Exporter 加固

- 请求截断检测（缓冲区 1024 字节）
- URI 路径遍历防护（拒绝 `..` 和 URL 编码变体）
- HTTP 版本验证
- 速率限制：64 个 IP 追踪，每 IP 每秒 10 请求
- 5 秒接收超时

### 5.6 YAML 解析边界防护

- 单值长度限制: 1024 字符
- Jail 数量限制: 16 个
- 每个 Jail 日志文件限制: 10 个

---

## 6. TOCTOU 竞态修复

**问题**: `save_state_to_file()` 存在 Time-of-Check to Time-of-Use 竞态条件。攻击者可在 `stat()` 检查后、`fopen()` 写入前将文件替换为符号链接，导致数据写入非预期位置。

**影响**: 严重 — 符号链接攻击导致任意文件覆写。

**修复**:

```c
int save_state_to_file(const char *path) {
    // 1. 检查阶段
    struct stat st;
    lstat(path, &st);
    dev_t saved_dev = st.st_dev;
    ino_t saved_ino = st.st_ino;

    // 2. O_NOFOLLOW 拒绝跟随符号链接
    int fd = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_TRUNC, 0644);

    // 3. inode 一致性检查
    fstat(fd, &st);
    if (st.st_dev != saved_dev || st.st_ino != saved_ino) {
        fw_pr_err("File inode changed, possible symlink attack");
        close(fd); unlink(path);
        return -1;
    }
    // 4. 安全写入 ...
}
```

同时修复了变量遮蔽问题 — 原代码中 `saved_dev`/`saved_ino` 在 if 块内声明，作用域错误导致一致性检查失效。

---

## 7. 其他安全特性

### 7.1 RCU 并发机制

- **读取**: `rcu_read_lock()` / `rcu_read_unlock()` 无锁读取
- **写入**: `spin_lock()` / `spin_unlock()` 互斥写操作
- **删除**: `hlist_del_rcu()` + `kfree_rcu()` 延迟释放
- **遍历**: `hash_for_each_rcu()` RCU 安全遍历

### 7.2 整数溢出和下溢防护

- `check_mul_overflow()` 覆盖所有乘法运算
- inotify 事件处理防止 `buf_len - event_len` 下溢
- `MAX_BAN_TIME` (365天)、`MIN_BAN_TIME` (30秒) 边界常量

### 7.3 输入验证

| 接口 | 验证项 | 说明 |
|------|--------|------|
| IP 地址 | `validate_ipv4_address()` | 统一 IPv4 格式验证（4 段，0-255） |
| 日志数据 | 长度限制 + 字符过滤 | 防止日志注入 |
| procfs | 命令格式解析 + 边界检查 | 防止 procfs 写入越界 |
| 正则表达式 | 长度 + 嵌套量词 + 交替数 | 防止 ReDoS |
| 文件路径 | 5 层纵深防御 | 防止路径遍历 |
| YAML 值 | 单值 1024 字符限制 | 防止内存耗尽 |

### 7.4 自动白名单保护

- 启动时自动发现系统 IP 并加入白名单（防自锁）
- 支持手动添加 IP 和子网（CIDR 格式）
- 白名单上限 64 条目

### 7.5 洪泛保护

- 内核模块内置速率限制日志
- 分片包添加 ratelimited 日志监控
- 永久 ban 容量检查（防拒绝服务）

### 7.6 全局变量受控访问

- `fw_info` 改为 `static`，通过 `get_fw_info()` 导出受控访问

---

## 8. 安全最佳实践

### 8.1 部署建议

1. **使用 systemd 管理**: 利用 15 项安全限制，不手动启动守护进程
2. **最小权限**: `NoNewPrivileges=yes` 限制权限提升
3. **定期更新**: 及时应用安全补丁
4. **目录权限**:

```bash
sudo chmod 750 /var/lib/firewall
sudo chmod 755 /etc/firewall
sudo chmod 644 /etc/firewall/*.yaml
```

### 8.2 配置建议

1. **封禁阈值**: `max_retries: 5`，`findtime: 600` 避免误封
2. **封禁时间**: `ban_time: 900`（15分钟），避免过长
3. **永久 ban**: 仅对确认恶意 IP 使用
4. **白名单**: 确保管理 IP 在白名单中
5. **自定义 regex**: 避免嵌套量词和过多交替符

### 8.3 监控建议

1. **Prometheus 指标**（端口 9119）:
   - `firewall_kernel_banned_ips_current` — 当前封禁数
   - `firewall_kernel_total_bans_total` — 累计封禁次数
   - `firewall_daemon_ips_banned_total` — 守护进程封禁次数

2. **日志关键词监控**:
   - `overflow detected` — 整数溢出告警
   - `symlink attack` — TOCTOU 攻击告警
   - `Nested quantifier` — ReDoS 尝试告警

3. **定期审计**:
   ```bash
   systemctl status firewall-daemon
   journalctl -u firewall-daemon --grep "error\|warn\|attack"
   cat /proc/firewall/stats
   systemd-analyze security firewall-daemon
   ```

---

## 安全修复时间线

| 版本 | 日期 | 关键修复 | 严重程度 |
|------|------|----------|----------|
| v2.0 | 2026-05-04 | 严格配置校验模式、参数白名单、值范围校验、配置注入防护 | 高 |
| v1.9 | 2026-05-04 | RCU 删除安全、khash 悬空指针、配置重载并发安全 | 严重 |
| v1.7 | 2026-05-03 | 整数溢出、SQLite UAF、路径遍历、ReDoS | 高 |
| v1.6 | 2026-04-22 | TOCTOU 竞态、安全编译选项、systemd 加固 | 严重 |
| v1.4 | 2026-04-19 | RCU 并发机制、整数溢出、输入验证 | 高 |
