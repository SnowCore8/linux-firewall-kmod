# 永久封禁指南 (SQLite 持久化)

**版本**: v2.0

## 1. 概述

永久封禁功能使用 SQLite 数据库持久化封禁记录，确保重启后封禁状态不丢失。

## 2. 配置

### 2.1 启用永久封禁

在配置文件中添加：

```yaml
defaults:
  permanent_ban_enabled: true
  permanent_db_path: /var/lib/firewall/bans.db
```

### 2.2 配置参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `permanent_ban_enabled` | boolean | `false` | 是否启用永久封禁 |
| `permanent_db_path` | string | `/var/lib/firewall/bans.db` | SQLite 数据库路径 |

## 3. 数据库 Schema

```sql
CREATE TABLE IF NOT EXISTS permanent_bans (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_permanent_bans_ip ON permanent_bans(ip);
```

## 4. 使用方法

### 4.1 通过 procfs 永久封禁

```bash
# 永久封禁 IP
echo "1.2.3.4 0" | sudo tee /proc/firewall/bans

# 移除永久封禁
echo "unban 1.2.3.4" | sudo tee /proc/firewall/bans
```

### 4.2 通过守护进程永久封禁

当 `permanent_ban_enabled: true` 时，封禁时长为 0 的 IP 自动存入 SQLite 数据库。

## 5. 数据库维护

### 5.1 查看永久封禁列表

```bash
sqlite3 /var/lib/firewall/bans.db "SELECT * FROM permanent_bans;"
```

### 5.2 手动添加永久封禁

```bash
sqlite3 /var/lib/firewall/bans.db "INSERT INTO permanent_bans (ip, reason) VALUES ('1.2.3.4', 'manual');"
```

### 5.3 移除永久封禁

```bash
sqlite3 /var/lib/firewall/bans.db "DELETE FROM permanent_bans WHERE ip='1.2.3.4';"
```

### 5.4 数据库备份

```bash
cp /var/lib/firewall/bans.db /var/lib/firewall/bans.db.bak
```

### 5.5 数据库修复

```bash
sqlite3 /var/lib/firewall/bans.db "PRAGMA integrity_check;"
```

## 6. 重启恢复

守护进程启动时自动从 SQLite 数据库恢复永久封禁：

1. 打开数据库连接
2. 查询所有永久封禁记录
3. 通过 procfs 写入内核模块
4. 标记为 `is_permanent = true`

## 7. 线程安全

SQLite 操作使用 `pthread_mutex_t` 保护，确保并发安全：

```c
pthread_mutex_lock(&db->lock);
// SQLite 操作
pthread_mutex_unlock(&db->lock);
```

## 8. 批量操作

支持批量插入永久封禁记录，使用事务保证原子性：

```c
sqlite3_exec(db->conn, "BEGIN;", NULL, NULL, NULL);
// 批量插入
sqlite3_exec(db->conn, "COMMIT;", NULL, NULL, NULL);
// 错误时：sqlite3_exec(db->conn, "ROLLBACK;", NULL, NULL, NULL);
```
