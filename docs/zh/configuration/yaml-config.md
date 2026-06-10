# YAML 配置详解

本文档详细介绍 `/etc/firewall/default.yaml` 配置文件的所有选项。

## 全局配置 (global)

```yaml
global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db
```

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `log_level` | string | `info` | 日志级别：`debug`, `info`, `warn`, `error` |
| `log_file` | string | `/var/log/firewall.log` | 日志文件路径 |
| `db_path` | string | `/var/lib/firewall/bans.db` | SQLite 数据库路径 |

### 日志级别

| 级别 | 说明 |
|------|------|
| `debug` | 调试信息，包含所有详细操作日志 |
| `info` | 一般信息，封禁/解封事件 |
| `warn` | 警告信息，配置问题、资源不足 |
| `error` | 错误信息，模块加载失败、数据库错误 |

## 白名单配置 (whitelist)

```yaml
whitelist:
  - 127.0.0.1
  - 192.168.1.0/24
  - 10.0.0.1
  - 172.16.0.0/16
```

| 格式 | 示例 | 说明 |
|------|------|------|
| 单个 IP | `192.168.1.100` | 封禁时跳过该 IP |
| CIDR 网段 | `192.168.1.0/24` | 封禁时跳过该网段所有 IP |

> **限制**：白名单最多支持 64 个条目。超出部分将被忽略并记录警告。

### 内置白名单

以下 IP 始终被白名单保护，无需手动配置：

- `127.0.0.1` - 本地回环地址

## Jail 配置

每个 jail 定义一个独立的监控和封禁规则。

### 完整示例

```yaml
jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 22
    protocol: tcp
```

### 基本参数

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `name` | string | 是 | - | Jail 名称，全局唯一 |
| `enabled` | bool | 否 | `true` | 是否启用该 jail |
| `log_path` | string | 是 | - | 要监控的日志文件路径 |
| `port` | int | 是 | - | 监控的目标端口 |
| `protocol` | string | 是 | - | 协议：`tcp`, `udp`, `all` |

### 过滤器配置 (filter)

```yaml
filter:
  regex: 'Failed password for .* from <HOST>'
```

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `regex` | string | 是 | PCRE2 正则表达式，使用 `<HOST>` 占位符匹配 IP |

### 正则表达式语法

使用 PCRE2 引擎，支持以下特性：

| 特性 | 示例 | 说明 |
|------|------|------|
| `<HOST>` 占位符 | `from <HOST>` | 匹配 IPv4/IPv6 地址 |
| 捕获组 | `(?:pattern)` | 非捕获组 |
| 字符类 | `[a-z]` | 字符范围 |
| 量词 | `*`, `+`, `?` | 重复匹配 |
| 锚点 | `^`, `$` | 行首/行尾 |

### `<HOST>` 占位符

`<HOST>` 是特殊占位符，自动匹配 IP 地址：

```
# 等效正则
<HOST> => (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
```

### 动作配置 (action)

```yaml
action:
  ban_time: 3600
  find_time: 600
  max_retries: 5
```

| 参数 | 类型 | 必需 | 默认值 | 说明 |
|------|------|------|--------|------|
| `ban_time` | int | 否 | `3600` | 封禁时长（秒），0 表示永久 |
| `find_time` | int | 否 | `600` | 时间窗口（秒），在此时间内计数 |
| `max_retries` | int | 否 | `5` | 最大失败次数，超过则封禁 |

### 时间参数关系

```
find_time (600s)
├── 在此时间窗口内统计失败次数
│
max_retries (5)
├── 达到此次数触发封禁
│
ban_time (3600s)
├── 封禁持续此时长
└── 到期后自动解封
```

## 完整配置示例

```yaml
# /etc/firewall/default.yaml

global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db

whitelist:
  - 127.0.0.1
  - 192.168.1.0/24
  - 10.0.0.1

jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 22
    protocol: tcp

  - name: nginx-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp

  - name: dovecot
    enabled: false
    log_path: /var/log/mail.log
    filter:
      regex: 'auth failed.*rip=<HOST>'
    action:
      ban_time: 7200
      find_time: 600
      max_retries: 3
    port: 143
    protocol: tcp
```