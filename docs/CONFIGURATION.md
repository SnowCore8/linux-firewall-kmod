# 配置指南

**版本**: v1.9

本文档详细介绍 Firewall 守护进程的 YAML 配置格式、参数说明、最佳实践和故障排查。

---

## 1. YAML 配置结构概述

Firewall 采用 **defaults + jails** 双层配置结构：

```yaml
defaults:           # 全局默认值，应用于所有 Jail
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

jails:              # Jail 定义，每个服务独立监控
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
    # 未指定的参数继承 defaults

permanent_db_path: "/var/lib/firewall/bans.db"   # 永久封禁数据库路径
permanent_ban_enabled: true                       # 是否启用永久封禁
```

### 参数继承和覆盖规则

| 规则 | 说明 |
|------|------|
| **继承** | Jail 中未指定的参数自动继承 `defaults` 中的值 |
| **覆盖** | Jail 中显式指定的参数覆盖 `defaults` 对应值 |
| **隔离** | 不同 Jail 之间互不影响，各自维护独立的计数器和时间窗口 |
| **全局** | `permanent_db_path` 和 `permanent_ban_enabled` 是全局参数，不属于 defaults 或 jails |

---

## 2. 全局默认值（defaults）

`defaults` 区块定义所有 Jail 的默认行为。Jail 中未指定的参数将使用这些默认值。

### 参数说明

| 参数 | 类型 | 默认值 | 说明 | 有效范围 |
|------|------|--------|------|----------|
| `max_retries` | integer | `5` | 触发封禁所需的失败次数 | 1 ~ 100 |
| `findtime` | integer | `600` | 失败记录的时间窗口（秒） | 10 ~ 86400 |
| `ban_time` | integer | `900` | 封禁持续时间（秒） | 30 ~ 31536000（1年） |
| `interval` | integer | `1` | 日志检查间隔（秒） | 1 ~ 60 |
| `metrics_port` | integer | `9119` | Prometheus 指标导出端口 | 1024 ~ 65535 |

### 参数详解

- **max_retries**: 在 `findtime` 时间窗口内，匹配到该次数的失败日志后触发封禁。值过小可能导致误封，过大则降低防护效果。
- **findtime**: 失败计数的滑动窗口大小。例如 `findtime: 600` 表示只统计最近 10 分钟内的失败记录。
- **ban_time**: 封禁持续时间。设置为 `0` 表示永久封禁（需启用 `permanent_ban_enabled`）。
- **interval**: 守护进程扫描日志文件的频率。值越小响应越快，但 CPU 占用越高。
- **metrics_port**: Prometheus `/metrics` 端口的监听端口。设置为 `0` 可禁用指标导出。

---

## 3. Jail 配置

每个 Jail 代表一个被监控的服务，拥有独立的日志源和封禁策略。

### 参数说明

| 参数 | 类型 | 默认值 | 说明 | 限制 |
|------|------|--------|------|------|
| `enabled` | boolean | `true` | 是否启用该 Jail | - |
| `log_files` | array | `[]` | 要监控的日志文件路径列表 | 最多 10 个文件 |
| `max_retries` | integer | 继承 defaults | 覆盖全局 max_retries | 1 ~ 100 |
| `findtime` | integer | 继承 defaults | 覆盖全局 findtime | 10 ~ 86400 |
| `ban_time` | integer | 继承 defaults | 覆盖全局 ban_time | 30 ~ 31536000 |
| `regex` | string | `""` | 自定义 PCRE2 正则表达式 | 最大 1024 字节 |

### 参数详解

- **enabled**: 设置为 `false` 可临时禁用某个 Jail 而不删除配置。禁用的 Jail 不会监控日志文件。
- **log_files**: 绝对路径列表。守护进程使用 inotify 监控这些文件的变更。支持同时监控多个日志文件（如 `/var/log/auth.log` 和 `/var/log/secure`）。
- **regex**: 空字符串 `""` 表示使用内置的 sshd 匹配模式。自定义正则必须包含至少一个捕获组 `(...)` 来提取 IP 地址。

---

## 4. 内置服务支持

### sshd（SSH 服务）

当 `regex: ""` 时，自动使用内置的 sshd 匹配模式，可识别以下日志格式：

```
Failed password for root from 192.168.1.100 port 22 ssh2
Failed password for invalid user admin from 10.0.0.1 port 22 ssh2
```

内置模式自动提取 `from` 关键字后的 IPv4 地址。

### 自定义服务

对于非 sshd 服务，需要编写自定义 `regex`。正则表达式必须：

1. 使用 PCRE2 语法
2. 包含至少一个捕获组 `(...)` 用于提取 IP 地址
3. 捕获组内容必须匹配 IPv4 地址格式（如 `192.168.1.1`）

---

## 5. 自定义正则表达式指南

### 捕获组提取 IP 的方法

守护进程会遍历正则表达式的所有捕获组，找到第一个匹配 IPv4 格式的捕获组内容作为封禁目标 IP。

```
# 正确示例 - 捕获组包含完整 IPv4
"Failed login from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"

# 正确示例 - 多个捕获组，第一个匹配 IP 的会被使用
"(\w+) from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) port (\d+)"

# 错误示例 - 捕获组不包含 IP
"Failed login from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"    # 缺少捕获组
```

### 常见日志格式示例

#### SSH（非标准格式）

```yaml
regex: "Failed password.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
```

#### FRP

```yaml
regex: ".*\\[E\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)|.*\\[W\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
```

匹配示例：
```
2026-04-22 17:52:16.417 [E] [proxy.go:100] remoteAddr: 43.100.123.123:7000
2026-04-22 17:52:16.417 [W] [proxy.go:100] remoteAddr: 43.100.123.123:7000
```

#### Nginx（错误日志）

```yaml
regex: "access forbidden by rule, client: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
```

匹配示例：
```
2026/04/22 17:52:16 [error] 1234#0: *5678 access forbidden by rule, client: 192.168.1.100
```

#### Dovecot

```yaml
regex: "auth:.*auth failed.*rip=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"
```

#### Postfix

```yaml
regex: "warning:.*\[([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\]: SASL.*authentication failure"
```

### ReDoS 防护限制

为防止正则表达式拒绝服务攻击（ReDoS），自定义 regex 受以下限制：

| 限制项 | 值 | 说明 |
|--------|-----|------|
| 最大长度 | 1024 字节 | 超过将被拒绝 |
| 最大交替数 | 50 个 `\|` | 防止回溯炸弹 |
| 嵌套量词 | 禁止 | 拒绝 `)*`、`)+`、`){`、`}?`、`++`、`*+` 等模式 |

> **提示**: 编写正则时避免使用 `.*` 后接量词的组合（如 `(.*?)+`），这可能导致指数级回溯。

---

## 6. 多配置合并规则

守护进程支持从配置目录加载多个 YAML 文件，便于模块化管理。

### 加载顺序

配置文件按 **字母顺序** 加载：

```
/etc/firewall/
├── 01-default.yaml    # 首先加载
├── 02-sshd.yaml       # 其次加载
├── 03-frp.yaml        # 再次加载
└── 99-custom.yaml     # 最后加载
```

### 覆盖规则

| 场景 | 行为 |
|------|------|
| `defaults` 参数 | 后加载的文件覆盖先加载的同名参数 |
| Jail 定义 | **不会互相覆盖**，不同文件中的同名 Jail 会被合并 |
| Jail 参数 | 同一 Jail 在后加载文件中的参数覆盖先加载文件 |
| 全局参数 | `permanent_db_path` 和 `permanent_ban_enabled` 被最后加载的值覆盖 |

### 限制

- 配置目录中最多加载 **50 个** `.yaml` / `.yml` 文件
- 所有 Jail 总数不超过 **16 个**
- 建议按功能拆分配置，如 `sshd.yaml`、`frp.yaml`、`nginx.yaml`

### 示例

```yaml
# 01-defaults.yaml
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

# 02-sshd.yaml
jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log

# 03-frp.yaml
jails:
  frp:
    enabled: true
    log_files:
      - /var/log/frp/frp.log
    max_retries: 10
    findtime: 300
    ban_time: 1800
    regex: ".*\\[E\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"
```

---

## 7. 配置热重载

守护进程支持运行时重载配置，无需重启服务。

### 触发方式

```bash
# 方式一：发送 SIGHUP 信号
sudo kill -HUP $(pidof firewall-daemon)

# 方式二：使用 systemd（推荐）
sudo systemctl reload firewall-daemon
```

### 热重载流程

1. 接收 `SIGHUP` 信号
2. 清理旧 Jail 资源（关闭日志文件句柄、释放 inotify 监控）
3. 重新解析所有 YAML 配置文件
4. 重新设置 inotify 监控
5. 重新注册所有 Jail 的日志文件

### 注意事项

| 事项 | 说明 |
|------|------|
| **已封禁 IP** | 不会因热重载而解封 |
| **配置错误** | 如果配置文件有语法错误，热重载会失败并记录错误日志 |
| **内存安全** | 热重载时会自动释放旧资源，防止内存泄漏 |
| **双缓冲模式** | 新配置在后台解析完成后才切换，持锁时间极短（约 50 行代码） |
| **服务中断** | 热重载期间日志监控会有短暂中断（通常 < 100ms） |

### 验证热重载

```bash
# 查看守护进程日志确认重载结果
sudo journalctl -u firewall-daemon -n 20 --no-pager

# 检查当前生效的 Jail 列表
sudo systemctl status firewall-daemon
```

---

## 8. 完整配置示例

### 示例一：default.yaml（完整注释版）

```yaml
# firewall daemon configuration file
# 版本: v1.9

# ============================================================
# 全局默认值 - 应用于所有 Jail，除非被 Jail 显式覆盖
# ============================================================
defaults:
  max_retries: 5        # 触发封禁的失败次数
  findtime: 600         # 失败记录时间窗口（秒，600 = 10分钟）
  ban_time: 900         # 封禁持续时间（秒，900 = 15分钟）
  interval: 1           # 日志检查间隔（秒）
  metrics_port: 9119    # Prometheus 指标导出端口

# ============================================================
# Jail 定义 - 每个服务独立监控
# ============================================================
jails:
  # SSH 服务防护（使用内置正则模式）
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log       # Debian/Ubuntu
      - /var/log/secure         # RHEL/CentOS
    max_retries: 5              # 继承 defaults，可省略
    findtime: 600               # 继承 defaults，可省略
    ban_time: 900               # 继承 defaults，可省略
    regex: ""                   # 空字符串 = 使用内置 sshd 模式

  # FRP 服务防护（自定义正则）
  frp:
    enabled: true
    log_files:
      - /var/log/frp/frp.log
    max_retries: 10             # 覆盖 defaults
    findtime: 300               # 覆盖 defaults（5分钟窗口）
    ban_time: 1800              # 覆盖 defaults（30分钟封禁）
    # 匹配 FRP 错误 [E] 和警告 [W] 日志中的远程 IP
    regex: ".*\\[E\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)|.*\\[W\\].*remoteAddr:\\s*([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"

# ============================================================
# 永久封禁配置（SQLite 持久化）
# ============================================================
permanent_db_path: "/var/lib/firewall/bans.db"   # SQLite 数据库路径
permanent_ban_enabled: true                       # 启用永久封禁
```

### 示例二：多 Jail 配置

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
    regex: ""

  nginx:
    enabled: true
    log_files:
      - /var/log/nginx/error.log
    max_retries: 3
    ban_time: 3600
    regex: "access forbidden by rule, client: ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"

  dovecot:
    enabled: true
    log_files:
      - /var/log/mail.log
    max_retries: 5
    findtime: 300
    ban_time: 1800
    regex: "auth:.*auth failed.*rip=([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)"

permanent_db_path: "/var/lib/firewall/bans.db"
permanent_ban_enabled: true
```

### 示例三：最小配置

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
    regex: ""
```

---

## 9. 配置验证

### 启动时验证

守护进程启动时会自动验证配置：

| 验证项 | 错误行为 |
|--------|----------|
| YAML 语法 | 启动失败，输出解析错误位置 |
| 必填参数缺失 | 使用默认值填充（`enabled` 默认 `true`） |
| 日志文件不存在 | 记录警告，继续运行（文件创建后自动监控） |
| regex 编译失败 | 该 Jail 被禁用，记录错误日志 |
| Jail 数量超限 | 超过 16 个时拒绝加载额外 Jail |
| 参数超出范围 | 使用边界值修正并记录警告 |

### 运行时验证

| 场景 | 行为 |
|------|------|
| 热重载配置错误 | 保留旧配置，记录错误日志 |
| 日志文件被删除 | 记录警告，文件恢复后自动重新监控 |
| regex 匹配异常 | 跳过该行日志，记录调试日志 |

### 常见错误和排查

| 错误现象 | 可能原因 | 解决方法 |
|----------|----------|----------|
| 启动失败：`Failed to parse YAML` | YAML 语法错误（缩进、冒号后缺空格） | 使用 `yamllint` 检查配置文件 |
| Jail 未生效 | `enabled: false` 或 regex 编译失败 | 检查日志中的 jail 加载信息 |
| 无法提取 IP | regex 捕获组未匹配到 IPv4 格式 | 使用 `pcre2test` 测试正则表达式 |
| 热重载失败 | 新配置有语法错误 | 查看 `journalctl` 错误日志，修复后重试 |
| metrics_port 冲突 | 端口已被其他服务占用 | 更换 `metrics_port` 或停止占用服务 |
| 封禁不触发 | `max_retries` 过大或 `findtime` 过小 | 调整参数，查看日志中的匹配计数 |

### 调试命令

```bash
# 查看守护进程日志
sudo journalctl -u firewall-daemon -f

# 查看特定时间段的日志
sudo journalctl -u firewall-daemon --since "10 minutes ago"

# 验证 YAML 语法
yamllint /etc/firewall/default.yaml

# 测试正则表达式（需要 pcre2-utils）
echo "Failed password for root from 192.168.1.100 port 22" | pcre2grep -oP 'Failed password.*from ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'

# 检查配置文件权限
ls -la /etc/firewall/*.yaml
```

### 配置文件权限建议

```bash
# 配置目录
sudo chmod 755 /etc/firewall/

# 配置文件（仅 root 可写）
sudo chmod 644 /etc/firewall/*.yaml
sudo chown root:root /etc/firewall/*.yaml

# 永久封禁数据库目录
sudo mkdir -p /var/lib/firewall
sudo chmod 700 /var/lib/firewall
sudo chown root:root /var/lib/firewall
```
