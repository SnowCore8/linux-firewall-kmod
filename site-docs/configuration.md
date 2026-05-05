# 配置指南

**版本**: v2.0

## 1. 配置文件结构

Firewall 使用 YAML 配置文件，支持两种加载方式：

```bash
# 加载单个配置文件
sudo ./build/daemon/firewall-daemon -c config/default.yaml

# 加载目录下所有 YAML 文件
sudo ./build/daemon/firewall-daemon -C /etc/firewall/
```

### 1.1 文件位置

| 位置 | 说明 |
|------|------|
| `/etc/firewall/` | 生产环境配置目录 |
| `config/` | 项目内置配置模板 |

### 1.2 配置结构

```yaml
# 全局默认配置
defaults:
  max_retries: 5
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119

# Jail 配置（每个服务一个块）
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
    - /var/log/secure
  max_retries: 5
  findtime: 600
  ban_time: 900
  regex: ""
```

## 2. 全局默认配置 (defaults)

`defaults` 块定义所有 Jail 的默认值，单个 Jail 可以覆盖这些值。

| 参数 | 类型 | 默认值 | 说明 | 有效范围 |
|------|------|--------|------|----------|
| `max_retries` | integer | `5` | 触发封禁所需的失败次数 | 1 ~ 100 |
| `findtime` | integer | `600` | 失败记录的时间窗口（秒） | 1 ~ 3600 |
| `ban_time` | integer | `900` | 封禁持续时间（秒），0=永久 | 0 或 1 ~ 86400 |
| `interval` | integer | `1` | 日志检查间隔（秒） | 1 ~ 60 |
| `metrics_port` | integer | `9119` | Prometheus 指标导出端口 | 0 ~ 65535 |

**示例**：

```yaml
defaults:
  max_retries: 5        # 5 次失败后封禁
  findtime: 600         # 10 分钟窗口
  ban_time: 900         # 封禁 15 分钟
  interval: 1           # 每秒检查一次
  metrics_port: 9119    # Prometheus 端口
```

## 3. Jail 配置

每个 Jail 代表一个服务的防护配置。

| 参数 | 类型 | 默认值 | 说明 | 限制 |
|------|------|--------|------|------|
| `enabled` | boolean | `true` | 是否启用该 Jail | - |
| `log_files` | array | `[]` | 要监控的日志文件路径列表 | 最多 10 个文件 |
| `max_retries` | integer | 继承 defaults | 覆盖默认 max_retries | 1 ~ 100 |
| `findtime` | integer | 继承 defaults | 覆盖默认 findtime | 1 ~ 3600 |
| `ban_time` | integer | 继承 defaults | 覆盖默认 ban_time，0=永久 | 0 或 1 ~ 86400 |
| `regex` | string | `""` | 自定义 PCRE2 正则表达式 | 最大 1024 字节 |

**示例**：

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  max_retries: 5
  findtime: 600
  ban_time: 900
  regex: ""  # 使用内置 SSHD 模式
```

## 4. 预设服务模板

项目提供 12 个预设服务模板：

| 文件 | Jail 名称 | 服务类型 | 默认日志路径 |
|------|-----------|---------|-------------|
| `default.yaml` | sshd | SSH | `/var/log/auth.log` |
| `nginx.yaml` | nginx | Web 服务器 | `/var/log/nginx/error.log` |
| `apache.yaml` | apache | Web 服务器 | `/var/log/apache2/error.log` |
| `dovecot.yaml` | dovecot | 邮件服务 | `/var/log/mail.log` |
| `postfix.yaml` | postfix | 邮件服务 | `/var/log/mail.log` |
| `mysql.yaml` | mysql | 数据库 | `/var/log/mysql/error.log` |
| `vsftpd.yaml` | vsftpd | FTP 服务 | `/var/log/vsftpd.log` |
| `wordpress.yaml` | wordpress | Web 应用 | `/var/log/nginx/error.log` |
| `redis.yaml` | redis | 数据库 | `/var/log/redis/redis-server.log` |
| `docker.yaml` | docker | 容器平台 | `/var/log/docker.log` |
| `traefik.yaml` | traefik | 反向代理 | `/var/log/traefik/traefik.log` |
| `frp.yaml` | frp | 内网穿透 | `/var/log/frp/frp.log` |

## 5. 智能推断

当 Jail 名称匹配已知服务时，系统自动推断配置：

| Jail 名称关键词 | 推断服务 | 内置正则 |
|----------------|---------|---------|
| `ssh` | SSHD | `Failed password for .* from <IP>` |
| `nginx` | Nginx | `access forbidden by rule, client: <IP>` |
| `apache` | Apache | `client denied by server configuration: ...` |
| `mysql` | MySQL | `Access denied for user .* from <IP>` |
| `redis` | Redis | `Invalid password from <IP>` |
| `vsftpd` | vsftpd | `FAIL LOGIN: Client "<IP>"` |
| `docker` | Docker | `TLS handshake error from <IP>` |
| `frp` | FRP | `remoteAddr: <IP>` |

## 6. 严格/宽松模式

### 6.1 严格模式（默认）

未知参数或无效值直接报错拒绝加载：

```bash
sudo ./build/daemon/firewall-daemon --strict
```

### 6.2 宽松模式

允许未知参数并输出警告：

```bash
sudo ./build/daemon/firewall-daemon --permissive
```

## 7. 配置热重载

发送 SIGHUP 信号重载配置：

```bash
sudo kill -HUP $(cat /run/firewall-daemon.pid)
```

**热重载流程**：
1. 解析新配置到临时结构
2. 验证配置有效性
3. 原子交换配置指针
4. 释放旧配置内存

## 8. 自定义正则

### 8.1 使用内置模式

```yaml
sshd:
  enabled: true
  log_files:
    - /var/log/auth.log
  regex: ""  # 使用内置 SSHD 模式
```

### 8.2 自定义 PCRE2 正则

```yaml
custom-app:
  enabled: true
  log_files:
    - /var/log/custom.log
  regex: "Authentication failure.*from\s+<IP>"
```

**要求**：
- 正则必须包含 `<IP>` 占位符用于 IP 提取
- 使用 PCRE2 语法
- 最大 1024 字节

### 8.3 ReDoS 防护

系统自动检测以下危险模式：
- 嵌套量词：`(a+)+`
- 占有量词：`a++`
- 过多分支选择：`(a|b|c|...){10,}`

检测到危险模式时拒绝加载并报错。

## 9. 配置校验规则

### 9.1 参数白名单

**Defaults 部分**仅接受以下参数：
- `max_retries`, `findtime`, `ban_time`, `interval`, `metrics_port`

**Jail 部分**仅接受以下参数：
- `enabled`, `log_files`, `max_retries`, `findtime`, `ban_time`
- `regex`

### 9.2 值范围检查

| 参数 | 最小值 | 最大值 |
|------|--------|--------|
| `max_retries` | 1 | 100 |
| `findtime` | 1 | 3600 |
| `ban_time` | 0 (永久) | 86400 (24 小时) |
| `interval` | 1 | 60 |
| `metrics_port` | 0 | 65535 |

### 9.3 路径验证

日志文件路径必须满足：
- 存在于 `/var/log/`、`/etc/`、`/home/`、`/srv/` 目录下
- 不包含 `//` 连续斜杠
- `realpath` 解析后仍在白名单目录内
