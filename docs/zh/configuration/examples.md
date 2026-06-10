# 配置示例

本文档提供常见服务场景的配置模板。

## SSH 防护

### 基础 SSH 防护

适用于 `/var/log/auth.log` (Debian/Ubuntu) 或 `/var/log/secure` (CentOS/RHEL)。

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

### 严格 SSH 防护

更激进的策略，适合面向公网的服务器。

```yaml
jails:
  - name: sshd-strict
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 86400       # 封禁 24 小时
      find_time: 3600       # 1 小时窗口
      max_retries: 3        # 仅 3 次
    port: 22
    protocol: tcp
```

### 多端口 SSH

SSH 运行在非标准端口。

```yaml
jails:
  - name: sshd-custom
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 2222
    protocol: tcp
```

## Web 服务器防护

### Nginx HTTP 认证防护

```yaml
jails:
  - name: nginx-http-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password was provided for basic authentication.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp
```

### Nginx 404 扫描防护

检测频繁访问不存在页面的行为。

```yaml
jails:
  - name: nginx-404
    enabled: true
    log_path: /var/log/nginx/access.log
    filter:
      regex: '<HOST>.*"GET.*HTTP/1\.[01]".*404'
    action:
      ban_time: 3600
      find_time: 60
      max_retries: 50
    port: 80
    protocol: tcp
```

### Apache 认证防护

```yaml
jails:
  - name: apache-auth
    enabled: true
    log_path: /var/log/apache2/error.log
    filter:
      regex: 'client <HOST>.*authentication failure'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp
```

## 邮件服务器防护

### Postfix SMTP 防护

```yaml
jails:
  - name: postfix
    enabled: true
    log_path: /var/log/mail.log
    filter:
      regex: 'warning: .*\[<HOST>\]: SASL .+ authentication failed'
    action:
      ban_time: 7200
      find_time: 600
      max_retries: 3
    port: 25
    protocol: tcp
```

### Dovecot IMAP/POP3 防护

```yaml
jails:
  - name: dovecot
    enabled: true
    log_path: /var/log/mail.log
    filter:
      regex: 'auth failed.*rip=<HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 143
    protocol: tcp
```

## FTP 防护

### vsftpd 防护

```yaml
jails:
  - name: vsftpd
    enabled: true
    log_path: /var/log/vsftpd.log
    filter:
      regex: 'FAIL LOGIN: Client "<HOST>"'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 21
    protocol: tcp
```

### ProFTPD 防护

```yaml
jails:
  - name: proftpd
    enabled: true
    log_path: /var/log/proftpd/auth.log
    filter:
      regex: 'USER .+: no such user found from <HOST>'
    action:
      ban_time: 3600
      find_time: 600
      max_retries: 5
    port: 21
    protocol: tcp
```

## 数据库防护

### MySQL/MariaDB 防护

```yaml
jails:
  - name: mysqld-auth
    enabled: true
    log_path: /var/log/mysql/error.log
    filter:
      regex: 'Access denied for user .*@<HOST>'
    action:
      ban_time: 3600
      find_time: 300
      max_retries: 10
    port: 3306
    protocol: tcp
```

### PostgreSQL 防护

```yaml
jails:
  - name: postgresql-auth
    enabled: true
    log_path: /var/log/postgresql/postgresql.log
    filter:
      regex: 'password authentication failed for user .* from <HOST>'
    action:
      ban_time: 3600
      find_time: 300
      max_retries: 10
    port: 5432
    protocol: tcp
```

## 自定义应用防护

### 通用认证失败日志

适配你的应用日志格式。

```yaml
jails:
  - name: custom-app
    enabled: true
    log_path: /var/log/myapp/auth.log
    filter:
      regex: 'Authentication failed from IP: <HOST>'
    action:
      ban_time: 1800
      find_time: 600
      max_retries: 5
    port: 8080
    protocol: tcp
```

### JSON 日志格式

使用正则匹配 JSON 格式的日志。

```yaml
jails:
  - name: json-app
    enabled: true
    log_path: /var/log/myapp/app.log
    filter:
      regex: '"event":"login_failed".*"source_ip":"<HOST>"'
    action:
      ban_time: 1800
      find_time: 600
      max_retries: 5
    port: 8080
    protocol: tcp
```

## 完整生产配置

一个面向公网的 Web 服务器的完整配置：

```yaml
global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db

whitelist:
  - 127.0.0.1
  - 192.168.1.0/24        # 内网管理
  - 10.0.0.0/8            # 办公网络

jails:
  # SSH 防护
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

  # Nginx HTTP 认证
  - name: nginx-http-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password was provided for basic authentication.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 80
    protocol: tcp

  # Nginx HTTPS 认证
  - name: nginx-https-auth
    enabled: true
    log_path: /var/log/nginx/error.log
    filter:
      regex: 'no user/password was provided for basic authentication.*client: <HOST>'
    action:
      ban_time: 1800
      find_time: 300
      max_retries: 10
    port: 443
    protocol: tcp

  # Postfix SMTP
  - name: postfix
    enabled: true
    log_path: /var/log/mail.log
    filter:
      regex: 'warning: .*\[<HOST>\]: SASL .+ authentication failed'
    action:
      ban_time: 7200
      find_time: 600
      max_retries: 3
    port: 25
    protocol: tcp
```