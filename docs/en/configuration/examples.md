# Configuration Examples

This document provides configuration templates for common service scenarios.

## SSH Protection

### Basic SSH Protection

For `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (CentOS/RHEL).

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

### Strict SSH Protection

More aggressive policy for internet-facing servers.

```yaml
jails:
  - name: sshd-strict
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for (?:invalid user )?.+ from <HOST>'
    action:
      ban_time: 86400       # Ban for 24 hours
      find_time: 3600       # 1 hour window
      max_retries: 3        # Only 3 attempts
    port: 22
    protocol: tcp
```

### Custom SSH Port

SSH running on a non-standard port.

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

## Web Server Protection

### Nginx HTTP Auth Protection

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

### Nginx 404 Scanner Protection

Detects frequent access to non-existent pages.

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

### Apache Auth Protection

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

## Mail Server Protection

### Postfix SMTP Protection

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

### Dovecot IMAP/POP3 Protection

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

## FTP Protection

### vsftpd Protection

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

### ProFTPD Protection

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

## Database Protection

### MySQL/MariaDB Protection

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

### PostgreSQL Protection

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

## Custom Application Protection

### Generic Auth Failure Log

Adapt to your application log format.

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

### JSON Log Format

Using regex to match JSON-formatted logs.

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

## Complete Production Configuration

A complete configuration for an internet-facing web server:

```yaml
global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db

whitelist:
  - 127.0.0.1
  - 192.168.1.0/24        # Internal management
  - 10.0.0.0/8            # Office network

jails:
  # SSH Protection
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

  # Nginx HTTP Auth
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

  # Nginx HTTPS Auth
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