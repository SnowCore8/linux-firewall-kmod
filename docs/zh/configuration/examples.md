# 配置示例

下面四份是 `config/` 目录里真实存在的文件，整份照抄。
字段含义见 [YAML 配置](yaml-config.md)。

## 一、单个日志源：`config/nginx.yaml`

```yaml
# Nginx 防护配置
# 监控 Nginx 错误日志，防护恶意扫描和攻击

jails:
  nginx:
    enabled: true
    log_files:
      - /var/log/nginx/error.log
    # 智能推断参数：max_retries=10, findtime=300, ban_time=1800
    # 匹配 Nginx 访问禁止规则的日志
    regexes:
      access_forbidden:
        pattern: 'access forbidden by rule, client: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)'
```

这份只写日志源和正则，数值一个没写。
名字 `nginx` 命中内置服务名表的 WEB 类，推断出的就是注释里那三个数：
`max_retries` 10、`findtime` 300、`ban_time` 1800。

## 二、多个日志源加转义：`config/mysql.yaml`

```yaml
# MySQL/MariaDB 数据库防护配置
# 监控数据库错误日志，防护数据库暴力破解

jails:
  mysql:
    enabled: true
    log_files:
      - /var/log/mysql/error.log
      - /var/log/mariadb/mariadb.log
    # 智能推断参数：max_retries=3, findtime=300, ban_time=3600
    # 注意：MySQL 默认不记录认证失败，需在配置中启用 log_warnings
    regexes:
      access_denied:
        pattern: "Access denied for user.*@.*\\[([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)\\]"
```

两个要点：

- `log_files` 可以给多个路径，Debian 系和 RHEL 系各一条，同时监控。
- 方括号在正则里要转义。这份用双引号写串，所以反斜杠要写成 `\\[`。
  单引号写串时反斜杠不用翻倍，见第一份。

## 三、换个日志写法：`config/redis.yaml`

```yaml
# Redis 防护配置
# 监控 Redis 未授权访问尝试，防护 Redis 暴力破解
# 注意：Redis 默认不记录认证失败，需在配置中启用 loglevel notice

jails:
  redis:
    enabled: true
    log_files:
      - /var/log/redis/redis-server.log
    # 智能推断参数：max_retries=3, findtime=300, ban_time=3600
    # 匹配 Redis 密码错误日志
    regexes:
      invalid_password:
        pattern: 'Client ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*invalid password'
```

一处与实现不符，提出来：
`src/daemon/internal/jail/service.go` 的服务名表里没有 redis。
所以这份文件里那行注释写的推断值拿不到。
实际生效的是 `defaults` 段里的三个值，仓库的 `config/default.yaml` 给的是 3 / 600 / 900。

## 四、停用一个 jail：`config/frp.yaml`

```yaml
# FRP 内网穿透服务防护配置
# 监控 FRP 用户连接日志，防护未授权访问/频繁扫描

jails:
  frp:
    # 已停用：原正则匹配的是 frps 的 "get a user connection"（成功建立连接）
    # 日志，与"失败/未授权"无关——每次正常访问都被计为一次失败并封禁正常访客。
    # frps 日志里不存在可用的失败判据（没有带来源 IP 的拒绝/错误行），
    # 无法通过改正则修正，故停用该 jail。
    enabled: false
    # 智能推断参数：max_retries=10, findtime=300, ban_time=1800
    # 匹配 FRP 用户连接日志，提取发起连接的客户端 IP
    regexes:
      user_connection:
        pattern: ".*get a user connection \\[([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):\\d+\\]"
    log_files:
      - /var/log/frp.log
```

`enabled: false` 的 jail 仍然留在配置里，只是不监控、不校验日志源。
这份文件的注释写清了为什么停用：那个正则匹配的是成功连接，不是失败。

## 五、`defaults` 与全局段：`config/default.yaml`

这是主配置。完整文件里有真实凭据，不要照抄那两行。
结构骨架照这个文件写，值换成你自己的：

```yaml
defaults:
  max_retries: 3
  findtime: 600
  ban_time: 900
  interval: 1
  metrics_port: 9119
  metrics_bind_address: "0.0.0.0"
  metrics_username: "<你的用户名>"    # 原文件是明文凭据，别提交
  metrics_password: "<你的密码>"      # 同上
  log_file: /var/log/firewall.log
  log_level: 3

jails:
  sshd:
    enabled: true
    log_files:
      - /var/log/auth.log
      - /var/log/secure
    max_retries: 2
    findtime: 600
    ban_time: -1
    regexes:
      invalid_user:
        pattern: "Invalid user [a-zA-Z0-9_.-]{1,64} from ([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})"

webui:
  sse_push_interval: 1
  rate_warning_pps: 50000
  rate_critical_pps: 200000
  rate_warning_syn: 1000
  rate_critical_syn: 5000

ddos:
  enabled: true
  global_conn_rate: 100000
  auto_ban_duration: 3600
  auto_ban_threshold: 3
  check_interval: 5
  max_syn_per_second: 2000
  max_udp_per_second: 10000
  max_icmp_per_second: 500
  max_ack_per_second: 20000
  max_rst_per_second: 2000
  max_fin_per_second: 2000
  static_threshold: true
  dynamic_threshold: false
  ddos_detection: true
  max_bans_per_second: 200
  max_rate_entries: 65536
  protect_open_ports: true

capacity:
  max_ban_entries: 65535
  max_whitelist_entries: 65535
  max_rate_entries: 65535
  max_local_ip_cache: 65535

trusted_ips:
  # - 10.0.0.0/8
```

这份里能看到几件事：

- `ban_time: -1` 是这个 jail 的永久封禁写法。
- `sshd` 三个数值都显式写了，服务名表的推断不会动它们。
- 只填 `metrics_username` 或只填 `metrics_password` 判为配置失败，两项要一起填。
- 文件里 `trusted_ips` 那段注释说的「启动时自动加入内核白名单」是真的：组合根在注册成功
  （拿到内核的守护进程租约）之后逐条下发，裸 IP 与 CIDR 两种写法都接受，键按内核的归一化
  规则折叠。一条写错只跳过那一条并告警，不会让守护进程起不来；改这一段要重启才生效，
  热重载不重下发。临时放行仍可以直接写 `echo "<网段>" | sudo tee /proc/firewall/whitelist`。
- 这份文件里的 `metrics_bind_address` 是 `0.0.0.0`，局域网能连，所以凭据必须配。

## 六、开关覆盖：`config/_overrides.yaml`

下划线开头的文件由守护进程自己写回，加载顺序永远排最后。
它的 jail 段只带 `enabled`，用来记住界面上的开关。

节选真实内容：

```yaml
jails:
  apache:
    enabled: true
  frp:
    enabled: false
  nginx:
    enabled: true
```

因为这类文件只承载运行期状态，加载它时遇到没定义过的 jail 名会忽略并告警。
它不会凭空造出一个缺 `log_files` 的 jail。

## 七、加上集群检测

`config/` 里现在没有带 `cluster` 段的文件。
下面是按字段定义写的加法，接在任意一个 jail 下面：

```yaml
jails:
  nginx:
    enabled: true
    log_files:
      - /var/log/nginx/error.log
    cluster:
      enabled: true
      audit_only: true
      prefix_v4: 24
      prefix_v6: 48
      window: 60
      min_ips: 5
      max_per_ip: 3
      ban_time: 3600
```

字段与默认值见 [YAML 配置](yaml-config.md) 第五节。
`audit_only: true` 是默认，先只看审计，确认判得准再改成封禁。

## 八、放好之后

装到系统里时，`config/*.yaml` 会被装进 `/etc/firewall/`，目录 0700、文件 0600、属主 root。
服务用 `-C /etc/firewall` 加载整个目录，按文件名字母序合并。

```bash
# 检查语法
yamllint -c .yamllint config/*.yaml

# 让守护进程重新读
sudo systemctl reload firewall-daemon

# 确认它读到的 jail 和阈值
sudo cat /proc/firewall/config
```

界面上也能看 jail 列表与生效阈值，路径是 `/api/v1/jails`。
