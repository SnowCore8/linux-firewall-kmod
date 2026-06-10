# 快速上手

本指南将在 5 分钟内帮助你配置并运行第一个 jail 规则。

## 前提条件

确保已完成 [安装](installation.md) 并验证模块正常工作。

## 第一步：配置文件

编辑主配置文件 `/etc/firewall/default.yaml`：

```bash
sudo vim /etc/firewall/default.yaml
```

### 基本配置

```yaml
# 全局设置
global:
  log_level: info
  log_file: /var/log/firewall.log
  db_path: /var/lib/firewall/bans.db

# SSH 防护 Jail
jails:
  - name: sshd
    enabled: true
    log_path: /var/log/auth.log
    filter:
      regex: 'Failed password for .* from <HOST>'
    action:
      ban_time: 3600        # 封禁 1 小时
      find_time: 600        # 10 分钟内
      max_retries: 5        # 5 次失败后封禁
    port: 22
    protocol: tcp
```

### 配置说明

| 参数 | 说明 | 示例值 |
|------|------|--------|
| `name` | Jail 名称 | `sshd` |
| `enabled` | 是否启用 | `true` |
| `log_path` | 监控的日志文件 | `/var/log/auth.log` |
| `regex` | 匹配失败登录的正则 | `Failed password for .* from <HOST>` |
| `ban_time` | 封禁时长（秒） | `3600` |
| `find_time` | 统计窗口（秒） | `600` |
| `max_retries` | 最大重试次数 | `5` |
| `port` | 监控的端口 | `22` |
| `protocol` | 协议类型 | `tcp` |

## 第二步：添加白名单

将你的管理 IP 加入白名单，防止被误封：

```yaml
# 在配置文件中添加
whitelist:
  - 192.168.1.0/24
  - 10.0.0.1
```

> **注意**：白名单最多支持 64 个条目。

## 第三步：启动服务

```bash
# 重新加载配置并启动
sudo systemctl restart firewall

# 检查状态
sudo systemctl status firewall
```

## 第四步：验证封禁

### 方法一：查看 ProcFS

```bash
cat /proc/firewall/bans
```

### 方法二：使用 firewall-daemon

```bash
# 查看封禁列表
cat /proc/firewall/bans

# 查看统计信息
cat /proc/firewall/stats
```

### 方法三：手动测试

```bash
# 手动封禁一个测试 IP
echo "192.168.1.100 3600" | sudo tee /proc/firewall/bans

# 确认已封禁
cat /proc/firewall/bans

# 解除封禁
echo "unban 192.168.1.100" | sudo tee /proc/firewall/bans
```

## 第五步：监控

### 查看 Prometheus 指标

```bash
curl http://localhost:9119/metrics
```

关键指标：

```
# TYPE firewall_kernel_banned_ips_current gauge
firewall_kernel_banned_ips_current 5

# TYPE firewall_ban_events_total counter
firewall_ban_events_total 12

# TYPE firewall_unban_events_total counter
firewall_unban_events_total 7
```

### 查看日志

```bash
sudo tail -f /var/log/firewall.log
```

## 配置更多 Jail

### Nginx 暴力破解防护

```yaml
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

### Postfix 防护

```yaml
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

## 下一步

- 阅读 [YAML 配置详解](../configuration/yaml-config.md) 了解所有配置选项
- 查看 [配置示例](../configuration/examples.md) 获取更多模板
- 了解 [架构设计](../architecture/) 深入理解工作原理