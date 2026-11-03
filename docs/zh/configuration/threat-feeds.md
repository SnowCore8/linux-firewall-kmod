# 威胁情报源配置指南

本文档说明如何配置和使用防火墙的威胁情报源自动聚合系统。

## 概述

威胁情报源系统自动从公网拉取恶意 IP  IP，经过解析、聚合后缓存到内存中。当本地日志判定发现新 IP 时，会先查询情报缓存，高置信度的恶意 IP 可直接封禁，跳过窗口计数。

**核心特性**：

- **自动更新**：每日自动拉取最新情报（可配置间隔）
- **热重载**：SIGHUP 触发配置重载时同步刷新情报
- **并发拉取**：多个源并行刷新，总耗时取最慢源
- **错误隔离**：单个源失败不影响其他源
- **性能隔离**：情报更新在后台 goroutine，不阻塞主判定链路

## 配置示例

```yaml
threat_feeds:
  enabled: true
  refresh_interval: 86400  # 24 小时
  http_timeout: 30
  max_retries: 3
  sources:
    - name: ipsum
      url: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
      enabled: true
      category: abuse
      confidence: 0.8
    - name: firehol_level1
      url: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
      enabled: true
      category: abuse
      confidence: 0.85
```

## 配置参数

### 全局参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 总开关，`false` 时整个情报系统不启动 |
| `refresh_interval` | uint32 | `86400` | 自动刷新间隔（秒），默认 24 小时 |
| `http_timeout` | uint32 | `30` | 单次拉取的 HTTP 超时（秒） |
| `max_retries` | int | `3` | 拉取失败后的重试次数 |

### 情报源参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `name` | string | 是 | 源的唯一标识（如 `ipsum`, `firehol`） |
| `url` | string | 是 | 拉取地址（必须是 HTTPS） |
| `enabled` | bool | 否 | 该源是否启用，默认 `false` |
| `category` | string | 否 | 默认分类（如 `abuse`, `scanner`, `botnet`） |
| `confidence` | float64 | 否 | 默认置信度，范围 [0.0, 1.0] |

## 推荐情报源

### 默认启用

#### IPsum

多源聚合的恶意 IP 名单，质量高，每日更新。

```yaml
- name: ipsum
  url: https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt
  enabled: true
  category: abuse
  confidence: 0.8
```

- **格式**：纯 IP 列表，`#` 开头为注释
- **条目数**：~20K
- **更新频率**：每日
- **特点**：聚合多个黑名单源，质量高

#### FireHOL Level 1

FireHOL 维护的保守名单，误报最低。

```yaml
- name: firehol_level1
  url: https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
  enabled: true
  category: abuse
  confidence: 0.85
```

- **格式**：IP/CIDR 列表，`#` 开头为注释
- **条目数**：~3K
- **更新频率**：每日
- **特点**：保守名单，误报低

### 可选启用

#### DShield

老牌扫描者 IP 名单，稳定性好。

```yaml
- name: dshield
  url: https://www.dshield.org/block.txt
  enabled: false
  category: scanner
  confidence: 0.7
```

- **格式**：TSV（Tab 分隔），列：`start_ip\tend_ip\tcount\tname`
- **条目数**：~1K
- **更新频率**：每日
- **特点**：专注扫描者 IP

#### Blocklist.de

按攻击类型分类的黑名单。

```yaml
- name: blocklist_de
  url: https://lists.blocklist.de/lists/all.txt
  enabled: false
  category: abuse
  confidence: 0.75
```

- **格式**：纯 IP 列表
- **条目数**：~10K
- **更新频率**：每小时
- **特点**：覆盖面广，更新频繁

#### Feodo Tracker

专注 botnet C2 服务器追踪。

```yaml
- name: feodo
  url: https://feodotracker.abuse.ch/downloads/ipblocklist.csv
  enabled: false
  category: botnet
  confidence: 0.9
```

- **格式**：CSV，第一列是 IP 地址
- **条目数**：~500
- **更新频率**：每日
- **特点**：专注 botnet C2（Emotet、Dridex 等）

## 自定义情报源

你可以添加自己的情报源，只需实现 `FeedSource` 接口：

```go
type FeedSource interface {
    Name() string
    URL() string
    Parse(data []byte) ([]FeedEntry, error)
}
```

**配置示例**：

```yaml
threat_feeds:
  enabled: true
  sources:
    - name: custom_feed
      url: https://example.com/custom-feed.txt
      enabled: true
      category: custom
      confidence: 0.6
```

**注意**：

- URL 必须是 HTTPS（安全限制）
- 域名必须在白名单中（防止 SSRF）
- 当前支持的格式：纯 IP 列表、CIDR 列表、TSV、CSV

## 热重载

情报系统支持 SIGHUP 热重载：

```bash
sudo kill -HUP $(pidof firewall-daemon)
```

重载时会自动刷新所有启用的情报源，无需重启守护进程。

## 性能影响

- **CPU**：并发拉取 5 个源 ~200ms（网络 IO 为主），解析 ~50ms（纯 CPU）
- **内存**：~10MB（100K 条目 × 100 字节/条目）
- **查询延迟**：精确匹配 < 100ns，CIDR 匹配 < 1ms（遍历 100K 条目）
- **磁盘 IO**：无持久化（纯内存缓存，重启后重新拉取）

## 故障排查

### 情报源拉取失败

检查日志：

```bash
journalctl -u firewall-daemon | grep "threat feed"
```

常见原因：

- 网络连接问题
- DNS 解析失败
- HTTPS 证书验证失败
- 域名不在白名单中

### 情报未生效

1. 检查配置是否启用：

```yaml
threat_feeds:
  enabled: true
```

2. 检查具体源是否启用：

```yaml
sources:
  - name: ipsum
    enabled: true  # 确保为 true
```

3. 手动触发刷新：

```bash
sudo kill -HUP $(pidof firewall-daemon)
```

### 查询性能问题

如果 CIDR 匹配延迟过高（> 1ms），考虑：

- 减少启用的情报源数量
- 优化情报源的数据格式（优先使用精确 IP 而非 CIDR）
- 增加刷新间隔（减少缓存条目数）

## 安全考虑

### SSRF 防护

情报系统实施了严格的 SSRF 防护：

- **HTTPS 强制**：只允许 HTTPS 协议
- **域名白名单**：只允许访问已知的情报源域名
- **重定向限制**：最多跟随 3 次重定向，每次重定向都校验目标域名

### 数据隔离

- 情报缓存纯内存，不持久化到磁盘
- 每个源的数据独立解析，失败不影响其他源
- 过期数据自动清理（默认 24 小时过期）

## 回滚计划

如果情报系统出现问题，可以通过配置快速禁用：

```yaml
threat_feeds:
  enabled: false
```

然后重载配置：

```bash
sudo kill -HUP $(pidof firewall-daemon)
```

禁用后系统退化为纯本地日志判定，不影响核心封禁功能。

## 参考资料

- [IPsum 项目](https://github.com/stamparm/ipsum)
- [FireHOL 黑名单](https://github.com/firehol/blocklist-ipsets)
- [DShield 黑名单](https://www.dshield.org/block.txt)
- [Blocklist.de](https://www.blocklist.de/)
- [Feodo Tracker](https://feodotracker.abuse.ch/)
