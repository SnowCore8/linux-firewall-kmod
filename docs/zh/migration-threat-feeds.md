# 威胁情报源系统迁移指南

本文档说明如何从旧版本迁移到支持威胁情报源系统的版本。

## 新增功能

v2.4 版本新增威胁情报源自动聚合系统，主要特性：

- **自动拉取**：每日自动从公网拉取威胁情报（IPsum、FireHOL、DShield 等）
- **智能聚合**：多源数据并发拉取、去重、聚合
- **定时刷新**：按 `refresh_interval` 自动拉取，也可调用 `POST /api/v2/threat-feeds/sync` 手动同步
- **性能隔离**：情报更新不阻塞主判定链路
- **错误容忍**：单个源失败不影响其他源

## 配置迁移

### 旧版本（v2.3 及之前）

旧版本没有 `threat_feeds` 配置段，系统仅依赖本地日志判定。

### 新版本（v2.4+）

新版本在 `config/default.yaml` 中新增 `threat_feeds` 配置段：

```yaml
threat_feeds:
  enabled: true
  refresh_interval: 86400
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

### 迁移步骤

1. **备份现有配置**

```bash
cp config/default.yaml config/default.yaml.backup
```

2. **更新配置文件**

将上述 `threat_feeds` 段添加到 `config/default.yaml` 末尾。

3. **验证配置**

```bash
cd src/daemon && go build ./cmd/firewall-daemon
./build/daemon/firewall-daemon -c config/default.yaml --help
```

4. **重启守护进程**

```bash
sudo systemctl restart firewall-daemon
```

5. **检查日志**

```bash
journalctl -u firewall-daemon | grep "threat feed"
```

应该看到类似输出：

```
INFO 情报源刷新成功 source=ipsum entries=18234 duration=245ms
INFO 情报源刷新成功 source=firehol_level1 entries=2876 duration=189ms
```

## 行为变化

### 启用情报源（默认）

- 启动时自动拉取所有启用的情报源
- 每日自动刷新（间隔可配置）
- 置信度 ≥ 0.8 的情报命中直接封禁，跳过失败窗口计数
- 置信度 < 0.8 的命中仍按常规阈值判定

### 禁用情报源

设置 `threat_feeds.enabled: false`，系统退化为纯本地日志判定，行为与旧版本完全一致。

## 兼容性

### 向后兼容

- 旧配置文件（无 `threat_feeds` 段）仍可正常加载
- 缺失 `threat_feeds` 段时使用默认值（启用 IPsum + FireHOL）
- 所有现有 API 和行为保持不变

### 向前兼容

- 新版本配置文件在旧版本守护进程上会忽略 `threat_feeds` 段
- 不会导致旧版本启动失败

## 性能影响

### 启动时间

- 首次拉取情报源：~200-500ms（取决于网络速度和源数量）
- 如果拉取失败，不阻塞启动，继续运行

### 运行时

- CPU：每 24 小时刷新一次，耗时 ~250ms（可忽略）
- 内存：~10MB（100K 条目）
- 查询延迟：< 1ms（对主判定链路影响可忽略）

### 网络

- 每 24 小时拉取 2-5 个情报源
- 每次拉取数据量：~100KB-2MB
- 总流量：~10MB/天（可忽略）

## 故障处理

### 情报源拉取失败

**现象**：日志中出现 `WARN 情报源刷新失败`

**原因**：
- 网络连接问题
- DNS 解析失败
- 情报源服务器不可用

**处理**：
1. 检查网络连接
2. 等待下次自动刷新（24 小时后）
3. 或手动触发：`curl -u admin:changeme -X POST http://127.0.0.1:9119/api/v2/threat-feeds/sync`

**影响**：不影响核心封禁功能，系统退化为纯本地判定

### 情报源域名变更

**现象**：日志中出现 `URL 校验失败: 域名不在白名单中`

**原因**：情报源更换了域名

**处理**：
1. 更新代码中的域名白名单（`src/daemon/internal/threatfeeds/http.go`）
2. 重新编译
3. 或临时禁用该情报源

### 内存占用过高

**现象**：守护进程内存占用 > 50MB

**原因**：启用了过多情报源，或情报源数据量异常增大

**处理**：
1. 减少启用的情报源数量
2. 增加刷新间隔（减少缓存条目累积）
3. 重启守护进程清理缓存

## 回滚方案

如果新版本出现问题，可以快速回滚到旧版本行为：

### 方案 1：禁用情报源（推荐）

修改 `config/default.yaml`：

```yaml
threat_feeds:
  enabled: false
```

重启守护进程：

```bash
sudo systemctl restart firewall-daemon
```

`threat_feeds.enabled` 只在启动时决定是否创建情报管理器，SIGHUP 不会停掉它。

### 方案 2：回退配置文件

```bash
cp config/default.yaml.backup config/default.yaml
sudo systemctl restart firewall-daemon
```

### 方案 3：回退二进制

```bash
sudo systemctl stop firewall-daemon
cp build/daemon/firewall-daemon.old build/daemon/firewall-daemon
sudo systemctl start firewall-daemon
```

## 升级检查清单

- [ ] 备份现有配置文件
- [ ] 更新配置文件，添加 `threat_feeds` 段
- [ ] 验证配置文件语法正确
- [ ] 重启守护进程
- [ ] 检查日志确认情报源刷新成功
- [ ] 验证核心封禁功能正常
- [ ] 监控内存和网络使用情况

## 常见问题

### Q: 情报源刷新失败会影响封禁功能吗？

A: 不会。情报源刷新失败只影响情报增强功能，核心封禁功能（基于本地日志判定）不受影响。

### Q: 可以只启用部分情报源吗？

A: 可以。在 `sources` 列表中设置 `enabled: false` 即可禁用特定源。

### Q: 情报数据会持久化吗？

A: 不会。情报数据仅保存在内存中，重启守护进程后会重新拉取。

### Q: 如何添加自定义情报源？

A: 参考 [威胁情报源配置指南](configuration/threat-feeds.md#自定义情报源)。

### Q: 情报源的置信度如何影响判定？

A: 
- 置信度 >= 0.8：直接封禁，跳过失败窗口计数
- 置信度 < 0.8：走常规阈值判定

## 技术支持

如有问题，请：

1. 查阅 [威胁情报源配置指南](configuration/threat-feeds.md)
2. 检查日志：`journalctl -u firewall-daemon | grep "threat feed"`
3. 提交 Issue：https://github.com/SnowCore8/linux-firewall-kmod/issues
