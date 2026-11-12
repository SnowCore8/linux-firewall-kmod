# 多维风险引擎迁移指南

本文档说明从旧单维度信誉模型到新多维风险向量引擎的迁移。

## 概述

### 旧模型（单维度信誉）

- 每个 IP 维护一个 `score`（0-100）
- 阈值计算使用**乘法模型**：`ceil(maxRetries × peak × internal × reputation)`
- **Bug**：内网系数(2.0) × 低信誉系数(0.5) = 1.0，导致内网低信誉 IP 与外网低信誉 IP 阈值相同

### 新模型（多维风险向量）

- 每个 IP 维护 7 个维度的风险向量：failure, ban, scan, bruteforce, ddos, geo, cluster
- 每个维度独立衰减（半衰期 7 天）
- 阈值计算使用**加法模型**：`baseThreshold + peakAddend + internalAddend + reputationAdjustment`
- **修复**：内网(+3) + 低信誉(-2) = +1，内网低信誉 IP 阈值高于外网低信誉 IP

## 启用新引擎

### 配置

在 `config/default.yaml` 中添加：

```yaml
risk_engine:
  enabled: true
  half_life_days: 7.0
  weights:
    failure: 1.0
    ban: 1.0
    scan: 1.0
    bruteforce: 1.0
    ddos: 1.0
    geo: 1.0
    cluster: 1.0
```

### Feature Flag

- `risk_engine.enabled = true`（默认）：使用新多维风险引擎
- `risk_engine.enabled = false`：使用旧单维度模型

## 数据库迁移

新引擎自动创建 3 张表：

1. **schema_migrations**：版本管理
2. **attack_events**：攻击事件记录（事件溯源）
3. **ip_risk_vectors**：风险向量快照（缓存）

旧表 `ip_reputation` 保留 6 个月（双写兼容期），之后自动清理。

## API 变更

### 新增路由（v2 API）

- `GET /api/v2/risk/vectors/:ip`：查询指定 IP 的风险向量
- `GET /api/v2/risk/vectors`：查询所有 IP 的风险向量列表
- `GET /api/v2/risk/events/:ip`：查询指定 IP 的攻击事件历史

### 旧路由（v1 API，已废弃）

- `GET /api/v1/stats/reputation`：已随 v1 API 整体删除，改用 `GET /api/v2/stats/reputation`

## 代码变更

### 判定逻辑

旧代码：
```go
threshold := decision.EffectiveThreshold(maxRetries, peakHours, internal, reputationScore)
```

新代码：
```go
threshold := decision.NewEffectiveThreshold(maxRetries, peakHours, internal, reputationScore)
```

### 事件记录

旧代码：
```go
facts.RecordFailure(ip)
```

新代码（自动记录到风险引擎）：
```go
facts.RecordFailure(ip)  // 内部自动调用 riskEngine.RecordEvent
```

自定义事件：
```go
facts.RecordRiskEvent(ip, risk.EventScan, 3.0)
```

## 回滚

如需回滚到旧模型：

1. 设置 `risk_engine.enabled = false`
2. 重启守护进程
3. 旧表 `ip_reputation` 仍可用，无需数据迁移

## 性能影响

- **CPU**：每行日志处理增加 ~230ns（向量衰减计算）
- **内存**：Facts 缓存增加 ~224KB（4096 IP × 56 字节/向量）
- **磁盘**：数据库增长 ~6MB/月（假设 1000 IP/天 × 30 天 × 200 字节/事件）
- **延迟**：P99 增加 < 1ms（缓存命中时）

## 测试验证

```bash
# 单元测试
cd src/daemon && go test ./internal/risk/... -v

# 集成测试
cd src/daemon && go test ./internal/persist/... -v

# 判定逻辑测试
cd src/daemon && go test ./internal/decision/... -v -run TestNewEffectiveThreshold

# 全量测试
make test
```

## 常见问题

### Q: 新引擎与旧引擎可以同时运行吗？

A: 不可以。通过 `risk_engine.enabled` feature flag 切换，两者互斥。

### Q: 迁移后旧数据会丢失吗？

A: 不会。旧表 `ip_reputation` 保留 6 个月，新表 `ip_risk_vectors` 从空开始积累。

### Q: 如何验证 Bug 已修复？

A: 运行测试 `TestNewEffectiveThresholdFixesMultiplicativeBug`，验证内网低信誉 IP 阈值 > 外网低信誉 IP 阈值。

## 参考资料

- API 契约：`contract/http.fwidl`（搜索 "v2 API"）
- 代码实现：`src/daemon/internal/risk/`
