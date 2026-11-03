# API v2 迁移指南

本文档说明如何从 API v1 迁移到 API v2。

> **破坏性变更**：v2 不是 v1 的兼容层。所有 `/api/v1/*` 路由已删除，
> 旧客户端必须同步更新到 `/api/v2/*` 才能继续工作。

## 变更概览

| 项目 | v1 | v2 |
|------|----|----|
| 路由前缀 | `/api/v1/*` | `/api/v2/*` |
| 健康检查 | `/health`、`/healthz`（根路径） | `/api/v2/health`、`/api/v2/healthz` |
| 威胁情报端点 | 无（404） | `/api/v2/threat-feeds/*` |
| 综合分析端点 | 无（404） | `/api/v2/analysis/*` |
| OpenAPI 文档 | 无 | `contract/generated/openapi.json` |
| 响应信封 | `ApiResponse{code, data, message}` | 不变 |
| 认证方式 | HTTP Basic | 不变 |

## 路由迁移对照

所有路由仅前缀从 `/api/v1` 变为 `/api/v2`，路径其余部分、方法、参数、响应形状均不变：

```
GET    /api/v1/bans                  → GET    /api/v2/bans
POST   /api/v1/bans                  → POST   /api/v2/bans
DELETE /api/v1/bans/:ip              → DELETE /api/v2/bans/:ip
GET    /api/v1/bans/:ip/detail       → GET    /api/v2/bans/:ip/detail
POST   /api/v1/bans/batch            → POST   /api/v2/bans/batch
POST   /api/v1/bans/unban-temporary  → POST   /api/v2/bans/unban-temporary
GET    /api/v1/config                → GET    /api/v2/config
PUT    /api/v1/config                → PUT    /api/v2/config
GET    /api/v2/events                → GET    /api/v2/events（SSE）
GET    /api/v1/jails                 → GET    /api/v2/jails
PUT    /api/v1/jails/:name           → PUT    /api/v2/jails/:name
GET    /api/v1/logs                  → GET    /api/v2/logs
GET    /api/v1/logs/stream           → GET    /api/v2/logs/stream（SSE）
GET    /api/v1/rates/current         → GET    /api/v2/rates/current
GET    /api/v1/rates/history         → GET    /api/v2/rates/history
GET    /api/v1/rates/windows         → GET    /api/v2/rates/windows
GET    /api/v1/stats                 → GET    /api/v2/stats
GET    /api/v1/stats/*               → GET    /api/v2/stats/*（全部 20 个子路由）
GET    /api/v1/whitelist             → GET    /api/v2/whitelist
POST   /api/v1/whitelist             → POST   /api/v2/whitelist
DELETE /api/v1/whitelist/:cidr       → DELETE /api/v2/whitelist/:cidr
GET    /api/v1/whitelist/recommendations → GET /api/v2/whitelist/recommendations
GET    /health                       → GET    /api/v2/health
GET    /healthz                      → GET    /api/v2/healthz
```

## 新增端点

### 威胁情报源（v2.4）

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v2/threat-feeds` | 需认证 | 情报源列表与同步状态 |
| POST | `/api/v2/threat-feeds/sync` | 需认证 | 手动触发一次同步 |
| GET | `/api/v2/threat-feeds/:id` | 需认证 | 单个情报源详情 |

### 综合分析

| 方法 | 路径 | 认证 | 说明 |
|------|------|------|------|
| GET | `/api/v2/analysis/summary` | 需认证 | 威胁等级 + Top 风险 IP + 活跃攻击摘要 |
| GET | `/api/v2/analysis/ip/:ip` | 需认证 | 单 IP 风险向量 + 封禁历史 + 信誉 + 预测 |

## 响应格式规范

所有 `/api/v2/*` 端点（健康检查除外）使用统一信封：

```json
{
  "code": 0,
  "data": { ... },
  "message": ""
}
```

- `code = 0` 表示成功，`data` 为载荷，`message` 为空串。
- `code != 0` 表示业务错误，`data` 为 `null`，`message` 含人读原因。
- HTTP 状态码与业务码的映射见下表。

健康检查（`/api/v2/health`、`/api/v2/healthz`）**不套信封**：
响应体直接是 `RuntimeSnapshot`，状态码即语义（200 就绪 / 503 未就绪）。

## 错误码说明

| 业务码 | HTTP 状态 | 含义 |
|--------|-----------|------|
| 0 | 200 | 成功 |
| 404 | 404 | Jail 不存在 |
| 40001 | 400 | 封禁失败（内核未确认、IP 非法、或内核返回错误） |
| 40002 | 400 | 解封失败（IP 非法或内核拒绝） |
| 40003 | 400 | 批量解封临时封禁失败 / 添加白名单失败 |
| 40004 | 400 | 更新配置失败 / 移除白名单失败 |
| 40005 | 400 | 批量封禁参数非法 / 日志查询参数非法 |
| 40006 | 400 | 封禁详情查询失败（IP 非法） |
| 40007 | 422 | 请求体不是合法 JSON 或字段类型不符 |
| 40008 | 415 | Content-Type 不是 application/json |
| 50002 | 500 | 服务端内部错误，message 含具体原因 |
| 50003 | 503 | 依赖未就绪（历史库 / 日志文件 / jail 控制器 / SSE 名额） |

认证失败返回 HTTP 401，响应体为纯文本 `401 Unauthorized\n`（不经信封，
且**不发** `WWW-Authenticate` 头——避免浏览器弹原生对话框挂起 fetch）。

## OpenAPI 文档使用指南

契约生成器自动产出 OpenAPI 3.0.3 规范：

```bash
# 重新生成（make contract 已包含此步骤）
python3 contract/gen.py contract/http.fwidl --targets openapi

# 产物位置
contract/generated/openapi.json

# 验证 JSON 合法性
python3 -m json.tool contract/generated/openapi.json > /dev/null
```

该文件由 `contract/http.fwidl` 单一真相源生成，**请勿手工编辑**。
改接口时先改 fwidl，再运行 `make contract` 重新生成。

可用任何 OpenAPI 3.0 工具消费：

- Swagger UI：`npx @redocly/cli preview-docs contract/generated/openapi.json`
- 代码生成：`openapi-generator-cli generate -i contract/generated/openapi.json -g typescript-fetch`
- 在线查看：将 JSON 粘贴到 https://editor.swagger.io/

## 前端迁移

前端 API 封装位于 `frontend/src/api/endpoints.ts`，所有路径取自生成的
`ROUTES` 常量（`contract/generated/http_contract.ts`），不手写字面量。

迁移步骤：

1. 将 `ROUTES.GET_API_V1_*` 全部替换为 `ROUTES.GET_API_V2_*`。
2. 健康检查从 `ROUTES.GET_HEALTH` 改为 `ROUTES.GET_API_V2_HEALTH`。
3. SSE 地址常量同步更新（`SSE_EVENTS_URL`、`LOG_STREAM_URL`）。
4. 新增端点使用 `getThreatFeeds()`、`syncThreatFeeds()`、`getThreatFeed(id)`、
   `getAnalysisSummary()`、`getAnalysisIp(ip)` 封装。

## 后端迁移

Go 侧路由注册位于 `src/daemon/internal/http/routes.go`，所有路径取自生成的
`httpcontract.Route*` 常量。

迁移步骤：

1. 路由常量从 `RouteGetApiV1*` 替换为 `RouteGetApiV2*`。
2. SSE 上限/心跳常量从 `SSEMaxConnectionsApiV1*` / `SSEKeepaliveSecondsApiV1*`
   替换为对应的 `ApiV2` 版本。
3. 新增 handler 文件：`threat_feeds.go`（3 个 handler）、`analysis.go`（2 个 handler）。
4. 测试文件中的 URL 字面量与常量同步更新。

## 验证清单

```bash
# 1. 契约生成与漂移检查
make contract && make contract-drift

# 2. 契约校验（含 OpenAPI 自检）
make contract-check

# 3. Go 单元测试
cd src/daemon && go test ./internal/http/... -v

# 4. 前端类型检查与构建
cd frontend && npx tsc --noEmit && npm run build

# 5. 部署后端到端验证
curl -u <user>:<pass> http://<host>:9119/api/v2/health
curl -u <user>:<pass> http://<host>:9119/api/v2/bans
curl -u <user>:<pass> http://<host>:9119/api/v2/threat-feeds
curl -u <user>:<pass> http://<host>:9119/api/v2/analysis/summary

# 6. OpenAPI 文档验证
python3 -m json.tool contract/generated/openapi.json > /dev/null
```
