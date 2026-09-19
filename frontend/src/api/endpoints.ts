/**
 * 全部 `/api/v1/*` 端点的类型化封装
 *
 * 路由真源：`src/daemon/http_exporter/handler.rs` 的 `build_router()`。
 * 逐个对照该函数的 `.route(...)` 列表实现，避免漏端点或写错 HTTP 方法。
 *
 * 路径参数编码：CIDR 含 `/`、IPv6 含 `:`，必须经 `encodeURIComponent` 编码，
 * 否则 `/api/v1/whitelist/10.0.0.0/8` 会被服务端解释成两段路径直接 404。
 *
 * 所有函数失败时抛 `ApiError`（见 client.ts）。
 */

import { delJson, getJson, getRawJson, sendJson } from './client'
import type {
  BanDetailResponse,
  BanOperationResponse,
  BanResponse,
  BanSortKey,
  BanDurationRecommendationResponse,
  BanEffectivenessResponse,
  BatchOperationResponse,
  CreateBanRequest,
  CreateWhitelistRequest,
  HourlyHeatmap,
  IcmpTypeDistributionResponse,
  IpFragmentStatsResponse,
  JailResponse,
  LogPageResponse,
  LogQueryParams,
  NetworkBlock,
  PaginatedResponse,
  PacketSizeDistributionResponse,
  PeriodicAttacker,
  CollaborativeAttack,
  PortScanResponse,
  RateHistoryResponse,
  RateResponse,
  RateWindowSnapshot,
  RecidivismResponse,
  ReputationEntryResponse,
  RuntimeSnapshot,
  ServiceProbeResponse,
  SseStatusResponse,
  StatsResponse,
  ThresholdRecommendationResponse,
  TtlDistributionResponse,
  UdpPortDistributionResponse,
  UpdateConfigRequest,
  UpdateJailRequest,
  AttackPredictionSummary,
  WebuiConfigResponse,
  WhitelistEntry,
  WhitelistOperationResponse,
  WhitelistRecommendation,
  BanDurationHistogramResponse,
} from './types'

// ============================================================================
// 长连接地址常量
// ============================================================================

/**
 * SSE 实时事件流地址（`GET /api/v1/events`）。
 *
 * `EventSource` **无法设置自定义请求头**，所以 Basic 凭据只能走 query：
 * 使用 `withAccessToken(SSE_EVENTS_URL)`（见 api/auth.ts）拼上 `?access_token=`
 * （服务端 `auth.rs` 的中间件兼容该参数）。
 *
 * 注意：**不要**指望浏览器自动附带 Basic Auth —— SPA 外壳是公开路由，
 * 顶层文档不返回 401，浏览器不会弹出、也不会缓存凭据。
 */
export const SSE_EVENTS_URL = '/api/v1/events'

/** SSE 实时日志流地址（`GET /api/v1/logs/stream`，tail -f 语义，命名事件 `log`）；用法同 SSE_EVENTS_URL */
export const LOG_STREAM_URL = '/api/v1/logs/stream'

// ============================================================================
// 内部工具
// ============================================================================

/** 把路径参数编码进 URL（处理 CIDR 的 `/` 与 IPv6 的 `:`） */
function encodeSegment(value: string): string {
  return encodeURIComponent(value)
}

/** 拼装查询串；跳过 undefined / null，避免 `?page=undefined` 这类脏参数 */
function withQuery(
  path: string,
  params: Record<string, string | number | undefined | null>,
): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue
    search.set(key, String(value))
  }
  const qs = search.toString()
  return qs ? `${path}?${qs}` : path
}

// ============================================================================
// 健康检查（无信封，公开端点）
// ============================================================================

/**
 * `GET /health` — 运行时就绪快照。
 * 未就绪时服务端返回 503，但响应体仍是完整结构（`status: "degraded"`），
 * 因此本函数按可用性探测使用：抛错 = 完全连不上守护进程。
 */
export function checkHealth(): Promise<RuntimeSnapshot> {
  return getRawJson<RuntimeSnapshot>('/health')
}

// ============================================================================
// 统计
// ============================================================================

/** `GET /api/v1/stats` — 仪表盘统计数据（含威胁等级） */
export function getStats(): Promise<StatsResponse> {
  return getJson<StatsResponse>('/api/v1/stats')
}

/**
 * `GET /api/v1/bans` — 活跃封禁列表。
 * 不带分页参数时后端返回全量数组（`BanResponse[]`）。
 */
export function getBans(): Promise<BanResponse[]>

/**
 * `GET /api/v1/bans?page=&page_size=&sort_by=` — 分页封禁列表。
 * 只要传了 `page` 或 `page_size`，后端就切换为分页信封结构。
 */
export function getBans(params: {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}): Promise<PaginatedResponse<BanResponse>>

export function getBans(params?: {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}): Promise<BanResponse[] | PaginatedResponse<BanResponse>> {
  if (!params) {
    return getJson<BanResponse[]>('/api/v1/bans')
  }
  return getJson<PaginatedResponse<BanResponse>>(
    withQuery('/api/v1/bans', {
      page: params.page,
      page_size: params.page_size,
      sort_by: params.sort_by,
    }),
  )
}

/** `GET /api/v1/bans/:ip/detail` — 封禁详情（决策链 + 历史 + 信誉分） */
export function getBanDetail(ip: string): Promise<BanDetailResponse> {
  return getJson<BanDetailResponse>(`/api/v1/bans/${encodeSegment(ip)}/detail`)
}

/** `POST /api/v1/bans` — 封禁单个 IP（duration 省略或 0 表示永久） */
export function createBan(req: CreateBanRequest): Promise<BanOperationResponse> {
  return sendJson<CreateBanRequest, BanOperationResponse>('/api/v1/bans', 'POST', req)
}

/** `DELETE /api/v1/bans/:ip` — 解封 IP（同时解除临时与永久封禁） */
export function deleteBan(ip: string): Promise<BanOperationResponse> {
  return delJson<BanOperationResponse>(`/api/v1/bans/${encodeSegment(ip)}`)
}

/** `POST /api/v1/bans/batch` — 批量封禁（后端上限 100 个 IP，单次封禁 3600 秒） */
export function batchBan(ips: string[]): Promise<BatchOperationResponse> {
  return sendJson<string[], BatchOperationResponse>('/api/v1/bans/batch', 'POST', ips)
}

/** `POST /api/v1/bans/unban-temporary` — 批量解封所有临时封禁（永久封禁不受影响） */
export function unbanAllTemporary(): Promise<BatchOperationResponse> {
  return sendJson<null, BatchOperationResponse>('/api/v1/bans/unban-temporary', 'POST', null)
}

// ============================================================================
// Jail
// ============================================================================

/** `GET /api/v1/jails` — Jail 列表（含运行时统计与阈值放宽信息） */
export function getJails(): Promise<JailResponse[]> {
  return getJson<JailResponse[]>('/api/v1/jails')
}

/** `PUT /api/v1/jails/:name` — 启用/禁用 Jail，返回更新后的完整条目 */
export function updateJail(name: string, enabled: boolean): Promise<JailResponse> {
  const body: UpdateJailRequest = { enabled }
  return sendJson<UpdateJailRequest, JailResponse>(
    `/api/v1/jails/${encodeSegment(name)}`,
    'PUT',
    body,
  )
}

// ============================================================================
// 配置
// ============================================================================

/** `GET /api/v1/config` — Web UI 配置（阈值、检测开关、容量） */
export function getConfig(): Promise<WebuiConfigResponse> {
  return getJson<WebuiConfigResponse>('/api/v1/config')
}

/** `PUT /api/v1/config` — 提交部分字段更新，返回更新后的完整配置 */
export function updateConfig(req: UpdateConfigRequest): Promise<WebuiConfigResponse> {
  return sendJson<UpdateConfigRequest, WebuiConfigResponse>('/api/v1/config', 'PUT', req)
}

// ============================================================================
// 白名单
// ============================================================================

/** `GET /api/v1/whitelist` — 白名单列表 */
export function getWhitelist(): Promise<WhitelistEntry[]> {
  return getJson<WhitelistEntry[]>('/api/v1/whitelist')
}

/** `POST /api/v1/whitelist` — 添加白名单（CIDR 或单 IP） */
export function createWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  const body: CreateWhitelistRequest = { cidr }
  return sendJson<CreateWhitelistRequest, WhitelistOperationResponse>(
    '/api/v1/whitelist',
    'POST',
    body,
  )
}

/** `DELETE /api/v1/whitelist/:cidr` — 移除白名单（CIDR 中的 `/` 会被编码） */
export function deleteWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  return delJson<WhitelistOperationResponse>(`/api/v1/whitelist/${encodeSegment(cidr)}`)
}

/** `GET /api/v1/whitelist/recommendations` — 智能白名单推荐（最多 10 条，按置信度降序） */
export function getWhitelistRecommendations(): Promise<WhitelistRecommendation[]> {
  return getJson<WhitelistRecommendation[]>('/api/v1/whitelist/recommendations')
}

// ============================================================================
// 速率（DDoS）
// ============================================================================

/** `GET /api/v1/rates/current` — 当前每 IP 速率（协议维度） */
export function getRatesCurrent(): Promise<RateResponse[]> {
  return getJson<RateResponse[]>('/api/v1/rates/current')
}

/** `GET /api/v1/rates/history` — 速率历史趋势（最近 1 小时，每 2 秒一条） */
export function getRatesHistory(): Promise<RateHistoryResponse[]> {
  return getJson<RateHistoryResponse[]>('/api/v1/rates/history')
}

/** `GET /api/v1/rates/windows` — 多窗口 EWMA 速率（短期 / 中期 / 长期） */
export function getRatesWindows(): Promise<RateWindowSnapshot> {
  return getJson<RateWindowSnapshot>('/api/v1/rates/windows')
}

// ============================================================================
// 统计 / 分析（stats 子路由）
// ============================================================================

/** `GET /api/v1/stats/heatmap` — 24 小时攻击热力图（bans/failed/ddos 三维度） */
export function getHeatmap(): Promise<HourlyHeatmap> {
  return getJson<HourlyHeatmap>('/api/v1/stats/heatmap')
}

/** `GET /api/v1/stats/recidivism` — 复发率统计 + TOP 10 复发 IP */
export function getRecidivism(): Promise<RecidivismResponse> {
  return getJson<RecidivismResponse>('/api/v1/stats/recidivism')
}

/** `GET /api/v1/stats/ban-effectiveness` — 按封禁级别的效果分析 */
export function getBanEffectiveness(): Promise<BanEffectivenessResponse> {
  return getJson<BanEffectivenessResponse>('/api/v1/stats/ban-effectiveness')
}

/** `GET /api/v1/stats/periodic-attackers` — 周期性攻击者（机器人特征）检测 */
export function getPeriodicAttackers(): Promise<PeriodicAttacker[]> {
  return getJson<PeriodicAttacker[]>('/api/v1/stats/periodic-attackers')
}

/** `GET /api/v1/stats/collaborative-attacks` — 协同攻击检测 */
export function getCollaborativeAttacks(): Promise<CollaborativeAttack[]> {
  return getJson<CollaborativeAttack[]>('/api/v1/stats/collaborative-attacks')
}

/** `GET /api/v1/stats/udp-ports` — UDP 端口分布 */
export function getUdpPorts(): Promise<UdpPortDistributionResponse> {
  return getJson<UdpPortDistributionResponse>('/api/v1/stats/udp-ports')
}

/** `GET /api/v1/stats/icmp-types` — ICMP 类型分布 */
export function getIcmpTypes(): Promise<IcmpTypeDistributionResponse> {
  return getJson<IcmpTypeDistributionResponse>('/api/v1/stats/icmp-types')
}

/**
 * `GET /api/v1/stats/sse-status` — SSE 连接数诊断。
 * useSse 在重连第 2 次起先调用它，判断是否已达服务端连接上限。
 */
export function getSseStatus(): Promise<SseStatusResponse> {
  return getJson<SseStatusResponse>('/api/v1/stats/sse-status')
}

/** `GET /api/v1/stats/ban-duration-histogram` — 封禁时长分布直方图 */
export function getBanDurationHistogram(): Promise<BanDurationHistogramResponse> {
  return getJson<BanDurationHistogramResponse>('/api/v1/stats/ban-duration-histogram')
}

/** `GET /api/v1/stats/packet-sizes` — 包大小分布 */
export function getPacketSizes(): Promise<PacketSizeDistributionResponse> {
  return getJson<PacketSizeDistributionResponse>('/api/v1/stats/packet-sizes')
}

/** `GET /api/v1/stats/ttl-distribution` — TTL 分布 */
export function getTtlDistribution(): Promise<TtlDistributionResponse> {
  return getJson<TtlDistributionResponse>('/api/v1/stats/ttl-distribution')
}

/** `GET /api/v1/stats/ip-fragments` — IP 分片统计 */
export function getIpFragments(): Promise<IpFragmentStatsResponse> {
  return getJson<IpFragmentStatsResponse>('/api/v1/stats/ip-fragments')
}

/** `GET /api/v1/stats/port-scanners` — 端口扫描检测结果 */
export function getPortScanners(): Promise<PortScanResponse> {
  return getJson<PortScanResponse>('/api/v1/stats/port-scanners')
}

/** `GET /api/v1/stats/service-probes` — 服务探测检测结果 */
export function getServiceProbes(): Promise<ServiceProbeResponse> {
  return getJson<ServiceProbeResponse>('/api/v1/stats/service-probes')
}

/** `GET /api/v1/stats/ban-duration-recommendations` — 封禁时长推荐 */
export function getBanDurationRecommendations(): Promise<BanDurationRecommendationResponse> {
  return getJson<BanDurationRecommendationResponse>('/api/v1/stats/ban-duration-recommendations')
}

/** `GET /api/v1/stats/reputation` — IP 信誉分列表 */
export function getReputation(): Promise<ReputationEntryResponse[]> {
  return getJson<ReputationEntryResponse[]>('/api/v1/stats/reputation')
}

/** `GET /api/v1/stats/threshold-recommendations` — Jail 阈值调优建议 */
export function getThresholdRecommendations(): Promise<ThresholdRecommendationResponse> {
  return getJson<ThresholdRecommendationResponse>('/api/v1/stats/threshold-recommendations')
}

/** `GET /api/v1/stats/network-distribution` — 攻击源网络分布（/24 或 /48 聚合） */
export function getNetworkDistribution(): Promise<NetworkBlock[]> {
  return getJson<NetworkBlock[]>('/api/v1/stats/network-distribution')
}

/** `GET /api/v1/stats/attack-predictions` — 攻击时间预测 + Jail 攻击趋势 */
export function getAttackPredictions(): Promise<AttackPredictionSummary> {
  return getJson<AttackPredictionSummary>('/api/v1/stats/attack-predictions')
}

// ============================================================================
// 日志
// ============================================================================

/**
 * `GET /api/v1/logs` — 历史日志分页查询。
 * 后端缺省 page=1、page_size=100（上限 500），最多扫描 5 万行。
 */
export function getLogs(params: LogQueryParams = {}): Promise<LogPageResponse> {
  return getJson<LogPageResponse>(
    withQuery('/api/v1/logs', {
      page: params.page,
      page_size: params.page_size,
      level: params.level,
      keyword: params.keyword,
      since: params.since,
    }),
  )
}
