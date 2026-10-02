/**
 * 全部 `/api/v1/*` 端点的类型化封装。
 *
 * 路径一律取自 `contract/generated/http_contract.ts` 的 `ROUTES`，不再手写字面量：
 * 契约由 `contract/http.fwidl` 生成，改接口时先改 fwidl 再重新生成。
 *
 * 路径参数编码：CIDR 含 `/`、IPv6 含 `:`，必须经 `encodeURIComponent` 编码，
 * 否则 `/api/v1/whitelist/10.0.0.0/8` 会被服务端解释成两段路径直接 404。
 *
 * 所有函数失败时抛 `ApiError`（见 client.ts）。
 */

import { ROUTES } from './contract'
import type {
  AnomalyResponse,
  AttackGeoResponse,
  AttackPredictionSummary,
  BanDetailResponse,
  BanDurationHistogramResponse,
  BanDurationRecommendationResponse,
  BanEffectivenessResponse,
  BanOperationResponse,
  BanResponse,
  BatchOperationResponse,
  CollaborativeAttack,
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
  WebuiConfigResponse,
  WhitelistEntry,
  WhitelistOperationResponse,
  WhitelistRecommendation,
} from './contract'
import type { BanSortKey } from './params'
import { delJson, getJson, getRawJson, sendJson } from './client'

// ============================================================================
// 长连接地址
// ============================================================================

/**
 * SSE 实时事件流地址（`GET /api/v1/events`）。
 *
 * `EventSource` **无法设置自定义请求头**，所以 Basic 凭据只能走 query：
 * 使用 `withAccessToken(SSE_EVENTS_URL)`（见 api/auth.ts）拼上 `?access_token=`
 * （服务端中间件兼容该参数）。
 */
export const SSE_EVENTS_URL = ROUTES.GET_API_V1_EVENTS

/** SSE 实时日志流地址（`GET /api/v1/logs/stream`，tail -f 语义，命名事件 `log`） */
export const LOG_STREAM_URL = ROUTES.GET_API_V1_LOGS_STREAM

// ============================================================================
// 内部工具
// ============================================================================

/** 把路径参数编码后填入路由模板的末尾占位段（`:ip` / `:cidr` / `:name`） */
function fill(route: string, value: string): string {
  return route.replace(/:[^/]+$/, encodeURIComponent(value))
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
  return getRawJson<RuntimeSnapshot>(ROUTES.GET_HEALTH)
}

// ============================================================================
// 统计
// ============================================================================

/** `GET /api/v1/stats` — 仪表盘统计数据（含威胁等级） */
export function getStats(): Promise<StatsResponse> {
  return getJson<StatsResponse>(ROUTES.GET_API_V1_STATS)
}

/**
 * `GET /api/v1/bans` — 活跃封禁列表，一律返回分页信封。
 * 不传参数时按契约默认分页（page=1 / page_size=20）；
 * `page_size` 服务端上限为 100（`views::MAX_PAGE_SIZE`）。
 */
export function getBans(params?: {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}): Promise<PaginatedResponse<BanResponse>> {
  return getJson<PaginatedResponse<BanResponse>>(
    withQuery(ROUTES.GET_API_V1_BANS, {
      page: params?.page,
      page_size: params?.page_size,
      sort_by: params?.sort_by,
    }),
  )
}

/** `GET /api/v1/bans/:ip/detail` — 封禁详情（决策链 + 历史 + 信誉分） */
export function getBanDetail(ip: string): Promise<BanDetailResponse> {
  return getJson<BanDetailResponse>(fill(ROUTES.GET_API_V1_BANS_IP_DETAIL, ip))
}

/** `POST /api/v1/bans` — 封禁单个 IP（duration 省略或 0 表示永久） */
export function createBan(req: CreateBanRequest): Promise<BanOperationResponse> {
  return sendJson<CreateBanRequest, BanOperationResponse>(ROUTES.POST_API_V1_BANS, 'POST', req)
}

/** `DELETE /api/v1/bans/:ip` — 解封 IP（同时解除临时与永久封禁） */
export function deleteBan(ip: string): Promise<BanOperationResponse> {
  return delJson<BanOperationResponse>(fill(ROUTES.DELETE_API_V1_BANS_IP, ip))
}

/** `POST /api/v1/bans/batch` — 批量封禁（后端上限 100 个 IP，单次封禁 3600 秒） */
export function batchBan(ips: string[]): Promise<BatchOperationResponse> {
  return sendJson<string[], BatchOperationResponse>(ROUTES.POST_API_V1_BANS_BATCH, 'POST', ips)
}

/** `POST /api/v1/bans/unban-temporary` — 批量解封所有临时封禁（永久封禁不受影响） */
export function unbanAllTemporary(): Promise<BatchOperationResponse> {
  return sendJson<null, BatchOperationResponse>(
    ROUTES.POST_API_V1_BANS_UNBAN_TEMPORARY,
    'POST',
    null,
  )
}

// ============================================================================
// Jail
// ============================================================================

/** `GET /api/v1/jails` — Jail 列表（含运行时统计与阈值放宽信息） */
export function getJails(): Promise<JailResponse[]> {
  return getJson<JailResponse[]>(ROUTES.GET_API_V1_JAILS)
}

/** `PUT /api/v1/jails/:name` — 启用/禁用 Jail，返回更新后的完整条目 */
export function updateJail(name: string, enabled: boolean): Promise<JailResponse> {
  const body: UpdateJailRequest = { enabled }
  return sendJson<UpdateJailRequest, JailResponse>(
    fill(ROUTES.PUT_API_V1_JAILS_NAME, name),
    'PUT',
    body,
  )
}

// ============================================================================
// 配置
// ============================================================================

/** `GET /api/v1/config` — Web UI 配置（阈值、检测开关、容量） */
export function getConfig(): Promise<WebuiConfigResponse> {
  return getJson<WebuiConfigResponse>(ROUTES.GET_API_V1_CONFIG)
}

/** `PUT /api/v1/config` — 提交部分字段更新，返回更新后的完整配置 */
export function updateConfig(req: UpdateConfigRequest): Promise<WebuiConfigResponse> {
  return sendJson<UpdateConfigRequest, WebuiConfigResponse>(ROUTES.PUT_API_V1_CONFIG, 'PUT', req)
}

// ============================================================================
// 白名单
// ============================================================================

/** `GET /api/v1/whitelist` — 白名单列表 */
export function getWhitelist(): Promise<WhitelistEntry[]> {
  return getJson<WhitelistEntry[]>(ROUTES.GET_API_V1_WHITELIST)
}

/** `POST /api/v1/whitelist` — 添加白名单（CIDR 或单 IP） */
export function createWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  const body: CreateWhitelistRequest = { cidr }
  return sendJson<CreateWhitelistRequest, WhitelistOperationResponse>(
    ROUTES.POST_API_V1_WHITELIST,
    'POST',
    body,
  )
}

/** `DELETE /api/v1/whitelist/:cidr` — 移除白名单（CIDR 中的 `/` 会被编码） */
export function deleteWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  return delJson<WhitelistOperationResponse>(fill(ROUTES.DELETE_API_V1_WHITELIST_CIDR, cidr))
}

/** `GET /api/v1/whitelist/recommendations` — 智能白名单推荐（最多 10 条，按置信度降序） */
export function getWhitelistRecommendations(): Promise<WhitelistRecommendation[]> {
  return getJson<WhitelistRecommendation[]>(ROUTES.GET_API_V1_WHITELIST_RECOMMENDATIONS)
}

// ============================================================================
// 速率（DDoS）
// ============================================================================

/** `GET /api/v1/rates/current` — 当前每 IP 速率（协议维度） */
export function getRatesCurrent(): Promise<RateResponse[]> {
  return getJson<RateResponse[]>(ROUTES.GET_API_V1_RATES_CURRENT)
}

/** `GET /api/v1/rates/history` — 速率历史趋势（最近 1 小时，每 2 秒一条） */
export function getRatesHistory(): Promise<RateHistoryResponse[]> {
  return getJson<RateHistoryResponse[]>(ROUTES.GET_API_V1_RATES_HISTORY)
}

/** `GET /api/v1/rates/windows` — 多窗口 EWMA 速率（短期 / 中期 / 长期） */
export function getRatesWindows(): Promise<RateWindowSnapshot> {
  return getJson<RateWindowSnapshot>(ROUTES.GET_API_V1_RATES_WINDOWS)
}

// ============================================================================
// 统计子路由（历史快照 / 包分析 / 趋势预测）
// ============================================================================

/** `GET /api/v1/stats/heatmap` — 24 小时封禁 / 失败 / DDoS 热力图 */
export function getHeatmap(): Promise<HourlyHeatmap> {
  return getJson<HourlyHeatmap>(ROUTES.GET_API_V1_STATS_HEATMAP)
}

/** `GET /api/v1/stats/recidivism` — 复发统计（被封禁过的 IP 再次攻击的比例） */
export function getRecidivism(): Promise<RecidivismResponse> {
  return getJson<RecidivismResponse>(ROUTES.GET_API_V1_STATS_RECIDIVISM)
}

/** `GET /api/v1/stats/ban-effectiveness` — 渐进式封禁各等级的成效对比 */
export function getBanEffectiveness(): Promise<BanEffectivenessResponse> {
  return getJson<BanEffectivenessResponse>(ROUTES.GET_API_V1_STATS_BAN_EFFECTIVENESS)
}

/** `GET /api/v1/stats/periodic-attackers` — 周期性攻击者（等间隔复现的扫描源） */
export function getPeriodicAttackers(): Promise<PeriodicAttacker[]> {
  return getJson<PeriodicAttacker[]>(ROUTES.GET_API_V1_STATS_PERIODIC_ATTACKERS)
}

/** `GET /api/v1/stats/collaborative-attacks` — 协同攻击（同一时间窗内的多源联动） */
export function getCollaborativeAttacks(): Promise<CollaborativeAttack[]> {
  return getJson<CollaborativeAttack[]>(ROUTES.GET_API_V1_STATS_COLLABORATIVE_ATTACKS)
}

/** `GET /api/v1/stats/udp-ports` — UDP 端口分布 */
export function getUdpPorts(): Promise<UdpPortDistributionResponse> {
  return getJson<UdpPortDistributionResponse>(ROUTES.GET_API_V1_STATS_UDP_PORTS)
}

/** `GET /api/v1/stats/icmp-types` — ICMP 类型 / 代码分布 */
export function getIcmpTypes(): Promise<IcmpTypeDistributionResponse> {
  return getJson<IcmpTypeDistributionResponse>(ROUTES.GET_API_V1_STATS_ICMP_TYPES)
}

/** `GET /api/v1/stats/sse-status` — 两条 SSE 流各自的当前连接数与上限 */
export function getSseStatus(): Promise<SseStatusResponse> {
  return getJson<SseStatusResponse>(ROUTES.GET_API_V1_STATS_SSE_STATUS)
}

/** `GET /api/v1/stats/ban-duration-histogram` — 已封禁时长的分布直方图 */
export function getBanDurationHistogram(): Promise<BanDurationHistogramResponse> {
  return getJson<BanDurationHistogramResponse>(ROUTES.GET_API_V1_STATS_BAN_DURATION_HISTOGRAM)
}

/** `GET /api/v1/stats/packet-sizes` — 包大小分布 */
export function getPacketSizes(): Promise<PacketSizeDistributionResponse> {
  return getJson<PacketSizeDistributionResponse>(ROUTES.GET_API_V1_STATS_PACKET_SIZES)
}

/** `GET /api/v1/stats/ttl-distribution` — TTL 分布（可旁路推断攻击者操作系统） */
export function getTtlDistribution(): Promise<TtlDistributionResponse> {
  return getJson<TtlDistributionResponse>(ROUTES.GET_API_V1_STATS_TTL_DISTRIBUTION)
}

/** `GET /api/v1/stats/ip-fragments` — IP 分片流量占比 */
export function getIpFragments(): Promise<IpFragmentStatsResponse> {
  return getJson<IpFragmentStatsResponse>(ROUTES.GET_API_V1_STATS_IP_FRAGMENTS)
}

/** `GET /api/v1/stats/port-scanners` — 端口扫描检测结果 */
export function getPortScanners(): Promise<PortScanResponse> {
  return getJson<PortScanResponse>(ROUTES.GET_API_V1_STATS_PORT_SCANNERS)
}

/** `GET /api/v1/stats/service-probes` — 服务探测检测结果 */
export function getServiceProbes(): Promise<ServiceProbeResponse> {
  return getJson<ServiceProbeResponse>(ROUTES.GET_API_V1_STATS_SERVICE_PROBES)
}

/** `GET /api/v1/stats/ban-duration-recommendations` — 按 jail 的封禁时长建议 */
export function getBanDurationRecommendations(): Promise<BanDurationRecommendationResponse> {
  return getJson<BanDurationRecommendationResponse>(
    ROUTES.GET_API_V1_STATS_BAN_DURATION_RECOMMENDATIONS,
  )
}

/** `GET /api/v1/stats/reputation` — IP 信誉分列表（分数越低，阈值倍率越严） */
export function getReputation(): Promise<ReputationEntryResponse[]> {
  return getJson<ReputationEntryResponse[]>(ROUTES.GET_API_V1_STATS_REPUTATION)
}

/** `GET /api/v1/stats/threshold-recommendations` — jail 阈值调优建议 */
export function getThresholdRecommendations(): Promise<ThresholdRecommendationResponse> {
  return getJson<ThresholdRecommendationResponse>(
    ROUTES.GET_API_V1_STATS_THRESHOLD_RECOMMENDATIONS,
  )
}

/** `GET /api/v1/stats/network-distribution` — 攻击源网段分布 */
export function getNetworkDistribution(): Promise<NetworkBlock[]> {
  return getJson<NetworkBlock[]>(ROUTES.GET_API_V1_STATS_NETWORK_DISTRIBUTION)
}

/** `GET /api/v1/stats/attack-predictions` — 下次攻击时间预测 + 各 jail 攻击趋势 */
export function getAttackPredictions(): Promise<AttackPredictionSummary> {
  return getJson<AttackPredictionSummary>(ROUTES.GET_API_V1_STATS_ATTACK_PREDICTIONS)
}

/** `GET /api/v1/stats/anomalies` — 全局流量偏离 + per-IP 行为离群（只观测，不触发封禁） */
export function getAnomalies(): Promise<AnomalyResponse> {
  return getJson<AnomalyResponse>(ROUTES.GET_API_V1_STATS_ANOMALIES)
}

/** `GET /api/v1/stats/attack-geo` — 攻击源地理分布；未启用 GeoIP 时 `geoip_enabled=false` */
export function getAttackGeo(): Promise<AttackGeoResponse> {
  return getJson<AttackGeoResponse>(ROUTES.GET_API_V1_STATS_ATTACK_GEO)
}

// ============================================================================
// 日志
// ============================================================================

/**
 * `GET /api/v1/logs` — 分页日志查询。
 *
 * 契约里的 `LogQueryParams` 字段全部是**必填可空**（`page: number | null`），
 * 不是可选字段，所以默认值用 `{} as LogQueryParams`，让调用方只传关心的项；
 * `withQuery` 会跳过 `null` / `undefined`，未填项不会出现在查询串里。
 */
export function getLogs(params: LogQueryParams = {} as LogQueryParams): Promise<LogPageResponse> {
  return getJson<LogPageResponse>(
    withQuery(ROUTES.GET_API_V1_LOGS, {
      page: params.page,
      page_size: params.page_size,
      level: params.level,
      keyword: params.keyword,
      since: params.since,
    }),
  )
}
