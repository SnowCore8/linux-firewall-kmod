/**
 * 端点封装 —— 每条契约路由一个具名函数，全站唯一的「路径消费点」。
 *
 * 纪律（由 `verify_http.py` 的 `check_routes_frontend` 机械强制）：
 *   * 契约里每条 `/api/v*` 路由都必须在这里经 `ROUTES.<常量>` 被消费一次，缺一条即判红；
 *   * 这里不得手写 `/api/v…` 字面量，路径一律取自 contract.ts 再导出的 ROUTES 表；
 *   * 引用了 ROUTES 表里不存在的常量同样判红（等于在等一个契约里没有的路径）。
 * 于是「前端调了哪些后端接口」永远是契约的一个子集，且随契约改名自动跟进。
 *
 * 两条 SSE 的 URL 也在这里构造（`eventsStreamUrl` / `logsStreamUrl`）：一来它们同样是
 * 契约路由（GET /api/v2/events、GET /api/v2/logs/stream），必须在本文件被 ROUTES 消费；
 * 二来 EventSource 不能设请求头，凭据走 `?access_token=`，拼接集中一处避免各视图各拼一遍。
 *
 * 路径参数（`:ip` / `:cidr` / `:name` / `:id`）由 `withParams` 逐个 `encodeURIComponent`：
 * CIDR 里的 `/` 必须转义成 `%2F` 才能落在单个路径段上（守护进程 `r.PathValue` 会解回来，
 * 其契约测试正是用 `10.0.0.0%2F8` 这种写法）。
 */

import { apiFetch, apiFetchRaw } from './client'
import { ROUTES } from './contract'
import { getAccessToken, TOKEN_QUERY_KEY } from './auth'
import type {
  AnalysisIpResponse,
  AnalysisSummaryResponse,
  AnomalyResponse,
  AttackGeoResponse,
  AttackPredictionSummary,
  BanDetailResponse,
  BanDurationHistogramResponse,
  BanDurationRecommendationResponse,
  BanEffectivenessResponse,
  BanOperationResponse,
  BanResponse,
  BatchBanRequest,
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
  PacketSizeDistributionResponse,
  PaginatedResponse,
  PeriodicAttacker,
  PortScanResponse,
  RateHistoryResponse,
  RateResponse,
  RateWindowSnapshot,
  RecidivismResponse,
  ReputationEntryResponse,
  RiskEventResponse,
  RiskVectorListResponse,
  RiskVectorResponse,
  RuntimeSnapshot,
  ServiceProbeResponse,
  SseStatusResponse,
  StatsResponse,
  ThreatFeedListResponse,
  ThreatFeedResponse,
  ThreatFeedSyncResult,
  ThresholdRecommendationResponse,
  TtlDistributionResponse,
  UdpPortDistributionResponse,
  UpdateConfigRequest,
  UpdateJailRequest,
  WebuiConfigResponse,
  WhitelistEntry,
  WhitelistOperationResponse,
  WhitelistRecommendation,
} from './types'
import type { BanSortKey } from './types'

// ---------------------------------------------------------------------------
// 路径参数替换
// ---------------------------------------------------------------------------

/** 把契约路径里的 `:key` 逐个换成编码后的实参；缺参数直接抛（编程错误，不该静默）。 */
function withParams(path: string, params: Record<string, string | number>): string {
  return path.replace(/:(\w+)/g, (_match, key: string) => {
    const value = params[key]
    if (value === undefined) {
      throw new Error(`路径 ${path} 缺少参数 ${key}`)
    }
    return encodeURIComponent(String(value))
  })
}

/** PUT /api/v2/jails/:name 的内联成功载荷（非契约具名类型，就地声明）。 */
export interface JailUpdateResult {
  name: string
  enabled: boolean
  status: string
}

// ---------------------------------------------------------------------------
// 健康 / 运行时状态（不经信封）
// ---------------------------------------------------------------------------

/** GET /api/v2/health：裸 RuntimeSnapshot，200=就绪 / 503=未就绪。 */
export function getHealth(signal?: AbortSignal): Promise<RuntimeSnapshot> {
  return apiFetchRaw<RuntimeSnapshot>(ROUTES.GET_API_V2_HEALTH, { signal })
}

/** GET /api/v2/healthz：与 /health 同函数，供探针使用。 */
export function getHealthz(signal?: AbortSignal): Promise<RuntimeSnapshot> {
  return apiFetchRaw<RuntimeSnapshot>(ROUTES.GET_API_V2_HEALTHZ, { signal })
}

// ---------------------------------------------------------------------------
// 统计总览
// ---------------------------------------------------------------------------

/** GET /api/v2/stats：首屏总览。 */
export function getStats(signal?: AbortSignal): Promise<StatsResponse> {
  return apiFetch<StatsResponse>(ROUTES.GET_API_V2_STATS, { signal })
}

// ---------------------------------------------------------------------------
// 封禁管理
// ---------------------------------------------------------------------------

export interface BanListParams {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}

/** GET /api/v2/bans：单一形状，恒为分页信封（不得有裸数组分支）。 */
export function getBans(
  params: BanListParams = {},
  signal?: AbortSignal,
): Promise<PaginatedResponse<BanResponse>> {
  return apiFetch<PaginatedResponse<BanResponse>>(ROUTES.GET_API_V2_BANS, {
    query: { page: params.page, page_size: params.page_size, sort_by: params.sort_by },
    signal,
  })
}

/** POST /api/v2/bans：手工封禁；duration 缺席/0=永久，正数=时长（秒）。 */
export function createBan(req: CreateBanRequest, signal?: AbortSignal): Promise<BanOperationResponse> {
  return apiFetch<BanOperationResponse>(ROUTES.POST_API_V2_BANS, {
    method: 'POST',
    body: req,
    signal,
  })
}

/** DELETE /api/v2/bans/:ip：解封单个 IP。 */
export function deleteBan(ip: string, signal?: AbortSignal): Promise<BanOperationResponse> {
  return apiFetch<BanOperationResponse>(withParams(ROUTES.DELETE_API_V2_BANS_IP, { ip }), {
    method: 'DELETE',
    signal,
  })
}

/** GET /api/v2/bans/:ip/detail：单个封禁的完整画像。 */
export function getBanDetail(ip: string, signal?: AbortSignal): Promise<BanDetailResponse> {
  return apiFetch<BanDetailResponse>(withParams(ROUTES.GET_API_V2_BANS_IP_DETAIL, { ip }), { signal })
}

/** POST /api/v2/bans/unban-temporary：解除全部临时封禁（不动永久封禁）。 */
export function unbanTemporary(signal?: AbortSignal): Promise<BatchOperationResponse> {
  return apiFetch<BatchOperationResponse>(ROUTES.POST_API_V2_BANS_UNBAN_TEMPORARY, {
    method: 'POST',
    signal,
  })
}

/** POST /api/v2/bans/batch：批量封禁（1..100 条；duration 缺省 3600 秒，不升格为永久）。 */
export function batchBan(req: BatchBanRequest, signal?: AbortSignal): Promise<BatchOperationResponse> {
  return apiFetch<BatchOperationResponse>(ROUTES.POST_API_V2_BANS_BATCH, {
    method: 'POST',
    body: req,
    signal,
  })
}

// ---------------------------------------------------------------------------
// Jail
// ---------------------------------------------------------------------------

/** GET /api/v2/jails：jail 配置 + 运行时计数（按配置顺序）。 */
export function getJails(signal?: AbortSignal): Promise<JailResponse[]> {
  return apiFetch<JailResponse[]>(ROUTES.GET_API_V2_JAILS, { signal })
}

/** PUT /api/v2/jails/:name：改启用状态（异步生效，不推 SSE 帧）。 */
export function updateJail(
  name: string,
  req: UpdateJailRequest,
  signal?: AbortSignal,
): Promise<JailUpdateResult> {
  return apiFetch<JailUpdateResult>(withParams(ROUTES.PUT_API_V2_JAILS_NAME, { name }), {
    method: 'PUT',
    body: req,
    signal,
  })
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/** GET /api/v2/config：Web UI 相关配置快照。 */
export function getConfig(signal?: AbortSignal): Promise<WebuiConfigResponse> {
  return apiFetch<WebuiConfigResponse>(ROUTES.GET_API_V2_CONFIG, { signal })
}

/** PUT /api/v2/config：提交要改的字段；返回更新后的完整快照。 */
export function updateConfig(
  req: UpdateConfigRequest,
  signal?: AbortSignal,
): Promise<WebuiConfigResponse> {
  return apiFetch<WebuiConfigResponse>(ROUTES.PUT_API_V2_CONFIG, {
    method: 'PUT',
    body: req,
    signal,
  })
}

// ---------------------------------------------------------------------------
// 白名单
// ---------------------------------------------------------------------------

/** GET /api/v2/whitelist：白名单条目数组。 */
export function getWhitelist(signal?: AbortSignal): Promise<WhitelistEntry[]> {
  return apiFetch<WhitelistEntry[]>(ROUTES.GET_API_V2_WHITELIST, { signal })
}

/** POST /api/v2/whitelist：新增白名单（CIDR 或裸 IP）。 */
export function addWhitelist(
  req: CreateWhitelistRequest,
  signal?: AbortSignal,
): Promise<WhitelistOperationResponse> {
  return apiFetch<WhitelistOperationResponse>(ROUTES.POST_API_V2_WHITELIST, {
    method: 'POST',
    body: req,
    signal,
  })
}

/** DELETE /api/v2/whitelist/:cidr：移除白名单（cidr 里的 `/` 由 withParams 转义）。 */
export function removeWhitelist(cidr: string, signal?: AbortSignal): Promise<WhitelistOperationResponse> {
  return apiFetch<WhitelistOperationResponse>(withParams(ROUTES.DELETE_API_V2_WHITELIST_CIDR, { cidr }), {
    method: 'DELETE',
    signal,
  })
}

export interface WhitelistRecommendationParams {
  min_bans?: number
  limit?: number
}

/** GET /api/v2/whitelist/recommendations：推荐数组本身（不另包信封）。 */
export function getWhitelistRecommendations(
  params: WhitelistRecommendationParams = {},
  signal?: AbortSignal,
): Promise<WhitelistRecommendation[]> {
  return apiFetch<WhitelistRecommendation[]>(ROUTES.GET_API_V2_WHITELIST_RECOMMENDATIONS, {
    query: { min_bans: params.min_bans, limit: params.limit },
    signal,
  })
}

// ---------------------------------------------------------------------------
// 速率
// ---------------------------------------------------------------------------

/** GET /api/v2/rates/current：当前速率表（按 pps 降序，不分页）。 */
export function getCurrentRates(signal?: AbortSignal): Promise<RateResponse[]> {
  return apiFetch<RateResponse[]>(ROUTES.GET_API_V2_RATES_CURRENT, { signal })
}

/** GET /api/v2/rates/history：速率历史环（时间升序）；limit 取最近 n 点。 */
export function getRatesHistory(limit?: number, signal?: AbortSignal): Promise<RateHistoryResponse[]> {
  return apiFetch<RateHistoryResponse[]>(ROUTES.GET_API_V2_RATES_HISTORY, {
    query: { limit },
    signal,
  })
}

/** GET /api/v2/rates/windows：短/中/长三档窗口速率快照。 */
export function getRateWindows(signal?: AbortSignal): Promise<RateWindowSnapshot> {
  return apiFetch<RateWindowSnapshot>(ROUTES.GET_API_V2_RATES_WINDOWS, { signal })
}

// ---------------------------------------------------------------------------
// 统计子路由
// ---------------------------------------------------------------------------

/** GET /api/v2/stats/heatmap：24 小时热力图（恒 24 项）。 */
export function getHeatmap(signal?: AbortSignal): Promise<HourlyHeatmap> {
  return apiFetch<HourlyHeatmap>(ROUTES.GET_API_V2_STATS_HEATMAP, { signal })
}

/** GET /api/v2/stats/recidivism：复发统计（rate 为百分数 0-100）。 */
export function getRecidivism(signal?: AbortSignal): Promise<RecidivismResponse> {
  return apiFetch<RecidivismResponse>(ROUTES.GET_API_V2_STATS_RECIDIVISM, { signal })
}

/** GET /api/v2/stats/ban-effectiveness：分级封禁成效。 */
export function getBanEffectiveness(signal?: AbortSignal): Promise<BanEffectivenessResponse> {
  return apiFetch<BanEffectivenessResponse>(ROUTES.GET_API_V2_STATS_BAN_EFFECTIVENESS, { signal })
}

/** GET /api/v2/stats/periodic-attackers：周期性攻击者数组。 */
export function getPeriodicAttackers(signal?: AbortSignal): Promise<PeriodicAttacker[]> {
  return apiFetch<PeriodicAttacker[]>(ROUTES.GET_API_V2_STATS_PERIODIC_ATTACKERS, { signal })
}

/** GET /api/v2/stats/collaborative-attacks：协同攻击窗口数组。 */
export function getCollaborativeAttacks(signal?: AbortSignal): Promise<CollaborativeAttack[]> {
  return apiFetch<CollaborativeAttack[]>(ROUTES.GET_API_V2_STATS_COLLABORATIVE_ATTACKS, { signal })
}

/** GET /api/v2/stats/udp-ports：UDP 端口分布。 */
export function getUdpPorts(signal?: AbortSignal): Promise<UdpPortDistributionResponse> {
  return apiFetch<UdpPortDistributionResponse>(ROUTES.GET_API_V2_STATS_UDP_PORTS, { signal })
}

/** GET /api/v2/stats/icmp-types：ICMP 类型分布。 */
export function getIcmpTypes(signal?: AbortSignal): Promise<IcmpTypeDistributionResponse> {
  return apiFetch<IcmpTypeDistributionResponse>(ROUTES.GET_API_V2_STATS_ICMP_TYPES, { signal })
}

/** GET /api/v2/stats/sse-status：两条 SSE 流各自的名额读数。 */
export function getSseStatus(signal?: AbortSignal): Promise<SseStatusResponse> {
  return apiFetch<SseStatusResponse>(ROUTES.GET_API_V2_STATS_SSE_STATUS, { signal })
}

/** GET /api/v2/stats/ban-duration-histogram：封禁时长直方图。 */
export function getBanDurationHistogram(signal?: AbortSignal): Promise<BanDurationHistogramResponse> {
  return apiFetch<BanDurationHistogramResponse>(ROUTES.GET_API_V2_STATS_BAN_DURATION_HISTOGRAM, { signal })
}

/** GET /api/v2/stats/packet-sizes：包长分布（累计口径）。 */
export function getPacketSizes(signal?: AbortSignal): Promise<PacketSizeDistributionResponse> {
  return apiFetch<PacketSizeDistributionResponse>(ROUTES.GET_API_V2_STATS_PACKET_SIZES, { signal })
}

/** GET /api/v2/stats/ttl-distribution：TTL 分布（累计口径）。 */
export function getTtlDistribution(signal?: AbortSignal): Promise<TtlDistributionResponse> {
  return apiFetch<TtlDistributionResponse>(ROUTES.GET_API_V2_STATS_TTL_DISTRIBUTION, { signal })
}

/** GET /api/v2/stats/ip-fragments：IP 分片统计（ratio 为百分数）。 */
export function getIpFragments(signal?: AbortSignal): Promise<IpFragmentStatsResponse> {
  return apiFetch<IpFragmentStatsResponse>(ROUTES.GET_API_V2_STATS_IP_FRAGMENTS, { signal })
}

/** GET /api/v2/stats/port-scanners：端口扫描检出。 */
export function getPortScanners(signal?: AbortSignal): Promise<PortScanResponse> {
  return apiFetch<PortScanResponse>(ROUTES.GET_API_V2_STATS_PORT_SCANNERS, { signal })
}

/** GET /api/v2/stats/service-probes：服务探测检出。 */
export function getServiceProbes(signal?: AbortSignal): Promise<ServiceProbeResponse> {
  return apiFetch<ServiceProbeResponse>(ROUTES.GET_API_V2_STATS_SERVICE_PROBES, { signal })
}

/** GET /api/v2/stats/ban-duration-recommendations：封禁时长推荐。 */
export function getBanDurationRecommendations(
  signal?: AbortSignal,
): Promise<BanDurationRecommendationResponse> {
  return apiFetch<BanDurationRecommendationResponse>(ROUTES.GET_API_V2_STATS_BAN_DURATION_RECOMMENDATIONS, {
    signal,
  })
}

/** GET /api/v2/stats/reputation：IP 信誉数组。 */
export function getReputation(signal?: AbortSignal): Promise<ReputationEntryResponse[]> {
  return apiFetch<ReputationEntryResponse[]>(ROUTES.GET_API_V2_STATS_REPUTATION, { signal })
}

/** GET /api/v2/stats/threshold-recommendations：阈值推荐。 */
export function getThresholdRecommendations(
  signal?: AbortSignal,
): Promise<ThresholdRecommendationResponse> {
  return apiFetch<ThresholdRecommendationResponse>(ROUTES.GET_API_V2_STATS_THRESHOLD_RECOMMENDATIONS, {
    signal,
  })
}

/** GET /api/v2/stats/network-distribution：网段聚合数组。 */
export function getNetworkDistribution(signal?: AbortSignal): Promise<NetworkBlock[]> {
  return apiFetch<NetworkBlock[]>(ROUTES.GET_API_V2_STATS_NETWORK_DISTRIBUTION, { signal })
}

/** GET /api/v2/stats/attack-predictions：攻击预测汇总。 */
export function getAttackPredictions(signal?: AbortSignal): Promise<AttackPredictionSummary> {
  return apiFetch<AttackPredictionSummary>(ROUTES.GET_API_V2_STATS_ATTACK_PREDICTIONS, { signal })
}

/** GET /api/v2/stats/anomalies：异常检测（只观测、不封禁）。 */
export function getAnomalies(signal?: AbortSignal): Promise<AnomalyResponse> {
  return apiFetch<AnomalyResponse>(ROUTES.GET_API_V2_STATS_ANOMALIES, { signal })
}

/** GET /api/v2/stats/attack-geo：攻击源地理分布（GeoIP 库未配置时 points 为空）。 */
export function getAttackGeo(signal?: AbortSignal): Promise<AttackGeoResponse> {
  return apiFetch<AttackGeoResponse>(ROUTES.GET_API_V2_STATS_ATTACK_GEO, { signal })
}

// ---------------------------------------------------------------------------
// 多维风险引擎（v2）—— 仅 risk_engine.enabled=true 时可用，否则 503
// ---------------------------------------------------------------------------

/** GET /api/v2/risk/vectors/:ip：单 IP 的 7 维风险向量。 */
export function getRiskVector(ip: string, signal?: AbortSignal): Promise<RiskVectorResponse> {
  return apiFetch<RiskVectorResponse>(withParams(ROUTES.GET_API_V2_RISK_VECTORS_IP, { ip }), { signal })
}

/** GET /api/v2/risk/events/:ip：单 IP 的攻击事件历史。 */
export function getRiskEvents(ip: string, signal?: AbortSignal): Promise<RiskEventResponse> {
  return apiFetch<RiskEventResponse>(withParams(ROUTES.GET_API_V2_RISK_EVENTS_IP, { ip }), { signal })
}

/** GET /api/v2/risk/vectors：全部风险向量列表（按总风险降序，最多 100 条）。 */
export function getRiskVectors(signal?: AbortSignal): Promise<RiskVectorListResponse> {
  return apiFetch<RiskVectorListResponse>(ROUTES.GET_API_V2_RISK_VECTORS, { signal })
}

// ---------------------------------------------------------------------------
// 日志（历史）
// ---------------------------------------------------------------------------

/** GET /api/v2/logs：历史日志分页（level/keyword/since 由服务端过滤）。 */
export function getLogs(params: LogQueryParams = {}, signal?: AbortSignal): Promise<LogPageResponse> {
  return apiFetch<LogPageResponse>(ROUTES.GET_API_V2_LOGS, {
    query: {
      page: params.page,
      page_size: params.page_size,
      level: params.level,
      keyword: params.keyword,
      since: params.since,
    },
    signal,
  })
}

// ---------------------------------------------------------------------------
// 威胁情报源
// ---------------------------------------------------------------------------

/** GET /api/v2/threat-feeds：情报源列表与同步状态。 */
export function getThreatFeeds(signal?: AbortSignal): Promise<ThreatFeedListResponse> {
  return apiFetch<ThreatFeedListResponse>(ROUTES.GET_API_V2_THREAT_FEEDS, { signal })
}

/** POST /api/v2/threat-feeds/sync：手动触发一次全量同步。 */
export function syncThreatFeeds(signal?: AbortSignal): Promise<ThreatFeedSyncResult> {
  return apiFetch<ThreatFeedSyncResult>(ROUTES.POST_API_V2_THREAT_FEEDS_SYNC, {
    method: 'POST',
    signal,
  })
}

/** GET /api/v2/threat-feeds/:id：单个情报源详情。 */
export function getThreatFeed(id: string, signal?: AbortSignal): Promise<ThreatFeedResponse> {
  return apiFetch<ThreatFeedResponse>(withParams(ROUTES.GET_API_V2_THREAT_FEEDS_ID, { id }), { signal })
}

// ---------------------------------------------------------------------------
// 综合分析
// ---------------------------------------------------------------------------

/** GET /api/v2/analysis/summary：一页式综合结论。 */
export function getAnalysisSummary(signal?: AbortSignal): Promise<AnalysisSummaryResponse> {
  return apiFetch<AnalysisSummaryResponse>(ROUTES.GET_API_V2_ANALYSIS_SUMMARY, { signal })
}

/** GET /api/v2/analysis/ip/:ip：单 IP 综合分析（风险 + 历史 + 信誉 + 预测）。 */
export function getAnalysisIp(ip: string, signal?: AbortSignal): Promise<AnalysisIpResponse> {
  return apiFetch<AnalysisIpResponse>(withParams(ROUTES.GET_API_V2_ANALYSIS_IP_IP, { ip }), { signal })
}

// ---------------------------------------------------------------------------
// 认证探测
// ---------------------------------------------------------------------------

/**
 * 登录探测：用最小分页拉一次封禁列表，凭据错/锁定会抛 `unauthorized`。
 * 不能用 GET /（恒 303 跳 /dashboard，探不出凭据对错）。
 */
export async function probeAuth(signal?: AbortSignal): Promise<void> {
  await getBans({ page: 1, page_size: 1 }, signal)
}

// ---------------------------------------------------------------------------
// SSE URL 构造（EventSource 不能设请求头，凭据走查询参数）
// ---------------------------------------------------------------------------

/** 把当前令牌拼成 `?access_token=`；无令牌返回空串（连接会被守护进程 401 拒绝）。 */
function tokenQuery(): string {
  const token = getAccessToken()
  return token ? `${TOKEN_QUERY_KEY}=${encodeURIComponent(token)}` : ''
}

/** GET /api/v2/events 的 EventSource URL（上限 10 连接）。 */
export function eventsStreamUrl(): string {
  const qs = tokenQuery()
  return qs ? `${ROUTES.GET_API_V2_EVENTS}?${qs}` : ROUTES.GET_API_V2_EVENTS
}

/** GET /api/v2/logs/stream 的 EventSource URL（上限 5 连接）。 */
export function logsStreamUrl(): string {
  const qs = tokenQuery()
  return qs ? `${ROUTES.GET_API_V2_LOGS_STREAM}?${qs}` : ROUTES.GET_API_V2_LOGS_STREAM
}
