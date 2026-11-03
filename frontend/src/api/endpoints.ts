/**
 * 全部 `/api/v2/*` 端点的类型化封装。
 *
 * 路径一律取自 `contract/generated/http_contract.ts` 的 `ROUTES`，不再手写字面量：
 * 契约由 `contract/http.fwidl` 生成，改接口时先改 fwidl 再重新生成。
 *
 * 路径参数编码：CIDR 含 `/`、IPv6 含 `:`，必须经 `encodeURIComponent` 编码，
 * 否则 `/api/v2/whitelist/10.0.0.0/8` 会被服务端解释成两段路径直接 404。
 *
 * 所有函数失败时抛 `ApiError`（见 client.ts）。
 */

import { ROUTES } from './contract'
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
  PaginatedResponse,
  PacketSizeDistributionResponse,
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
} from './contract'
import type { BanSortKey } from './params'
import { delJson, getJson, getRawJson, sendJson } from './client'

// ============================================================================
// 长连接地址
// ============================================================================

/**
 * SSE 实时事件流地址（`GET /api/v2/events`）。
 *
 * `EventSource` **无法设置自定义请求头**，所以 Basic 凭据只能走 query：
 * 使用 `withAccessToken(SSE_EVENTS_URL)`（见 api/auth.ts）拼上 `?access_token=`
 * （服务端中间件兼容该参数）。
 */
export const SSE_EVENTS_URL = ROUTES.GET_API_V2_EVENTS

/** SSE 实时日志流地址（`GET /api/v2/logs/stream`，tail -f 语义，命名事件 `log`） */
export const LOG_STREAM_URL = ROUTES.GET_API_V2_LOGS_STREAM

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
 * `GET /api/v2/health` — 运行时就绪快照。
 * 未就绪时服务端返回 503，但响应体仍是完整结构（`status: "degraded"`），
 * 因此本函数按可用性探测使用：抛错 = 完全连不上守护进程。
 */
export function checkHealth(): Promise<RuntimeSnapshot> {
  return getRawJson<RuntimeSnapshot>(ROUTES.GET_API_V2_HEALTH)
}

// ============================================================================
// 统计
// ============================================================================

/** `GET /api/v2/stats` — 仪表盘统计数据（含威胁等级） */
export function getStats(): Promise<StatsResponse> {
  return getJson<StatsResponse>(ROUTES.GET_API_V2_STATS)
}

/**
 * `GET /api/v2/bans` — 活跃封禁列表，一律返回分页信封。
 * 不传参数时按契约默认分页（page=1 / page_size=20）；
 * `page_size` 服务端上限为 100（`views::MAX_PAGE_SIZE`）。
 */
export function getBans(params?: {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}): Promise<PaginatedResponse<BanResponse>> {
  return getJson<PaginatedResponse<BanResponse>>(
    withQuery(ROUTES.GET_API_V2_BANS, {
      page: params?.page,
      page_size: params?.page_size,
      sort_by: params?.sort_by,
    }),
  )
}

/** `GET /api/v2/bans/:ip/detail` — 封禁详情（决策链 + 历史 + 信誉分） */
export function getBanDetail(ip: string): Promise<BanDetailResponse> {
  return getJson<BanDetailResponse>(fill(ROUTES.GET_API_V2_BANS_IP_DETAIL, ip))
}

/** `POST /api/v2/bans` — 封禁单个 IP（duration 省略或 0 表示永久） */
export function createBan(req: CreateBanRequest): Promise<BanOperationResponse> {
  return sendJson<CreateBanRequest, BanOperationResponse>(ROUTES.POST_API_V2_BANS, 'POST', req)
}

/** `DELETE /api/v2/bans/:ip` — 解封 IP（同时解除临时与永久封禁） */
export function deleteBan(ip: string): Promise<BanOperationResponse> {
  return delJson<BanOperationResponse>(fill(ROUTES.DELETE_API_V2_BANS_IP, ip))
}

/**
 * `POST /api/v2/bans/batch` — 批量封禁（契约上限单次 100 条，`duration` 缺省 3600 秒）。
 *
 * 请求体是契约的 `BatchBanRequest`（`{ips, duration, reason}`），**不是**裸 `string[]`：
 * 服务端解的是这个对象，发数组会整批落到 422/40007。`duration` 在这里没有「缺省即永久」
 * 的读法——批量入口产生的永远是有时长封禁，因此它们都能被 unbanTemporary 一次撤掉。
 */
export function batchBan(ips: string[], duration?: number): Promise<BatchOperationResponse> {
  // 契约把 Option<u64> 映射成 `number | null`（必填、可为 null），所以这里写 null 而不是
  // 省略字段：null 与缺席在 Go 侧同为「指针为 nil」，但省略会让 TS 类型不通过。
  const body: BatchBanRequest = { ips, duration: duration ?? null, reason: null }
  return sendJson<BatchBanRequest, BatchOperationResponse>(
    ROUTES.POST_API_V2_BANS_BATCH,
    'POST',
    body,
  )
}

/** `POST /api/v2/bans/unban-temporary` — 批量解封所有临时封禁（永久封禁不受影响） */
export function unbanAllTemporary(): Promise<BatchOperationResponse> {
  return sendJson<null, BatchOperationResponse>(
    ROUTES.POST_API_V2_BANS_UNBAN_TEMPORARY,
    'POST',
    null,
  )
}

// ============================================================================
// Jail
// ============================================================================

/** `GET /api/v2/jails` — Jail 列表（含运行时统计与阈值放宽信息） */
export function getJails(): Promise<JailResponse[]> {
  return getJson<JailResponse[]>(ROUTES.GET_API_V2_JAILS)
}

/** `PUT /api/v2/jails/:name` — 启用/禁用 Jail，返回更新后的完整条目 */
export function updateJail(name: string, enabled: boolean): Promise<JailResponse> {
  const body: UpdateJailRequest = { enabled }
  return sendJson<UpdateJailRequest, JailResponse>(
    fill(ROUTES.PUT_API_V2_JAILS_NAME, name),
    'PUT',
    body,
  )
}

// ============================================================================
// 配置
// ============================================================================

/** `GET /api/v2/config` — Web UI 配置（阈值、检测开关、容量） */
export function getConfig(): Promise<WebuiConfigResponse> {
  return getJson<WebuiConfigResponse>(ROUTES.GET_API_V2_CONFIG)
}

/** `PUT /api/v2/config` — 提交部分字段更新，返回更新后的完整配置 */
export function updateConfig(req: UpdateConfigRequest): Promise<WebuiConfigResponse> {
  return sendJson<UpdateConfigRequest, WebuiConfigResponse>(ROUTES.PUT_API_V2_CONFIG, 'PUT', req)
}

// ============================================================================
// 白名单
// ============================================================================

/** `GET /api/v2/whitelist` — 白名单列表 */
export function getWhitelist(): Promise<WhitelistEntry[]> {
  return getJson<WhitelistEntry[]>(ROUTES.GET_API_V2_WHITELIST)
}

/** `POST /api/v2/whitelist` — 添加白名单（CIDR 或单 IP） */
export function createWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  const body: CreateWhitelistRequest = { cidr }
  return sendJson<CreateWhitelistRequest, WhitelistOperationResponse>(
    ROUTES.POST_API_V2_WHITELIST,
    'POST',
    body,
  )
}

/** `DELETE /api/v2/whitelist/:cidr` — 移除白名单（CIDR 中的 `/` 会被编码） */
export function deleteWhitelist(cidr: string): Promise<WhitelistOperationResponse> {
  return delJson<WhitelistOperationResponse>(fill(ROUTES.DELETE_API_V2_WHITELIST_CIDR, cidr))
}

/** `GET /api/v2/whitelist/recommendations` — 智能白名单推荐（最多 10 条，按置信度降序） */
export function getWhitelistRecommendations(): Promise<WhitelistRecommendation[]> {
  return getJson<WhitelistRecommendation[]>(ROUTES.GET_API_V2_WHITELIST_RECOMMENDATIONS)
}

// ============================================================================
// 速率（DDoS）
// ============================================================================

/** `GET /api/v2/rates/current` — 当前每 IP 速率（协议维度） */
export function getRatesCurrent(): Promise<RateResponse[]> {
  return getJson<RateResponse[]>(ROUTES.GET_API_V2_RATES_CURRENT)
}

/** `GET /api/v2/rates/history` — 速率历史趋势（最近 1 小时，每 2 秒一条） */
export function getRatesHistory(): Promise<RateHistoryResponse[]> {
  return getJson<RateHistoryResponse[]>(ROUTES.GET_API_V2_RATES_HISTORY)
}

/** `GET /api/v2/rates/windows` — 多窗口 EWMA 速率（短期 / 中期 / 长期） */
export function getRatesWindows(): Promise<RateWindowSnapshot> {
  return getJson<RateWindowSnapshot>(ROUTES.GET_API_V2_RATES_WINDOWS)
}

// ============================================================================
// 统计子路由（历史快照 / 包分析 / 趋势预测）
// ============================================================================

/** `GET /api/v2/stats/heatmap` — 24 小时封禁 / 失败 / DDoS 热力图 */
export function getHeatmap(): Promise<HourlyHeatmap> {
  return getJson<HourlyHeatmap>(ROUTES.GET_API_V2_STATS_HEATMAP)
}

/** `GET /api/v2/stats/recidivism` — 复发统计（被封禁过的 IP 再次攻击的比例） */
export function getRecidivism(): Promise<RecidivismResponse> {
  return getJson<RecidivismResponse>(ROUTES.GET_API_V2_STATS_RECIDIVISM)
}

/** `GET /api/v2/stats/ban-effectiveness` — 渐进式封禁各等级的成效对比 */
export function getBanEffectiveness(): Promise<BanEffectivenessResponse> {
  return getJson<BanEffectivenessResponse>(ROUTES.GET_API_V2_STATS_BAN_EFFECTIVENESS)
}

/** `GET /api/v2/stats/periodic-attackers` — 周期性攻击者（等间隔复现的扫描源） */
export function getPeriodicAttackers(): Promise<PeriodicAttacker[]> {
  return getJson<PeriodicAttacker[]>(ROUTES.GET_API_V2_STATS_PERIODIC_ATTACKERS)
}

/** `GET /api/v2/stats/collaborative-attacks` — 协同攻击（同一时间窗内的多源联动） */
export function getCollaborativeAttacks(): Promise<CollaborativeAttack[]> {
  return getJson<CollaborativeAttack[]>(ROUTES.GET_API_V2_STATS_COLLABORATIVE_ATTACKS)
}

/** `GET /api/v2/stats/udp-ports` — UDP 端口分布 */
export function getUdpPorts(): Promise<UdpPortDistributionResponse> {
  return getJson<UdpPortDistributionResponse>(ROUTES.GET_API_V2_STATS_UDP_PORTS)
}

/** `GET /api/v2/stats/icmp-types` — ICMP 类型 / 代码分布 */
export function getIcmpTypes(): Promise<IcmpTypeDistributionResponse> {
  return getJson<IcmpTypeDistributionResponse>(ROUTES.GET_API_V2_STATS_ICMP_TYPES)
}

/** `GET /api/v2/stats/sse-status` — 两条 SSE 流各自的当前连接数与上限 */
export function getSseStatus(): Promise<SseStatusResponse> {
  return getJson<SseStatusResponse>(ROUTES.GET_API_V2_STATS_SSE_STATUS)
}

/** `GET /api/v2/stats/ban-duration-histogram` — 已封禁时长的分布直方图 */
export function getBanDurationHistogram(): Promise<BanDurationHistogramResponse> {
  return getJson<BanDurationHistogramResponse>(ROUTES.GET_API_V2_STATS_BAN_DURATION_HISTOGRAM)
}

/** `GET /api/v2/stats/packet-sizes` — 包大小分布 */
export function getPacketSizes(): Promise<PacketSizeDistributionResponse> {
  return getJson<PacketSizeDistributionResponse>(ROUTES.GET_API_V2_STATS_PACKET_SIZES)
}

/** `GET /api/v2/stats/ttl-distribution` — TTL 分布（可旁路推断攻击者操作系统） */
export function getTtlDistribution(): Promise<TtlDistributionResponse> {
  return getJson<TtlDistributionResponse>(ROUTES.GET_API_V2_STATS_TTL_DISTRIBUTION)
}

/** `GET /api/v2/stats/ip-fragments` — IP 分片流量占比 */
export function getIpFragments(): Promise<IpFragmentStatsResponse> {
  return getJson<IpFragmentStatsResponse>(ROUTES.GET_API_V2_STATS_IP_FRAGMENTS)
}

/** `GET /api/v2/stats/port-scanners` — 端口扫描检测结果 */
export function getPortScanners(): Promise<PortScanResponse> {
  return getJson<PortScanResponse>(ROUTES.GET_API_V2_STATS_PORT_SCANNERS)
}

/** `GET /api/v2/stats/service-probes` — 服务探测检测结果 */
export function getServiceProbes(): Promise<ServiceProbeResponse> {
  return getJson<ServiceProbeResponse>(ROUTES.GET_API_V2_STATS_SERVICE_PROBES)
}

/** `GET /api/v2/stats/ban-duration-recommendations` — 按 jail 的封禁时长建议 */
export function getBanDurationRecommendations(): Promise<BanDurationRecommendationResponse> {
  return getJson<BanDurationRecommendationResponse>(
    ROUTES.GET_API_V2_STATS_BAN_DURATION_RECOMMENDATIONS,
  )
}

/** `GET /api/v2/stats/reputation` — IP 信誉分列表（分数越低，阈值倍率越严） */
export function getReputation(): Promise<ReputationEntryResponse[]> {
  return getJson<ReputationEntryResponse[]>(ROUTES.GET_API_V2_STATS_REPUTATION)
}

/** `GET /api/v2/stats/threshold-recommendations` — jail 阈值调优建议 */
export function getThresholdRecommendations(): Promise<ThresholdRecommendationResponse> {
  return getJson<ThresholdRecommendationResponse>(
    ROUTES.GET_API_V2_STATS_THRESHOLD_RECOMMENDATIONS,
  )
}

/** `GET /api/v2/stats/network-distribution` — 攻击源网段分布 */
export function getNetworkDistribution(): Promise<NetworkBlock[]> {
  return getJson<NetworkBlock[]>(ROUTES.GET_API_V2_STATS_NETWORK_DISTRIBUTION)
}

/** `GET /api/v2/stats/attack-predictions` — 下次攻击时间预测 + 各 jail 攻击趋势 */
export function getAttackPredictions(): Promise<AttackPredictionSummary> {
  return getJson<AttackPredictionSummary>(ROUTES.GET_API_V2_STATS_ATTACK_PREDICTIONS)
}

/** `GET /api/v2/stats/anomalies` — 全局流量偏离 + per-IP 行为离群（只观测，不触发封禁） */
export function getAnomalies(): Promise<AnomalyResponse> {
  return getJson<AnomalyResponse>(ROUTES.GET_API_V2_STATS_ANOMALIES)
}

/** `GET /api/v2/stats/attack-geo` — 攻击源地理分布；未启用 GeoIP 时 `geoip_enabled=false` */
export function getAttackGeo(): Promise<AttackGeoResponse> {
  return getJson<AttackGeoResponse>(ROUTES.GET_API_V2_STATS_ATTACK_GEO)
}

// ============================================================================
// 日志
// ============================================================================

/**
 * `GET /api/v2/logs` — 分页日志查询。
 *
 * 契约里的 `LogQueryParams` 是请求侧 `Option<T>`，生成出来即可选可为空
 * （`page?: number | null`），调用方只传关心的项即可；`withQuery` 会跳过
 * `null` / `undefined`，未填项不会出现在查询串里。
 */
export function getLogs(params: LogQueryParams = {}): Promise<LogPageResponse> {
  return getJson<LogPageResponse>(
    withQuery(ROUTES.GET_API_V2_LOGS, {
      page: params.page,
      page_size: params.page_size,
      level: params.level,
      keyword: params.keyword,
      since: params.since,
    }),
  )
}

// ============================================================================
// 威胁情报源 (v2.4)
// ============================================================================

/** `GET /api/v2/threat-feeds` — 外部威胁情报源列表与同步状态 */
export function getThreatFeeds(): Promise<ThreatFeedListResponse> {
  return getJson<ThreatFeedListResponse>(ROUTES.GET_API_V2_THREAT_FEEDS)
}

/** `POST /api/v2/threat-feeds/sync` — 手动触发一次威胁情报同步 */
export function syncThreatFeeds(): Promise<ThreatFeedSyncResult> {
  return sendJson<null, ThreatFeedSyncResult>(ROUTES.POST_API_V2_THREAT_FEEDS_SYNC, 'POST', null)
}

/** `GET /api/v2/threat-feeds/:id` — 单个威胁情报源详情 */
export function getThreatFeed(id: string): Promise<ThreatFeedResponse> {
  return getJson<ThreatFeedResponse>(fill(ROUTES.GET_API_V2_THREAT_FEEDS_ID, id))
}

// ============================================================================
// 综合分析
// ============================================================================

/** `GET /api/v2/analysis/summary` — 综合分析摘要（威胁等级 + Top 风险 IP + 活跃攻击） */
export function getAnalysisSummary(): Promise<AnalysisSummaryResponse> {
  return getJson<AnalysisSummaryResponse>(ROUTES.GET_API_V2_ANALYSIS_SUMMARY)
}

/** `GET /api/v2/analysis/ip/:ip` — 单 IP 综合分析（风险向量 + 封禁历史 + 信誉 + 预测） */
export function getAnalysisIp(ip: string): Promise<AnalysisIpResponse> {
  return getJson<AnalysisIpResponse>(fill(ROUTES.GET_API_V2_ANALYSIS_IP_IP, ip))
}

// ============================================================================
// 健康检查别名与风险引擎 (v2)
// ============================================================================

/** `GET /api/v2/healthz` — /api/v2/health 的别名（k8s/负载均衡探针用），载荷同为 RuntimeSnapshot */
export function checkHealthz(): Promise<RuntimeSnapshot> {
  return getRawJson<RuntimeSnapshot>(ROUTES.GET_API_V2_HEALTHZ)
}

/** `GET /api/v2/risk/vectors` — 全部 IP 的风险向量列表（按总风险降序，最多 100 条）；risk_engine 未启用时 503 */
export function getRiskVectors(): Promise<RiskVectorListResponse> {
  return getJson<RiskVectorListResponse>(ROUTES.GET_API_V2_RISK_VECTORS)
}

/** `GET /api/v2/risk/vectors/:ip` — 指定 IP 的多维风险向量；risk_engine 未启用时 503，IP 非法时 40006 */
export function getRiskVector(ip: string): Promise<RiskVectorResponse> {
  return getJson<RiskVectorResponse>(fill(ROUTES.GET_API_V2_RISK_VECTORS_IP, ip))
}

/** `GET /api/v2/risk/events/:ip` — 指定 IP 的攻击事件历史（最近 100 条，按时间降序）；risk_engine 未启用时 503 */
export function getRiskEvents(ip: string): Promise<RiskEventResponse> {
  return getJson<RiskEventResponse>(fill(ROUTES.GET_API_V2_RISK_EVENTS_IP, ip))
}
