/**
 * 前端类型镜像 —— 与 contract/http.fwidl 生成的载荷逐字段对齐。
 *
 * 这一份不是「随手写的 TS 类型」：`contract/verify_http.py` 的 `check_types_frontend`
 * 会把这里每个 `export interface` 与契约的同名载荷做**字段名逐项**比对（缺一个、多一个都
 * 判红）。所以规则很简单——契约里有的字段这里必须有、名字必须一致；契约里没有的字段这里
 * 一个都不能加。字段的 TS 类型按契约的线上语义标注（数值一律 number、可空一律 `| null`），
 * 门禁只核对字段名，但类型标准确才能让视图层拿到真实的自动补全。
 *
 * 请求体（`*Request` / `*Params`）门禁不在 types.ts 核对（它们由 endpoints.ts 的调用签名
 * 体现），但视图与端点封装要用，故一并声明在此，集中一处便于校验规则复用。
 *
 * 唯一真相源是契约；改这里之前先改 `contract/http.fwidl` 再 `python3 contract/gen.py`。
 */

// ---------------------------------------------------------------------------
// 信封与分页
// ---------------------------------------------------------------------------

/** 统一响应信封：成功 = HTTP 2xx 且 code === 0，data 才是业务载荷。 */
export interface ApiResponse<T> {
  code: number
  data: T
  message: string
}

/** 分页信封：GET /api/v2/bans、/api/v2/logs 等列表端点的外层形状。 */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// ---------------------------------------------------------------------------
// 运行时状态 / 健康
// ---------------------------------------------------------------------------

/** GET /api/v2/health 的载荷；注意这条**不经信封**，直接是裸 RuntimeSnapshot。 */
export interface RuntimeSnapshot {
  status: string
  netlink_ready: boolean
  kmod_proc_present: boolean
  ban_cache_initialized: boolean
  ban_history_initialized: boolean
  active_bans: number
  lease_state: string
  lease_losses: number
}

// ---------------------------------------------------------------------------
// 统计总览
// ---------------------------------------------------------------------------

/** 图表通用形状：labels 与 values 等长同下标。 */
export interface ChartData {
  labels: string[]
  values: number[]
}

/** 威胁等级读数：level 取 safe/low/medium/high/critical 之一。 */
export interface ThreatLevel {
  level: string
  score: number
  factors: string[]
  current_pps: number
  pps_ratio: number
  ban_table_usage: number
  recent_bans: number
  baseline_frozen: boolean
  peak_hours: boolean
}

/** GET /api/v2/stats 的载荷：首屏总览，混合内核快照 / 历史库时间窗 / 本进程状态。 */
export interface StatsResponse {
  daemon_version: string
  kernel_version: string
  today_bans: number
  failed_attempts: number
  ddos_events: number
  uptime_seconds: number
  ban_trend: ChartData
  jail_distribution: ChartData
  failure_reasons: ChartData
  failed_attempts_trend: ChartData
  current_bans: number
  total_bans: number
  total_unbans: number
  whitelist_count: number
  packets_dropped: number
  packets_accepted: number
  state_save_truncated: number
  threat_level: ThreatLevel
}

// ---------------------------------------------------------------------------
// 封禁管理
// ---------------------------------------------------------------------------

/** 封禁列表条目（GET /api/v2/bans 分页项、SSE bans 帧条目同形）。 */
export interface BanResponse {
  ip: string
  jail: string
  banned_at: number
  remaining_seconds: number
  reason: string
  ban_count: number
  is_permanent: boolean
}

/** 单个封禁的完整画像（GET /api/v2/bans/:ip/detail）。 */
export interface BanDetailResponse {
  ip: string
  is_banned: boolean
  jail_name: string
  reason: string
  banned_at: number
  expires_at: number
  is_permanent: boolean
  fail_count: number
  ban_count: number
  last_unbanned_at: number
  was_permanent: boolean
  progressive_level: string
  next_ban_duration: string
  reputation_score: number
}

/** 封禁/解封单条操作结果（POST /api/v2/bans、DELETE /api/v2/bans/:ip）。 */
export interface BanOperationResponse {
  ip: string
  action: string
  permanent: boolean
  duration_seconds: number | null
}

/** 批量操作结果（POST /api/v2/bans/batch、/api/v2/bans/unban-temporary）。 */
export interface BatchOperationResponse {
  total: number
  succeeded: number
  failed_count: number
  details: string[]
}

// ---------------------------------------------------------------------------
// Jail
// ---------------------------------------------------------------------------

/** Jail 配置 + 运行时计数（GET /api/v2/jails 数组项）。 */
export interface JailResponse {
  name: string
  enabled: boolean
  ban_count: number
  max_retries: number
  effective_max_retries: number
  findtime: number
  ban_time: number
  is_peak_hours: boolean
  peak_hours_addend: number
  internal_ip_addend: number
  lines_parsed: number
  regex_matches: number
  ips_extracted: number
  failed_attempts: number
  bans_triggered: number
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/** Web UI 相关配置快照（GET /api/v2/config、PUT /api/v2/config）。 */
export interface WebuiConfigResponse {
  sse_push_interval: number
  rate_warning_pps: number
  rate_critical_pps: number
  rate_warning_syn: number
  rate_critical_syn: number
  max_syn_per_second: number
  max_udp_per_second: number
  max_icmp_per_second: number
  max_ack_per_second: number
  max_rst_per_second: number
  max_fin_per_second: number
  static_threshold: boolean
  dynamic_threshold: boolean
  ddos_detection: boolean
  max_ban_entries: number
  max_whitelist_entries: number
  max_rate_entries: number
  max_local_ip_cache: number
  clear_logs_at: string | null
}

// ---------------------------------------------------------------------------
// 白名单
// ---------------------------------------------------------------------------

/**
 * 白名单条目。契约名是 `WhitelistEntryResponse`，但通过 ts_name 显式声明前端名为
 * `WhitelistEntry`（门禁按 ts_name 核对），故这里就叫 WhitelistEntry。
 */
export interface WhitelistEntry {
  cidr: string
  device: string
}

/** 白名单增删结果（POST/DELETE /api/v2/whitelist）。 */
export interface WhitelistOperationResponse {
  cidr: string
  action: string
}

/** 白名单推荐（GET /api/v2/whitelist/recommendations 数组项）。 */
export interface WhitelistRecommendation {
  rec_type: string
  cidr: string
  reason: string
  affected_ips: number
  total_bans: number
  confidence: number
}

// ---------------------------------------------------------------------------
// 速率
// ---------------------------------------------------------------------------

/** 单 IP 速率读数（GET /api/v2/rates/current 数组项、SSE rates 帧同形）。 */
export interface RateResponse {
  ip: string
  packets_per_sec: number
  bytes_per_sec: number
  syn_packets_per_sec: number
  udp_packets_per_sec: number
  icmp_packets_per_sec: number
  ack_packets_per_sec: number
  rst_packets_per_sec: number
  fin_packets_per_sec: number
}

/** 速率历史点（GET /api/v2/rates/history 数组项，时间升序）。 */
export interface RateHistoryResponse {
  timestamp: number
  total_pps: number
  total_bps: number
  tracked_ips: number
}

/** 三档窗口速率快照（GET /api/v2/rates/windows）。 */
export interface RateWindowSnapshot {
  pps_short: number
  pps_mid: number
  pps_long: number
  bps_short: number
  bps_mid: number
  bps_long: number
}

// ---------------------------------------------------------------------------
// 复发 / 成效 / 周期性 / 协同
// ---------------------------------------------------------------------------

/** 复发统计（GET /api/v2/stats/recidivism）；recidivism_rate 是百分数 0-100。 */
export interface RecidivismResponse {
  total_ips: number
  recidivist_ips: number
  recidivism_rate: number
  permanent_bans: number
  top_recidivists: RecidivistEntry[]
}

/** 复发榜条目。 */
export interface RecidivistEntry {
  ip: string
  ban_count: number
  last_banned_at: number
  was_permanent: boolean
}

/** 分级封禁成效（GET /api/v2/stats/ban-effectiveness）。 */
export interface BanEffectivenessResponse {
  levels: BanLevelEffectiveness[]
  total_unique_ips: number
  overall_recidivism_rate: number
  summary: string
}

/** 单个分级档位的成效。 */
export interface BanLevelEffectiveness {
  level: number
  label: string
  total_ips: number
  recidivist_ips: number
  recidivism_rate: number
  permanent_bans: number
  verdict: string
}

/** 周期性攻击者（GET /api/v2/stats/periodic-attackers 数组项）。 */
export interface PeriodicAttacker {
  ip: string
  ban_count: number
  avg_interval_secs: number
  interval_stddev: number
  periodicity_score: number
  jail_name: string
  timestamps: number[]
}

/** 协同攻击窗口（GET /api/v2/stats/collaborative-attacks 数组项）。 */
export interface CollaborativeAttack {
  jail_name: string
  window_start: number
  window_end: number
  ip_count: number
  ips: string[]
  total_bans: number
  correlation_score: number
}

// ---------------------------------------------------------------------------
// 预测 / 阈值推荐 / 时长推荐
// ---------------------------------------------------------------------------

/** 单 IP 攻击预测。 */
export interface AttackPrediction {
  ip: string
  ban_count: number
  jail_name: string
  last_ban_at: number
  median_interval_secs: number
  predicted_next_attack: number
  remaining_secs: number
  confidence: number
  urgency: string
}

/** 攻击预测汇总（GET /api/v2/stats/attack-predictions）。 */
export interface AttackPredictionSummary {
  predictions: AttackPrediction[]
  jail_trends: JailAttackTrend[]
  imminent_count: number
  within_24h_count: number
}

/** 单 jail 的攻击趋势。 */
export interface JailAttackTrend {
  jail_name: string
  bans_24h: number
  bans_7d: number
  trend: string
  predicted_attackers_24h: number
}

/** 阈值推荐条目。 */
export interface ThresholdRecommendation {
  jail_name: string
  current_threshold: number
  recommended_threshold: number
  direction: string
  total_bans: number
  unique_ips: number
  recidivist_ips: number
  recidivism_rate: number
  avg_bans_per_ip: number
  reason: string
  confidence: number
}

/** 阈值推荐汇总（GET /api/v2/stats/threshold-recommendations）。 */
export interface ThresholdRecommendationResponse {
  recommendations: ThresholdRecommendation[]
  summary: string
}

/** 封禁时长推荐条目。 */
export interface BanDurationRecommendation {
  jail_name: string
  current_ban_time: number
  recidivist_count: number
  median_return_secs: number
  recommended_ban_time: number
  reason: string
  needs_adjustment: boolean
}

/** 封禁时长推荐汇总（GET /api/v2/stats/ban-duration-recommendations）。 */
export interface BanDurationRecommendationResponse {
  recommendations: BanDurationRecommendation[]
  summary: string
}

// ---------------------------------------------------------------------------
// 信誉
// ---------------------------------------------------------------------------

/** IP 信誉条目（GET /api/v2/stats/reputation 数组项）。 */
export interface ReputationEntryResponse {
  ip: string
  score: number
  last_failure_at: number
  total_failures: number
  total_bans: number
  threshold_adjustment: number
}

// ---------------------------------------------------------------------------
// 多维风险引擎（v2）
// ---------------------------------------------------------------------------

/** 单 IP 的 7 维风险向量。 */
export interface RiskVectorResponse {
  ip: string
  failure: number
  ban: number
  scan: number
  bruteforce: number
  ddos: number
  geo: number
  cluster: number
  total_risk: number
  last_event_at: number
  updated_at: number
}

/** 风险向量列表（GET /api/v2/risk/vectors，按总风险降序）。 */
export interface RiskVectorListResponse {
  vectors: RiskVectorResponse[]
  total: number
}

/** 单条风险事件。 */
export interface RiskEventEntry {
  id: number
  ip: string
  event_type: string
  increment: number
  occurred_at: number
}

/** 单 IP 的风险事件历史（GET /api/v2/risk/events/:ip）。 */
export interface RiskEventResponse {
  ip: string
  events: RiskEventEntry[]
  total: number
}

// ---------------------------------------------------------------------------
// 内核分布统计（UDP / ICMP / 包长 / TTL / 分片 / 扫描 / 探测）
// ---------------------------------------------------------------------------

/** UDP 端口分布（GET /api/v2/stats/udp-ports）。 */
export interface UdpPortDistributionResponse {
  ports: UdpPortEntry[]
  total_entries: number
  max_entries: number
}

/** UDP 端口条目。 */
export interface UdpPortEntry {
  port: number
  packets: number
  bytes: number
  last_seen_secs: number
}

/** ICMP 类型分布（GET /api/v2/stats/icmp-types）。 */
export interface IcmpTypeDistributionResponse {
  types: IcmpTypeEntry[]
  total_entries: number
  max_entries: number
}

/** ICMP 类型条目。 */
export interface IcmpTypeEntry {
  type: number
  code: number
  packets: number
  bytes: number
  last_seen_secs: number
}

/** 包长分布（GET /api/v2/stats/packet-sizes）；labels/counts/percentages 等长。 */
export interface PacketSizeDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** TTL 分布（GET /api/v2/stats/ttl-distribution）；labels/counts/percentages 等长。 */
export interface TtlDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** 封禁时长直方图（GET /api/v2/stats/ban-duration-histogram）。 */
export interface BanDurationHistogramResponse {
  labels: string[]
  counts: number[]
  total: number
}

/** IP 分片统计（GET /api/v2/stats/ip-fragments）；fragment_ratio 是百分数 0-100。 */
export interface IpFragmentStatsResponse {
  total_packets: number
  fragment_packets: number
  fragment_ratio: number
}

/** 端口扫描检出（GET /api/v2/stats/port-scanners）。 */
export interface PortScanResponse {
  threshold: number
  total_detected: number
  scanners: PortScannerEntry[]
}

/** 端口扫描源条目。 */
export interface PortScannerEntry {
  ip: string
  unique_ports: number
  packets: number
}

/** 服务探测检出（GET /api/v2/stats/service-probes）。 */
export interface ServiceProbeResponse {
  threshold: number
  total_detected: number
  probes: ServiceProbeEntry[]
}

/** 服务探测源条目。 */
export interface ServiceProbeEntry {
  ip: string
  protocol_count: number
  packets: number
}

// ---------------------------------------------------------------------------
// 网段分布 / 热力图
// ---------------------------------------------------------------------------

/** 网段聚合（GET /api/v2/stats/network-distribution 数组项）。 */
export interface NetworkBlock {
  subnet: string
  unique_ips: number
  total_bans: number
  last_banned_at: number
  top_ip: string
}

/** 24 小时热力图（GET /api/v2/stats/heatmap）；hours 恒为 24 项。 */
export interface HourlyHeatmap {
  hours: HourlyBucket[]
}

/** 单个钟点槽（本地时区自然小时 0-23）。 */
export interface HourlyBucket {
  hour: number
  bans: number
  failed_attempts: number
  ddos_events: number
}

// ---------------------------------------------------------------------------
// 日志
// ---------------------------------------------------------------------------

/** 历史日志分页（GET /api/v2/logs）。 */
export interface LogPageResponse {
  items: LogEntry[]
  total_lines: number
  page: number
  page_size: number
  total_pages: number
}

/** 单条日志（原始行 + 行号）。 */
export interface LogEntry {
  line_number: number
  content: string
}

// ---------------------------------------------------------------------------
// SSE 连接状态
// ---------------------------------------------------------------------------

/** 单条流的连接名额读数。 */
export interface SseStreamStatus {
  current_connections: number
  max_connections: number
  limit_reached: boolean
}

/** 两条流各自的名额（GET /api/v2/stats/sse-status）；不得用一条推断另一条。 */
export interface SseStatusResponse {
  events: SseStreamStatus
  logs: SseStreamStatus
}

// ---------------------------------------------------------------------------
// 威胁情报源
// ---------------------------------------------------------------------------

/** 单个情报源状态。 */
export interface ThreatFeedResponse {
  id: string
  name: string
  source_url: string
  enabled: boolean
  category: string
  confidence: number
  last_synced_at: number | null
  entry_count: number
  sync_status: string
  last_error: string | null
}

/** 情报源列表（GET /api/v2/threat-feeds）。 */
export interface ThreatFeedListResponse {
  feeds: ThreatFeedResponse[]
  total: number
}

/** 一次同步的结果（POST /api/v2/threat-feeds/sync）。 */
export interface ThreatFeedSyncResult {
  feed_id: string
  new_entries: number
  updated_entries: number
  synced_at: number
}

// ---------------------------------------------------------------------------
// 异常检测
// ---------------------------------------------------------------------------

/** 异常检测载荷（GET /api/v2/stats/anomalies）；只观测、不触发封禁。 */
export interface AnomalyResponse {
  global_score: number
  global_dimensions: DimensionScore[]
  global_features: FeatureValue[] | null
  global_baseline_p50: FeatureValue[]
  global_baseline_p95: FeatureValue[]
  global_sample_count: number
  ip_anomalies: IpAnomalyEntry[]
  timestamp: number
}

/** 单维度偏差分（0-1 归一化）。 */
export interface DimensionScore {
  name: string
  score: number
}

/** 具名特征值。 */
export interface FeatureValue {
  name: string
  value: number
}

/** per-IP 异常条目。 */
export interface IpAnomalyEntry {
  ip: string
  score: number
  dimensions: DimensionScore[]
}

// ---------------------------------------------------------------------------
// 攻击源地理分布
// ---------------------------------------------------------------------------

/**
 * 攻击源地理分布（GET /api/v2/stats/attack-geo）。
 * 当前实现无 GeoIP 读库：geoip_enabled 恒 false、points 恒 []、located_ips 恒 0；
 * 本机坐标三件套仍按配置返回。
 */
export interface AttackGeoResponse {
  geoip_enabled: boolean
  points: GeoPoint[]
  total_ips: number
  located_ips: number
  server_latitude: number | null
  server_longitude: number | null
  server_location_source: string
}

/** 单个地理位置聚合。 */
export interface GeoPoint {
  latitude: number
  longitude: number
  country_code: string
  country: string
  city: string
  subdivision: string
  unique_ips: number
  total_bans: number
  top_ip: string
  last_banned_at: number
}

// ---------------------------------------------------------------------------
// 综合分析
// ---------------------------------------------------------------------------

/** 综合分析摘要（GET /api/v2/analysis/summary）。 */
export interface AnalysisSummaryResponse {
  threat_level: ThreatLevel
  top_risk_ips: RiskVectorResponse[]
  active_attacks: number
  anomalies_count: number
  collaborative_count: number
  summary: string
  timestamp: number
}

/** 单 IP 综合分析（GET /api/v2/analysis/ip/:ip）。 */
export interface AnalysisIpResponse {
  ip: string
  risk: RiskVectorResponse | null
  ban_history: BanResponse[]
  reputation: ReputationEntryResponse | null
  prediction: AttackPrediction | null
  is_whitelisted: boolean
}

// ===========================================================================
// 请求体（门禁不在 types.ts 核对，但端点与视图需要；集中声明便于校验复用）
// ===========================================================================

/** POST /api/v2/bans 请求体。duration 三态：缺席/0=永久，正数=时长（秒）。 */
export interface CreateBanRequest {
  ip: string
  duration?: number | null
  reason?: string | null
}

/** POST /api/v2/bans/batch 请求体（单次 1..100 条；duration 缺省 3600 秒）。 */
export interface BatchBanRequest {
  ips: string[]
  duration?: number | null
  reason?: string | null
}

/** PUT /api/v2/jails/:name 请求体：当前只允许改启用状态。 */
export interface UpdateJailRequest {
  enabled: boolean
}

/** PUT /api/v2/config 请求体：全部可选，只提交要改的字段。 */
export interface UpdateConfigRequest {
  sse_push_interval?: number | null
  rate_warning_pps?: number | null
  rate_critical_pps?: number | null
  rate_warning_syn?: number | null
  rate_critical_syn?: number | null
  max_syn_per_second?: number | null
  max_udp_per_second?: number | null
  max_icmp_per_second?: number | null
  max_ack_per_second?: number | null
  max_rst_per_second?: number | null
  max_fin_per_second?: number | null
  static_threshold?: boolean | null
  dynamic_threshold?: boolean | null
  ddos_detection?: boolean | null
  max_ban_entries?: number | null
  max_whitelist_entries?: number | null
  max_rate_entries?: number | null
  max_local_ip_cache?: number | null
  clear_logs_at?: string | null
}

/** POST /api/v2/whitelist 请求体。 */
export interface CreateWhitelistRequest {
  cidr: string
}

/** GET /api/v2/logs 查询参数。 */
export interface LogQueryParams {
  page?: number | null
  page_size?: number | null
  level?: string | null
  keyword?: string | null
  since?: string | null
}

/** 通用分页/排序查询参数（GET /api/v2/bans 等）。 */
export interface PaginationParams {
  page?: number | null
  page_size?: number | null
  sort_by?: string | null
}

// ===========================================================================
// 前端专属辅助类型（非契约载荷；门禁只核对上面与契约同名的 interface）
// ===========================================================================

/**
 * GET /api/v2/bans 支持的排序键。契约固定 7 个取值，未识别的值服务端回落
 * `banned_at_desc`（见 defect HTTP_BAN_SORT_DOC_INCOMPLETE，已 fixed）。
 * 这里独立成联合类型，供排序下拉与查询构造复用，避免散落字符串。
 */
export type BanSortKey =
  | 'banned_at_desc'
  | 'banned_at_asc'
  | 'ip_asc'
  | 'ip_desc'
  | 'jail_asc'
  | 'remaining_asc'
  | 'remaining_desc'

/** 威胁等级枚举（ThreatLevel.level 的取值域）；用于配色与文案映射。 */
export type ThreatLevelName = 'safe' | 'low' | 'medium' | 'high' | 'critical'

/** 日志级别（客户端过滤用；后端按 `[LEVEL]` 前缀，对 JSON 行失效）。 */
export type LogLevel = 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
