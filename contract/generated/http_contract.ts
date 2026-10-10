/**
 * 由 contract/http.fwidl 生成 —— 请勿手工编辑。
 *
 * 守护进程 HTTP 接口的路径与 SSE 事件名单一真相源。前端不得再手写这些字面量。
 */

/** API 前缀：/api/v1 */
export const API_BASE = "/api/v1"

/** 鉴权参数：scheme、query 凭据键名、失败计数阈值与锁定时长 */
export const AUTH = {
  /** `Authorization: Basic …` 里的凭据方案 */
  SCHEME: "Basic",
  /** EventSource 不能设请求头，凭据走这个查询参数 */
  TOKEN_QUERY: "access_token",
  /** 触发锁定前的连续失败次数 */
  FAILURE_THRESHOLD: 10,
  /** 一次锁定持续的秒数（锁定期内正确凭据同样被拒） */
  LOCKOUT_SECONDS: 60,
  /** 凭据缺失/错误时的 HTTP 状态码（纯文本形状，不经信封） */
  UNAUTHORIZED_STATUS: 401,
} as const

/** 全部路由路径（与守护进程注册的字面量逐字一致） */
export const ROUTES = {
  /** `GET /health` */
  GET_HEALTH: "/health",
  /** `GET /healthz` */
  GET_HEALTHZ: "/healthz",
  /** `GET /` */
  GET: "/",
  /** `GET /dashboard` */
  GET_DASHBOARD: "/dashboard",
  /** `GET /bans` */
  GET_BANS: "/bans",
  /** `GET /whitelist` */
  GET_WHITELIST: "/whitelist",
  /** `GET /jails` */
  GET_JAILS: "/jails",
  /** `GET /ddos` */
  GET_DDOS: "/ddos",
  /** `GET /globe` */
  GET_GLOBE: "/globe",
  /** `GET /logs` */
  GET_LOGS: "/logs",
  /** `GET /settings` */
  GET_SETTINGS: "/settings",
  /** `GET /more` */
  GET_MORE: "/more",
  /** `GET /static/*path` */
  GET_STATIC_PATH: "/static/*path",
  /** `GET /sw.js` */
  GET_SW_JS: "/sw.js",
  /** `GET /metrics` */
  GET_METRICS: "/metrics",
  /** `GET /api/v1/events` */
  GET_API_V1_EVENTS: "/api/v1/events",
  /** `GET /api/v1/logs/stream` */
  GET_API_V1_LOGS_STREAM: "/api/v1/logs/stream",
  /** `GET /api/v1/stats` */
  GET_API_V1_STATS: "/api/v1/stats",
  /** `GET /api/v1/bans` */
  GET_API_V1_BANS: "/api/v1/bans",
  /** `POST /api/v1/bans` */
  POST_API_V1_BANS: "/api/v1/bans",
  /** `DELETE /api/v1/bans/:ip` */
  DELETE_API_V1_BANS_IP: "/api/v1/bans/:ip",
  /** `GET /api/v1/bans/:ip/detail` */
  GET_API_V1_BANS_IP_DETAIL: "/api/v1/bans/:ip/detail",
  /** `POST /api/v1/bans/unban-temporary` */
  POST_API_V1_BANS_UNBAN_TEMPORARY: "/api/v1/bans/unban-temporary",
  /** `POST /api/v1/bans/batch` */
  POST_API_V1_BANS_BATCH: "/api/v1/bans/batch",
  /** `GET /api/v1/jails` */
  GET_API_V1_JAILS: "/api/v1/jails",
  /** `PUT /api/v1/jails/:name` */
  PUT_API_V1_JAILS_NAME: "/api/v1/jails/:name",
  /** `GET /api/v1/config` */
  GET_API_V1_CONFIG: "/api/v1/config",
  /** `PUT /api/v1/config` */
  PUT_API_V1_CONFIG: "/api/v1/config",
  /** `GET /api/v1/whitelist` */
  GET_API_V1_WHITELIST: "/api/v1/whitelist",
  /** `POST /api/v1/whitelist` */
  POST_API_V1_WHITELIST: "/api/v1/whitelist",
  /** `DELETE /api/v1/whitelist/:cidr` */
  DELETE_API_V1_WHITELIST_CIDR: "/api/v1/whitelist/:cidr",
  /** `GET /api/v1/whitelist/recommendations` */
  GET_API_V1_WHITELIST_RECOMMENDATIONS: "/api/v1/whitelist/recommendations",
  /** `GET /api/v1/rates/current` */
  GET_API_V1_RATES_CURRENT: "/api/v1/rates/current",
  /** `GET /api/v1/rates/history` */
  GET_API_V1_RATES_HISTORY: "/api/v1/rates/history",
  /** `GET /api/v1/rates/windows` */
  GET_API_V1_RATES_WINDOWS: "/api/v1/rates/windows",
  /** `GET /api/v1/stats/heatmap` */
  GET_API_V1_STATS_HEATMAP: "/api/v1/stats/heatmap",
  /** `GET /api/v1/stats/recidivism` */
  GET_API_V1_STATS_RECIDIVISM: "/api/v1/stats/recidivism",
  /** `GET /api/v1/stats/ban-effectiveness` */
  GET_API_V1_STATS_BAN_EFFECTIVENESS: "/api/v1/stats/ban-effectiveness",
  /** `GET /api/v1/stats/periodic-attackers` */
  GET_API_V1_STATS_PERIODIC_ATTACKERS: "/api/v1/stats/periodic-attackers",
  /** `GET /api/v1/stats/collaborative-attacks` */
  GET_API_V1_STATS_COLLABORATIVE_ATTACKS: "/api/v1/stats/collaborative-attacks",
  /** `GET /api/v1/stats/udp-ports` */
  GET_API_V1_STATS_UDP_PORTS: "/api/v1/stats/udp-ports",
  /** `GET /api/v1/stats/icmp-types` */
  GET_API_V1_STATS_ICMP_TYPES: "/api/v1/stats/icmp-types",
  /** `GET /api/v1/stats/sse-status` */
  GET_API_V1_STATS_SSE_STATUS: "/api/v1/stats/sse-status",
  /** `GET /api/v1/stats/ban-duration-histogram` */
  GET_API_V1_STATS_BAN_DURATION_HISTOGRAM: "/api/v1/stats/ban-duration-histogram",
  /** `GET /api/v1/stats/packet-sizes` */
  GET_API_V1_STATS_PACKET_SIZES: "/api/v1/stats/packet-sizes",
  /** `GET /api/v1/stats/ttl-distribution` */
  GET_API_V1_STATS_TTL_DISTRIBUTION: "/api/v1/stats/ttl-distribution",
  /** `GET /api/v1/stats/ip-fragments` */
  GET_API_V1_STATS_IP_FRAGMENTS: "/api/v1/stats/ip-fragments",
  /** `GET /api/v1/stats/port-scanners` */
  GET_API_V1_STATS_PORT_SCANNERS: "/api/v1/stats/port-scanners",
  /** `GET /api/v1/stats/service-probes` */
  GET_API_V1_STATS_SERVICE_PROBES: "/api/v1/stats/service-probes",
  /** `GET /api/v1/stats/ban-duration-recommendations` */
  GET_API_V1_STATS_BAN_DURATION_RECOMMENDATIONS: "/api/v1/stats/ban-duration-recommendations",
  /** `GET /api/v1/stats/reputation` */
  GET_API_V1_STATS_REPUTATION: "/api/v1/stats/reputation",
  /** `GET /api/v1/stats/threshold-recommendations` */
  GET_API_V1_STATS_THRESHOLD_RECOMMENDATIONS: "/api/v1/stats/threshold-recommendations",
  /** `GET /api/v1/stats/network-distribution` */
  GET_API_V1_STATS_NETWORK_DISTRIBUTION: "/api/v1/stats/network-distribution",
  /** `GET /api/v1/stats/attack-predictions` */
  GET_API_V1_STATS_ATTACK_PREDICTIONS: "/api/v1/stats/attack-predictions",
  /** `GET /api/v1/stats/anomalies` */
  GET_API_V1_STATS_ANOMALIES: "/api/v1/stats/anomalies",
  /** `GET /api/v1/stats/attack-geo` */
  GET_API_V1_STATS_ATTACK_GEO: "/api/v1/stats/attack-geo",
  /** `GET /api/v1/logs` */
  GET_API_V1_LOGS: "/api/v1/logs",
} as const

/** `/api/v1/events` 的事件名联合类型（上限 10 连接） */
export type SseEventsApiV1Events = "connected" | "stats" | "bans" | "jails" | "whitelist" | "rates"

/** `/api/v1/logs/stream` 的事件名联合类型（上限 5 连接） */
export type SseEventsApiV1LogsStream = "connected" | "log" | "error"

/** 响应/请求载荷类型（字段与 daemon 序列化出的 JSON key 一一对应） */
/** 契约类型 `AnomalyResponse` */
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

/** 契约类型 `DimensionScore` */
export interface DimensionScore {
  name: string
  score: number
}

/** 契约类型 `FeatureValue` */
export interface FeatureValue {
  name: string
  value: number
}

/** 契约类型 `IpAnomalyEntry` */
export interface IpAnomalyEntry {
  ip: string
  score: number
  dimensions: DimensionScore[]
}

/** 契约类型 `AttackGeoResponse` */
export interface AttackGeoResponse {
  geoip_enabled: boolean
  points: GeoPoint[]
  total_ips: number
  located_ips: number
  server_latitude: number | null
  server_longitude: number | null
  server_location_source: string
}

/** 契约类型 `GeoPoint` */
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

/** 契约类型 `ApiResponse` */
export interface ApiResponse<T> {
  code: number
  data: T
  message: string
}

/** 契约类型 `PaginatedResponse` */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/** 契约类型 `RuntimeSnapshot` */
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

/** 契约类型 `StatsResponse` */
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
  threat_level: ThreatLevel
}

/** 契约类型 `ChartData` */
export interface ChartData {
  labels: string[]
  values: number[]
}

/** 契约类型 `ThreatLevel` */
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

/** 契约类型 `BanResponse` */
export interface BanResponse {
  ip: string
  jail: string
  banned_at: number
  remaining_seconds: number
  reason: string
  ban_count: number
  is_permanent: boolean
}

/** 契约类型 `BanDetailResponse` */
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
  reputation_multiplier: number
}

/** 契约类型 `BanOperationResponse` */
export interface BanOperationResponse {
  ip: string
  action: string
  permanent: boolean
  duration_seconds: number | null
}

/** 契约类型 `BatchOperationResponse` */
export interface BatchOperationResponse {
  total: number
  succeeded: number
  failed_count: number
  details: string[]
}

/** 契约类型 `CreateBanRequest` */
export interface CreateBanRequest {
  ip: string
  duration: number | null
  reason: string | null
}

/** 契约类型 `JailResponse` */
export interface JailResponse {
  name: string
  enabled: boolean
  ban_count: number
  max_retries: number
  effective_max_retries: number
  findtime: number
  ban_time: number
  is_peak_hours: boolean
  peak_hours_multiplier: number
  internal_ip_multiplier: number
  lines_parsed: number
  regex_matches: number
  ips_extracted: number
  failed_attempts: number
  bans_triggered: number
}

/** 契约类型 `UpdateJailRequest` */
export interface UpdateJailRequest {
  enabled: boolean
}

/** 契约类型 `WebuiConfigResponse` */
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

/** 契约类型 `UpdateConfigRequest` */
export interface UpdateConfigRequest {
  sse_push_interval: number | null
  rate_warning_pps: number | null
  rate_critical_pps: number | null
  rate_warning_syn: number | null
  rate_critical_syn: number | null
  max_syn_per_second: number | null
  max_udp_per_second: number | null
  max_icmp_per_second: number | null
  max_ack_per_second: number | null
  max_rst_per_second: number | null
  max_fin_per_second: number | null
  static_threshold: boolean | null
  dynamic_threshold: boolean | null
  ddos_detection: boolean | null
  max_ban_entries: number | null
  max_whitelist_entries: number | null
  max_rate_entries: number | null
  max_local_ip_cache: number | null
  clear_logs_at: string | null
}

/** 契约类型 `WhitelistEntryResponse`（前端名） */
export interface WhitelistEntry {
  cidr: string
  device: string
}

/** 契约类型 `WhitelistOperationResponse` */
export interface WhitelistOperationResponse {
  cidr: string
  action: string
}

/** 契约类型 `WhitelistRecommendation` */
export interface WhitelistRecommendation {
  rec_type: string
  cidr: string
  reason: string
  affected_ips: number
  total_bans: number
  confidence: number
}

/** 契约类型 `CreateWhitelistRequest` */
export interface CreateWhitelistRequest {
  cidr: string
}

/** 契约类型 `RateResponse` */
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

/** 契约类型 `RateHistoryResponse` */
export interface RateHistoryResponse {
  timestamp: number
  total_pps: number
  total_bps: number
  tracked_ips: number
}

/** 契约类型 `RateWindowSnapshot` */
export interface RateWindowSnapshot {
  pps_short: number
  pps_mid: number
  pps_long: number
  bps_short: number
  bps_mid: number
  bps_long: number
}

/** 契约类型 `RecidivismResponse` */
export interface RecidivismResponse {
  total_ips: number
  recidivist_ips: number
  recidivism_rate: number
  permanent_bans: number
  top_recidivists: RecidivistEntry[]
}

/** 契约类型 `RecidivistEntry` */
export interface RecidivistEntry {
  ip: string
  ban_count: number
  last_banned_at: number
  was_permanent: boolean
}

/** 契约类型 `BanEffectivenessResponse` */
export interface BanEffectivenessResponse {
  levels: BanLevelEffectiveness[]
  total_unique_ips: number
  overall_recidivism_rate: number
  summary: string
}

/** 契约类型 `BanLevelEffectiveness` */
export interface BanLevelEffectiveness {
  level: number
  label: string
  total_ips: number
  recidivist_ips: number
  recidivism_rate: number
  permanent_bans: number
  verdict: string
}

/** 契约类型 `PeriodicAttacker` */
export interface PeriodicAttacker {
  ip: string
  ban_count: number
  avg_interval_secs: number
  interval_stddev: number
  periodicity_score: number
  jail_name: string
  timestamps: number[]
}

/** 契约类型 `CollaborativeAttack` */
export interface CollaborativeAttack {
  jail_name: string
  window_start: number
  window_end: number
  ip_count: number
  ips: string[]
  total_bans: number
  correlation_score: number
}

/** 契约类型 `AttackPrediction` */
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

/** 契约类型 `AttackPredictionSummary` */
export interface AttackPredictionSummary {
  predictions: AttackPrediction[]
  jail_trends: JailAttackTrend[]
  imminent_count: number
  within_24h_count: number
}

/** 契约类型 `JailAttackTrend` */
export interface JailAttackTrend {
  jail_name: string
  bans_24h: number
  bans_7d: number
  trend: string
  predicted_attackers_24h: number
}

/** 契约类型 `ThresholdRecommendation` */
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

/** 契约类型 `ThresholdRecommendationResponse` */
export interface ThresholdRecommendationResponse {
  recommendations: ThresholdRecommendation[]
  summary: string
}

/** 契约类型 `BanDurationRecommendation` */
export interface BanDurationRecommendation {
  jail_name: string
  current_ban_time: number
  recidivist_count: number
  median_return_secs: number
  recommended_ban_time: number
  reason: string
  needs_adjustment: boolean
}

/** 契约类型 `BanDurationRecommendationResponse` */
export interface BanDurationRecommendationResponse {
  recommendations: BanDurationRecommendation[]
  summary: string
}

/** 契约类型 `ReputationEntryResponse` */
export interface ReputationEntryResponse {
  ip: string
  score: number
  last_failure_at: number
  total_failures: number
  total_bans: number
  threshold_multiplier: number
}

/** 契约类型 `UdpPortDistributionResponse` */
export interface UdpPortDistributionResponse {
  ports: UdpPortEntry[]
  total_entries: number
  max_entries: number
}

/** 契约类型 `UdpPortEntry` */
export interface UdpPortEntry {
  port: number
  packets: number
  bytes: number
  last_seen_secs: number
}

/** 契约类型 `IcmpTypeDistributionResponse` */
export interface IcmpTypeDistributionResponse {
  types: IcmpTypeEntry[]
  total_entries: number
  max_entries: number
}

/** 契约类型 `IcmpTypeEntry` */
export interface IcmpTypeEntry {
  type: number
  code: number
  packets: number
  bytes: number
  last_seen_secs: number
}

/** 契约类型 `PacketSizeDistributionResponse` */
export interface PacketSizeDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** 契约类型 `TtlDistributionResponse` */
export interface TtlDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** 契约类型 `BanDurationHistogramResponse` */
export interface BanDurationHistogramResponse {
  labels: string[]
  counts: number[]
  total: number
}

/** 契约类型 `IpFragmentStatsResponse` */
export interface IpFragmentStatsResponse {
  total_packets: number
  fragment_packets: number
  fragment_ratio: number
}

/** 契约类型 `PortScanResponse` */
export interface PortScanResponse {
  threshold: number
  total_detected: number
  scanners: PortScannerEntry[]
}

/** 契约类型 `PortScannerEntry` */
export interface PortScannerEntry {
  ip: string
  unique_ports: number
  packets: number
}

/** 契约类型 `ServiceProbeResponse` */
export interface ServiceProbeResponse {
  threshold: number
  probes: ServiceProbeEntry[]
}

/** 契约类型 `ServiceProbeEntry` */
export interface ServiceProbeEntry {
  ip: string
  protocol_count: number
  packets: number
}

/** 契约类型 `NetworkBlock` */
export interface NetworkBlock {
  subnet: string
  unique_ips: number
  total_bans: number
  last_banned_at: number
  top_ip: string
}

/** 契约类型 `HourlyHeatmap` */
export interface HourlyHeatmap {
  hours: HourlyBucket[]
}

/** 契约类型 `HourlyBucket` */
export interface HourlyBucket {
  hour: number
  bans: number
  failed_attempts: number
  ddos_events: number
}

/** 契约类型 `LogPageResponse` */
export interface LogPageResponse {
  items: LogEntry[]
  total_lines: number
  page: number
  page_size: number
  total_pages: number
}

/** 契约类型 `LogEntry` */
export interface LogEntry {
  line_number: number
  content: string
}

/** 契约类型 `LogQueryParams` */
export interface LogQueryParams {
  page: number | null
  page_size: number | null
  level: string | null
  keyword: string | null
  since: string | null
}

/** 契约类型 `PaginationParams` */
export interface PaginationParams {
  page: number | null
  page_size: number | null
  sort_by: string | null
}

/** 契约类型 `SseStreamStatus` */
export interface SseStreamStatus {
  current_connections: number
  max_connections: number
  limit_reached: boolean
}

/** 契约类型 `SseStatusResponse` */
export interface SseStatusResponse {
  events: SseStreamStatus
  logs: SseStreamStatus
}
