/**
 * 后端数据模型（TypeScript 侧视图）
 *
 * 唯一真源：`src/daemon/web_ui/*.rs`（api.rs / ban_ops.rs / stats.rs / analysis.rs /
 * ddos_stats.rs / packet_analysis.rs / recommendations.rs / log_viewer.rs /
 * runtime_status.rs）与 `src/daemon/history_snapshot/*.rs`。
 *
 * 命名约定：字段名一律保持后端 serde 序列化后的 snake_case 原样，不做驼峰映射 ——
 * 这样任何一个字段名/类型写错都会在联调时立刻暴露，不会被一层转换函数悄悄吞掉。
 *
 * 类型映射：
 * - Rust `u8`/`u16`/`u32`/`usize` → `number`
 * - Rust `u64`/`i64` → `number`（JSON number；仅在超过 2^53 时丢精度，本系统的
 *   计数与时间戳量级远低于该上限）
 * - Rust `f64` → `number`
 * - Rust `Option<T>` 且未加 `skip_serializing_if` → `T | null`（字段本身仍会出现）
 * - Rust 请求体里的 `Option<T>` → `?:` 可选字段（反序列化时缺省即 None）
 */

// ============================================================================
// 通用信封与图表结构
// ============================================================================

/**
 * 统一响应信封（`src/daemon/web_ui/api.rs` 的 `ApiResponse<T>`）。
 * 契约：HTTP 2xx 且 `code === 0` 才算成功；`code !== 0` 时 `message` 是失败原因。
 */
export interface ApiResponse<T> {
  code: number
  data: T
  message: string
}

/**
 * 图表数据（Rust `ChartData`）：labels 与 values 按下标一一对应。
 * 用于封禁趋势 / Jail 分布 / 失败原因分布等。
 */
export interface ChartData {
  labels: string[]
  values: number[]
}

// ============================================================================
// 统计与仪表盘（stats.rs / api.rs）
// ============================================================================

/** 实时威胁等级评估（Rust `ThreatLevel`） */
export interface ThreatLevel {
  /** 等级标签：safe / low / medium / high / critical */
  level: string
  /** 数值化等级（0-4） */
  score: number
  /** 评估依据文案（为空时后端会填入「一切正常」） */
  factors: string[]
  /** 当前短期窗口 PPS */
  current_pps: number
  /** 当前 PPS 与警告阈值的比率（>1 表示已超阈值） */
  pps_ratio: number
  /** 内核封禁表桶使用率（0.0-1.0，按 4096 桶计算） */
  ban_table_usage: number
  /** 最近 5 分钟封禁数 */
  recent_bans: number
  /** 基线是否已冻结（异常流量突增时停用基线） */
  baseline_frozen: boolean
  /** 是否处于业务高峰期（基线上调 50%） */
  peak_hours: boolean
}

/** `GET /api/v1/stats` 响应（Rust `StatsResponse`） */
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

// ============================================================================
// 封禁 / 白名单 / Jail（api.rs / ban_ops.rs）
// ============================================================================

/**
 * 封禁条目（Rust `BanResponse`）。
 * `remaining_seconds` 为 `-1` 表示永久封禁（与后端一致，不是「剩余 -1 秒」）。
 */
export interface BanResponse {
  ip: string
  jail: string
  /** 封禁时间（Unix 秒） */
  banned_at: number
  /** 剩余秒数；-1 = 永久封禁 */
  remaining_seconds: number
  reason: string
  /** 该 IP 累计被封禁次数（渐进式封禁依据） */
  ban_count: number
  is_permanent: boolean
}

/** Jail 条目（Rust `JailResponse`） */
export interface JailResponse {
  name: string
  enabled: boolean
  /** 该 Jail 当前封禁的 IP 数 */
  ban_count: number
  /** 配置的失败次数阈值 */
  max_retries: number
  /** 当前生效阈值（高峰期会按倍数放宽） */
  effective_max_retries: number
  /** 滑动窗口大小（秒） */
  findtime: number
  /** 封禁时长（秒），-1 表示永久 */
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

/** DDoS 速率快照（Rust `RateResponse`），来自全局 RATE_CACHE */
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

/** 速率历史点（Rust `RateHistoryResponse`），后端每 2 秒一条、保留约 1 小时 */
export interface RateHistoryResponse {
  /** 采样时间（Unix 秒） */
  timestamp: number
  total_pps: number
  total_bps: number
  /** 该采样时刻被追踪的 IP 数 */
  tracked_ips: number
}

/** 多窗口速率 EWMA 快照（Rust `RateWindowSnapshot`）：短期 ~5s / 中期 ~60s / 长期 ~300s */
export interface RateWindowSnapshot {
  pps_short: number
  pps_mid: number
  pps_long: number
  bps_short: number
  bps_mid: number
  bps_long: number
}

/** Whitelist 条目（Rust `WhitelistEntryResponse`，序列化字段 cidr/device） */
export interface WhitelistEntry {
  cidr: string
  /** 绑定的设备名（未绑定时为空串） */
  device: string
}

/** 封禁操作结果（Rust `BanOperationResponse`） */
export interface BanOperationResponse {
  ip: string
  /** "banned" 或 "unbanned" */
  action: string
  permanent: boolean
  /** 永久封禁时为 null */
  duration_seconds: number | null
}

/** 白名单操作结果（Rust `WhitelistOperationResponse`） */
export interface WhitelistOperationResponse {
  cidr: string
  /** "added" 或 "removed" */
  action: string
}

/** 批量操作汇总（Rust `BatchOperationResponse`） */
export interface BatchOperationResponse {
  total: number
  succeeded: number
  failed_count: number
  /** 成功项明细（批量解封时是 IP，批量封禁时也是 IP） */
  details: string[]
}

/**
 * 封禁详情（Rust `BanDetailResponse`）：当前封禁状态 + 历史 + 渐进式等级 + 信誉分。
 * 未在封禁中时 `jail_name`/`reason` 为空串，各时间戳为 0。
 */
export interface BanDetailResponse {
  ip: string
  is_banned: boolean
  jail_name: string
  reason: string
  /** 封禁时间（Unix 秒，0 = 无记录） */
  banned_at: number
  /** 过期时间（Unix 秒，0 = 永久或无记录） */
  expires_at: number
  is_permanent: boolean
  /** 触发封禁前的失败次数 */
  fail_count: number
  ban_count: number
  /** 上次解封时间（Unix 秒，0 = 当前仍在封禁中） */
  last_unbanned_at: number
  was_permanent: boolean
  /** 渐进式封禁等级说明（如「二次封禁（累犯）」） */
  progressive_level: string
  /** 下次封禁时长说明（如 "300 秒" / "永久封禁" / "未知"，是文案而非纯数字） */
  next_ban_duration: string
  /** IP 信誉分（0-100，100 = 完全信任） */
  reputation_score: number
  /** 信誉阈值乘数（0.5 / 0.8 / 1.0） */
  reputation_multiplier: number
}

/** 封禁列表排序字段：取值来自 `ban_ops.rs` 的分支匹配 */
export type BanSortKey =
  | 'banned_at_desc'
  | 'banned_at_asc'
  | 'ip_asc'
  | 'ip_desc'
  | 'jail_asc'
  | 'remaining_asc'
  | 'remaining_desc'

/** `GET /api/v1/bans` 分页参数（Rust `PaginationParams`）；后端缺省 page=1、page_size=20 */
export interface PaginationParams {
  page?: number
  page_size?: number
  sort_by?: BanSortKey
}

/** 分页包装（Rust `PaginatedResponse<T>`） */
export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

/** `POST /api/v1/bans` 请求体（Rust `CreateBanRequest`） */
export interface CreateBanRequest {
  ip: string
  /** 封禁时长（秒）：0 或省略 = 永久封禁（与内核 ban_time=-1 语义一致） */
  duration?: number
  /** 封禁原因（缺省时后端记为 "manual"） */
  reason?: string
}

/** `POST /api/v1/whitelist` 请求体（Rust `CreateWhitelistRequest`） */
export interface CreateWhitelistRequest {
  /** CIDR 或单个 IP，如 "10.0.0.0/8"、"192.168.1.1" */
  cidr: string
}

/** `PUT /api/v1/jails/:name` 请求体（Rust `UpdateJailRequest`） */
export interface UpdateJailRequest {
  enabled: boolean
}

// ============================================================================
// Web UI 配置（api.rs）
// ============================================================================

/** `GET /api/v1/config` 响应（Rust `WebuiConfigResponse`） */
export interface WebuiConfigResponse {
  sse_push_interval: number
  rate_warning_pps: number
  rate_critical_pps: number
  rate_warning_syn: number
  rate_critical_syn: number
  /** 协议专项阈值（下发到内核 netlink） */
  max_syn_per_second: number
  max_udp_per_second: number
  max_icmp_per_second: number
  max_ack_per_second: number
  max_rst_per_second: number
  max_fin_per_second: number
  /** DDoS 检测算法开关 */
  static_threshold: boolean
  dynamic_threshold: boolean
  ddos_detection: boolean
  /** 容量配置 */
  max_ban_entries: number
  max_whitelist_entries: number
  max_rate_entries: number
  max_local_ip_cache: number
  /** 日志过滤起点（ISO 8601 时间戳字符串）；null = 不做时间过滤 */
  clear_logs_at: string | null
}

/**
 * `PUT /api/v1/config` 请求体（Rust `UpdateConfigRequest`）。
 * 所有字段可选：只提交需要修改的字段，未提交的字段保持后端现值。
 * 约束（后端会校验并返回 400）：warning < critical；各阈值与容量均不能为 0；
 * `sse_push_interval` 必须在 1-60 之间。
 */
export interface UpdateConfigRequest {
  sse_push_interval?: number
  rate_warning_pps?: number
  rate_critical_pps?: number
  rate_warning_syn?: number
  rate_critical_syn?: number
  max_syn_per_second?: number
  max_udp_per_second?: number
  max_icmp_per_second?: number
  max_ack_per_second?: number
  max_rst_per_second?: number
  max_fin_per_second?: number
  static_threshold?: boolean
  dynamic_threshold?: boolean
  ddos_detection?: boolean
  max_ban_entries?: number
  max_whitelist_entries?: number
  max_rate_entries?: number
  max_local_ip_cache?: number
  /** 传空字符串 = 取消日志时间过滤；传时间戳 = 过滤早于该时间的日志行 */
  clear_logs_at?: string
}

// ============================================================================
// 封禁效果与智能推荐（stats.rs / analysis.rs / recommendations.rs）
// ============================================================================

/** 复发 IP 条目（Rust `RecidivistEntry`） */
export interface RecidivistEntry {
  ip: string
  ban_count: number
  last_banned_at: number
  was_permanent: boolean
}

/** 复发率统计（Rust `RecidivismResponse`） */
export interface RecidivismResponse {
  total_ips: number
  recidivist_ips: number
  /** 复发率，单位是百分数（0.0 ~ 100.0），不是 0-1 比例 */
  recidivism_rate: number
  permanent_bans: number
  top_recidivists: RecidivistEntry[]
}

/** 单级别封禁效果（Rust `BanLevelEffectiveness`） */
export interface BanLevelEffectiveness {
  /** 1=首次, 2=二次, 3=三次, 4=四次+ */
  level: number
  label: string
  total_ips: number
  recidivist_ips: number
  /** 复发率，0.0-1.0 的比例值（与前一个模型的单位不同，勿混用） */
  recidivism_rate: number
  permanent_bans: number
  verdict: string
}

/** 封禁效果分析（Rust `BanEffectivenessResponse`） */
export interface BanEffectivenessResponse {
  levels: BanLevelEffectiveness[]
  total_unique_ips: number
  /** 总体复发率，0.0-1.0 的比例值 */
  overall_recidivism_rate: number
  summary: string
}

/** 白名单推荐条目（Rust `WhitelistRecommendation`） */
export interface WhitelistRecommendation {
  /** "subnet" 或 "ip" */
  rec_type: string
  cidr: string
  reason: string
  affected_ips: number
  total_bans: number
  /** 置信度 0-100 */
  confidence: number
}

/** 封禁时长推荐条目（Rust `BanDurationRecommendation`） */
export interface BanDurationRecommendation {
  jail_name: string
  /** 当前配置的封禁时长（秒），-1 = 永久 */
  current_ban_time: number
  recidivist_count: number
  median_return_secs: number
  recommended_ban_time: number
  reason: string
  needs_adjustment: boolean
}

/** 封禁时长推荐汇总（Rust `BanDurationRecommendationResponse`） */
export interface BanDurationRecommendationResponse {
  recommendations: BanDurationRecommendation[]
  summary: string
}

/** IP 信誉分条目（Rust `ReputationEntryResponse`） */
export interface ReputationEntryResponse {
  ip: string
  /** 0-100 */
  score: number
  last_failure_at: number
  total_failures: number
  total_bans: number
  /** 当前阈值乘数（0.5 / 0.8 / 1.0） */
  threshold_multiplier: number
}

/** 阈值调优建议条目（Rust `ThresholdRecommendation`） */
export interface ThresholdRecommendation {
  jail_name: string
  current_threshold: number
  /** 0 = 无需调整 */
  recommended_threshold: number
  /** "increase" / "decrease" / "maintain" */
  direction: string
  total_bans: number
  unique_ips: number
  recidivist_ips: number
  /** 复发率（比例值） */
  recidivism_rate: number
  avg_bans_per_ip: number
  reason: string
  /** 置信度 0-100 */
  confidence: number
}

/** 阈值调优建议汇总（Rust `ThresholdRecommendationResponse`） */
export interface ThresholdRecommendationResponse {
  recommendations: ThresholdRecommendation[]
  summary: string
}

// ============================================================================
// 内核/流量特征分析（ddos_stats.rs / packet_analysis.rs）
// ============================================================================

/** UDP 端口分布条目（Rust `UdpPortEntry`） */
export interface UdpPortEntry {
  port: number
  packets: number
  bytes: number
  /** 距最近一次出现的秒数 */
  last_seen_secs: number
}

/** UDP 端口分布响应（Rust `UdpPortDistributionResponse`） */
export interface UdpPortDistributionResponse {
  /** 已按 packets 降序排序 */
  ports: UdpPortEntry[]
  total_entries: number
  max_entries: number
}

/** ICMP 类型分布条目（Rust `IcmpTypeEntry`，serde 把 `r#type` 序列化为 "type"） */
export interface IcmpTypeEntry {
  type: number
  code: number
  packets: number
  bytes: number
  last_seen_secs: number
}

/** ICMP 类型分布响应（Rust `IcmpTypeDistributionResponse`） */
export interface IcmpTypeDistributionResponse {
  /** 已按 packets 降序排序 */
  types: IcmpTypeEntry[]
  total_entries: number
  max_entries: number
}

/** 封禁时长分布直方图（Rust `BanDurationHistogramResponse`），counts 已转成非累积值 */
export interface BanDurationHistogramResponse {
  labels: string[]
  counts: number[]
  total: number
}

/** 包大小分布（Rust `PacketSizeDistributionResponse`）：counts 与 percentages 按下标对应 labels */
export interface PacketSizeDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** TTL 分布（Rust `TtlDistributionResponse`） */
export interface TtlDistributionResponse {
  labels: string[]
  counts: number[]
  total: number
  percentages: number[]
}

/** IP 分片统计（Rust `IpFragmentStatsResponse`），fragment_ratio 是百分数 */
export interface IpFragmentStatsResponse {
  total_packets: number
  fragment_packets: number
  /** 分片占比（百分数 0-100） */
  fragment_ratio: number
}

/** 端口扫描者条目（Rust `PortScannerEntry`） */
export interface PortScannerEntry {
  ip: string
  unique_ports: number
  packets: number
}

/** 端口扫描检测（Rust `PortScanResponse`） */
export interface PortScanResponse {
  /** 判定阈值（不同端口数） */
  threshold: number
  total_detected: number
  scanners: PortScannerEntry[]
}

/** 服务探测者条目（Rust `ServiceProbeEntry`） */
export interface ServiceProbeEntry {
  ip: string
  /** 探测过的协议数量 */
  protocol_count: number
  packets: number
}

/** 服务探测检测（Rust `ServiceProbeResponse`） */
export interface ServiceProbeResponse {
  threshold: number
  probes: ServiceProbeEntry[]
}

// ============================================================================
// 历史分析（history_snapshot/*.rs）
// ============================================================================

/** 单小时聚合桶（Rust `HourlyBucket`） */
export interface HourlyBucket {
  /** 小时编号 0-23 */
  hour: number
  bans: number
  failed_attempts: number
  ddos_events: number
}

/** 24 小时热力图（Rust `HourlyHeatmap`）：`hours` 固定 24 项，下标即小时 */
export interface HourlyHeatmap {
  hours: HourlyBucket[]
}

/** 周期性攻击者（Rust `PeriodicAttacker`） */
export interface PeriodicAttacker {
  ip: string
  ban_count: number
  /** 平均封禁间隔（秒） */
  avg_interval_secs: number
  interval_stddev: number
  /** 周期规律性评分 0-100，越高越像机器人 */
  periodicity_score: number
  jail_name: string
  /** 事件时间戳列表（Unix 秒） */
  timestamps: number[]
}

/** 协同攻击（Rust `CollaborativeAttack`） */
export interface CollaborativeAttack {
  jail_name: string
  window_start: number
  window_end: number
  ip_count: number
  ips: string[]
  total_bans: number
  /** 协同评分 0-100，越高越协同 */
  correlation_score: number
}

/** 攻击源网络分布（Rust `NetworkBlock`），按 IPv4 /24 或 IPv6 /48 聚合 */
export interface NetworkBlock {
  /** 子网前缀，如 "192.168.1" */
  subnet: string
  unique_ips: number
  total_bans: number
  last_banned_at: number
  /** 该子网内封禁次数最多的 IP */
  top_ip: string
}

/** 单 IP 攻击预测（Rust `AttackPrediction`） */
export interface AttackPrediction {
  ip: string
  ban_count: number
  jail_name: string
  last_ban_at: number
  /** 预期攻击间隔中位数（秒） */
  median_interval_secs: number
  predicted_next_attack: number
  /** 距预测时刻的剩余秒数（负数 = 已超期） */
  remaining_secs: number
  /** 置信度 0-100 */
  confidence: number
  /** "imminent"（<1h）/ "soon"（<6h）/ "later"（<24h）/ "distant" */
  urgency: string
}

/** Jail 级攻击趋势（Rust `JailAttackTrend`） */
export interface JailAttackTrend {
  jail_name: string
  bans_24h: number
  bans_7d: number
  /** "rising" / "stable" / "falling" */
  trend: string
  predicted_attackers_24h: number
}

/** 攻击预测汇总（Rust `AttackPredictionSummary`） */
export interface AttackPredictionSummary {
  /** 已按紧急程度排序 */
  predictions: AttackPrediction[]
  jail_trends: JailAttackTrend[]
  /** 预测 1 小时内会有攻击的 IP 数 */
  imminent_count: number
  /** 预测 24 小时内会有攻击的 IP 数 */
  within_24h_count: number
}

// ============================================================================
// 日志（log_viewer.rs）
// ============================================================================

/** 日志条目（Rust `LogEntry`） */
export interface LogEntry {
  line_number: number
  content: string
}

/** 日志分页响应（Rust `LogPageResponse`） */
export interface LogPageResponse {
  items: LogEntry[]
  total_lines: number
  page: number
  page_size: number
  total_pages: number
}

/** `GET /api/v1/logs` 查询参数（Rust `LogQueryParams`）；后端缺省 page=1、page_size=100（上限 500） */
export interface LogQueryParams {
  page?: number
  page_size?: number
  /** 日志级别过滤：ERROR / WARN / INFO / DEBUG */
  level?: string
  /** 关键词（后端按小写包含匹配） */
  keyword?: string
  /** 只返回此时间之后的日志行（行首前 19 字符按字典序比较，需形如 2026-07-12T07:17:40） */
  since?: string
}

// ============================================================================
// SSE 诊断与运行时健康（api.rs / runtime_status.rs）
// ============================================================================

/** 单条 SSE 流的连接状态（Rust `SseStreamStatus`） */
export interface SseStreamStatus {
  current_connections: number
  max_connections: number
  /** 已达**本流**上限：客户端此时应停止重连，等用户手动重试 */
  limit_reached: boolean
}

/**
 * `GET /api/v1/stats/sse-status` 响应（Rust `SseStatusResponse`）。
 * 两条流各自独立的上限（events 10 / logs 5）；`limit_reached` 必须按所属流判断，
 * 不能用一条流的上限推断另一条（这正是修复前的缺陷）。
 */
export interface SseStatusResponse {
  /** `/api/v1/events` 管理事件流 */
  events: SseStreamStatus
  /** `/api/v1/logs/stream` 日志流 */
  logs: SseStreamStatus
}

/**
 * `GET /health`（与 `/healthz`）响应（Rust `RuntimeSnapshot`）。
 * 注意：该端点不套 ApiResponse 信封；未就绪时 HTTP 状态为 503 但响应体仍是本结构。
 */
export interface RuntimeSnapshot {
  /** "ok"（netlink 与 /proc/firewall 均就绪）或 "degraded" */
  status: 'ok' | 'degraded'
  netlink_ready: boolean
  kmod_proc_present: boolean
  ban_cache_initialized: boolean
  ban_history_initialized: boolean
  active_bans: number
}
