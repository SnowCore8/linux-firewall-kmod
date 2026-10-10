// 资源面的具名响应载荷：封禁 / 白名单 / 配置 / 日志 / SSE 诊断。
//
// 这里的每一个 struct 都**逐字**对应 contract/http.fwidl 的一个 type 块：结构体名 =
// 契约类型名，json tag = 契约字段的线上 key。这不是为了好看，而是契约门禁的锚点——
// verify_http.py 的载荷核对按类型名在 Go 源码里找 struct，再把两边的 key 做双向差集。
// 用 map[string]any 写字面量时，字段没有任何具名承载，跨层核对在这一层失去锚点
// （缺口基线里那条 type-unmapped 说的就是这件事），前端 types.ts 改个名也不会红。
//
// 因此新增响应一律**加 struct**，不要回到 map：
//   - key 拼写与顺序由 struct 声明顺序决定（encoding/json 按声明顺序输出）；
//   - 可选字段用指针或显式零值，按契约那句「失败时 data 为 null」的口径给值；
//   - 字段含义写在这里，契约的 type 块写它的注释，两边各留一份说明而不是互相引用。
package http

import (
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/bans"
)

// PaginatedResponse 是列表类端点的统一分页信封（契约 PaginatedResponse<T>）。
//
// total 是**过滤前的全集条数**，items 是当前页；total_pages 由 total 与 page_size
// 向上取整得出。读侧只需要 items 也要把四个数写全：前端分页控件按 total_pages 决定
// 尾页，缺了它就只能把「这一页有几条」当总数显示。
type PaginatedResponse[T any] struct {
	Items      []T    `json:"items"`
	Total      uint64 `json:"total"`
	Page       uint32 `json:"page"`
	PageSize   uint32 `json:"page_size"`
	TotalPages uint32 `json:"total_pages"`
}

// BanResponse 是封禁表里一条活跃封禁（GET /api/v1/bans 的 items 元素）。
type BanResponse struct {
	IP               string `json:"ip"`
	Jail             string `json:"jail"`
	BannedAt         int64  `json:"banned_at"`
	RemainingSeconds int64  `json:"remaining_seconds"`
	Reason           string `json:"reason"`
	BanCount         uint32 `json:"ban_count"`
	IsPermanent      bool   `json:"is_permanent"`
}

// BanDetailResponse 是单个 IP 的封禁详情（GET /api/v1/bans/:ip/detail）。
//
// **未封禁不是错误**：is_banned=false 的 200 响应照样带历史与信誉读数（契约给这条路由
// 只编了 40006 = IP 非法）。前端详情面板正是靠这个形状在「解封之后还想看历史」时可用。
type BanDetailResponse struct {
	IP                   string  `json:"ip"`
	IsBanned             bool    `json:"is_banned"`
	JailName             string  `json:"jail_name"`
	Reason               string  `json:"reason"`
	BannedAt             int64   `json:"banned_at"`
	ExpiresAt            int64   `json:"expires_at"`
	IsPermanent          bool    `json:"is_permanent"`
	FailCount            uint32  `json:"fail_count"`
	BanCount             uint32  `json:"ban_count"`
	LastUnbannedAt       int64   `json:"last_unbanned_at"`
	WasPermanent         bool    `json:"was_permanent"`
	ProgressiveLevel     string  `json:"progressive_level"`
	NextBanDuration      string  `json:"next_ban_duration"`
	ReputationScore      uint32  `json:"reputation_score"`
	ReputationMultiplier float64 `json:"reputation_multiplier"`
}

// BanOperationResponse 是单条封禁/解封操作的结果（POST /api/v1/bans、
// DELETE /api/v1/bans/:ip、POST /api/v1/bans/unban-temporary）。
type BanOperationResponse struct {
	IP           string  `json:"ip"`
	Action       string  `json:"action"`
	Permanent    bool    `json:"permanent"`
	DurationSecs *uint64 `json:"duration_seconds"`
}

// BatchOperationResponse 是批量操作的汇总（POST /api/v1/bans/batch）。
//
// details 逐条给出失败原因（与请求里的 ips 同序），条数可以少于 total——只为失败的
// 那几条留原文，成功条目没有需要解释的东西。
type BatchOperationResponse struct {
	Total       uint64   `json:"total"`
	Succeeded   uint64   `json:"succeeded"`
	FailedCount uint64   `json:"failed_count"`
	Details     []string `json:"details"`
}

// CreateBanRequest 是 POST /api/v1/bans 的请求体。
//
// duration 用指针：契约把它声明成 Option<u64>，Go 侧要能原样表达「字段缺席」——单条封禁
// 里缺席与显式 0 同为永久（契约的这条路由就是这么定义的），但指针是契约类型本身，
// 用值类型会把「没写」读成「写了 0」，批量那条路由的缺省语义就不是 0 了。
type CreateBanRequest struct {
	IP       string  `json:"ip"`
	Duration *uint64 `json:"duration"`
	Reason   *string `json:"reason"`
}

// BatchBanRequest 是 POST /api/v1/bans/batch 的请求体。
//
// 与单条那条路由**共用不了**这个 struct 的地方是 duration 的缺省语义：这里缺席或 0 都是
// 「3600 秒的有时长封禁」，永不升格为永久（缺陷 HTTP_BATCH_BAN_BECOMES_PERMANENT 的
// resolution）。批量入口一旦把缺省读成永久，/api/v1/bans/unban-temporary 就看不见这批
// 条目（它只解临时），用户没有批量退路。
type BatchBanRequest struct {
	IPs      []string `json:"ips"`
	Duration *uint64  `json:"duration"`
	Reason   *string  `json:"reason"`
}

// WhitelistEntryResponse 是白名单的一条（前端 interface 名为 WhitelistEntry）。
type WhitelistEntryResponse struct {
	CIDR   string `json:"cidr"`
	Device string `json:"device"`
}

// WhitelistOperationResponse 是白名单增删操作的结果。
type WhitelistOperationResponse struct {
	CIDR   string `json:"cidr"`
	Action string `json:"action"`
}

// CreateWhitelistRequest 是 POST /api/v1/whitelist 的请求体。
type CreateWhitelistRequest struct {
	CIDR string `json:"cidr"`
}

// LogEntry 是一行日志：line_number 是它在文件里的物理行号（1 起）。
//
// 行号而不是数组下标：前端把 content 直接贴进 <pre>，用户要能拿行号去 grep 同一个文件。
type LogEntry struct {
	LineNumber uint64 `json:"line_number"`
	Content    string `json:"content"`
}

// LogPageResponse 是 GET /api/v1/logs 的分页载荷。
//
// total_lines 是**过滤后**的匹配行数（level/keyword/since 之后），前端据此算可翻页数；
// 与 PaginatedResponse.total 同义，但契约给日志单独起了名字，这里就照契约的形状写。
type LogPageResponse struct {
	Items      []LogEntry `json:"items"`
	TotalLines uint64     `json:"total_lines"`
	Page       uint32     `json:"page"`
	PageSize   uint32     `json:"page_size"`
	TotalPages uint32     `json:"total_pages"`
}

// SseStreamStatus 是一条 SSE 流的连接诊断。
//
// 两个计数在契约里是 usize，Go 侧对应 `int`（同为机器字长）——不是随手挑的无符号窄类型：
// 读数是 SSEStream 自己维护的名额账本，换类型只会多一次没有意义的转换。
type SseStreamStatus struct {
	CurrentConnections int  `json:"current_connections"`
	MaxConnections     int  `json:"max_connections"`
	LimitReached       bool `json:"limit_reached"`
}

// SseStatusResponse 是两条流各一份的诊断（GET /api/v1/stats/sse-status）。
//
// events 与 logs 的上限独立（10 / 5），limit_reached 由**所属流**判定：用一条流的上限
// 推断另一条，前端会在日志流被拒时判成「还没满」，把 503 当网络故障无限重连。
type SseStatusResponse struct {
	Events SseStreamStatus `json:"events"`
	Logs   SseStreamStatus `json:"logs"`
}

// ============================================================================
// 统计总览（GET /api/v1/stats）
// ============================================================================

// ChartData 是一组「标签 ↔ 数值」按下标对齐的图表数据。
//
// 两个切片**永远等长**：前端按 labels[i] 给 values[i] 命名，长度不一致会画出错位而不是
// 报错。取不到任何数据时两边都是空切片（不是 null），图表组件因此不需要判空分支。
type ChartData struct {
	Labels []string `json:"labels"`
	Values []uint64 `json:"values"`
}

// ThreatLevel 是实时威胁评估（契约 type ThreatLevel）。
//
// 四个读数都来自内核观测快照，不是再问一次内核：current_pps 是速率 EWMA 的短期窗口，
// pps_ratio 是它相对有效基线的倍数，ban_table_usage 是活跃封禁数 / 配置的封禁表条目上限，
// recent_bans 是最近 5 分钟的封禁条数。level 与 score 由这三路信号取最严重者折出。
type ThreatLevel struct {
	Level          string   `json:"level"`
	Score          uint8    `json:"score"`
	Factors        []string `json:"factors"`
	CurrentPps     uint64   `json:"current_pps"`
	PpsRatio       float64  `json:"pps_ratio"`
	BanTableUsage  float64  `json:"ban_table_usage"`
	RecentBans     uint64   `json:"recent_bans"`
	BaselineFrozen bool     `json:"baseline_frozen"`
	PeakHours      bool     `json:"peak_hours"`
}

// StatsResponse 是总览面板的一次读数（GET /api/v1/stats）。
//
// 三个口径写在这里而不是留给前端猜：
//   - today_bans 带真实时间窗（本地时区自然日 00:00 起，历史库 ban_events 计数），
//     与 total_bans（内核进程累计计数器）是两个不同的量；
//   - current_bans / total_bans / total_unbans / whitelist_count / packets_* 来自内核
//     统计快照的最新一刻，链路断开时它们是**陈旧值**（新鲜度由 /health 的链路字段判断）；
//   - failed_attempts 与 threat_level 的速率部分是**本进程**的计数与平滑结果，重启归零。
type StatsResponse struct {
	DaemonVersion string `json:"daemon_version"`
	KernelVersion string `json:"kernel_version"`
	TodayBans     uint64 `json:"today_bans"`

	FailedAttempts uint64 `json:"failed_attempts"`
	DdosEvents     uint64 `json:"ddos_events"`
	UptimeSeconds  uint64 `json:"uptime_seconds"`

	BanTrend            ChartData   `json:"ban_trend"`
	JailDistribution    ChartData   `json:"jail_distribution"`
	FailureReasons      ChartData   `json:"failure_reasons"`
	FailedAttemptsTrend ChartData   `json:"failed_attempts_trend"`
	CurrentBans         uint64      `json:"current_bans"`
	TotalBans           uint64      `json:"total_bans"`
	TotalUnbans         uint64      `json:"total_unbans"`
	WhitelistCount      uint64      `json:"whitelist_count"`
	PacketsDropped      uint64      `json:"packets_dropped"`
	PacketsAccepted     uint64      `json:"packets_accepted"`
	ThreatLevel         ThreatLevel `json:"threat_level"`
}

// ============================================================================
// 速率（GET /api/v1/rates/*）
// ============================================================================

// RateResponse 是一个源地址的当前速率（GET /api/v1/rates/current 的数组元素）。
//
// 八个数值都是**每秒速率**而不是累计计数：内核速率表对外语义就是速率
// （fw_rate.c:fw_rate_fill_row 填的是 smoothed_*），累计值留在内核侧做窗口滚动。
type RateResponse struct {
	IP                string `json:"ip"`
	PacketsPerSec     uint64 `json:"packets_per_sec"`
	BytesPerSec       uint64 `json:"bytes_per_sec"`
	SynPacketsPerSec  uint64 `json:"syn_packets_per_sec"`
	UdpPacketsPerSec  uint64 `json:"udp_packets_per_sec"`
	IcmpPacketsPerSec uint64 `json:"icmp_packets_per_sec"`
	AckPacketsPerSec  uint64 `json:"ack_packets_per_sec"`
	RstPacketsPerSec  uint64 `json:"rst_packets_per_sec"`
	FinPacketsPerSec  uint64 `json:"fin_packets_per_sec"`
}

// RateHistoryResponse 是全局速率的一次采样点（GET /api/v1/rates/history 的数组元素）。
//
// 采样节奏 = 内核事件泵的查询周期：每问一次速率表就落一个点，而不是按墙上时钟插值补
// 空白——补出来的点没有对应的内核回答，图上看着连续，实际是猜的。
type RateHistoryResponse struct {
	Timestamp  uint64 `json:"timestamp"`
	TotalPps   uint64 `json:"total_pps"`
	TotalBps   uint64 `json:"total_bps"`
	TrackedIps uint32 `json:"tracked_ips"`
}

// RateWindowSnapshot 是速率的多窗口 EWMA（GET /api/v1/rates/windows）。
//
// 短/中/长 = 5 秒 / 60 秒 / 300 秒，三档都在守护进程侧派生（内核只回答「自上次查询以来
// 的平均速率」，没有窗口概念）。还没有任何样本时六个数都是 0，与「速率为 0」不可区分——
// 契约给这条路由只编了 code 0，所以这里不额外造一个 initialized 字段：读侧要区分就看
// /api/v1/rates/current 有没有速率表。
type RateWindowSnapshot struct {
	PpsShort uint64 `json:"pps_short"`
	PpsMid   uint64 `json:"pps_mid"`
	PpsLong  uint64 `json:"pps_long"`
	BpsShort uint64 `json:"bps_short"`
	BpsMid   uint64 `json:"bps_mid"`
	BpsLong  uint64 `json:"bps_long"`
}

// ============================================================================
// 内核协议分布快照（GET /api/v1/stats/{packet-sizes,ttl-distribution,ip-fragments,
// udp-ports,icmp-types,port-scanners,service-probes}）
// ============================================================================

// PacketSizeDistributionResponse 是「标签 + 计数 + 百分比」三件套直方图，
// packet-sizes 与 ttl-distribution 共用同一套字段（契约是两个独立 type 块，字段一致）。
//
// 标签恒等于内核的分桶数（内核未命中任何桶时也是一排 0），计数与百分比是**自模块加载起
// 的累计**：内核的直方图数组只在 init/unload 归零，采样时的 flush 只搬运收发计数。
type PacketSizeDistributionResponse struct {
	Labels      []string  `json:"labels"`
	Counts      []uint64  `json:"counts"`
	Total       uint64    `json:"total"`
	Percentages []float64 `json:"percentages"`
}

// TtlDistributionResponse 是 TTL 分桶直方图。见 PacketSizeDistributionResponse 的口径。
type TtlDistributionResponse struct {
	Labels      []string  `json:"labels"`
	Counts      []uint64  `json:"counts"`
	Total       uint64    `json:"total"`
	Percentages []float64 `json:"percentages"`
}

// IpFragmentStatsResponse 是分片占比。
//
// fragment_ratio 是**百分数 0-100**（不是 0-1 比例），与契约字段注释一致；总包数为 0 时
// 报 0 而不是 NaN——encoding/json 遇到 NaN 会直接报错、整个响应发不出去，而「还没有流量」
// 显然不该让面板那一栏变成请求失败。
type IpFragmentStatsResponse struct {
	TotalPackets    uint64  `json:"total_packets"`
	FragmentPackets uint64  `json:"fragment_packets"`
	FragmentRatio   float64 `json:"fragment_ratio"`
}

// UdpPortEntry 是一个 UDP 端口的命中读数。
type UdpPortEntry struct {
	Port         uint16 `json:"port"`
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	LastSeenSecs uint64 `json:"last_seen_secs"`
}

// UdpPortDistributionResponse 是 UDP 端口分布。
//
// ports 是**本次快照带出的行**（netlink 定长载荷只容 64 行，内核按端口升序填充）；
// total_entries 原样透传内核在同一字段里给的数——那是**本次打包的行数**，不是表内跟踪
// 总数（内核手里有总数但没放进这条响应，见 defect HTTP_UDP_PORT_TOTAL_IS_PACKED_COUNT）；
// max_entries 是内核的跟踪容量（512）。三者可以互不相等，且必须都报：只报 ports 就把
// 「截断」这件事藏掉了。
type UdpPortDistributionResponse struct {
	Ports        []UdpPortEntry `json:"ports"`
	TotalEntries uint64         `json:"total_entries"`
	MaxEntries   uint64         `json:"max_entries"`
}

// IcmpTypeEntry 是一个 ICMP type/code 组合的命中读数。
//
// 契约字段名 `type` 与 Go 关键字冲突，靠 json tag 保持线上 key 不变——线上形状才是契约。
type IcmpTypeEntry struct {
	Type         uint8  `json:"type"`
	Code         uint8  `json:"code"`
	Packets      uint64 `json:"packets"`
	Bytes        uint64 `json:"bytes"`
	LastSeenSecs uint64 `json:"last_seen_secs"`
}

// IcmpTypeDistributionResponse 是 ICMP 类型分布，截断口径同 UDP。
type IcmpTypeDistributionResponse struct {
	Types        []IcmpTypeEntry `json:"types"`
	TotalEntries uint64          `json:"total_entries"`
	MaxEntries   uint64          `json:"max_entries"`
}

// PortScannerEntry 是一个疑似端口扫描者。
//
// unique_ports 是内核侧的**去重端口并集下界**（条目生命周期内只增不减，上限
// PORT_SCAN_SEEN_MAX=32，到顶后不再增长），不是窗口内计数。
type PortScannerEntry struct {
	IP          string `json:"ip"`
	UniquePorts uint32 `json:"unique_ports"`
	Packets     uint64 `json:"packets"`
}

// PortScanResponse 是端口扫描检出结果。
//
// total_detected 是内核的**累计检出事件计数**（每次判定 +1，模块重载归零），与 scanners
// 的行数不是同一个量——后者只带最近活跃的前 20 个地址。与 ServiceProbeResponse 的同名字段
// 口径不同，见 defect HTTP_SCANNER_TOTAL_COUNT_ASYMMETRY。
type PortScanResponse struct {
	Threshold     uint32             `json:"threshold"`
	TotalDetected uint32             `json:"total_detected"`
	Scanners      []PortScannerEntry `json:"scanners"`
}

// ServiceProbeEntry 是一个多协议探测者。
type ServiceProbeEntry struct {
	IP            string `json:"ip"`
	ProtocolCount uint32 `json:"protocol_count"`
	Packets       uint64 `json:"packets"`
}

// ServiceProbeResponse 是服务探测检出结果。
//
// total_detected 与 PortScanResponse 对齐（缺陷 HTTP_SERVICE_PROBE_NO_TOTAL）：前端两处
// 「检出 N 个」文案共用同一个字段名，缺一侧就得写分支。
type ServiceProbeResponse struct {
	Threshold     uint32              `json:"threshold"`
	TotalDetected uint32              `json:"total_detected"`
	Probes        []ServiceProbeEntry `json:"probes"`
}

// ============================================================================
// 热力图与异常检测
// ============================================================================

// HourlyBucket 是一个小时桶（本地时区的 hour-of-day，0..23）。
type HourlyBucket struct {
	Hour           uint32 `json:"hour"`
	Bans           uint64 `json:"bans"`
	FailedAttempts uint64 `json:"failed_attempts"`
	DdosEvents     uint64 `json:"ddos_events"`
}

// HourlyHeatmap 是 24 项定长热力图：下标即小时，缺数据的小时也要占位。
type HourlyHeatmap struct {
	Hours [24]HourlyBucket `json:"hours"`
}

// FeatureValue 是一个特征名与其当前/基线取值。
type FeatureValue struct {
	Name  string  `json:"name"`
	Value float64 `json:"value"`
}

// DimensionScore 是单个维度的偏差分（0-1 归一化）。
type DimensionScore struct {
	Name  string  `json:"name"`
	Score float64 `json:"score"`
}

// IpAnomalyEntry 是一个源地址相对同批地址群体的行为离群读数。
type IpAnomalyEntry struct {
	IP         string           `json:"ip"`
	Score      float64          `json:"score"`
	Dimensions []DimensionScore `json:"dimensions"`
}

// AnomalyResponse 是异常检测结果（只观测，不触发任何封禁）。
//
// global_features 为 null 表示本轮样本不足（未达最小样本护栏）：此时两条基线与
// global_dimensions 都是空数组、global_score 是 0。用「空」而不是「0 基线」是刻意的——
// 0 基线会让任何非零当前值都算成无穷偏离，图上就是一片红。
type AnomalyResponse struct {
	GlobalScore       float64          `json:"global_score"`
	GlobalDimensions  []DimensionScore `json:"global_dimensions"`
	GlobalFeatures    []FeatureValue   `json:"global_features"`
	GlobalBaselineP50 []FeatureValue   `json:"global_baseline_p50"`
	GlobalBaselineP95 []FeatureValue   `json:"global_baseline_p95"`
	GlobalSampleCount uint64           `json:"global_sample_count"`
	IpAnomalies       []IpAnomalyEntry `json:"ip_anomalies"`
	Timestamp         int64            `json:"timestamp"`
}

// ============================================================================
// 载荷构造helper
// ============================================================================

// chart 把已经排好序的标签与数值折成 ChartData，保证两条切片等长。
//
// 截断而不是补零：长度不等说明产出方的标签与数值本来就不是同一批，多出来的那半截没有
// 名字也没有归属，画出来只会误导读图的人。
func chart(labels []string, values []uint64) ChartData {
	if labels == nil {
		labels = []string{}
	}
	if values == nil {
		values = []uint64{}
	}
	if n := min(len(labels), len(values)); len(labels) != n || len(values) != n {
		labels, values = labels[:n], values[:n]
	}
	return ChartData{Labels: labels, Values: values}
}

// percentages 把分桶计数折成百分数（0-100），总数为 0 时逐项 0。
func percentages(counts []uint64, total uint64) []float64 {
	out := make([]float64, len(counts))
	if total == 0 {
		return out
	}
	for i, c := range counts {
		out[i] = float64(c) / float64(total) * 100
	}
	return out
}

// banToResponse 把内存镜像的一条封禁映射成契约载荷。
//
// remaining_seconds 对永久封禁写 0：契约该字段是 i64 且没有 null 形状，而前端把
// is_permanent 当「不显示倒计时」的开关，剩余秒数在永久条目上没有读者。
func banToResponse(info bans.BanInfo, now int64) BanResponse {
	remaining := int64(0)
	if !info.IsPermanent && info.ExpiresAt > now {
		remaining = info.ExpiresAt - now
	}
	return BanResponse{
		IP:               info.IP,
		Jail:             info.JailName,
		BannedAt:         info.BannedAt,
		RemainingSeconds: remaining,
		Reason:           info.Reason,
		BanCount:         info.BanCount,
		IsPermanent:      info.IsPermanent,
	}
}

// banResponses 把整张活跃封禁表映射成契约载荷（REST 全集与 SSE bans 域共用）。
func banResponses(infos []bans.BanInfo, now int64) []BanResponse {
	out := make([]BanResponse, 0, len(infos))
	for _, info := range infos {
		out = append(out, banToResponse(info, now))
	}
	return out
}
