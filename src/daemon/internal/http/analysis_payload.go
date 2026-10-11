// 历史库分析面的具名响应载荷。
//
// 每一个 struct 都**逐字**对应 contract/http.fwidl 的一个 type 块：结构体名 = 契约类型名，
// json tag = 契约字段的线上 key（规矩见 payload.go 顶部）。这一批是从
// internal/analysis 的计算结果**映射**过来的：分析层按自己的口径命名读数（regularity、
// jitter、event_count……），载荷按契约的口径命名（periodicity_score、interval_stddev、
// ban_count……）。两层同名会让契约门禁的「按类型名找 struct」撞上分析层那一个（它按文件
// 顺序取第一个命中），字段核对因此变成看运气——所以 analysis 侧的类型一律叫 `*Finding`。
//
// 映射时做的都是**同一件事的不同问法**之间的换算，不新造读数：
//   - 计数换名：event_count → ban_count（同一批封禁事件的两种说法）；
//   - 尺度换算：0-1 的置信度 → u8 百分数（契约里 confidence/periodicity_score 都是 0-100）；
//   - 相对量在读取时刻算：remaining_secs = predicted_next_attack - 本次读取的时刻。
package http

import (
	"fmt"
	"math"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/analysis"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/decision"
	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// RecidivismResponse 是复发统计（GET /api/v1/stats/recidivism）。
//
// recidivism_rate 是**百分数 0-100**（与 ban-effectiveness 同一个口径，见契约的
// HTTP_RECIDIVISM_RATE_UNIT）：库里算出来的就是 ×100 的数，这里原样搬，不再除回去。
type RecidivismResponse struct {
	TotalIPs       uint64            `json:"total_ips"`
	RecidivistIPs  uint64            `json:"recidivist_ips"`
	RecidivismRate float64           `json:"recidivism_rate"`
	PermanentBans  uint64            `json:"permanent_bans"`
	TopRecidivists []RecidivistEntry `json:"top_recidivists"`
}

// RecidivistEntry 是复发榜上的一条（被封过 ≥2 次的地址）。
type RecidivistEntry struct {
	IP           string `json:"ip"`
	BanCount     uint32 `json:"ban_count"`
	LastBannedAt int64  `json:"last_banned_at"`
	WasPermanent bool   `json:"was_permanent"`
}

// ReputationEntryResponse 是一个低信誉地址的读数（GET /api/v1/stats/reputation）。
//
// total_failures / total_bans 是**该列开始记录以来**的累计数：这两列比表晚，迁移只补列
// 不补史，老地址从 0 起算（契约字段注释同此口径）。
type ReputationEntryResponse struct {
	IP                  string  `json:"ip"`
	Score               uint32  `json:"score"`
	LastFailureAt       int64   `json:"last_failure_at"`
	TotalFailures       uint32  `json:"total_failures"`
	TotalBans           uint32  `json:"total_bans"`
	ThresholdMultiplier float64 `json:"threshold_multiplier"`
}

// PeriodicAttacker 是周期性攻击者（GET /api/v1/stats/periodic-attackers）。
type PeriodicAttacker struct {
	IP               string  `json:"ip"`
	BanCount         uint32  `json:"ban_count"`
	AvgIntervalSecs  float64 `json:"avg_interval_secs"`
	IntervalStddev   float64 `json:"interval_stddev"`
	PeriodicityScore uint8   `json:"periodicity_score"`
	JailName         string  `json:"jail_name"`
	Timestamps       []int64 `json:"timestamps"`
}

// CollaborativeAttack 是多源联动窗口（GET /api/v1/stats/collaborative-attacks）。
//
// ip_count 与 ips 的长度可以不等：ips 带出的是窗口内参与者（截断到前若干个），
// ip_count 是那一窗口内的**唯一地址数**，读侧靠差值知道还有多少人没列出来。
type CollaborativeAttack struct {
	JailName         string   `json:"jail_name"`
	WindowStart      int64    `json:"window_start"`
	WindowEnd        int64    `json:"window_end"`
	IPCount          uint32   `json:"ip_count"`
	IPs              []string `json:"ips"`
	TotalBans        uint32   `json:"total_bans"`
	CorrelationScore uint8    `json:"correlation_score"`
}

// NetworkBlock 是同一 /24（v6 为 /48）网段的封禁聚合
// （GET /api/v1/stats/network-distribution）。
type NetworkBlock struct {
	Subnet       string `json:"subnet"`
	UniqueIPs    uint32 `json:"unique_ips"`
	TotalBans    uint32 `json:"total_bans"`
	LastBannedAt int64  `json:"last_banned_at"`
	TopIP        string `json:"top_ip"`
}

// AttackPrediction 是一个地址的下次动手估计
// （/api/v1/stats/attack-predictions 的 predictions 元素）。
//
// remaining_secs 可以为负：预测时刻已经过去（该地址按它的周期早就该再来了），
// 面板把它读成「随时可能」而不是「还有 -120 秒」。
type AttackPrediction struct {
	IP                  string  `json:"ip"`
	BanCount            uint32  `json:"ban_count"`
	JailName            string  `json:"jail_name"`
	LastBanAt           int64   `json:"last_ban_at"`
	MedianIntervalSecs  float64 `json:"median_interval_secs"`
	PredictedNextAttack int64   `json:"predicted_next_attack"`
	RemainingSecs       int64   `json:"remaining_secs"`
	Confidence          uint8   `json:"confidence"`
	Urgency             string  `json:"urgency"`
}

// JailAttackTrend 是一个 jail 的近 24h / 7d 封禁走向。
type JailAttackTrend struct {
	JailName              string `json:"jail_name"`
	Bans24h               uint32 `json:"bans_24h"`
	Bans7d                uint32 `json:"bans_7d"`
	Trend                 string `json:"trend"`
	PredictedAttackers24h uint32 `json:"predicted_attackers_24h"`
}

// AttackPredictionSummary 是预测面板的整体载荷
// （GET /api/v1/stats/attack-predictions）。
type AttackPredictionSummary struct {
	Predictions    []AttackPrediction `json:"predictions"`
	JailTrends     []JailAttackTrend  `json:"jail_trends"`
	ImminentCount  uint32             `json:"imminent_count"`
	Within24HCount uint32             `json:"within_24h_count"`
}

// ThresholdRecommendation 是一个 jail 的失败阈值调整建议。
//
// recidivism_rate 与复发统计同口径（百分数 0-100，按地址而非按事件）。
type ThresholdRecommendation struct {
	JailName             string  `json:"jail_name"`
	CurrentThreshold     uint32  `json:"current_threshold"`
	RecommendedThreshold uint32  `json:"recommended_threshold"`
	Direction            string  `json:"direction"`
	TotalBans            uint32  `json:"total_bans"`
	UniqueIPs            uint32  `json:"unique_ips"`
	RecidivistIPs        uint32  `json:"recidivist_ips"`
	RecidivismRate       float64 `json:"recidivism_rate"`
	AvgBansPerIP         float64 `json:"avg_bans_per_ip"`
	Reason               string  `json:"reason"`
	Confidence           uint8   `json:"confidence"`
}

// ThresholdRecommendationResponse 是阈值建议的整体载荷。
//
// summary 是对**这份列表**的一句话交代（含「几个 jail 没进列表」），面板顶部直接用。
type ThresholdRecommendationResponse struct {
	Recommendations []ThresholdRecommendation `json:"recommendations"`
	Summary         string                    `json:"summary"`
}

// BanDurationRecommendation 是一个 jail 的封禁时长调整建议。
//
// current_ban_time 是 i32（契约如此）：配置里负数表示永久封禁，而永久的 jail **不进**
// 这份列表（没有时长可调），因此列表内的值恒为非负。缺它是因为只报「建议改成多少」而
// 不报「现在是多少」，运维无法判断建议是否已被自己采纳。
type BanDurationRecommendation struct {
	JailName           string `json:"jail_name"`
	CurrentBanTime     int32  `json:"current_ban_time"`
	RecidivistCount    uint32 `json:"recidivist_count"`
	MedianReturnSecs   uint64 `json:"median_return_secs"`
	RecommendedBanTime uint64 `json:"recommended_ban_time"`
	Reason             string `json:"reason"`
	NeedsAdjustment    bool   `json:"needs_adjustment"`
}

// BanDurationRecommendationResponse 是时长建议的整体载荷。
type BanDurationRecommendationResponse struct {
	Recommendations []BanDurationRecommendation `json:"recommendations"`
	Summary         string                      `json:"summary"`
}

// BanLevelEffectiveness 是渐进式封禁某一级的成效
// （GET /api/v1/stats/ban-effectiveness 的 levels 元素）。
//
// 「级」就是该地址被封的**第几次**（第 1 级 = 基础时长，第 2 级 = 30 分钟，第 3 级 =
// 24 小时，第 4 级 = 永久及以后，见 decision.ProgressiveDuration）。
//
// recidivism_rate 在这里的含义与复发统计略不同，是**这一级往下走的比率**：到达第 L 级的
// 地址里，有多少又升到了第 L+1 级（百分数 0-100）。这一级越没拦住，比率越高。
type BanLevelEffectiveness struct {
	Level          uint8   `json:"level"`
	Label          string  `json:"label"`
	TotalIPs       uint32  `json:"total_ips"`
	RecidivistIPs  uint32  `json:"recidivist_ips"`
	RecidivismRate float64 `json:"recidivism_rate"`
	PermanentBans  uint32  `json:"permanent_bans"`
	Verdict        string  `json:"verdict"`
}

// BanEffectivenessResponse 是分级成效的整体载荷。
type BanEffectivenessResponse struct {
	Levels                []BanLevelEffectiveness `json:"levels"`
	TotalUniqueIPs        uint32                  `json:"total_unique_ips"`
	OverallRecidivismRate float64                 `json:"overall_recidivism_rate"`
	Summary               string                  `json:"summary"`
}

// BanDurationHistogramResponse 是封禁时长的分布直方图
// （GET /api/v1/stats/ban-duration-histogram）。
//
// labels/counts 等长同下标，total = counts 之和。落在「未知」之外：迁移前写的旧行没有
// 时长读数，不进任何一桶也不进 total（宁可少算，不把不知道画成 0 秒）。
type BanDurationHistogramResponse struct {
	Labels []string `json:"labels"`
	Counts []uint64 `json:"counts"`
	Total  uint64   `json:"total"`
}

// AttackGeoResponse 是攻击源地理分布（GET /api/v1/stats/attack-geo）。
//
// 本守护进程**没有 GeoIP 读库**（配置项 geoip_db_path 无人消费，见契约的
// HTTP_GEOIP_NOT_IMPLEMENTED），因此 geoip_enabled 恒为 false、points 恒为空、两个计数
// 恒为 0；本机坐标三件套仍有真源（config 的 server_latitude/longitude），照常给出。
type AttackGeoResponse struct {
	GeoipEnabled         bool       `json:"geoip_enabled"`
	Points               []GeoPoint `json:"points"`
	TotalIPs             uint32     `json:"total_ips"`
	LocatedIPs           uint32     `json:"located_ips"`
	ServerLatitude       *float64   `json:"server_latitude"`
	ServerLongitude      *float64   `json:"server_longitude"`
	ServerLocationSource string     `json:"server_location_source"`
}

// GeoPoint 是一个定位结果点。当前没有任何产出路径会构造它（points 恒空），字段形状
// 仍按契约保留：前端按这张表画地图，缺了名字就连不上。
type GeoPoint struct {
	Latitude     float64 `json:"latitude"`
	Longitude    float64 `json:"longitude"`
	CountryCode  string  `json:"country_code"`
	Country      string  `json:"country"`
	City         string  `json:"city"`
	Subdivision  string  `json:"subdivision"`
	UniqueIPs    uint32  `json:"unique_ips"`
	TotalBans    uint32  `json:"total_bans"`
	TopIP        string  `json:"top_ip"`
	LastBannedAt int64   `json:"last_banned_at"`
}

// JailResponse 是一个 jail 的配置与运行时读数（GET /api/v1/jails 的元素）。
//
// 三项乘数与 is_peak_hours 来自判定层的**常量与时刻**（decision 包），不是配置项；
// effective_max_retries 是「此刻一个外部新地址实际面对的阈值」= ceil(max_retries ×
// 高峰期系数)，信誉系数取满分 1.0——内网系数与信誉系数都**按来源地址**生效，
// 不属于 jail，jail 级的读数不能把它们乘进去（乘了就变成「这个 jail 对所有地址的阈值」，
// 而那个数不存在）。
//
// ban_count 是**当前活跃**封禁数（内存镜像，与 /api/v1/stats 的 current_bans 同源），
// 不是历史累计——后者在 ban_events 里，由 /stats/ban-effectiveness 那一面回答。
// 后五个计数器是本进程解析日志以来的累计值，重启归零；jail 尚未产生任何读数的字段记 0。
type JailResponse struct {
	Name                 string  `json:"name"`
	Enabled              bool    `json:"enabled"`
	BanCount             uint64  `json:"ban_count"`
	MaxRetries           uint32  `json:"max_retries"`
	EffectiveMaxRetries  uint32  `json:"effective_max_retries"`
	Findtime             uint32  `json:"findtime"`
	BanTime              int32   `json:"ban_time"`
	IsPeakHours          bool    `json:"is_peak_hours"`
	PeakHoursMultiplier  float64 `json:"peak_hours_multiplier"`
	InternalIPMultiplier float64 `json:"internal_ip_multiplier"`
	LinesParsed          uint64  `json:"lines_parsed"`
	RegexMatches         uint64  `json:"regex_matches"`
	IPsExtracted         uint64  `json:"ips_extracted"`
	FailedAttempts       uint64  `json:"failed_attempts"`
	BansTriggered        uint64  `json:"bans_triggered"`
}

// u8Score 把 0-100 的分收进 u8：四舍五入后钳到 [0,100]。
//
// 分析层的分本来就是 0-100 的浮点（regularity / collaboration score），契约声明 u8 是
// 要它在面板上就是个百分数刻度。NaN 走钳位下界（math.Round(NaN)=NaN，转 uint8 是未定义值）。
func u8Score(score float64) uint8 {
	if math.IsNaN(score) || score <= 0 {
		return 0
	}
	rounded := math.Round(score)
	if rounded >= 100 {
		return 100
	}
	return uint8(rounded)
}

// mapPeriodicAttackers 把周期检测的读数折成载荷。
func mapPeriodicAttackers(findings []analysis.PeriodicAttackFinding) []PeriodicAttacker {
	out := make([]PeriodicAttacker, 0, len(findings))
	for _, f := range findings {
		out = append(out, PeriodicAttacker{
			IP:               f.IP,
			BanCount:         uint32(f.EventCount),
			AvgIntervalSecs:  f.AvgInterval,
			IntervalStddev:   f.StdDev,
			PeriodicityScore: u8Score(f.Regularity),
			JailName:         f.JailName,
			Timestamps:       append([]int64{}, f.Timestamps...),
		})
	}
	return out
}

// mapCollaborativeAttacks 把联动窗口读数折成载荷。
func mapCollaborativeAttacks(findings []analysis.CollaborativeAttackFinding) []CollaborativeAttack {
	out := make([]CollaborativeAttack, 0, len(findings))
	for _, f := range findings {
		out = append(out, CollaborativeAttack{
			JailName:         f.JailName,
			WindowStart:      f.WindowStart,
			WindowEnd:        f.WindowEnd,
			IPCount:          uint32(f.UniqueIPs),
			IPs:              append([]string{}, f.IPs...),
			TotalBans:        uint32(f.BanCount),
			CorrelationScore: u8Score(f.Score),
		})
	}
	return out
}

// mapNetworkBlocks 把网段聚合读数折成载荷。
//
// 分析层的 representative_ip 就是载荷的 top_ip（该网段内被封次数最多的地址），换个名字
// 是因为契约按「面板上那一列显示什么」命名。
func mapNetworkBlocks(rows []analysis.NetworkDistribution) []NetworkBlock {
	out := make([]NetworkBlock, 0, len(rows))
	for _, r := range rows {
		out = append(out, NetworkBlock{
			Subnet:       r.Subnet,
			UniqueIPs:    uint32(r.UniqueIPs),
			TotalBans:    uint32(r.TotalBans),
			LastBannedAt: r.LastBannedAt,
			TopIP:        r.RepresentativeIP,
		})
	}
	return out
}

// mapReputationEntries 把信誉读数折成载荷。
//
// threshold_multiplier 直接取判定层的信誉系数（decision.ReputationMultiplier：80 分以上
// 1.0、50 分以上 0.8、其余 0.5）——载荷里这一栏要回答的就是「这个分数现在让阈值放宽了几成」，
// 用判定层那一份算式而不是在这里重抄一遍分段，两处才会一起改。
func mapReputationEntries(reps []persist.IPReputation) []ReputationEntryResponse {
	out := make([]ReputationEntryResponse, 0, len(reps))
	for _, r := range reps {
		lastFailure := int64(0)
		if r.LastFailure != nil {
			lastFailure = *r.LastFailure
		}
		out = append(out, ReputationEntryResponse{
			IP:                  r.IP,
			Score:               uint32(clampInt(r.Score)),
			LastFailureAt:       lastFailure,
			TotalFailures:       uint32(clampInt(r.TotalFailures)),
			TotalBans:           uint32(clampInt(r.TotalBans)),
			ThresholdMultiplier: reputationMultiplier(r.Score),
		})
	}
	return out
}

// clampInt 把负数收进 0：库里这几列都是计数，出现负值只能是数据被写坏，
// 载荷的类型是 u32，让负数直接转换会得到一个巨大的数。
func clampInt(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

// reputationMultiplier 取判定层的信誉系数（≥80 → 1.0，≥50 → 0.8，其余 0.5）。
//
// 转调 decision.ReputationMultiplier 而不是在这里重抄一遍分段：载荷里 threshold_multiplier
// 要回答的就是「这个分数现在让阈值放宽了几成」，那件事只有判定层那一份算式说了算，
// 两处各写一遍迟早会给出不同的数（面板显示的系数与实际生效的阈值对不上）。
func reputationMultiplier(score int) float64 {
	if score < 0 {
		score = 0
	}
	return decision.ReputationMultiplier(uint32(score))
}

// mapPredictions 把攻击预测折成整体载荷。remaining_secs 以**本次读取的时刻**为基准。
func mapPredictions(summary *analysis.PredictionSummary, now time.Time) AttackPredictionSummary {
	out := AttackPredictionSummary{
		Predictions: []AttackPrediction{},
		JailTrends:  []JailAttackTrend{},
	}
	if summary == nil {
		return out
	}
	nowSecs := now.Unix()
	for _, p := range summary.Predictions {
		out.Predictions = append(out.Predictions, AttackPrediction{
			IP:                  p.IP,
			BanCount:            uint32(p.EventCount),
			JailName:            p.JailName,
			LastBanAt:           p.LastBanAt,
			MedianIntervalSecs:  p.MedianPeriod,
			PredictedNextAttack: p.NextAttackAt,
			RemainingSecs:       p.NextAttackAt - nowSecs,
			Confidence:          u8Score(p.Confidence),
			Urgency:             p.Urgency,
		})
	}
	for _, t := range summary.JailTrends {
		out.JailTrends = append(out.JailTrends, JailAttackTrend{
			JailName:              t.JailName,
			Bans24h:               uint32(clampInt(t.Bans24h)),
			Bans7d:                uint32(clampInt(t.Bans7d)),
			Trend:                 t.Trend,
			PredictedAttackers24h: uint32(clampInt(t.PredictedAttackers)),
		})
	}
	out.ImminentCount = uint32(clampInt(summary.ImminentCount))
	out.Within24HCount = uint32(clampInt(summary.Within24hCount))
	return out
}

// mapThresholdRecommendations 把阈值建议折成载荷，并**只保留配置里现存的 jail**。
//
// 过滤是为了不交付兜底值：分析层查不到该 jail 的当前阈值时会给一个默认数（5），
// 而载荷里的 current_threshold 长得像读数。事件里的 jail 可能已经不在配置里
// （jail 被删掉、或那条封禁来自 API 的手工路径 "api"），对这些 jail 谈「把阈值从几改到几」
// 没有落点。
func mapThresholdRecommendations(
	findings []analysis.ThresholdFinding,
	known func(jail string) bool,
) ThresholdRecommendationResponse {
	out := ThresholdRecommendationResponse{Recommendations: []ThresholdRecommendation{}}
	changes := 0
	for _, f := range findings {
		if !known(f.JailName) {
			continue
		}
		if f.Direction != "maintain" {
			changes++
		}
		out.Recommendations = append(out.Recommendations, ThresholdRecommendation{
			JailName:             f.JailName,
			CurrentThreshold:     uint32(clampInt(f.CurrentValue)),
			RecommendedThreshold: uint32(clampInt(f.RecommendedVal)),
			Direction:            f.Direction,
			TotalBans:            uint32(clampInt(f.TotalBans)),
			UniqueIPs:            uint32(clampInt(f.UniqueIPs)),
			RecidivistIPs:        uint32(clampInt(f.RecidivistIPs)),
			RecidivismRate:       f.RecidivismRate,
			AvgBansPerIP:         f.AvgBansPerIP,
			Reason:               f.Explanation,
			Confidence:           u8Score(f.Confidence * 100),
		})
	}
	out.Summary = fmt.Sprintf(
		"近 7 天有 %d 个 jail 的样本达到门槛，其中 %d 个建议调整阈值（按复发率降序）",
		len(out.Recommendations), changes,
	)
	return out
}

// mapBanDurationRecommendations 把时长建议折成载荷。
//
// needs_adjustment 就是分析层的 is_sufficient 取反：契约问「要不要改」，计算层答
// 「当前够不够」，是同一件事的两面，不另设判据。
func mapBanDurationRecommendations(
	findings []analysis.BanDurationFinding,
	known func(jail string) bool,
) BanDurationRecommendationResponse {
	out := BanDurationRecommendationResponse{Recommendations: []BanDurationRecommendation{}}
	needs := 0
	for _, f := range findings {
		if !known(f.JailName) {
			continue
		}
		if !f.IsSufficient {
			needs++
		}
		out.Recommendations = append(out.Recommendations, BanDurationRecommendation{
			JailName:           f.JailName,
			CurrentBanTime:     int32(f.CurrentDuration),
			RecidivistCount:    uint32(clampInt(f.RecidivistCount)),
			MedianReturnSecs:   uint64(math.Round(f.MedianInterval)),
			RecommendedBanTime: uint64(clampInt64(f.RecommendedDuration)),
			Reason:             f.Explanation,
			NeedsAdjustment:    !f.IsSufficient,
		})
	}
	out.Summary = fmt.Sprintf(
		"%d 个 jail 有复发样本，其中 %d 个建议延长封禁时长（按复发地址数降序）",
		len(out.Recommendations), needs,
	)
	return out
}

// clampInt64 把负数收进 0（u64 字段用）。
func clampInt64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// 渐进式封禁的级数与各级标签。
//
// 级数与 decision.ProgressiveDuration 的分档一致（首次→基础时长、1→30 分钟、2→24 小时、
// ≥3→永久）。标签写在这里而不只写在前端：契约把 label 定为载荷字段，服务端给什么
// 面板就显示什么，改分档时两边一起改才有对齐点。
const EffectivenessLevelCount = 4

var effectivenessLabels = []string{
	"第 1 次（基础时长）",
	"第 2 次（30 分钟）",
	"第 3 次（24 小时）",
	"第 4 次及以上（永久）",
}

// mapBanEffectiveness 把「地址 × 封禁等级」底账折成分级成效。
//
// 判据按**漏斗**读：maxByIP[ip] 是该地址最高到过第几级（ban_events.ban_count 是每次封禁
// 时的累计次数，取最大即到过的级）。到达第 L 级 = max ≥ L；第 L 级的复发 = max ≥ L+1
// （又升了一级）。第 4 级是开口桶（永久及以后）：它的 recidivist_ips 因此是「到顶格之后
// 还被封过一次」的地址数（ban_count ≥ 5），不是一个恒为 0 的占位——永久封禁可以被人工
// 解封，解封后再犯是这一级唯一的复发信号，藏掉它面板就以为顶格无人回归。
// permanent_bans 按**该级本身**是否永久封禁计（不是「至今是否永久」）。
//
// 分母为 0 时比率记 0 并在 verdict 里写「无样本」：面板不能把「没人到达这一级」读成
// 「这一级很有效」。
func mapBanEffectiveness(rows []persist.BanLevelRow) BanEffectivenessResponse {
	maxByIP := make(map[string]int)
	permanentAt := make([]map[string]bool, EffectivenessLevelCount+1)
	for i := range permanentAt {
		permanentAt[i] = make(map[string]bool)
	}
	for _, r := range rows {
		if r.BanCount > maxByIP[r.IP] {
			maxByIP[r.IP] = r.BanCount
		}
		if r.IsPermanent {
			permanentAt[min(r.BanCount, EffectivenessLevelCount)][r.IP] = true
		}
	}

	out := BanEffectivenessResponse{Levels: []BanLevelEffectiveness{}}
	for level := 1; level <= EffectivenessLevelCount; level++ {
		var reached, movedUp uint32
		for _, maxCount := range maxByIP {
			if maxCount >= level {
				reached++
			}
			if maxCount >= level+1 {
				movedUp++
			}
		}
		rate := 0.0
		if reached > 0 {
			rate = float64(movedUp) / float64(reached) * 100
		}
		out.Levels = append(out.Levels, BanLevelEffectiveness{
			Level:          uint8(level),
			Label:          effectivenessLabels[level-1],
			TotalIPs:       reached,
			RecidivistIPs:  movedUp,
			RecidivismRate: rate,
			PermanentBans:  uint32(len(permanentAt[level])),
			Verdict:        effectivenessVerdict(level, reached, movedUp, rate),
		})
	}

	totalUnique := uint32(len(maxByIP))
	recidivistIPs := uint32(0)
	for _, maxCount := range maxByIP {
		if maxCount >= 2 {
			recidivistIPs++
		}
	}
	if totalUnique > 0 {
		out.OverallRecidivismRate = float64(recidivistIPs) / float64(totalUnique) * 100
	}
	out.TotalUniqueIPs = totalUnique
	out.Summary = fmt.Sprintf(
		"共 %d 个地址被封禁过，其中 %d 个（%.1f%%）复发到第 2 级及以上",
		totalUnique, recidivistIPs, out.OverallRecidivismRate,
	)
	return out
}

// effectivenessVerdict 给一级的结论文本。
//
// 阈值与前端 RecidivismPanel 的 describeRate 同刻度（≥30 偏高、≥10 可接受、其余很低）：
// 两处读的是同一个百分数，边界不同会让相邻读数互相打脸。
//
// 顶格（第 4 级）不走这套措辞：它的分母是「已到永久档」的地址，复发含义是「永久解封后
// 再犯」，与「这一级时长太短」不是一回事，用同一句「复发率偏低所以有效」会误导。
func effectivenessVerdict(level int, total uint32, movedUp uint32, rate float64) string {
	if total == 0 {
		return "无样本"
	}
	if level == EffectivenessLevelCount {
		if movedUp == 0 {
			return "已到顶格（永久），此后无人再被封禁"
		}
		return fmt.Sprintf("已到顶格（永久），其中 %d 个解封后再次被封禁", movedUp)
	}
	switch {
	case rate >= 30:
		return "复发率偏高，这一级没拦住"
	case rate >= 10:
		return "复发率可接受"
	default:
		return "复发率很低，这一级有效"
	}
}

// 时长直方图的桶边界（秒，左闭右开）。
//
// 边界按 decision.ProgressiveDuration 的实际档位来（基础时长 / 30 分钟 / 24 小时 / 永久），
// 面板因此能把「哪一桶鼓起来」对上「渐进式封禁有没有真的往上走」。最后一桶「永久」读
// is_permanent 而不是时长，所以边界表比标签表少一格。
var (
	durationBucketUpper  = []int64{300, 1800, 7200, 86400}
	durationBucketLabels = []string{"≤5 分钟", "5–30 分钟", "30 分钟–2 小时", "2–24 小时", ">24 小时", "永久"}
	permanentBucketIndex = len(durationBucketLabels) - 1
)

// mapBanDurationHistogram 把封禁时长读数归进直方图。
//
// 没有时长读数的行（duration_secs 为 NULL 且非永久）不进任何桶、也不进 total：
// 迁移前写的旧行「封了多久」已经无从追究，把它们画进「≤5 分钟」桶会凭空造出一批柱子。
func mapBanDurationHistogram(samples []persist.BanEvent) BanDurationHistogramResponse {
	counts := make([]uint64, len(durationBucketLabels))
	for _, s := range samples {
		if s.IsPermanent {
			counts[permanentBucketIndex]++
			continue
		}
		if s.DurationSecs == nil {
			continue
		}
		d := clampInt64(*s.DurationSecs)
		idx := len(durationBucketUpper)
		for i, upper := range durationBucketUpper {
			if d < upper {
				idx = i
				break
			}
		}
		counts[idx]++
	}

	var total uint64
	for _, c := range counts {
		total += c
	}
	return BanDurationHistogramResponse{
		Labels: append([]string{}, durationBucketLabels...),
		Counts: counts,
		Total:  total,
	}
}
