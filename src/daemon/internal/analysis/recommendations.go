package analysis

import (
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

const (
	// thresholdWindowDays 是阈值建议的样本窗口（契约 ThresholdRecommendation 声明的近 7 天）。
	thresholdWindowDays = 7
	// banDurationWindowDays 是时长建议的复发窗口。间隔中位数要看到足够长的复发周期，
	// 7 天会把「每周来一次」的样本截成单个间隔；30 天与历史库的常见保留期同量级。
	banDurationWindowDays = 30
)

// BanDurationFinding 是「某个 jail 的封禁时长该不该改」的读数。
//
// 与契约载荷 BanDurationRecommendation 刻意不同名，理由见 PeriodicAttackFinding。
type BanDurationFinding struct {
	JailName            string  `json:"jail_name"`
	CurrentDuration     int64   `json:"current_duration_seconds"`
	RecommendedDuration int64   `json:"recommended_duration_seconds"`
	RecidivistCount     int     `json:"recidivist_count"`
	MedianInterval      float64 `json:"median_interval_seconds"`
	Explanation         string  `json:"explanation"`
	IsSufficient        bool    `json:"is_sufficient"`
}

func RecommendBanDurations(db *persist.DB, currentDurations map[string]int64) ([]BanDurationFinding, error) {
	since := time.Now().AddDate(0, 0, -banDurationWindowDays).Unix()
	jailStats, err := db.BanDurationStatsSince(since)
	if err != nil {
		return nil, err
	}

	var recommendations []BanDurationFinding
	for _, stats := range jailStats {
		jail := stats.JailName
		median := stats.MedianInterval
		recidivistCount := stats.RecidivistCount

		current := currentDurations[jail]
		switch {
		case current < 0:
			// 配置级永久封禁：没有「时长」可调，延长/缩短都无从谈起。不给出建议条目
			// 比给出一个 current=-1 / recommended=0 的条目更诚实（后两个数在载荷里都是
			// 「立刻过期」的形状）。契约 route note 记了这个省略口径。
			continue
		case current == 0:
			current = DefaultBanDurationForRecommendation
		}

		recommended := current
		isSufficient := true
		explanation := "当前封禁时长已足够"

		if median > float64(current) {
			recommended = int64(median * 1.5)
			if recommended < current*2 {
				recommended = current * 2
			}
			isSufficient = false
			explanation = "复发间隔中位数超过当前封禁时长，建议延长"
		}

		recommendations = append(recommendations, BanDurationFinding{
			JailName:            jail,
			CurrentDuration:     current,
			RecommendedDuration: recommended,
			RecidivistCount:     recidivistCount,
			MedianInterval:      median,
			Explanation:         explanation,
			IsSufficient:        isSufficient,
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].RecidivistCount != recommendations[j].RecidivistCount {
			return recommendations[i].RecidivistCount > recommendations[j].RecidivistCount
		}
		return recommendations[i].JailName < recommendations[j].JailName
	})

	return recommendations, nil
}

// ThresholdFinding 是「某个 jail 的失败阈值该不该改」的读数。
//
// 复发口径是**按地址、在本 jail 内**的：一个地址在本 jail 的近 7 天里被封 ≥2 次才算复发。
// 旧实现拿事件的 ban_count>1 判定，那个数是**跨 jail 的全局累计次数**，于是「被 sshd 封过
// 一次的地址这次被 mysql 封」会被记进 mysql 的复发——阈值建议要回答的是「这个 jail 拦得住
// 吗」，借全局次数回答会串味。载荷里的 recidivism_rate 因此与 /stats/recidivism 同口径
// （复发地址数 / 唯一地址数 × 100，百分数）。
type ThresholdFinding struct {
	JailName       string  `json:"jail_name"`
	Direction      string  `json:"direction"`
	CurrentValue   int     `json:"current_value"`
	RecommendedVal int     `json:"recommended_value"`
	TotalBans      int     `json:"total_bans"`
	UniqueIPs      int     `json:"unique_ips"`
	RecidivistIPs  int     `json:"recidivist_ips"`
	RecidivismRate float64 `json:"recidivism_rate"`
	AvgBansPerIP   float64 `json:"avg_bans_per_ip"`
	Confidence     float64 `json:"confidence"`
	Explanation    string  `json:"explanation"`
}

func RecommendThresholds(db *persist.DB, currentThresholds map[string]int) ([]ThresholdFinding, error) {
	sevenDaysAgo := time.Now().AddDate(0, 0, -thresholdWindowDays).Unix()
	jailStats, err := db.BanJailStatsSince(sevenDaysAgo)
	if err != nil {
		return nil, err
	}

	var recommendations []ThresholdFinding
	for _, stats := range jailStats {
		if stats.TotalBans < MinThresholdSampleEvents {
			continue
		}

		uniqueIPs := stats.UniqueIPs
		recidivistIPs := stats.RecidivistIPs
		if uniqueIPs == 0 {
			continue
		}

		jail := stats.JailName
		rate := float64(recidivistIPs) / float64(uniqueIPs) * 100
		current := currentThresholds[jail]
		if current == 0 {
			current = DefaultThresholdForRecommendation
		}

		var direction string
		var recommended int
		var explanation string

		if rate > 30 {
			direction = "decrease"
			recommended = int(float64(current) * 0.7)
			if recommended < 1 {
				recommended = 1
			}
			explanation = "复发率过高，攻击者未被充分阻止，建议降低阈值"
		} else if rate < 10 && stats.TotalBans > 20 {
			direction = "increase"
			recommended = int(float64(current) * 1.5)
			explanation = "复发率低且封禁数多，可能存在误封，建议放宽阈值"
		} else {
			direction = "maintain"
			recommended = current
			explanation = "复发率在合理范围，维持当前阈值"
		}

		// 钳位与取整可能把推荐值拉回当前值：current=1 时 decrease 算 0.7→下限 1，
		// increase 取整后也是 1。此时仍报 decrease/increase 会让面板出现「建议降到 1
		// （当前已是 1）」这种自相矛盾的读数。载荷里「要不要改」由 direction 表达，
		// 值相等就归为 maintain。
		if direction != "maintain" && recommended == current {
			direction = "maintain"
			explanation = "推荐值与当前阈值相同，维持现状"
		}

		// 置信度只看样本量（封禁事件数）：样本越厚，同一复发率越不像巧合。
		// 阶梯与载荷口径是 u8 百分数，这里给 0-1，由读侧换算。
		confidence := 0.3
		if stats.TotalBans >= 50 {
			confidence = 0.9
		} else if stats.TotalBans >= 20 {
			confidence = 0.7
		} else if stats.TotalBans >= 10 {
			confidence = 0.5
		}

		recommendations = append(recommendations, ThresholdFinding{
			JailName:       jail,
			Direction:      direction,
			CurrentValue:   current,
			RecommendedVal: recommended,
			TotalBans:      stats.TotalBans,
			UniqueIPs:      uniqueIPs,
			RecidivistIPs:  recidivistIPs,
			RecidivismRate: rate,
			AvgBansPerIP:   float64(stats.TotalBans) / float64(uniqueIPs),
			Confidence:     confidence,
			Explanation:    explanation,
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		if recommendations[i].RecidivismRate != recommendations[j].RecidivismRate {
			return recommendations[i].RecidivismRate > recommendations[j].RecidivismRate
		}
		return recommendations[i].JailName < recommendations[j].JailName
	})

	return recommendations, nil
}

const (
	// MinThresholdSampleEvents 是给出一个阈值建议所需的近 7 天封禁事件数。
	// 低于它时样本太薄，复发率的抖动比方向本身还大。
	MinThresholdSampleEvents = 10
	// DefaultThresholdForRecommendation 是配置里查不到该 jail 时的兜底阈值。
	//
	// 兜底值会进载荷的 current_threshold，读侧无法区分「配置真是 5」与「查不到所以给了 5」，
	// 因此 internal/http 只保留配置里现存的 jail（见 handlers 里的过滤）。
	DefaultThresholdForRecommendation = 5
	// DefaultBanDurationForRecommendation 是配置里查不到该 jail 时的兜底封禁时长（秒）。
	// 同上：internal/http 会把配置里不存在的 jail 滤掉，不让兜底值冒充读数。
	DefaultBanDurationForRecommendation = 3600
)
