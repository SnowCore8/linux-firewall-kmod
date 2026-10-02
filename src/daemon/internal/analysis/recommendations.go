package analysis

import (
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type BanDurationRecommendation struct {
	JailName            string  `json:"jail_name"`
	CurrentDuration     int64   `json:"current_duration_seconds"`
	RecommendedDuration int64   `json:"recommended_duration_seconds"`
	RecidivistCount     int     `json:"recidivist_count"`
	MedianInterval      float64 `json:"median_interval_seconds"`
	Explanation         string  `json:"explanation"`
	IsSufficient        bool    `json:"is_sufficient"`
}

func RecommendBanDurations(db *persist.DB, currentDurations map[string]int64) ([]BanDurationRecommendation, error) {
	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	jailIPs := make(map[string]map[string][]int64)
	for _, e := range events {
		if jailIPs[e.JailName] == nil {
			jailIPs[e.JailName] = make(map[string][]int64)
		}
		jailIPs[e.JailName][e.IP] = append(jailIPs[e.JailName][e.IP], e.BannedAt)
	}

	var recommendations []BanDurationRecommendation
	for jail, ipTimestamps := range jailIPs {
		var intervals []float64
		recidivistCount := 0

		for _, timestamps := range ipTimestamps {
			if len(timestamps) < 2 {
				continue
			}
			recidivistCount++
			sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })
			for i := 1; i < len(timestamps); i++ {
				intervals = append(intervals, float64(timestamps[i]-timestamps[i-1]))
			}
		}

		if len(intervals) == 0 {
			continue
		}

		sort.Float64s(intervals)
		median := intervals[len(intervals)/2]

		current := currentDurations[jail]
		if current == 0 {
			current = 3600
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

		recommendations = append(recommendations, BanDurationRecommendation{
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
		return recommendations[i].RecidivistCount > recommendations[j].RecidivistCount
	})

	return recommendations, nil
}

type ThresholdRecommendation struct {
	JailName         string  `json:"jail_name"`
	Direction        string  `json:"direction"`
	CurrentValue     int     `json:"current_value"`
	RecommendedValue int     `json:"recommended_value"`
	RecidivismRate   float64 `json:"recidivism_rate"`
	Confidence       float64 `json:"confidence"`
	Explanation      string  `json:"explanation"`
}

func RecommendThresholds(db *persist.DB, currentThresholds map[string]int) ([]ThresholdRecommendation, error) {
	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	sevenDaysAgo := time.Now().AddDate(0, 0, -7).Unix()
	jailStats := make(map[string]struct {
		total    int
		recidive int
	})

	for _, e := range events {
		if e.BannedAt < sevenDaysAgo {
			continue
		}
		stats := jailStats[e.JailName]
		stats.total++
		if e.BanCount > 1 {
			stats.recidive++
		}
		jailStats[e.JailName] = stats
	}

	var recommendations []ThresholdRecommendation
	for jail, stats := range jailStats {
		if stats.total < 10 {
			continue
		}

		rate := float64(stats.recidive) / float64(stats.total) * 100
		current := currentThresholds[jail]
		if current == 0 {
			current = 5
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
		} else if rate < 10 && stats.total > 20 {
			direction = "increase"
			recommended = int(float64(current) * 1.5)
			explanation = "复发率低且封禁数多，可能存在误封，建议放宽阈值"
		} else {
			direction = "maintain"
			recommended = current
			explanation = "复发率在合理范围，维持当前阈值"
		}

		confidence := 0.3
		if stats.total >= 50 {
			confidence = 0.9
		} else if stats.total >= 20 {
			confidence = 0.7
		} else if stats.total >= 10 {
			confidence = 0.5
		}

		recommendations = append(recommendations, ThresholdRecommendation{
			JailName:         jail,
			Direction:        direction,
			CurrentValue:     current,
			RecommendedValue: recommended,
			RecidivismRate:   rate,
			Confidence:       confidence,
			Explanation:      explanation,
		})
	}

	sort.Slice(recommendations, func(i, j int) bool {
		return recommendations[i].RecidivismRate > recommendations[j].RecidivismRate
	})

	return recommendations, nil
}
