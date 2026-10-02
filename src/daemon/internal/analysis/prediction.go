package analysis

import (
	"math"
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type AttackPrediction struct {
	IP           string  `json:"ip"`
	JailName     string  `json:"jail_name"`
	NextAttackAt int64   `json:"next_attack_at"`
	Confidence   float64 `json:"confidence_score"`
	Urgency      string  `json:"urgency"`
	EventCount   int     `json:"event_count"`
	MedianPeriod float64 `json:"median_period_seconds"`
}

type JailTrend struct {
	JailName           string `json:"jail_name"`
	Trend              string `json:"trend"`
	Bans24h            int    `json:"bans_24h"`
	Bans7d             int    `json:"bans_7d"`
	PredictedAttackers int    `json:"predicted_attackers"`
}

type PredictionSummary struct {
	Predictions    []AttackPrediction `json:"predictions"`
	JailTrends     []JailTrend        `json:"jail_trends"`
	ImminentCount  int                `json:"imminent_count"`
	Within24hCount int                `json:"within_24h_count"`
}

func PredictAttacks(db *persist.DB, limit int) (*PredictionSummary, error) {
	if limit <= 0 {
		limit = 15
	}

	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	ipData := make(map[string]*struct {
		jail       string
		timestamps []int64
	})

	for _, e := range events {
		if ipData[e.IP] == nil {
			ipData[e.IP] = &struct {
				jail       string
				timestamps []int64
			}{jail: e.JailName}
		}
		ipData[e.IP].timestamps = append(ipData[e.IP].timestamps, e.BannedAt)
	}

	now := time.Now().Unix()
	var predictions []AttackPrediction

	for ip, data := range ipData {
		if len(data.timestamps) < 3 {
			continue
		}

		sort.Slice(data.timestamps, func(i, j int) bool { return data.timestamps[i] < data.timestamps[j] })

		var intervals []float64
		for i := 1; i < len(data.timestamps); i++ {
			intervals = append(intervals, float64(data.timestamps[i]-data.timestamps[i-1]))
		}

		sort.Float64s(intervals)
		median := intervals[len(intervals)/2]

		var sum float64
		for _, v := range intervals {
			sum += v
		}
		avg := sum / float64(len(intervals))

		var varianceSum float64
		for _, v := range intervals {
			diff := v - avg
			varianceSum += diff * diff
		}
		stddev := math.Sqrt(varianceSum / float64(len(intervals)))

		cv := 0.0
		if avg > 0 {
			cv = stddev / avg
		}

		regularityScore := 0.0
		if cv < 0.3 {
			regularityScore = (1 - cv) * 100
		}

		dataAmountScore := math.Min(100, float64(len(data.timestamps))/5*100)
		confidence := regularityScore*0.6 + dataAmountScore*0.4

		lastBan := data.timestamps[len(data.timestamps)-1]
		nextAttack := lastBan + int64(median)

		var urgency string
		hoursUntil := float64(nextAttack-now) / 3600
		if hoursUntil < 1 {
			urgency = "imminent"
		} else if hoursUntil < 6 {
			urgency = "soon"
		} else if hoursUntil < 24 {
			urgency = "later"
		} else {
			urgency = "distant"
		}

		predictions = append(predictions, AttackPrediction{
			IP:           ip,
			JailName:     data.jail,
			NextAttackAt: nextAttack,
			Confidence:   confidence,
			Urgency:      urgency,
			EventCount:   len(data.timestamps),
			MedianPeriod: median,
		})
	}

	sort.Slice(predictions, func(i, j int) bool {
		return predictions[i].NextAttackAt < predictions[j].NextAttackAt
	})

	if len(predictions) > limit {
		predictions = predictions[:limit]
	}

	jailTrends, err := analyzeJailTrends(db)
	if err != nil {
		return nil, err
	}

	var imminentCount, within24hCount int
	for _, p := range predictions {
		if p.Urgency == "imminent" {
			imminentCount++
		}
		if p.Urgency == "imminent" || p.Urgency == "soon" || p.Urgency == "later" {
			within24hCount++
		}
	}

	return &PredictionSummary{
		Predictions:    predictions,
		JailTrends:     jailTrends,
		ImminentCount:  imminentCount,
		Within24hCount: within24hCount,
	}, nil
}

func analyzeJailTrends(db *persist.DB) ([]JailTrend, error) {
	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	dayAgo := now - 86400
	weekAgo := now - 7*86400

	jailData := make(map[string]*struct {
		bans24h int
		bans7d  int
	})

	for _, e := range events {
		if jailData[e.JailName] == nil {
			jailData[e.JailName] = &struct {
				bans24h int
				bans7d  int
			}{}
		}
		if e.BannedAt >= dayAgo {
			jailData[e.JailName].bans24h++
		}
		if e.BannedAt >= weekAgo {
			jailData[e.JailName].bans7d++
		}
	}

	var trends []JailTrend
	for jail, data := range jailData {
		dailyAvg7d := float64(data.bans7d) / 7
		dailyAvg24h := float64(data.bans24h)

		var trend string
		ratio := 0.0
		if dailyAvg7d > 0 {
			ratio = dailyAvg24h / dailyAvg7d
		}

		if ratio > 1.5 {
			trend = "rising"
		} else if ratio < 0.5 {
			trend = "falling"
		} else {
			trend = "stable"
		}

		trends = append(trends, JailTrend{
			JailName: jail,
			Trend:    trend,
			Bans24h:  data.bans24h,
			Bans7d:   data.bans7d,
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		return trends[i].Bans24h > trends[j].Bans24h
	})

	return trends, nil
}
