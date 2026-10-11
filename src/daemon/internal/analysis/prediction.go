package analysis

import (
	"math"
	"sort"
	"time"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

// AttackPredictionFinding 是对一个地址下次动手时刻的估计。
//
// 与契约载荷 `AttackPrediction` 刻意不同名（理由见 PeriodicAttackFinding）；载荷里的
// remaining_secs 不在这里算——它是「相对读的一刻还剩多久」，属于响应时刻的量，
// 在计算层算会把时刻钉死在采样时间上。
type AttackPredictionFinding struct {
	IP           string  `json:"ip"`
	JailName     string  `json:"jail_name"`
	NextAttackAt int64   `json:"next_attack_at"`
	LastBanAt    int64   `json:"last_ban_at"`
	Confidence   float64 `json:"confidence_score"`
	Urgency      string  `json:"urgency"`
	EventCount   int     `json:"event_count"`
	MedianPeriod float64 `json:"median_period_seconds"`
}

type JailTrend struct {
	JailName string `json:"jail_name"`
	Trend    string `json:"trend"`
	Bans24h  int    `json:"bans_24h"`
	Bans7d   int    `json:"bans_7d"`
	// PredictedAttackers 是「未来 24 小时内预计再动手」的地址数。
	//
	// 旧实现声明了这个字段却从未赋值（恒 0），面板上那一列因此永远是零——它现在由
	// PredictAttacks 从**截断前**的完整预测集算出，不受 limit 影响（截断只影响列表长度，
	// 不该让计数跟着变小）。
	PredictedAttackers int `json:"predicted_attackers"`
}

type PredictionSummary struct {
	Predictions    []AttackPredictionFinding `json:"predictions"`
	JailTrends     []JailTrend               `json:"jail_trends"`
	ImminentCount  int                       `json:"imminent_count"`
	Within24hCount int                       `json:"within_24h_count"`
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
			// 事件按 banned_at 降序读入，首次出现即该地址**最近一次**封禁，
			// 于是 jail 取的就是最近那条的归属（后续同一 IP 不再覆盖它）。
			ipData[e.IP] = &struct {
				jail       string
				timestamps []int64
			}{jail: e.JailName}
		}
		ipData[e.IP].timestamps = append(ipData[e.IP].timestamps, e.BannedAt)
	}

	now := time.Now().Unix()
	var predictions []AttackPredictionFinding

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

		predictions = append(predictions, AttackPredictionFinding{
			IP:           ip,
			JailName:     data.jail,
			NextAttackAt: nextAttack,
			LastBanAt:    lastBan,
			Confidence:   confidence,
			Urgency:      urgency,
			EventCount:   len(data.timestamps),
			MedianPeriod: median,
		})
	}

	// 每 jail 的「24 小时内预计再动手」要在**截断前**统计：limit 管的是列表长度，
	// 不是这件事的规模。已过期的估计（nextAttack <= now）也算——它表示随时可能再来。
	perJailUpcoming := make(map[string]int)
	for _, p := range predictions {
		if p.NextAttackAt <= now+86400 {
			perJailUpcoming[p.JailName]++
		}
	}

	sort.Slice(predictions, func(i, j int) bool {
		if predictions[i].NextAttackAt != predictions[j].NextAttackAt {
			return predictions[i].NextAttackAt < predictions[j].NextAttackAt
		}
		return predictions[i].IP < predictions[j].IP
	})

	// imminent / within_24h 描述的是**载荷里那一批估计**，因此先截断再计数：
	// 用全集计数会让「imminent_count」比列表长度还大，面板上「N 条即将动手」和下面的
	// 表格就对不上（limit 管的是列表长度，不是这件事的规模）。
	if len(predictions) > limit {
		predictions = predictions[:limit]
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

	jailTrends := analyzeJailTrends(events, perJailUpcoming)

	return &PredictionSummary{
		Predictions:    predictions,
		JailTrends:     jailTrends,
		ImminentCount:  imminentCount,
		Within24hCount: within24hCount,
	}, nil
}

// analyzeJailTrends 按 jail 汇总「最近 24h / 7d 的封禁量」并给出走向。
//
// upcoming 是调用方从预测集算出的「24 小时内预计再动手」计数（按 jail 传入）；
// 本层自己不做预测，只把趋势与那个读数并排放好。
func analyzeJailTrends(events []persist.BanEvent, upcoming map[string]int) []JailTrend {
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

		// 趋势 = 近 24 小时的封禁数相对 7 天日均的倍数。七天窗口里一次封禁都没有时
		// 没有基数可比，只能记 stable——旧写法在这种 jail 上算出 ratio=0 而报 falling，
		// 面板会把「没有样本」读成「快好了」。
		ratio := 0.0
		if dailyAvg7d > 0 {
			ratio = dailyAvg24h / dailyAvg7d
		}

		var trend string
		switch {
		case dailyAvg7d <= 0:
			trend = "stable"
		case ratio > 1.5:
			trend = "rising"
		case ratio < 0.5:
			trend = "falling"
		default:
			trend = "stable"
		}

		trends = append(trends, JailTrend{
			JailName:           jail,
			Trend:              trend,
			Bans24h:            data.bans24h,
			Bans7d:             data.bans7d,
			PredictedAttackers: upcoming[jail],
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		if trends[i].Bans24h != trends[j].Bans24h {
			return trends[i].Bans24h > trends[j].Bans24h
		}
		return trends[i].JailName < trends[j].JailName
	})

	return trends
}
