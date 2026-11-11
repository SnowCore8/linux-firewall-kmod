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

	// 每个地址的间隔统计在 SQL 内聚合：返回的是一行一个地址，不随事件总量增长，
	// 也不再有「先取最近 1 万条」的截断——窗口外的老事件不会挤掉窗口内的样本。
	ipStats, err := db.GetIPBanIntervalStats()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	var predictions []AttackPredictionFinding

	for _, stats := range ipStats {
		if stats.EventCount < 3 {
			continue
		}
		median := stats.MedianInterval
		if median <= 0 {
			// 中位间隔为 0：事件聚集在同一秒，给不出「下一次」的时刻。
			// 继续算会得到 next = 上次封禁、urgency = imminent 的假预测。
			continue
		}

		avg := stats.AvgInterval
		cv := 0.0
		if avg > 0 {
			cv = stats.StdDev / avg
		}

		regularityScore := 0.0
		if cv < 0.3 {
			regularityScore = (1 - cv) * 100
		}

		dataAmountScore := math.Min(100, float64(stats.EventCount)/5*100)
		confidence := regularityScore*0.6 + dataAmountScore*0.4

		lastBan := stats.LastBannedAt
		nextAttack := lastBan + int64(math.Round(median))

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
			IP:           stats.IP,
			JailName:     stats.JailName,
			NextAttackAt: nextAttack,
			LastBanAt:    lastBan,
			Confidence:   confidence,
			Urgency:      urgency,
			EventCount:   stats.EventCount,
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

	jailTrends, err := analyzeJailTrends(db, now, perJailUpcoming)
	if err != nil {
		return nil, err
	}

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
func analyzeJailTrends(db *persist.DB, now int64, upcoming map[string]int) ([]JailTrend, error) {
	counts, err := db.GetJailBanWindowCounts(now)
	if err != nil {
		return nil, err
	}

	var trends []JailTrend
	for _, data := range counts {
		// 趋势 = 近 24 小时的封禁数相对**前一日同一段**（now-48h..now-24h）的倍数，
		// 与契约 JailAttackTrend.trend 的口径一致。除以 7 天日均会把一周前的高发日
		// 摊进分母：近一天的回落在面板上读成 stable，而不是契约承诺的「与前一日的
		// 量比较」。
		ratio := 0.0
		if data.BansPrev24h > 0 {
			ratio = float64(data.Bans24h) / float64(data.BansPrev24h)
		}

		var trend string
		switch {
		case data.BansPrev24h <= 0:
			// 前一日没有样本就没有基数可比，只能记 stable（契约同口径）。此处若拿
			// 24h 的数量硬判 rising，等于把「昨天没样本」读成「今天在涨」。
			trend = "stable"
		case ratio > 1.5:
			trend = "rising"
		case ratio < 0.5:
			trend = "falling"
		default:
			trend = "stable"
		}

		trends = append(trends, JailTrend{
			JailName:           data.JailName,
			Trend:              trend,
			Bans24h:            data.Bans24h,
			Bans7d:             data.Bans7d,
			PredictedAttackers: upcoming[data.JailName],
		})
	}

	sort.Slice(trends, func(i, j int) bool {
		if trends[i].Bans24h != trends[j].Bans24h {
			return trends[i].Bans24h > trends[j].Bans24h
		}
		return trends[i].JailName < trends[j].JailName
	})

	return trends, nil
}
