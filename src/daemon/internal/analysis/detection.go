package analysis

import (
	"math"
	"sort"

	"github.com/snowcore8/linux-firewall-kmod/daemon/internal/persist"
)

type PeriodicAttacker struct {
	IP          string  `json:"ip"`
	JailName    string  `json:"jail_name"`
	Regularity  float64 `json:"regularity_score"`
	AvgInterval float64 `json:"avg_interval_seconds"`
	Jitter      float64 `json:"jitter_rate"`
	EventCount  int     `json:"event_count"`
}

func DetectPeriodicAttackers(db *persist.DB, minEvents int, limit int) ([]PeriodicAttacker, error) {
	if minEvents < 3 {
		minEvents = 3
	}
	if limit <= 0 {
		limit = 20
	}

	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	ipEvents := make(map[string][]int64)
	ipJail := make(map[string]string)
	for _, e := range events {
		ipEvents[e.IP] = append(ipEvents[e.IP], e.BannedAt)
		ipJail[e.IP] = e.JailName
	}

	var attackers []PeriodicAttacker
	for ip, timestamps := range ipEvents {
		if len(timestamps) < minEvents {
			continue
		}

		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

		var intervals []float64
		for i := 1; i < len(timestamps); i++ {
			intervals = append(intervals, float64(timestamps[i]-timestamps[i-1]))
		}

		if len(intervals) == 0 {
			continue
		}

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

		regularity := 0.0
		if cv < 0.3 {
			regularity = (1 - cv) * 100
		}

		attackers = append(attackers, PeriodicAttacker{
			IP:          ip,
			JailName:    ipJail[ip],
			Regularity:  regularity,
			AvgInterval: avg,
			Jitter:      cv,
			EventCount:  len(timestamps),
		})
	}

	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i].Regularity > attackers[j].Regularity
	})

	if len(attackers) > limit {
		attackers = attackers[:limit]
	}

	return attackers, nil
}

type CollaborativeAttack struct {
	JailName    string   `json:"jail_name"`
	WindowStart int64    `json:"window_start"`
	WindowEnd   int64    `json:"window_end"`
	IPs         []string `json:"ips"`
	BanCount    int      `json:"ban_count"`
	Score       float64  `json:"collaboration_score"`
}

func DetectCollaborativeAttacks(db *persist.DB, windowSeconds int, minIPs int, limit int) ([]CollaborativeAttack, error) {
	if windowSeconds <= 0 {
		windowSeconds = 300
	}
	if minIPs < 2 {
		minIPs = 3
	}
	if limit <= 0 {
		limit = 20
	}

	events, err := db.GetBanEvents(10000)
	if err != nil {
		return nil, err
	}

	jailEvents := make(map[string][]int64)
	jailIPs := make(map[string]map[string]bool)
	for _, e := range events {
		jailEvents[e.JailName] = append(jailEvents[e.JailName], e.BannedAt)
		if jailIPs[e.JailName] == nil {
			jailIPs[e.JailName] = make(map[string]bool)
		}
		jailIPs[e.JailName][e.IP] = true
	}

	var attacks []CollaborativeAttack
	for jail, timestamps := range jailEvents {
		sort.Slice(timestamps, func(i, j int) bool { return timestamps[i] < timestamps[j] })

		for i := 0; i < len(timestamps); i++ {
			windowEnd := timestamps[i] + int64(windowSeconds)
			var count int
			for j := i; j < len(timestamps) && timestamps[j] <= windowEnd; j++ {
				count++
			}

			if count >= minIPs {
				ips := make([]string, 0, len(jailIPs[jail]))
				for ip := range jailIPs[jail] {
					ips = append(ips, ip)
				}
				score := math.Min(100, float64(count)/10*100)
				attacks = append(attacks, CollaborativeAttack{
					JailName:    jail,
					WindowStart: timestamps[i],
					WindowEnd:   windowEnd,
					IPs:         ips[:min(len(ips), 10)],
					BanCount:    count,
					Score:       score,
				})
				break
			}
		}
	}

	sort.Slice(attacks, func(i, j int) bool {
		return attacks[i].Score > attacks[j].Score
	})

	if len(attacks) > limit {
		attacks = attacks[:limit]
	}

	return attacks, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
